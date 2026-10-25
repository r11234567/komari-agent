package files

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
)

const (
	defaultTransferChunkSize = int64(25 * 1024 * 1024)
	maxTransferChunkSize     = int64(128 * 1024 * 1024)
	searchResultLimit        = 500
)

type fileInfo struct {
	Name       string    `json:"name"`
	Path       string    `json:"path"`
	IsDir      bool      `json:"is_dir"`
	IsSymlink  bool      `json:"is_symlink"`
	Size       int64     `json:"size"`
	Mode       string    `json:"mode"`
	ModeOctal  string    `json:"mode_octal"`
	UID        int       `json:"uid"`
	GID        int       `json:"gid"`
	Owner      string    `json:"owner"`
	Group      string    `json:"group"`
	ModifiedAt time.Time `json:"modified_at"`
	Target     string    `json:"target,omitempty"`
}

type uploadChunkState struct {
	Size         int64
	ExpectedSize int64
	ChunkSize    int64
	TargetPath   string
	Parts        map[int64]struct{}
	PartCount    int64
	TempPath     string
	CreatedAt    time.Time
}

var (
	uploadChunksMu = sync.Mutex{}
	uploadChunks   = make(map[string]uploadChunkState)
)

type searchMatch struct {
	Path  string `json:"path"`
	Line  int    `json:"line"`
	Text  string `json:"text,omitempty"`
	IsDir bool   `json:"is_dir"`
}

func listFiles(root string) (json.RawMessage, error) {
	if runtime.GOOS == "windows" && strings.TrimSpace(root) == "/" {
		return listVirtualRootEntries()
	}
	root = resolveFilePath(root)
	entries, err := os.ReadDir(root)
	if err != nil {
		return nil, err
	}
	files := make([]fileInfo, 0, len(entries))
	for _, entry := range entries {
		info, err := describeFile(filepath.Join(root, entry.Name()), entry.Type()&fs.ModeSymlink != 0)
		if err != nil {
			continue
		}
		files = append(files, info)
	}
	sort.SliceStable(files, func(i, j int) bool {
		if files[i].IsDir != files[j].IsDir {
			return files[i].IsDir
		}
		return strings.ToLower(files[i].Name) < strings.ToLower(files[j].Name)
	})
	return json.Marshal(files)
}

func statFile(path string) (json.RawMessage, error) {
	path = resolveFilePath(path)
	info, err := describeFile(path, isSymlink(path))
	if err != nil {
		return nil, err
	}
	return json.Marshal(info)
}

// Replacing a link would silently change its type, and replacing a special
// file could lose device semantics. Require an explicit regular-file target.
func replaceableFile(path string) (os.FileInfo, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("cannot replace a non-regular file; choose its regular-file target explicitly")
	}
	return info, nil
}

func preserveReplacementMetadata(temporary string, existing os.FileInfo) error {
	mode := fs.FileMode(0o644)
	if existing != nil {
		mode = existing.Mode() & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
		uid, gid, _, _ := fileOwnership(existing)
		if uid >= 0 && gid >= 0 {
			if err := changeOwnership(temporary, uid, gid); err != nil {
				return fmt.Errorf("cannot preserve file ownership: %w", err)
			}
		}
	}
	return os.Chmod(temporary, mode)
}

// createFile creates or truncates an empty regular file without carrying file
// data through the RPC control channel. Non-empty replacements use the raw
// upload stream and are finalized by upload_commit.
func createFile(path string) (json.RawMessage, error) {
	path = resolveFilePath(path)
	if path == string(filepath.Separator) || path == "." {
		return nil, errors.New("file path is required")
	}
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return nil, err
	}
	existing, err := replaceableFile(path)
	if err != nil {
		return nil, err
	}
	temporary, err := os.CreateTemp(directory, ".komari-empty-*")
	if err != nil {
		return nil, err
	}
	temporaryName := temporary.Name()
	removeTemporary := true
	defer func() {
		_ = temporary.Close()
		if removeTemporary {
			_ = os.Remove(temporaryName)
		}
	}()
	if err := preserveReplacementMetadata(temporaryName, existing); err != nil {
		return nil, err
	}
	if err := temporary.Close(); err != nil {
		return nil, err
	}
	if err := replaceFile(temporaryName, path); err != nil {
		return nil, err
	}
	removeTemporary = false
	if err := syncUploadDirectory(directory); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"created": true, "size": 0})
}

func mkdir(path, modeValue string) (json.RawMessage, error) {
	path = resolveFilePath(path)
	mode := fs.FileMode(0o755)
	if strings.TrimSpace(modeValue) != "" {
		parsed, err := parseMode(modeValue)
		if err != nil {
			return nil, err
		}
		mode = fs.FileMode(parsed)
	}
	if err := os.MkdirAll(path, mode); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"created": true})
}

func deletePath(path string, recursive bool) (json.RawMessage, error) {
	cleaned := resolveFilePath(path)
	volume := filepath.VolumeName(cleaned)
	volumeRoot := ""
	if volume != "" {
		volumeRoot = filepath.Clean(volume + string(filepath.Separator))
	}
	if cleaned == string(filepath.Separator) || cleaned == volumeRoot {
		return nil, errors.New("refusing to delete a filesystem root")
	}
	if _, err := os.Lstat(cleaned); err != nil {
		return nil, err
	}
	remove := os.Remove
	if recursive {
		remove = os.RemoveAll
	}
	if err := remove(cleaned); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"deleted": true})
}

func movePath(source, destination string, overwrite bool) (json.RawMessage, error) {
	source = resolveFilePath(source)
	destination = resolveFilePath(destination)
	if samePath(source, destination) {
		return json.Marshal(map[string]any{"moved": true})
	}
	if pathContains(source, destination) {
		return nil, errors.New("cannot move a path into itself")
	}
	if !overwrite {
		if _, err := os.Lstat(destination); err == nil {
			return nil, fmt.Errorf("destination already exists: %s", destination)
		} else if !os.IsNotExist(err) {
			return nil, err
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return nil, err
	}
	rename := replaceFile
	if !overwrite {
		rename = renameWithoutOverwrite
	}
	if err := rename(source, destination); err != nil {
		if !isCrossDeviceRename(err) {
			return nil, err
		}
		// Windows and Unix both reject rename across volumes. Fall back to a
		// copy followed by removal so moving between drive letters works too.
		info, statErr := os.Lstat(source)
		if statErr != nil {
			return nil, statErr
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if copyErr := copySymlink(source, destination, overwrite); copyErr != nil {
				return nil, copyErr
			}
		} else if info.IsDir() {
			if copyErr := copyDirectory(source, destination, overwrite); copyErr != nil {
				return nil, copyErr
			}
		} else if copyErr := copyRegularFile(source, destination, info, overwrite); copyErr != nil {
			return nil, copyErr
		}
		if removeErr := os.RemoveAll(source); removeErr != nil {
			return nil, removeErr
		}
	}
	return json.Marshal(map[string]any{"moved": true})
}

func isCrossDeviceRename(err error) bool {
	return errors.Is(err, syscall.EXDEV) || errors.Is(err, syscall.Errno(17))
}

func copyPath(source, destination string, recursive, overwrite bool) (json.RawMessage, error) {
	source = resolveFilePath(source)
	destination = resolveFilePath(destination)
	if samePath(source, destination) {
		return nil, errors.New("source and destination are the same")
	}
	info, err := os.Lstat(source)
	if err != nil {
		return nil, err
	}
	if info.IsDir() {
		if !recursive {
			return nil, errors.New("recursive is required to copy a directory")
		}
		if pathContains(source, destination) {
			return nil, errors.New("cannot copy a directory into itself")
		}
		if err := copyDirectory(source, destination, overwrite); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"copied": true})
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if err := copySymlink(source, destination, overwrite); err != nil {
			return nil, err
		}
		return json.Marshal(map[string]any{"copied": true})
	}
	if err := copyRegularFile(source, destination, info, overwrite); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"copied": true})
}

func copyRegularFile(source, destination string, info os.FileInfo, overwrite bool) error {
	if !info.Mode().IsRegular() {
		return errors.New("only regular files can be copied")
	}
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if existing, err := os.Lstat(destination); err == nil {
		if !overwrite {
			return fmt.Errorf("destination already exists: %s", destination)
		}
		if !existing.Mode().IsRegular() {
			return errors.New("cannot replace a non-regular destination with a file")
		}
		if os.SameFile(info, existing) {
			return errors.New("source and destination are the same file")
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	output, err := os.CreateTemp(filepath.Dir(destination), ".komari-copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(output.Name())
	defer output.Close()
	if _, err = io.Copy(output, input); err != nil {
		return err
	}
	if err = output.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	if err = os.Chtimes(output.Name(), info.ModTime(), info.ModTime()); err != nil {
		return err
	}
	if !overwrite {
		// Linking publishes the complete file without replacing a destination
		// created after our check. Unsupported filesystems fail safely.
		return os.Link(output.Name(), destination)
	}
	return replaceFile(output.Name(), destination)
}

func copySymlink(source, destination string, overwrite bool) error {
	target, err := os.Readlink(source)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if existing, err := os.Lstat(destination); err == nil {
		if !overwrite {
			return fmt.Errorf("destination already exists: %s", destination)
		}
		if existing.IsDir() && existing.Mode()&os.ModeSymlink == 0 {
			return errors.New("cannot replace destination directory with a symlink")
		}
		if err := os.Remove(destination); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.Symlink(target, destination)
}

func copyDirectory(source, destination string, overwrite bool) error {
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if !overwrite {
		if err := os.Mkdir(destination, 0o755); err != nil {
			return err
		}
	}
	return filepath.WalkDir(source, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		relative, err := filepath.Rel(source, path)
		if err != nil {
			return err
		}
		target := destination
		if relative != "." {
			target = filepath.Join(destination, relative)
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return copySymlink(path, target, overwrite)
		}
		if entry.IsDir() {
			if existing, err := os.Lstat(target); err == nil && (!existing.IsDir() || existing.Mode()&os.ModeSymlink != 0) {
				return errors.New("cannot copy a directory through a non-directory destination")
			} else if err != nil && !os.IsNotExist(err) {
				return err
			}
			if err := os.MkdirAll(target, info.Mode().Perm()); err != nil {
				return err
			}
			if err := os.Chmod(target, info.Mode().Perm()); err != nil {
				return err
			}
			return os.Chtimes(target, info.ModTime(), info.ModTime())
		}
		return copyRegularFile(path, target, info, overwrite)
	})
}

func samePath(left, right string) bool {
	if runtime.GOOS == "windows" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func pathContains(parent, child string) bool {
	relative, err := filepath.Rel(filepath.Clean(parent), filepath.Clean(child))
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return false
	}
	return !filepath.IsAbs(relative)
}
func chmodPath(path, modeValue string) (json.RawMessage, error) {
	path = resolveFilePath(path)
	mode, err := parseMode(modeValue)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, fs.FileMode(mode)); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"mode": fmt.Sprintf("%04o", mode)})
}

func chownPath(args map[string]interface{}) (json.RawMessage, error) {
	path := resolveFilePath(argString(args, "path"))
	uid := -1
	gid := -1
	if _, exists := args["uid"]; exists {
		uid = int(argInt64(args, "uid"))
	}
	if owner := argString(args, "owner"); owner != "" {
		resolved, err := resolveUnixAccount(owner, true)
		if err != nil {
			return nil, err
		}
		uid = resolved
	}
	if _, exists := args["gid"]; exists {
		gid = int(argInt64(args, "gid"))
	}
	if group := argString(args, "group"); group != "" {
		resolved, err := resolveUnixAccount(group, false)
		if err != nil {
			return nil, err
		}
		gid = resolved
	}
	if err := changeOwnership(path, uid, gid); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"uid": uid, "gid": gid})
}

func searchFiles(args map[string]interface{}) (json.RawMessage, error) {
	query := argString(args, "query")
	includeContent := argBool(args, "content")
	if query == "" {
		return nil, errors.New("query is required")
	}

	var roots []string
	if runtime.GOOS == "windows" && strings.TrimSpace(argString(args, "path")) == "/" {
		roots = virtualRootSearchPaths()
	} else {
		roots = []string{resolveFilePath(argString(args, "path"))}
	}
	lowerQuery := strings.ToLower(query)

	matches := make([]searchMatch, 0)
	searchRootFiles := func(root string) error {
		return filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
			if len(matches) >= searchResultLimit {
				return fs.SkipAll
			}
			if walkErr != nil {
				if path == root {
					return walkErr
				}
				if entry != nil && entry.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			nameMatch := strings.Contains(strings.ToLower(entry.Name()), lowerQuery)
			isSymlink := entry.Type()&fs.ModeSymlink != 0
			if nameMatch && !includeContent {
				matches = append(matches, searchMatch{
					Path:  virtualizeFilePath(path),
					IsDir: entry.IsDir(),
				})
			} else if includeContent && !entry.IsDir() && !isSymlink {
				if match, ok := matchFileContent(path, query, lowerQuery); ok && match.Line > 0 {
					matches = append(matches, match)
					return nil
				}
			}
			return nil
		})
	}
	for _, root := range roots {
		if err := searchRootFiles(root); err != nil && !errors.Is(err, fs.SkipAll) {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{"matches": matches, "limited": len(matches) >= searchResultLimit})
}

func uploadChunkCount(size, chunkSize int64) int64 {
	if size <= 0 || chunkSize <= 0 {
		return 0
	}
	return (size + chunkSize - 1) / chunkSize
}

func uploadPartPathFor(targetPath, uploadID string) string {
	target := filepath.ToSlash(targetPath)
	name := filepath.Base(target)
	if name == "" || name == "." || name == "/" {
		name = "upload"
	}
	return filepath.Join(filepath.Dir(target), "."+name+".komari-upload-"+uploadID+".part")
}

func syncUploadDirectory(dir string) error {
	if runtime.GOOS == "windows" {
		return nil
	}
	dirFile, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer dirFile.Close()
	return dirFile.Sync()
}

func removeUploadFileLocked(uploadID string) error {
	state, ok := uploadChunks[uploadID]
	if !ok {
		return nil
	}
	if state.TempPath != "" {
		if err := os.Remove(state.TempPath); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	delete(uploadChunks, uploadID)
	return nil
}

func cancelFileUpload(args map[string]interface{}) (json.RawMessage, error) {
	uploadID := strings.TrimSpace(argString(args, "upload_id"))
	if uploadID == "" {
		return nil, errors.New("upload_id is required")
	}
	// Stop any Agent-side HTTP body readers before removing the temporary file.
	// This lets an explicit cancel interrupt a slow relay instead of waiting for
	// the current chunk to drain.
	cancelUploadStreams(uploadID)
	waitUploadStreams(uploadID)
	writeLock := uploadWriteLock(uploadID)
	writeLock.Lock()
	defer func() {
		writeLock.Unlock()
		forgetUploadWriteLock(uploadID)
	}()
	targetPath := strings.TrimSpace(argString(args, "path"))
	if targetPath != "" {
		targetPath = resolveFilePath(targetPath)
	}

	uploadChunksMu.Lock()
	state, exists := uploadChunks[uploadID]
	if exists {
		if targetPath != "" && state.TargetPath != "" && !samePath(targetPath, state.TargetPath) {
			uploadChunksMu.Unlock()
			return nil, errors.New("upload target path does not match session")
		}
		if err := removeUploadFileLocked(uploadID); err != nil {
			uploadChunksMu.Unlock()
			return nil, err
		}
		uploadChunksMu.Unlock()
		return json.Marshal(map[string]any{"cancelled": true})
	}
	uploadChunksMu.Unlock()

	// A process restart can discard the in-memory state while leaving the part
	// file behind. Derive the deterministic path and remove only that file.
	if targetPath != "" {
		partPath := uploadPartPathFor(targetPath, uploadID)
		if err := os.Remove(partPath); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{"cancelled": true})
}

// commitFileUpload finalizes a set of raw HTTP upload streams. The control
// request carries metadata only; all file bytes have already been written to
// the private part file by upload_stream.
func commitFileUpload(args map[string]interface{}) (json.RawMessage, error) {
	uploadID := strings.TrimSpace(argString(args, "upload_id"))
	path := resolveFilePath(argString(args, "path"))
	totalSize := argInt64(args, "total_size")
	chunkSize := argInt64(args, "chunk_size")
	chunkCount := argInt64(args, "chunk_count")
	if uploadID == "" {
		return nil, errors.New("upload_id is required")
	}
	if path == string(filepath.Separator) || path == "." {
		return nil, errors.New("upload path must be a file")
	}
	if totalSize <= 0 || chunkCount <= 0 {
		return nil, errors.New("chunk_count and total_size are required")
	}
	if chunkSize == 0 {
		chunkSize = defaultTransferChunkSize
	}
	if chunkSize <= 0 || chunkSize > maxTransferChunkSize {
		return nil, fmt.Errorf("chunk_size must be between 1 and %d bytes", maxTransferChunkSize)
	}
	expectedChunkCount := uploadChunkCount(totalSize, chunkSize)
	if chunkCount != expectedChunkCount {
		return nil, fmt.Errorf("chunk_count %d does not match total_size %d", chunkCount, totalSize)
	}

	// Streams write independent offsets concurrently. Wait for every active
	// stream before inspecting and renaming the part file.
	waitUploadStreams(uploadID)
	writeLock := uploadWriteLock(uploadID)
	writeLock.Lock()
	defer func() {
		writeLock.Unlock()
		forgetUploadWriteLock(uploadID)
	}()

	uploadChunksMu.Lock()
	state, exists := uploadChunks[uploadID]
	if !exists {
		uploadChunksMu.Unlock()
		return nil, errors.New("unknown upload session")
	}
	if state.TargetPath != "" && !samePath(state.TargetPath, path) {
		uploadChunksMu.Unlock()
		return nil, errors.New("upload target path does not match session")
	}
	if state.ExpectedSize != 0 && state.ExpectedSize != totalSize {
		uploadChunksMu.Unlock()
		return nil, errors.New("upload total size does not match session")
	}
	if state.ChunkSize != 0 && state.ChunkSize != chunkSize {
		uploadChunksMu.Unlock()
		return nil, errors.New("upload chunk size does not match session")
	}
	if state.PartCount != 0 && state.PartCount != chunkCount {
		uploadChunksMu.Unlock()
		return nil, errors.New("upload chunk count does not match session")
	}
	if len(state.Parts) != int(chunkCount) {
		received := len(state.Parts)
		uploadChunksMu.Unlock()
		return nil, fmt.Errorf("upload incomplete: received %d of %d chunks", received, chunkCount)
	}
	partPath := state.TempPath
	uploadChunksMu.Unlock()
	if partPath == "" {
		return nil, errors.New("upload part file is missing")
	}

	partInfo, err := os.Stat(partPath)
	if err != nil {
		return nil, err
	}
	if partInfo.Size() < totalSize {
		return nil, fmt.Errorf("upload part file is %d bytes, want %d", partInfo.Size(), totalSize)
	}
	if partInfo.Size() > totalSize {
		if err := os.Truncate(partPath, totalSize); err != nil {
			return nil, err
		}
	}
	targetDir := filepath.Dir(path)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return nil, err
	}
	existing, err := replaceableFile(path)
	if err != nil {
		return nil, err
	}
	if err := preserveReplacementMetadata(partPath, existing); err != nil {
		return nil, err
	}
	if err := replaceFile(partPath, path); err != nil {
		return nil, err
	}
	if err := syncUploadDirectory(targetDir); err != nil {
		return nil, err
	}
	uploadChunksMu.Lock()
	delete(uploadChunks, uploadID)
	uploadChunksMu.Unlock()
	return json.Marshal(map[string]any{
		"received": totalSize,
		"final":    true,
		"offset":   totalSize,
	})
}

func describeFile(path string, symlink bool) (fileInfo, error) {
	var info os.FileInfo
	var err error
	if symlink {
		info, err = os.Lstat(path)
	} else {
		info, err = os.Stat(path)
	}
	if err != nil {
		return fileInfo{}, err
	}
	uid, gid, owner, group := fileOwnership(info)
	item := fileInfo{
		Name:       filepath.Base(path),
		Path:       virtualizeFilePath(path),
		IsDir:      info.IsDir(),
		IsSymlink:  symlink,
		Size:       info.Size(),
		Mode:       info.Mode().String(),
		ModeOctal:  fmt.Sprintf("%04o", info.Mode().Perm()),
		UID:        uid,
		GID:        gid,
		Owner:      owner,
		Group:      group,
		ModifiedAt: info.ModTime().UTC(),
	}
	if symlink {
		if target, linkErr := os.Readlink(path); linkErr == nil {
			item.Target = target
			if targetInfo, statErr := os.Stat(path); statErr == nil {
				item.IsDir = targetInfo.IsDir()
				item.Size = targetInfo.Size()
				item.Mode = targetInfo.Mode().String()
				item.ModeOctal = fmt.Sprintf("%04o", targetInfo.Mode().Perm())
				uid, gid, owner, group := fileOwnership(targetInfo)
				item.UID = uid
				item.GID = gid
				item.Owner = owner
				item.Group = group
				item.ModifiedAt = targetInfo.ModTime().UTC()
			}
		}
	}
	return item, nil
}

func matchFileContent(path, query, lowerQuery string) (searchMatch, bool) {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() || info.Size() > 10*1024*1024 {
		return searchMatch{}, false
	}
	file, err := os.Open(path)
	if err != nil {
		return searchMatch{}, false
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 64*1024), 1024*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := scanner.Text()
		if strings.Contains(strings.ToLower(line), lowerQuery) {
			text := line
			if len(text) > 300 {
				text = text[:300]
			}
			return searchMatch{
				Path: virtualizeFilePath(path),
				Line: lineNumber,
				Text: text,
			}, true
		}
	}
	return searchMatch{}, false
}

func resolveFilePath(path string) string {
	trimmed := strings.TrimSpace(path)
	if trimmed == "" {
		trimmed = "/"
	}
	if trimmed == "~" || strings.HasPrefix(trimmed, "~/") || strings.HasPrefix(trimmed, `~\`) {
		if home, err := os.UserHomeDir(); err == nil && home != "" {
			if trimmed == "~" {
				return resolveOSPath(home)
			}
			return resolveOSPath(filepath.Join(home, trimmed[2:]))
		}
	}
	resolved := filepath.Clean(trimmed)
	return resolveOSPath(resolved)
}

func virtualizeFilePath(path string) string {
	native := filepath.ToSlash(path)
	if runtime.GOOS != "windows" {
		return native
	}

	volume := filepath.VolumeName(native)
	if volume == "" {
		return native
	}
	drive := strings.TrimSuffix(volume, ":")
	rest := strings.TrimPrefix(native[len(volume):], "/")
	if rest == "" {
		return "/" + strings.ToUpper(drive)
	}
	return "/" + strings.ToUpper(drive) + "/" + rest
}

func isSymlink(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSymlink != 0
}

func argString(args map[string]interface{}, key string) string {
	if args == nil {
		return ""
	}
	value, _ := args[key].(string)
	return value
}

func argBool(args map[string]interface{}, key string) bool {
	value, _ := args[key].(bool)
	return value
}

func argInt64(args map[string]interface{}, key string) int64 {
	if args == nil {
		return 0
	}
	switch number := args[key].(type) {
	case float64:
		return int64(number)
	case float32:
		return int64(number)
	case int:
		return int64(number)
	case int8:
		return int64(number)
	case int16:
		return int64(number)
	case int32:
		return int64(number)
	case int64:
		return number
	case uint:
		return int64(number)
	case uint8:
		return int64(number)
	case uint16:
		return int64(number)
	case uint32:
		return int64(number)
	case uint64:
		return int64(number)
	case json.Number:
		parsed, _ := number.Int64()
		return parsed
	default:
		return 0
	}
}

func parseMode(value string) (uint32, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return 0, errors.New("mode is required")
	}
	parsed, err := strconv.ParseUint(strings.TrimPrefix(value, "0o"), 8, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid octal mode: %s", value)
	}
	return uint32(parsed), nil
}
