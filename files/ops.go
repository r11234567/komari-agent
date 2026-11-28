package files

import (
	"bufio"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
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
	InstanceID string    `json:"instance_id,omitempty"`
}

type uploadChunkState struct {
	WorkspaceID  string
	Size         int64
	ExpectedSize int64
	ChunkSize    int64
	TargetPath   string
	Parts        map[int64]struct{}
	PartCount    int64
	TempPath     string
	PartIdentity string
	CreatedAt    time.Time
}

type uploadManifest struct {
	UploadID     string    `json:"upload_id"`
	WorkspaceID  string    `json:"workspace_id,omitempty"`
	TargetPath   string    `json:"target_path"`
	PartIdentity string    `json:"part_identity,omitempty"`
	ExpectedSize int64     `json:"expected_size"`
	ChunkSize    int64     `json:"chunk_size"`
	PartCount    int64     `json:"part_count"`
	Received     int64     `json:"received"`
	Parts        []int64   `json:"parts"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

var (
	uploadChunksMu sync.Mutex
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
	return createFileWithMode(path, "")
}

func octalFileMode(parsed uint32) fs.FileMode {
	mode := fs.FileMode(parsed & 0o777)
	// Go stores special permission flags separately from Unix octal bits.
	if parsed&0o4000 != 0 {
		mode |= os.ModeSetuid
	}
	if parsed&0o2000 != 0 {
		mode |= os.ModeSetgid
	}
	if parsed&0o1000 != 0 {
		mode |= os.ModeSticky
	}
	return mode
}

func createFileWithMode(path, modeValue string) (json.RawMessage, error) {
	// Validate before creating directories or replacing existing contents.
	hasMode := strings.TrimSpace(modeValue) != ""
	var requestedMode fs.FileMode
	if hasMode {
		parsed, err := parseMode(modeValue)
		if err != nil {
			return nil, err
		}
		if parsed > 0o7777 {
			return nil, fmt.Errorf("invalid octal mode: %s", modeValue)
		}
		requestedMode = octalFileMode(parsed)
	}
	path = resolveFilePath(path)
	if path == string(filepath.Separator) || path == "." {
		return nil, errors.New("file path is required")
	}
	if err := createEmptyRegularFileSafe(path, hasMode, requestedMode); err != nil {
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
	if err := mkdirSafe(path, mode); err != nil {
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
	if err := deletePathSafe(cleaned, recursive); err != nil {
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
	if err := moveSameDeviceSafe(source, destination, overwrite); err != nil {
		if !isCrossDeviceRename(err) {
			return nil, err
		}
		if err := copyPathSafe(source, destination, true, overwrite, true); err != nil {
			return nil, err
		}
	}
	return json.Marshal(map[string]any{"moved": true})
}

func isCrossDeviceRename(err error) bool {
	if runtime.GOOS == "windows" {
		return errors.Is(err, syscall.Errno(17)) // ERROR_NOT_SAME_DEVICE
	}
	return errors.Is(err, syscall.EXDEV)
}

func copyPath(source, destination string, recursive, overwrite bool) (json.RawMessage, error) {
	source = resolveFilePath(source)
	destination = resolveFilePath(destination)
	if samePath(source, destination) {
		return nil, errors.New("source and destination are the same")
	}
	if err := copyPathSafe(source, destination, recursive, overwrite, false); err != nil {
		return nil, err
	}
	return json.Marshal(map[string]any{"copied": true})
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
	if mode > 0o7777 {
		return nil, fmt.Errorf("invalid octal mode: %s", modeValue)
	}
	if err := chmodSafe(path, octalFileMode(mode)); err != nil {
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
	if err := chownSafe(path, uid, gid); err != nil {
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
	return 1 + (size-1)/chunkSize
}

func uploadPartPathFor(targetPath, uploadID string) string {
	return filepath.Join(uploadStagePath(targetPath, uploadID), "part")
}

func uploadManifestPathFor(targetPath, uploadID string) string {
	return filepath.Join(uploadStagePath(targetPath, uploadID), "manifest.json")
}

func uploadStagePath(targetPath, uploadID string) string {
	digest := sha256.Sum256([]byte(filepath.Base(targetPath) + "\x00" + uploadID))
	return filepath.Join(filepath.Dir(targetPath), fmt.Sprintf(".komari-upload-%x", digest[:16]))
}

func cloneUploadStateLocked(state uploadChunkState) uploadChunkState {
	cloned := state
	cloned.Parts = make(map[int64]struct{}, len(state.Parts))
	for idx := range state.Parts {
		cloned.Parts[idx] = struct{}{}
	}
	return cloned
}

func saveUploadManifest(uploadID string, state uploadChunkState) error {
	if uploadID == "" || state.TargetPath == "" {
		return nil
	}
	parts := make([]int64, 0, len(state.Parts))
	for idx := range state.Parts {
		parts = append(parts, idx)
	}
	sort.Slice(parts, func(i, j int) bool { return parts[i] < parts[j] })
	manifest := uploadManifest{
		UploadID:     uploadID,
		WorkspaceID:  state.WorkspaceID,
		TargetPath:   state.TargetPath,
		PartIdentity: state.PartIdentity,
		ExpectedSize: state.ExpectedSize,
		ChunkSize:    state.ChunkSize,
		PartCount:    state.PartCount,
		Received:     state.Size,
		Parts:        parts,
		CreatedAt:    state.CreatedAt,
		UpdatedAt:    time.Now().UTC(),
	}
	encoded, err := json.Marshal(manifest)
	if err != nil {
		return err
	}
	return writeAtomicFileSafe(uploadManifestPathFor(state.TargetPath, uploadID), encoded, 0o600, state.PartIdentity)
}

func restoreUploadSessionLocked(scope, targetPath, uploadID string) (uploadChunkState, bool, error) {
	if state, exists := uploadChunks[uploadID]; exists {
		if state.WorkspaceID != scope {
			return uploadChunkState{}, false, errors.New("upload session belongs to another workspace")
		}
		return state, true, nil
	}
	if strings.TrimSpace(targetPath) == "" {
		return uploadChunkState{}, false, nil
	}
	manifestPath := uploadManifestPathFor(targetPath, uploadID)
	raw, err := readRegularFileSafe(manifestPath, 4<<20)
	if err != nil {
		if os.IsNotExist(err) {
			return uploadChunkState{}, false, nil
		}
		return uploadChunkState{}, false, err
	}
	var manifest uploadManifest
	if err := json.Unmarshal(raw, &manifest); err != nil {
		return uploadChunkState{}, false, fmt.Errorf("corrupt upload manifest: %w", err)
	}
	if manifest.UploadID != uploadID {
		return uploadChunkState{}, false, errors.New("upload manifest id mismatch")
	}
	if manifest.WorkspaceID != scope {
		return uploadChunkState{}, false, errors.New("upload session belongs to another workspace")
	}
	if !samePath(manifest.TargetPath, targetPath) {
		return uploadChunkState{}, false, errors.New("upload target path does not match session")
	}
	if manifest.ChunkSize <= 0 || manifest.ChunkSize > maxTransferChunkSize ||
		manifest.ExpectedSize <= 0 || manifest.PartCount != uploadChunkCount(manifest.ExpectedSize, manifest.ChunkSize) ||
		(len(manifest.Parts) == 0 && manifest.Received != 0) {
		return uploadChunkState{}, false, errors.New("invalid upload manifest geometry")
	}
	partPath := uploadPartPathFor(targetPath, uploadID)
	partFile, err := openUploadPartSafe(partPath, false)
	if err != nil {
		return uploadChunkState{}, false, err
	}
	defer partFile.Close()
	partIdentity := manifest.PartIdentity
	if partIdentity == "" && (runtime.GOOS == "darwin" || runtime.GOOS == "freebsd") {
		// Older BSD workers did not persist an identity. The new opener has
		// already verified the part and stage are private and worker-owned.
		partIdentity, err = uploadPartIdentity(partFile)
		if err != nil {
			return uploadChunkState{}, false, err
		}
	}
	if err := checkUploadPartIdentity(partFile, partIdentity); err != nil {
		return uploadChunkState{}, false, err
	}
	partInfo, err := partFile.Stat()
	if err != nil {
		return uploadChunkState{}, false, err
	}

	parts := make(map[int64]struct{}, len(manifest.Parts))
	var received int64
	for _, idx := range manifest.Parts {
		if idx < 0 || idx >= manifest.PartCount {
			return uploadChunkState{}, false, errors.New("invalid recorded upload chunk")
		}
		if _, duplicate := parts[idx]; duplicate {
			return uploadChunkState{}, false, errors.New("duplicate recorded upload chunk")
		}
		offset := idx * manifest.ChunkSize
		received = max(received, offset+min(manifest.ChunkSize, manifest.ExpectedSize-offset))
		parts[idx] = struct{}{}
	}
	if received != manifest.Received || partInfo.Size() < received {
		return uploadChunkState{}, false, errors.New("upload manifest does not match staged length")
	}
	state := uploadChunkState{
		WorkspaceID:  manifest.WorkspaceID,
		Size:         manifest.Received,
		ExpectedSize: manifest.ExpectedSize,
		ChunkSize:    manifest.ChunkSize,
		TargetPath:   manifest.TargetPath,
		Parts:        parts,
		PartCount:    manifest.PartCount,
		TempPath:     partPath,
		PartIdentity: partIdentity,
		CreatedAt:    manifest.CreatedAt,
	}
	uploadChunks[uploadID] = state
	return state, true, nil
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
	if err := removeUploadStage(uploadStagePath(state.TargetPath, uploadID), state.PartIdentity); err != nil {
		return err
	}
	delete(uploadChunks, uploadID)
	return nil
}

func cancelFileUpload(args map[string]interface{}) (json.RawMessage, error) {
	return cancelFileUploadScoped("", args)
}

func cancelFileUploadScoped(scope string, args map[string]interface{}) (json.RawMessage, error) {
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
	defer writeLock.Unlock()
	targetPath := strings.TrimSpace(argString(args, "path"))
	if targetPath != "" {
		targetPath = resolveFilePath(targetPath)
	}

	uploadChunksMu.Lock()
	state, exists, restoreErr := restoreUploadSessionLocked(scope, targetPath, uploadID)
	if restoreErr != nil {
		uploadChunksMu.Unlock()
		return nil, restoreErr
	}
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

	return json.Marshal(map[string]any{"cancelled": true})
}

// commitFileUpload finalizes a set of raw HTTP upload streams. The control
// request carries metadata only; all file bytes have already been written to
// the private part file by upload_stream.
func commitFileUpload(args map[string]interface{}) (json.RawMessage, error) {
	return commitFileUploadScoped("", args)
}

func commitFileUploadScoped(scope string, args map[string]interface{}) (json.RawMessage, error) {
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
	defer writeLock.Unlock()

	uploadChunksMu.Lock()
	state, exists, restoreErr := restoreUploadSessionLocked(scope, path, uploadID)
	if restoreErr != nil {
		uploadChunksMu.Unlock()
		return nil, restoreErr
	}
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
	partIdentity := state.PartIdentity
	uploadChunksMu.Unlock()
	if partPath == "" {
		return nil, errors.New("upload part file is missing")
	}

	if err := commitUploadPartSafe(partPath, path, totalSize, partIdentity); err != nil {
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
	if !symlink && info.Mode().IsRegular() {
		item.InstanceID = fileInstanceID(info)
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
	file, info, err := openRegularNoSymlinks(path, os.O_RDONLY, 0)
	if err != nil {
		return searchMatch{}, false
	}
	defer file.Close()
	if info.IsDir() || info.Size() > 10*1024*1024 {
		return searchMatch{}, false
	}
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
