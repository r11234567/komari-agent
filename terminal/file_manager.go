package terminal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"

	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	maxFileTransferSize = uint64(2 << 30)
	maxFileChunkSize    = 384 << 10
	downloadChunkSize   = 256 << 10
)

type uploadState struct {
	mu        sync.Mutex
	file      *os.File
	tempPath  string
	target    string
	expected  uint64
	received  uint64
	overwrite bool
	hash      hash.Hash
}

type FileManager struct {
	ctx     context.Context
	cancel  context.CancelFunc
	emit    func(*websshv1.FileEvent) error
	mu      sync.Mutex
	uploads map[string]*uploadState
}

func NewFileManager(parent context.Context, emit func(*websshv1.FileEvent) error) *FileManager {
	ctx, cancel := context.WithCancel(parent)
	return &FileManager{ctx: ctx, cancel: cancel, emit: emit, uploads: make(map[string]*uploadState)}
}

func (manager *FileManager) Close() {
	manager.cancel()
	manager.mu.Lock()
	uploads := manager.uploads
	manager.uploads = make(map[string]*uploadState)
	manager.mu.Unlock()
	for _, upload := range uploads {
		upload.mu.Lock()
		_ = upload.file.Close()
		_ = os.Remove(upload.tempPath)
		upload.mu.Unlock()
	}
}

func (manager *FileManager) Handle(command *websshv1.FileCommand) error {
	if command == nil || command.RequestId == "" {
		return errors.New("invalid file command")
	}
	switch command.Operation {
	case websshv1.FileOperation_FILE_OPERATION_LIST:
		return manager.list(command)
	case websshv1.FileOperation_FILE_OPERATION_MKDIR:
		return manager.mkdir(command)
	case websshv1.FileOperation_FILE_OPERATION_CREATE:
		return manager.create(command)
	case websshv1.FileOperation_FILE_OPERATION_RENAME:
		return manager.rename(command)
	case websshv1.FileOperation_FILE_OPERATION_COPY:
		return manager.copy(command)
	case websshv1.FileOperation_FILE_OPERATION_DELETE:
		return manager.remove(command)
	case websshv1.FileOperation_FILE_OPERATION_UPLOAD_START:
		return manager.startUpload(command)
	case websshv1.FileOperation_FILE_OPERATION_UPLOAD_CHUNK:
		return manager.uploadChunk(command)
	case websshv1.FileOperation_FILE_OPERATION_UPLOAD_FINISH:
		return manager.finishUpload(command)
	case websshv1.FileOperation_FILE_OPERATION_DOWNLOAD:
		go manager.download(command)
		return nil
	default:
		return manager.respond(command, nil, errors.New("unsupported file operation"))
	}
}

func (manager *FileManager) respond(command *websshv1.FileCommand, event *websshv1.FileEvent, err error) error {
	if event == nil {
		event = &websshv1.FileEvent{}
	}
	event.RequestId = command.RequestId
	event.Operation = command.Operation
	event.Success = err == nil
	if err != nil {
		event.Error = err.Error()
	}
	return manager.emit(event)
}

func normalizeFilePath(value string) (string, error) {
	if strings.ContainsRune(value, '\x00') {
		return "", errors.New("invalid path")
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return filesystemRoots()[0], nil
	}
	if !filepath.IsAbs(value) {
		value = filepath.Join(filesystemRoots()[0], value)
	}
	return filepath.Clean(value), nil
}

func isFilesystemRoot(path string) bool {
	cleaned := filepath.Clean(path)
	if filepath.Dir(cleaned) == cleaned {
		return true
	}
	for _, root := range filesystemRoots() {
		if strings.EqualFold(cleaned, filepath.Clean(root)) {
			return true
		}
	}
	return false
}

func (manager *FileManager) list(command *websshv1.FileCommand) error {
	path, err := normalizeFilePath(command.Path)
	if err == nil {
		err = rejectSymlinkPath(path)
	}
	if err != nil {
		return manager.respond(command, nil, err)
	}
	entries, err := os.ReadDir(path)
	if err != nil {
		return manager.respond(command, nil, err)
	}
	result := make([]*websshv1.FileEntry, 0, len(entries))
	for _, entry := range entries {
		info, infoErr := entry.Info()
		if infoErr != nil {
			continue
		}
		result = append(result, &websshv1.FileEntry{Name: entry.Name(), Path: filepath.Join(path, entry.Name()), Directory: entry.IsDir(), Size: uint64(max(info.Size(), 0)), ModifiedAt: timestamppb.New(info.ModTime())})
	}
	sort.Slice(result, func(left, right int) bool {
		if result[left].Directory != result[right].Directory {
			return result[left].Directory
		}
		return strings.ToLower(result[left].Name) < strings.ToLower(result[right].Name)
	})
	parent := filepath.Dir(path)
	if parent == path {
		parent = ""
	}
	return manager.respond(command, &websshv1.FileEvent{Entries: result, Parent: parent}, nil)
}

func (manager *FileManager) mkdir(command *websshv1.FileCommand) error {
	path, err := normalizeFilePath(command.Path)
	if err == nil {
		err = rejectSymlinkPath(filepath.Dir(path))
	}
	if err == nil {
		err = os.Mkdir(path, 0o755)
	}
	return manager.respond(command, nil, err)
}

func (manager *FileManager) create(command *websshv1.FileCommand) error {
	path, err := normalizeFilePath(command.Path)
	if err == nil {
		err = rejectSymlinkPath(filepath.Dir(path))
	}
	if err == nil {
		var file *os.File
		file, err = os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o644)
		if file != nil {
			err = errors.Join(err, file.Close())
		}
	}
	return manager.respond(command, nil, err)
}

func (manager *FileManager) rename(command *websshv1.FileCommand) error {
	source, err := normalizeFilePath(command.Path)
	if err == nil {
		err = rejectSymlinkPath(source)
	}
	if err == nil && isFilesystemRoot(source) {
		err = errors.New("filesystem roots cannot be renamed")
	}
	destination := ""
	if err == nil {
		destination, err = normalizeFilePath(command.Destination)
	}
	if err == nil {
		err = rejectSymlinkPath(filepath.Dir(destination))
	}
	if err == nil {
		if _, statErr := os.Lstat(destination); statErr == nil {
			err = errors.New("destination already exists")
		} else if !errors.Is(statErr, os.ErrNotExist) {
			err = statErr
		}
	}
	if err == nil {
		err = os.Rename(source, destination)
	}
	return manager.respond(command, nil, err)
}

func (manager *FileManager) copy(command *websshv1.FileCommand) error {
	source, err := normalizeFilePath(command.Path)
	if err != nil {
		return manager.respond(command, nil, err)
	}
	destination, err := normalizeFilePath(command.Destination)
	if err == nil {
		err = copyPath(source, destination)
	}
	return manager.respond(command, nil, err)
}

func copyPath(source, destination string) error {
	if isFilesystemRoot(source) || isFilesystemRoot(destination) {
		return errors.New("filesystem roots cannot be copied")
	}
	if err := rejectSymlinkPath(source); err != nil {
		return err
	}
	sourceInfo, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if sourceInfo.Mode()&os.ModeSymlink != 0 {
		return errors.New("symbolic links cannot be copied")
	}
	if _, err := os.Lstat(destination); err == nil {
		return errors.New("destination already exists")
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if symlink, err := pathHasSymlink(filepath.Dir(destination)); err != nil || symlink {
		if err != nil {
			return err
		}
		return errors.New("copy destinations cannot use symbolic links")
	}
	absSource, err := filepath.Abs(source)
	if err != nil {
		return err
	}
	absDestination, err := filepath.Abs(destination)
	if err != nil {
		return err
	}
	if sourceInfo.IsDir() {
		if pathContains(absSource, absDestination) {
			return errors.New("a directory cannot be copied into itself")
		}
		if err := validateCopyDirectory(source); err != nil {
			return err
		}
		return copyDirectory(source, destination)
	}
	if !sourceInfo.Mode().IsRegular() {
		return errors.New("only regular files and directories can be copied")
	}
	return copyRegularFile(source, destination, sourceInfo.Mode().Perm())
}

func pathHasSymlink(path string) (bool, error) {
	current, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	for {
		info, err := os.Lstat(current)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return false, err
		}
		if err == nil && info.Mode()&os.ModeSymlink != 0 {
			return true, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return false, nil
		}
		current = parent
	}
}

func rejectSymlinkPath(path string) error {
	symlink, err := pathHasSymlink(path)
	if err != nil {
		return err
	}
	if symlink {
		return errors.New("symbolic-link paths are not allowed")
	}
	return nil
}

func pathContains(parent, child string) bool {
	if runtime.GOOS == "windows" {
		parent, child = strings.ToLower(parent), strings.ToLower(child)
	}
	relative, err := filepath.Rel(parent, child)
	return err == nil && !filepath.IsAbs(relative) && (relative == "." || (relative != ".." && !strings.HasPrefix(relative, ".."+string(filepath.Separator))))
}

func validateCopyDirectory(source string) error {
	return filepath.WalkDir(source, func(_ string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return errors.New("directories containing symbolic links cannot be copied")
		}
		if !entry.IsDir() && !entry.Type().IsRegular() {
			return errors.New("directories containing special files cannot be copied")
		}
		return nil
	})
}

func copyDirectory(source, destination string) (err error) {
	sourceInfo, err := os.Stat(source)
	if err != nil {
		return err
	}
	if err := os.Mkdir(destination, sourceInfo.Mode().Perm()); err != nil {
		return err
	}
	complete := false
	defer func() {
		if !complete {
			err = errors.Join(err, os.RemoveAll(destination))
		}
	}()
	err = filepath.WalkDir(source, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || current == source {
			return walkErr
		}
		relative, err := filepath.Rel(source, current)
		if err != nil {
			return err
		}
		target := filepath.Join(destination, relative)
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return os.Mkdir(target, info.Mode().Perm())
		}
		return copyRegularFile(current, target, info.Mode().Perm())
	})
	complete = err == nil
	return err
}

func copyRegularFile(source, destination string, mode fs.FileMode) (err error) {
	input, err := os.Open(source)
	if err != nil {
		return err
	}
	defer input.Close()
	output, err := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	complete := false
	defer func() {
		err = errors.Join(err, output.Close())
		if !complete {
			err = errors.Join(err, os.Remove(destination))
		}
	}()
	if _, err = io.Copy(output, input); err == nil {
		err = output.Sync()
	}
	complete = err == nil
	return err
}

func (manager *FileManager) remove(command *websshv1.FileCommand) error {
	path, err := normalizeFilePath(command.Path)
	if err == nil {
		err = rejectSymlinkPath(path)
	}
	if err == nil && isFilesystemRoot(path) {
		err = errors.New("filesystem roots cannot be deleted")
	}
	if err == nil {
		info, statErr := os.Lstat(path)
		if statErr != nil {
			err = statErr
		} else if info.IsDir() && !command.Recursive {
			err = errors.New("directory deletion requires recursive confirmation")
		}
	}
	if err == nil {
		if command.Recursive {
			err = os.RemoveAll(path)
		} else {
			err = os.Remove(path)
		}
	}
	return manager.respond(command, nil, err)
}

func newTransferID() (string, error) {
	buffer := make([]byte, 16)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return hex.EncodeToString(buffer), nil
}

func (manager *FileManager) startUpload(command *websshv1.FileCommand) error {
	target, err := normalizeFilePath(command.Path)
	if err == nil {
		err = validateUploadTarget(target, command.Overwrite)
	}
	if err == nil && command.Size > maxFileTransferSize {
		err = fmt.Errorf("file exceeds the %d byte transfer limit", maxFileTransferSize)
	}
	var temporary *os.File
	if err == nil {
		temporary, err = os.CreateTemp(filepath.Dir(target), ".komari-upload-*")
	}
	if err != nil {
		return manager.respond(command, nil, err)
	}
	_ = temporary.Chmod(0o600)
	uploadID, err := newTransferID()
	if err != nil {
		_ = temporary.Close()
		_ = os.Remove(temporary.Name())
		return manager.respond(command, nil, err)
	}
	manager.mu.Lock()
	manager.uploads[uploadID] = &uploadState{file: temporary, tempPath: temporary.Name(), target: target, expected: command.Size, overwrite: command.Overwrite, hash: sha256.New()}
	manager.mu.Unlock()
	return manager.respond(command, &websshv1.FileEvent{UploadId: uploadID}, nil)
}

func (manager *FileManager) uploadChunk(command *websshv1.FileCommand) error {
	manager.mu.Lock()
	upload := manager.uploads[command.UploadId]
	manager.mu.Unlock()
	if upload == nil {
		return manager.respond(command, nil, errors.New("upload session not found"))
	}
	var err error
	if len(command.Data) > maxFileChunkSize {
		err = errors.New("upload chunk is too large")
	}
	upload.mu.Lock()
	if err == nil && upload.received+uint64(len(command.Data)) > upload.expected {
		err = errors.New("upload exceeds declared size")
	}
	if err == nil {
		_, err = upload.file.Write(command.Data)
	}
	if err == nil {
		upload.received += uint64(len(command.Data))
		_, _ = upload.hash.Write(command.Data)
	}
	received := upload.received
	upload.mu.Unlock()
	return manager.respond(command, &websshv1.FileEvent{UploadId: command.UploadId, Transferred: received}, err)
}

func (manager *FileManager) finishUpload(command *websshv1.FileCommand) error {
	manager.mu.Lock()
	upload := manager.uploads[command.UploadId]
	delete(manager.uploads, command.UploadId)
	manager.mu.Unlock()
	if upload == nil {
		return manager.respond(command, nil, errors.New("upload session not found"))
	}
	upload.mu.Lock()
	defer upload.mu.Unlock()
	cleanup := true
	defer func() {
		if cleanup {
			_ = upload.file.Close()
			_ = os.Remove(upload.tempPath)
		}
	}()
	if upload.received != upload.expected {
		return manager.respond(command, nil, errors.New("uploaded size does not match declared size"))
	}
	actualHash := hex.EncodeToString(upload.hash.Sum(nil))
	if command.Sha256 != "" && !strings.EqualFold(command.Sha256, actualHash) {
		return manager.respond(command, nil, errors.New("uploaded file checksum mismatch"))
	}
	if err := upload.file.Sync(); err != nil {
		return manager.respond(command, nil, err)
	}
	if err := upload.file.Close(); err != nil {
		return manager.respond(command, nil, err)
	}
	if err := validateUploadTarget(upload.target, upload.overwrite); err != nil {
		return manager.respond(command, nil, err)
	}
	if err := replaceUploadedFile(upload.tempPath, upload.target, upload.overwrite); err != nil {
		return manager.respond(command, nil, err)
	}
	cleanup = false
	return manager.respond(command, &websshv1.FileEvent{UploadId: command.UploadId, Sha256: actualHash, Size: upload.received, Transferred: upload.received, Complete: true}, nil)
}

func validateUploadTarget(target string, overwrite bool) error {
	if err := rejectSymlinkPath(filepath.Dir(target)); err != nil {
		return err
	}
	info, err := os.Lstat(target)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return errors.New("upload target must be a regular file")
	}
	if !overwrite {
		return errors.New("destination already exists")
	}
	return nil
}

func replaceUploadedFile(tempPath, target string, overwrite bool) error {
	if !overwrite || runtime.GOOS != "windows" {
		return os.Rename(tempPath, target)
	}
	backupID, err := newTransferID()
	if err != nil {
		return err
	}
	backup := filepath.Join(filepath.Dir(target), ".komari-backup-"+backupID)
	if err := os.Rename(target, backup); err != nil {
		return err
	}
	if err := os.Rename(tempPath, target); err != nil {
		return errors.Join(err, os.Rename(backup, target))
	}
	_ = os.Remove(backup)
	return nil
}

func (manager *FileManager) download(command *websshv1.FileCommand) {
	path, err := normalizeFilePath(command.Path)
	var file *os.File
	var info os.FileInfo
	if err == nil {
		info, err = os.Lstat(path)
	}
	if err == nil && (!info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0) {
		err = errors.New("only regular files can be downloaded")
	}
	if err == nil && uint64(info.Size()) > maxFileTransferSize {
		err = errors.New("file exceeds transfer limit")
	}
	if err == nil {
		file, err = os.Open(path)
	}
	if err != nil {
		_ = manager.respond(command, nil, err)
		return
	}
	defer file.Close()
	hasher := sha256.New()
	buffer := make([]byte, downloadChunkSize)
	var transferred uint64
	for {
		count, readErr := file.Read(buffer)
		if count > 0 {
			_, _ = hasher.Write(buffer[:count])
			transferred += uint64(count)
			if err := manager.respond(command, &websshv1.FileEvent{Size: uint64(info.Size()), Transferred: transferred, Data: append([]byte(nil), buffer[:count]...)}, nil); err != nil {
				return
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil || manager.ctx.Err() != nil {
			if readErr != nil {
				_ = manager.respond(command, nil, readErr)
			}
			return
		}
	}
	_ = manager.respond(command, &websshv1.FileEvent{Size: uint64(info.Size()), Transferred: transferred, Sha256: hex.EncodeToString(hasher.Sum(nil)), Complete: true}, nil)
}
