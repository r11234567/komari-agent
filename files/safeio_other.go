//go:build !linux

package files

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func openRegularNoSymlinks(path string, flags int, mode uint32) (*os.File, os.FileInfo, error) {
	if linfo, lerr := os.Lstat(path); lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("cannot operate on a symlink target")
	}
	file, err := os.OpenFile(path, flags, fs.FileMode(mode))
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	if !info.Mode().IsRegular() {
		_ = file.Close()
		return nil, nil, errors.New("cannot operate on a non-regular file")
	}
	return file, info, nil
}

func deletePathSafe(path string, recursive bool) error {
	if _, err := os.Lstat(path); err != nil {
		return err
	}
	if recursive {
		return os.RemoveAll(path)
	}
	return os.Remove(path)
}

func mkdirSafe(path string, mode fs.FileMode) error {
	return os.MkdirAll(path, mode)
}

func chmodSafe(path string, mode fs.FileMode) error {
	if linfo, err := os.Lstat(path); err != nil {
		return err
	} else if linfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing chmod on symlink %q", path)
	}
	return os.Chmod(path, mode)
}

func chownSafe(path string, uid, gid int) error {
	return changeOwnership(path, uid, gid)
}

func writeAtomicFileSafe(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	cleanup := true
	defer func() {
		_ = tmp.Close()
		if cleanup {
			_ = os.Remove(tmpName)
		}
	}()
	if _, err := tmp.Write(data); err != nil {
		return err
	}
	if err := tmp.Chmod(perm); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := replaceFile(tmpName, path); err != nil {
		return err
	}
	cleanup = false
	return syncUploadDirectory(dir)
}

func readRegularFileSafe(path string, maxBytes int64) ([]byte, error) {
	file, info, err := openRegularNoSymlinks(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum %d bytes", path, maxBytes)
	}
	return os.ReadFile(path)
}

func createEmptyRegularFileSafe(path string, hasMode bool, requestedMode fs.FileMode) error {
	directory := filepath.Dir(path)
	if err := os.MkdirAll(directory, 0o755); err != nil {
		return err
	}
	existing, err := replaceableFile(path)
	if err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".komari-empty-*")
	if err != nil {
		return err
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
		return err
	}
	if hasMode {
		if err := os.Chmod(temporaryName, requestedMode); err != nil {
			return err
		}
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := replaceFile(temporaryName, path); err != nil {
		return err
	}
	removeTemporary = false
	return syncUploadDirectory(directory)
}

func openUploadPartSafe(partPath string, truncate bool) (*os.File, error) {
	flags := os.O_WRONLY | os.O_CREATE
	if truncate {
		flags |= os.O_TRUNC
	}
	return os.OpenFile(partPath, flags, 0o600)
}

func commitUploadPartSafe(partPath, targetPath string, totalSize int64) error {
	partInfo, err := os.Stat(partPath)
	if err != nil {
		return err
	}
	if partInfo.Size() < totalSize {
		return fmt.Errorf("upload part file is %d bytes, want %d", partInfo.Size(), totalSize)
	}
	if partInfo.Size() > totalSize {
		if err := os.Truncate(partPath, totalSize); err != nil {
			return err
		}
	}
	targetDir := filepath.Dir(targetPath)
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	existing, err := replaceableFile(targetPath)
	if err != nil {
		return err
	}
	if err := preserveReplacementMetadata(partPath, existing); err != nil {
		return err
	}
	if err := replaceFile(partPath, targetPath); err != nil {
		return err
	}
	return syncUploadDirectory(targetDir)
}

func moveSameDeviceSafe(source, destination string, overwrite bool) error {
	if !overwrite {
		if _, err := os.Lstat(destination); err == nil {
			return fmt.Errorf("destination already exists: %s", destination)
		} else if !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.MkdirAll(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	rename := replaceFile
	if !overwrite {
		rename = renameWithoutOverwrite
	}
	return rename(source, destination)
}
