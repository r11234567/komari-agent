//go:build !linux && !darwin && !freebsd

package files

import (
	"errors"
	"fmt"
	"io"
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

func writeAtomicFileSafe(path string, data []byte, perm fs.FileMode, _ string) error {
	dir := filepath.Dir(path)
	if err := checkUploadStage(dir); err != nil {
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
	if err := checkUploadStage(filepath.Dir(path)); err != nil {
		return nil, err
	}
	file, info, err := openRegularNoSymlinks(path, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	if maxBytes > 0 && info.Size() > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum %d bytes", path, maxBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxBytes+1))
	if int64(len(data)) > maxBytes {
		return nil, fmt.Errorf("file %q exceeds maximum %d bytes", path, maxBytes)
	}
	return data, err
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

func checkUploadStage(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return errors.New("invalid upload staging directory")
	}
	return nil
}

func openUploadPartSafe(partPath string, create bool) (*os.File, error) {
	stage := filepath.Dir(partPath)
	if create {
		if err := os.Mkdir(stage, 0o700); err != nil && !os.IsExist(err) {
			return nil, err
		}
	}
	if err := checkUploadStage(stage); err != nil {
		return nil, err
	}
	if create {
		file, err := os.OpenFile(partPath, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil || !os.IsExist(err) {
			return file, err
		}
	}
	file, _, err := openRegularNoSymlinks(partPath, os.O_RDWR, 0)
	return file, err
}

func uploadPartIdentity(*os.File) (string, error)    { return "", nil }
func checkUploadPartIdentity(*os.File, string) error { return nil }

func removeUploadStage(path, _ string) error {
	if err := checkUploadStage(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	for _, name := range []string{"part", "manifest.json"} {
		if err := os.Remove(filepath.Join(path, name)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	return os.Remove(path)
}

func commitUploadPartSafe(partPath, targetPath string, totalSize int64, _ string) error {
	part, err := openUploadPartSafe(partPath, false)
	if err != nil {
		return err
	}
	defer part.Close()
	partInfo, err := part.Stat()
	if err != nil {
		return err
	}
	if partInfo.Size() < totalSize {
		return fmt.Errorf("upload part file is %d bytes, want %d", partInfo.Size(), totalSize)
	}
	if partInfo.Size() > totalSize {
		if err := part.Truncate(totalSize); err != nil {
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
	if err := part.Close(); err != nil {
		return err
	}
	if err := replaceFile(partPath, targetPath); err != nil {
		return err
	}
	_ = removeUploadStage(filepath.Dir(partPath), "")
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
