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

func copyPathSafe(source, destination string, recursive, overwrite, removeSource bool) error {
	if err := copyEntry(source, destination, recursive, overwrite); err != nil {
		return err
	}
	if removeSource {
		return os.RemoveAll(source)
	}
	return nil
}

func copyEntry(source, destination string, recursive, overwrite bool) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		if !recursive {
			return errors.New("recursive is required to copy a directory")
		}
		if pathContains(source, destination) {
			return errors.New("cannot copy a directory into itself")
		}
		if err := copyDirectory(source, destination, overwrite); err != nil {
			return err
		}
		return nil
	}
	if info.Mode()&os.ModeSymlink != 0 {
		if err := copySymlink(source, destination, overwrite); err != nil {
			return err
		}
		return nil
	}
	if err := copyRegularFile(source, destination, overwrite); err != nil {
		return err
	}
	return nil
}

func copyRegularFile(source, destination string, overwrite bool) error {
	input, fdInfo, err := openRegularNoSymlinks(source, os.O_RDONLY, 0)
	if err != nil {
		return err
	}
	defer input.Close()
	if err := mkdirSafe(filepath.Dir(destination), 0o755); err != nil {
		return err
	}
	if existing, err := os.Lstat(destination); err == nil {
		if !overwrite {
			return fmt.Errorf("destination already exists: %s", destination)
		}
		if !existing.Mode().IsRegular() {
			return errors.New("cannot replace a non-regular destination with a file")
		}
		if os.SameFile(fdInfo, existing) {
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
	if err = output.Chmod(fdInfo.Mode().Perm()); err != nil {
		return err
	}
	if err = output.Sync(); err != nil {
		return err
	}
	if err = output.Close(); err != nil {
		return err
	}
	if err = os.Chtimes(output.Name(), fdInfo.ModTime(), fdInfo.ModTime()); err != nil {
		return err
	}
	return moveSameDeviceSafe(output.Name(), destination, overwrite)
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
		return copyRegularFile(path, target, overwrite)
	})
}
