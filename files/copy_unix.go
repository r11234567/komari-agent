//go:build linux || darwin || freebsd

package files

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"os"

	"golang.org/x/sys/unix"
)

func copyPathSafe(source, destination string, recursive, overwrite, removeSource bool) error {
	srcDir, srcName, err := openParentNoSymlinks(source, false, 0)
	if err != nil {
		return err
	}
	defer srcDir.Close()

	src, err := statNoFollowInDir(srcDir, srcName)
	if err != nil {
		return err
	}
	if src == nil {
		return &os.PathError{Op: "copy", Path: source, Err: os.ErrNotExist}
	}
	if src.Mode&unix.S_IFMT == unix.S_IFDIR {
		if !recursive {
			return errors.New("recursive is required to copy a directory")
		}
		if pathContains(source, destination) {
			return errors.New("cannot copy a directory into itself")
		}
	}

	dstDir, dstName, err := openParentNoSymlinks(destination, true, 0o755)
	if err != nil {
		return err
	}
	defer dstDir.Close()
	if err := copyEntryInDir(srcDir, srcName, src, dstDir, dstName, overwrite); err != nil {
		return err
	}
	if removeSource {
		return removeCopiedSource(srcDir, srcName, src)
	}
	return nil
}

func removeCopiedSource(parent *os.File, name string, expected *unix.Stat_t) error {
	stage, cleanup, err := createCopyStage(parent)
	if err != nil {
		return err
	}
	defer stage.Close()
	keep := false
	defer func() {
		if !keep {
			cleanup()
		}
	}()
	// Detach the entry before checking its identity and doing any deletion.
	// An entry concurrently installed at the old name cannot be removed here.
	if err := renameInDir(parent, name, stage, "entry", true); err != nil {
		return err
	}
	actual, err := statNoFollowInDir(stage, "entry")
	if err != nil || actual == nil || !sameEntry(expected, actual) {
		if restoreErr := renameInDir(stage, "entry", parent, name, false); restoreErr != nil {
			keep = true
			return errors.Join(err, fmt.Errorf("source changed during move and is retained in %q: %w", stage.Name(), restoreErr))
		}
		return errors.Join(err, errors.New("source changed during cross-device move"))
	}
	if err := unlinkatSafe(stage, "entry", true); err != nil {
		keep = true
		return fmt.Errorf("remove copied source retained in %q: %w", stage.Name(), err)
	}
	return nil
}

func sameEntry(left, right *unix.Stat_t) bool {
	return left.Dev == right.Dev && left.Ino == right.Ino
}

func openCopySource(parent *os.File, name string, expected *unix.Stat_t, flags int) (*os.File, os.FileInfo, error) {
	file, err := openInDir(parent, name, flags|unix.O_RDONLY|unix.O_NONBLOCK|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}
	info, err := file.Stat()
	if err == nil {
		var actual unix.Stat_t
		err = unix.Fstat(int(file.Fd()), &actual)
		if err == nil && (!sameEntry(expected, &actual) || expected.Mode&unix.S_IFMT != actual.Mode&unix.S_IFMT) {
			err = errors.New("source changed during copy")
		}
	}
	if err != nil {
		_ = file.Close()
		return nil, nil, err
	}
	return file, info, nil
}

func copyEntryInDir(srcDir *os.File, srcName string, src *unix.Stat_t, dstDir *os.File, dstName string, overwrite bool) error {
	dst, err := statNoFollowInDir(dstDir, dstName)
	if err != nil {
		return err
	}
	if dst != nil {
		if !overwrite {
			return &os.PathError{Op: "copy", Path: dstName, Err: os.ErrExist}
		}
		if sameEntry(src, dst) {
			return errors.New("source and destination are the same file")
		}
	}

	switch src.Mode & unix.S_IFMT {
	case unix.S_IFDIR:
		return copyDirectoryInDir(srcDir, srcName, src, dstDir, dstName, dst, overwrite)
	case unix.S_IFREG:
		if dst != nil && dst.Mode&unix.S_IFMT != unix.S_IFREG {
			return errors.New("cannot replace a non-regular destination with a file")
		}
		return copyRegularInDir(srcDir, srcName, src, dstDir, dstName, overwrite)
	case unix.S_IFLNK:
		if dst != nil && dst.Mode&unix.S_IFMT == unix.S_IFDIR {
			return errors.New("cannot replace destination directory with a symlink")
		}
		return copySymlinkInDir(srcDir, srcName, dstDir, dstName, overwrite)
	default:
		return errors.New("cannot copy a non-regular file")
	}
}

func copyDirectoryInDir(srcDir *os.File, srcName string, src *unix.Stat_t, dstDir *os.File, dstName string, dst *unix.Stat_t, overwrite bool) error {
	input, info, err := openCopySource(srcDir, srcName, src, unix.O_DIRECTORY)
	if err != nil {
		return err
	}
	defer input.Close()

	if dst == nil {
		err = tempFailureRetry(func() error { return unix.Mkdirat(int(dstDir.Fd()), dstName, 0o700) })
		if err != nil {
			return err
		}
	} else if dst.Mode&unix.S_IFMT != unix.S_IFDIR {
		return errors.New("cannot copy a directory through a non-directory destination")
	}
	output, err := openInDir(dstDir, dstName, unix.O_RDONLY|unix.O_DIRECTORY, 0)
	if err != nil {
		return err
	}
	defer output.Close()
	var actual unix.Stat_t
	if err := unix.Fstat(int(output.Fd()), &actual); err != nil {
		return err
	}
	if sameEntry(src, &actual) || (dst != nil && !sameEntry(dst, &actual)) ||
		(dst == nil && (actual.Uid != uint32(os.Geteuid()) || actual.Mode&0o777 != 0o700)) {
		return errors.New("destination changed during copy")
	}

	for {
		names, readErr := input.Readdirnames(128)
		for _, name := range names {
			entry, err := statNoFollowInDir(input, name)
			if err != nil {
				return err
			}
			if entry == nil {
				return &os.PathError{Op: "copy", Path: name, Err: os.ErrNotExist}
			}
			if err := copyEntryInDir(input, name, entry, output, name, overwrite); err != nil {
				return err
			}
		}
		if errors.Is(readErr, io.EOF) {
			break
		}
		if readErr != nil {
			return readErr
		}
	}

	// Apply metadata after copying children so their creation cannot change
	// the copied timestamp or be blocked by the source directory's mode.
	if err := output.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	return setCopiedTime(output, info.ModTime())
}

func createCopyStage(parent *os.File) (*os.File, func(), error) {
	for i := 0; i < 64; i++ {
		name := ".komari-copy-" + rand.Text()
		err := tempFailureRetry(func() error { return unix.Mkdirat(int(parent.Fd()), name, 0o700) })
		if errors.Is(err, unix.EEXIST) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		stage, err := openPrivateDirIn(parent, name)
		if err != nil {
			return nil, nil, err
		}
		return stage, func() {
			_ = unix.Unlinkat(int(stage.Fd()), "entry", 0)
			_ = stage.Close()
			_ = unix.Unlinkat(int(parent.Fd()), name, unix.AT_REMOVEDIR)
		}, nil
	}
	return nil, nil, errors.New("exhausted temporary directory names")
}

func copyRegularInDir(srcDir *os.File, srcName string, src *unix.Stat_t, dstDir *os.File, dstName string, overwrite bool) error {
	input, info, err := openCopySource(srcDir, srcName, src, 0)
	if err != nil {
		return err
	}
	defer input.Close()
	stage, cleanup, err := createCopyStage(dstDir)
	if err != nil {
		return err
	}
	defer cleanup()
	output, err := openInDir(stage, "entry", unix.O_WRONLY|unix.O_CREAT|unix.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer output.Close()
	if _, err := io.Copy(output, input); err != nil {
		return err
	}
	if err := output.Chmod(info.Mode().Perm()); err != nil {
		return err
	}
	if err := setCopiedTime(output, info.ModTime()); err != nil {
		return err
	}
	if err := output.Sync(); err != nil {
		return err
	}
	if err := output.Close(); err != nil {
		return err
	}
	return renameInDir(stage, "entry", dstDir, dstName, overwrite)
}

func copySymlinkInDir(srcDir *os.File, srcName string, dstDir *os.File, dstName string, overwrite bool) error {
	var buf [4096]byte
	var length int
	err := tempFailureRetry(func() error {
		var err error
		length, err = unix.Readlinkat(int(srcDir.Fd()), srcName, buf[:])
		return err
	})
	if err != nil {
		return err
	}
	if length == len(buf) {
		return fmt.Errorf("symbolic link %q is too long", srcName)
	}
	target := string(buf[:length])
	if !overwrite {
		return tempFailureRetry(func() error { return unix.Symlinkat(target, int(dstDir.Fd()), dstName) })
	}
	stage, cleanup, err := createCopyStage(dstDir)
	if err != nil {
		return err
	}
	defer cleanup()
	if err := unix.Symlinkat(target, int(stage.Fd()), "entry"); err != nil {
		return err
	}
	return renameInDir(stage, "entry", dstDir, dstName, true)
}
