//go:build linux

package files

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

var editAccessNames = [...]string{"system.posix_acl_access", "security.selinux"}

func editAccessAttributes(file *os.File) ([][]byte, error) {
	capabilities, err := readEditAttribute(file, "security.capability")
	if err != nil {
		return nil, err
	}
	if len(capabilities) != 0 {
		return nil, errors.New("cannot edit a file with Linux capabilities")
	}
	attributes := make([][]byte, len(editAccessNames))
	for i, name := range editAccessNames {
		attributes[i], err = readEditAttribute(file, name)
		if err != nil {
			return nil, err
		}
	}
	return attributes, nil
}

func preserveEditAccessAttributes(file *os.File, attributes [][]byte) error {
	for i, name := range editAccessNames {
		existing, err := readEditAttribute(file, name)
		if err != nil {
			return err
		}
		if bytes.Equal(existing, attributes[i]) {
			continue
		}
		if attributes[i] == nil {
			err = tempFailureRetry(func() error { return unix.Fremovexattr(int(file.Fd()), name) })
		} else {
			err = tempFailureRetry(func() error { return unix.Fsetxattr(int(file.Fd()), name, attributes[i], 0) })
		}
		if err != nil {
			return fmt.Errorf("preserve file attribute %s: %w", name, err)
		}
		if stored, err := readEditAttribute(file, name); err != nil || !bytes.Equal(stored, attributes[i]) {
			return fmt.Errorf("could not verify preservation of file attribute %s", name)
		}
	}
	return nil
}

func readEditAttribute(file *os.File, name string) ([]byte, error) {
	fd := int(file.Fd())
	var size int
	err := tempFailureRetry(func() (err error) {
		size, err = unix.Fgetxattr(fd, name, nil)
		return err
	})
	switch {
	case errors.Is(err, unix.ENODATA), errors.Is(err, unix.EOPNOTSUPP):
		return nil, nil
	case err != nil:
		return nil, fmt.Errorf("read file attribute %s: %w", name, err)
	}
	value := make([]byte, size)
	err = tempFailureRetry(func() (err error) {
		size, err = unix.Fgetxattr(fd, name, value)
		return err
	})
	if err != nil || size > len(value) {
		return nil, fmt.Errorf("file attribute %s changed while reading", name)
	}
	return value[:size], nil
}

func openat2NoSymlinks(path string, flags int, mode uint32) (int, error) {
	how := &unix.OpenHow{
		Flags:   uint64(flags | unix.O_CLOEXEC),
		Resolve: unix.RESOLVE_NO_SYMLINKS,
	}
	if flags&(unix.O_CREAT|unix.O_TMPFILE) != 0 {
		how.Mode = uint64(mode)
	}
	var fd int
	err := tempFailureRetry(func() error {
		var openErr error
		fd, openErr = unix.Openat2(unix.AT_FDCWD, path, how)
		return openErr
	})
	return fd, err
}

func renameInDir(srcDir *os.File, srcName string, dstDir *os.File, dstName string, overwrite bool) error {
	var flags uint
	if !overwrite {
		flags = unix.RENAME_NOREPLACE
	}
	return tempFailureRetry(func() error {
		return unix.Renameat2(int(srcDir.Fd()), srcName, int(dstDir.Fd()), dstName, flags)
	})
}

func openNoSymlinksFast(path string, flags int, mode uint32) (*os.File, error) {
	fd, err := openat2NoSymlinks(path, flags, mode)
	switch {
	case err == nil:
		return os.NewFile(uintptr(fd), path), nil
	case errors.Is(err, unix.ENOSYS), errors.Is(err, unix.EPERM):
		return nil, nil
	case errors.Is(err, unix.ELOOP):
		return nil, fmt.Errorf("refusing to traverse symlink at %q: %w", path, err)
	default:
		return nil, &os.PathError{Op: "openat2", Path: path, Err: err}
	}
}

func setCopiedTime(file *os.File, t time.Time) error {
	ts := unix.NsecToTimespec(t.UnixNano())
	err := tempFailureRetry(func() error {
		return unix.UtimesNanoAt(int(file.Fd()), "", []unix.Timespec{ts, ts}, unix.AT_EMPTY_PATH)
	})
	if errors.Is(err, unix.EINVAL) || errors.Is(err, unix.ENOENT) {
		tv := unix.NsecToTimeval(t.UnixNano())
		return tempFailureRetry(func() error { return unix.Futimes(int(file.Fd()), []unix.Timeval{tv, tv}) })
	}
	return err
}
