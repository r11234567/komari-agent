//go:build linux

package files

import (
	"errors"
	"fmt"
	"os"
	"time"

	"golang.org/x/sys/unix"
)

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
