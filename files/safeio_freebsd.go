package files

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func renameInDir(src *os.File, srcName string, dst *os.File, dstName string, overwrite bool) error {
	if overwrite {
		return tempFailureRetry(func() error { return unix.Renameat(int(src.Fd()), srcName, int(dst.Fd()), dstName) })
	}
	info, err := statNoFollowInDir(src, srcName)
	if err != nil {
		return err
	}
	if info == nil {
		return &os.PathError{Op: "rename", Path: srcName, Err: os.ErrNotExist}
	}
	if info.Mode&unix.S_IFMT == unix.S_IFDIR {
		return errors.New("non-overwriting directory moves are unsupported on this platform")
	}
	if err := tempFailureRetry(func() error { return unix.Linkat(int(src.Fd()), srcName, int(dst.Fd()), dstName, 0) }); err != nil {
		return err
	}
	return tempFailureRetry(func() error { return unix.Unlinkat(int(src.Fd()), srcName, 0) })
}
