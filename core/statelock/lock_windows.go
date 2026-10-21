//go:build windows

package statelock

import (
	"errors"
	"golang.org/x/sys/windows"
	"os"
)

func openLock(path string) (*os.File, error) {
	if i, err := os.Lstat(path); err == nil && i.Mode()&os.ModeSymlink != 0 {
		return nil, errors.New("symlink state lock refused")
	}
	return os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
}
func lock(f *os.File) error {
	return windows.LockFileEx(windows.Handle(f.Fd()), windows.LOCKFILE_EXCLUSIVE_LOCK|windows.LOCKFILE_FAIL_IMMEDIATELY, 0, 1, 0, &windows.Overlapped{})
}
func unlock(f *os.File) {
	_ = windows.UnlockFileEx(windows.Handle(f.Fd()), 0, 1, 0, &windows.Overlapped{})
}
