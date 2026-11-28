//go:build darwin || freebsd

package files

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

func openNoSymlinksFast(string, int, uint32) (*os.File, error) { return nil, nil }

func editAccessAttributes(*os.File) ([][]byte, error) { return nil, nil }

func preserveEditAccessAttributes(*os.File, [][]byte) error { return nil }

func setCopiedTime(file *os.File, t time.Time) error {
	tv := unix.NsecToTimeval(t.UnixNano())
	return tempFailureRetry(func() error { return unix.Futimes(int(file.Fd()), []unix.Timeval{tv, tv}) })
}
