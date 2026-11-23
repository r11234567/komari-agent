package files

import (
	"os"

	"golang.org/x/sys/unix"
)

func renameInDir(src *os.File, srcName string, dst *os.File, dstName string, overwrite bool) error {
	if !overwrite {
		return tempFailureRetry(func() error {
			return unix.RenameatxNp(int(src.Fd()), srcName, int(dst.Fd()), dstName, unix.RENAME_EXCL)
		})
	}
	return tempFailureRetry(func() error { return unix.Renameat(int(src.Fd()), srcName, int(dst.Fd()), dstName) })
}
