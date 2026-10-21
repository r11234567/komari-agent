//go:build linux

package hostcmd

import (
	"fmt"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"golang.org/x/sys/unix"
	"os"
)

func acquireHostLock() (func(), error) {
	if err := ensureTrustedDir("/var/lib/komari-host"); err != nil {
		return nil, err
	}
	path := "/var/lib/komari-host/.operations.lock"
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CREAT|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	if err = hostops.TrustedPath(path); err != nil {
		f.Close()
		return nil, err
	}
	if err = unix.Flock(fd, unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("another host operation is running: %w", err)
	}
	return func() { _ = unix.Flock(fd, unix.LOCK_UN); _ = f.Close() }, nil
}
