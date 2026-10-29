//go:build linux

package credentials

import (
	"context"
	"encoding/binary"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// WatchChanges observes the directory because credentials are atomically
// renamed. Events are hints only: consumers must securely reload and validate.
// No periodic network request or per-file polling is performed on Linux.
func WatchChanges(ctx context.Context, path string) (<-chan struct{}, error) {
	fd, err := unix.InotifyInit1(unix.IN_CLOEXEC | unix.IN_NONBLOCK)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), "credential-inotify")
	if _, err = unix.InotifyAddWatch(fd, filepath.Dir(path), unix.IN_MOVED_TO|unix.IN_CLOSE_WRITE|unix.IN_CREATE|unix.IN_DELETE|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF); err != nil {
		file.Close()
		return nil, err
	}
	changes := make(chan struct{}, 1)
	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			file.Close()
		case <-done:
		}
	}()
	go func() {
		defer close(done)
		defer close(changes)
		defer file.Close()
		buffer := make([]byte, 16384)
		for {
			// os.File integrates the nonblocking descriptor with Go's poller.
			n, err := file.Read(buffer)
			if err != nil {
				return
			}
			relevant := false
			for offset := 0; offset+16 <= n; {
				mask := binary.NativeEndian.Uint32(buffer[offset+4 : offset+8])
				size := int(binary.NativeEndian.Uint32(buffer[offset+12 : offset+16]))
				if offset+16+size > n {
					relevant = true
					break
				}
				name := strings.TrimRight(string(buffer[offset+16:offset+16+size]), "\x00")
				if name == filepath.Base(path) || mask&(unix.IN_Q_OVERFLOW|unix.IN_DELETE_SELF|unix.IN_MOVE_SELF) != 0 {
					relevant = true
				}
				offset += 16 + size
			}
			if relevant {
				select {
				case changes <- struct{}{}:
				default:
				}
			}
		}
	}()
	return changes, nil
}
