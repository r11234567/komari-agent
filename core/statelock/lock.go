// Package statelock provides non-blocking process locks for daemon-owned state.
package statelock

import (
	"fmt"
	"os"
	"path/filepath"
)

func Acquire(path string) (func(), error) {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return nil, err
	}
	f, err := openLock(path)
	if err != nil {
		return nil, err
	}
	if err = lock(f); err != nil {
		f.Close()
		return nil, fmt.Errorf("state writer already active or lock unavailable: %w", err)
	}
	return func() { unlock(f); f.Close() }, nil
}
