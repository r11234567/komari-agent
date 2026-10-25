//go:build unix && !linux

package files

import (
	"errors"
	"os"
)

func renameWithoutOverwrite(source, destination string) error {
	info, err := os.Lstat(source)
	if err != nil {
		return err
	}
	if info.IsDir() {
		return errors.New("non-overwriting directory moves are unsupported on this platform")
	}
	if err := os.Link(source, destination); err != nil {
		return err
	}
	return os.Remove(source)
}
