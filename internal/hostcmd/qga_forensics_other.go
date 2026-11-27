//go:build !linux

package hostcmd

import (
	"errors"
	"io"
)

func runQGAForensics(_ []string, _ io.Writer) error {
	return errors.New("QGA forensics requires a Linux systemd installation")
}
