//go:build windows

package osidentity

import (
	"errors"
	"os/exec"
)

func (i *Identity) Configure(cmd *exec.Cmd, directory string) error {
	return errors.New("workspace OS identity isolation is not supported on Windows yet")
}
