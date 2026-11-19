//go:build windows

package server

import (
	"errors"
	"os"
	"os/exec"

	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
)

func configureExecutionIdentity(command *exec.Cmd, spec *execv1.ExecutionSpec) error {
	if spec.RunAsRoot {
		return errors.New("root execution is unavailable on Windows")
	}
	command.Dir = spec.WorkingDirectory
	command.Env = os.Environ()
	return nil
}
