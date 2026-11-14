//go:build !windows

package server

import (
	"errors"
	"os"
	"os/exec"
	"syscall"
	"time"

	"github.com/komari-monitor/komari-agent/core/osidentity"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
)

func configureExecutionIdentity(command *exec.Cmd, spec *execv1.ExecutionSpec) error {
	identity, err := osidentity.ResolveExecution(spec.RunAsRoot)
	if err != nil {
		return err
	}
	directory := spec.WorkingDirectory
	if directory == "" && !spec.RunAsRoot {
		directory = "/"
	}
	if err := identity.Configure(command, directory); err != nil {
		return err
	}
	if command.SysProcAttr == nil {
		command.SysProcAttr = &syscall.SysProcAttr{}
	}
	command.SysProcAttr.Setpgid = true
	command.Cancel = func() error {
		err := syscall.Kill(-command.Process.Pid, syscall.SIGKILL)
		if errors.Is(err, syscall.ESRCH) {
			return os.ErrProcessDone
		}
		return err
	}
	command.WaitDelay = 2 * time.Second
	if !spec.RunAsRoot {
		return osidentity.RestrictPrivilegeGain(command)
	}
	return nil
}
