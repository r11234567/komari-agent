//go:build !linux && !windows

package rescue

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
)

func isPrivileged() bool { return os.Geteuid() == 0 }

func ensureRuntimeOwnership(string, ActionConfig) error { return nil }

func platformCommand(ctx context.Context, name string, arguments ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func restartAgent(context.Context, ActionConfig) (ActionResult, error) {
	return ActionResult{}, errors.New("rescue service restart is supported only on Linux and Windows")
}

func repairFirewall(context.Context, ActionConfig) (ActionResult, error) {
	return ActionResult{}, errors.New("rescue firewall repair is supported only on Linux and Windows")
}
