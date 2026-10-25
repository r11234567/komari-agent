//go:build !windows

package terminal

import (
	"fmt"
	"github.com/creack/pty"
	"github.com/komari-monitor/komari-agent/core/osidentity"
	"os/exec"
	"path/filepath"
)

func newTerminalAs(username, shell, directory string) (*terminalImpl, error) {
	identity, err := osidentity.Resolve(username)
	if err != nil {
		return nil, err
	}
	if shell == "" {
		shell = "/bin/sh"
	}
	if !filepath.IsAbs(shell) || filepath.Clean(shell) != shell {
		return nil, fmt.Errorf("shell must be an absolute path")
	}
	cmd := exec.Command(shell, "-l")
	if err := identity.Configure(cmd, directory); err != nil {
		return nil, err
	}
	tty, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start terminal as %s: %w", username, err)
	}
	return &terminalImpl{shell: shell, workingDir: cmd.Dir, term: &unixTerminal{tty: tty, cmd: cmd}}, nil
}
