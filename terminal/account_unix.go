//go:build !windows

package terminal

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/creack/pty"
	"github.com/komari-monitor/komari-agent/core/osidentity"
)

func newTerminalAs(username, shell, directory string) (*terminalImpl, error) {
	identity, err := osidentity.Resolve(username)
	if err != nil {
		return nil, err
	}
	if shell == "" {
		shell, err = accountLoginShell(identity)
		if err != nil {
			return nil, err
		}
	}
	if !filepath.IsAbs(shell) || filepath.Clean(shell) != shell {
		return nil, fmt.Errorf("shell must be an absolute path")
	}
	cmd := buildAccountShellCommand(shell)
	if err := identity.Configure(cmd, directory); err != nil {
		return nil, err
	}
	cmd.Env = append(cmd.Env, "SHELL="+shell)
	tty, err := pty.Start(cmd)
	if err != nil {
		return nil, fmt.Errorf("start terminal as %s: %w", username, err)
	}
	return &terminalImpl{shell: shell, workingDir: cmd.Dir, term: &unixTerminal{tty: tty, cmd: cmd}}, nil
}

// Read the account database, never the Agent's SHELL. getent supports NSS
// accounts as well as /etc/passwd; the fallback covers hosts without getent.
func accountLoginShell(identity *osidentity.Identity) (string, error) {
	if getent, err := exec.LookPath("getent"); err == nil {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, getent, "passwd", identity.User.Uid)
		cmd.Env = identity.Environment()
		output, err := cmd.Output()
		if err != nil {
			return "", fmt.Errorf("read selected account login shell: %w", err)
		}
		return loginShellFromPasswd(strings.NewReader(string(output)), identity.User.Username, identity.User.Uid)
	}
	passwd, err := os.Open("/etc/passwd")
	if err != nil {
		return "", fmt.Errorf("read selected account login shell: %w", err)
	}
	defer passwd.Close()
	return loginShellFromPasswd(passwd, identity.User.Username, identity.User.Uid)
}

func loginShellFromPasswd(input io.Reader, username, uid string) (string, error) {
	scanner := bufio.NewScanner(input)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) != 7 || fields[0] != username || fields[2] != uid {
			continue
		}
		shell := fields[6]
		if shell == "" {
			shell = "/bin/sh"
		}
		if !filepath.IsAbs(shell) || filepath.Clean(shell) != shell {
			return "", fmt.Errorf("selected account login shell must be an absolute path")
		}
		// nologin and false remain account restrictions, not reasons to silently
		// substitute an interactive shell.
		return shell, nil
	}
	if err := scanner.Err(); err != nil {
		return "", err
	}
	return "", fmt.Errorf("selected account is missing from the login shell database")
}

// SSH normally prints cached MOTD through PAM. Read those cached files as the
// selected account without running arbitrary update-motd hooks on every tab.
const accountShellPrelude = `if [ ! -e "$HOME/.hushlogin" ]; then
if [ -r /run/motd.dynamic ]; then cat /run/motd.dynamic; elif [ -r /var/run/motd.dynamic ]; then cat /var/run/motd.dynamic; fi
[ ! -r /etc/motd ] || cat /etc/motd
fi
exec "$1" -i -l`

func buildAccountShellCommand(shell string) *exec.Cmd {
	return exec.Command("/bin/sh", "-c", accountShellPrelude, "komari-workspace", shell)
}
