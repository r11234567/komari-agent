//go:build linux

package hostcmd

import (
	"errors"
	"fmt"
	"os/exec"
	"os/user"
)

// Run during administrator-owned installation/update, before replacing services.
// Older main/install.sh versions still execute the selected release's host tool.
func ensureExecutionAccount() error {
	if _, err := exec.LookPath("setpriv"); err != nil {
		return fmt.Errorf("restricted execution requires util-linux setpriv: %w", err)
	}
	account, err := user.Lookup("komari")
	if err != nil {
		var missing user.UnknownUserError
		if !errors.As(err, &missing) {
			return err
		}
		command := exec.Command("useradd", "--system", "--no-create-home", "--home-dir", "/nonexistent", "--shell", "/usr/sbin/nologin", "komari")
		if output, err := command.CombinedOutput(); err != nil {
			return fmt.Errorf("create komari execution account: %w: %s", err, output)
		}
		account, err = user.Lookup("komari")
		if err != nil {
			return err
		}
	}
	if account.Uid == "0" {
		return errors.New("komari execution account must not be UID 0")
	}
	return nil
}
