//go:build linux

package osidentity

import (
	"fmt"
	"os/exec"
)

// RestrictPrivilegeGain prevents setuid binaries and file capabilities from
// restoring privilege after the child has switched to an ordinary account.
func RestrictPrivilegeGain(command *exec.Cmd) error {
	setpriv, err := exec.LookPath("setpriv")
	if err != nil {
		return fmt.Errorf("setpriv is required for restricted remote execution: %w", err)
	}
	command.Args = append([]string{setpriv, "--no-new-privs", "--", command.Path}, command.Args[1:]...)
	command.Path = setpriv
	return nil
}
