//go:build !linux

package osidentity

import "os/exec"

func RestrictPrivilegeGain(command *exec.Cmd) error { return nil }
