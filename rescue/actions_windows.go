//go:build windows

package rescue

import (
	"bytes"
	"context"
	"errors"
	"os/exec"
	"strings"

	"golang.org/x/sys/windows"
)

func isPrivileged() bool {
	token := windows.Token(0)
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return false
	}
	member, err := token.IsMember(administrators)
	return err == nil && member
}

func ensureRuntimeOwnership(string, ActionConfig) error { return nil }

func platformCommand(ctx context.Context, name string, arguments ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func restartAgent(ctx context.Context, config ActionConfig) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("restarting the Agent requires an Administrator rescue helper")
	}
	service := strings.TrimSpace(config.ServiceName)
	if service == "" || strings.ContainsAny(service, "/\\\x00\n\r") {
		return ActionResult{}, errors.New("invalid Agent service name")
	}
	if config.RuntimeIdentity == "current-user" {
		stopped, stopErr := runBounded(ctx, "schtasks.exe", "/End", "/TN", service)
		started, startErr := runBounded(ctx, "schtasks.exe", "/Run", "/TN", service)
		result := ActionResult{
			Stdout: append(stopped.Stdout, started.Stdout...),
			Stderr: append(stopped.Stderr, started.Stderr...),
		}
		if startErr != nil {
			return result, startErr
		}
		if stopErr != nil && len(stopped.Stderr) > 0 {
			result.Stderr = append(result.Stderr, []byte("scheduled task was not running before restart\n")...)
		}
		return result, nil
	}
	return runBounded(ctx, "powershell.exe", "-NoProfile", "-NonInteractive", "-Command", "Restart-Service -Name '"+strings.ReplaceAll(service, "'", "''")+"' -Force")
}

func repairFirewall(ctx context.Context, config ActionConfig) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("firewall repair requires an Administrator rescue helper")
	}
	if !fileExists(config.FirewallMarker) {
		return ActionResult{}, errors.New("rescue firewall management was not enabled during installation")
	}
	return runBounded(ctx, "netsh.exe", "advfirewall", "firewall", "set", "rule", "name=Komari Rescue Helper", "new", "enable=yes")
}
