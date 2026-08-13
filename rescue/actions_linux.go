//go:build linux

package rescue

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
)

func isPrivileged() bool { return os.Geteuid() == 0 }

func ensureRuntimeOwnership(path string, config ActionConfig) error {
	if (config.RuntimeIdentity != "current-user" && config.RuntimeIdentity != "service-account") || strings.TrimSpace(config.RuntimeUser) == "" {
		return nil
	}
	account, err := user.Lookup(config.RuntimeUser)
	if err != nil {
		return fmt.Errorf("look up Agent runtime user: %w", err)
	}
	uid, err := strconv.Atoi(account.Uid)
	if err != nil {
		return fmt.Errorf("parse Agent runtime user ID: %w", err)
	}
	gid, err := strconv.Atoi(account.Gid)
	if err != nil {
		return fmt.Errorf("parse Agent runtime group ID: %w", err)
	}
	if err := os.Chown(path, uid, gid); err != nil {
		return fmt.Errorf("restore Agent runtime snapshot ownership: %w", err)
	}
	return nil
}

func platformCommand(ctx context.Context, name string, arguments ...string) ([]byte, []byte, error) {
	command := exec.CommandContext(ctx, name, arguments...)
	var stdout, stderr bytes.Buffer
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func restartAgent(ctx context.Context, config ActionConfig) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("restarting the Agent requires a privileged rescue helper")
	}
	service := strings.TrimSpace(config.ServiceName)
	if service == "" || strings.ContainsAny(service, "/\\\x00\n\r") {
		return ActionResult{}, errors.New("invalid Agent service name")
	}
	if config.RuntimeIdentity == "current-user" {
		name := strings.TrimSpace(config.RuntimeUser)
		if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "/\\\x00\n\r") {
			return ActionResult{}, errors.New("invalid Agent runtime user")
		}
		account, err := user.Lookup(name)
		if err != nil {
			return ActionResult{}, fmt.Errorf("look up Agent runtime user: %w", err)
		}
		uid, err := strconv.ParseUint(account.Uid, 10, 32)
		if err != nil {
			return ActionResult{}, fmt.Errorf("parse Agent runtime user ID: %w", err)
		}
		return runBounded(ctx, "runuser", "-u", name, "--", "env", fmt.Sprintf("XDG_RUNTIME_DIR=/run/user/%d", uid), "systemctl", "--user", "restart", service+".service")
	}
	return runBounded(ctx, "systemctl", "restart", service+".service")
}

func repairFirewall(ctx context.Context, config ActionConfig) (ActionResult, error) {
	if !isPrivileged() {
		return ActionResult{}, errors.New("firewall repair requires a privileged rescue helper")
	}
	if !fileExists(config.FirewallMarker) {
		return ActionResult{}, errors.New("rescue firewall management was not enabled during installation")
	}
	if _, err := exec.LookPath("ufw"); err != nil {
		return ActionResult{}, errors.New("ufw is unavailable; no installer-managed firewall rule can be repaired")
	}
	result, err := runBounded(ctx, "ufw", "allow", "out", "443/tcp", "comment", "komari-rescue")
	if err != nil {
		return result, fmt.Errorf("repair Komari rescue firewall rule: %w", err)
	}
	return result, nil
}
