package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
)

const maximumActionOutput = 1 << 20

type ActionConfig struct {
	AgentPath        string
	ConfigPath       string
	RuntimeStatePath string
	ServiceName      string
	RuntimeIdentity  string
	RuntimeUser      string
	FirewallMarker   string
}

type ActionResult struct {
	Stdout []byte
	Stderr []byte
}

func ExecuteAction(ctx context.Context, config ActionConfig, action rescuev1.RescueAction, arguments []string) (ActionResult, error) {
	if len(arguments) != 0 {
		return ActionResult{}, errors.New("rescue actions do not accept remote arguments")
	}
	switch action {
	case rescuev1.RescueAction_RESCUE_ACTION_DIAGNOSTICS:
		return diagnostics(config), nil
	case rescuev1.RescueAction_RESCUE_ACTION_VERIFY_INSTALLATION:
		return verifyInstallation(config)
	case rescuev1.RescueAction_RESCUE_ACTION_RESTORE_LAST_CONFIG:
		return restoreLastConfig(config)
	case rescuev1.RescueAction_RESCUE_ACTION_ROLLBACK_RUNTIME_SNAPSHOT:
		return rollbackRuntimeSnapshot(config)
	case rescuev1.RescueAction_RESCUE_ACTION_REPAIR_FIREWALL:
		return repairFirewall(ctx, config)
	case rescuev1.RescueAction_RESCUE_ACTION_RESTART_AGENT:
		return restartAgent(ctx, config)
	default:
		return ActionResult{}, fmt.Errorf("unsupported rescue action %s", action)
	}
}

func diagnostics(config ActionConfig) ActionResult {
	configBackupPath := strings.TrimSpace(config.ConfigPath)
	if configBackupPath == "" {
		configBackupPath = strings.TrimSpace(config.RuntimeStatePath)
	}
	lines := []string{
		"platform=" + runtime.GOOS + "/" + runtime.GOARCH,
		"privileged=" + fmt.Sprint(isPrivileged()),
		"agent_path=" + cleanDiagnosticValue(config.AgentPath),
		"service_name=" + cleanDiagnosticValue(config.ServiceName),
		"runtime_identity=" + cleanDiagnosticValue(config.RuntimeIdentity),
		"runtime_state_present=" + fmt.Sprint(fileExists(config.RuntimeStatePath)),
		"config_backup_present=" + fmt.Sprint(fileExists(configBackupPath+".bak")),
		"firewall_managed=" + fmt.Sprint(fileExists(config.FirewallMarker)),
	}
	return ActionResult{Stdout: []byte(strings.Join(lines, "\n") + "\n")}
}

func verifyInstallation(config ActionConfig) (ActionResult, error) {
	if strings.TrimSpace(config.AgentPath) == "" {
		return ActionResult{}, errors.New("agent path is not configured")
	}
	info, err := os.Stat(config.AgentPath)
	if err != nil {
		return ActionResult{}, fmt.Errorf("inspect Agent binary: %w", err)
	}
	if !info.Mode().IsRegular() {
		return ActionResult{}, errors.New("configured Agent path is not a regular file")
	}
	return ActionResult{Stdout: []byte(fmt.Sprintf("agent_binary=verified\nsize=%d\nmode=%s\n", info.Size(), info.Mode().Perm()))}, nil
}

func restoreLastConfig(config ActionConfig) (ActionResult, error) {
	path := strings.TrimSpace(config.ConfigPath)
	if path == "" {
		path = strings.TrimSpace(config.RuntimeStatePath)
	}
	if path == "" {
		return ActionResult{}, errors.New("Agent configuration path is not configured")
	}
	backup := path + ".bak"
	data, err := os.ReadFile(backup)
	if err != nil {
		return ActionResult{}, fmt.Errorf("read last Agent config: %w", err)
	}
	if !json.Valid(data) {
		return ActionResult{}, errors.New("last Agent config is not valid JSON")
	}
	if err := atomicWrite(path, data, 0o600); err != nil {
		return ActionResult{}, fmt.Errorf("restore last Agent config: %w", err)
	}
	if err := ensureRuntimeOwnership(path, config); err != nil {
		return ActionResult{}, err
	}
	return ActionResult{Stdout: []byte("agent_config=restored\n")}, nil
}

func rollbackRuntimeSnapshot(config ActionConfig) (ActionResult, error) {
	if strings.TrimSpace(config.RuntimeStatePath) == "" {
		return ActionResult{}, errors.New("runtime snapshot path is not configured")
	}
	data, err := os.ReadFile(config.RuntimeStatePath)
	if err != nil {
		return ActionResult{}, fmt.Errorf("read runtime snapshot: %w", err)
	}
	var state struct {
		Current  json.RawMessage  `json:"current"`
		Previous *json.RawMessage `json:"previous"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return ActionResult{}, fmt.Errorf("decode runtime snapshot: %w", err)
	}
	if len(state.Current) == 0 || state.Previous == nil || len(*state.Previous) == 0 {
		return ActionResult{}, errors.New("no previous runtime snapshot is available")
	}
	current := append(json.RawMessage(nil), state.Current...)
	state.Current = append(json.RawMessage(nil), (*state.Previous)...)
	state.Previous = &current
	updated, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return ActionResult{}, err
	}
	if err := atomicWrite(config.RuntimeStatePath, updated, 0o600); err != nil {
		return ActionResult{}, fmt.Errorf("persist runtime rollback: %w", err)
	}
	if err := ensureRuntimeOwnership(config.RuntimeStatePath, config); err != nil {
		return ActionResult{}, err
	}
	return ActionResult{Stdout: []byte("runtime_snapshot=rolled_back\n")}, nil
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(dir, ".komari-rescue-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(mode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func runBounded(ctx context.Context, name string, arguments ...string) (ActionResult, error) {
	stdout, stderr, err := platformCommand(ctx, name, arguments...)
	result := ActionResult{Stdout: limitBytes(stdout, maximumActionOutput), Stderr: limitBytes(stderr, maximumActionOutput)}
	if err != nil {
		return result, err
	}
	return result, nil
}

func limitBytes(value []byte, limit int) []byte {
	if len(value) <= limit {
		return value
	}
	const suffix = "\n[output truncated]\n"
	if limit <= len(suffix) {
		return append([]byte(nil), value[:limit]...)
	}
	return append(append([]byte(nil), value[:limit-len(suffix)]...), []byte(suffix)...)
}

func cleanDiagnosticValue(value string) string {
	return strings.NewReplacer("\n", "", "\r", "").Replace(value)
}

func fileExists(path string) bool {
	if strings.TrimSpace(path) == "" {
		return false
	}
	_, err := os.Stat(path)
	return err == nil
}

func deadlineForAssignment(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().Add(2 * time.Minute)
	}
	return value
}
