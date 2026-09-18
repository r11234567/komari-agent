package rescue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/komari-monitor/komari-agent/core/privileged"
	unit "github.com/komari-monitor/komari-agent/monitoring/unit"
	diagv1 "github.com/r11234567/komari-proto/gen/go/komari/diag/v1"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
)

const maximumActionOutput = 1 << 20

type ActionConfig struct {
	AgentPath          string
	ConfigPath         string
	RuntimeStatePath   string
	ServiceName        string
	RuntimeIdentity    string
	RuntimeUser        string
	ControlPlaneURL    string
	IsolationStatePath string
	// PrivilegedStatePath lets the helper withdraw a privileged configuration
	// without the panel. An empty value falls back to the default location, so
	// a helper installed before this existed still finds the state.
	PrivilegedStatePath string
}

type ActionResult struct {
	Stdout      []byte
	Stderr      []byte
	AfterReport func(context.Context) error
	// Diagnostics carries a typed performance snapshot for the read-only
	// diagnostic actions, so a panel renders fields instead of parsing text.
	Diagnostics *diagv1.DiagnosticsReport
	// SSHAccess reports the state a temporary SSH action actually reached.
	SSHAccess *rescuev1.TemporarySSHAccess
}

// ExecuteAction runs one bounded rescue action.
//
// sshPort applies only to the temporary SSH actions and arrives as a typed
// field rather than through arguments: arguments stay categorically rejected
// for every action, which is what keeps this helper from becoming a remote
// shell by accident.
func ExecuteAction(ctx context.Context, config ActionConfig, action rescuev1.RescueAction, arguments []string, sshPort uint32) (ActionResult, error) {
	if len(arguments) != 0 {
		return ActionResult{}, errors.New("rescue actions do not accept remote arguments")
	}
	switch action {
	case rescuev1.RescueAction_RESCUE_ACTION_DIAGNOSTICS:
		return machineDiagnostics(ctx)
	case rescuev1.RescueAction_RESCUE_ACTION_DETAILED_CPU_METRICS:
		return performanceDiagnostics(ctx, true, false)
	case rescuev1.RescueAction_RESCUE_ACTION_DETAILED_MEMORY_METRICS:
		return performanceDiagnostics(ctx, false, true)
	case rescuev1.RescueAction_RESCUE_ACTION_TEMPORARY_SSH_ACCESS:
		return grantTemporarySSHAccess(ctx, config, sshPort)
	case rescuev1.RescueAction_RESCUE_ACTION_REVOKE_TEMPORARY_SSH_ACCESS:
		return revokeTemporarySSHAccess(ctx, config)
	case rescuev1.RescueAction_RESCUE_ACTION_ROLLBACK_PRIVILEGED_CONFIG:
		return rollbackPrivilegedConfig(config)
	case rescuev1.RescueAction_RESCUE_ACTION_SHUTDOWN:
		return preparePowerAction(config, false)
	case rescuev1.RescueAction_RESCUE_ACTION_REBOOT:
		return preparePowerAction(config, true)
	case rescuev1.RescueAction_RESCUE_ACTION_BLOCK_PUBLIC_INTERFACES:
		if err := ensureNoActiveIsolation(config); err != nil {
			return ActionResult{}, err
		}
		return prepareInterfaceIsolation(config, rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_PUBLIC_INTERFACES)
	case rescuev1.RescueAction_RESCUE_ACTION_BLOCK_TAILSCALE_INTERFACES:
		if err := ensureNoActiveIsolation(config); err != nil {
			return ActionResult{}, err
		}
		return prepareInterfaceIsolation(config, rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_TAILSCALE_INTERFACES)
	case rescuev1.RescueAction_RESCUE_ACTION_ISOLATE_CONTROL_PLANE:
		if err := ensureNoActiveIsolation(config); err != nil {
			return ActionResult{}, err
		}
		return prepareControlPlaneIsolation(ctx, config)
	case rescuev1.RescueAction_RESCUE_ACTION_RESTORE_NETWORK:
		return restoreNetwork(ctx, config)
	case rescuev1.RescueAction_RESCUE_ACTION_ROLLBACK_ONLINE_CONFIG:
		return prepareAgentRestart(config)
	default:
		return ActionResult{}, fmt.Errorf("unsupported rescue action %s", action)
	}
}

// performanceDiagnostics collects a read-only performance snapshot.
//
// It is platform-neutral because the collector itself is where the platform
// difference lives. Unlike every other action here it needs no privilege: it
// reads kernel counters any user may read, which is what lets the control
// plane offer it without a fresh two-factor proof.
func performanceDiagnostics(_ context.Context, includeCPU, includeMemory bool) (ActionResult, error) {
	report, err := unit.CollectDiagnostics(includeCPU, includeMemory)
	if err != nil {
		return ActionResult{}, err
	}
	return ActionResult{Diagnostics: report}, nil
}

// rollbackPrivilegedConfig withdraws the active privileged configuration.
//
// The rescue helper can do this without any panel involvement, which is the
// point: if a privilege change was wrong, or the panel that sent it is
// unreachable, the host must still be able to take those privileges back.
// Unlike the CLI path this asks for no local password, because narrowing what
// the Agent may do is not the direction that needs guarding, and a rescue
// session already proved administrator authority with a second factor.
func rollbackPrivilegedConfig(config ActionConfig) (ActionResult, error) {
	store, err := privileged.Open(config.PrivilegedStatePath)
	if err != nil {
		return ActionResult{}, err
	}
	restored, revision, err := store.Rollback()
	if err != nil {
		return ActionResult{}, err
	}
	return ActionResult{Stdout: []byte(fmt.Sprintf(
		"rolled_back_revision=%d\nremote_control=%t\nwebssh=%t\nexecution=%t\nrescue_helper=%t\n"+
			"note=restart the Agent for this to take effect\n",
		revision, restored.RemoteControlEnabled, restored.WebSSHEnabled,
		restored.ExecutionEnabled, restored.RescueHelperEnabled))}, nil
}

func ensureNoActiveIsolation(config ActionConfig) error {
	mode, _ := networkIsolationStatus(config)
	if mode != rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_NONE &&
		mode != rescuev1.NetworkIsolationMode_NETWORK_ISOLATION_MODE_UNSPECIFIED {
		return errors.New("remove the active Komari network isolation before selecting another isolation mode")
	}
	return nil
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

func deadlineForAssignment(value time.Time) time.Time {
	if value.IsZero() {
		return time.Now().Add(2 * time.Minute)
	}
	return value
}
