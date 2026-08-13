package rescue

import (
	"context"
	"errors"
	"fmt"
	"time"

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
}

type ActionResult struct {
	Stdout      []byte
	Stderr      []byte
	AfterReport func(context.Context) error
}

func ExecuteAction(ctx context.Context, config ActionConfig, action rescuev1.RescueAction, arguments []string) (ActionResult, error) {
	if len(arguments) != 0 {
		return ActionResult{}, errors.New("rescue actions do not accept remote arguments")
	}
	switch action {
	case rescuev1.RescueAction_RESCUE_ACTION_DIAGNOSTICS:
		return machineDiagnostics(ctx)
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
