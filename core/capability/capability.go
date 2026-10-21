package capability

import (
	"context"
	privilegedconfig "github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	"runtime"
	"time"

	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

func available() *reportv1.CapabilityState { return &reportv1.CapabilityState{Available: true} }

func limited(reason string) *reportv1.CapabilityState {
	return &reportv1.CapabilityState{Limitation: reason}
}

// Detect reports independently degradable capabilities. It never claims to
// elevate a process and is safe to call from a non-root/standard-user agent.
func Detect(remoteControlEnabled bool) *reportv1.AgentCapabilities {
	privilege, privileged, privilegeLimitation := privilegeState()
	result := detect(remoteControlEnabled, privilege, privileged, privilegeLimitation)
	result.ReturnRouteProbe = returnRouteProbeState()
	return result
}

// RemoteControlAllowed enforces the master switch. A signed same-identity
// grant permits non-root access using the daemon account only. Final execution
// and terminal entry points additionally require their separate sub-capability.
func RemoteControlAllowed(remoteControlEnabled bool) (bool, string) {
	mode, privilegedOS, limitation := privilegeState()
	cfg := runtimeconfig.EffectiveForMode(mode)
	return remoteAllowed(remoteControlEnabled && cfg.Privileged.RemoteControlEnabled, mode, privilegedOS, limitation)
}
func remoteAllowed(enabled bool, mode reportv1.PrivilegeMode, privilegedOS bool, limitation string) (bool, string) {
	if !enabled {
		return false, "remote control is disabled by effective configuration or local policy"
	}
	if !privilegedOS {
		store := privilegedconfig.ActiveStore()
		if store == nil || store.State().AppliedRevision == 0 || store.Active().RequiredPrivilegeMode != mode {
			return false, "same-identity signed authorization required; " + limitation
		}
	}
	return true, ""
}
func ExecutionAllowed() (bool, string) {
	caps := Detect(runtimeconfig.RemoteControlEnabled())
	return caps.Execution.Available, caps.Execution.Limitation
}
func WebSSHAllowed() (bool, string) {
	caps := Detect(runtimeconfig.RemoteControlEnabled())
	return caps.Webssh.Available, caps.Webssh.Limitation
}

// CancelOnRevocation also terminates existing jobs/sessions, including idle PTYs.
func CancelOnRevocation(ctx context.Context, cancel context.CancelFunc, allowed func() (bool, string)) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if ok, _ := allowed(); !ok {
				cancel()
				return
			}
		}
	}
}

func detect(remoteControlEnabled bool, privilege reportv1.PrivilegeMode, privileged bool, privilegeLimitation string) *reportv1.AgentCapabilities {
	remote := available()
	execution := available()
	webssh := available()
	if allowed, reason := remoteAllowed(remoteControlEnabled, privilege, privileged, privilegeLimitation); !allowed {
		remote = limited(reason)
		execution = limited(reason)
		webssh = limited(reason)
	}
	cfg := runtimeconfig.EffectiveForMode(privilege)
	if privilegedconfig.ActiveStore() != nil || !cfg.Privileged.RemoteControlEnabled {
		if !cfg.Privileged.RemoteControlEnabled {
			remote = limited("remote control denied by effective configuration")
			execution = limited("remote control denied by effective configuration")
			webssh = limited("remote control denied by effective configuration")
		}
		if !cfg.Privileged.ExecutionEnabled {
			execution = limited("execution denied by effective configuration")
		}
		if !cfg.Privileged.WebSSHEnabled {
			webssh = limited("WebSSH denied by effective configuration")
		}
	}
	service := available()
	if !privileged {
		service = limited(privilegeLimitation)
	}
	result := &reportv1.AgentCapabilities{
		PrivilegeMode:     privilege,
		Gpu:               limited("GPU disabled by effective configuration"),
		DetailedGpu:       limited("detailed GPU disabled by effective configuration"),
		NetworkInterfaces: available(),
		MountPoints:       available(),
		RemoteControl:     remote,
		ServiceControl:    service,
		Execution:         execution,
		Webssh:            webssh,
		ReturnRouteProbe:  available(),
	}
	if cfg.Runtime.EnableGPU {
		result.Gpu = available()
	}
	if cfg.Runtime.DetailedGPU {
		result.DetailedGpu = available()
	}
	result.RescueHelper = limited("rescue helper is not installed")
	if cfg.Privileged.RescueHelperEnabled {
		result.RescueHelper = available()
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		result.ServiceControl = limited("service control capability is platform-dependent")
	}
	return result
}
