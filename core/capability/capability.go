package capability

import (
	"runtime"

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
	return detect(remoteControlEnabled, privilege, privileged, privilegeLimitation)
}

// RemoteControlAllowed is the enforcement point for execution and terminal
// access. Remote control always runs commands with the Agent process identity,
// so a non-root/non-administrator Agent must never expose it.
func RemoteControlAllowed(remoteControlEnabled bool) (bool, string) {
	_, privileged, limitation := privilegeState()
	return remoteControlAllowed(remoteControlEnabled, privileged, limitation)
}

func remoteControlAllowed(remoteControlEnabled, privileged bool, limitation string) (bool, string) {
	if !remoteControlEnabled {
		return false, "remote control is disabled by the applied runtime configuration"
	}
	if !privileged {
		return false, "remote control requires root or administrator privileges; " + limitation
	}
	return true, ""
}

func detect(remoteControlEnabled bool, privilege reportv1.PrivilegeMode, privileged bool, privilegeLimitation string) *reportv1.AgentCapabilities {
	remote := available()
	execution := available()
	webssh := available()
	if allowed, reason := remoteControlAllowed(remoteControlEnabled, privileged, privilegeLimitation); !allowed {
		remote = limited(reason)
		execution = limited(reason)
		webssh = limited(reason)
	}
	service := available()
	if !privileged {
		service = limited(privilegeLimitation)
	}
	result := &reportv1.AgentCapabilities{
		PrivilegeMode:     privilege,
		Gpu:               available(),
		DetailedGpu:       available(),
		NetworkInterfaces: available(),
		MountPoints:       available(),
		RemoteControl:     remote,
		ServiceControl:    service,
		Execution:         execution,
		Webssh:            webssh,
	}
	if runtime.GOOS != "linux" && runtime.GOOS != "windows" {
		result.ServiceControl = limited("service control capability is platform-dependent")
	}
	return result
}
