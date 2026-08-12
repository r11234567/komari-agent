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

func detect(remoteControlEnabled bool, privilege reportv1.PrivilegeMode, privileged bool, privilegeLimitation string) *reportv1.AgentCapabilities {
	remote := available()
	execution := available()
	webssh := available()
	if !remoteControlEnabled {
		remote = limited("disabled by the applied runtime configuration")
		execution = limited("remote control is disabled by the applied runtime configuration")
		webssh = limited("remote control is disabled by the applied runtime configuration")
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
