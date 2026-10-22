package runtimeconfig

import (
	"fmt"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

// EffectiveConfig is the view used by collectors, capability reports and gates.
// Protected policy is re-read so local force-deny takes effect without rewriting
// daemon-owned snapshots. Invalid policy fails closed.
type EffectiveConfig struct {
	Runtime       Snapshot            `json:"runtime"`
	Privileged    privileged.Settings `json:"privileged"`
	Source        string              `json:"privileged_source"`
	Sources       map[string]string   `json:"sources"`
	Blocked       map[string]string   `json:"blocked,omitempty"`
	BlockedReason string              `json:"blocked_reason,omitempty"`
}

func CurrentPolicy() (*hostops.Policy, error) {
	m, err := hostops.ReadManifest(flags_pkg.GlobalConfig.ServiceManifestFile)
	if err != nil {
		return nil, err
	}
	return hostops.ReadPolicy(m)
}
func PolicyAllows(settings privileged.Settings, p *hostops.Policy) bool {
	return p != nil && int32(settings.RequiredPrivilegeMode) == p.PrivilegeMode &&
		(!settings.RemoteControlEnabled || p.AllowRemoteControl && !p.ForceDenyRemoteControl) &&
		(!settings.WebSSHEnabled || p.AllowWebSSH) && (!settings.ExecutionEnabled || p.AllowExecution) &&
		(!settings.EnableGPU || p.AllowGPU) && (!settings.RescueHelperEnabled || p.AllowRescueHelper && !p.ForceDenyRescueHelper && p.HelperInstalled && p.HelperAuthorized)
}
func Effective() EffectiveConfig {
	return Inspect(flags_pkg.GlobalConfig, active.Load(), privileged.ActiveStore())
}

// Inspect evaluates a disk view without changing the process-wide stores or
// claiming that the querying process is the running daemon.
func Inspect(config *flags_pkg.Config, runtimeStore *Store, privilegedStore *privileged.Store) EffectiveConfig {
	raw := FromFlags(config)
	if runtimeStore != nil {
		raw = runtimeStore.Current()
	}
	result := EffectiveConfig{Runtime: raw, Source: "bootstrap flags", Sources: map[string]string{}, Blocked: map[string]string{}}
	runtimeSource := "bootstrap flags"
	if raw.Revision > 0 {
		runtimeSource = fmt.Sprintf("applied runtime r%d", raw.Revision)
	}
	for _, field := range []string{"memory_include_cache", "detailed_gpu", "include_nics", "exclude_nics", "include_mountpoints", "report_interval", "traffic_reset_day", "get_ip_addr_from_nic"} {
		result.Sources[field] = runtimeSource
	}
	result.Privileged = privileged.Settings{RemoteControlEnabled: raw.RemoteControlEnabled, WebSSHEnabled: raw.RemoteControlEnabled, ExecutionEnabled: raw.RemoteControlEnabled, EnableGPU: raw.EnableGPU}
	if privilegedStore != nil {
		result.Privileged = privilegedStore.Effective()
		result.Source = "applied privileged snapshot intersected with signed pending restrictions"
	}
	for _, field := range []string{"remote_control_enabled", "webssh_enabled", "execution_enabled", "enable_gpu", "rescue_helper_enabled", "required_privilege_mode"} {
		result.Sources[field] = result.Source
	}
	if config.ServiceManifestFile != "" {
		m, err := hostops.ReadManifest(config.ServiceManifestFile)
		var p *hostops.Policy
		if err == nil {
			p, err = hostops.ReadPolicy(m)
		}
		if err != nil {
			result.Privileged = privileged.Settings{}
			result.BlockedReason = "protected installation policy unavailable: " + err.Error()
		} else {
			s := &result.Privileged
			for field, denied := range map[string]bool{"remote_control_enabled": !p.AllowRemoteControl || p.ForceDenyRemoteControl, "webssh_enabled": !p.AllowWebSSH, "execution_enabled": !p.AllowExecution, "enable_gpu": !p.AllowGPU, "rescue_helper_enabled": !p.AllowRescueHelper || p.ForceDenyRescueHelper || !p.HelperInstalled || !p.HelperAuthorized} {
				if denied {
					result.Blocked[field] = "protected local policy"
				}
			}

			if s.RequiredPrivilegeMode != 0 && int32(s.RequiredPrivilegeMode) != p.PrivilegeMode {
				result.Privileged = privileged.Settings{}
				result.BlockedReason = "applied identity differs from protected installation policy"
			}
			s.RemoteControlEnabled = s.RemoteControlEnabled && p.AllowRemoteControl && !p.ForceDenyRemoteControl
			s.WebSSHEnabled = s.WebSSHEnabled && p.AllowWebSSH
			s.ExecutionEnabled = s.ExecutionEnabled && p.AllowExecution
			s.EnableGPU = s.EnableGPU && p.AllowGPU
			s.RescueHelperEnabled = s.RescueHelperEnabled && p.AllowRescueHelper && !p.ForceDenyRescueHelper && p.HelperInstalled && p.HelperAuthorized
			// Formerly writable historical state must not revive a capability
			// during restart, before the current host-approved target loads.
			if privilegedStore != nil && p.HostSettings != nil && privilegedStore.State().AppliedRevision <= p.HostRevision {
				target := p.HostSettings
				s.RemoteControlEnabled = s.RemoteControlEnabled && target.RemoteControlEnabled
				s.WebSSHEnabled = s.WebSSHEnabled && target.WebSSHEnabled
				s.ExecutionEnabled = s.ExecutionEnabled && target.ExecutionEnabled
				s.EnableGPU = s.EnableGPU && target.EnableGPU
				s.RescueHelperEnabled = s.RescueHelperEnabled && target.RescueHelperEnabled
				result.Sources["host_transition_ceiling"] = fmt.Sprintf("protected host revision r%d", p.HostRevision)
			}
			if p.ForceDenyRemoteControl {
				result.BlockedReason = "protected local force-deny"
			}
		}
	}
	if config.DisableRemoteControl {
		result.Privileged.RemoteControlEnabled = false
		result.Blocked["remote_control_enabled"] = "local force-deny"
		result.Sources["remote_control_enabled"] = "local force-deny"
	}
	if result.BlockedReason != "" {
		result.Blocked["privileged"] = result.BlockedReason
	}
	result.Privileged.WebSSHEnabled = result.Privileged.RemoteControlEnabled && result.Privileged.WebSSHEnabled
	result.Privileged.ExecutionEnabled = result.Privileged.RemoteControlEnabled && result.Privileged.ExecutionEnabled
	result.Runtime.EnableGPU = result.Privileged.EnableGPU
	result.Runtime.RemoteControlEnabled = result.Privileged.RemoteControlEnabled
	result.Runtime.DetailedGPU = raw.DetailedGPU && result.Runtime.EnableGPU
	return result
}
func EffectiveForMode(actual reportv1.PrivilegeMode) EffectiveConfig {
	result := Effective()
	if required := result.Privileged.RequiredPrivilegeMode; required != 0 && required != actual {
		result.Privileged = privileged.Settings{}
		result.Runtime.RemoteControlEnabled = false
		result.Runtime.EnableGPU = false
		result.Runtime.DetailedGPU = false
		result.BlockedReason = "actual daemon identity differs from applied privileged snapshot"
	}
	return result
}
