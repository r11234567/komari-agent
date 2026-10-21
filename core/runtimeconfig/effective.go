package runtimeconfig

import (
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
		(!settings.EnableGPU || p.AllowGPU) && !settings.RescueHelperEnabled
}
func Effective() EffectiveConfig {
	raw := FromFlags(flags_pkg.GlobalConfig)
	if store := active.Load(); store != nil {
		raw = store.Current()
	}
	result := EffectiveConfig{Runtime: raw, Source: "bootstrap flags"}
	result.Privileged = privileged.Settings{RemoteControlEnabled: raw.RemoteControlEnabled, WebSSHEnabled: raw.RemoteControlEnabled, ExecutionEnabled: raw.RemoteControlEnabled, EnableGPU: raw.EnableGPU}
	if store := privileged.ActiveStore(); store != nil {
		result.Privileged = store.Effective()
		result.Source = "applied privileged snapshot intersected with signed pending restrictions"
	}
	if flags_pkg.GlobalConfig.ServiceManifestFile != "" {
		p, err := CurrentPolicy()
		if err != nil {
			result.Privileged = privileged.Settings{}
			result.BlockedReason = "protected installation policy unavailable: " + err.Error()
		} else {
			s := &result.Privileged
			if s.RequiredPrivilegeMode != 0 && int32(s.RequiredPrivilegeMode) != p.PrivilegeMode {
				result.Privileged = privileged.Settings{}
				result.BlockedReason = "applied identity differs from protected installation policy"
			}
			s.RemoteControlEnabled = s.RemoteControlEnabled && p.AllowRemoteControl && !p.ForceDenyRemoteControl
			s.WebSSHEnabled = s.WebSSHEnabled && p.AllowWebSSH
			s.ExecutionEnabled = s.ExecutionEnabled && p.AllowExecution
			s.EnableGPU = s.EnableGPU && p.AllowGPU
			s.RescueHelperEnabled = false
			if p.ForceDenyRemoteControl {
				result.BlockedReason = "protected local force-deny"
			}
		}
	}
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
