// Package installation reports the running daemon's non-secret local state.
// Observations are informational and never authorize a host operation.
package installation

import (
	"os"
	"os/user"
	"path/filepath"
	"runtime"

	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func Observe(config *flags_pkg.Config, startupID string, mode reportv1.PrivilegeMode) *reportv1.InstallationObservation {
	observation := &reportv1.InstallationObservation{
		ObservedAt: timestamppb.Now(), StartupId: startupID, OperatingSystem: runtime.GOOS,
		PrivilegeMode: mode, Transport: "Connect-RPC",
	}
	if executable, err := os.Executable(); err == nil {
		if resolved, err := filepath.EvalSymlinks(executable); err == nil {
			executable = resolved
		}
		observation.Executable = executable
	}
	if identity, err := user.Current(); err == nil {
		observation.ProcessUser, observation.ProcessUserId = identity.Username, identity.Uid
	}
	if config == nil {
		return observation
	}
	// Whitelist individual options. Never serialize flags: they contain tokens,
	// enrollment keys and Cloudflare credentials.
	observation.DisableAutoUpdate = boolPointer(config.DisableAutoUpdate)
	observation.IgnoreUnsafeCertificate = boolPointer(config.IgnoreUnsafeCert)
	observation.DisableRemoteControl = boolPointer(config.DisableRemoteControl)
	// update.CheckAndUpdate refuses daemon self-modification on every platform.
	observation.DaemonSelfUpdateSupported = boolPointer(false)
	observation.ConfigFile = config.ConfigFile
	observation.ServiceManifest = config.ServiceManifestFile
	observation.RuntimeStateFile = config.RuntimeStateFile
	if observation.RuntimeStateFile == "" {
		observation.RuntimeStateFile = runtimeconfig.DefaultStatePath()
	}
	observation.PrivilegedStateFile = config.PrivilegedStateFile
	if observation.PrivilegedStateFile == "" {
		observation.PrivilegedStateFile = privileged.DefaultPath()
	}
	if manifest, err := hostops.ReadManifest(config.ServiceManifestFile); err == nil {
		observation.ServiceName, observation.InitSystem = manifest.ServiceName, manifest.InitSystem
	}
	return observation
}

func boolPointer(value bool) *bool { return &value }
