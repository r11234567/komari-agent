package runtimeconfig

import (
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"path/filepath"
	"testing"
)

func auditAppliedStore(t *testing.T) *privileged.Store {
	t.Helper()
	s, err := privileged.Open(filepath.Join(t.TempDir(), "privileged.json"))
	if err != nil {
		t.Fatal(err)
	}
	local := privileged.Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT, RemoteControlEnabled: true, EnableGPU: true}
	r := &configv1.PrivilegedRevision{Revision: 1, ProtocolVersion: 2, InstallationBaseline: true, ApprovalGeneration: 1, ConfigHash: privileged.Hash(local), Privileged: local.Proto(), Authorization: &hostv1.HostAuthorization{ServiceId: "fixture"}}
	if err := s.AdoptBaseline(r, local, local.RequiredPrivilegeMode, privileged.Receipt{ID: "baseline"}); err != nil {
		t.Fatal(err)
	}
	old := privileged.ActiveStore()
	privileged.SetActive(s)
	t.Cleanup(func() { privileged.SetActive(old) })
	oldFlags := *flags_pkg.GlobalConfig
	t.Cleanup(func() { *flags_pkg.GlobalConfig = oldFlags })
	return s
}

func TestRegressionAppliedPrivilegeBlockedByInstallFlag(t *testing.T) {
	auditAppliedStore(t)
	flags_pkg.GlobalConfig.DisableRemoteControl = true
	if !RemoteControlEnabled() {
		t.Fatal("locally approved remote_control=true is still overridden by installer --disable-remote-control")
	}
}

func TestRegressionAppliedGPUNotUsedByCollectors(t *testing.T) {
	auditAppliedStore(t)
	runtime, err := New(FromFlags(&flags_pkg.Config{Interval: 3}), filepath.Join(t.TempDir(), "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := active.Load()
	SetActive(runtime)
	t.Cleanup(func() { SetActive(old) })
	if !Current().EnableGPU {
		t.Fatal("privileged active.enable_gpu=true, but runtimeconfig.Current().EnableGPU=false (collector reads Current)")
	}
}

func TestRegressionProtocolSettingsSilentlyIgnored(t *testing.T) {
	s, err := New(FromFlags(&flags_pkg.Config{Interval: 3}), filepath.Join(t.TempDir(), "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	dns := "192.0.2.53"
	snap, err := s.Apply(&configv1.DesiredConfig{Revision: 1, Runtime: &configv1.RuntimeConfig{CustomDns: &dns}})
	if err == nil && snap.Revision == 1 {
		t.Fatal("custom_dns is accepted and revision advances, but Snapshot has no custom DNS field and resolver is not updated")
	}
}
