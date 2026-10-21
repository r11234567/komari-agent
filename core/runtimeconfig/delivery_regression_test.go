package runtimeconfig

import (
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"path/filepath"
	"testing"
)

func auditAppliedStore(t *testing.T) *privileged.Store {
	t.Helper()
	s, err := privileged.Open(filepath.Join(t.TempDir(), "privileged.json"))
	if err != nil {
		t.Fatal(err)
	}
	local := privileged.Settings{RequiredPrivilegeMode: processMode(), RemoteControlEnabled: true, EnableGPU: true}
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
	if RemoteControlEnabled() {
		t.Fatal("applied snapshot bypassed explicit local force-deny")
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

func TestRegressionRemoteNICFalseOverridesBootstrap(t *testing.T) {
	oldFlags := *flags_pkg.GlobalConfig
	flags_pkg.GlobalConfig.GetIpAddrFromNic = true
	t.Cleanup(func() { *flags_pkg.GlobalConfig = oldFlags })
	store, err := New(FromFlags(flags_pkg.GlobalConfig), filepath.Join(t.TempDir(), "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := active.Load()
	SetActive(store)
	t.Cleanup(func() { SetActive(old) })
	no := false
	if _, err = store.Apply(&configv1.DesiredConfig{Revision: 1, Runtime: &configv1.RuntimeConfig{GetIpAddrFromNic: &no}}); err != nil {
		t.Fatal(err)
	}
	if Current().GetIPAddrFromNIC {
		t.Fatal("remote false could not disable a true bootstrap NIC setting")
	}
}
func TestRegressionRuntimeSnapshotAndACKAreAtomicAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	initial := FromFlags(&flags_pkg.Config{Interval: 3})
	store, err := New(initial, path)
	if err != nil {
		t.Fatal(err)
	}
	first := []byte("immutable-ack-r1")
	if _, err = store.ApplyWithReceipt(&configv1.DesiredConfig{Revision: 1, Runtime: &configv1.RuntimeConfig{}}, first); err != nil {
		t.Fatal(err)
	}
	reopened, err := New(initial, path)
	if err != nil {
		t.Fatal(err)
	}
	if reopened.Current().Revision != 1 || string(reopened.Receipt()) != string(first) {
		t.Fatal("crash lost snapshot or its ACK")
	}
	if _, err = reopened.ApplyWithReceipt(&configv1.DesiredConfig{Revision: 2, Runtime: &configv1.RuntimeConfig{}}, []byte("immutable-ack-r2")); err != nil {
		t.Fatal(err)
	}
	if string(reopened.Receipt()) != string(first) {
		t.Fatal("new revision overwrote the old immutable receipt")
	}
	if err = reopened.FinishReceipt([]byte("wrong-payload")); err != nil {
		t.Fatal(err)
	}
	if string(reopened.Receipt()) != string(first) {
		t.Fatal("concurrent send deleted a different receipt")
	}
	if err = reopened.FinishReceipt(first); err != nil {
		t.Fatal(err)
	}
	reopened, err = New(initial, path)
	if err != nil {
		t.Fatal(err)
	}
	if string(reopened.Receipt()) != "immutable-ack-r2" {
		t.Fatal("next receipt did not survive restart")
	}
}
