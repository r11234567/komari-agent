package runtimeconfig

import (
	"path/filepath"
	"testing"
	"time"

	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
)

func TestApplyPersistsAndRollsBack(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	initial := Snapshot{ReportInterval: 3 * time.Second, RemoteControlEnabled: true}
	store, err := New(initial, path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = store.Apply(&configv1.DesiredConfig{Revision: 7, Runtime: &configv1.RuntimeConfig{
		ReportInterval: durationpb.New(5 * time.Second),
	}})
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := New(initial, path)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Current(); got.Revision != 7 || !got.RemoteControlEnabled || got.ReportInterval != 5*time.Second {
		t.Fatalf("unexpected loaded snapshot: %+v", got)
	}
	rolledBack, err := loaded.Rollback()
	if err != nil {
		t.Fatal(err)
	}
	if rolledBack.Revision != 0 || !rolledBack.RemoteControlEnabled {
		t.Fatalf("unexpected rollback snapshot: %+v", rolledBack)
	}
}

func TestApplyRejectsInvalidAndStaleWithoutMutation(t *testing.T) {
	store, err := New(Snapshot{Revision: 4, ReportInterval: 3 * time.Second, RemoteControlEnabled: true}, filepath.Join(t.TempDir(), "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	remote := false
	_, err = store.Apply(&configv1.DesiredConfig{Revision: 5, Runtime: &configv1.RuntimeConfig{
		ReportInterval: durationpb.New(100 * time.Millisecond), RemoteControlEnabled: &remote,
	}})
	if err == nil {
		t.Fatal("expected invalid interval to be rejected")
	}
	_, err = store.Apply(&configv1.DesiredConfig{Revision: 3, Runtime: &configv1.RuntimeConfig{ReportInterval: durationpb.New(3 * time.Second)}})
	if err == nil {
		t.Fatal("expected stale revision to be rejected")
	}
	if got := store.Current(); got.Revision != 4 || !got.RemoteControlEnabled {
		t.Fatalf("rejected config changed current snapshot: %+v", got)
	}
}

func TestRemoteControlDefaultsToDeniedForZeroTrustAndRespectsPrivilegedStore(t *testing.T) {
	// For zero-trust mode without token flag, RemoteControlEnabled in FromFlags is false
	cfg := &flags_pkg.Config{Interval: 3.0}
	snap := FromFlags(cfg)
	if snap.RemoteControlEnabled {
		t.Fatal("expected remote control to default to false for zero-trust enrolled mode")
	}

	// Privileged store active state controls RemoteControlEnabled
	privPath := filepath.Join(t.TempDir(), "privileged.json")
	privStore, err := privileged.Open(privPath)
	if err != nil {
		t.Fatal(err)
	}
	privileged.SetActive(privStore)
	defer privileged.SetActive(nil)

	if RemoteControlEnabled() {
		t.Fatal("expected RemoteControlEnabled to be false when privileged store has default active settings")
	}

	// Deliver and promote a privileged revision enabling remote control
	rev := &configv1.PrivilegedRevision{
		Revision: 1,
		Privileged: &configv1.PrivilegedConfig{
			RemoteControlEnabled: proto.Bool(true),
		},
	}
	if err := privStore.RecordPending(rev); err != nil {
		t.Fatal(err)
	}
	if _, err := privStore.Promote(reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT); err != nil {
		t.Fatal(err)
	}

	if !RemoteControlEnabled() {
		t.Fatal("expected RemoteControlEnabled to be true after promoting privileged revision")
	}

	// Flag override should disable it regardless
	flags_pkg.GlobalConfig.DisableRemoteControl = true
	defer func() { flags_pkg.GlobalConfig.DisableRemoteControl = false }()
	if RemoteControlEnabled() {
		t.Fatal("expected RemoteControlEnabled to be false when DisableRemoteControl flag is set")
	}
}
