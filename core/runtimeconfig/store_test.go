package runtimeconfig

import (
	"path/filepath"
	"testing"
	"time"

	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
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
