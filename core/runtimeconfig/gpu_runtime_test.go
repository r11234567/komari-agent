package runtimeconfig

import (
	"path/filepath"
	"runtime"
	"testing"
	"time"

	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
)

func TestBasicGPUOrdinaryDeliveryIsWindowsOnlyAndPersistsExplicitOff(t *testing.T) {
	path := filepath.Join(t.TempDir(), "runtime.json")
	store, err := New(Snapshot{ReportInterval: 3 * time.Second}, path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		yes := true
		if _, err := store.Apply(&configv1.DesiredConfig{Revision: 1, Runtime: &configv1.RuntimeConfig{EnableGpu: &yes}}); err == nil || store.Current().Revision != 0 {
			t.Fatal("ordinary GPU delivery bypassed non-Windows privilege policy")
		}
		return
	}
	if !Inspect(&flags.Config{Interval: 3}, store, nil).Runtime.EnableGPU {
		t.Fatal("historical Windows configuration did not default GPU on")
	}
	for revision, enabled := range []bool{false, true, false} {
		if _, err := store.Apply(&configv1.DesiredConfig{Revision: uint64(revision + 1), Runtime: &configv1.RuntimeConfig{EnableGpu: &enabled}}); err != nil {
			t.Fatal(err)
		}
		restarted, err := New(Snapshot{ReportInterval: 3 * time.Second}, path)
		if err != nil {
			t.Fatal(err)
		}
		if got := Inspect(&flags.Config{Interval: 3}, restarted, nil).Runtime.EnableGPU; got != enabled {
			t.Fatalf("GPU toggle lost after restart: %v want %v", got, enabled)
		}
		snapshot := restarted.Current()
		*snapshot.WindowsGPUEnabled = !enabled
		if *restarted.Current().WindowsGPUEnabled != enabled {
			t.Fatal("caller mutated the stored GPU setting")
		}
	}
}
