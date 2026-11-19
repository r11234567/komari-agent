package cmd

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHandleAutoDiscoveryRefusesRemovedRegisterEndpoint(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auto-discovery.json")
	t.Setenv("AGENT_AUTO_DISCOVERY_FILE", path)

	err := handleAutoDiscovery()
	if !errors.Is(err, errLegacyAutoDiscoveryRemoved) {
		t.Fatalf("handleAutoDiscovery() error = %v, want %v", err, errLegacyAutoDiscoveryRemoved)
	}
	if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
		t.Fatalf("handleAutoDiscovery() unexpectedly created %s", path)
	}
}

func TestLoadAutoDiscoveryConfigTightensExistingFileMode(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auto-discovery.json")
	if err := os.WriteFile(path, []byte(`{"uuid":"agent-1","token":"legacy-token"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_AUTO_DISCOVERY_FILE", path)

	cfg, err := loadAutoDiscoveryConfig()
	if err != nil {
		t.Fatalf("loadAutoDiscoveryConfig() error = %v", err)
	}
	if cfg == nil || cfg.UUID != "agent-1" || cfg.Token != "legacy-token" {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if perm := info.Mode().Perm(); perm != 0o600 {
			t.Fatalf("auto-discovery file perm = %04o, want 0600", perm)
		}
	}
}

func TestLoadAutoDiscoveryConfigFailsWhenPermissiveChmodFails(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not enforced on Windows")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "auto-discovery.json")
	if err := os.WriteFile(path, []byte(`{"uuid":"agent-1","token":"legacy-token"}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AGENT_AUTO_DISCOVERY_FILE", path)

	origChmod := chmodAutoDiscoveryFile
	chmodAutoDiscoveryFile = func(string, os.FileMode) error {
		return errors.New("operation not permitted")
	}
	t.Cleanup(func() { chmodAutoDiscoveryFile = origChmod })

	if _, err := loadAutoDiscoveryConfig(); err == nil {
		t.Fatal("expected error when tightening overly permissive 0644 auto-discovery file fails")
	}
}
