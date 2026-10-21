package cmd

import (
	"bytes"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	"os"
	"path/filepath"
	"testing"
)

func TestLegacyUpgradeNeverWritesStateOrRunsDaemonWritableScript(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "privileged.json")
	oldFlags := *flags
	oldService := installedService
	t.Cleanup(func() { *flags = oldFlags; installedService = oldService })
	flags.PrivilegedStateFile = path
	installedService = &serviceConfig{ServiceName: "custom-agent", ServiceUser: "komari"}
	s, err := privileged.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = s.RecordPending(&configv1.PrivilegedRevision{Revision: 1, Privileged: &configv1.PrivilegedConfig{}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(dir, "executed")
	if err = os.WriteFile(filepath.Join(dir, "elevate.sh"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = upgradeCmd.RunE(upgradeCmd, nil); err == nil {
		t.Fatal("legacy upgrade must require migration, even if CLI is root")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("CLI overwrote daemon state")
	}
	if _, err = os.Stat(marker); !os.IsNotExist(err) {
		t.Fatal("candidate elevation script was executed")
	}
}
func TestCompatibilityAliasUsesSameCommand(t *testing.T) {
	c, _, err := RootCmd.Find([]string{"update-conf"})
	if err != nil || c != upgradeCmd {
		t.Fatalf("alias duplicated command: %v", err)
	}
}
func TestPrivilegedRollbackCannotReenableWithoutNewApproval(t *testing.T) {
	if err := rollbackCmd.RunE(rollbackCmd, nil); err == nil {
		t.Fatal("CLI cannot write privileged rollback snapshots")
	}
}
