//go:build linux

package hostcmd

import (
	"os"
	"testing"

	"github.com/komari-monitor/komari-agent/core/hostops"
)

func TestPendingSoftwareUpgradeBindsRecoveryToInstallation(t *testing.T) {
	m := &hostops.Manifest{ManifestPath: "/etc/komari/services/test.json", Executable: "/usr/lib/komari/test/agent", HostTool: "/usr/lib/komari/test/host"}
	good := func() softwareUpgrade {
		return softwareUpgrade{Phase: "restore_failed", Manifest: m.ManifestPath, Paths: upgradePaths(m), Modes: []os.FileMode{0o755, 0o755, 0o755, 0o600}, Active: []bool{true, true}}
	}
	for _, phase := range []string{"prepared", "replacing", "restore_failed"} {
		s := good()
		s.Phase = phase
		if err := validateUpgradeJournal(m, &s); err != nil {
			t.Fatal(err)
		}
	}
	for name, corrupt := range map[string]func(*softwareUpgrade){
		"other manifest":        func(s *softwareUpgrade) { s.Manifest = "/other/manifest.json" },
		"other executable":      func(s *softwareUpgrade) { s.Paths[0] = "/other/agent" },
		"reordered paths":       func(s *softwareUpgrade) { s.Paths[0], s.Paths[1] = s.Paths[1], s.Paths[0] },
		"missing mode":          func(s *softwareUpgrade) { s.Modes = s.Modes[:3] },
		"missing service state": func(s *softwareUpgrade) { s.Active = s.Active[:1] },
		"writable binary":       func(s *softwareUpgrade) { s.Modes[0] = 0o777 },
		"exposed configuration": func(s *softwareUpgrade) { s.Modes[3] = 0o644 },
		"unknown phase":         func(s *softwareUpgrade) { s.Phase = "pending" },
	} {
		t.Run(name, func(t *testing.T) {
			s := good()
			corrupt(&s)
			if err := validateUpgradeJournal(m, &s); err == nil {
				t.Fatal("unsafe recovery metadata accepted")
			}
		})
	}
}
