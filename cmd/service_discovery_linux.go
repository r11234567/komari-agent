//go:build linux

package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func diagnoseMissingManifest(executable string) error {
	if os.Getppid() == 1 && os.Getenv("INVOCATION_ID") != "" {
		return fmt.Errorf("installed systemd service has no manifest; run komari-host migrate --service <service> --legacy-disable preserve")
	}
	for _, dir := range []string{"/etc/systemd/system", "/usr/lib/systemd/system"} {
		paths, _ := filepath.Glob(filepath.Join(dir, "*.service"))
		for _, p := range paths {
			b, e := os.ReadFile(p)
			if e == nil && strings.Contains(string(b), executable) {
				return fmt.Errorf("installed service %s has no service manifest; run komari-host migrate --service %s --legacy-disable preserve", filepath.Base(p), strings.TrimSuffix(filepath.Base(p), ".service"))
			}
		}
	}
	if strings.HasPrefix(executable, "/opt/komari/") || strings.HasPrefix(executable, "/usr/lib/komari/") {
		return fmt.Errorf("installation at %s requires a trusted service manifest; run komari-host migrate", executable)
	}
	return nil
}
