package installation

import (
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

func TestObservationUsesProcessAndSharedManifestWithoutLeakingFlags(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "service-config.json")
	data := []byte(`{"service_name":"custom-agent","service_user":"invented-template-account","init_system":"windows"}`)
	if err := os.WriteFile(manifest, data, 0600); err != nil {
		t.Fatal(err)
	}
	config := &flags_pkg.Config{ServiceManifestFile: manifest, IgnoreUnsafeCert: true, DisableRemoteControl: true,
		Token: "never-report-token", AutoDiscoveryKey: "never-report-discovery", CFAccessClientSecret: "never-report-cloudflare"}
	got := Observe(config, "this-daemon-startup", reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT)
	identity, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if got.OperatingSystem != runtime.GOOS || got.ServiceName != "custom-agent" || got.ProcessUser != identity.Username || got.ProcessUserId != identity.Uid || got.StartupId != "this-daemon-startup" || got.Executable == "" {
		t.Fatalf("process observation replaced by template: %+v", got)
	}
	if got.DisableAutoUpdate == nil || *got.DisableAutoUpdate || !got.GetIgnoreUnsafeCertificate() || !got.GetDisableRemoteControl() || got.DaemonSelfUpdateSupported == nil || *got.DaemonSelfUpdateSupported {
		t.Fatal("missing explicit local options or incorrect update support")
	}
	wire, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(wire), "never-report-") || strings.Contains(string(wire), "invented-template-account") {
		t.Fatal("observation leaked credentials or claimed manifest user as actual daemon identity")
	}
	unknown := Observe(nil, "standalone", 0)
	if unknown.ServiceName != "" || unknown.ServiceManifest != "" || unknown.IgnoreUnsafeCertificate != nil {
		t.Fatal("missing configuration fabricated installation defaults")
	}
}
