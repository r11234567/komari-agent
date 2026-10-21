//go:build linux

package hostcmd

import (
	"github.com/komari-monitor/komari-agent/core/hostops"
	"strings"
	"testing"
)

func TestMigrationRetainsCustomPathsIdentityAndArguments(t *testing.T) {
	o := serviceObservation{User: "komari", WorkingDirectory: "/opt/custom", ExecStart: `{ path=/opt/custom/agent ; argv[]=/opt/custom/agent --endpoint https://panel.example --runtime-state-file /opt/custom/runtime-special.json --credentials-file /opt/custom/key.json --privileged-state-file /opt/custom/priv.json --replay-state-file /opt/custom/replay.json --disable-remote-control ; ignore_errors=no ; start_time=[n/a] ; }`}
	p, args, err := buildMigration("my-service", o, "preserve")
	if err != nil {
		t.Fatal(err)
	}
	if p.Manifest.ServiceName != "my-service" || p.Manifest.ServiceUser != "komari" || p.Manifest.RuntimeStateFile != "/opt/custom/runtime-special.json" || p.Manifest.CredentialsFile != "/opt/custom/key.json" {
		t.Fatalf("migration lost state: %+v", p.Manifest)
	}
	if !p.Policy.ForceDenyRemoteControl || p.Policy.BaselineRemoteControl || p.Policy.HelperInstalled {
		t.Fatal("migration inferred a local grant")
	}
	if !strings.Contains(strings.Join(args, " "), "https://panel.example") {
		t.Fatal("endpoint lost")
	}
	if _, _, err = buildMigration("my-service", o, ""); err == nil {
		t.Fatal("unknown disable origin must be resolved explicitly")
	}
	p, args, err = buildMigration("my-service", o, "release")
	if err != nil {
		t.Fatal(err)
	}
	if p.Policy.ForceDenyRemoteControl || strings.Contains(strings.Join(args, " "), "--disable-remote-control") {
		t.Fatal("explicit release was not applied")
	}
}
func TestSystemdArgvRejectsAmbiguity(t *testing.T) {
	for _, s := range []string{"", `{ path=/a ; argv[]=/a ; ignore_errors=no ; } { path=/b ; argv[]=/b ; ignore_errors=no ; }`, `{ path=/a ; argv[]=/a --x 'unclosed ; ignore_errors=no ; }`} {
		if _, err := parseExecStart(s); err == nil {
			t.Fatalf("ambiguous command accepted: %s", s)
		}
	}
	args, err := parseExecStart(`{ path=/opt/a ; argv[]=/opt/a --runtime-state-file /var/lib/my\x20node/state.json ; ignore_errors=no ; }`)
	if err != nil || len(args) != 3 || args[2] != "/var/lib/my node/state.json" {
		t.Fatalf("escaped path: %v %v", args, err)
	}
}
func TestHostApplyExplicitlyUnavailable(t *testing.T) {
	if err := Run([]string{"apply", "--manifest", "/nonexistent"}, &strings.Builder{}); err == nil {
		t.Fatal("unimplemented host operation reported success")
	}
}
func TestServiceNamesCannotSelectPaths(t *testing.T) {
	for _, s := range []string{"../other", "a/b", "-other", "a\nUser=root"} {
		if hostops.ValidService(s) {
			t.Fatalf("unsafe service: %s", s)
		}
	}
}
