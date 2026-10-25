//go:build linux

package hostcmd

import (
	"io"
	"reflect"
	"strings"
	"testing"

	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
)

func TestLegacyRemoteControlReviewDoesNotMutateProtectedPolicy(t *testing.T) {
	settings := privileged.Settings{RemoteControlEnabled: true}
	r := &configv1.PrivilegedRevision{Privileged: settings.Proto()}
	for _, source := range []string{"legacy-unknown-preserve", "explicit-local-install", "legacy-remote-control-reauthorized", ""} {
		p := hostops.Policy{ForceDenyRemoteControl: true, AllowRemoteControl: true, DisableSource: source, ForceDenyRescueHelper: true}
		before := p
		preview, review := legacyRemoteControlReview(&p, r)
		if review != (source == "legacy-unknown-preserve") || !reflect.DeepEqual(p, before) {
			t.Fatalf("unexpected review or modified policy: source=%q review=%t policy=%+v", source, review, p)
		}
		if !preview.ForceDenyRescueHelper || preview.AllowExecution != p.AllowExecution {
			t.Fatal("legacy review released an unrelated ceiling")
		}
	}
	p := hostops.Policy{ForceDenyRemoteControl: true, DisableSource: "legacy-unknown-preserve"}
	if _, review := legacyRemoteControlReview(&p, r); review {
		t.Fatal("legacy review released allow_remote_control=false")
	}
	p.AllowRemoteControl = true
	r.Privileged = (&privileged.Settings{}).Proto()
	if _, review := legacyRemoteControlReview(&p, r); review {
		t.Fatal("a task that does not request remote control released the deny")
	}
}

func TestLegacyRemoteControlConsentBindsServiceAndRevision(t *testing.T) {
	for _, answer := range []string{"", "yes\n", "authorize other 4\n", "authorize fixture 3\n", "authorize fixture 4"} {
		if err := readLegacyRemoteControlConsent(strings.NewReader(answer), io.Discard, "fixture", 4); err == nil {
			t.Fatalf("accepted incomplete or mismatched local consent %q", answer)
		}
	}
	if err := readLegacyRemoteControlConsent(strings.NewReader("authorize fixture 4\n"), io.Discard, "fixture", 4); err != nil {
		t.Fatal(err)
	}
}

func TestLocalCeilingsIdentifyEveryConflictingSetting(t *testing.T) {
	p := hostops.Policy{ForceDenyRemoteControl: true, ForceDenyRescueHelper: true, DisableSource: "explicit-local-install"}
	s := privileged.Settings{RemoteControlEnabled: true, WebSSHEnabled: true, ExecutionEnabled: true, EnableGPU: true, RescueHelperEnabled: true}
	reasons := strings.Join(localCeilingViolations(&p, s, false), "; ")
	for _, field := range []string{"force_deny_remote_control", "allow_remote_control", "allow_webssh", "allow_execution", "allow_gpu", "force_deny_rescue_helper", "allow_rescue_helper"} {
		if !strings.Contains(reasons, field) {
			t.Fatalf("missing blocking field %s in %s", field, reasons)
		}
	}
	if reasons := localCeilingViolations(&p, privileged.Settings{}, false); len(reasons) != 0 {
		t.Fatal("disabled settings were blocked:", reasons)
	}
}
