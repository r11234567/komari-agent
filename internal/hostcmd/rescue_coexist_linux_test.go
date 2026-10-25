//go:build linux

package hostcmd

import (
	"testing"

	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
)

func TestIndependentRescueAndRemoteControlKeepLocalCeilings(t *testing.T) {
	s := privileged.Settings{RequiredPrivilegeMode: 1, RemoteControlEnabled: true, WebSSHEnabled: true, ExecutionEnabled: true, RescueHelperEnabled: true}
	r := &configv1.PrivilegedRevision{Privileged: s.Proto(), Authorization: &hostv1.HostAuthorization{TargetPrivilegeMode: 1, Actions: []hostv1.HostAction{1}}}
	p := hostops.Policy{PrivilegeMode: 2, AllowRemoteControl: true, AllowWebSSH: true, AllowExecution: true, AllowRescueHelper: true, HelperInstalled: true}
	trust := &hostops.Trust{ServiceUser: "komari"}
	if err := validateActions(nil, &p, trust, r, serviceObservation{User: "komari"}); err != nil {
		t.Fatal("independently authorized services cannot coexist:", err)
	}
	for _, deny := range []string{"remote", "rescue"} {
		denied := p
		denied.ForceDenyRemoteControl = deny == "remote"
		denied.ForceDenyRescueHelper = deny == "rescue"
		if err := validateActions(nil, &denied, trust, r, serviceObservation{User: "komari"}); err == nil {
			t.Fatal("coexistence bypassed explicit local deny:", deny)
		}
	}
}
