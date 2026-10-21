package capability

import (
	"fmt"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"path/filepath"
	"testing"
)

func TestRegressionSeparateExecutionAndWebSSHFlagsIgnored(t *testing.T) {
	s, _ := privileged.Open(filepath.Join(t.TempDir(), "privileged.json"))
	local := privileged.Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT, RemoteControlEnabled: true}
	r := &configv1.PrivilegedRevision{Revision: 1, ProtocolVersion: 2, InstallationBaseline: true, ApprovalGeneration: 1, ConfigHash: privileged.Hash(local), Privileged: local.Proto(), Authorization: &hostv1.HostAuthorization{ServiceId: "fixture"}}
	if err := s.AdoptBaseline(r, local, local.RequiredPrivilegeMode, privileged.Receipt{ID: "baseline"}); err != nil {
		t.Fatal(err)
	}
	old := privileged.ActiveStore()
	privileged.SetActive(s)
	t.Cleanup(func() { privileged.SetActive(old) })
	caps := detect(s.Active().RemoteControlEnabled, reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT, true, "")
	if caps.Execution.Available || caps.Webssh.Available {
		t.Fatalf("execution=false/webssh=false, but capabilities execution=%t webssh=%t", caps.Execution.Available, caps.Webssh.Available)
	}
}

func TestRegressionWebSSHAndExecutionAreIndependentInBothDirections(t *testing.T) {
	for _, execution := range []bool{false, true} {
		t.Run(fmt.Sprint(execution), func(t *testing.T) {
			local := privileged.Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, RemoteControlEnabled: true, WebSSHEnabled: !execution, ExecutionEnabled: execution}
			store, err := privileged.Open(filepath.Join(t.TempDir(), "priv.json"))
			if err != nil {
				t.Fatal(err)
			}
			r := &configv1.PrivilegedRevision{Revision: 1, ProtocolVersion: 2, InstallationBaseline: true, ApprovalGeneration: 1, ConfigHash: privileged.Hash(local), Privileged: local.Proto(), Authorization: &hostv1.HostAuthorization{ServiceId: "fixture"}}
			if err = store.AdoptBaseline(r, local, local.RequiredPrivilegeMode, privileged.Receipt{ID: "baseline"}); err != nil {
				t.Fatal(err)
			}
			old := privileged.ActiveStore()
			privileged.SetActive(store)
			defer privileged.SetActive(old)
			caps := detect(true, local.RequiredPrivilegeMode, false, "non-root fixture")
			if !caps.RemoteControl.Available || caps.Execution.Available != execution || caps.Webssh.Available == execution {
				t.Fatalf("sub-capabilities or same-identity grant ignored: %+v", caps)
			}
		})
	}
}
