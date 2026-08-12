package capability

import (
	"testing"

	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

func TestRemoteControlCapabilityRespectsRuntimeSetting(t *testing.T) {
	capabilities := Detect(false)
	if capabilities.RemoteControl.Available || capabilities.Execution.Available || capabilities.Webssh.Available {
		t.Fatalf("remote control capabilities must be disabled: %+v", capabilities)
	}
	if capabilities.RemoteControl.Limitation == "" {
		t.Fatal("disabled remote control requires a limitation")
	}
}

func TestNonPrivilegedCapabilityRejectsRemoteControl(t *testing.T) {
	capabilities := detect(true, reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, false, "fixture limitation")
	if capabilities.RemoteControl.Available || capabilities.Execution.Available || capabilities.Webssh.Available {
		t.Fatalf("non-privileged agent advertised remote control: %+v", capabilities)
	}
}

func TestPrivilegeFixturesDeclareLimitedCapabilities(t *testing.T) {
	fixtures := []struct {
		name       string
		privilege  reportv1.PrivilegeMode
		privileged bool
	}{
		{"linux-non-root", reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, false},
		{"windows-standard", reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_STANDARD_USER, false},
		{"windows-admin", reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_ADMINISTRATOR, true},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			capabilities := detect(true, fixture.privilege, fixture.privileged, "fixture limitation")
			if capabilities.PrivilegeMode != fixture.privilege {
				t.Fatalf("privilege mode = %s", capabilities.PrivilegeMode)
			}
			if capabilities.ServiceControl.Available != fixture.privileged {
				t.Fatalf("service capability = %+v", capabilities.ServiceControl)
			}
		})
	}
}
