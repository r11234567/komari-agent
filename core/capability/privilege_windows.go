//go:build windows

package capability

import (
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"golang.org/x/sys/windows"
)

func privilegeState() (reportv1.PrivilegeMode, bool, string) {
	token := windows.Token(0)
	if token.IsElevated() {
		return reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_ADMINISTRATOR, true, ""
	}
	return reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_STANDARD_USER, false, "running as a standard Windows user; elevated service control is unavailable"
}

func returnRouteProbeState() *reportv1.CapabilityState {
	if windows.Token(0).IsElevated() {
		return available()
	}
	return limited("built-in ICMP return-route probes require an administrator service token")
}
