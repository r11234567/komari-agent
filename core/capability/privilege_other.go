//go:build !linux && !windows

package capability

import reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"

func privilegeState() (reportv1.PrivilegeMode, bool, string) {
	return reportv1.PrivilegeMode_PRIVILEGE_MODE_OTHER, false, "privilege detection is not available on this platform"
}

func returnRouteProbeState() *reportv1.CapabilityState {
	return limited("built-in ICMP return-route probe capability is not available on this platform")
}
