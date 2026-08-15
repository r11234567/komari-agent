//go:build linux

package capability

import (
	"os"
	"strconv"
	"strings"

	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

const linuxCapabilityNetRaw = uint64(1 << 13)

func privilegeState() (reportv1.PrivilegeMode, bool, string) {
	if os.Geteuid() == 0 {
		return reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT, true, ""
	}
	return reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, false, "running as a non-root Linux user; privileged service control is unavailable"
}

func returnRouteProbeState() *reportv1.CapabilityState {
	if os.Geteuid() == 0 {
		return available()
	}
	status, err := os.ReadFile("/proc/self/status")
	if err == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if !strings.HasPrefix(line, "CapEff:") {
				continue
			}
			value, parseErr := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(line, "CapEff:")), 16, 64)
			if parseErr == nil && value&linuxCapabilityNetRaw != 0 {
				return available()
			}
			break
		}
	}
	return limited("built-in ICMP return-route probes require root or CAP_NET_RAW")
}
