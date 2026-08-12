//go:build linux

package capability

import (
	"os"

	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

func privilegeState() (reportv1.PrivilegeMode, bool, string) {
	if os.Geteuid() == 0 {
		return reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT, true, ""
	}
	return reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, false, "running as a non-root Linux user; privileged service control is unavailable"
}
