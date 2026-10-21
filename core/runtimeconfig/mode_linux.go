//go:build linux

package runtimeconfig

import (
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"os"
)

func processMode() reportv1.PrivilegeMode {
	if os.Geteuid() == 0 {
		return reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT
	}
	return reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT
}
