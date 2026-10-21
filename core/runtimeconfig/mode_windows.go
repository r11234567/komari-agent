//go:build windows

package runtimeconfig

import (
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"golang.org/x/sys/windows"
)

func processMode() reportv1.PrivilegeMode {
	if windows.Token(0).IsElevated() {
		return reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_ADMINISTRATOR
	}
	return reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_STANDARD_USER
}
