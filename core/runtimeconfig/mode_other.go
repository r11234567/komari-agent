//go:build !linux && !windows

package runtimeconfig

import reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"

func processMode() reportv1.PrivilegeMode { return reportv1.PrivilegeMode_PRIVILEGE_MODE_OTHER }
