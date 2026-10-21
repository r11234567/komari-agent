//go:build linux

package hostops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func ReadHelperStatus(m *Manifest) (*HelperStatus, error) {
	var status HelperStatus
	if err := ReadJSON(HelperStatusPath(m), &status, true); err != nil {
		return nil, err
	}
	if status.PID <= 1 || time.Since(status.ObservedAt) > 10*time.Second || status.ObservedAt.After(time.Now().Add(time.Second)) {
		return nil, errors.New("helper heartbeat is stale")
	}
	prefix := fmt.Sprintf("/proc/%d", status.PID)
	b, err := os.ReadFile(prefix + "/status")
	if err != nil {
		return nil, err
	}
	root := false
	for _, line := range strings.Split(string(b), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			root = len(fields) == 4
			for _, v := range fields {
				root = root && v == "0"
			}
		}
	}
	if !root {
		return nil, errors.New("helper PID is not root")
	}
	exe, err := os.Readlink(prefix + "/exe")
	if err != nil {
		return nil, err
	}
	if exe != filepath.Join(filepath.Dir(m.HostTool), "komari-agent-rescue") {
		return nil, errors.New("helper PID executable mismatch")
	}
	cgroup, err := os.ReadFile(prefix + "/cgroup")
	if err != nil {
		return nil, err
	}
	if !strings.Contains(string(cgroup), "/"+m.ServiceName+"-rescue.service") {
		return nil, errors.New("helper PID is not in its dedicated systemd unit")
	}
	if err = TrustedPath(exe); err != nil {
		return nil, err
	}
	return &status, nil
}

func HostActionsReady(m *Manifest) bool {
	if m == nil || m.InitSystem != "systemd" {
		return false
	}
	if _, err := ReadTrust(m); err != nil {
		return false
	}
	if err := TrustedPath(m.HostTool); err != nil {
		return false
	}
	if err := TrustedPath("/usr/bin/pamtester"); err != nil {
		return false
	}
	const path = "/etc/pam.d/komari-host"
	if err := TrustedPath(path); err != nil {
		return false
	}
	data, err := os.ReadFile(path)
	return err == nil && string(data) == "# Komari host: fresh local password and account validity\nauth required pam_unix.so\naccount required pam_unix.so\n"
}
