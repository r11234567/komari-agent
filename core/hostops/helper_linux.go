//go:build linux

package hostops

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// PrepareHelperStatus runs in the root helper on every start. /run is volatile,
// and legacy migration never guaranteed this directory existed in the first place.
func PrepareHelperStatus(m *Manifest) error {
	if os.Geteuid() != 0 || m == nil || m.InitSystem != "systemd" || !ValidService(m.ServiceName) {
		return errors.New("helper heartbeat preparation requires a root systemd helper")
	}
	dir := filepath.Dir(HelperStatusPath(m))
	if err := TrustedPath(filepath.Dir(dir)); err != nil {
		return err
	}
	if err := os.Mkdir(dir, 0o755); err != nil && !os.IsExist(err) {
		return err
	}
	// Never repair ownership, follow a symlink or accept a writable existing
	// directory. Only a directory already protected from other users is usable.
	if err := TrustedPath(dir); err != nil {
		return err
	}
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return errors.New("helper heartbeat parent is not a directory")
	}
	// A restrictive inherited umask must not hide public evidence from the Agent.
	return os.Chmod(dir, 0o755)
}

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
	expected := filepath.Join(filepath.Dir(m.HostTool), "komari-agent-rescue")
	exe, err := os.Readlink(prefix + "/exe")
	// Linux ptrace rules prevent a non-root daemon from reading a root
	// process's exe link. Its root-owned heartbeat binds executable and PID
	// start ticks; UID and cgroup are still observed from the kernel.
	if err != nil {
		if !os.IsPermission(err) || os.Geteuid() == 0 {
			return nil, err
		}
		exe = status.Executable
	}
	if exe != expected || status.Executable != expected {
		return nil, errors.New("helper PID executable mismatch")
	}
	ticks, err := ProcessStartTicks(status.PID)
	if err != nil {
		return nil, err
	}
	if ticks == 0 || ticks != status.StartTicks {
		return nil, errors.New("helper PID was reused")
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

func ProcessStartTicks(pid int) (uint64, error) {
	b, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, err
	}
	end := strings.LastIndex(string(b), ") ")
	if end < 0 {
		return 0, errors.New("invalid proc stat")
	}
	fields := strings.Fields(string(b)[end+2:])
	if len(fields) < 20 {
		return 0, errors.New("truncated proc stat")
	}
	return strconv.ParseUint(fields[19], 10, 64)
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
