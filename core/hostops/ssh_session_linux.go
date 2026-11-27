package hostops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

var errDirectSSH = errors.New("approval requires an interactive SSH login opened directly to this host")

// DirectSSHUID verifies the caller using logind and its OpenSSH ancestry.
// Environment variables and an allocated pseudo-terminal alone carry no trust.
func DirectSSHUID() (uint32, error) {
	terminal, err := os.Open("/dev/tty")
	if err != nil {
		return 0, errDirectSSH
	}
	terminal.Close()
	const loginctl = "/usr/bin/loginctl"
	if err := TrustedPath(loginctl); err != nil {
		return 0, errDirectSSH
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, loginctl, "--no-pager", "show-session", "self",
		"--property=Remote", "--property=RemoteHost", "--property=Service", "--property=Type", "--property=TTY", "--property=User")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	data, err := cmd.Output()
	if err != nil {
		return 0, errDirectSSH
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0, errDirectSSH
	}
	uid, err := verifySSHProperties(string(data), addrs)
	if err != nil || !hasOpenSSHAncestor() {
		return 0, errDirectSSH
	}
	return uid, nil
}

func verifySSHProperties(data string, locals []net.Addr) (uint32, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		key, value, valid := strings.Cut(line, "=")
		if !valid {
			return 0, errDirectSSH
		}
		fields[key] = value
	}
	if fields["Remote"] != "yes" || fields["Service"] != "sshd" || fields["Type"] != "tty" {
		return 0, errDirectSSH
	}
	tty := strings.TrimPrefix(fields["TTY"], "/dev/")
	// Some OpenSSH/PAM versions omit the logind TTY display name. The
	// caller already proved it has a kernel controlling terminal.
	if tty != "" {
		if !strings.HasPrefix(tty, "pts/") {
			return 0, errDirectSSH
		}
		if _, err := strconv.ParseUint(strings.TrimPrefix(tty, "pts/"), 10, 32); err != nil {
			return 0, errDirectSSH
		}
	}
	remote, err := netip.ParseAddr(fields["RemoteHost"])
	if err != nil {
		return 0, errDirectSSH
	}
	remote = remote.WithZone("").Unmap()
	if !remote.IsValid() || !remote.IsGlobalUnicast() {
		return 0, errDirectSSH
	}
	for _, local := range locals {
		switch ip := local.(type) {
		case *net.IPNet:
			if addr, ok := netip.AddrFromSlice(ip.IP); ok && addr.Unmap() == remote {
				return 0, errDirectSSH
			}
		case *net.IPAddr:
			if addr, ok := netip.AddrFromSlice(ip.IP); ok && addr.Unmap() == remote {
				return 0, errDirectSSH
			}
		}
	}
	uid, err := strconv.ParseUint(fields["User"], 10, 32)
	if err != nil {
		return 0, errDirectSSH
	}
	return uint32(uid), nil
}

func hasOpenSSHAncestor() bool {
	var trusted []os.FileInfo
	for _, path := range []string{"/usr/sbin/sshd", "/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session"} {
		if TrustedPath(path) == nil {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
				trusted = append(trusted, info)
			}
		}
	}
	pid := os.Getppid()
	for depth := 0; pid > 1 && depth < 32; depth++ {
		base := fmt.Sprintf("/proc/%d", pid)
		if info, err := os.Stat(base + "/exe"); err == nil {
			for _, executable := range trusted {
				if os.SameFile(info, executable) {
					return true
				}
			}
		}
		data, err := os.ReadFile(base + "/stat")
		if err != nil {
			return false
		}
		end := strings.LastIndex(string(data), ") ")
		if end < 0 {
			return false
		}
		fields := strings.Fields(string(data[end+2:]))
		if len(fields) < 2 {
			return false
		}
		pid, err = strconv.Atoi(fields[1])
		if err != nil {
			return false
		}
	}
	return false
}
