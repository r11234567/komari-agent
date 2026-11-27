package hostops

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

var errDirectSSH = errors.New("approval requires an interactive SSH login opened directly to this host")

// DirectSSHUID verifies the caller using logind and its OpenSSH ancestry.
// Environment variables and an allocated pseudo-terminal alone carry no trust.
func DirectSSHUID() (uint32, error) {
	_, tty, err := processTerminal("/proc/self")
	if err != nil {
		return 0, errDirectSSH
	}
	if tty < 0 {
		return 0, errDirectSSH
	}
	const loginctl = "/usr/bin/loginctl"
	if err := TrustedPath(loginctl); err != nil {
		return 0, errDirectSSH
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, loginctl, "--no-pager", "show-session", "self",
		"--property=Remote", "--property=RemoteHost", "--property=Service", "--property=Type",
		"--property=TTY", "--property=User", "--property=State", "--property=Active")
	cmd.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL=C"}
	data, err := cmd.Output()
	if err != nil {
		return 0, errDirectSSH
	}
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return 0, errDirectSSH
	}
	session, err := verifySSHProperties(string(data), addrs)
	if err != nil || !ownsLoginTerminal(tty, session.tty) {
		return 0, errDirectSSH
	}
	return session.uid, nil
}

type sshSession struct {
	uid uint32
	tty int // -1 if PAM did not publish the PTY name.
}

func verifySSHProperties(data string, locals []net.Addr) (sshSession, error) {
	fields := make(map[string]string)
	for _, line := range strings.Split(strings.TrimSpace(data), "\n") {
		key, value, valid := strings.Cut(line, "=")
		if !valid {
			return sshSession{}, errDirectSSH
		}
		fields[key] = value
	}
	if fields["Remote"] != "yes" || fields["Service"] != "sshd" || fields["Type"] != "tty" ||
		fields["State"] != "active" || fields["Active"] != "yes" {
		return sshSession{}, errDirectSSH
	}
	tty := strings.TrimPrefix(fields["TTY"], "/dev/")
	index := -1
	if tty != "" {
		if !strings.HasPrefix(tty, "pts/") {
			return sshSession{}, errDirectSSH
		}
		n, err := strconv.ParseUint(strings.TrimPrefix(tty, "pts/"), 10, 31)
		if err != nil {
			return sshSession{}, errDirectSSH
		}
		index = int(n)
	}
	remote, err := netip.ParseAddr(fields["RemoteHost"])
	if err != nil {
		return sshSession{}, errDirectSSH
	}
	remote = remote.WithZone("").Unmap()
	if !remote.IsValid() || !remote.IsGlobalUnicast() {
		return sshSession{}, errDirectSSH
	}
	for _, local := range locals {
		switch ip := local.(type) {
		case *net.IPNet:
			if addr, ok := netip.AddrFromSlice(ip.IP); ok && addr.Unmap() == remote {
				return sshSession{}, errDirectSSH
			}
		case *net.IPAddr:
			if addr, ok := netip.AddrFromSlice(ip.IP); ok && addr.Unmap() == remote {
				return sshSession{}, errDirectSSH
			}
		}
	}
	uid, err := strconv.ParseUint(fields["User"], 10, 32)
	if err != nil {
		return sshSession{}, errDirectSSH
	}
	return sshSession{uid: uint32(uid), tty: index}, nil
}

func trustedExecutables(paths ...string) (trusted []os.FileInfo) {
	for _, path := range paths {
		if TrustedPath(path) == nil {
			if info, err := os.Stat(path); err == nil && info.Mode().IsRegular() {
				trusted = append(trusted, info)
			}
		}
	}
	return trusted
}

func ownsLoginTerminal(current, reported int) bool {
	sshd := trustedExecutables("/usr/bin/sshd", "/usr/sbin/sshd", "/usr/lib/ssh/sshd-session",
		"/usr/lib/openssh/sshd-session", "/usr/libexec/openssh/sshd-session")
	// Ubuntu's sudo alternative can point to sudo.ws or the packaged sudo-rs
	// binary. Match their trusted executable inodes without trusting the link.
	sudo := trustedExecutables("/usr/bin/sudo", "/usr/bin/sudo.ws", "/usr/lib/cargo/bin/sudo")
	pid := os.Getppid()
	for depth := 0; pid > 1 && depth < 32; depth++ {
		base := fmt.Sprintf("/proc/%d", pid)
		parent, controlling, err := processTerminal(base)
		if err != nil {
			return false
		}
		if info, err := os.Stat(base + "/exe"); err == nil {
			for _, executable := range sshd {
				if os.SameFile(info, executable) && (reported < 0 || current == reported) && holdsPTYMaster(base, current) {
					return true
				}
			}
			// sudo with use_pty holds the command's PTY master on the
			// caller's terminal. Verify both sides before following it.
			if controlling >= 0 && controlling != current {
				for _, executable := range sudo {
					if os.SameFile(info, executable) && holdsPTYMaster(base, current) {
						current = controlling
						break
					}
				}
			}
		}
		pid = parent
	}
	return false
}

func processTerminal(base string) (parent, tty int, err error) {
	data, err := os.ReadFile(base + "/stat")
	if err != nil {
		return 0, -1, err
	}
	return parseProcessTerminal(string(data))
}

func parseProcessTerminal(stat string) (parent, tty int, err error) {
	end := strings.LastIndex(stat, ") ")
	if end < 0 {
		return 0, -1, errDirectSSH
	}
	fields := strings.Fields(stat[end+2:])
	if len(fields) < 5 {
		return 0, -1, errDirectSSH
	}
	parent, err = strconv.Atoi(fields[1])
	device, decodeErr := strconv.ParseInt(fields[4], 10, 32)
	if err != nil || decodeErr != nil {
		return 0, -1, errDirectSSH
	}
	number := uint64(uint32(device))
	major, minor := unix.Major(number), unix.Minor(number)
	if major < 136 || major > 143 || (major != 136 && minor > 255) {
		return parent, -1, nil
	}
	return parent, int((major-136)*256 + minor), nil
}

func holdsPTYMaster(base string, tty int) bool {
	dir, err := os.Open(base + "/fdinfo")
	if err != nil {
		return false
	}
	defer dir.Close()
	entries, _ := dir.Readdirnames(256)
	for _, name := range entries {
		data, err := os.ReadFile(filepath.Join(dir.Name(), name))
		if err != nil {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			field, text, ok := strings.Cut(line, ":")
			if ok && field == "tty-index" && strings.TrimSpace(text) == strconv.Itoa(tty) {
				return true
			}
		}
	}
	return false
}
