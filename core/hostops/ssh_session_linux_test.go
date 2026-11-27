package hostops

import (
	"net"
	"strings"
	"testing"
)

func TestDirectSSHProperties(t *testing.T) {
	valid := "Remote=yes\nRemoteHost=192.0.2.2\nService=sshd\nType=tty\nTTY=pts/4\nUser=1001\nState=active\nActive=yes\n"
	local := []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(30, 32)}}
	if got, err := verifySSHProperties(valid, local); err != nil || got != (sshSession{uid: 1001, tty: 4}) {
		t.Fatalf("direct SSH login = %+v, error = %v", got, err)
	}
	if got, err := verifySSHProperties(strings.Replace(valid, "TTY=pts/4", "TTY=", 1), local); err != nil || got != (sshSession{uid: 1001, tty: -1}) {
		t.Fatalf("direct SSH login without a logind TTY name = %+v, error = %v", got, err)
	}
	for _, tc := range []struct{ from, to string }{
		{"Remote=yes", "Remote=no"},
		{"Service=sshd", "Service=login"},
		{"Type=tty", "Type=unspecified"},
		{"TTY=pts/4", "TTY=ssh"},
		{"User=1001", "User=-1"},
		{"State=active", "State=closing"},
		{"Active=yes", "Active=no"},
		{"192.0.2.2", "::ffff:127.0.0.1"},
		{"192.0.2.2", "192.0.2.1"},
		{"192.0.2.2", "localhost"},
	} {
		if _, err := verifySSHProperties(strings.Replace(valid, tc.from, tc.to, 1), local); err == nil {
			t.Errorf("accepted invalid login with %s", tc.to)
		}
	}
}

func TestKernelPTYComesFromProcStat(t *testing.T) {
	parent, tty, err := parseProcessTerminal("42 (program with ) in name) S 21 42 42 34820 42")
	if err != nil || parent != 21 || tty != 4 {
		t.Fatalf("parent=%d tty=%d err=%v", parent, tty, err)
	}
	_, tty, err = parseProcessTerminal("42 (program) S 21 42 42 0 -1")
	if err != nil || tty != -1 {
		t.Fatalf("process with no controlling PTY: tty=%d err=%v", tty, err)
	}
}
