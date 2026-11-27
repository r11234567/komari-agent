package hostops

import (
	"net"
	"strings"
	"testing"
)

func TestDirectSSHProperties(t *testing.T) {
	valid := "Remote=yes\nRemoteHost=192.0.2.2\nService=sshd\nType=tty\nTTY=pts/4\nUser=1001\n"
	local := []net.Addr{&net.IPNet{IP: net.ParseIP("192.0.2.1"), Mask: net.CIDRMask(30, 32)}}
	if uid, err := verifySSHProperties(valid, local); err != nil || uid != 1001 {
		t.Fatalf("direct SSH UID = %d, error = %v", uid, err)
	}
	for _, tc := range []struct{ from, to string }{
		{"Remote=yes", "Remote=no"},
		{"Service=sshd", "Service=login"},
		{"Type=tty", "Type=unspecified"},
		{"TTY=pts/4", "TTY="},
		{"TTY=pts/4", "TTY=ssh"},
		{"User=1001", "User=-1"},
		{"192.0.2.2", "::ffff:127.0.0.1"},
		{"192.0.2.2", "192.0.2.1"},
		{"192.0.2.2", "localhost"},
	} {
		if _, err := verifySSHProperties(strings.Replace(valid, tc.from, tc.to, 1), local); err == nil {
			t.Errorf("accepted invalid login with %s", tc.to)
		}
	}
}
