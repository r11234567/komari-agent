package rescue

import (
	"context"
	"errors"
	"os/exec"
	"testing"
)

func TestSSHWindowFirewallDiagnosis(t *testing.T) {
	unreadable := errors.New("permission denied")
	native := []byte(`{"nftables":[{"chain":{"family":"inet","table":"filter","name":"input","hook":"input","type":"filter"}}]}`)
	legacy := []byte(`{"nftables":[{"chain":{"family":"ip","table":"filter","name":"INPUT","hook":"input","type":"filter"}}]}`)
	for _, tc := range []struct {
		name, ufw, backend, code string
		ufwErr, ipsetErr         error
		nft                      []byte
	}{
		{name: "UFW wins over the presence of nft", ufw: "WARN: example\nStatus: active\n", nft: native, backend: sshWindowUFW},
		{name: "UFW package required", ufw: "Status: active\n", ipsetErr: exec.ErrNotFound, code: "SSH_UFW_IPSET_MISSING"},
		{name: "UFW kernel read failure", ufw: "Status: active\n", ipsetErr: unreadable, code: sshFirewallCheckFailed},
		{name: "UFW read failure does not fall back", ufwErr: unreadable, nft: native, code: sshFirewallCheckFailed},
		{name: "inactive UFW leaves native nftables", ufw: "Status: inactive\n", nft: native, backend: sshWindowNFT},
		{name: "iptables nft compatibility alone", ufwErr: exec.ErrNotFound, nft: legacy, code: sshFirewallUnsupported},
		{name: "no firewall tool", ufwErr: exec.ErrNotFound, code: sshFirewallUnsupported},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend, err := inspectSSHWindowFirewall(t.Context(), func(_ context.Context, cmd string, _ ...string) ([]byte, error) {
				switch cmd {
				case "ufw":
					return []byte(tc.ufw), tc.ufwErr
				case "ipset":
					return nil, tc.ipsetErr
				case "nft":
					if tc.nft != nil {
						return tc.nft, nil
					}
				}
				return nil, exec.ErrNotFound
			})
			if tc.code == "" {
				if err != nil || backend != tc.backend {
					t.Fatalf("got %q, %v; want %s", backend, err, tc.backend)
				}
				return
			}
			var diagnostic *sshWindowSetupError
			if backend != "" || !errors.As(err, &diagnostic) || diagnostic.code != tc.code {
				t.Fatalf("got %q, %v; want %s", backend, err, tc.code)
			}
		})
	}
}
