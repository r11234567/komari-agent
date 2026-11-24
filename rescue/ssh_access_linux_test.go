package rescue

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func TestTemporarySSHRejectsLoopbackAndNonSSH(t *testing.T) {
	for _, tc := range []struct {
		bind, banner string
		probe        bool
	}{
		{"127.0.0.1:0", "SSH-2.0-loopback\r\n", true},
		{"0.0.0.0:0", "HTTP/1.1 200 OK\r\n", false},
	} {
		t.Run(tc.bind, func(t *testing.T) {
			listener, err := net.Listen("tcp4", tc.bind)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			go serveSSHTest(t.Context(), listener, func(conn net.Conn) { _, _ = conn.Write([]byte(tc.banner)) })
			port := uint32(listener.Addr().(*net.TCPAddr).Port)
			if got := probeSSHIdentification(t.Context(), net.JoinHostPort("127.0.0.1", fmt.Sprint(port))); got != tc.probe {
				t.Fatalf("SSH identification result %v, want %v", got, tc.probe)
			}
			if state := inspectSSHDaemon(t.Context(), port); state.Reachable || state.Limitation == "" {
				t.Fatalf("listener should not qualify: %v", state)
			}
			if isPrivileged() {
				config := ActionConfig{IsolationStatePath: filepath.Join(t.TempDir(), "isolation.json")}
				result, err := grantTemporarySSHAccess(t.Context(), config, port)
				if err == nil || result.SSHAccess == nil || result.SSHAccess.Granted {
					t.Fatalf("bad grant receipt: %+v, error: %v", result, err)
				}
				if _, err := os.Stat(sshAccessStatePath(config)); !os.IsNotExist(err) {
					t.Fatalf("failed preflight created SSH state: %v", err)
				}
			}
		})
	}
}

func TestTemporarySSHNftRejectsAmbiguousHooks(t *testing.T) {
	for name, extra := range map[string]string{
		"another input": `,{"chain":{"family":"ip","table":"other","name":"input","hook":"input","type":"filter"}}`,
		"ingress":       `,{"chain":{"family":"netdev","table":"other","name":"early","hook":"ingress","type":"filter"}}`,
		"prerouting":    `,{"chain":{"family":"inet","table":"other","name":"early","hook":"prerouting","type":"filter"}}`,
		"single input":  "",
	} {
		t.Run(name, func(t *testing.T) {
			var rules sshNftRuleset
			if err := json.Unmarshal([]byte(`{"nftables":[{"chain":{"family":"inet","table":"test","name":"input","hook":"input","type":"filter"}}`+extra+`]}`), &rules); err != nil {
				t.Fatal(err)
			}
			chain, err := rules.sshInputChain()
			if extra == "" && (err != nil || chain == nil || chain.Table != "test" || chain.Name != "input") {
				t.Fatalf("unexpected nft chain: %v, %v", chain, err)
			}
			if extra != "" && err == nil {
				t.Fatalf("ambiguous firewall accepted: %v", chain)
			}
		})
	}
}

// Run in an isolated network namespace with a linked peer and a blocking inet
// input filter. The peer's ssh-keyscan performs a real SSH key exchange.
func TestTemporarySSHNftPeerIntegration(t *testing.T) {
	peer, address := os.Getenv("KOMARI_SSH_TEST_PEER_PID"), os.Getenv("KOMARI_SSH_TEST_ADDRESS")
	if peer == "" || address == "" {
		t.Skip("requires isolated nftables network and peer namespaces")
	}
	listener, err := net.Listen("tcp4", net.JoinHostPort(address, "0"))
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(private)
	if err != nil {
		t.Fatal(err)
	}
	server := &ssh.ServerConfig{NoClientAuth: true}
	server.AddHostKey(signer)
	go serveSSHTest(t.Context(), listener, func(conn net.Conn) {
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		if sshConn, _, _, err := ssh.NewServerConn(conn, server); err == nil {
			_ = sshConn.Close()
		}
	})

	checkPeer := func(want bool) {
		t.Helper()
		ctx, cancel := context.WithTimeout(t.Context(), 4*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "nsenter", "-t", peer, "-n", "ssh-keyscan", "-t", "ed25519", "-T", "1", "-p", strconv.Itoa(int(port)), address).Output()
		if got := err == nil && strings.Contains(string(out), "ssh-ed25519 "); got != want {
			t.Fatalf("peer reached SSH = %v, want %v (command error: %v)", got, want, err)
		}
	}
	config := ActionConfig{IsolationStatePath: filepath.Join(t.TempDir(), "isolation.json")}
	t.Cleanup(func() { _ = CloseTemporarySSHAccess(context.Background(), config) })
	checkPeer(false)
	grant, err := grantTemporarySSHAccess(t.Context(), config, port)
	if err != nil || !grant.SSHAccess.GetGranted() || !grant.SSHAccess.GetSshdState().GetReachable() {
		t.Fatalf("grant failed: %v, %v", grant.SSHAccess, err)
	}
	if state, err := loadSSHAccessState(config); err != nil || state.NftChain == nil {
		t.Fatalf("grant did not target existing input filter: %v, %v", state, err)
	}
	checkPeer(true)
	revoked, err := revokeTemporarySSHAccess(t.Context(), config)
	if err != nil || revoked.SSHAccess == nil || revoked.SSHAccess.Granted {
		t.Fatalf("revoke failed: %v, %v", revoked.SSHAccess, err)
	}
	checkPeer(false)
	if _, err := grantTemporarySSHAccess(t.Context(), config, port); err != nil {
		t.Fatal(err)
	}
	expired, err := loadSSHAccessState(config)
	if err != nil {
		t.Fatal(err)
	}
	expired.ExpiresAt = time.Now().Add(-time.Second)
	if err := saveSSHAccessState(config, expired); err != nil {
		t.Fatal(err)
	}
	if err := ReconcileTemporarySSHAccess(t.Context(), config); err != nil {
		t.Fatal(err)
	}
	checkPeer(false)
}

func serveSSHTest(ctx context.Context, listener net.Listener, serve func(net.Conn)) {
	for ctx.Err() == nil {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			serve(conn)
		}()
	}
}
