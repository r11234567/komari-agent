//go:build linux

package rescue

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTemporarySSHWindowNftables(t *testing.T) {
	peer := os.Getenv("KOMARI_SSH_WINDOW_PEER_PID")
	if peer == "" {
		t.Skip("run scripts/ci/test-temporary-ssh-window.sh in an isolated Linux environment")
	}
	dir, err := os.MkdirTemp("/run", "komari-ssh-window-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	listener, err := net.Listen("tcp", "[::]:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	port := uint32(listener.Addr().(*net.TCPAddr).Port)
	manifest := &hostops.Manifest{ServiceName: "test", HostPolicyFile: filepath.Join(dir, "policy.json"), CredentialsFile: filepath.Join(dir, "credentials.json")}
	checkStatus := func(code, detail string, wantPort uint32) {
		t.Helper()
		status := &rescuev1.RescueHelperStatus{}
		sshWindowStatus(t.Context(), manifest, "enrollment-test", status)
		if !status.GetSshWindowSupported() || status.GetSshAccessPort() != wantPort ||
			status.GetSshWindowError().GetCode() != code || !strings.Contains(status.GetSshWindowError().GetMessage(), detail) {
			t.Fatalf("want SSH status %q containing %q with port %d, got %v", code, detail, wantPort, status)
		}
	}
	configPath := filepath.Join(dir, "test.temporary-ssh.json")
	checkStatus("SSH_CONFIG_MISSING", configPath, 0)
	if err := os.WriteFile(configPath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkStatus("SSH_CONFIG_INVALID", "invalid temporary SSH table", 0)
	settings := []byte(fmt.Sprintf(`{"table":"public_edge_guard","chain":"input","interface":"sshhost","port":%d}`, port))
	if err := os.WriteFile(configPath, settings, 0o600); err != nil {
		t.Fatal(err)
	}
	checkStatus("SSH_NFT_READ_FAILED", "public_edge_guard", 0)
	config, err := loadSSHWindowConfig(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if err := config.apply(t.Context(), "add table inet public_edge_guard\n"); err != nil {
		t.Fatal(err)
	}
	checkStatus("SSH_NFT_RULES_INVALID", "public_edge_guard/input", 0)
	firewall := fmt.Sprintf(`table inet public_edge_guard {
	  set komari_rescue_ssh_v4 { type ipv4_addr; flags timeout; }
	  set komari_rescue_ssh_v6 { type ipv6_addr; flags timeout; }
	  chain input {
	    type filter hook input priority -100; policy accept;
	    ct state established,related accept
	    iifname "sshhost" ip6 nexthdr ipv6-icmp accept
	    iifname "sshhost" ip saddr @komari_rescue_ssh_v4 tcp dport %d accept
	    iifname "sshhost" ip6 saddr @komari_rescue_ssh_v6 tcp dport %d accept
	    iifname "sshhost" drop
	  }
	}
	table ip crowdsec {
	  chain incoming { type filter hook input priority -10; policy accept; }
	}
	table ip filter {
	  chain INPUT { type filter hook input priority 0; policy accept; }
	}
	table ip6 filter {
	  chain INPUT { type filter hook input priority 0; policy accept; }
	}
	`, port, port)
	if err := config.apply(t.Context(), firewall); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(config.statePath, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	checkStatus("SSH_STATE_INVALID", "unexpected EOF", 0)
	if err := os.Remove(config.statePath); err != nil {
		t.Fatal(err)
	}
	checkStatus("", "", port)
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
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if sshConn, _, _, err := ssh.NewServerConn(conn, server); err == nil {
			_ = sshConn.Close()
		}
	})
	binary, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	probe := func(source, dest string, want bool) {
		t.Helper()
		address := net.JoinHostPort(dest, strconv.FormatUint(uint64(port), 10))
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "nsenter", "-t", peer, "-n", binary, "-test.run=^TestTemporarySSHWindowPeer$")
		cmd.Env = append(os.Environ(), "KOMARI_SSH_WINDOW_DIAL="+address, "KOMARI_SSH_WINDOW_SOURCE="+source,
			"KOMARI_SSH_WINDOW_TEST_KEY="+base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal()))
		output, err := cmd.CombinedOutput()
		connected := err == nil && strings.Contains(string(output), "SSH peer connected")
		if connected != want || !want && (err != nil || !strings.Contains(string(output), "SSH peer blocked")) {
			t.Fatalf("%s → %s: connected=%t, want %t: %v %s", source, address, connected, want, err, output)
		}
	}
	requireGrant := func(session *rescuev1.RescueSession, lifetime time.Duration) *rescuev1.TemporarySSHAccess {
		t.Helper()
		result, err := config.grant(t.Context(), session, lifetime, nil)
		if err != nil || !result.SSHAccess.GetGranted() || !result.SSHAccess.GetSshdState().GetReachable() {
			t.Fatalf("grant: %v, %v", result.SSHAccess, err)
		}
		return result.SSHAccess
	}
	makeSession := func(id, source, previous string) *rescuev1.RescueSession {
		return &rescuev1.RescueSession{
			SessionId: strings.Repeat(id, 32), SshPort: &port, CreatedAt: timestamppb.Now(),
			SshWindow: &rescuev1.SSHWindowRequest{SourceIp: source, PreviousGrantId: previous, EnrollmentKeyId: "enrollment-one"},
		}
	}
	probe("192.0.2.2", "192.0.2.1", false)
	if err := config.apply(t.Context(), "add chain inet public_edge_guard extra\nadd rule inet public_edge_guard extra ip saddr @komari_rescue_ssh_v4 accept\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := config.inspect(t.Context(), true); err == nil || !strings.Contains(err.Error(), "unexpected rule") {
		t.Fatalf("set reuse outside its fixed port was accepted: %v", err)
	}
	if err := config.apply(t.Context(), "flush chain inet public_edge_guard extra\ndelete chain inet public_edge_guard extra\n"); err != nil {
		t.Fatal(err)
	}
	v4 := makeSession("A", "192.0.2.2", "")
	first := requireGrant(v4, temporarySSHDuration)
	if lifetime := first.GetExpiresAt().AsTime().Sub(first.GetGrantedAt().AsTime()); lifetime > 15*time.Minute || lifetime < 15*time.Minute-2*time.Second {
		t.Fatalf("production kernel deadline = %s", lifetime)
	}
	probe("192.0.2.2", "192.0.2.1", true)
	probe("192.0.2.3", "192.0.2.1", false)
	probe("fd69:434f:4d41::2", "fd69:434f:4d41::1", false)
	if err := config.apply(t.Context(), "add rule ip crowdsec incoming ip saddr 192.0.2.2 drop\n"); err != nil {
		t.Fatal(err)
	}
	probe("192.0.2.2", "192.0.2.1", false)
	if err := config.apply(t.Context(), "flush chain ip crowdsec incoming\n"); err != nil {
		t.Fatal(err)
	}
	if err := config.apply(t.Context(), config.flushCommands()+"add element inet public_edge_guard nonexistent { 192.0.2.3 }\n"); err == nil {
		t.Fatal("invalid nftables transaction succeeded")
	}
	probe("192.0.2.2", "192.0.2.1", true)
	if retry := requireGrant(v4, temporarySSHDuration); retry.ExpiresAt.AsTime().After(first.ExpiresAt.AsTime().Add(time.Second)) {
		t.Fatalf("retry extended expiry: %s → %s", first.ExpiresAt, retry.ExpiresAt)
	}
	v6 := makeSession("B", "fd69:434f:4d41::2", v4.SessionId)
	requireGrant(v6, temporarySSHDuration)
	if _, err := config.revoke(t.Context(), "enrollment-one", v4.SessionId); err != nil {
		t.Fatal(err)
	}
	probe("192.0.2.2", "192.0.2.1", false)
	probe("fd69:434f:4d41::2", "fd69:434f:4d41::1", true)
	probe("fd69:434f:4d41::3", "fd69:434f:4d41::1", false)
	removed, err := config.revoke(t.Context(), "enrollment-one", v6.SessionId)
	if err != nil || removed.SSHAccess.GetGrantId() != v6.SessionId || removed.SSHAccess.GetGranted() {
		t.Fatalf("explicit revoke: %v, %v", removed.SSHAccess, err)
	}
	probe("fd69:434f:4d41::2", "fd69:434f:4d41::1", false)
	beforeReload := makeSession("D", "fd69:434f:4d41::2", "")
	requireGrant(beforeReload, temporarySSHDuration)
	if err := config.apply(t.Context(), "delete table inet public_edge_guard\n"+firewall[:strings.Index(firewall, "table ip crowdsec")]); err != nil {
		t.Fatal(err)
	}
	config, err = loadSSHWindowConfig(manifest)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := config.grant(t.Context(), beforeReload, temporarySSHDuration, nil); err == nil {
		t.Fatal("replayed grant reopened after firewall reload and helper restart")
	}
	probe("fd69:434f:4d41::2", "fd69:434f:4d41::1", false)
	v6 = makeSession("E", "fd69:434f:4d41::2", "")
	requireGrant(v6, temporarySSHDuration)
	if err := os.WriteFile(manifest.CredentialsFile, []byte(`{"key_id":"enrollment-two"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	checkSSHWindowIdentity(t.Context(), manifest)
	probe("fd69:434f:4d41::2", "fd69:434f:4d41::1", false)
	if _, err := config.grant(t.Context(), v6, temporarySSHDuration, nil); err == nil {
		t.Fatal("closed grant reopened")
	}
	short := makeSession("C", "192.0.2.2", "")
	short.SshWindow.EnrollmentKeyId = "enrollment-two"
	requireGrant(short, 4*time.Second)
	probe("192.0.2.2", "192.0.2.1", true)
	// No helper, panel or reconciliation call is involved in expiration.
	time.Sleep(5 * time.Second)
	probe("192.0.2.2", "192.0.2.1", false)
	if active, err := config.inspect(t.Context(), true); err != nil || active != nil {
		t.Fatalf("kernel window still active: %+v, %v", active, err)
	}

	helper, panel, sign := jitterHelperFixture(t)
	if err := os.WriteFile(filepath.Join(filepath.Dir(helper.manifest.HostPolicyFile), helper.manifest.ServiceName+".temporary-ssh.json"), settings, 0o600); err != nil {
		t.Fatal(err)
	}
	config, err = loadSSHWindowConfig(helper.manifest)
	if err != nil {
		t.Fatal(err)
	}
	identity, ok := readHostIdentity(helper.manifest, helper.hostTrust)
	if !ok {
		t.Fatal("signed-watch identity unavailable")
	}
	panel.frames <- sign(time.Now(), 1)
	waitJitterCondition(t, helper.authorized.Load, 3*time.Second)
	watched := makeSession("F", "192.0.2.2", "")
	watched.SshWindow.EnrollmentKeyId = identity.KeyID
	watchReceipt := requireGrant(watched, temporarySSHDuration)
	panel.control <- nil
	waitJitterCondition(t, func() bool { return !helper.authorized.Load() }, 3*time.Second)
	probe("192.0.2.2", "192.0.2.1", true)
	waitJitterCondition(t, func() bool { return panel.requests.Load() >= 2 && panel.active.Load() == 1 }, 3*time.Second)
	panel.frames <- sign(time.Now(), 2)
	waitJitterCondition(t, helper.authorized.Load, 3*time.Second)
	if retry := requireGrant(watched, temporarySSHDuration); retry.ExpiresAt.AsTime().After(watchReceipt.ExpiresAt.AsTime().Add(time.Second)) {
		t.Fatal("a reconnect or duplicate extended the kernel deadline")
	}
	now := time.Now()
	panel.control <- &configv1.WatchPrivilegedDeliveryResponse{RescueEnrollmentRevoked: panel.seal(&securityv1.SignedInstruction{
		AgentId: identity.AgentID, InstructionType: "rescue:ssh-enrollment-revoked:v1", Nonce: "temporary-ssh-watch-test",
		Body: []byte(identity.KeyID), IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(30 * time.Second)),
	})}
	waitJitterCondition(t, func() bool {
		active, err := config.inspect(t.Context(), true)
		return active == nil && err == nil
	}, 3*time.Second)
	probe("192.0.2.2", "192.0.2.1", false)
}

func TestTemporarySSHWindowPeer(t *testing.T) {
	dest := os.Getenv("KOMARI_SSH_WINDOW_DIAL")
	if dest == "" {
		t.Skip("isolated peer process only")
	}
	source := netip.MustParseAddr(os.Getenv("KOMARI_SSH_WINDOW_SOURCE"))
	dialer := net.Dialer{Timeout: 500 * time.Millisecond, LocalAddr: &net.TCPAddr{IP: source.AsSlice()}}
	conn, err := dialer.Dial("tcp", dest)
	if err != nil {
		fmt.Println("SSH peer blocked:", err)
		return
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(time.Second))
	encoded, err := base64.StdEncoding.DecodeString(os.Getenv("KOMARI_SSH_WINDOW_TEST_KEY"))
	if err != nil {
		t.Fatal(err)
	}
	key, err := ssh.ParsePublicKey(encoded)
	if err != nil {
		t.Fatal(err)
	}
	client, _, _, err := ssh.NewClientConn(conn, dest, &ssh.ClientConfig{User: "test", HostKeyCallback: ssh.FixedHostKey(key)})
	if err != nil {
		t.Fatalf("TCP reachable but SSH handshake failed: %v", err)
	}
	defer client.Close()
	fmt.Println("SSH peer connected")
}
