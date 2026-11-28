package rescue

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
	"golang.org/x/crypto/ssh"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestTemporarySSHWindowUFW(t *testing.T) {
	peer := os.Getenv("KOMARI_SSH_WINDOW_PEER_PID")
	if peer == "" {
		t.Skip("run scripts/ci/test-temporary-ssh-window.sh ufw in an isolated Linux environment")
	}
	run := func(name string, args ...string) string {
		t.Helper()
		out, err := sshWindowCommand(t.Context(), name, args...)
		if err != nil {
			t.Fatalf("%s %v: %v: %s", name, args, err, out)
		}
		return string(out)
	}
	dir, err := os.MkdirTemp("/run", "komari-ssh-ufw-")
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
	portText := strconv.Itoa(int(port))
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
		ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, "nsenter", "-t", peer, "-n", binary, "-test.run=^TestTemporarySSHWindowPeer$")
		cmd.Env = append(os.Environ(), "KOMARI_SSH_WINDOW_DIAL="+net.JoinHostPort(dest, portText), "KOMARI_SSH_WINDOW_SOURCE="+source,
			"KOMARI_SSH_WINDOW_TEST_KEY="+base64.StdEncoding.EncodeToString(signer.PublicKey().Marshal()))
		out, err := cmd.CombinedOutput()
		expect := "SSH peer blocked"
		if want {
			expect = "SSH peer connected"
		}
		if err != nil || !strings.Contains(string(out), expect) {
			t.Fatalf("%s → %s: want %q: %v %s", source, dest, expect, err, out)
		}
	}
	const v4, other4, host4 = "192.0.2.2", "192.0.2.3", "192.0.2.1"
	const v6, other6, host6 = "fd69:434f:4d41::2", "fd69:434f:4d41::3", "fd69:434f:4d41::1"

	run("ufw", "--force", "enable")
	run("ip", "route", "add", "default", "dev", "sshhost")
	manifest := &hostops.Manifest{ServiceName: "test", HostPolicyFile: filepath.Join(dir, "policy.json")}
	status := &rescuev1.RescueHelperStatus{}
	sshWindowStatus(t.Context(), manifest, "enrollment-ufw", status)
	if status.GetSshWindowError().GetCode() != "SSH_CONFIG_MISSING" {
		t.Fatalf("expected a compatible UFW host awaiting setup: %v", status)
	}
	setup, err := PlanSSHWindow(t.Context(), manifest, SSHWindowSetupOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if setup.config.Backend != sshWindowUFW || setup.config.Interface != "sshhost" || setup.config.Port != port {
		t.Fatalf("bad setup: %s", setup.Description())
	}
	if out := run("ipset", "list", "-name"); strings.Contains(out, sshWindowV4Set) {
		t.Fatal("read-only setup created a set")
	}
	probe(v4, host4, false)
	if err := setup.Apply(t.Context()); err != nil {
		t.Fatal(err)
	}
	config, err := loadSSHWindowConfig(manifest)
	if err != nil {
		t.Fatal(err)
	}
	newGrant := func(id, ip, previous string) *rescuev1.RescueSession {
		return &rescuev1.RescueSession{SessionId: strings.Repeat(id, 32), SshPort: &port, CreatedAt: timestamppb.Now(),
			SshWindow: &rescuev1.SSHWindowRequest{SourceIp: ip, PreviousGrantId: previous, EnrollmentKeyId: "enrollment-ufw"}}
	}
	grant := func(session *rescuev1.RescueSession, duration time.Duration) *rescuev1.TemporarySSHAccess {
		t.Helper()
		result, err := config.grant(t.Context(), session, duration, nil)
		if err != nil || !result.SSHAccess.GetGranted() ||
			result.SSHAccess.GetExpiryMechanism() != rescuev1.ExpiryMechanism_EXPIRY_MECHANISM_IPSET_TIMEOUT {
			t.Fatalf("grant: %v, %v", result.SSHAccess, err)
		}
		return result.SSHAccess
	}
	probe(v4, host4, false)
	first := newGrant("A", v4, "")
	receipt := grant(first, temporarySSHDuration)
	if remaining := receipt.GetExpiresAt().AsTime().Sub(receipt.GetGrantedAt().AsTime()); remaining > temporarySSHDuration || remaining < temporarySSHDuration-3*time.Second {
		t.Fatalf("unexpected production deadline: %s", remaining)
	}
	probe(v4, host4, true)
	probe(other4, host4, false)
	probe(v6, host6, false)
	run("iptables", "-A", "ufw-user-input", "-p", "tcp", "-s", v4, "--dport", portText, "-j", "DROP")
	probe(v4, host4, false)
	run("iptables", "-D", "ufw-user-input", "-p", "tcp", "-s", v4, "--dport", portText, "-j", "DROP")
	if duplicate := grant(first, temporarySSHDuration); duplicate.GetExpiresAt().AsTime().After(receipt.GetExpiresAt().AsTime().Add(time.Second)) {
		t.Fatal("duplicate extended the window")
	}
	// Refuse to grant if any other rule references the set.
	run("iptables", "-N", "komari-test-extra")
	run("iptables", "-A", "komari-test-extra", "-m", "set", "--match-set", sshWindowV4Set, "src", "-j", "ACCEPT")
	if _, err := config.inspect(t.Context(), true); !errors.Is(err, errSSHWindowRules) {
		t.Fatalf("unexpected set reference went undetected: %v", err)
	}
	run("iptables", "-F", "komari-test-extra")
	run("iptables", "-X", "komari-test-extra")

	second := newGrant("B", v6, first.SessionId)
	grant(second, temporarySSHDuration)
	probe(v4, host4, false)
	probe(v6, host6, true)
	probe(other6, host6, false)
	out, err := config.revoke(t.Context(), "enrollment-ufw", second.SessionId)
	if err != nil || out.SSHAccess.GetGranted() || out.SSHAccess.GetGrantId() != second.SessionId {
		t.Fatalf("revoke: %v, %v", out.SSHAccess, err)
	}
	probe(v6, host6, false)

	beforeReload := newGrant("C", v4, "")
	grant(beforeReload, temporarySSHDuration)
	probe(v4, host4, true)
	run("ufw", "reload")
	probe(v4, host4, false)
	status = &rescuev1.RescueHelperStatus{}
	sshWindowStatus(t.Context(), manifest, "enrollment-ufw", status)
	if status.GetSshAccessPort() != port || status.GetSshAccess().GetGranted() {
		t.Fatalf("expected ready, but old grant closed after reload: %v", status)
	}
	if _, err := config.grant(t.Context(), beforeReload, temporarySSHDuration, nil); err == nil {
		t.Fatal("previous grant reopened after UFW reload")
	}
	run("iptables", "-A", "ufw-after-input", "-p", "tcp", "-s", v4, "--dport", portText, "-j", "DROP")
	afterRule := newGrant("E", v4, "")
	grant(afterRule, temporarySSHDuration)
	probe(v4, host4, false)
	if _, err := config.revoke(t.Context(), "enrollment-ufw", afterRule.SessionId); err != nil {
		t.Fatal(err)
	}
	short := newGrant("D", other4, "")
	grant(short, 4*time.Second)
	probe(other4, host4, true)
	probe(v4, host4, false)
	// No helper or panel call is involved during expiry.
	time.Sleep(5 * time.Second)
	probe(other4, host4, false)
	if active, err := config.inspect(t.Context(), true); err != nil || active != nil {
		t.Fatalf("expired grant is still present: %+v, %v", active, err)
	}
}
