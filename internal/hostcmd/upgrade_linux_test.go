//go:build linux

package hostcmd

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/hostops"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
)

// Called only inside the existing disposable real-systemd acceptance fixture.
// Reuse its actual Agent, Host, rescue, pinned test publisher and panel.
func exerciseInstalledRescueUpgrade(t *testing.T, m *hostops.Manifest, key ed25519.PrivateKey, panel *hostTestPanel) {
	t.Helper()
	stage := filepath.Join(filepath.Dir(m.HostTool), "upgrade-acceptance")
	if err := ensureTrustedDir(stage); err != nil {
		t.Fatal(err)
	}
	paths := []string{m.Executable, m.HostTool, helperBinary(m), helperConfig(m), m.HostPolicyFile, m.CredentialsFile, hostops.TrustPath(m), helperUnitPath(m)}
	read := func() [][]byte {
		result := make([][]byte, len(paths))
		for i, path := range paths {
			var err error
			result[i], err = os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
		}
		return result
	}
	unchanged := func(want [][]byte) {
		for i, got := range read() {
			if !bytes.Equal(got, want[i]) {
				t.Fatal("upgrade unexpectedly changed:", paths[i])
			}
		}
	}
	before := read()
	targets := make([][]byte, 3)
	for i, name := range []string{"agent", "host", "helper"} {
		targets[i] = append(append([]byte{}, before[i]...), []byte("\nisolated-upgrade-acceptance\n")...)
		if err := hostops.AtomicWrite(filepath.Join(stage, name), targets[i], 0o700); err != nil {
			t.Fatal(err)
		}
	}
	hash := func(data []byte) string { sum := sha256.Sum256(data); return hex.EncodeToString(sum[:]) }
	signed := testRelease(t, key, targets[2])
	metadata := filepath.Join(stage, "helper.release.json")
	if err := hostops.WriteJSON(metadata, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"upgrade-installed-rescue", "--manifest", m.ManifestPath,
		"--agent-artifact", filepath.Join(stage, "agent"), "--agent-sha256", hash(targets[0]),
		"--host-artifact", filepath.Join(stage, "host"), "--host-sha256", hash(targets[1]),
		"--helper-artifact", filepath.Join(stage, "helper"), "--release-manifest", metadata, "--version", "ci-stage6"}
	signed.Signature[0] ^= 1
	if err := hostops.WriteJSON(metadata, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(args, io.Discard); err == nil {
		t.Fatal("untrusted upgrade signature was accepted")
	}
	unchanged(before)
	signed.Signature[0] ^= 1
	if err := hostops.WriteJSON(metadata, signed, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(args, io.Discard); err != nil {
		t.Fatal("coordinated real rescue upgrade:", err)
	}
	after := read()
	for i := 0; i < 3; i++ {
		if !bytes.Equal(after[i], targets[i]) {
			t.Fatal("installed component did not receive target bytes:", paths[i])
		}
	}
	for i := 4; i < len(paths); i++ {
		if !bytes.Equal(after[i], before[i]) {
			t.Fatal("upgrade changed authority, identity or unit metadata:", paths[i])
		}
	}
	if err := waitHelper(m); err != nil {
		t.Fatal("real helper did not recover after coordinated upgrade:", err)
	}
	// Valid publisher signature, but an ELF that cannot execute: all components
	// and the previous helper config must be restored, not just the Agent.
	broken := []byte("\x7fELFisolated-invalid-executable")
	if err := hostops.AtomicWrite(filepath.Join(stage, "helper"), broken, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hostops.WriteJSON(metadata, testRelease(t, key, broken), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(args, io.Discard); err == nil {
		t.Fatal("unhealthy signed rescue upgrade claimed success")
	}
	unchanged(after)
	if err := waitHelper(m); err != nil {
		t.Fatal("previous real rescue did not recover after upgrade rollback:", err)
	}
	// A newer desired revision waiting for approval immediately withdraws work,
	// including across process restart and upgrade. It is not an unhealthy ELF.
	panel.mu.Lock()
	panel.current.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_CONFIRMATION
	panel.current.UpdateSequence++
	panel.mu.Unlock()
	if err := restartReviewedService(helperUnit(m)); err != nil {
		t.Fatal(err)
	}
	assertIdle := func() {
		t.Helper()
		panel.mu.Lock()
		leases := panel.rescueLeases
		panel.mu.Unlock()
		if err := verifyUpgradeService(helperUnit(m), helperBinary(m)); err != nil {
			t.Fatal("pending approval restarted or killed the installed helper:", err)
		}
		status, err := hostops.ReadHelperStatus(m)
		if err != nil || status.Authorized || status.LeaseReady {
			t.Fatalf("pending helper falsely advertises authorization/readiness: status=%+v error=%v", status, err)
		}
		panel.mu.Lock()
		defer panel.mu.Unlock()
		if panel.rescueLeases != leases {
			t.Fatal("idle helper leased rescue work without approval")
		}
	}
	assertIdle()
	if err := hostops.AtomicWrite(filepath.Join(stage, "helper"), targets[2], 0o700); err != nil {
		t.Fatal(err)
	}
	if err := hostops.WriteJSON(metadata, testRelease(t, key, targets[2]), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Run(args, io.Discard); err != nil {
		t.Fatal("pending approval must not block a signed software-only upgrade:", err)
	}
	assertIdle()
	unchanged(after)
	// Startup during a panel outage must also remain idle rather than prevent
	// restoring software. No connectivity failure substitutes for approval.
	panel.mu.Lock()
	panel.failAuthorization = true
	panel.mu.Unlock()
	if err := restartReviewedService(helperUnit(m)); err != nil {
		t.Fatal(err)
	}
	assertIdle()
	panel.mu.Lock()
	panel.failAuthorization = false
	panel.current.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED
	panel.current.UpdateSequence++
	panel.mu.Unlock()
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		status, err := hostops.ReadHelperStatus(m)
		if err == nil && status.Authorized && status.LeaseReady {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err := waitHelper(m); err != nil {
		t.Fatal("helper did not regain readiness after genuine signed approval:", err)
	}
	t.Log("Real installed-rescue upgrade verified signatures, all three binaries, preserved authority/identity, and complete rollback after startup failure")
}
