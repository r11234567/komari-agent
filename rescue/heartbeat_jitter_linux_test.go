//go:build linux

package rescue

import (
	"context"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
)

type jitterHeartbeatPanel struct {
	configconnect.UnimplementedPrivilegedDeliveryServiceHandler
	frames   chan *configv1.PrivilegedRevision
	requests atomic.Int32
	active   atomic.Int32
}

func (p *jitterHeartbeatPanel) WatchPrivilegedDelivery(ctx context.Context, _ *connect.Request[configv1.WatchPrivilegedDeliveryRequest], stream *connect.ServerStream[configv1.WatchPrivilegedDeliveryResponse]) error {
	p.requests.Add(1)
	p.active.Add(1)
	defer p.active.Add(-1)
	stream.ResponseHeader().Set(authorizationWatchHeader, "v1")
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case frame, open := <-p.frames:
			if !open {
				return nil
			}
			if err := stream.Send(&configv1.WatchPrivilegedDeliveryResponse{Revision: frame}); err != nil {
				return err
			}
		}
	}
}

func jitterHelperFixture(t *testing.T) (*Helper, *jitterHeartbeatPanel, func(time.Time, uint64) *configv1.PrivilegedRevision) {
	t.Helper()
	if os.Getenv("KOMARI_CREDENTIAL_ROOT_TEST") != "1" {
		t.Skip("requires disposable root CI checkpoint")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root checkpoint must run as root")
	}
	root, err := os.MkdirTemp("/root", "komari-jitter-ci-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	trust, sign := heartbeatFixture(t)
	panel := &jitterHeartbeatPanel{frames: make(chan *configv1.PrivilegedRevision, 8)}
	_, handler := configconnect.NewPrivilegedDeliveryServiceHandler(panel)
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	trust.Endpoint = server.URL
	manifest := &hostops.Manifest{Version: 2, InitSystem: "systemd", ServiceName: "jitter-ci-" + filepath.Base(root), HostPolicyFile: filepath.Join(root, "policy.json"), CredentialsFile: filepath.Join(root, "credentials.json")}
	policy := hostops.Policy{Version: 2, ServiceID: manifest.ServiceName, AllowRescueHelper: true, HelperInstalled: true, HelperAuthorized: true}
	if err = hostops.WriteJSON(manifest.HostPolicyFile, policy, 0600); err != nil {
		t.Fatal(err)
	}
	_, key, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := credentials.Open(manifest.CredentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Save(credentials.Identity{Endpoint: server.URL, AgentID: "node", PrivateKey: key, KeyID: keyID, AccessToken: "synthetic-jitter-at", RefreshToken: "synthetic-jitter-rt"}); err != nil {
		t.Fatal(err)
	}
	if err := hostops.PrepareHelperStatus(manifest); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(hostops.HelperStatusPath(manifest)) })
	helper := &Helper{manifest: manifest, hostTrust: trust, action: ActionConfig{IsolationStatePath: filepath.Join(root, "isolation.json")}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); helper.watchAuthorization(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("jitter watcher survived cancellation")
		}
	})
	return helper, panel, sign
}

func waitJitterCondition(t *testing.T, condition func() bool, limit time.Duration) {
	t.Helper()
	deadline := time.Now().Add(limit)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("jitter checkpoint condition timed out")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestRescueAuthorizationJitterAndBoundedSilence(t *testing.T) {
	helper, panel, sign := jitterHelperFixture(t)
	panel.frames <- sign(time.Now(), 1)
	waitJitterCondition(t, func() bool { return helper.authorized.Load() && helper.leaseReady.Load() }, 3*time.Second)
	until := time.Now().Add(3200 * time.Millisecond)
	for time.Now().Before(until) {
		if !helper.authorized.Load() || !helper.leaseReady.Load() {
			t.Fatal("three-second heartbeat gap revoked a healthy stream")
		}
		time.Sleep(10 * time.Millisecond)
	}
	// Resume on the SAME connection with an already-aged signed frame.
	issued := time.Now().Add(-3 * time.Second)
	panel.frames <- sign(issued, 2)
	time.Sleep(150 * time.Millisecond)
	if panel.requests.Load() != 1 || !helper.authorized.Load() {
		t.Fatal("jitter caused needless reconnect")
	}
	// Silent expiry must use signed time, not receipt or reconnect time.
	waitJitterCondition(t, func() bool { return !helper.authorized.Load() && !helper.leaseReady.Load() }, 7800*time.Millisecond)
	elapsed := time.Since(issued)
	if elapsed < 10*time.Second || elapsed > 11*time.Second {
		t.Fatalf("signed silence deadline moved: %s", elapsed)
	}
	t.Logf("three-second jitter survived; signed authorization expired after %s", elapsed)
	// Wait for the old canceled handler to exit before delivering to its replacement.
	waitJitterCondition(t, func() bool { return panel.requests.Load() >= 2 && panel.active.Load() == 1 }, 3*time.Second)
	panel.frames <- sign(time.Now(), 3)
	waitJitterCondition(t, func() bool { return helper.authorized.Load() }, 3*time.Second)
	policy := hostops.Policy{Version: 2, ServiceID: helper.manifest.ServiceName, AllowRescueHelper: true, HelperInstalled: true, HelperAuthorized: true, ForceDenyRescueHelper: true}
	if err := hostops.WriteJSON(helper.manifest.HostPolicyFile, policy, 0600); err != nil {
		t.Fatal(err)
	}
	waitJitterCondition(t, func() bool { return !helper.authorized.Load() && !helper.leaseReady.Load() }, time.Second)
}

func TestRescueAuthorizationDisconnectStillDeniesImmediately(t *testing.T) {
	helper, panel, sign := jitterHelperFixture(t)
	panel.frames <- sign(time.Now(), 1)
	waitJitterCondition(t, func() bool { return helper.authorized.Load() }, 3*time.Second)
	started := time.Now()
	close(panel.frames)
	waitJitterCondition(t, func() bool { return !helper.authorized.Load() && !helper.leaseReady.Load() }, time.Second)
	t.Logf("explicit EOF denied after %s instead of waiting for silence window", time.Since(started))
}
