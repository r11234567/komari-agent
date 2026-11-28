//go:build linux

package rescue

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
)

type jitterHeartbeatPanel struct {
	configconnect.UnimplementedPrivilegedDeliveryServiceHandler
	frames   chan *configv1.PrivilegedRevision
	control  chan *configv1.WatchPrivilegedDeliveryResponse
	seal     func(*securityv1.SignedInstruction) *securityv1.SignedEnvelope
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
		case frame := <-p.control:
			if frame == nil {
				return nil
			}
			if err := stream.Send(frame); err != nil {
				return err
			}
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

func jitterHelperFixture(t *testing.T, middleware ...func(http.Handler) http.Handler) (*Helper, *jitterHeartbeatPanel, func(time.Time, uint64) *configv1.PrivilegedRevision) {
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
	trust, sign, seal := heartbeatFixtureWithSigner(t)
	panel := &jitterHeartbeatPanel{frames: make(chan *configv1.PrivilegedRevision, 8),
		control: make(chan *configv1.WatchPrivilegedDeliveryResponse, 8), seal: seal}
	_, handler := configconnect.NewPrivilegedDeliveryServiceHandler(panel)
	for _, wrap := range middleware {
		handler = wrap(handler)
	}
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

func TestRescueAuthorizationRecoversFromGatewayAndNonceChallenge(t *testing.T) {
	const staleNonce = "stale-fixture-nonce"
	const currentNonce = "current-fixture-nonce"
	var watches, challenges atomic.Int32
	helper, panel, sign := jitterHelperFixture(t, func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ping" {
				w.Header().Set("DPoP-Nonce", staleNonce)
				w.WriteHeader(http.StatusOK)
				return
			}
			if watches.Add(1) == 1 {
				http.Error(w, "temporary upstream outage", http.StatusBadGateway)
				return
			}
			parts := strings.Split(r.Header.Get("DPoP"), ".")
			if len(parts) != 3 {
				http.Error(w, "missing proof", http.StatusBadRequest)
				return
			}
			claims, err := base64.RawURLEncoding.DecodeString(parts[1])
			var proof struct {
				Nonce string `json:"nonce"`
			}
			if err != nil || json.Unmarshal(claims, &proof) != nil {
				http.Error(w, "invalid proof", http.StatusBadRequest)
				return
			}
			if proof.Nonce != currentNonce {
				challenges.Add(1)
				w.Header().Set("DPoP-Nonce", currentNonce)
				// Model an intermediary preserving the nonce while omitting
				// the challenge header that enables an in-request retry.
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"code":"unauthenticated","message":"dpop: missing, invalid or expired server nonce"}`))
				return
			}
			next.ServeHTTP(w, r)
		})
	})
	waitJitterCondition(t, func() bool { return panel.requests.Load() == 1 }, 5*time.Second)
	if helper.authorized.Load() || helper.leaseReady.Load() {
		t.Fatal("Helper authorized before receiving a signed heartbeat")
	}
	panel.frames <- sign(time.Now(), 1)
	waitJitterCondition(t, func() bool { return helper.authorized.Load() && helper.leaseReady.Load() }, 3*time.Second)
	if watches.Load() != 3 || challenges.Load() != 1 {
		t.Fatalf("expected one gateway failure, one nonce challenge and one authorized watch, got %d watches and %d challenges", watches.Load(), challenges.Load())
	}
}
