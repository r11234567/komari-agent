//go:build linux

package rescue

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
)

func TestCredentialHandoffPreservesFreshLeaseAndHonorsRevocation(t *testing.T) {
	if os.Getenv("KOMARI_CREDENTIAL_ROOT_TEST") != "1" {
		t.Skip("requires dedicated disposable root CI checkpoint")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root checkpoint must actually execute as root")
	}
	root, err := os.MkdirTemp("/root", "komari-credential-ci-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(root)
	trust, sign := heartbeatFixture(t)
	_, key, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	private, err := base64.StdEncoding.DecodeString(key)
	if err != nil {
		t.Fatal(err)
	}
	public := ed25519.PrivateKey(private).Public().(ed25519.PublicKey)
	panel := &continuousHeartbeatPanel{sign: sign}
	var newRequests atomic.Int32
	_, handler := configconnect.NewPrivilegedDeliveryServiceHandler(panel)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
		if token != "synthetic-old-at" && token != "synthetic-new-at" {
			http.Error(w, "unauthorized", 401)
			return
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read", 400)
			return
		}
		// Verify the real network request remains bound to this token/key.
		if !verifyHandoffRequest(r, body, token, public) {
			http.Error(w, "invalid DPoP", 401)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		if token == "synthetic-new-at" {
			newRequests.Add(1)
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	trust.Endpoint = server.URL
	manifest := &hostops.Manifest{Version: 2, ServiceName: "credential-ci-" + filepath.Base(root), HostPolicyFile: filepath.Join(root, "policy.json"), CredentialsFile: filepath.Join(root, "credentials.json")}
	policy := hostops.Policy{Version: 2, ServiceID: manifest.ServiceName, AllowRescueHelper: true, HelperInstalled: true, HelperAuthorized: true}
	if err = hostops.WriteJSON(manifest.HostPolicyFile, policy, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := credentials.Open(manifest.CredentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	id := credentials.Identity{Endpoint: server.URL, AgentID: "node", PrivateKey: key, KeyID: keyID, AccessToken: "synthetic-old-at", RefreshToken: "synthetic-refresh"}
	if err = store.Save(id); err != nil {
		t.Fatal(err)
	}
	helper := &Helper{manifest: manifest, hostTrust: trust, action: ActionConfig{IsolationStatePath: filepath.Join(root, "isolation.json")}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); helper.watchAuthorization(ctx) }()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			t.Error("helper watch did not stop")
		}
	}()
	wait := func(condition func() bool, limit time.Duration) {
		t.Helper()
		deadline := time.Now().Add(limit)
		for !condition() {
			if time.Now().After(deadline) {
				t.Fatal("handoff condition timed out")
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	wait(func() bool { return helper.authorized.Load() && helper.leaseReady.Load() }, 3*time.Second)
	id.AccessToken = "synthetic-new-at"
	started := time.Now()
	if err = store.Save(id); err != nil {
		t.Fatal(err)
	}
	for newRequests.Load() == 0 {
		if !helper.authorized.Load() || !helper.leaseReady.Load() {
			t.Fatal("credential replacement dropped a fresh rescue lease")
		}
		if time.Since(started) > 1500*time.Millisecond {
			t.Fatal("credential notification did not reconnect within freshness window")
		}
		time.Sleep(5 * time.Millisecond)
	}
	// Keep observing after the new stream's first signed frame is processed.
	deadline := time.Now().Add(1200 * time.Millisecond)
	for time.Now().Before(deadline) {
		if !helper.authorized.Load() {
			t.Fatal("rotated stream lost authorization")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if panel.requests.Load() != 2 {
		t.Fatalf("expected exactly two streams, got %d", panel.requests.Load())
	}

	// Losing local identity must fail closed despite valid old network frames.
	if err = os.Remove(manifest.CredentialsFile); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return !helper.authorized.Load() }, time.Second)
	if err = store.Save(id); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return helper.authorized.Load() }, 3*time.Second)
	policy.ForceDenyRescueHelper = true
	if err = hostops.WriteJSON(manifest.HostPolicyFile, policy, 0600); err != nil {
		t.Fatal(err)
	}
	wait(func() bool { return !helper.authorized.Load() && !helper.leaseReady.Load() }, time.Second)
}

func verifyHandoffRequest(r *http.Request, body []byte, token string, public ed25519.PublicKey) bool {
	payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%x\n%x", r.Method, r.URL.Path, r.Header.Get("X-Komari-Timestamp"), r.Header.Get("X-Komari-Nonce"), sha256.Sum256([]byte(token)), sha256.Sum256(body))
	signature, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Komari-Signature"))
	return err == nil && ed25519.Verify(public, []byte(payload), signature)
}
