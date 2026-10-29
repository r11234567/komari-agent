package clientcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func signRenewalResponse(t *testing.T, r *http.Request, response *enrollmentv1.RefreshCredentialsResponse, key ed25519.PrivateKey) {
	t.Helper()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Error(err)
		return
	}
	var request enrollmentv1.RefreshCredentialsRequest
	if err = proto.Unmarshal(body, &request); err != nil {
		t.Error(err)
		return
	}
	var proof struct {
		RequestID  string  `json:"request_id"`
		Generation *uint64 `json:"generation"`
	}
	if request.Proof == nil || json.Unmarshal(request.Proof.Payload, &proof) != nil || proof.RequestID == "" {
		t.Error("missing persisted V2 refresh proof")
		return
	}
	generation := uint64(1)
	if proof.Generation != nil {
		generation = *proof.Generation + 1
	}
	raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(response.Credentials)
	digest := sha256.Sum256(raw)
	payload, _ := json.Marshal(map[string]any{"protocol": 2, "agent_id": response.Credentials.AgentId, "request_id": proof.RequestID, "generation": generation, "credentials_sha256": hex.EncodeToString(digest[:])})
	response.Proof = &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{{Algorithm: 1, KeyId: "renewal-panel", Value: ed25519.Sign(key, payload)}}}
}

func renewalFixture(t *testing.T) (*Client, *httptest.Server, *atomic.Int32) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	calls := &atomic.Int32{}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		response := &enrollmentv1.RefreshCredentialsResponse{Credentials: &enrollmentv1.AgentCredentials{AgentId: "renewal-node", AccessToken: "synthetic-next-access", RefreshToken: "synthetic-next-refresh", AccessTokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(7 * 24 * time.Hour))}}
		signRenewalResponse(t, r, response, private)
		raw, _ := proto.Marshal(response)
		w.Header().Set("Content-Type", "application/proto")
		_, _ = w.Write(raw)
	}))
	t.Cleanup(server.Close)
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	err = store.Save(credentials.Identity{Endpoint: server.URL, AgentID: "renewal-node", PublicKey: pub, PrivateKey: key, KeyID: keyID, AccessToken: "synthetic-old-access", RefreshToken: "synthetic-old-refresh", AccessTokenExpiresAt: time.Now().Add(4 * time.Minute), RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour), ControlPlaneKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "renewal-panel", Value: base64.StdEncoding.EncodeToString(public)}}})
	if err != nil {
		t.Fatal(err)
	}
	return &Client{endpoint: server.URL, token: "synthetic-old-access", credentialStore: store}, server, calls
}

func TestCredentialRenewalOneOwnerForConcurrentCallers(t *testing.T) {
	client, _, calls := renewalFixture(t)
	var wg sync.WaitGroup
	for range 12 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := client.refreshCredentials(context.Background(), "synthetic-old-access"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("expected one exchange, got %d", calls.Load())
	}
	reopened, err := credentials.Open(client.credentialStore.Path())
	if err != nil {
		t.Fatal(err)
	}
	id, _ := reopened.Identity()
	if id.Generation == nil || *id.Generation != 1 || id.PendingRefresh != nil || client.tokenValue() != id.AccessToken {
		t.Fatal("rotated credentials were not durably published")
	}
}

func TestCredentialRenewalTimerRefreshesBeforeExpiryAndCancels(t *testing.T) {
	client, _, calls := renewalFixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); client.runCredentialRenewal(ctx) }()
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	for {
		id, _ := client.credentialStore.Identity()
		if id.Generation != nil {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("proactive timer never committed before expiry")
		case <-time.After(10 * time.Millisecond):
		}
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("renewal worker ignored cancellation")
	}
	id, _ := client.credentialStore.Identity()
	if id.Generation == nil || *id.Generation != 1 || time.Until(id.AccessTokenExpiresAt) < 59*time.Minute {
		t.Fatal("proactive renewal did not save the next pair")
	}
	time.Sleep(50 * time.Millisecond)
	if calls.Load() != 1 {
		t.Fatal("renewal loop polled after success")
	}
	now := time.Now()
	id.PendingRefresh = nil
	id.AccessTokenExpiresAt = now.Add(time.Hour)
	delay := credentialRenewalDelay(id, now)
	if delay < 54*time.Minute || delay > 55*time.Minute {
		t.Fatalf("invalid proactive jitter: %s", delay)
	}
}
