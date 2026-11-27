package clientcore

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/enrollment"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	enrollmentconnect "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1/enrollmentv1connect"
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

func TestCredentialRenewalPermanentRejectionDoesNotPoll(t *testing.T) {
	client, _, _ := renewalFixture(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		err := connect.NewError(connect.CodeUnauthenticated, fmt.Errorf("administrator reapproval required"))
		detail, detailErr := connect.NewErrorDetail(&commonv1.ErrorDetail{Code: "REFRESH_CREDENTIAL_REJECTED"})
		if detailErr != nil {
			t.Error(detailErr)
			return
		}
		err.AddDetail(detail)
		_ = connect.NewErrorWriter().Write(w, r, err)
	}))
	defer server.Close()
	client.endpoint = server.URL
	done := make(chan struct{})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { defer close(done); client.runCredentialRenewal(ctx) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("permanent denial kept proactive renewal polling")
	}
	for range 10 {
		if err := client.refreshCredentials(ctx, "synthetic-old-access"); !permanentCredentialRejection(err) {
			t.Fatalf("cached denial lost its type: %v", err)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("concurrent/reactive consumers repeated a permanent exchange: %d", calls.Load())
	}
	id, _ := client.credentialStore.Identity()
	if id.AccessToken != "synthetic-old-access" || id.PendingRefresh == nil {
		t.Fatal("permanent rejection destroyed recoverable identity")
	}
}

func TestCredentialRenewalFinalHorizonDoesNotPoll(t *testing.T) {
	client, _, calls := renewalFixture(t)
	id, _ := client.credentialStore.Identity()
	now := time.Now()
	id.AccessTokenExpiresAt = now.Add(2 * time.Minute)
	id.RefreshTokenExpiresAt = id.AccessTokenExpiresAt
	if err := client.credentialStore.Save(id); err != nil {
		t.Fatal(err)
	}
	if delay := credentialRenewalDelay(id, now); delay != 2*time.Minute {
		t.Fatalf("final authorization horizon must not renew early: %s", delay)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); client.runCredentialRenewal(ctx) }()
	select {
	case <-done:
		t.Fatal("worker exited before authorization boundary")
	case <-time.After(150 * time.Millisecond):
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("final-horizon timer ignored cancellation")
	}
	if calls.Load() != 0 {
		t.Fatalf("fixed-expiry success storm: %d exchanges", calls.Load())
	}
	if delay := credentialRenewalDelay(id, id.RefreshTokenExpiresAt); delay != 0 {
		t.Fatalf("expired credentials must reach authoritative server rejection: %s", delay)
	}
	id.RefreshTokenExpiresAt = now.Add(24 * time.Hour)
	if delay := credentialRenewalDelay(id, now); delay != 0 {
		t.Fatalf("ordinary short-lived AT must still refresh early: %s", delay)
	}
}

type recoveryRequiredEnrollmentHandler struct {
	enrollmentconnect.UnimplementedEnrollmentServiceHandler
	calls *atomic.Int32
}

func (h *recoveryRequiredEnrollmentHandler) RefreshCredentials(context.Context, *connect.Request[enrollmentv1.RefreshCredentialsRequest]) (*connect.Response[enrollmentv1.RefreshCredentialsResponse], error) {
	h.calls.Add(1)
	rpcErr := connect.NewError(connect.CodeFailedPrecondition, errors.New("refresh recovery window expired"))
	if detail, err := connect.NewErrorDetail(&commonv1.ErrorDetail{Code: "REFRESH_RECOVERY_REQUIRED"}); err == nil {
		rpcErr.AddDetail(detail)
	}
	return nil, rpcErr
}

func TestCredentialRenewalStopsOnlyOnRefreshRecoveryRequiredDetail(t *testing.T) {
	recoveryErr := connect.NewWireError(connect.CodeFailedPrecondition, errors.New("refresh recovery window expired"))
	detail, err := connect.NewErrorDetail(&commonv1.ErrorDetail{Code: "REFRESH_RECOVERY_REQUIRED"})
	if err != nil {
		t.Fatal(err)
	}
	recoveryErr.AddDetail(detail)
	if permanentCredentialRejection(recoveryErr) || errors.Is(classify(recoveryErr), ErrPermissionDenied) {
		t.Fatal("wire recovery details outside the refresh RPC must not stop the agent")
	}

	localRecoveryErr := connect.NewError(connect.CodeFailedPrecondition, errors.New("local status mapping"))
	localRecoveryErr.AddDetail(detail)
	if permanentCredentialRejection(localRecoveryErr) {
		t.Fatal("non-wire CodeFailedPrecondition must not halt renewal retries")
	}

	plainFailedPrecondition := connect.NewWireError(connect.CodeFailedPrecondition, errors.New("other precondition"))
	if permanentCredentialRejection(plainFailedPrecondition) {
		t.Fatal("plain CodeFailedPrecondition without REFRESH_RECOVERY_REQUIRED detail must remain retryable")
	}

	otherDetailErr := connect.NewWireError(connect.CodeFailedPrecondition, errors.New("different precondition"))
	otherDetail, err := connect.NewErrorDetail(&commonv1.ErrorDetail{Code: "OTHER_PRECONDITION"})
	if err != nil {
		t.Fatal(err)
	}
	otherDetailErr.AddDetail(otherDetail)
	if permanentCredentialRejection(otherDetailErr) {
		t.Fatal("CodeFailedPrecondition with unrelated ErrorDetail code must remain retryable")
	}

	// End-to-end Connect wire check: runCredentialRenewal must stop after one
	// server response carrying FailedPrecondition + REFRESH_RECOVERY_REQUIRED.
	calls := &atomic.Int32{}
	_, handler := enrollmentconnect.NewEnrollmentServiceHandler(&recoveryRequiredEnrollmentHandler{calls: calls})
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)

	public, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	store, err := credentials.Open(filepath.Join(t.TempDir(), "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(credentials.Identity{
		Endpoint:              server.URL,
		AgentID:               "renewal-node",
		PublicKey:             pub,
		PrivateKey:            key,
		KeyID:                 keyID,
		AccessToken:           "synthetic-old-access",
		RefreshToken:          "synthetic-old-refresh",
		AccessTokenExpiresAt:  time.Now().Add(-time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(24 * time.Hour),
		ControlPlaneKeys:      []credentials.PinnedKey{{Algorithm: 1, KeyID: "renewal-panel", Value: base64.StdEncoding.EncodeToString(public)}},
	}); err != nil {
		t.Fatal(err)
	}
	client := &Client{endpoint: server.URL, token: "synthetic-old-access", credentialStore: store}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.runCredentialRenewal(ctx)
	}()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("runCredentialRenewal did not stop after REFRESH_RECOVERY_REQUIRED response")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("expected exactly 1 refresh attempt before halting, got %d", got)
	}
}

func TestCredentialRenewalProxyDenialCanRecoverWithoutAccessToken(t *testing.T) {
	for _, status := range []int{401, 403, 429, 502} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			client, _, _ := renewalFixture(t)
			public, private, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			id, _ := client.credentialStore.Identity()
			id.AccessTokenExpiresAt = time.Now().Add(-time.Hour)
			id.ControlPlaneKeys = []credentials.PinnedKey{{Algorithm: 1, KeyID: "renewal-panel", Value: base64.StdEncoding.EncodeToString(public)}}
			if err := client.credentialStore.Save(id); err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("refresh sent ambient access credentials")
				}
				if calls.Add(1) == 1 {
					w.Header().Set("Content-Type", "text/html")
					w.WriteHeader(status)
					_, _ = io.WriteString(w, "<html>upstream challenge</html>")
					return
				}
				response := &enrollmentv1.RefreshCredentialsResponse{Credentials: &enrollmentv1.AgentCredentials{AgentId: id.AgentID, AccessToken: "recovered-access", RefreshToken: "recovered-refresh", AccessTokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(24 * time.Hour))}}
				signRenewalResponse(t, r, response, private)
				raw, _ := proto.Marshal(response)
				w.Header().Set("Content-Type", "application/proto")
				_, _ = w.Write(raw)
			}))
			defer server.Close()
			client.endpoint = server.URL
			err = client.refreshCredentials(context.Background(), id.AccessToken)
			if err == nil || permanentCredentialRejection(err) {
				t.Fatalf("proxy response stopped renewal: %v", err)
			}
			pending, _ := client.credentialStore.Identity()
			if pending.PendingRefresh == nil || pending.AccessToken != id.AccessToken || pending.RefreshToken != id.RefreshToken {
				t.Fatal("proxy error destroyed recoverable credentials")
			}
			if err := client.refreshCredentials(context.Background(), id.AccessToken); err == nil || calls.Load() != 1 {
				t.Fatal("transient response bypassed retry budget")
			}
			// Advance only the retry deadline; preserve the durable operation.
			client.refreshRetryAt = time.Time{}
			if err := client.refreshCredentials(context.Background(), id.AccessToken); err != nil {
				t.Fatal(err)
			}
			recovered, _ := client.credentialStore.Identity()
			if calls.Load() != 2 || recovered.AccessToken != "recovered-access" || recovered.PendingRefresh != nil || recovered.Generation == nil || *recovered.Generation != 1 {
				t.Fatal("renewal did not recover and durably publish the verified pair")
			}
		})
	}
}

func TestNativeEntryErrorHasNoRefreshRevocationAuthority(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeUnauthenticated, connect.CodePermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			localErr := connect.NewError(code, fmt.Errorf("local status mapping"))
			if permanentCredentialRejection(localErr) || errors.Is(classify(localErr), ErrPermissionDenied) {
				t.Fatal("local error acquired server authority")
			}
			wireErr := connect.NewWireError(code, fmt.Errorf("proxy 401/403 without domain detail"))
			if permanentCredentialRejection(wireErr) || errors.Is(classify(wireErr), ErrPermissionDenied) {
				t.Fatal("bare wire 401/403 without domain detail acquired revocation authority")
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("trust bootstrap sent ambient credentials")
				}
				_ = connect.NewErrorWriter().Write(w, r, connect.NewError(code, fmt.Errorf("authoritative credential rejection")))
			}))
			defer server.Close()
			client, err := enrollment.New(server.URL, server.Client())
			if err != nil {
				t.Fatal(err)
			}
			_, _, _, _, err = client.FetchTrustBundle(context.Background(), "fixture-agent")
			if err == nil || permanentCredentialRejection(err) {
				t.Fatalf("entry rejection must not become permanent credential rejection: %v", err)
			}
		})
	}
}

// Exercise the worker itself with exactly the wire encoding used by the
// server's AbortRequest, then a signed response, without resetting retry state
// or restarting the worker. IsWireError is not domain rejection authority.
func TestCredentialRenewalWorkerRecoversFromNativeEntryDenial(t *testing.T) {
	for _, code := range []connect.Code{connect.CodeUnauthenticated, connect.CodePermissionDenied} {
		t.Run(code.String(), func(t *testing.T) {
			client, success, successes := renewalFixture(t)
			identity, _ := client.credentialStore.Identity()
			identity.AccessTokenExpiresAt = time.Now().Add(-time.Hour)
			if err := client.credentialStore.Save(identity); err != nil {
				t.Fatal(err)
			}
			var attempts atomic.Int32
			denied := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "" {
					t.Error("refresh acquired ambient authentication")
				}
				if attempts.Add(1) == 1 {
					_ = connect.NewErrorWriter().Write(w, r, connect.NewError(code, fmt.Errorf("request origin is not allowed")))
					close(denied)
					return
				}
				success.Config.Handler.ServeHTTP(w, r)
			}))
			defer server.Close()
			client.endpoint = server.URL
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			done := make(chan struct{})
			go func() { defer close(done); client.runCredentialRenewal(ctx) }()
			select {
			case <-denied:
			case <-time.After(3 * time.Second):
				t.Fatal("worker did not attempt refresh")
			}
			deadline := time.NewTimer(10 * time.Second)
			defer deadline.Stop()
			for {
				next, _ := client.credentialStore.Identity()
				if next.Generation != nil {
					if *next.Generation != 1 || next.PendingRefresh != nil || next.RefreshToken != "synthetic-next-refresh" {
						t.Fatal("worker failed to commit the verified next credential generation")
					}
					// Refresh durably saves the identity before publishing the token
					// used by live requests. Observe both within the original deadline.
					if client.tokenValue() == next.AccessToken {
						break
					}
				}
				select {
				case <-done:
					t.Fatal("ingress denial permanently stopped the renewal worker")
				case <-deadline.C:
					t.Fatal("worker failed to recover within its ordinary retry budget")
				case <-time.After(20 * time.Millisecond):
				}
			}
			cancel()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("renewal worker ignored cancellation")
			}
			if attempts.Load() != 2 || successes.Load() != 1 {
				t.Fatalf("unexpected retry storm: attempts=%d successes=%d", attempts.Load(), successes.Load())
			}
		})
	}
}
