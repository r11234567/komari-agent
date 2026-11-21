package requestheaders

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
)

func TestDPoPTransport_UnaryRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	identity := credentials.Identity{
		Endpoint:    "https://panel.example.com",
		AgentID:     "agent-test-unary",
		AccessToken: "test-access-token",
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}

	var capturedSig, capturedTs, capturedNonce, capturedAuth, capturedBodyMode string
	var capturedPayload string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-Komari-Signature")
		capturedTs = r.Header.Get("X-Komari-Timestamp")
		capturedNonce = r.Header.Get("X-Komari-Nonce")
		capturedAuth = r.Header.Get("Authorization")
		capturedBodyMode = r.Header.Get("X-Komari-Body-Mode")

		bodyBytes, _ := io.ReadAll(r.Body)
		tokenDigest := sha256.Sum256([]byte("test-access-token"))
		tokenHash := hex.EncodeToString(tokenDigest[:])
		bodyDigest := sha256.Sum256(bodyBytes)
		bodyHash := hex.EncodeToString(bodyDigest[:])

		capturedPayload = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", r.Method, r.URL.Path, capturedTs, capturedNonce, tokenHash, bodyHash)

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := WrapWithStaticDPoP(srv.Client(), identity)

	reqBody := []byte(`{"hello": "world"}`)
	req, err := http.NewRequest("POST", srv.URL+"/api/test", bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if capturedAuth != "Bearer test-access-token" {
		t.Fatalf("unexpected Authorization header: %s", capturedAuth)
	}
	if capturedSig == "" || capturedTs == "" || capturedNonce == "" {
		t.Fatal("missing DPoP headers on unary request")
	}
	if capturedBodyMode != "" {
		t.Fatalf("unary request should not have X-Komari-Body-Mode: stream, got %q", capturedBodyMode)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(capturedSig)
	if err != nil {
		t.Fatalf("invalid signature encoding: %v", err)
	}
	if !ed25519.Verify(pub, []byte(capturedPayload), sigBytes) {
		t.Fatal("unary request DPoP signature verification failed")
	}
}

func TestDPoPTransport_StreamingRequest(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	identity := credentials.Identity{
		Endpoint:    "https://panel.example.com",
		AgentID:     "agent-test-stream",
		AccessToken: "stream-access-token",
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}

	var capturedSig, capturedTs, capturedNonce, capturedBodyMode string
	var capturedPayload string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-Komari-Signature")
		capturedTs = r.Header.Get("X-Komari-Timestamp")
		capturedNonce = r.Header.Get("X-Komari-Nonce")
		capturedBodyMode = r.Header.Get("X-Komari-Body-Mode")

		tokenDigest := sha256.Sum256([]byte("stream-access-token"))
		tokenHash := hex.EncodeToString(tokenDigest[:])
		emptyDigest := sha256.Sum256(nil)
		emptyHash := hex.EncodeToString(emptyDigest[:])

		capturedPayload = fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", r.Method, r.URL.Path, capturedTs, capturedNonce, tokenHash, emptyHash)

		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := WrapWithStaticDPoP(srv.Client(), identity)

	// Create a streaming request with chunked body (ContentLength = -1)
	pipeReader, pipeWriter := io.Pipe()
	go func() {
		_, _ = pipeWriter.Write([]byte("streaming-chunk-1"))
		time.Sleep(10 * time.Millisecond)
		_, _ = pipeWriter.Write([]byte("streaming-chunk-2"))
		_ = pipeWriter.Close()
	}()

	req, err := http.NewRequest("POST", srv.URL+"/komari.exec.v1.ExecutionService/WatchDirectives", pipeReader)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", resp.StatusCode)
	}
	if capturedBodyMode != "stream" {
		t.Fatalf("expected X-Komari-Body-Mode: stream, got %q", capturedBodyMode)
	}

	sigBytes, err := base64.StdEncoding.DecodeString(capturedSig)
	if err != nil {
		t.Fatalf("invalid signature encoding: %v", err)
	}
	if !ed25519.Verify(pub, []byte(capturedPayload), sigBytes) {
		t.Fatal("streaming request DPoP signature verification failed")
	}
}

func TestDPoPTransport_401AutomaticRetry(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	curToken := "old-expired-token"
	identity := credentials.Identity{
		Endpoint:    "https://panel.example.com",
		AgentID:     "agent-test-401",
		AccessToken: curToken,
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}

	attempts := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		auth := r.Header.Get("Authorization")
		if auth == "Bearer old-expired-token" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if auth == "Bearer fresh-rotated-token" {
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer srv.Close()

	client := WrapWithDPoP(srv.Client(), func() (credentials.Identity, bool) {
		id := identity
		id.AccessToken = curToken
		return id, true
	}, func() string {
		return curToken
	}, func(ctx context.Context, oldToken string) error {
		curToken = "fresh-rotated-token"
		return nil
	})

	req, err := http.NewRequest("POST", srv.URL+"/test-refresh", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK after 401 retry, got %d", resp.StatusCode)
	}
	if attempts != 2 {
		t.Fatalf("expected 2 attempts (initial 401 + retry), got %d", attempts)
	}
}

func TestDPoPTransport_401DoesNotReplayStreamBody(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	curToken := "expired-stream-token"
	identity := credentials.Identity{
		Endpoint:    "https://panel.example.com",
		AgentID:     "agent-stream-401",
		AccessToken: curToken,
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}

	attempts := 0
	refreshed := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	client := WrapWithDPoP(srv.Client(), func() (credentials.Identity, bool) {
		id := identity
		id.AccessToken = curToken
		return id, true
	}, func() string {
		return curToken
	}, func(ctx context.Context, oldToken string) error {
		refreshed = true
		curToken = "fresh-stream-token"
		return nil
	})

	pr, pw := io.Pipe()
	go func() {
		_, _ = pw.Write([]byte("stream-chunk"))
		_ = pw.Close()
	}()
	req, err := http.NewRequest("POST", srv.URL+"/komari.webssh.v1.WebSSHService/AttachSession", pr)
	if err != nil {
		t.Fatal(err)
	}
	req.ContentLength = -1

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if !refreshed {
		t.Fatal("expected On401 credential refresh to run on streaming 401")
	}
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected original 401 so caller stream loop reconnects, got %d", resp.StatusCode)
	}
	if attempts != 1 {
		t.Fatalf("streaming request must not be replayed in-place; got %d attempts", attempts)
	}
}

type trackingReadCloser struct {
	io.Reader
	closed bool
}

func (r *trackingReadCloser) Close() error {
	r.closed = true
	return nil
}

func TestDPoPTransport_DoesNotMutateRequestAndClosesBody(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	identity := credentials.Identity{
		Endpoint:    "https://panel.example.com",
		AgentID:     "agent-immutable",
		AccessToken: "immutable-access-token",
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := WrapWithStaticDPoP(srv.Client(), identity)
	tracked := &trackingReadCloser{Reader: strings.NewReader(`{"metric":1}`)}
	req, err := http.NewRequest("POST", srv.URL+"/komari.metrics.v1.MetricsService/SubmitMetrics", tracked)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Custom", "keep")

	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if !tracked.closed {
		t.Fatal("expected DPoPTransport to close original unary request body")
	}
	for _, h := range []string{"Authorization", "X-Komari-Signature", "X-Komari-Timestamp", "X-Komari-Nonce", "X-Komari-Body-Mode"} {
		if got := req.Header.Get(h); got != "" {
			t.Fatalf("RoundTrip mutated original request header %s=%q", h, got)
		}
	}
	if req.Header.Get("X-Custom") != "keep" {
		t.Fatal("original custom header was lost")
	}
}
