package requestheaders

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
)

func parseAndVerifyDPoPProof(t *testing.T, r *http.Request, body []byte, token string, expectedPub ed25519.PublicKey, wantStream bool) dpopClaims {
	t.Helper()
	proof := r.Header.Get("DPoP")
	if proof == "" {
		t.Fatal("missing DPoP header")
	}
	parts := strings.Split(proof, ".")
	if len(parts) != 3 {
		t.Fatalf("invalid DPoP compact JWS segments: got %d", len(parts))
	}
	headerRaw, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode DPoP header: %v", err)
	}
	claimsRaw, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode DPoP claims: %v", err)
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode DPoP signature: %v", err)
	}
	var hdr dpopHeader
	if err := json.Unmarshal(headerRaw, &hdr); err != nil {
		t.Fatalf("unmarshal DPoP header: %v", err)
	}
	if hdr.Typ != "dpop+jwt" || hdr.Alg != "EdDSA" {
		t.Fatalf("unexpected DPoP header typ=%q alg=%q", hdr.Typ, hdr.Alg)
	}
	if hdr.JWK.Kty != "OKP" || hdr.JWK.Crv != "Ed25519" {
		t.Fatalf("unexpected DPoP JWK: %+v", hdr.JWK)
	}
	xBytes, err := base64.RawURLEncoding.DecodeString(hdr.JWK.X)
	if err != nil || !bytes.Equal(xBytes, expectedPub) {
		t.Fatalf("DPoP JWK public key mismatch: err=%v", err)
	}
	signingInput := parts[0] + "." + parts[1]
	if !ed25519.Verify(expectedPub, []byte(signingInput), sig) {
		t.Fatal("DPoP JWS signature verification failed")
	}

	var claims dpopClaims
	if err := json.Unmarshal(claimsRaw, &claims); err != nil {
		t.Fatalf("unmarshal DPoP claims: %v", err)
	}
	if claims.JTI == "" || claims.HTM != r.Method || claims.IAT == 0 {
		t.Fatalf("incomplete DPoP claims: %+v", claims)
	}
	wantScheme := strings.ToLower(strings.TrimSpace(r.URL.Scheme))
	if wantScheme == "" {
		if r.TLS != nil {
			wantScheme = "https"
		} else {
			wantScheme = "http"
		}
	}
	wantHost := strings.ToLower(strings.TrimSpace(r.Host))
	if wantHost == "" {
		wantHost = strings.ToLower(strings.TrimSpace(r.URL.Host))
	}
	wantPath := r.URL.EscapedPath()
	if wantPath == "" {
		wantPath = "/"
	}
	wantHTU := wantScheme + "://" + wantHost + wantPath
	if claims.HTU != wantHTU {
		t.Fatalf("DPoP htu=%q, want %q", claims.HTU, wantHTU)
	}
	tokDigest := sha256.Sum256([]byte(token))
	wantATH := base64.RawURLEncoding.EncodeToString(tokDigest[:])
	if claims.ATH != wantATH {
		t.Fatalf("DPoP ath=%q, want %q", claims.ATH, wantATH)
	}
	if wantStream {
		emptyDigest := sha256.Sum256(nil)
		wantBH := base64.RawURLEncoding.EncodeToString(emptyDigest[:])
		if claims.BM != "stream" || claims.BH != wantBH {
			t.Fatalf("unexpected stream DPoP claims bm=%q bh=%q", claims.BM, claims.BH)
		}
	} else {
		bodyDigest := sha256.Sum256(body)
		wantBH := base64.RawURLEncoding.EncodeToString(bodyDigest[:])
		if claims.BM != "" || claims.BH != wantBH {
			t.Fatalf("unexpected unary DPoP claims bm=%q bh=%q want %q", claims.BM, claims.BH, wantBH)
		}
	}
	return claims
}

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

	var capturedAuth, capturedLegacySig string
	var verifiedClaims dpopClaims

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		capturedLegacySig = r.Header.Get("X-Komari-Signature")
		bodyBytes, _ := io.ReadAll(r.Body)
		verifiedClaims = parseAndVerifyDPoPProof(t, r, bodyBytes, "test-access-token", pub, false)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := WrapWithStaticDPoP(srv.Client(), identity)

	reqBody := []byte(`{"hello": "world"}`)
	req, err := http.NewRequest("POST", srv.URL+"/api/test?ignored=1", bytes.NewReader(reqBody))
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
	if capturedAuth != "DPoP test-access-token" {
		t.Fatalf("unexpected Authorization header: %s", capturedAuth)
	}
	if capturedLegacySig != "" {
		t.Fatalf("expected legacy X-Komari-Signature header to be omitted, got %q", capturedLegacySig)
	}
	if strings.Contains(verifiedClaims.HTU, "ignored=") {
		t.Fatalf("DPoP htu must omit query string, got %q", verifiedClaims.HTU)
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

	var capturedAuth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		_, _ = io.ReadAll(r.Body)
		parseAndVerifyDPoPProof(t, r, nil, "stream-access-token", pub, true)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	client := WrapWithStaticDPoP(srv.Client(), identity)

	pipeReader, pipeWriter := io.Pipe()
	go func() {
		_, _ = pipeWriter.Write([]byte("streaming-chunk-1"))
		time.Sleep(10 * time.Millisecond)
		_, _ = pipeWriter.Write([]byte("streaming-chunk-2"))
		_ = pipeWriter.Close()
	}()

	req, err := http.NewRequest("POST", srv.URL+"/komari.exec.v1.ExecutionService/LeaseExecution", pipeReader)
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
	if capturedAuth != "DPoP stream-access-token" {
		t.Fatalf("unexpected Authorization header: %s", capturedAuth)
	}
}

func TestDPoPTransport_NonceChallengeRetryAndCaching(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	identity := credentials.Identity{
		Endpoint:    "https://panel.example.com",
		AgentID:     "agent-nonce",
		AccessToken: "nonce-token",
		PrivateKey:  base64.StdEncoding.EncodeToString(priv),
	}

	const issuedNonce = "srv-nonce-123"
	var attempts int
	var seenNonces []string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts++
		bodyBytes, _ := io.ReadAll(r.Body)
		claims := parseAndVerifyDPoPProof(t, r, bodyBytes, "nonce-token", pub, false)
		seenNonces = append(seenNonces, claims.Nonce)
		if claims.Nonce != issuedNonce {
			w.Header().Set("DPoP-Nonce", issuedNonce)
			w.Header().Set("WWW-Authenticate", `DPoP error="use_dpop_nonce"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	on401Called := false
	client := WrapWithDPoPAndNonces(srv.Client(), func() (credentials.Identity, bool) {
		return identity, true
	}, func() string {
		return identity.AccessToken
	}, func(ctx context.Context, oldToken string) error {
		on401Called = true
		return nil
	}, NewNonceStore())

	req1, _ := http.NewRequest("POST", srv.URL+"/komari.report.v1.AgentReportService/SubmitReport", strings.NewReader("first"))
	resp1, err := client.Do(req1)
	if err != nil {
		t.Fatal(err)
	}
	resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK || attempts != 2 || on401Called {
		t.Fatalf("nonce challenge retry failed: status=%d attempts=%d on401=%v nonces=%v", resp1.StatusCode, attempts, on401Called, seenNonces)
	}

	// Subsequent request to the same origin sends the cached DPoP-Nonce proactively.
	req2, _ := http.NewRequest("POST", srv.URL+"/komari.metrics.v1.MetricsService/SubmitMetrics", strings.NewReader("second"))
	resp2, err := client.Do(req2)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || attempts != 3 || seenNonces[2] != issuedNonce {
		t.Fatalf("cached nonce not sent on follow-up: status=%d attempts=%d nonces=%v", resp2.StatusCode, attempts, seenNonces)
	}
}

func TestDPoPTransport_401AutomaticRetry(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
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
		bodyBytes, _ := io.ReadAll(r.Body)
		auth := r.Header.Get("Authorization")
		if auth == "DPoP old-expired-token" {
			parseAndVerifyDPoPProof(t, r, bodyBytes, "old-expired-token", pub, false)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if auth == "DPoP fresh-rotated-token" {
			parseAndVerifyDPoPProof(t, r, bodyBytes, "fresh-rotated-token", pub, false)
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
		w.Header().Set("DPoP-Nonce", "stream-nonce-1")
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	nonces := NewNonceStore()
	client := WrapWithDPoPAndNonces(srv.Client(), func() (credentials.Identity, bool) {
		id := identity
		id.AccessToken = curToken
		return id, true
	}, func() string {
		return curToken
	}, func(ctx context.Context, oldToken string) error {
		refreshed = true
		curToken = "fresh-stream-token"
		return nil
	}, nonces)

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
	if got := nonces.Get(srv.URL); got != "stream-nonce-1" {
		t.Fatalf("expected stream 401 to cache DPoP-Nonce for reconnect, got %q", got)
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
	for _, h := range []string{"Authorization", "DPoP", "X-Komari-Signature", "X-Komari-Timestamp", "X-Komari-Nonce", "X-Komari-Body-Mode"} {
		if got := req.Header.Get(h); got != "" {
			t.Fatalf("RoundTrip mutated original request header %s=%q", h, got)
		}
	}
	if req.Header.Get("X-Custom") != "keep" {
		t.Fatal("original custom header was lost")
	}
}

func TestNegotiatedAgentProofAcrossPanelUpgradeAndRollback(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const token = "synthetic-agent-token"
	const nonce = "synthetic-server-nonce"
	const procedure = "/komari.example.v1.AgentService/Check"
	for _, jwt := range []bool{false, true, false} {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path == "/ping" {
				if r.Header.Get("Authorization") != "" || r.Header.Get("X-Komari-Agent-Nonce-For") != "test-agent" {
					t.Error("probe carried a credential or used the wrong agent identifier")
				}
				if jwt {
					w.Header().Set("X-Komari-Agent-Proof", "dpop-jwt-v1")
					w.Header().Set("DPoP-Nonce", nonce)
				}
				w.WriteHeader(http.StatusOK)
				return
			}
			if r.URL.Path != procedure {
				t.Errorf("unexpected request path %q", r.URL.Path)
			}
			if jwt {
				if r.Header.Get("Authorization") != "DPoP "+token {
					t.Error("JWT-capable Panel did not receive the DPoP scheme")
				}
				if claims := parseAndVerifyDPoPProof(t, r, nil, token, pub, false); claims.Nonce != nonce {
					t.Error("first signed request did not use the probe nonce")
				}
			} else if r.Header.Get("Authorization") != "Bearer "+token ||
				r.Header.Get("X-Komari-Signature") == "" || r.Header.Get("DPoP") != "" {
				t.Error("old Panel did not receive a legacy signed request")
			}
			w.WriteHeader(http.StatusNoContent)
		}))
		identity := credentials.Identity{AgentID: "test-agent", AccessToken: token, PrivateKey: base64.StdEncoding.EncodeToString(key)}
		client := WithProtocolNegotiation(WrapWithStaticDPoP(server.Client(), identity))
		resp, err := client.Get(server.URL + procedure)
		if err != nil {
			server.Close()
			t.Fatal(err)
		}
		_ = resp.Body.Close()
		server.Close()
		if resp.StatusCode != http.StatusNoContent {
			t.Fatalf("request status = %d", resp.StatusCode)
		}
	}
}
