package clientcore

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestClassifyFallsBackOnlyForTransportOrMissingService(t *testing.T) {
	if !errors.Is(classify(connect.NewError(connect.CodeUnavailable, errors.New("offline"))), ErrLegacyFallback) {
		t.Fatal("unavailable must use compatibility fallback")
	}
	if !errors.Is(classify(connect.NewError(connect.CodeUnimplemented, errors.New("old server"))), ErrLegacyFallback) {
		t.Fatal("unimplemented must use compatibility fallback")
	}
	for _, code := range []connect.Code{connect.CodeUnauthenticated, connect.CodePermissionDenied, connect.CodeInvalidArgument, connect.CodeAborted, connect.CodeCanceled, connect.CodeDeadlineExceeded} {
		if errors.Is(classify(connect.NewError(code, errors.New("must not fallback"))), ErrLegacyFallback) {
			t.Fatalf("%s must not use compatibility fallback", code)
		}
	}
}

func TestConnectBaseURL(t *testing.T) {
	if _, err := connectBaseURL("https://panel.example.test/"); err != nil {
		t.Fatal(err)
	}
	if _, err := connectBaseURL("not-a-url"); err == nil {
		t.Fatal("expected invalid endpoint error")
	}
	if err := classify(context.Canceled); !errors.Is(err, context.Canceled) {
		t.Fatal("cancellation must remain visible")
	}
}

func TestNewLoadsPersistedCredentialsWhenFlagsEmpty(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatalf("failed to open credentials: %v", err)
	}

	identity := credentials.Identity{
		Endpoint:             "https://panel.example.com:8443",
		AgentID:              "agent-uuid-12345",
		AccessToken:          "persisted-access-token-abcde",
		AccessTokenExpiresAt: time.Now().Add(24 * time.Hour),
		RefreshToken:         "persisted-refresh-token-12345",
	}
	if err := store.Save(identity); err != nil {
		t.Fatalf("failed to save identity: %v", err)
	}

	config := &flags_pkg.Config{
		Endpoint:        "", // Empty flags
		Token:           "", // Empty flags
		CredentialsFile: credPath,
	}

	rStore, err := runtimeconfig.New(runtimeconfig.FromFlags(config), filepath.Join(tempDir, "runtime.json"))
	if err != nil {
		t.Fatalf("failed to create runtime store: %v", err)
	}

	client, err := New(config, rStore)
	if err != nil {
		t.Fatalf("expected New to succeed by loading credentials.json, got error: %v", err)
	}

	if client.token != "persisted-access-token-abcde" {
		t.Fatalf("expected token %q, got %q", "persisted-access-token-abcde", client.token)
	}

	if client.agentID != "agent-uuid-12345" {
		t.Fatalf("expected agentID %q, got %q", "agent-uuid-12345", client.agentID)
	}
}

func TestVerifyExecutionAssignment_SignedEnvelopeSecurity(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")
	replayPath := filepath.Join(tempDir, "replay.json")

	panelPub, panelPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := credentials.Identity{
		Endpoint: "https://panel.example.com",
		AgentID:  "agent-test-123",
		ControlPlaneKeys: []credentials.PinnedKey{
			{
				Algorithm: int32(securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519),
				Value:     base64.StdEncoding.EncodeToString(panelPub),
				KeyID:     "panel-key-1",
			},
		},
	}
	if err := store.Save(identity); err != nil {
		t.Fatal(err)
	}

	cfg := &flags_pkg.Config{
		Endpoint:        "https://panel.example.com",
		Token:           "test-token",
		CredentialsFile: credPath,
		ReplayStateFile: replayPath,
	}
	rStore, _ := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(tempDir, "runtime.json"))
	client, err := New(cfg, rStore)
	if err != nil {
		t.Fatal(err)
	}

	spec := &execv1.ExecutionSpec{
		Command:   "uname",
		Arguments: []string{"-a"},
	}
	specBytes, _ := proto.Marshal(spec)

	nonce := uuid.NewString()
	instruction := &securityv1.SignedInstruction{
		AgentId:         "agent-test-123",
		Nonce:           nonce,
		IssuedAt:        timestamppb.Now(),
		ExpiresAt:       timestamppb.New(time.Now().Add(5 * time.Minute)),
		InstructionType: "exec:v1",
		Body:            specBytes,
	}
	payloadBytes, _ := proto.Marshal(instruction)
	sig := ed25519.Sign(panelPriv, payloadBytes)

	validEnvelope := &securityv1.SignedEnvelope{
		Payload: payloadBytes,
		Signatures: []*securityv1.Signature{
			{
				Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
				Value:     sig,
				KeyId:     "panel-key-1",
			},
		},
	}

	assignment := &execv1.ExecutionAssignment{
		AssignmentId: "assign-1",
		Execution: &execv1.Execution{
			ExecutionId: "exec-1",
		},
		Envelope: validEnvelope,
	}

	// 1. Valid execution assignment unpacks successfully
	unpacked, err := client.verifyExecutionAssignment(assignment)
	if err != nil {
		t.Fatalf("expected valid assignment to verify, got error: %v", err)
	}
	if unpacked.Command != "uname" || len(unpacked.Arguments) != 1 || unpacked.Arguments[0] != "-a" {
		t.Fatalf("unpacked spec mismatch: %+v", unpacked)
	}

	// 2. Replay attack with same nonce is rejected
	_, replayErr := client.verifyExecutionAssignment(assignment)
	if replayErr == nil {
		t.Fatal("expected replay attack with same nonce to be rejected, but it succeeded")
	}

	// 3. Tampered payload is rejected
	tamperedPayload := append([]byte(nil), payloadBytes...)
	tamperedPayload[len(tamperedPayload)-1] ^= 0xff
	tamperedAssignment := &execv1.ExecutionAssignment{
		AssignmentId: "assign-2",
		Execution: &execv1.Execution{
			ExecutionId: "exec-2",
		},
		Envelope: &securityv1.SignedEnvelope{
			Payload: tamperedPayload,
			Signatures: []*securityv1.Signature{
				{
					Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
					Value:     sig,
					KeyId:     "panel-key-1",
				},
			},
		},
	}
	if _, err := client.verifyExecutionAssignment(tamperedAssignment); err == nil {
		t.Fatal("expected tampered payload to be rejected")
	}

	// 4. Missing envelope is rejected
	if _, err := client.verifyExecutionAssignment(&execv1.ExecutionAssignment{Execution: &execv1.Execution{ExecutionId: "e3"}}); err == nil {
		t.Fatal("expected nil envelope to be rejected")
	}
}

func TestDPoPRequestSigningAndBodyHash(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	pubKeyStr, privKeyStr, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	rawPub, _ := base64.StdEncoding.DecodeString(pubKeyStr)
	pubKey := ed25519.PublicKey(rawPub)

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}
	identity := credentials.Identity{
		Endpoint:    "https://panel.example.com",
		AgentID:     "agent-dpop-1",
		PublicKey:   pubKeyStr,
		PrivateKey:  privKeyStr,
		KeyID:       keyID,
		AccessToken: "test-access-token-12345",
	}
	if err := store.Save(identity); err != nil {
		t.Fatal(err)
	}

	cfg := &flags_pkg.Config{
		Endpoint:        "https://panel.example.com",
		Token:           "test-access-token-12345",
		CredentialsFile: credPath,
	}
	rStore, _ := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(tempDir, "runtime.json"))
	client, err := New(cfg, rStore)
	if err != nil {
		t.Fatal(err)
	}

	var capturedSig, capturedTs, capturedNonce, capturedAuth string
	var capturedBody []byte
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedSig = r.Header.Get("X-Komari-Signature")
		capturedTs = r.Header.Get("X-Komari-Timestamp")
		capturedNonce = r.Header.Get("X-Komari-Nonce")
		capturedAuth = r.Header.Get("Authorization")
		capturedBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	dpopClient := wrapWithDPoP(server.Client(), client)

	reqBody := []byte(`{"message": "dpop test body payload"}`)
	path := "/komari.report.v1.AgentReportService/SubmitReport"
	req, err := http.NewRequest("POST", server.URL+path, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}

	resp, err := dpopClient.Do(req)
	if err != nil {
		t.Fatalf("dpop request failed: %v", err)
	}
	defer resp.Body.Close()

	if capturedSig == "" {
		t.Fatal("expected X-Komari-Signature to be present")
	}
	if capturedTs == "" {
		t.Fatal("expected X-Komari-Timestamp to be present")
	}
	if capturedNonce == "" {
		t.Fatal("expected X-Komari-Nonce to be present")
	}
	if capturedAuth != "Bearer test-access-token-12345" {
		t.Fatalf("expected Bearer token, got %q", capturedAuth)
	}
	if string(capturedBody) != string(reqBody) {
		t.Fatalf("expected body %q, got %q", string(reqBody), string(capturedBody))
	}

	// Verify the signature against pubKey with the exact RFC 9449 canonical payload
	tokenDigest := sha256.Sum256([]byte("test-access-token-12345"))
	tokenHash := hex.EncodeToString(tokenDigest[:])
	bodyDigest := sha256.Sum256(reqBody)
	bodyHash := hex.EncodeToString(bodyDigest[:])

	expectedPayload := fmt.Sprintf("%s\n%s\n%s\n%s\n%s\n%s", "POST", path, capturedTs, capturedNonce, tokenHash, bodyHash)
	sigBytes, err := base64.StdEncoding.DecodeString(capturedSig)
	if err != nil {
		t.Fatalf("decode signature failed: %v", err)
	}
	if !ed25519.Verify(pubKey, []byte(expectedPayload), sigBytes) {
		t.Fatal("DPoP signature verification against agent public key failed!")
	}
	t.Log("DPoP uplink signature verified successfully")
}

func TestDPoP_AutoRefreshOn401(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	pubKeyStr, privKeyStr, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}

	initialIdentity := credentials.Identity{
		AgentID:               "agent-refresh-1",
		PublicKey:             pubKeyStr,
		PrivateKey:            privKeyStr,
		KeyID:                 keyID,
		AccessToken:           "initial-expired-token",
		AccessTokenExpiresAt:  time.Now().Add(-1 * time.Hour),
		RefreshToken:          "valid-refresh-token-1234",
		RefreshTokenExpiresAt: time.Now().Add(30 * 24 * time.Hour),
	}

	var submitAttempts int
	var serverURL string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/komari.enrollment.v1.EnrollmentService/RefreshCredentials":
			// Mock refresh endpoint
			respMsg := &enrollmentv1.RefreshCredentialsResponse{
				Credentials: &enrollmentv1.AgentCredentials{
					AgentId:               "agent-refresh-1",
					AccessToken:           "new-access-token-rotated",
					AccessTokenExpiresAt:  timestamppb.New(time.Now().Add(24 * time.Hour)),
					RefreshToken:          "new-refresh-token-rotated",
					RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(30 * 24 * time.Hour)),
				},
			}
			out, _ := proto.Marshal(respMsg)
			w.Header().Set("Content-Type", "application/proto")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(out)
		case "/komari.report.v1.AgentReportService/SubmitReport":
			submitAttempts++
			auth := r.Header.Get("Authorization")
			if auth == "Bearer initial-expired-token" {
				// Reject initial expired token with 401
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusUnauthorized)
				_, _ = w.Write([]byte(`{"code": "UNAUTHENTICATED", "message": "token expired"}`))
				return
			}
			if auth == "Bearer new-access-token-rotated" {
				// Accept rotated token
				w.Header().Set("Content-Type", "application/proto")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte{})
				return
			}
			w.WriteHeader(http.StatusBadRequest)
		default:
			http.NotFound(w, r)
		}
	}))
	defer testServer.Close()
	serverURL = testServer.URL
	initialIdentity.Endpoint = serverURL
	if err := store.Save(initialIdentity); err != nil {
		t.Fatal(err)
	}

	cfg := &flags_pkg.Config{
		Endpoint:        serverURL,
		Token:           "initial-expired-token",
		CredentialsFile: credPath,
	}
	rStore, _ := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(tempDir, "runtime.json"))
	client, err := New(cfg, rStore)
	if err != nil {
		t.Fatal(err)
	}

	dpopClient := wrapWithDPoP(testServer.Client(), client)

	reqBody := []byte(`{"message": "submit-report"}`)
	path := "/komari.report.v1.AgentReportService/SubmitReport"
	req, err := http.NewRequest("POST", serverURL+path, bytes.NewReader(reqBody))
	if err != nil {
		t.Fatal(err)
	}

	// This request starts with "initial-expired-token", gets 401, auto-refreshes with the server,
	// updates credentials.json, and retries with "new-access-token-rotated" returning 200 OK!
	resp, err := dpopClient.Do(req)
	if err != nil {
		t.Fatalf("request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected HTTP 200 OK after auto-refresh, got %d", resp.StatusCode)
	}
	if submitAttempts != 2 {
		t.Fatalf("expected exactly 2 submit attempts (1 expired + 1 retry), got %d", submitAttempts)
	}
	if client.tokenValue() != "new-access-token-rotated" {
		t.Fatalf("expected client token to be updated, got %q", client.tokenValue())
	}

	persistedStore, err := credentials.Open(credPath)
	if err != nil {
		t.Fatalf("failed to reopen credentials store: %v", err)
	}
	persisted, ok := persistedStore.Identity()
	if !ok || persisted.AccessToken != "new-access-token-rotated" {
		t.Fatalf("expected persisted token to be updated in credentials.json, got %+v", persisted)
	}
	t.Log("Token auto-refresh state machine on 401 verified successfully")
}

func TestCredentialPriority_FileOverridesFlags(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatalf("failed to open credentials: %v", err)
	}

	identity := credentials.Identity{
		Endpoint:    "https://panel.file-priority.com",
		AgentID:     "agent-id-from-file",
		AccessToken: "access-token-from-file",
	}
	if err := store.Save(identity); err != nil {
		t.Fatalf("failed to save identity: %v", err)
	}

	// Flags have conflicting values
	cfg := &flags_pkg.Config{
		Endpoint:        "https://panel.flags-ignored.com",
		Token:           "token-from-flags",
		CredentialsFile: credPath,
	}

	rStore, err := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(tempDir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}

	client, err := New(cfg, rStore)
	if err != nil {
		t.Fatalf("expected New to succeed, got %v", err)
	}

	// Verify priority: credentials.json must win!
	if client.endpoint != "https://panel.file-priority.com" {
		t.Fatalf("expected endpoint %q, got %q", "https://panel.file-priority.com", client.endpoint)
	}
	if client.token != "access-token-from-file" {
		t.Fatalf("expected token %q, got %q", "access-token-from-file", client.token)
	}
	if client.agentID != "agent-id-from-file" {
		t.Fatalf("expected agentID %q, got %q", "agent-id-from-file", client.agentID)
	}
}

func TestVerifyPrivilegedRevision_RejectsZeroKeys(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}

	// Identity with ZERO pinned keys
	identity := credentials.Identity{
		Endpoint:         "https://panel.example.com",
		AgentID:          "agent-zero-keys",
		AccessToken:      "token-123",
		ControlPlaneKeys: []credentials.PinnedKey{},
	}
	if err := store.Save(identity); err != nil {
		t.Fatal(err)
	}

	cfg := &flags_pkg.Config{
		Endpoint:        "https://panel.example.com",
		Token:           "token-123",
		CredentialsFile: credPath,
	}
	rStore, _ := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(tempDir, "runtime.json"))
	client, err := New(cfg, rStore)
	if err != nil {
		t.Fatal(err)
	}

	// Call verifyPrivilegedRevision with zero pinned keys and no mock server
	err = client.verifyPrivilegedRevision(&configv1.PrivilegedRevision{
		Revision: 10,
	})

	// Must NOT return nil! It must reject with an error!
	if err == nil {
		t.Fatal("verifyPrivilegedRevision with 0 pinned keys must fail, but succeeded with nil")
	}
	t.Logf("verifyPrivilegedRevision correctly rejected zero pinned keys: %v", err)
}

func TestVerifyExecutionAssignment_RejectsZeroKeys(t *testing.T) {
	tempDir := t.TempDir()
	credPath := filepath.Join(tempDir, "credentials.json")

	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}

	// Identity with ZERO pinned keys
	identity := credentials.Identity{
		Endpoint:         "https://panel.example.com",
		AgentID:          "agent-zero-keys",
		AccessToken:      "token-123",
		ControlPlaneKeys: []credentials.PinnedKey{},
	}
	if err := store.Save(identity); err != nil {
		t.Fatal(err)
	}

	cfg := &flags_pkg.Config{
		Endpoint:        "https://panel.example.com",
		Token:           "token-123",
		CredentialsFile: credPath,
	}
	rStore, _ := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(tempDir, "runtime.json"))
	client, err := New(cfg, rStore)
	if err != nil {
		t.Fatal(err)
	}

	assignment := &execv1.ExecutionAssignment{
		AssignmentId: "assign-zero-keys",
		Execution: &execv1.Execution{
			ExecutionId: "exec-zero-keys",
		},
		Envelope: &securityv1.SignedEnvelope{
			Payload: []byte("some-payload"),
		},
	}

	_, err = client.verifyExecutionAssignment(assignment)
	if err == nil {
		t.Fatal("verifyExecutionAssignment with 0 pinned keys must fail, but succeeded with nil")
	}
	t.Logf("verifyExecutionAssignment correctly rejected zero pinned keys: %v", err)
}

func TestProbeCancellationOnFatalError(t *testing.T) {
	tempDir := t.TempDir()
	cfg := &flags_pkg.Config{
		Endpoint: "https://panel.example.com",
		Token:    "token-123",
	}
	rStore, _ := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(tempDir, "runtime.json"))
	client, err := New(cfg, rStore)
	if err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	client.setProbeCancel(cancel)

	select {
	case <-ctx.Done():
		t.Fatal("context should not be cancelled yet")
	default:
	}

	client.cancelProbes()

	select {
	case <-ctx.Done():
		// Success! Context was cancelled by cancelProbes()
	case <-time.After(1 * time.Second):
		t.Fatal("probe context was not cancelled within timeout")
	}
}

