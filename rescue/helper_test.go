package rescue

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/credentials"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestHelper_VerifyRescueAssignmentEnvelope(t *testing.T) {
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
		AgentID:  "agent-rescue-test",
		ControlPlaneKeys: []credentials.PinnedKey{
			{
				Algorithm: int32(securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519),
				Value:     base64.StdEncoding.EncodeToString(panelPub),
				KeyID:     "panel-rescue-key-1",
			},
		},
	}
	if err := store.Save(identity); err != nil {
		t.Fatal(err)
	}

	cfg := Config{
		Endpoint:        "https://panel.example.com",
		Token:           "test-token",
		CredentialsFile: credPath,
		ReplayFile:      replayPath,
	}

	helper, err := New(cfg)
	if err != nil {
		t.Fatalf("failed to create rescue helper: %v", err)
	}

	session := &rescuev1.RescueSession{
		SessionId: "session-100",
		Action:    rescuev1.RescueAction_RESCUE_ACTION_DIAGNOSTICS,
		SshPort:   proto.Uint32(0),
	}
	sessionBytes, _ := proto.Marshal(session)

	instruction := &securityv1.SignedInstruction{
		AgentId:         "agent-rescue-test",
		Nonce:           uuid.NewString(),
		IssuedAt:        timestamppb.Now(),
		ExpiresAt:       timestamppb.New(time.Now().Add(5 * time.Minute)),
		InstructionType: "rescue:v1",
		Body:            sessionBytes,
	}
	payloadBytes, _ := proto.Marshal(instruction)
	sig := ed25519.Sign(panelPriv, payloadBytes)

	validEnvelope := &securityv1.SignedEnvelope{
		Payload: payloadBytes,
		Signatures: []*securityv1.Signature{
			{
				Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
				Value:     sig,
				KeyId:     "panel-rescue-key-1",
			},
		},
	}

	// 1. Valid assignment with valid envelope
	validAssignment := &rescuev1.RescueAssignment{
		AssignmentId: "assign-rescue-1",
		Session:      session,
		Envelope:     validEnvelope,
	}

	resSession, err := helper.verifyRescueAssignment(validAssignment)
	if err != nil {
		t.Fatalf("expected valid assignment to pass envelope verification, got: %v", err)
	}
	if resSession.GetSessionId() != "session-100" {
		t.Fatalf("expected session ID %q, got %q", "session-100", resSession.GetSessionId())
	}

	// 2. Missing envelope must be rejected
	missingEnvelopeAssignment := &rescuev1.RescueAssignment{
		AssignmentId: "assign-rescue-2",
		Session:      session,
		Envelope:     nil,
	}
	if _, err := helper.verifyRescueAssignment(missingEnvelopeAssignment); err == nil {
		t.Fatal("expected missing envelope to be rejected, but it succeeded")
	}

	// 3. Forged envelope (bad signature) must be rejected
	forgedEnvelope := proto.Clone(validEnvelope).(*securityv1.SignedEnvelope)
	forgedEnvelope.Signatures[0].Value = []byte("invalid-fake-signature")
	forgedAssignment := &rescuev1.RescueAssignment{
		AssignmentId: "assign-rescue-3",
		Session:      session,
		Envelope:     forgedEnvelope,
	}
	if _, err := helper.verifyRescueAssignment(forgedAssignment); err == nil {
		t.Fatal("expected forged signature envelope to be rejected, but it succeeded")
	}

	// 4. Mismatched session (envelope authorizes DIAGNOSTICS, assignment claims TEMPORARY_SSH_ACCESS)
	mismatchedSession := &rescuev1.RescueSession{
		SessionId: "session-100",
		Action:    rescuev1.RescueAction_RESCUE_ACTION_TEMPORARY_SSH_ACCESS,
		SshPort:   proto.Uint32(2222),
	}
	mismatchedAssignment := &rescuev1.RescueAssignment{
		AssignmentId: "assign-rescue-4",
		Session:      mismatchedSession,
		Envelope:     validEnvelope,
	}
	if _, err := helper.verifyRescueAssignment(mismatchedAssignment); err == nil {
		t.Fatal("expected mismatched action to be rejected, but it succeeded")
	}
}
