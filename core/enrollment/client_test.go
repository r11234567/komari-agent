package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestVerifyResponseEnvelope_SuccessAndSecurity(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	identity := credentials.Identity{
		Endpoint: "https://panel.example.com",
		AgentID:  "agent-enroll-123",
		ControlPlaneKeys: []credentials.PinnedKey{
			{
				Algorithm: int32(securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519),
				Value:     base64.StdEncoding.EncodeToString(pub),
				KeyID:     "panel-enroll-key-1",
			},
		},
	}

	issued := &enrollmentv1.AgentCredentials{
		AgentId:               "agent-enroll-123",
		AccessToken:           "new-access-token-999",
		AccessTokenExpiresAt:  timestamppb.New(time.Now().Add(24 * time.Hour)),
		RefreshToken:          "new-refresh-token-888",
		RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(30 * 24 * time.Hour)),
	}

	tokenDigest := sha256.Sum256([]byte("new-access-token-999"))
	instruction := &securityv1.SignedInstruction{
		AgentId:         "agent-enroll-123",
		Nonce:           "refresh-nonce-1",
		IssuedAt:        timestamppb.Now(),
		ExpiresAt:       timestamppb.New(time.Now().Add(5 * time.Minute)),
		InstructionType: "refresh:v1",
		Body:            []byte(hex.EncodeToString(tokenDigest[:])),
	}
	payloadBytes, _ := proto.Marshal(instruction)
	sig := ed25519.Sign(priv, payloadBytes)

	validEnvelope := &securityv1.SignedEnvelope{
		Payload: payloadBytes,
		Signatures: []*securityv1.Signature{
			{
				Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
				Value:     sig,
				KeyId:     "panel-enroll-key-1",
			},
		},
	}

	// 1. Valid envelope and matching credentials -> SUCCESS
	if err := verifyResponseEnvelope(validEnvelope, identity, issued); err != nil {
		t.Fatalf("expected valid envelope to succeed, got %v", err)
	}

	// 2. Mismatched token in issued credentials -> REJECTED
	mismatchedIssued := &enrollmentv1.AgentCredentials{
		AgentId:     "agent-enroll-123",
		AccessToken: "different-unauthorized-token",
	}
	if err := verifyResponseEnvelope(validEnvelope, identity, mismatchedIssued); err == nil {
		t.Fatal("expected mismatched token to be rejected, but it succeeded")
	}

	// 3. Forged signature -> REJECTED
	forgedEnvelope := proto.Clone(validEnvelope).(*securityv1.SignedEnvelope)
	forgedEnvelope.Signatures[0].Value = []byte("corrupted-sig")
	if err := verifyResponseEnvelope(forgedEnvelope, identity, issued); err == nil {
		t.Fatal("expected forged signature to be rejected, but it succeeded")
	}

	// 4. Zero pinned keys -> REJECTED
	zeroKeyIdentity := identity
	zeroKeyIdentity.ControlPlaneKeys = nil
	if err := verifyResponseEnvelope(validEnvelope, zeroKeyIdentity, issued); err == nil {
		t.Fatal("expected zero pinned keys to be rejected, but it succeeded")
	}
}
