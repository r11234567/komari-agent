package enrollment

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/credentials"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestCredentialRefreshV2RejectsTamperingAndMissingProof(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	generation := uint64(8)
	id := credentials.Identity{AgentID: "node", AccessToken: "old-at", RefreshToken: "old-rt", Generation: &generation, PendingRefresh: &credentials.RefreshAttempt{RequestID: uuid.NewString()}, ControlPlaneKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "panel", Value: base64.StdEncoding.EncodeToString(public)}}}
	issued := &enrollmentv1.AgentCredentials{AgentId: "node", AccessToken: "new-at", RefreshToken: "new-rt", AccessTokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(7 * 24 * time.Hour)), Scopes: []string{"report"}}
	raw, _ := proto.MarshalOptions{Deterministic: true}.Marshal(issued)
	digest := sha256.Sum256(raw)
	payload, _ := json.Marshal(refreshV2Response{Protocol: 2, AgentID: id.AgentID, RequestID: id.PendingRefresh.RequestID, Generation: 9, CredentialsSHA256: hex.EncodeToString(digest[:])})
	envelope := &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{{Algorithm: 1, KeyId: "panel", Value: ed25519.Sign(private, payload)}}}
	if got, err := verifyRefreshV2Response(envelope, id, issued); err != nil || got != 9 {
		t.Fatalf("valid response rejected: %d %v", got, err)
	}
	for _, field := range []string{"access", "refresh", "access-expiry", "refresh-expiry", "scopes", "agent", "request", "generation", "proof", "signature", "key-expired", "threshold"} {
		t.Run(field, func(t *testing.T) {
			altered := proto.Clone(issued).(*enrollmentv1.AgentCredentials)
			proof := proto.Clone(envelope).(*securityv1.SignedEnvelope)
			identity := id
			switch field {
			case "access":
				altered.AccessToken = "forged"
			case "refresh":
				altered.RefreshToken = "forged"
			case "access-expiry":
				altered.AccessTokenExpiresAt = timestamppb.New(time.Now().Add(24 * time.Hour))
			case "refresh-expiry":
				altered.RefreshTokenExpiresAt = timestamppb.New(time.Now().Add(365 * 24 * time.Hour))
			case "scopes":
				altered.Scopes = []string{"admin"}
			case "agent":
				altered.AgentId = "other"
			case "request":
				identity.PendingRefresh = &credentials.RefreshAttempt{RequestID: uuid.NewString()}
			case "generation":
				wrong := uint64(99)
				identity.Generation = &wrong
			case "proof":
				proof = nil
			case "signature":
				proof.Signatures[0].Value[0] ^= 1
			case "key-expired":
				expiry := time.Now().Add(-time.Second)
				identity.ControlPlaneKeys = append([]credentials.PinnedKey(nil), id.ControlPlaneKeys...)
				identity.ControlPlaneKeys[0].NotAfter = &expiry
			case "threshold":
				identity.PolicyMinimumSignatures = 2
			}
			if _, err := verifyRefreshV2Response(proof, identity, altered); err == nil {
				t.Fatal("tampered or unbound credential response accepted")
			}
		})
	}
}
