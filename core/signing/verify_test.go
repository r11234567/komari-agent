package signing

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type fixture struct {
	private  ed25519.PrivateKey
	identity credentials.Identity
	replay   *ReplayGuard
}

func newFixture(t *testing.T) fixture {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return fixture{
		private: private,
		identity: credentials.Identity{
			AgentID: "agent-1",
			ControlPlaneKeys: []credentials.PinnedKey{{
				Algorithm: int32(securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519),
				Value:     base64.StdEncoding.EncodeToString(public),
				KeyID:     "key-1",
			}},
		},
		replay: NewReplayGuard(filepath.Join(t.TempDir(), "nonces.json")),
	}
}

func (f fixture) envelope(t *testing.T, mutate func(*securityv1.SignedInstruction)) *securityv1.SignedEnvelope {
	t.Helper()
	instruction := &securityv1.SignedInstruction{
		AgentId:         "agent-1",
		Nonce:           "nonce-" + t.Name(),
		IssuedAt:        timestamppb.Now(),
		ExpiresAt:       timestamppb.New(time.Now().Add(10 * time.Minute)),
		InstructionType: "test",
		Body:            []byte("body"),
	}
	if mutate != nil {
		mutate(instruction)
	}
	payload, err := proto.Marshal(instruction)
	if err != nil {
		t.Fatal(err)
	}
	return &securityv1.SignedEnvelope{
		Payload: payload,
		Signatures: []*securityv1.Signature{{
			Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519,
			Value:     ed25519.Sign(f.private, payload),
			KeyId:     "key-1",
		}},
	}
}

func TestVerifyAcceptsValidInstruction(t *testing.T) {
	f := newFixture(t)
	instruction, err := New(f.identity, f.replay).Verify(f.envelope(t, nil))
	if err != nil {
		t.Fatalf("Verify() error = %v", err)
	}
	if string(instruction.Body) != "body" || instruction.VerifiedBy != "key-1" {
		t.Fatalf("Verify() = %+v", instruction)
	}
}

func TestVerifyRejectsWithoutPinnedKeys(t *testing.T) {
	f := newFixture(t)
	envelope := f.envelope(t, nil)
	f.identity.ControlPlaneKeys = nil
	if _, err := New(f.identity, f.replay).Verify(envelope); err == nil {
		t.Fatal("Verify() accepted an instruction with no pinned keys")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	f := newFixture(t)
	envelope := f.envelope(t, nil)
	envelope.Payload = append(envelope.Payload, 0x01)
	if _, err := New(f.identity, f.replay).Verify(envelope); err == nil {
		t.Fatal("Verify() accepted a tampered payload")
	}
}

func TestVerifyRejectsForeignKey(t *testing.T) {
	f := newFixture(t)
	other := newFixture(t)
	if _, err := New(f.identity, f.replay).Verify(other.envelope(t, nil)); err == nil {
		t.Fatal("Verify() accepted a signature from an unpinned key")
	}
}

func TestVerifyRejectsOtherAgent(t *testing.T) {
	f := newFixture(t)
	envelope := f.envelope(t, func(i *securityv1.SignedInstruction) { i.AgentId = "agent-2" })
	if _, err := New(f.identity, f.replay).Verify(envelope); err == nil {
		t.Fatal("Verify() accepted an instruction addressed to another agent")
	}
}

func TestVerifyRejectsExpiredAndUnbounded(t *testing.T) {
	f := newFixture(t)
	expired := f.envelope(t, func(i *securityv1.SignedInstruction) {
		i.Nonce = "expired"
		i.ExpiresAt = timestamppb.New(time.Now().Add(-time.Hour))
	})
	if _, err := New(f.identity, f.replay).Verify(expired); err == nil {
		t.Fatal("Verify() accepted an expired instruction")
	}
	unbounded := f.envelope(t, func(i *securityv1.SignedInstruction) {
		i.Nonce = "unbounded"
		i.ExpiresAt = nil
	})
	if _, err := New(f.identity, f.replay).Verify(unbounded); err == nil {
		t.Fatal("Verify() accepted an instruction without an expiry")
	}
}

func TestVerifyRejectsReplayAcrossRestart(t *testing.T) {
	f := newFixture(t)
	envelope := f.envelope(t, nil)
	if _, err := New(f.identity, f.replay).Verify(envelope); err != nil {
		t.Fatalf("first Verify() error = %v", err)
	}
	// A fresh guard over the same file models an Agent restart.
	restarted := NewReplayGuard(f.replay.path)
	_, err := New(f.identity, restarted).Verify(envelope)
	if err == nil || !strings.Contains(err.Error(), "already carried out") {
		t.Fatalf("replayed Verify() error = %v, want replay rejection", err)
	}
}

func TestVerifyIgnoresUnimplementedAlgorithm(t *testing.T) {
	f := newFixture(t)
	envelope := f.envelope(t, nil)
	envelope.Signatures[0].Algorithm = securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65
	f.identity.ControlPlaneKeys[0].Algorithm = int32(securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65)
	f.identity.PolicyAlgorithms = []int32{int32(securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ML_DSA_65)}
	if _, err := New(f.identity, f.replay).Verify(envelope); err == nil {
		t.Fatal("Verify() treated an algorithm it cannot check as verified")
	}
}
