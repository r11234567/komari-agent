package enrollment

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"path/filepath"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestVerifiedTrustRotationPersistsMonotonicRevision(t *testing.T) {
	now := time.Now().UTC()
	keyPair := func() (*securityv1.PublicKey, ed25519.PrivateKey) {
		t.Helper()
		public, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		hash := sha256.Sum256(public)
		return &securityv1.PublicKey{KeyId: base64.RawURLEncoding.EncodeToString(hash[:16]), Value: public,
			Algorithm: trustAlgorithm, NotBefore: timestamppb.New(now.Add(-time.Minute))}, private
	}
	old, oldPrivate := keyPair()
	next, nextPrivate := keyPair()
	envelope := func(key *securityv1.PublicKey, private ed25519.PrivateKey, body proto.Message) *securityv1.SignedEnvelope {
		t.Helper()
		payload, err := proto.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		return &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{
			{KeyId: key.GetKeyId(), Algorithm: trustAlgorithm, Value: ed25519.Sign(private, payload)},
		}}
	}
	rotation := envelope(old, oldPrivate, &enrollmentv1.TrustKeyRotation{PreviousKeyId: old.KeyId, Revision: 2, Key: next})
	challenge := bytes.Repeat([]byte{17}, 32)
	current, err := trustKey(old)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(credentials.Identity{AgentID: "fixture-agent", TrustRevision: 1,
		TrustSigningKeyID: old.KeyId, ControlPlaneKeys: []credentials.PinnedKey{current}}); err != nil {
		t.Fatal(err)
	}
	before, _ := store.Identity()
	makeBundle := func(key *securityv1.PublicKey, private ed25519.PrivateKey, revision uint64, rotations ...*securityv1.SignedEnvelope) *securityv1.SignedEnvelope {
		t.Helper()
		request := &enrollmentv1.TrustBundle{
			Revision: revision, Challenge: challenge, SigningKeys: []*securityv1.PublicKey{key}, Rotations: rotations,
			Policy: &securityv1.VerificationPolicy{AcceptedAlgorithms: []securityv1.SignatureAlgorithm{trustAlgorithm}, MinimumSignatures: 1},
		}
		body, err := proto.Marshal(request)
		if err != nil {
			t.Fatal(err)
		}
		return envelope(key, private, &securityv1.SignedInstruction{
			AgentId: before.AgentID, Nonce: base64.RawURLEncoding.EncodeToString(challenge), Body: body,
			IssuedAt: timestamppb.New(now), ExpiresAt: timestamppb.New(now.Add(time.Minute)),
			InstructionType: string(request.ProtoReflect().Descriptor().FullName()),
		})
	}
	signed := makeBundle(next, nextPrivate, 2, rotation)
	if _, err := verifyTrustBundle(before, bytes.Repeat([]byte{99}, 32), signed, now); err == nil {
		t.Fatal("bundle accepted without the matching local challenge")
	}
	updated, err := verifyTrustBundle(before, challenge, signed, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.ApplyVerifiedTrustBundle(before, updated); err != nil {
		t.Fatal(err)
	}
	reopened, err := credentials.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	after, _ := reopened.Identity()
	if after.TrustRevision != 2 || after.TrustSigningKeyID != next.KeyId {
		t.Fatalf("rotation was not persisted: revision=%d signer=%q", after.TrustRevision, after.TrustSigningKeyID)
	}
	if _, err := verifyTrustBundle(after, challenge, makeBundle(old, oldPrivate, 1), now); err == nil {
		t.Fatal("persisted trust accepted an older revision")
	}
}
