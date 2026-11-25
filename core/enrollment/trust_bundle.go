package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/signing"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
)

const trustAlgorithm = securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519

// FetchVerifiedTrustBundle advances trust only from an existing local pin.
func (c *Client) FetchVerifiedTrustBundle(ctx context.Context, identity credentials.Identity) (credentials.Identity, error) {
	if identity.AgentID == "" || len(identity.ControlPlaneKeys) == 0 {
		return identity, errors.New("an existing local panel pin is required")
	}
	challenge := make([]byte, 32)
	if _, err := rand.Read(challenge); err != nil {
		return identity, err
	}
	response, err := c.service.GetTrustBundle(ctx, connect.NewRequest(&enrollmentv1.GetTrustBundleRequest{AgentId: identity.AgentID, Challenge: challenge}))
	if err != nil {
		return identity, err
	}
	return verifyTrustBundle(identity, challenge, response.Msg.GetEnvelope(), time.Now().UTC())
}

func verifyTrustBundle(identity credentials.Identity, challenge []byte, envelope *securityv1.SignedEnvelope, now time.Time) (credentials.Identity, error) {
	var instruction securityv1.SignedInstruction
	if len(envelope.GetPayload()) == 0 || len(envelope.GetPayload()) > 256<<10 || len(envelope.GetSignatures()) != 1 ||
		proto.Unmarshal(envelope.GetPayload(), &instruction) != nil {
		return identity, errors.New("invalid signed trust bundle")
	}
	var bundle enrollmentv1.TrustBundle
	if proto.Unmarshal(instruction.GetBody(), &bundle) != nil || len(bundle.GetRotations()) > 128 ||
		!bytes.Equal(bundle.GetChallenge(), challenge) || bundle.GetRevision() == 0 || bundle.GetRevision() < identity.TrustRevision {
		return identity, errors.New("trust bundle challenge or revision is invalid")
	}
	anchors := make(map[string]credentials.PinnedKey, len(identity.ControlPlaneKeys))
	for _, key := range identity.ControlPlaneKeys {
		if identity.TrustSigningKeyID != "" {
			if key.KeyID == identity.TrustSigningKeyID {
				anchors[key.KeyID] = key
			}
			continue
		}
		if trustKeyActiveAt(key, now) {
			anchors[key.KeyID] = key
		}
	}
	revision := identity.TrustRevision
	for _, proof := range bundle.GetRotations() {
		var rotation enrollmentv1.TrustKeyRotation
		if proto.Unmarshal(proof.GetPayload(), &rotation) != nil {
			return identity, errors.New("invalid panel key rotation")
		}
		key, found := anchors[rotation.GetPreviousKeyId()]
		if !found || rotation.GetRevision() <= revision {
			continue
		}
		if rotation.GetRevision() > bundle.GetRevision() || (revision != 0 && rotation.GetRevision() != revision+1) ||
			!validTrustSignature(key, proof) {
			return identity, errors.New("panel key rotation is not authorized by the preceding key")
		}
		next, err := trustKey(rotation.GetKey())
		if err != nil || next.NotBefore.After(now) || next.NotAfter != nil {
			return identity, errors.New("panel key rotation has an invalid successor")
		}
		anchors = map[string]credentials.PinnedKey{next.KeyID: next}
		revision = rotation.GetRevision()
	}
	signer := envelope.GetSignatures()[0].GetKeyId()
	key, ok := anchors[signer]
	if !ok || (revision != 0 && revision != bundle.GetRevision()) {
		return identity, errors.New("trust bundle signer is outside the locally trusted rotation chain")
	}
	anchor := credentials.Identity{AgentID: identity.AgentID, ControlPlaneKeys: []credentials.PinnedKey{key}}
	verified, err := signing.New(anchor, nil).Verify(envelope)
	if err != nil {
		return identity, err
	}
	if verified.InstructionType != string(bundle.ProtoReflect().Descriptor().FullName()) ||
		verified.Nonce != base64.RawURLEncoding.EncodeToString(challenge) || verified.IssuedAt.IsZero() ||
		!now.Before(verified.ExpiresAt) || verified.ExpiresAt.Sub(verified.IssuedAt) <= 0 ||
		verified.ExpiresAt.Sub(verified.IssuedAt) > time.Minute {
		return identity, errors.New("trust bundle is outside its authorization window")
	}
	policy := bundle.GetPolicy()
	if len(policy.GetAcceptedAlgorithms()) != 1 || policy.GetAcceptedAlgorithms()[0] != trustAlgorithm || policy.GetMinimumSignatures() != 1 {
		return identity, errors.New("trust bundle contains an unsupported verification policy")
	}
	keys := make([]credentials.PinnedKey, 0, len(bundle.GetSigningKeys()))
	currentFound := false
	seen := make(map[string]bool)
	for _, candidate := range bundle.GetSigningKeys() {
		pinned, err := trustKey(candidate)
		if err != nil || seen[pinned.KeyID] {
			return identity, errors.New("trust bundle contains an invalid key")
		}
		seen[pinned.KeyID] = true
		if trustKeyActiveAt(pinned, now) {
			keys = append(keys, pinned)
			if pinned.KeyID == signer && pinned.Value == key.Value && pinned.NotAfter == nil {
				currentFound = true
			}
		}
	}
	if !currentFound {
		return identity, errors.New("trust bundle does not include its active signer")
	}
	identity.ControlPlaneKeys = keys
	identity.TrustRevision = bundle.GetRevision()
	identity.TrustSigningKeyID = signer
	identity.PolicyAlgorithms = []int32{int32(trustAlgorithm)}
	identity.PolicyRequireAll = policy.GetRequireAll()
	identity.PolicyMinimumSignatures = policy.GetMinimumSignatures()
	return identity, nil
}

func trustKeyActiveAt(key credentials.PinnedKey, now time.Time) bool {
	return !now.Before(key.NotBefore) && (key.NotAfter == nil || now.Before(*key.NotAfter))
}

func validTrustSignature(key credentials.PinnedKey, envelope *securityv1.SignedEnvelope) bool {
	raw, err := base64.StdEncoding.DecodeString(key.Value)
	if err != nil || len(raw) != ed25519.PublicKeySize || key.Algorithm != int32(trustAlgorithm) || len(envelope.GetSignatures()) != 1 {
		return false
	}
	signature := envelope.GetSignatures()[0]
	return signature.GetKeyId() == key.KeyID && signature.GetAlgorithm() == trustAlgorithm &&
		ed25519.Verify(raw, envelope.GetPayload(), signature.GetValue())
}

func trustKey(key *securityv1.PublicKey) (credentials.PinnedKey, error) {
	raw := key.GetValue()
	digest := sha256.Sum256(raw)
	if len(raw) != ed25519.PublicKeySize || key.GetAlgorithm() != trustAlgorithm ||
		key.GetKeyId() != base64.RawURLEncoding.EncodeToString(digest[:16]) || !key.GetNotBefore().IsValid() {
		return credentials.PinnedKey{}, errors.New("invalid panel public key")
	}
	pinned := credentials.PinnedKey{KeyID: key.GetKeyId(), Algorithm: int32(trustAlgorithm), Value: base64.StdEncoding.EncodeToString(raw), NotBefore: key.GetNotBefore().AsTime()}
	if expiry := key.GetNotAfter(); expiry != nil {
		if !expiry.IsValid() || expiry.AsTime().Before(pinned.NotBefore) {
			return credentials.PinnedKey{}, errors.New("invalid panel key expiry")
		}
		at := expiry.AsTime()
		pinned.NotAfter = &at
	}
	return pinned, nil
}
