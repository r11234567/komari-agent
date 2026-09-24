// Package signing verifies that a privileged instruction really came from the
// panel this Agent enrolled with.
//
// TLS cannot answer that question on its own. It routinely terminates at a
// reverse proxy or an access gateway that sees plaintext, so anything past
// that point could compose an instruction the Agent would otherwise obey. The
// panel therefore signs instructions end to end, and this package is where an
// Agent decides whether to believe one.
//
// Every failure path here rejects. There is deliberately no mode that accepts
// an unverifiable instruction: an Agent that falls back to trusting whatever
// arrives has the same security properties as one that never checked, while
// giving everyone the impression that it did.
package signing

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// maximumClockSkew tolerates a modest disagreement between the panel's clock
// and this host's. Without it an Agent whose clock runs slightly fast rejects
// instructions that were issued correctly, which looks like an attack and is
// not one.
const maximumClockSkew = 2 * time.Minute

// Verifier checks signed instructions against the keys this Agent pinned.
type Verifier struct {
	agentID string
	keys    []credentials.PinnedKey
	policy  Policy
	replay  *ReplayGuard
	nowFunc func() time.Time
}

// Policy is the verification policy delivered with the trust bundle.
type Policy struct {
	// AcceptedAlgorithms lists algorithms that may count toward the threshold.
	// An algorithm absent from this list is ignored even if its signature is
	// cryptographically valid, which is what lets a deployment retire one.
	AcceptedAlgorithms []int32
	// RequireAll demands every accepted algorithm present in the envelope
	// verify, for a deployment that has finished migrating to dual-signing.
	RequireAll bool
	// MinimumSignatures is how many must verify. Zero means one.
	MinimumSignatures uint32
}

// Instruction is a verified instruction. It is only ever produced after every
// check has passed, so holding one is itself the proof.
type Instruction struct {
	AgentID         string
	Nonce           string
	InstructionType string
	Body            []byte
	IssuedAt        time.Time
	ExpiresAt       time.Time
	// VerifiedBy names the key that vouched for it, for the audit trail.
	VerifiedBy string
}

// New builds a verifier from a stored identity.
//
// An identity with no pinned keys produces a verifier that rejects everything.
// That is the intended behaviour: the alternative is accepting instructions
// from anyone, which is worse than refusing to act.
func New(identity credentials.Identity, replay *ReplayGuard) *Verifier {
	policy := Policy{
		AcceptedAlgorithms: identity.PolicyAlgorithms,
		RequireAll:         identity.PolicyRequireAll,
		MinimumSignatures:  identity.PolicyMinimumSignatures,
	}
	// A bundle that arrived without an explicit algorithm list still has to
	// mean something. Ed25519 is what enrollment pins today, so defaulting to
	// it keeps an older bundle working without widening what is accepted.
	if len(policy.AcceptedAlgorithms) == 0 {
		policy.AcceptedAlgorithms = []int32{int32(securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519)}
	}
	return &Verifier{
		agentID: identity.AgentID,
		keys:    identity.ControlPlaneKeys,
		policy:  policy,
		replay:  replay,
		nowFunc: time.Now,
	}
}

// Verify checks an envelope and returns the instruction it carries.
func (v *Verifier) Verify(envelope *securityv1.SignedEnvelope) (Instruction, error) {
	if envelope == nil {
		return Instruction{}, errors.New("no signed instruction was provided")
	}
	if len(v.keys) == 0 {
		return Instruction{}, errors.New(
			"no panel signing keys are pinned, so this instruction cannot be verified; run 'komari-agent trust refresh'")
	}
	payload := envelope.GetPayload()
	if len(payload) == 0 {
		return Instruction{}, errors.New("the signed instruction has no payload")
	}

	verifiedBy, err := v.verifySignatures(payload, envelope.GetSignatures())
	if err != nil {
		return Instruction{}, err
	}

	// The payload is parsed only after its signature is established. Decoding
	// attacker-controlled bytes first would expose the parser to input nobody
	// vouched for.
	var instruction securityv1.SignedInstruction
	if err := proto.Unmarshal(payload, &instruction); err != nil {
		return Instruction{}, fmt.Errorf("the signed payload could not be decoded: %w", err)
	}

	now := v.nowFunc()
	if err := v.checkBinding(&instruction, now); err != nil {
		return Instruction{}, err
	}

	// The nonce is consumed last, once everything else has passed. Consuming
	// it earlier would let a malformed replay burn a nonce and make the
	// legitimate instruction fail.
	if v.replay != nil {
		if err := v.replay.Consume(instruction.GetNonce(), timeOrZero(instruction.GetExpiresAt())); err != nil {
			return Instruction{}, err
		}
	}

	return Instruction{
		AgentID:         instruction.GetAgentId(),
		Nonce:           instruction.GetNonce(),
		InstructionType: instruction.GetInstructionType(),
		Body:            instruction.GetBody(),
		IssuedAt:        timeOrZero(instruction.GetIssuedAt()),
		ExpiresAt:       timeOrZero(instruction.GetExpiresAt()),
		VerifiedBy:      verifiedBy,
	}, nil
}

// verifySignatures applies the policy and reports which key vouched.
func (v *Verifier) verifySignatures(payload []byte, signatures []*securityv1.Signature) (string, error) {
	if len(signatures) == 0 {
		return "", errors.New("the instruction carries no signature")
	}
	accepted := make(map[int32]bool, len(v.policy.AcceptedAlgorithms))
	for _, algorithm := range v.policy.AcceptedAlgorithms {
		accepted[algorithm] = true
	}

	now := v.nowFunc()
	verified := make(map[int32]bool)
	present := make(map[int32]bool)
	verifiedKeyIDs := make([]string, 0, len(signatures))

	for _, signature := range signatures {
		algorithm := int32(signature.GetAlgorithm())
		// An algorithm outside the policy is skipped rather than failing the
		// envelope, so a panel signing with both an old and a new scheme does
		// not break Agents that only accept one of them.
		if !accepted[algorithm] {
			continue
		}
		present[algorithm] = true
		key, ok := v.findKey(signature.GetKeyId(), algorithm, now)
		if !ok {
			continue
		}
		if verifyOne(algorithm, key, payload, signature.GetValue()) {
			verified[algorithm] = true
			verifiedKeyIDs = append(verifiedKeyIDs, signature.GetKeyId())
		}
	}

	if v.policy.RequireAll {
		for algorithm := range present {
			if !verified[algorithm] {
				return "", fmt.Errorf("a %s signature was present but did not verify", describeAlgorithm(algorithm))
			}
		}
	}

	minimum := int(v.policy.MinimumSignatures)
	if minimum <= 0 {
		minimum = 1
	}
	if len(verifiedKeyIDs) < minimum {
		return "", fmt.Errorf("the instruction needed %d valid signature(s) but %d verified", minimum, len(verifiedKeyIDs))
	}
	return strings.Join(verifiedKeyIDs, ","), nil
}

// findKey locates a pinned key that is valid right now.
func (v *Verifier) findKey(keyID string, algorithm int32, now time.Time) ([]byte, bool) {
	for _, pinned := range v.keys {
		if pinned.Algorithm != algorithm {
			continue
		}
		// An empty key ID on the signature means the panel did not say which
		// key it used, so every pinned key of the right algorithm is tried.
		if keyID != "" && pinned.KeyID != keyID {
			continue
		}
		if !pinned.NotBefore.IsZero() && now.Add(maximumClockSkew).Before(pinned.NotBefore) {
			continue
		}
		if pinned.NotAfter != nil && now.Add(-maximumClockSkew).After(*pinned.NotAfter) {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(pinned.Value)
		if err != nil {
			continue
		}
		return raw, true
	}
	return nil, false
}

// checkBinding enforces the replay defenses carried inside the signature.
//
// These are signed fields rather than transport metadata on purpose: a
// signature that did not bind the target and a deadline could be captured and
// replayed against a different host, or against the same host later.
func (v *Verifier) checkBinding(instruction *securityv1.SignedInstruction, now time.Time) error {
	if got := instruction.GetAgentId(); got != v.agentID {
		return fmt.Errorf("the instruction was issued for agent %s, not this one", got)
	}
	if strings.TrimSpace(instruction.GetNonce()) == "" {
		return errors.New("the instruction carries no nonce, so a replay could not be detected")
	}
	expires := timeOrZero(instruction.GetExpiresAt())
	if expires.IsZero() {
		return errors.New("the instruction has no expiry, so a captured copy would stay valid forever")
	}
	if now.Add(-maximumClockSkew).After(expires) {
		return fmt.Errorf("the instruction expired at %s", expires.UTC().Format(time.RFC3339))
	}
	if issued := timeOrZero(instruction.GetIssuedAt()); !issued.IsZero() {
		if issued.After(now.Add(maximumClockSkew)) {
			return errors.New("the instruction is dated in the future")
		}
	}
	return nil
}

func verifyOne(algorithm int32, key, payload, signature []byte) bool {
	switch securityv1.SignatureAlgorithm(algorithm) {
	case securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519:
		if len(key) != ed25519.PublicKeySize {
			return false
		}
		return ed25519.Verify(ed25519.PublicKey(key), payload, signature)
	default:
		// An algorithm this build cannot check never counts as verified. The
		// post-quantum values exist in the protocol before any implementation
		// does, and treating "unrecognized" as "fine" would make adding one to
		// the policy a way to bypass verification entirely.
		return false
	}
}

func describeAlgorithm(algorithm int32) string {
	name := securityv1.SignatureAlgorithm(algorithm).String()
	return strings.TrimPrefix(name, "SIGNATURE_ALGORITHM_")
}

// timeOrZero converts a protobuf timestamp, treating absent and invalid values
// alike. IsValid is checked rather than comparing against nil, because
// AsTime on an absent timestamp yields the Unix epoch instead of a zero time,
// which would read as "set, and very expired" rather than "not set".
func timeOrZero(value *timestamppb.Timestamp) time.Time {
	if !value.IsValid() {
		return time.Time{}
	}
	return value.AsTime()
}
