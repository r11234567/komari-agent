package signing

import (
	"errors"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
)

// VerifyRecorded authenticates historical local state without renewing any
// approval. Callers may only validate an already persisted snapshot with it;
// new grants always require Verify plus an online currentness check.
func (v *Verifier) VerifyRecorded(envelope *securityv1.SignedEnvelope) (Instruction, error) {
	if envelope == nil {
		return Instruction{}, errors.New("missing recorded signature")
	}
	var payload securityv1.SignedInstruction
	if err := proto.Unmarshal(envelope.Payload, &payload); err != nil {
		return Instruction{}, err
	}
	if payload.IssuedAt == nil || payload.IssuedAt.CheckValid() != nil {
		return Instruction{}, errors.New("recorded signature has no valid issuance time")
	}
	copy := *v
	copy.replay = nil
	copy.nowFunc = payload.IssuedAt.AsTime
	return copy.Verify(envelope)
}
