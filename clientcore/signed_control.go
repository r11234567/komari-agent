package clientcore

import (
	"errors"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/signing"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/proto"
)

func (c *Client) verifyAgentControl(envelope *securityv1.SignedEnvelope, expected proto.Message, nonce string, replay *signing.ReplayGuard) error {
	identity, ok := c.identity()
	if !ok || identity.AgentID == "" {
		return errors.New("agent identity is required to verify control instructions")
	}
	verified, err := signing.New(identity, nil).Verify(envelope)
	if err != nil {
		return err
	}
	if verified.InstructionType != string(expected.ProtoReflect().Descriptor().FullName()) {
		return errors.New("signed control instruction has an unexpected type")
	}
	if nonce != "" && verified.Nonce != nonce {
		return errors.New("signed control instruction has an unexpected purpose")
	}
	if verified.IssuedAt.IsZero() || !verified.ExpiresAt.After(verified.IssuedAt) || !time.Now().Before(verified.ExpiresAt) {
		return errors.New("signed control instruction is outside its lease")
	}
	body := expected.ProtoReflect().New().Interface()
	if err := proto.Unmarshal(verified.Body, body); err != nil {
		return err
	}
	if !proto.Equal(body, expected) {
		return errors.New("control instruction does not match the signed parameters")
	}
	if replay != nil {
		return replay.Consume(verified.Nonce, verified.ExpiresAt)
	}
	return nil
}

// Terminal frames are bound to a single attachment and verified in order.
// On resume, the new attachment has its own challenge and frame numbering.
type signedTerminalConnection struct {
	terminalConnection
	client     *Client
	assignment *websshv1.SessionAssignment
	challenge  []byte
	received   uint64
}

func (s *signedTerminalConnection) Receive() (*websshv1.AttachSessionResponse, error) {
	wire, err := s.terminalConnection.Receive()
	if err != nil {
		return nil, err
	}
	if wire == nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("terminal control frame is missing"))
	}
	frame := proto.CloneOf(wire)
	frame.Envelope = nil
	expected := &websshv1.SessionControlFrame{
		SessionId: s.assignment.GetSessionId(), AssignmentId: s.assignment.GetAssignmentId(),
		Frame: frame, Challenge: s.challenge, FrameNumber: s.received + 1,
	}
	if err := s.client.verifyAgentControl(wire.GetEnvelope(), expected, "", nil); err != nil {
		return nil, connect.NewError(connect.CodeUnauthenticated, err)
	}
	s.received++
	return frame, nil
}
