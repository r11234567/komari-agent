package clientcore

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/signing"
	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
	networkv1 "github.com/r11234567/komari-proto/gen/go/komari/network/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func controlSigningFixture(t *testing.T) (*Client, func(proto.Message, string) *securityv1.SignedEnvelope) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	store, err := credentials.Open(filepath.Join(dir, "identity.json"))
	if err != nil {
		t.Fatal(err)
	}
	const agent, keyID = "test-agent", "test-panel"
	algorithm := securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519
	if err := store.Save(credentials.Identity{AgentID: agent, ControlPlaneKeys: []credentials.PinnedKey{
		{KeyID: keyID, Value: base64.StdEncoding.EncodeToString(public), Algorithm: int32(algorithm)},
	}}); err != nil {
		t.Fatal(err)
	}
	seal := func(message proto.Message, nonce string) *securityv1.SignedEnvelope {
		t.Helper()
		body, err := proto.Marshal(message)
		if err != nil {
			t.Fatal(err)
		}
		payload, err := proto.Marshal(&securityv1.SignedInstruction{
			AgentId: agent, Nonce: nonce, IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)),
			InstructionType: string(message.ProtoReflect().Descriptor().FullName()), Body: body,
		})
		if err != nil {
			t.Fatal(err)
		}
		return &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{
			{KeyId: keyID, Algorithm: algorithm, Value: ed25519.Sign(private, payload)},
		}}
	}
	return &Client{credentialStore: store, replayGuard: signing.NewReplayGuard(filepath.Join(dir, "nonces.json"))}, seal
}

func TestControlRejectsUnsignedTerminalAndChangedFileLeaseBeforeDispatch(t *testing.T) {
	client, seal := controlSigningFixture(t)
	// Both dispatchers require a configured transport after verification.
	// Leaving it absent also checks that rejection never enters dispatch.
	terminal := &websshv1.SessionAssignment{LeaseExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}
	if err := client.attachRemoteSession(context.Background(), terminal); err == nil || !strings.Contains(err.Error(), "verify terminal assignment") {
		t.Fatalf("unsigned terminal lease did not fail at verification: %v", err)
	}
	file := &filev1.FileAssignment{AssignmentId: "assignment", RequestId: "original"}
	file.Envelope = seal(file, "file:lease:assignment")
	file.RequestId = "different"
	if err := client.attachFileOperation(context.Background(), file, nil); err == nil || !strings.Contains(err.Error(), "verify file lease") {
		t.Fatalf("changed file lease did not fail at verification: %v", err)
	}
}

func TestControlProbeBindingAndPersistentReplay(t *testing.T) {
	client, seal := controlSigningFixture(t)
	probe := &networkv1.PingProbeAssignment{AssignmentId: "probe", Target: "probe.example"}
	envelope := seal(probe, "probe-nonce")
	changed := proto.CloneOf(probe)
	changed.Target = "different.example"
	if err := client.verifyAgentControl(envelope, changed, "", client.replayGuard); err == nil {
		t.Fatal("changed probe accepted")
	}
	if err := client.verifyAgentControl(envelope, probe, "", client.replayGuard); err != nil {
		t.Fatalf("unchanged probe rejected: %v", err)
	}
	if err := client.verifyAgentControl(envelope, probe, "", client.replayGuard); err == nil {
		t.Fatal("used probe accepted twice")
	}
}

func TestSignedTerminalFramesBindChallengeAndSequence(t *testing.T) {
	client, seal := controlSigningFixture(t)
	challenge := []byte("test-attachment")
	assignment := &websshv1.SessionAssignment{SessionId: "session", AssignmentId: "assignment"}
	frames := make(chan *websshv1.AttachSessionResponse, 3)
	transport := &resumeConnection{ctx: context.Background(), frames: frames}
	stream := &signedTerminalConnection{terminalConnection: transport, client: client, assignment: assignment, challenge: challenge}
	makeFrame := func(number uint64, challenge []byte) *websshv1.AttachSessionResponse {
		frame := &websshv1.AttachSessionResponse{AcceptedEventSequence: 1}
		frame.Envelope = seal(&websshv1.SessionControlFrame{
			SessionId: assignment.SessionId, AssignmentId: assignment.AssignmentId,
			Frame: frame, Challenge: challenge, FrameNumber: number,
		}, "terminal-frame")
		return frame
	}
	frames <- makeFrame(1, challenge)
	frames <- makeFrame(1, challenge)
	frames <- makeFrame(2, []byte("other-attachment"))
	if frame, err := stream.Receive(); err != nil || frame.GetAcceptedEventSequence() != 1 {
		t.Fatalf("first frame rejected: %v", err)
	}
	for _, label := range []string{"repeated sequence", "wrong challenge"} {
		if frame, err := stream.Receive(); frame != nil || connect.CodeOf(err) != connect.CodeUnauthenticated {
			t.Fatalf("%s reached downstream: %v, %v", label, frame, err)
		}
	}
}
