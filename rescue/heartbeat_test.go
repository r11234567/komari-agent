package rescue

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func heartbeatFixture(t *testing.T) (*hostops.Trust, func(time.Time, uint64) *configv1.PrivilegedRevision) {
	t.Helper()
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust := &hostops.Trust{AgentID: "node", PanelKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "panel", Value: base64.StdEncoding.EncodeToString(public)}}}
	sign := func(at time.Time, seq uint64) *configv1.PrivilegedRevision {
		settings := privileged.Settings{RequiredPrivilegeMode: 2, RescueHelperEnabled: true}
		revision := &configv1.PrivilegedRevision{AgentId: "node", ProtocolVersion: 2, Revision: 1, UpdateSequence: seq, Privileged: settings.Proto(), ConfigHash: privileged.Hash(settings), State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED}
		body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(revision)
		payload, _ := proto.Marshal(&securityv1.SignedInstruction{AgentId: "node", Nonce: at.String(), InstructionType: "komari.config.v2.PrivilegedRevision", IssuedAt: timestamppb.New(at), ExpiresAt: timestamppb.New(at.Add(time.Minute)), Body: body})
		revision.Signature = &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{{Algorithm: 1, KeyId: "panel", Value: ed25519.Sign(key, payload)}}}
		return revision
	}
	return trust, sign
}
func TestRescueHeartbeatRejectsReplayDelayRegressionAndTampering(t *testing.T) {
	trust, sign := heartbeatFixture(t)
	now := time.Now()
	var cursor heartbeatCursor
	first := sign(now, 5)
	if err := cursor.accept(trust, first, now); err != nil {
		t.Fatal(err)
	}
	if !rescueRevisionAllowed(first) {
		t.Fatal("approved rescue denied")
	}
	if err := cursor.accept(trust, first, now); err == nil {
		t.Fatal("replayed heartbeat renewed authorization")
	}
	if err := cursor.accept(trust, sign(now.Add(time.Millisecond), 4), now); err == nil {
		t.Fatal("regressed sequence accepted")
	}
	if err := cursor.accept(trust, sign(now.Add(-3*time.Second), 6), now); err == nil {
		t.Fatal("delayed heartbeat accepted")
	}
	if err := cursor.accept(trust, sign(now.Add(2*time.Second), 6), now); err == nil {
		t.Fatal("future heartbeat accepted")
	}
	tampered := sign(now.Add(time.Millisecond), 6)
	tampered.Privileged.RescueHelperEnabled = false
	if err := cursor.accept(trust, tampered, now); err == nil {
		t.Fatal("tampered binding accepted")
	}
	if err := cursor.accept(trust, sign(now.Add(time.Millisecond), 6), now); err != nil {
		t.Fatal(err)
	}
	first.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_CONFIRMATION
	if rescueRevisionAllowed(first) {
		t.Fatal("pending rescue authorized")
	}
}

type heartbeatPanel struct {
	configconnect.UnimplementedPrivilegedDeliveryServiceHandler
	revision *configv1.PrivilegedRevision
}

func (s *heartbeatPanel) WatchPrivilegedDelivery(ctx context.Context, req *connect.Request[configv1.WatchPrivilegedDeliveryRequest], stream *connect.ServerStream[configv1.WatchPrivilegedDeliveryResponse]) error {
	stream.ResponseHeader().Set(authorizationWatchHeader, "v1")
	return stream.Send(&configv1.WatchPrivilegedDeliveryResponse{Revision: s.revision})
}
func TestRescueReceivesRealSignedStreamAndReportsDisconnect(t *testing.T) {
	trust, sign := heartbeatFixture(t)
	path, handler := configconnect.NewPrivilegedDeliveryServiceHandler(&heartbeatPanel{revision: sign(time.Now(), 1)})
	_ = path
	server := httptest.NewServer(handler)
	defer server.Close()
	client := configconnect.NewPrivilegedDeliveryServiceClient(server.Client(), server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	frames := make(chan authorizationFrame, 2)
	go receiveAuthorization(ctx, client, connect.NewRequest(&configv1.WatchPrivilegedDeliveryRequest{AgentId: "node", ProtocolVersion: 2}), frames)
	select {
	case frame := <-frames:
		var cursor heartbeatCursor
		if frame.err != nil {
			t.Fatal(frame.err)
		}
		if err := cursor.accept(trust, frame.revision, time.Now()); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("real stream did not deliver signed frame")
	}
	select {
	case frame := <-frames:
		if frame.err == nil {
			t.Fatal("clean EOF did not revoke watch")
		}
	case <-ctx.Done():
		t.Fatal("disconnect was not surfaced")
	}
}
