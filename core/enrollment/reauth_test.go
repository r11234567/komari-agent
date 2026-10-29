package enrollment

import (
	"bytes"
	"context"
	"encoding/base64"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	enrollmentconnect "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1/enrollmentv1connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type reauthPanel struct {
	enrollmentconnect.UnimplementedEnrollmentServiceHandler
	begin *enrollmentv1.BeginEnrollmentRequest
}

func (panel *reauthPanel) BeginEnrollment(ctx context.Context, req *connect.Request[enrollmentv1.BeginEnrollmentRequest]) (*connect.Response[enrollmentv1.BeginEnrollmentResponse], error) {
	panel.begin = req.Msg
	return connect.NewResponse(&enrollmentv1.BeginEnrollmentResponse{DeviceCode: "synthetic-device", UserCode: "SYNTHETIC", VerificationUri: "https://unit.invalid/bind", ExpiresAt: timestamppb.New(time.Now().Add(time.Minute)), PollInterval: durationpb.New(2 * time.Second)}), nil
}
func (panel *reauthPanel) PollEnrollment(ctx context.Context, req *connect.Request[enrollmentv1.PollEnrollmentRequest]) (*connect.Response[enrollmentv1.PollEnrollmentResponse], error) {
	return connect.NewResponse(&enrollmentv1.PollEnrollmentResponse{State: enrollmentv1.EnrollmentState_ENROLLMENT_STATE_APPROVED, Credentials: &enrollmentv1.AgentCredentials{AgentId: "existing-node", AccessToken: "synthetic-next-at", RefreshToken: "synthetic-next-rt", AccessTokenExpiresAt: timestamppb.New(time.Now().Add(time.Hour)), RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(7 * 24 * time.Hour))}}), nil
}
func TestCredentialReauthUsesExistingKeyAtEnrollmentBoundary(t *testing.T) {
	public, private, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	panel := &reauthPanel{}
	_, handler := enrollmentconnect.NewEnrollmentServiceHandler(panel)
	server := httptest.NewServer(handler)
	defer server.Close()
	client, err := New(server.URL, server.Client())
	if err != nil {
		t.Fatal(err)
	}
	id := credentials.Identity{Endpoint: server.URL, AgentID: "existing-node", PublicKey: public, PrivateKey: private, KeyID: keyID, RefreshToken: "synthetic-expired-rt", RefreshTokenExpiresAt: time.Now().Add(-time.Hour)}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	next, err := client.Reauth(ctx, id, nil)
	if err != nil {
		t.Fatal(err)
	}
	offered, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		t.Fatal(err)
	}
	if panel.begin == nil || !bytes.Equal(panel.begin.AgentPublicKey.Value, offered) || panel.begin.GetExistingAgentId() != id.AgentID {
		t.Fatal("reauth offered a different public key or machine ID")
	}
	if next.PrivateKey != private || next.PublicKey != public || next.AgentID != id.AgentID || next.RefreshToken == id.RefreshToken {
		t.Fatal("returned credentials and retained machine identity do not match")
	}
}
