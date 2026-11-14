package cmd

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	enrollmentv1 "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1"
	enrollmentconnect "github.com/r11234567/komari-proto/gen/go/komari/enrollment/v1/enrollmentv1connect"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type reauthCLITestPanel struct {
	enrollmentconnect.UnimplementedEnrollmentServiceHandler
	refreshCalls int
	beginReq     *enrollmentv1.BeginEnrollmentRequest
}

func (p *reauthCLITestPanel) RefreshCredentials(ctx context.Context, req *connect.Request[enrollmentv1.RefreshCredentialsRequest]) (*connect.Response[enrollmentv1.RefreshCredentialsResponse], error) {
	p.refreshCalls++
	return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("refresh token revoked"))
}

func (p *reauthCLITestPanel) BeginEnrollment(ctx context.Context, req *connect.Request[enrollmentv1.BeginEnrollmentRequest]) (*connect.Response[enrollmentv1.BeginEnrollmentResponse], error) {
	p.beginReq = req.Msg
	return connect.NewResponse(&enrollmentv1.BeginEnrollmentResponse{
		DeviceCode:      "synthetic-device-code",
		UserCode:        "SYNTH-CODE",
		VerificationUri: "https://panel.invalid/bind",
		ExpiresAt:       timestamppb.New(time.Now().Add(time.Minute)),
		PollInterval:    durationpb.New(2 * time.Second),
	}), nil
}

func (p *reauthCLITestPanel) PollEnrollment(ctx context.Context, req *connect.Request[enrollmentv1.PollEnrollmentRequest]) (*connect.Response[enrollmentv1.PollEnrollmentResponse], error) {
	return connect.NewResponse(&enrollmentv1.PollEnrollmentResponse{
		State: enrollmentv1.EnrollmentState_ENROLLMENT_STATE_APPROVED,
		Credentials: &enrollmentv1.AgentCredentials{
			AgentId:               "existing-agent-1",
			AccessToken:           "synthetic-reauthed-at",
			RefreshToken:          "synthetic-reauthed-rt",
			AccessTokenExpiresAt:  timestamppb.New(time.Now().Add(time.Hour)),
			RefreshTokenExpiresAt: timestamppb.New(time.Now().Add(30 * 24 * time.Hour)),
		},
	}), nil
}

func TestReauthProceedsWhenRefreshRejectedBeforeLocalExpiry(t *testing.T) {
	oldFlags := *flags
	t.Cleanup(func() {
		*flags = oldFlags
		reauthCmd.SetOut(nil)
		reauthCmd.SetContext(context.Background())
		refreshCmd.SetContext(context.Background())
	})

	public, private, keyID, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	panel := &reauthCLITestPanel{}
	_, handler := enrollmentconnect.NewEnrollmentServiceHandler(panel)
	server := httptest.NewServer(handler)
	defer server.Close()

	credPath := filepath.Join(t.TempDir(), "credentials.json")
	store, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}
	pinned := []credentials.PinnedKey{{Algorithm: 1, KeyID: "panel-key-1", Value: base64.StdEncoding.EncodeToString([]byte("synthetic-panel-key"))}}
	err = store.Save(credentials.Identity{
		Endpoint:              server.URL,
		AgentID:               "existing-agent-1",
		PublicKey:             public,
		PrivateKey:            private,
		KeyID:                 keyID,
		AccessToken:           "synthetic-rejected-at",
		RefreshToken:          "synthetic-rejected-rt",
		AccessTokenExpiresAt:  time.Now().Add(-time.Minute),
		RefreshTokenExpiresAt: time.Now().Add(30 * 24 * time.Hour),
		ControlPlaneKeys:      pinned,
	})
	if err != nil {
		t.Fatal(err)
	}

	flags.CredentialsFile = credPath
	flags.PreferIPVersion = ""

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	refreshCmd.SetContext(ctx)
	if err := refreshCmd.RunE(refreshCmd, nil); err == nil {
		t.Fatal("expected refresh to fail when panel rejects refresh token")
	}
	if panel.refreshCalls != 1 {
		t.Fatalf("refreshCalls = %d, want 1", panel.refreshCalls)
	}

	var output bytes.Buffer
	reauthCmd.SetOut(&output)
	reauthCmd.SetContext(ctx)
	if err := reauthCmd.RunE(reauthCmd, nil); err != nil {
		t.Fatalf("reauth failed when local refresh token was unexpired but rejected: %v", err)
	}

	if panel.beginReq == nil {
		t.Fatal("reauth exited locally without contacting panel BeginEnrollment")
	}
	if panel.beginReq.GetExistingAgentId() != "existing-agent-1" {
		t.Fatalf("ExistingAgentId = %q, want %q", panel.beginReq.GetExistingAgentId(), "existing-agent-1")
	}
	offered, err := base64.StdEncoding.DecodeString(public)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(panel.beginReq.GetAgentPublicKey().GetValue(), offered) {
		t.Fatal("reauth did not preserve existing public key")
	}

	reloaded, err := credentials.Open(credPath)
	if err != nil {
		t.Fatal(err)
	}
	saved, ok := reloaded.Identity()
	if !ok {
		t.Fatal("missing persisted identity after reauth")
	}
	if saved.AccessToken != "synthetic-reauthed-at" || saved.RefreshToken != "synthetic-reauthed-rt" {
		t.Fatalf("unexpected credentials after reauth: access=%q refresh=%q", saved.AccessToken, saved.RefreshToken)
	}
	if saved.PendingRefresh != nil {
		t.Fatal("expected PendingRefresh to be cleared after reauth")
	}
	if saved.PrivateKey != private || len(saved.ControlPlaneKeys) != 1 || saved.ControlPlaneKeys[0].KeyID != "panel-key-1" {
		t.Fatal("reauth did not preserve existing keypair and pinned trust bundle")
	}
	if !strings.Contains(output.String(), "Re-authenticated as agent existing-agent-1") {
		t.Fatalf("unexpected reauth output: %s", output.String())
	}
}

func TestReauthRequiresEnrolledIdentity(t *testing.T) {
	oldFlags := *flags
	t.Cleanup(func() {
		*flags = oldFlags
		reauthCmd.SetContext(context.Background())
	})

	dir := t.TempDir()
	flags.CredentialsFile = filepath.Join(dir, "missing.json")
	reauthCmd.SetContext(context.Background())
	if err := reauthCmd.RunE(reauthCmd, nil); err == nil {
		t.Fatal("expected error when credentials file does not exist")
	}

	emptyPath := filepath.Join(dir, "empty-agent.json")
	store, err := credentials.Open(emptyPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Save(credentials.Identity{Endpoint: "https://panel.invalid"}); err != nil {
		t.Fatal(err)
	}
	flags.CredentialsFile = emptyPath
	if err := reauthCmd.RunE(reauthCmd, nil); err == nil {
		t.Fatal("expected error when AgentID is empty")
	}
}
