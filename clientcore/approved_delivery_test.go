package clientcore

import (
	"connectrpc.com/connect"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

type approvalTestService struct {
	configv1connect.UnimplementedPrivilegedDeliveryServiceHandler
	mu       sync.Mutex
	current  *configv1.PrivilegedRevision
	failACK  bool
	receipts []*configv1.ReportPrivilegedDeliveryRequest
}

func (s *approvalTestService) GetPrivilegedDelivery(context.Context, *connect.Request[configv1.GetPrivilegedDeliveryRequest]) (*connect.Response[configv1.GetPrivilegedDeliveryResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return connect.NewResponse(&configv1.GetPrivilegedDeliveryResponse{Revision: proto.Clone(s.current).(*configv1.PrivilegedRevision)}), nil
}
func (s *approvalTestService) ReportPrivilegedDelivery(_ context.Context, req *connect.Request[configv1.ReportPrivilegedDeliveryRequest]) (*connect.Response[configv1.ReportPrivilegedDeliveryResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.receipts = append(s.receipts, proto.Clone(req.Msg).(*configv1.ReportPrivilegedDeliveryRequest))
	if s.failACK {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("lost ACK transport"))
	}
	return connect.NewResponse(&configv1.ReportPrivilegedDeliveryResponse{Accepted: true}), nil
}
func signApproval(t *testing.T, key ed25519.PrivateKey, r *configv1.PrivilegedRevision) *configv1.PrivilegedRevision {
	t.Helper()
	r = proto.Clone(r).(*configv1.PrivilegedRevision)
	r.Signature = nil
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(r)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := proto.Marshal(&securityv1.SignedInstruction{AgentId: r.AgentId, Nonce: "envelope", InstructionType: "komari.config.v2.PrivilegedRevision", Body: body, IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))})
	if err != nil {
		t.Fatal(err)
	}
	r.Signature = &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{{KeyId: "panel", Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519, Value: ed25519.Sign(key, payload)}}}
	return r
}
func TestApprovedDeliveryUsesCurrentSignaturePolicyAndRetriesExactReceipt(t *testing.T) {
	manifestPath := os.Getenv("KOMARI_TEST_APPROVAL_MANIFEST")
	if manifestPath == "" {
		t.Skip("trusted policy fixture is installed by scripts/ci/test-approved-delivery.sh on disposable CI runner")
	}
	manifest, err := hostops.ReadManifest(manifestPath)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := hostops.ReadPolicy(manifest)
	if err != nil {
		t.Fatal(err)
	}
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	local := privileged.Settings{RequiredPrivilegeMode: capability.Detect(false).PrivilegeMode, RemoteControlEnabled: true, WebSSHEnabled: true}
	hash := privileged.Hash(local)
	r := &configv1.PrivilegedRevision{AgentId: "node", Revision: 2, ProtocolVersion: 2, ApprovalGeneration: 1, UpdateSequence: 2, ConfigHash: hash, Privileged: local.Proto(), State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_AWAITING_AGENT, ReceivedAt: timestamppb.Now(), Authorization: &hostv1.HostAuthorization{AgentId: "node", Revision: 2, ConfigHash: hash, ApprovalGeneration: 1, ServiceId: manifest.ServiceName, TargetPrivilegeMode: local.RequiredPrivilegeMode, Nonce: "approval-nonce", ApprovedBy: "operator", IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}}
	r = signApproval(t, key, r)
	service := &approvalTestService{current: r, failACK: true}
	mux := http.NewServeMux()
	p, h := configv1connect.NewPrivilegedDeliveryServiceHandler(service)
	mux.Handle(p, h)
	server := httptest.NewServer(mux)
	defer server.Close()
	dir := t.TempDir()
	identity, err := credentials.Open(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = identity.Save(credentials.Identity{AgentID: "node", ControlPlaneKeys: []credentials.PinnedKey{{KeyID: "panel", Algorithm: 1, Value: base64.StdEncoding.EncodeToString(pub)}}}); err != nil {
		t.Fatal(err)
	}
	runtime, err := runtimeconfig.New(runtimeconfig.FromFlags(&flags_pkg.Config{}), filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	store, err := privileged.Open(filepath.Join(dir, "privileged.json"))
	if err != nil {
		t.Fatal(err)
	}
	c := &Client{agentID: "node", startupID: "boot", store: runtime, privilegedStore: store, credentialStore: identity, hostManifest: manifest, hostPolicy: policy, privileged: configv1connect.NewPrivilegedDeliveryServiceClient(server.Client(), server.URL)}
	oldPriv := privileged.ActiveStore()
	privileged.SetActive(store)
	defer privileged.SetActive(oldPriv)
	oldFlags := *flags_pkg.GlobalConfig
	defer func() { *flags_pkg.GlobalConfig = oldFlags }()
	flags_pkg.GlobalConfig.ServiceManifestFile = manifestPath
	// Reception before 2FA cannot apply anything, even though settings are signed.
	unconfirmed := proto.Clone(r).(*configv1.PrivilegedRevision)
	unconfirmed.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_CONFIRMATION
	unconfirmed.Authorization = nil
	unconfirmed.ApprovalGeneration = 0
	unconfirmed.UpdateSequence = 1
	if err = c.recordPrivilegedRevision(context.Background(), signApproval(t, key, unconfirmed)); err != nil {
		t.Fatal(err)
	}
	if store.State().AppliedRevision != 0 {
		t.Fatal("receiving an unconfirmed target granted capabilities")
	}
	// Full-body signature protects flags and approval fields.
	tampered := proto.Clone(r).(*configv1.PrivilegedRevision)
	tampered.Authorization.ApprovalGeneration++
	if err = c.recordPrivilegedRevision(context.Background(), tampered); err == nil {
		t.Fatal("tampered signed authorization accepted")
	}
	if err = c.recordPrivilegedRevision(context.Background(), r); err == nil {
		t.Fatal("fixture must lose ACK after applying")
	}
	if store.State().AppliedRevision != 2 || !store.Effective().WebSSHEnabled || store.Effective().ExecutionEnabled {
		t.Fatal("approved per-capability snapshot was not applied")
	}
	if ok, _ := capability.WebSSHAllowed(); !ok {
		t.Fatal("same-identity non-root WebSSH was blocked")
	}
	if ok, _ := capability.ExecutionAllowed(); ok {
		t.Fatal("execution=false was ignored at final gate")
	}
	reopened, err := privileged.Open(store.Path())
	if err != nil {
		t.Fatal(err)
	}
	pending := reopened.State().Outbox
	if len(pending) != 1 {
		t.Fatalf("missing durable ACK: %+v", pending)
	}
	c.privilegedStore = reopened
	privileged.SetActive(reopened)
	c.startupID = "after-restart"
	service.mu.Lock()
	service.failACK = false
	service.mu.Unlock()
	if err = c.flushReceipts(context.Background()); err != nil {
		t.Fatal(err)
	}
	service.mu.Lock()
	receipts := service.receipts
	service.mu.Unlock()
	if len(receipts) != 2 || !proto.Equal(receipts[0], receipts[1]) || receipts[0].ReceiptId != pending[0].ID {
		t.Fatal("ACK retry changed observation, payload or receipt ID")
	}
	if len(reopened.State().Outbox) != 0 {
		t.Fatal("successful retry was not removed")
	}
	// Another installation with no local active state cannot revive an old
	// signed approval after the authoritative target changed online.
	newer := proto.Clone(r).(*configv1.PrivilegedRevision)
	newer.Revision = 3
	newer.Authorization.Revision = 3
	newer.UpdateSequence = 3
	newer = signApproval(t, key, newer)
	service.mu.Lock()
	service.current = newer
	service.mu.Unlock()
	c.privilegedStore, err = privileged.Open(filepath.Join(dir, "other.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = c.recordPrivilegedRevision(context.Background(), r); err == nil {
		t.Fatal("superseded but unexpired approval accepted")
	}
	if c.privilegedStore.State().AppliedRevision != 0 {
		t.Fatal("captured approval was revived")
	}
	// A separate root-owned force-deny is stronger than the approved snapshot.
	flags_pkg.GlobalConfig.ServiceManifestFile = os.Getenv("KOMARI_TEST_DENY_MANIFEST")
	if flags_pkg.GlobalConfig.ServiceManifestFile == "" {
		t.Fatal("missing force-deny fixture")
	}
	if ok, _ := capability.WebSSHAllowed(); ok || runtimeconfig.Effective().BlockedReason == "" {
		t.Fatal("protected force-deny did not override approved grant")
	}
	// Replacing the protected policy with an unreadable location fails closed.
	flags_pkg.GlobalConfig.ServiceManifestFile = filepath.Join(dir, "missing.json")
	if ok, _ := capability.WebSSHAllowed(); ok || runtimeconfig.Current().EnableGPU {
		t.Fatal("missing protected policy did not fail closed")
	}
}
