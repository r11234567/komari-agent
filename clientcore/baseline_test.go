package clientcore

import (
	"connectrpc.com/connect"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/host/v1/hostv1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

type baselineTestService struct {
	configv1connect.UnimplementedConfigServiceHandler
	configv1connect.UnimplementedPrivilegedDeliveryServiceHandler
	hostv1connect.UnimplementedHostServiceHandler
	key      ed25519.PrivateKey
	fail     atomic.Bool
	requests atomic.Int32
	receipts atomic.Int32
	first    *configv1.InitializeNodeConfigRequest
	t        *testing.T
}

func (s *baselineTestService) NegotiateHostProtocol(context.Context, *connect.Request[hostv1.NegotiateHostProtocolRequest]) (*connect.Response[hostv1.NegotiateHostProtocolResponse], error) {
	return connect.NewResponse(&hostv1.NegotiateHostProtocolResponse{ProtocolVersion: 2}), nil
}
func (s *baselineTestService) InitializeNodeConfig(_ context.Context, req *connect.Request[configv1.InitializeNodeConfigRequest]) (*connect.Response[configv1.InitializeNodeConfigResponse], error) {
	s.requests.Add(1)
	if s.first == nil {
		s.first = proto.Clone(req.Msg).(*configv1.InitializeNodeConfigRequest)
	} else if !proto.Equal(s.first, req.Msg) {
		s.t.Error("baseline retry request changed after local revision advanced")
	}
	p := req.Msg.Privileged
	hash := privileged.Hash(privileged.SettingsFromProto(p))
	r := &configv1.PrivilegedRevision{AgentId: req.Msg.AgentId, Revision: 1, ProtocolVersion: 2, InstallationBaseline: true, ApprovalGeneration: 1, ConfigHash: hash, Privileged: p, State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_AWAITING_AGENT, Authorization: &hostv1.HostAuthorization{AgentId: req.Msg.AgentId, Revision: 1, ConfigHash: hash, ApprovalGeneration: 1, ServiceId: req.Msg.ServiceId, TargetPrivilegeMode: p.RequiredPrivilegeMode}}
	body, _ := proto.MarshalOptions{Deterministic: true}.Marshal(r)
	payload, _ := proto.Marshal(&securityv1.SignedInstruction{AgentId: r.AgentId, Nonce: "fresh-envelope", InstructionType: "komari.config.v2.PrivilegedRevision", Body: body, IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))})
	r.Signature = &securityv1.SignedEnvelope{Payload: payload, Signatures: []*securityv1.Signature{{KeyId: "panel", Algorithm: securityv1.SignatureAlgorithm_SIGNATURE_ALGORITHM_ED25519, Value: ed25519.Sign(s.key, payload)}}}
	return connect.NewResponse(&configv1.InitializeNodeConfigResponse{Initialized: true, Runtime: &configv1.DesiredConfig{AgentId: r.AgentId, Revision: 1, Runtime: req.Msg.Runtime}, Privileged: r}), nil
}
func (s *baselineTestService) AcknowledgeConfig(context.Context, *connect.Request[configv1.AcknowledgeConfigRequest]) (*connect.Response[configv1.AcknowledgeConfigResponse], error) {
	if s.fail.Load() {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}
	return connect.NewResponse(&configv1.AcknowledgeConfigResponse{Accepted: true}), nil
}
func (s *baselineTestService) ReportPrivilegedDelivery(_ context.Context, req *connect.Request[configv1.ReportPrivilegedDeliveryRequest]) (*connect.Response[configv1.ReportPrivilegedDeliveryResponse], error) {
	if s.fail.Load() {
		return nil, connect.NewError(connect.CodeUnavailable, nil)
	}
	if req.Msg.Observation == nil || req.Msg.ReceiptId == "" {
		s.t.Error("ACK lacks durable receipt or daemon observation")
	}
	s.receipts.Add(1)
	return connect.NewResponse(&configv1.ReportPrivilegedDeliveryResponse{Accepted: true}), nil
}
func TestBaselineACKRetriesAfterLocalLoadAndReconnect(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	service := &baselineTestService{key: key, t: t}
	service.fail.Store(true)
	mux := http.NewServeMux()
	p, h := configv1connect.NewConfigServiceHandler(service)
	mux.Handle(p, h)
	p, h = configv1connect.NewPrivilegedDeliveryServiceHandler(service)
	mux.Handle(p, h)
	p, h = hostv1connect.NewHostServiceHandler(service)
	mux.Handle(p, h)
	server := httptest.NewServer(mux)
	defer server.Close()
	dir := t.TempDir()
	identity, err := credentials.Open(filepath.Join(dir, "credentials.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err = identity.Save(credentials.Identity{AgentID: "new-node", ControlPlaneKeys: []credentials.PinnedKey{{KeyID: "panel", Algorithm: 1, Value: base64.StdEncoding.EncodeToString(pub)}}}); err != nil {
		t.Fatal(err)
	}
	store, err := runtimeconfig.New(runtimeconfig.FromFlags(&flags_pkg.Config{}), filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	priv, err := privileged.Open(filepath.Join(dir, "privileged.json"))
	if err != nil {
		t.Fatal(err)
	}
	policy := &hostops.Policy{Version: 2, ServiceID: "custom", PrivilegeMode: int32(capability.Detect(false).PrivilegeMode)}
	policyPath := filepath.Join(dir, "policy.json")
	if err = hostops.WriteJSON(policyPath, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	c := &Client{agentID: "new-node", startupID: "boot-1", store: store, privilegedStore: priv, credentialStore: identity, hostPolicy: policy, hostManifest: &hostops.Manifest{ServiceName: "custom", HostPolicyFile: policyPath}, config: configv1connect.NewConfigServiceClient(server.Client(), server.URL), privileged: configv1connect.NewPrivilegedDeliveryServiceClient(server.Client(), server.URL), host: hostv1connect.NewHostServiceClient(server.Client(), server.URL)}
	if err = c.initializeHost(context.Background()); err == nil {
		t.Fatal("fixture must lose ACK transport")
	}
	if store.Current().Revision != 1 || priv.State().AppliedRevision != 1 || len(priv.State().Outbox) == 0 {
		t.Fatal("local snapshot and ACK were not persisted before sending")
	}
	c.privilegedStore, err = privileged.Open(priv.Path())
	if err != nil {
		t.Fatal(err)
	}
	c.startupID = "boot-2"
	service.fail.Store(false)
	if err = c.initializeHost(context.Background()); err != nil {
		t.Fatal(err)
	}
	if service.requests.Load() != 2 || service.receipts.Load() != 1 || len(c.privilegedStore.State().Outbox) != 0 {
		t.Fatal("baseline retry duplicated revisions or lost pending receipt")
	}
}
