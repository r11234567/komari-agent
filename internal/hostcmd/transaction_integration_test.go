//go:build linux

package hostcmd

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creack/pty"
	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	hostconnect "github.com/r11234567/komari-proto/gen/go/komari/host/v1/hostv1connect"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	metricsconnect "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1/metricsv1connect"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	reportconnect "github.com/r11234567/komari-proto/gen/go/komari/report/v1/reportv1connect"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
	rescueconnect "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1/rescuev1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Only the panel is a fixture. Binaries, PAM, service restarts, UID/caps/NNP,
// root-owned paths, helper heartbeats and daemon ACKs are the actual code.
type hostTestPanel struct {
	configconnect.UnimplementedConfigServiceHandler
	configconnect.UnimplementedPrivilegedDeliveryServiceHandler
	hostconnect.UnimplementedHostServiceHandler
	metricsconnect.UnimplementedMetricsServiceHandler
	reportconnect.UnimplementedAgentReportServiceHandler
	rescueconnect.UnimplementedRescueServiceHandler
	negotiatedActions []hostv1.HostAction
	mu                sync.Mutex
	key               ed25519.PrivateKey
	current           *configv1.PrivilegedRevision
	op                *hostv1.HostOperation
	startup           string
	prior             string
	mode              reportv1.PrivilegeMode
	installed         bool
	observations      []*hostv1.DaemonObservation
	receipts          map[string][]byte
	failLocalACK      bool
	loseDaemonACK     bool
	hideCompletedRead bool
	interruptProfile  chan struct{}
}

func (s *hostTestPanel) sign(kind, nonce string, message proto.Message) *securityv1.SignedEnvelope {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(message)
	p, _ := proto.Marshal(&securityv1.SignedInstruction{AgentId: "stage6-node", InstructionType: kind, Nonce: nonce, Body: b, IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(10 * time.Minute))})
	return &securityv1.SignedEnvelope{Payload: p, Signatures: []*securityv1.Signature{{KeyId: "stage6", Algorithm: 1, Value: ed25519.Sign(s.key, p)}}}
}
func (s *hostTestPanel) revision() *configv1.PrivilegedRevision {
	r := proto.Clone(s.current).(*configv1.PrivilegedRevision)
	r.Signature = nil
	r.Signature = s.sign("komari.config.v2.PrivilegedRevision", "revision", r)
	return r
}
func (s *hostTestPanel) operation() *hostv1.HostOperation {
	o := proto.Clone(s.op).(*hostv1.HostOperation)
	o.Signature = nil
	o.Signature = s.sign("komari.host.v1.HostOperation", o.OperationId, o)
	return o
}
func (s *hostTestPanel) set(service string, mode reportv1.PrivilegeMode, helper bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rev := uint64(2)
	if s.current != nil {
		rev = s.current.Revision + 1
	}
	settings := privileged.Settings{RequiredPrivilegeMode: mode, RescueHelperEnabled: helper}
	var actions []hostv1.HostAction
	if s.mode != mode {
		actions = append(actions, 1)
	}
	if helper && !s.installed {
		actions = append(actions, 2)
	}
	if !helper && s.installed {
		actions = append(actions, 3)
	}
	hash := privileged.Hash(settings)
	s.current = &configv1.PrivilegedRevision{AgentId: "stage6-node", Revision: rev, ProtocolVersion: 2, ApprovalGeneration: 1, UpdateSequence: rev * 10, ReceivedAt: timestamppb.Now(), ConfigHash: hash, Privileged: settings.Proto(), State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_MANUAL_AUTHORIZATION, Authorization: &hostv1.HostAuthorization{AgentId: "stage6-node", Revision: rev, ApprovalGeneration: 1, ConfigHash: hash, ServiceId: service, TargetPrivilegeMode: mode, Actions: actions, Nonce: "nonce-" + strconv.Itoa(int(rev)), ApprovedBy: "ci-2fa-operator", IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(5 * time.Minute))}}
	s.op = nil
}
func (s *hostTestPanel) GetDesiredConfig(context.Context, *connect.Request[configv1.GetDesiredConfigRequest]) (*connect.Response[configv1.GetDesiredConfigResponse], error) {
	return connect.NewResponse(&configv1.GetDesiredConfigResponse{}), nil
}
func (s *hostTestPanel) SubmitReport(context.Context, *connect.Request[reportv1.SubmitReportRequest]) (*connect.Response[reportv1.SubmitReportResponse], error) {
	return connect.NewResponse(&reportv1.SubmitReportResponse{Accepted: true}), nil
}
func (s *hostTestPanel) SubmitMetrics(_ context.Context, r *connect.Request[metricsv1.SubmitMetricsRequest]) (*connect.Response[metricsv1.SubmitMetricsResponse], error) {
	return connect.NewResponse(&metricsv1.SubmitMetricsResponse{AcceptedSequence: r.Msg.Sequence, AcceptedPoints: uint32(len(r.Msg.Points))}), nil
}
func (s *hostTestPanel) NegotiateHostProtocol(_ context.Context, r *connect.Request[hostv1.NegotiateHostProtocolRequest]) (*connect.Response[hostv1.NegotiateHostProtocolResponse], error) {
	s.mu.Lock()
	s.negotiatedActions = append([]hostv1.HostAction(nil), r.Msg.SupportedActions...)
	defer s.mu.Unlock()
	s.startup = r.Msg.StartupId
	// Restored daemons negotiate their real identity even when the preceding
	// target's final ACK was accepted. Do not keep that target's stale mode.
	s.mode = r.Msg.PrivilegeMode
	return connect.NewResponse(&hostv1.NegotiateHostProtocolResponse{ProtocolVersion: 2}), nil
}
func (s *hostTestPanel) GetPrivilegedDelivery(context.Context, *connect.Request[configv1.GetPrivilegedDeliveryRequest]) (*connect.Response[configv1.GetPrivilegedDeliveryResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.hideCompletedRead && s.current.State == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("fixture completed-read outage"))
	}
	return connect.NewResponse(&configv1.GetPrivilegedDeliveryResponse{Revision: s.revision()}), nil
}
func (s *hostTestPanel) WatchPrivilegedDelivery(ctx context.Context, r *connect.Request[configv1.WatchPrivilegedDeliveryRequest], stream *connect.ServerStream[configv1.WatchPrivilegedDeliveryResponse]) error {
	seq := r.Msg.AfterSequence
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			s.mu.Lock()
			current := s.revision()
			s.mu.Unlock()
			if current.UpdateSequence > seq {
				if err := stream.Send(&configv1.WatchPrivilegedDeliveryResponse{Revision: current, UpdateSequence: current.UpdateSequence}); err != nil {
					return err
				}
				seq = current.UpdateSequence
			}
		}
	}
}
func (s *hostTestPanel) PrepareHostOperation(_ context.Context, r *connect.Request[hostv1.PrepareHostOperationRequest]) (*connect.Response[hostv1.PrepareHostOperationResponse], error) {
	if r.Header().Get("CF-Access-Client-Id") != "ci-access-id" || r.Header().Get("CF-Access-Client-Secret") != "ci-access-value" {
		return nil, connect.NewError(connect.CodeUnauthenticated, errors.New("host transport lost Access configuration"))
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a := s.current.Authorization
	if r.Msg.Revision != a.Revision || r.Msg.Nonce != a.Nonce || r.Msg.ConfigHash != a.ConfigHash || r.Msg.ApprovalGeneration != a.ApprovalGeneration {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("fixture binding rejected"))
	}
	if s.op != nil {
		return connect.NewResponse(&hostv1.PrepareHostOperationResponse{Operation: s.operation()}), nil
	}
	s.prior = s.startup
	s.op = &hostv1.HostOperation{OperationId: r.Msg.OperationId, Authorization: a, Phase: 1, LeaseExpiresAt: a.ExpiresAt}
	s.current.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_APPLYING
	s.current.UpdateSequence++
	return connect.NewResponse(&hostv1.PrepareHostOperationResponse{Operation: s.operation()}), nil
}
func (s *hostTestPanel) GetHostOperation(ctx context.Context, r *connect.Request[hostv1.GetHostOperationRequest]) (*connect.Response[hostv1.GetHostOperationResponse], error) {
	s.mu.Lock()
	gate := s.interruptProfile
	s.mu.Unlock()
	if gate != nil {
		select {
		case gate <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.op == nil || s.op.OperationId != r.Msg.OperationId {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no operation"))
	}
	return connect.NewResponse(&hostv1.GetHostOperationResponse{Operation: s.operation()}), nil
}
func (s *hostTestPanel) ReportHostOperation(_ context.Context, r *connect.Request[hostv1.ReportHostOperationRequest]) (*connect.Response[hostv1.ReportHostOperationResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.op == nil || s.op.OperationId != r.Msg.OperationId {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("no operation"))
	}
	b, _ := proto.Marshal(r.Msg)
	if prior, ok := s.receipts[r.Msg.ReceiptId]; ok {
		if string(prior) != string(b) {
			return nil, errors.New("receipt changed")
		}
		return connect.NewResponse(&hostv1.ReportHostOperationResponse{Accepted: true, Operation: s.operation()}), nil
	}
	if s.failLocalACK && r.Msg.Phase == 3 {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("fixture network outage"))
	}
	// Match production: only an identical receipt may retry a terminal phase.
	if s.op.Phase >= 4 {
		return nil, connect.NewError(connect.CodeFailedPrecondition, errors.New("illegal host operation transition"))
	}
	if r.Msg.Phase < s.op.Phase || r.Msg.LocalAuthentication == "" || r.Msg.Operator == "" {
		return nil, errors.New("phase/auth missing")
	}
	s.receipts[r.Msg.ReceiptId] = b
	s.op.Phase = r.Msg.Phase
	s.current.UpdateSequence++
	if r.Msg.Phase >= 4 {
		s.current.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_FAILED
	}
	return connect.NewResponse(&hostv1.ReportHostOperationResponse{Accepted: true, Operation: s.operation()}), nil
}
func (s *hostTestPanel) ReportPrivilegedDelivery(_ context.Context, r *connect.Request[configv1.ReportPrivilegedDeliveryRequest]) (*connect.Response[configv1.ReportPrivilegedDeliveryResponse], error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if r.Msg.Observation == nil {
		return connect.NewResponse(&configv1.ReportPrivilegedDeliveryResponse{Accepted: true}), nil
	}
	encoded, err := proto.Marshal(r.Msg)
	if err != nil {
		return nil, err
	}
	if previous, exists := s.receipts[r.Msg.ReceiptId]; exists {
		if string(previous) != string(encoded) {
			return nil, errors.New("daemon receipt changed")
		}
		if s.loseDaemonACK {
			return nil, connect.NewError(connect.CodeUnavailable, errors.New("fixture lost daemon ACK response"))
		}
		return connect.NewResponse(&configv1.ReportPrivilegedDeliveryResponse{Accepted: true}), nil
	}
	o := r.Msg.Observation
	if s.op == nil || s.op.Phase != 3 || o.OperationId != s.op.OperationId || o.ConfigHash != s.current.ConfigHash || o.PrivilegeMode != s.current.Privileged.RequiredPrivilegeMode || o.StartupId == s.prior {
		return nil, errors.New("daemon did not independently confirm restarted operation")
	}
	s.observations = append(s.observations, proto.Clone(o).(*hostv1.DaemonObservation))
	s.mode = o.PrivilegeMode
	s.installed = o.HelperInstalled
	s.current.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED
	s.current.UpdateSequence++
	s.receipts[r.Msg.ReceiptId] = encoded
	if s.loseDaemonACK {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("fixture lost daemon ACK response"))
	}
	return connect.NewResponse(&configv1.ReportPrivilegedDeliveryResponse{Accepted: true}), nil
}
func (s *hostTestPanel) ReportRescueStatus(context.Context, *connect.Request[rescuev1.ReportRescueStatusRequest]) (*connect.Response[rescuev1.ReportRescueStatusResponse], error) {
	return connect.NewResponse(&rescuev1.ReportRescueStatusResponse{Accepted: true}), nil
}
func (s *hostTestPanel) LeaseRescueSessions(ctx context.Context, _ *connect.Request[rescuev1.LeaseRescueSessionsRequest], stream *connect.ServerStream[rescuev1.LeaseRescueSessionsResponse]) error {
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-time.After(time.Second):
		return stream.Send(&rescuev1.LeaseRescueSessionsResponse{})
	}
}

func TestHostSystemdTransactionAcceptance(t *testing.T) {
	if os.Getenv("KOMARI_STAGE6_ACCEPTANCE") != "true" {
		t.Skip("disposable real-systemd/PAM GitHub runner only")
	}
	if os.Geteuid() != 0 || os.Getenv("GITHUB_ACTIONS") != "true" {
		t.Fatal("root disposable CI required")
	}
	service := os.Getenv("KOMARI_STAGE6_SERVICE")
	dir := filepath.Join("/usr/lib/komari", service)
	host := filepath.Join(dir, "komari-host")
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	panel := &hostTestPanel{key: key, mode: 2, receipts: map[string][]byte{}}
	panel.set(service, 1, false)
	mux := http.NewServeMux()
	p, h := configconnect.NewConfigServiceHandler(panel)
	mux.Handle(p, h)
	p, h = configconnect.NewPrivilegedDeliveryServiceHandler(panel)
	mux.Handle(p, h)
	p, h = hostconnect.NewHostServiceHandler(panel)
	mux.Handle(p, h)
	p, h = reportconnect.NewAgentReportServiceHandler(panel)
	mux.Handle(p, h)
	p, h = metricsconnect.NewMetricsServiceHandler(panel)
	mux.Handle(p, h)
	p, h = rescueconnect.NewRescueServiceHandler(panel)
	mux.Handle(p, h)
	server := httptest.NewServer(h2c.NewHandler(mux, &http2.Server{}))
	t.Cleanup(server.Close)
	if err = Run([]string{"install", "--service", service, "--user", "komari-stage6-agent", "--binary-dir", dir, "--", "--disable-auto-update", "--cf-access-client-id", "ci-access-id", "--cf-access-client-secret", "ci-access-value"}, io.Discard); err != nil {
		t.Fatal(err)
	}
	m, err := resolveManifest(filepath.Join(hostops.Registry, service+".json"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _, _ = systemctl("stop", service); _, _ = systemctl("stop", helperUnit(m)) })
	accessPath := filepath.Join(dir, "host-access.json")
	if err = hostops.WriteJSON(accessPath, hostops.AccessConfig{ClientID: "ci-access-id", ClientSecret: "ci-access-value"}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err = Run([]string{"trust", "--manifest", m.ManifestPath, "--endpoint", server.URL, "--agent-id", "stage6-node", "--panel-key-id", "stage6", "--panel-public-key", base64.StdEncoding.EncodeToString(pub), "--release-key-id", "stage6", "--release-public-key", base64.StdEncoding.EncodeToString(pub), "--access-config", accessPath}, io.Discard); err != nil {
		t.Fatal(err)
	}
	creds, err := credentials.Open(m.CredentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	agentpub, agentpriv, kid, err := credentials.GenerateKeypair()
	if err != nil {
		t.Fatal(err)
	}
	if err = creds.Save(credentials.Identity{AgentID: "stage6-node", Endpoint: server.URL, AccessToken: "ci-disposable-token", RefreshToken: "ci-disposable-refresh", PrivateKey: agentpriv, PublicKey: agentpub, KeyID: kid, ControlPlaneKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "stage6", Value: base64.StdEncoding.EncodeToString(pub)}}}); err != nil {
		t.Fatal(err)
	}
	runtime, err := runtimeconfig.New(runtimeconfig.FromFlags(&flags.Config{Interval: 3}), m.RuntimeStateFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = runtime.Apply(&configv1.DesiredConfig{AgentId: "stage6-node", Revision: 4, Runtime: &configv1.RuntimeConfig{}}); err != nil {
		t.Fatal(err)
	}
	agent, err := user.Lookup("komari-stage6-agent")
	if err != nil {
		t.Fatal(err)
	}
	uid, _ := strconv.Atoi(agent.Uid)
	gid, _ := strconv.Atoi(agent.Gid)
	// Legacy migration keeps the original state paths. Reproduce SJC's old
	// executable sharing that directory, rather than testing only JSON files.
	legacyArtifact := filepath.Join(filepath.Dir(m.CredentialsFile), "agent")
	legacyFile, err := os.OpenFile(legacyArtifact, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o755)
	if err != nil {
		t.Fatal(err)
	}
	const legacySize = int64(19550635)
	legacyMarker := []byte("preserved retired Agent ELF")
	if err = legacyFile.Truncate(legacySize); err == nil {
		_, err = legacyFile.WriteAt(legacyMarker, legacySize-int64(len(legacyMarker)))
	}
	legacyFile.Close()
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(legacyArtifact, uid, gid); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{m.CredentialsFile, m.RuntimeStateFile} {
		if err = os.Chown(path, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	admin, err := user.Lookup("komari-stage6-admin")
	if err != nil {
		t.Fatal(err)
	}
	random := make([]byte, 24)
	_, _ = rand.Read(random)
	password := hex.EncodeToString(random)
	passwd := exec.Command("/usr/sbin/chpasswd")
	passwd.Stdin = strings.NewReader(admin.Username + ":" + password + "\n")
	if output, err := passwd.CombinedOutput(); err != nil {
		t.Fatalf("configure disposable PAM account: %v %s", err, output)
	}
	if _, err = systemctl("start", service); err != nil {
		t.Fatal(err)
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal(err)
	}
	// Isolated legacy-upgrade fixture: the same approved root task requests
	// remote control, while migration preserved an unknown historical deny.
	legacyPolicy, err := hostops.ReadPolicy(m)
	if err != nil {
		t.Fatal(err)
	}
	legacyPolicy.ForceDenyRemoteControl = true
	legacyPolicy.DisableSource = "legacy-unknown-preserve"
	if err = hostops.WriteJSON(m.HostPolicyFile, legacyPolicy, 0o644); err != nil {
		t.Fatal(err)
	}
	panel.mu.Lock()
	settings := privileged.SettingsFromProto(panel.current.Privileged)
	settings.RemoteControlEnabled = true
	panel.current.Privileged = settings.Proto()
	panel.current.ConfigHash = privileged.Hash(settings)
	panel.current.Authorization.ConfigHash = panel.current.ConfigHash
	panel.mu.Unlock()
	legacyConsentAnswer := "decline"
	var interrupt <-chan struct{}
	var lastRunOutput string
	run := func(passwordInput string, args ...string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 100*time.Second)
		defer cancel()
		c := exec.CommandContext(ctx, host, args...)
		c.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin", "SUDO_USER=" + admin.Username, "SUDO_UID=" + admin.Uid}
		terminal, err := pty.Start(c)
		if err != nil {
			return err
		}
		defer terminal.Close()
		if interrupt != nil {
			go func(gate <-chan struct{}) {
				select {
				case <-gate:
					_ = c.Process.Kill()
				case <-ctx.Done():
				}
			}(interrupt)
		}
		done := make(chan struct{})
		var output strings.Builder
		go func() {
			defer close(done)
			buf := make([]byte, 1024)
			sent := false
			consentSent := false
			for {
				n, e := terminal.Read(buf)
				if n > 0 {
					output.Write(buf[:n])
					if !consentSent && strings.Contains(output.String(), "Legacy remote-control consent:") {
						_, _ = terminal.Write([]byte(legacyConsentAnswer + "\n"))
						consentSent = true
					}
					if !sent && strings.Contains(strings.ToLower(output.String()), "password:") {
						_, _ = terminal.Write([]byte(passwordInput + "\n"))
						sent = true
					}
				}
				if e != nil {
					return
				}
			}
		}()
		err = c.Wait()
		<-done
		lastRunOutput = strings.ReplaceAll(output.String(), password, "[redacted]")
		t.Log(lastRunOutput)
		return err
	}
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "2"); err == nil {
		t.Fatal("declined local legacy consent executed a host task")
	}
	legacyConsentAnswer = "authorize " + service + " 2"
	if err = run("deliberately-wrong", "apply", "--manifest", m.ManifestPath, "--revision", "2"); err == nil {
		t.Fatal("root/sudo identity bypassed fresh PAM password")
	}
	panel.mu.Lock()
	claimed := panel.op != nil
	panel.mu.Unlock()
	if claimed {
		t.Fatal("failed local authentication claimed operation")
	}
	legacyPolicy, err = hostops.ReadPolicy(m)
	if err != nil || !legacyPolicy.ForceDenyRemoteControl {
		t.Fatal("declined consent or failed PAM changed the protected deny:", err)
	}
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "2"); err != nil {
		t.Fatal(err)
	}
	if err = verifyService(service, 0, 1); err != nil {
		t.Fatal(err)
	}
	legacyPolicy, err = hostops.ReadPolicy(m)
	if err != nil || legacyPolicy.ForceDenyRemoteControl || legacyPolicy.DisableSource != "legacy-remote-control-reauthorized" {
		t.Fatal("approved, locally confirmed and PAM-authenticated task did not commit legacy consent:", err)
	}
	observed, err := observe(service)
	if err != nil || observed.WorkingDirectory != filepath.Dir(m.CredentialsFile) {
		t.Fatalf("host conversion lost the service working directory: %v %s", err, observed.WorkingDirectory)
	}
	store, err := privileged.Open(m.PrivilegedStateFile)
	if err != nil || store.State().AppliedRevision != 2 {
		t.Fatalf("real daemon did not load/ACK target: %v", err)
	}
	loaded, err := credentials.Open(m.CredentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	id, _ := loaded.Identity()
	if id.AgentID != "stage6-node" {
		t.Fatal("identity lost")
	}
	runtime, err = runtimeconfig.New(runtimeconfig.FromFlags(&flags.Config{}), m.RuntimeStateFile)
	if err != nil || runtime.Current().Revision != 4 {
		t.Fatal("runtime r4 lost")
	}
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "2"); err == nil {
		t.Fatal("completed nonce was replayed")
	}
	// Demotion uses the pinned original account and does not reset enrollment.
	panel.set(service, 2, false)
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "3"); err != nil {
		t.Fatal(err)
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal(err)
	}
	// Install the real helper while preserving the ordinary daemon identity.
	panel.set(service, 2, true)
	panel.mu.Lock()
	canInstall := false
	for _, action := range panel.negotiatedActions {
		canInstall = canInstall || action == 2
	}
	panel.mu.Unlock()
	policy, err := hostops.ReadPolicy(m)
	if err != nil || policy.AllowRescueHelper || !canInstall {
		t.Fatalf("uninstalled helper must advertise installation without prior consent: supported=%t policy=%+v error=%v", canInstall, policy, err)
	}
	helper := filepath.Join(dir, "helper-release")
	data, err := os.ReadFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	signed := testRelease(t, key, data)
	cache := helperCache(m)
	if err = ensureTrustedDir(filepath.Dir(cache)); err != nil {
		t.Fatal(err)
	}
	if err = hostops.AtomicWrite(cache, []byte("corrupt cached ELF"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = hostops.WriteJSON(cache+".release.json", signed, 0o644); err != nil {
		t.Fatal(err)
	}
	// Failed verification after PAM must leave the Agent running, without a lease
	// or policy grant. Retry the same approval after replacing the bad cache.
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "4"); err == nil {
		t.Fatal("corrupt helper cache accepted")
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal("preparation failure stopped Agent:", err)
	}
	if _, err = os.Stat(filepath.Join(journalDir(m), "transaction.json")); !os.IsNotExist(err) {
		t.Fatal("preparation failure claimed a transaction")
	}
	if err = hostops.AtomicWrite(cache, data, 0o600); err != nil {
		t.Fatal(err)
	}
	// Legacy migration and a reboot both leave /run without this directory.
	// A fresh-install-only fixture previously hid the missing-heartbeat failure.
	heartbeatDir := filepath.Dir(hostops.HelperStatusPath(m))
	if err = os.Remove(heartbeatDir); err != nil {
		t.Fatal("remove empty heartbeat directory on disposable runner:", err)
	}
	// The root helper must reject existing unsafe directories, not take them over.
	if err = os.Symlink(dir, heartbeatDir); err != nil {
		t.Fatal(err)
	}
	if err = hostops.PrepareHelperStatus(m); err == nil {
		t.Fatal("symlink heartbeat directory accepted")
	}
	if err = os.Remove(heartbeatDir); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(heartbeatDir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err = os.Chown(heartbeatDir, uid, gid); err != nil {
		t.Fatal(err)
	}
	if err = hostops.PrepareHelperStatus(m); err == nil {
		t.Fatal("Agent-owned heartbeat directory accepted")
	}
	if err = os.Remove(heartbeatDir); err != nil {
		t.Fatal(err)
	}
	t.Log("first rescue installation starts without /run/komari")
	// No --allow-rescue-helper, fetch-helper or offline artifact flags are needed.
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "4"); err != nil {
		t.Fatal(err)
	}
	policy, err = hostops.ReadPolicy(m)
	if err != nil || !policy.AllowRescueHelper || !policy.HelperInstalled || policy.PrivilegeMode != 2 {
		t.Fatalf("PAM install consent/Agent identity: policy=%+v error=%v", policy, err)
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal("installing helper changed daemon identity:", err)
	}
	status, err := hostops.ReadHelperStatus(m)
	if err != nil || !status.LeaseReady || !status.Authorized {
		t.Fatalf("helper not independently ready: %v", err)
	}
	exerciseInstalledRescueUpgrade(t, m, key)
	if err = hostops.TrustedPath(heartbeatDir); err != nil {
		t.Fatal(err)
	}
	if info, e := os.Stat(heartbeatDir); e != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("heartbeat directory must be public and protected: info=%v error=%v", info, e)
	}
	// Reproduce volatile /run after reboot without another host apply or a new
	// approval. The installed helper must recreate its evidence on every startup.
	if _, err = systemctl("stop", helperUnit(m)); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(hostops.HelperStatusPath(m)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err = os.Remove(heartbeatDir); err != nil {
		t.Fatal(err)
	}
	if err = restartReviewedService(helperUnit(m)); err != nil {
		t.Fatal(err)
	}
	if err = waitHelper(m); err != nil {
		t.Fatal("helper did not recover after volatile runtime directory loss:", err)
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal("helper restart changed ordinary Agent identity:", err)
	}
	t.Log("helper restart recreated /run/komari and published a verified root heartbeat")
	// Signed withdrawal denies new rescue work before any administrator removes it.
	panel.set(service, 2, false)
	deadline := time.Now().Add(8 * time.Second)
	revoked := false
	for time.Now().Before(deadline) {
		status, err = hostops.ReadHelperStatus(m)
		if err == nil && !status.Authorized {
			revoked = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if !revoked {
		t.Fatal("helper ignored signed withdrawal")
	}
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "5"); err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(helperUnitPath(m)); !os.IsNotExist(err) {
		t.Fatal("helper service was not removed")
	}
	// A real systemd startup failure must restore the prior non-root service.
	bootstrapBefore, err := os.Stat(bootstrapPath(m))
	if err != nil {
		t.Fatal(err)
	}
	panel.set(service, 1, false)
	if err = ensureTrustedDir(filepath.Dir(profilePath(m))); err != nil {
		t.Fatal(err)
	}
	failing := filepath.Join(filepath.Dir(profilePath(m)), "99-ci-startup-failure.conf")
	legacyPolicy, err = hostops.ReadPolicy(m)
	if err != nil {
		t.Fatal(err)
	}
	legacyPolicy.ForceDenyRemoteControl = true
	legacyPolicy.DisableSource = "legacy-unknown-preserve"
	if err = hostops.WriteJSON(m.HostPolicyFile, legacyPolicy, 0o644); err != nil {
		t.Fatal(err)
	}
	panel.mu.Lock()
	settings = privileged.SettingsFromProto(panel.current.Privileged)
	settings.RemoteControlEnabled = true
	panel.current.Privileged = settings.Proto()
	panel.current.ConfigHash = privileged.Hash(settings)
	panel.current.Authorization.ConfigHash = panel.current.ConfigHash
	panel.mu.Unlock()
	legacyConsentAnswer = "authorize " + service + " 6"
	if err = hostops.AtomicWrite(failing, []byte("[Service]\nExecStartPre=/bin/false\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// The guard intentionally remains for both profiles, so first verify the
	// failure is recorded. Recovery is then retried after fixing that OS error.
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "6"); err == nil {
		t.Fatal("failing restart claimed success")
	}
	// A partially started root daemon can leave new state files that were not
	// present in the original ownership log. Recovery must return access too.
	createdState := filepath.Join(filepath.Dir(m.CredentialsFile), "created-after-transition.json")
	if err = hostops.AtomicWrite(createdState, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err = os.Remove(failing); err != nil {
		t.Fatal(err)
	}
	if _, err = systemctl("daemon-reload"); err != nil {
		t.Fatal(err)
	}
	if err = run(password, "restore", "--manifest", m.ManifestPath); err != nil {
		t.Fatal(err)
	}
	bootstrapAfter, err := os.Stat(bootstrapPath(m))
	if err != nil {
		t.Fatal(err)
	}
	legacyPolicy, err = hostops.ReadPolicy(m)
	if err != nil || !legacyPolicy.ForceDenyRemoteControl || legacyPolicy.DisableSource != "legacy-unknown-preserve" {
		t.Fatal("failed transaction did not restore the pre-consent restriction:", err)
	}
	before, after := bootstrapBefore.Sys().(*syscall.Stat_t), bootstrapAfter.Sys().(*syscall.Stat_t)
	if before.Uid != after.Uid || before.Gid != after.Gid || bootstrapBefore.Mode() != bootstrapAfter.Mode() {
		t.Fatal("restoration changed bootstrap ownership or permissions")
	}
	createdInfo, err := os.Stat(createdState)
	if err != nil {
		t.Fatal(err)
	}
	createdOwner := createdInfo.Sys().(*syscall.Stat_t)
	if int(createdOwner.Uid) != uid || int(createdOwner.Gid) != gid || createdInfo.Mode().Perm() != 0o600 {
		t.Fatal("new files created during transition were left inaccessible after recovery")
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal(err)
	}
	// Expired grants cannot claim a lease or change identity.
	panel.set(service, 1, false)
	panel.mu.Lock()
	panel.current.Authorization.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
	panel.mu.Unlock()
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "7"); err == nil {
		t.Fatal("expired approval executed")
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal(err)
	}
	// A lost phase-3 report stays in the durable host outbox, and the daemon
	// cannot advance applied until exactly that report is accepted on resume.
	panel.set(service, 1, false)
	panel.mu.Lock()
	panel.failLocalACK = true
	panel.mu.Unlock()
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "8"); err == nil {
		t.Fatal("lost host ACK was hidden")
	}
	var pending hostJournal
	if err = hostops.ReadJSON(filepath.Join(journalDir(m), "transaction.json"), &pending, true); err != nil {
		t.Fatal(err)
	}
	if pending.Phase != "local_applied" || len(pending.Receipt) == 0 {
		t.Fatal("lost host receipt was not durable")
	}
	store, err = privileged.Open(m.PrivilegedStateFile)
	if err != nil || store.State().AppliedRevision >= 8 {
		t.Fatal("daemon advanced before host report")
	}
	panel.mu.Lock()
	panel.failLocalACK = false
	panel.mu.Unlock()
	// The normal no-argument command discovers the adjacent manifest, while
	// apply above bound the journal to the registry copy. A genuinely different
	// installation must still fail before authentication or OS mutation.
	adjacentManifest := filepath.Join(filepath.Dir(m.HostTool), "service-config.json")
	different := *m
	different.CredentialsFile += ".different-installation"
	if err = hostops.WriteJSON(adjacentManifest, &different, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = run(password, "resume"); err == nil || !strings.Contains(lastRunOutput, "journal installation differs") {
		t.Fatal("different installation accepted by no-argument recovery:", lastRunOutput)
	}
	if err = hostops.WriteJSON(adjacentManifest, m, 0o644); err != nil {
		t.Fatal(err)
	}
	if err = run(password, "resume"); err != nil {
		t.Fatal(err)
	}
	store, err = privileged.Open(m.PrivilegedStateFile)
	if err != nil || store.State().AppliedRevision != 8 {
		t.Fatal("no-argument recovery did not reconcile the real daemon ACK:", err)
	}
	// Kill the actual host process after it stopped the daemon and fenced
	// state inodes, while the online lease recheck is in progress.
	panel.set(service, 2, false)
	gate := make(chan struct{}, 1)
	panel.mu.Lock()
	panel.interruptProfile = gate
	panel.mu.Unlock()
	interrupt = gate
	// Also exercise the reverse alias: default apply, explicit recovery.
	if err = run(password, "apply", "--revision", "9"); err == nil {
		t.Fatal("host process was not interrupted")
	}
	interrupt = nil
	panel.mu.Lock()
	panel.interruptProfile = nil
	panel.mu.Unlock()
	if err = hostops.ReadJSON(filepath.Join(journalDir(m), "transaction.json"), &pending, true); err != nil {
		t.Fatal(err)
	}
	if pending.Phase != "mutating" || len(pending.Ownership) == 0 {
		t.Fatal("interrupt did not exercise fenced state")
	}
	if err = run(password, "resume", "--manifest", m.ManifestPath); err != nil {
		t.Fatal(err)
	}
	if err = verifyService(service, 0, 1); err != nil {
		t.Fatal("interrupted demotion did not restore original root profile:", err)
	}
	// The panel accepts a daemon ACK but both that response and the host's final
	// read are lost. Explicit local restoration must invalidate the old ACK.
	panel.set(service, 2, false)
	panel.mu.Lock()
	panel.loseDaemonACK, panel.hideCompletedRead = true, true
	panel.mu.Unlock()
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "10"); err != nil {
		t.Fatal(err)
	}
	if err = hostops.ReadJSON(filepath.Join(journalDir(m), "transaction.json"), &pending, true); err != nil {
		t.Fatal(err)
	}
	if pending.Phase != "local_applied" {
		t.Fatal("lost final ACK did not retain the host journal")
	}
	panel.mu.Lock()
	acceptedBeforeOutage := panel.current.State == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED
	panel.hideCompletedRead = false
	panel.mu.Unlock()
	if !acceptedBeforeOutage {
		t.Fatal("fault was not injected after panel acceptance")
	}
	if err = run(password, "restore", "--manifest", m.ManifestPath); err != nil {
		t.Fatal(err)
	}
	if err = verifyService(service, 0, 1); err != nil {
		t.Fatal(err)
	}
	deadline = time.Now().Add(15 * time.Second)
	invalidated := false
	for time.Now().Before(deadline) {
		store, err = privileged.Open(m.PrivilegedStateFile)
		if err == nil {
			for _, entry := range store.State().RejectedReceipts {
				var report configv1.ReportPrivilegedDeliveryRequest
				if proto.Unmarshal(entry.Payload, &report) == nil && report.Revision == 10 && report.GetObservation().GetOperationId() == pending.ID {
					invalidated = true
				}
			}
		}
		if invalidated {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if !invalidated {
		t.Fatal("restored daemon retained or retransmitted its invalid old success")
	}
	panel.mu.Lock()
	restoredAfterOutage := panel.op.Phase == hostv1.HostOperationPhase_HOST_OPERATION_PHASE_RESTORED && panel.current.State == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_FAILED
	panel.loseDaemonACK = false
	panel.mu.Unlock()
	if !restoredAfterOutage {
		t.Fatal("restoration after lost final ACK did not close the operation")
	}
	// A failed target startup with a successful automatic restoration must
	// archive immediately, so the next approved revision needs no manual restore.
	rootOnly := filepath.Join(dir, "ci-root-only-start")
	if err = hostops.AtomicWrite(rootOnly, []byte("#!/bin/sh\n[ \"$(id -u)\" = 0 ]\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err = hostops.AtomicWrite(failing, []byte("[Service]\nExecStartPre="+unitQuote(rootOnly)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	panel.set(service, 2, false)
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "11"); err == nil || !strings.Contains(lastRunOutput, "transaction archived") {
		t.Fatal("automatic restoration did not report confirmed archive:", err)
	}
	if err = verifyService(service, 0, 1); err != nil {
		t.Fatal("failed demotion did not restore original root service:", err)
	}
	if _, err = os.Stat(filepath.Join(journalDir(m), "transaction.json")); !os.IsNotExist(err) {
		t.Fatal("confirmed automatic restoration left an active journal:", err)
	}
	panel.mu.Lock()
	archivedOperationID := panel.op.OperationId
	panel.mu.Unlock()
	if _, err = os.Stat(journalDir(m) + "-" + archivedOperationID); err != nil {
		t.Fatal("automatic restoration discarded transaction history:", err)
	}
	if err = os.Remove(failing); err != nil {
		t.Fatal(err)
	}
	if _, err = systemctl("daemon-reload"); err != nil {
		t.Fatal(err)
	}
	panel.set(service, 2, false)
	if err = run(password, "apply", "--manifest", m.ManifestPath, "--revision", "12"); err != nil {
		t.Fatal("new approved task blocked after confirmed rollback:", err)
	}
	if err = verifyService(service, uid, 2); err != nil {
		t.Fatal(err)
	}
	t.Log("confirmed rollback archived automatically; next signed revision applied without manual journal cleanup")
	legacyFile, err = os.Open(legacyArtifact)
	if err != nil {
		t.Fatal(err)
	}
	defer legacyFile.Close()
	marker := make([]byte, len(legacyMarker))
	if _, err = legacyFile.ReadAt(marker, legacySize-int64(len(legacyMarker))); err != nil || string(marker) != string(legacyMarker) {
		t.Fatalf("host transactions changed the retired legacy executable: %q %v", marker, err)
	}
	t.Log("Verified real PAM, identity promotion/demotion, daemon ACK, UUID/r4 preservation, legacy 19.6 MB mixed state directory, replay/expiry rejection, helper lifecycle/revocation, startup failure, lost host receipt, process-kill recovery, and restoration after a lost final daemon ACK")
}
