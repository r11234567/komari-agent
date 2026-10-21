package hostcmd

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/requestheaders"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	hostconnect "github.com/r11234567/komari-proto/gen/go/komari/host/v1/hostv1connect"
)

type panel struct {
	trust      *hostops.Trust
	identity   credentials.Identity
	host       hostconnect.HostServiceClient
	privileged configconnect.PrivilegedDeliveryServiceClient
}

func newPanel(m *hostops.Manifest, t *hostops.Trust) (*panel, error) {
	b, err := hostops.ReadCandidate(m.CredentialsFile)
	if err != nil {
		return nil, err
	}
	var id credentials.Identity
	if err = json.Unmarshal(b, &id); err != nil {
		return nil, errors.New("invalid enrolled credentials")
	}
	if id.AgentID != t.AgentID || id.Endpoint != t.Endpoint || id.AccessToken == "" {
		return nil, errors.New("credentials do not match independently pinned host identity/endpoint; refresh login as the daemon account")
	}
	id.Endpoint = t.Endpoint
	id.ControlPlaneKeys = t.PanelKeys
	id.PolicyAlgorithms = []int32{1}
	id.PolicyMinimumSignatures = 1
	base := &http.Client{Timeout: 30 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return errors.New("host RPC redirects are forbidden") }}
	h := requestheaders.WrapWithStaticDPoP(base, id)
	h.CheckRedirect = base.CheckRedirect
	return &panel{trust: t, identity: id, host: hostconnect.NewHostServiceClient(h, t.Endpoint, connect.WithReadMaxBytes(1<<20)), privileged: configconnect.NewPrivilegedDeliveryServiceClient(h, t.Endpoint, connect.WithReadMaxBytes(1<<20))}, nil
}
func auth[T any](p *panel, msg *T) *connect.Request[T] {
	r := connect.NewRequest(msg)
	requestheaders.ApplyAgentAuthentication(r.Header(), p.identity.AccessToken, "", "")
	return r
}
func (p *panel) current(ctx context.Context) (*configv1.PrivilegedRevision, error) {
	r, err := p.privileged.GetPrivilegedDelivery(ctx, auth(p, &configv1.GetPrivilegedDeliveryRequest{AgentId: p.trust.AgentID}))
	if err != nil {
		return nil, err
	}
	if err = hostops.VerifyRevision(p.trust, r.Msg.Revision); err != nil {
		return nil, err
	}
	return r.Msg.Revision, nil
}
func (p *panel) get(ctx context.Context, id string) (*hostv1.HostOperation, error) {
	r, err := p.host.GetHostOperation(ctx, auth(p, &hostv1.GetHostOperationRequest{AgentId: p.trust.AgentID, OperationId: id}))
	if err != nil {
		return nil, err
	}
	return r.Msg.Operation, nil
}
