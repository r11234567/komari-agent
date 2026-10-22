package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/requestheaders"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
)

func readHostIdentity(m *hostops.Manifest, t *hostops.Trust) (credentials.Identity, bool) {
	var id credentials.Identity
	b, err := hostops.ReadCandidate(m.CredentialsFile)
	if err != nil || json.Unmarshal(b, &id) != nil || id.AgentID != t.AgentID || id.Endpoint != t.Endpoint || id.AccessToken == "" {
		return id, false
	}
	id.ControlPlaneKeys = t.PanelKeys
	id.PolicyAlgorithms = []int32{1}
	id.PolicyMinimumSignatures = 1
	id.PolicyRequireAll = false
	return id, true
}
func (h *Helper) checkAuthorization(parent context.Context) error {
	policy, err := hostops.ReadPolicy(h.manifest)
	if err != nil {
		return err
	}
	if !policy.AllowRescueHelper || policy.ForceDenyRescueHelper || !policy.HelperInstalled || !policy.HelperAuthorized {
		return errors.New("root policy denies rescue helper")
	}
	id, ok := readHostIdentity(h.manifest, h.hostTrust)
	if !ok {
		return errors.New("helper credentials unavailable")
	}
	ctx, cancel := context.WithTimeout(parent, 1500*time.Millisecond)
	defer cancel()
	client := requestheaders.WrapWithStaticDPoP(nil, id)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("helper redirects forbidden") }
	rpc := configconnect.NewPrivilegedDeliveryServiceClient(client, h.hostTrust.Endpoint, connect.WithReadMaxBytes(1<<20))
	req := connect.NewRequest(&configv1.GetPrivilegedDeliveryRequest{AgentId: id.AgentID})
	h.authorize(req.Header())
	res, err := rpc.GetPrivilegedDelivery(ctx, req)
	if err != nil {
		return err
	}
	r := res.Msg.Revision
	if err = hostops.VerifySignedRevision(h.hostTrust, r); err != nil {
		return err
	}
	if !r.GetPrivileged().GetRescueHelperEnabled() || (r.State != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_APPLYING && r.State != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED && r.State != configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_AWAITING_AGENT) {
		return errors.New("current signed rescue grant is withdrawn or not approved")
	}
	h.authorized.Store(true)
	return nil
}
func (h *Helper) watchAuthorization(ctx context.Context) {
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	defer os.Remove(hostops.HelperStatusPath(h.manifest))
	lastAuthorizationError, lastHeartbeatError := "", ""
	for {
		select {
		case <-ctx.Done():
			h.authorized.Store(false)
			return
		case <-ticker.C:
			err := h.checkAuthorization(ctx)
			if err != nil {
				message := truncateError(err.Error())
				if message != lastAuthorizationError {
					log.Printf("rescue authorization check failed: %s", message)
				}
				lastAuthorizationError = message
				if h.authorized.Swap(false) {
					_ = CloseTemporarySSHAccess(ctx, h.action)
				}
				h.leaseReady.Store(false)
			} else {
				if lastAuthorizationError != "" {
					log.Print("rescue authorization check recovered")
				}
				lastAuthorizationError = ""
				h.leaseReady.Store(true)
			}
			if err := h.publishHostStatus(); err != nil {
				message := truncateError(err.Error())
				if message != lastHeartbeatError {
					log.Printf("publish rescue heartbeat failed: %s", message)
				}
				lastHeartbeatError = message
			} else {
				if lastHeartbeatError != "" {
					log.Print("rescue heartbeat publishing recovered")
				}
				lastHeartbeatError = ""
			}
		}
	}
}

func (h *Helper) publishHostStatus() error {
	ticks, err := hostops.ProcessStartTicks(os.Getpid())
	if err != nil {
		return fmt.Errorf("read process start ticks: %w", err)
	}
	executable, err := os.Executable()
	if err != nil {
		return fmt.Errorf("read process executable: %w", err)
	}
	return hostops.WriteJSON(hostops.HelperStatusPath(h.manifest), hostops.HelperStatus{PID: os.Getpid(), StartTicks: ticks, Executable: executable, Authorized: h.authorized.Load(), LeaseReady: h.leaseReady.Load(), ObservedAt: time.Now().UTC()}, 0o644)
}
func (h *Helper) cancelOnRevocation(ctx context.Context, cancel context.CancelFunc) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if !h.authorized.Load() {
				cancel()
				return
			}
		}
	}
}
