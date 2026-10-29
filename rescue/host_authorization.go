package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/requestheaders"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
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
		return fmt.Errorf("rescue idle: current signed revision=%d state=%s rescue_enabled=%t; waiting for an approved rescue configuration", r.Revision, r.State, r.GetPrivileged().GetRescueHelperEnabled())
	}
	h.authorized.Store(true)
	return nil
}

// Rescue streams carry a fresh, fully signed revision every second. No frame,
// invalid frame, disconnect or local policy denial closes the gate. The two
// second bound matches the previous 500ms + 1500ms unary failure window.
const authorizationSilence = 2 * time.Second
const authorizationWatchHeader = "X-Komari-Rescue-Watch"

// Share the connection pool across reconnects, including credential rotation.
var authorizationWatchTransport = func() *http.Transport {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DialContext = (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	transport.TLSHandshakeTimeout = 5 * time.Second
	transport.ResponseHeaderTimeout = 10 * time.Second
	return transport
}()

// A response stream has no HTTP total deadline: signed-heartbeat freshness
// and the watch context bound its lifetime. Unary RPCs retain their timeout.
func newAuthorizationWatchClient(id credentials.Identity) *http.Client {
	client := requestheaders.WrapWithStaticDPoP(&http.Client{Transport: authorizationWatchTransport}, id)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return errors.New("helper redirects forbidden") }
	return client
}

type authorizationFrame struct {
	revision *configv1.PrivilegedRevision
	err      error
}

type heartbeatCursor struct {
	issued   time.Time
	sequence uint64
}

func (c *heartbeatCursor) accept(trust *hostops.Trust, r *configv1.PrivilegedRevision, now time.Time) error {
	if err := hostops.VerifySignedRevision(trust, r); err != nil {
		return err
	}
	// Parse only after verifying signature, schema, complete body and binding.
	var instruction securityv1.SignedInstruction
	if err := proto.Unmarshal(r.Signature.Payload, &instruction); err != nil {
		return err
	}
	if instruction.IssuedAt == nil || instruction.IssuedAt.CheckValid() != nil {
		return errors.New("missing rescue heartbeat time")
	}
	issued := instruction.IssuedAt.AsTime()
	if now.Sub(issued) > authorizationSilence || issued.After(now.Add(time.Second)) || !issued.After(c.issued) || r.UpdateSequence < c.sequence {
		return errors.New("stale, replayed or regressed rescue heartbeat")
	}
	c.issued, c.sequence = issued, r.UpdateSequence
	return nil
}
func rescueRevisionAllowed(r *configv1.PrivilegedRevision) bool {
	return r.GetPrivileged().GetRescueHelperEnabled() && (r.State == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_APPLYING || r.State == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_DELIVERED || r.State == configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_AWAITING_AGENT)
}

func receiveAuthorization(ctx context.Context, rpc configconnect.PrivilegedDeliveryServiceClient, req *connect.Request[configv1.WatchPrivilegedDeliveryRequest], frames chan<- authorizationFrame) {
	send := func(frame authorizationFrame) {
		select {
		case frames <- frame:
		case <-ctx.Done():
		}
	}
	stream, err := rpc.WatchPrivilegedDelivery(ctx, req)
	if err != nil {
		send(authorizationFrame{err: err})
		return
	}
	defer stream.Close()
	for stream.Receive() {
		if stream.ResponseHeader().Get(authorizationWatchHeader) != "v1" {
			send(authorizationFrame{err: errors.New("panel lacks signed rescue heartbeat support; upgrade panel first")})
			return
		}
		send(authorizationFrame{revision: stream.Msg().Revision})
	}
	err = stream.Err()
	if err == nil {
		err = errors.New("rescue authorization stream closed")
	}
	send(authorizationFrame{err: err})
}

func (h *Helper) watchAuthorization(ctx context.Context) {
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	defer os.Remove(hostops.HelperStatusPath(h.manifest))
	changes, watchErr := credentials.WatchChanges(ctx, h.manifest.CredentialsFile)
	if watchErr != nil {
		log.Printf("credential file notification unavailable: %v", watchErr)
	}
	var connectedToken string
	var frames chan authorizationFrame
	var cancelStream context.CancelFunc
	defer func() {
		if cancelStream != nil {
			cancelStream()
		}
		h.authorized.Store(false)
		h.leaseReady.Store(false)
	}()
	var cursor heartbeatCursor
	var lastFrame, nextRetry, lastLocal, lastPublish, lastCredentialCheck time.Time
	backoff := 500 * time.Millisecond
	lastError := ""
	deny := func(err error) {
		h.leaseReady.Store(false)
		if h.authorized.Swap(false) {
			_ = CloseTemporarySSHAccess(ctx, h.action)
		}
		if err != nil && err.Error() != lastError {
			log.Printf("rescue authorization watch failed: %s", truncateError(err.Error()))
			lastError = err.Error()
		}
	}
	disconnect := func(now time.Time, err error) {
		deny(err)
		if cancelStream != nil {
			cancelStream()
			cancelStream = nil
		}
		frames = nil
		nextRetry = now.Add(backoff)
		backoff = min(30*time.Second, backoff*2)
	}

	handoff := func() {
		id, ok := readHostIdentity(h.manifest, h.hostTrust)
		if !ok || id.AccessToken == connectedToken {
			return
		}
		// Switch connections immediately while retaining only the last verified
		// heartbeat's original two-second freshness. No lease is extended here.
		if cancelStream != nil {
			cancelStream()
			cancelStream = nil
		}
		frames = nil
		nextRetry = time.Time{}
		backoff = 500 * time.Millisecond
	}

	for {
		select {
		case <-ctx.Done():
			deny(ctx.Err())
			return
		case _, open := <-changes:
			if !open {
				changes = nil
				continue
			}
			handoff()
		case frame := <-frames:
			now := time.Now()
			if frame.err != nil {
				disconnect(now, frame.err)
				continue
			}
			if err := cursor.accept(h.hostTrust, frame.revision, now); err != nil {
				disconnect(now, err)
				continue
			}
			lastFrame = now
			if cursor.issued.Before(now) {
				lastFrame = cursor.issued
			}
			// A revoked or pending signed state remains on the stream, without a
			// retry loop. It cannot start leasing or executing rescue actions.
			if !rescueRevisionAllowed(frame.revision) {
				deny(errors.New("current signed rescue grant is withdrawn or not approved"))
				continue
			}
			policy, err := hostops.ReadPolicy(h.manifest)
			if err != nil || !policy.AllowRescueHelper || policy.ForceDenyRescueHelper || !policy.HelperInstalled || !policy.HelperAuthorized {
				deny(errors.New("root policy denies rescue helper"))
				continue
			}
			h.authorized.Store(true)
			h.leaseReady.Store(true)
			if lastError != "" {
				log.Print("rescue authorization watch recovered")
				lastError = ""
			}
			backoff = 500 * time.Millisecond
		case now := <-ticker.C:
			if changes == nil && now.Sub(lastCredentialCheck) >= 5*time.Second {
				lastCredentialCheck = now
				handoff()
			}
			if frames == nil && !now.Before(nextRetry) {
				id, ok := readHostIdentity(h.manifest, h.hostTrust)
				if !ok {
					disconnect(now, errors.New("helper credentials unavailable"))
					continue
				}
				streamCtx, cancel := context.WithTimeout(ctx, 25*time.Minute)
				cancelStream = cancel
				connectedToken = id.AccessToken
				client := newAuthorizationWatchClient(id)
				rpc := configconnect.NewPrivilegedDeliveryServiceClient(client, h.hostTrust.Endpoint, connect.WithReadMaxBytes(1<<20))
				req := connect.NewRequest(&configv1.WatchPrivilegedDeliveryRequest{AgentId: id.AgentID, ProtocolVersion: 2})
				h.authorize(req.Header())
				req.Header().Set(authorizationWatchHeader, "v1")
				frames = make(chan authorizationFrame, 1)
				if lastFrame.IsZero() || !h.authorized.Load() {
					lastFrame = now
				}
				go receiveAuthorization(streamCtx, rpc, req, frames)
			}
			if frames != nil && now.Sub(lastFrame) >= authorizationSilence {
				disconnect(now, errors.New("signed rescue heartbeat timed out"))
			}
			if now.Sub(lastLocal) >= 500*time.Millisecond {
				lastLocal = now
				policy, err := hostops.ReadPolicy(h.manifest)
				if err != nil || !policy.AllowRescueHelper || policy.ForceDenyRescueHelper || !policy.HelperInstalled || !policy.HelperAuthorized {
					deny(errors.New("root policy denies rescue helper"))
				}
			}
			if now.Sub(lastPublish) >= 2*time.Second {
				lastPublish = now
				if err := h.publishHostStatus(); err != nil {
					log.Printf("publish rescue heartbeat failed: %s", truncateError(err.Error()))
				}
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
