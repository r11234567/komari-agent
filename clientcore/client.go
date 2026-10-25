// Package clientcore owns the Agent's Connect transport. Legacy v1/v2 remains
// outside this package and is selected only when the Connect endpoint is absent
// or the transport cannot be reached.
package clientcore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/enrollment"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/installation"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	"github.com/komari-monitor/komari-agent/core/signing"
	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/monitoring"
	"github.com/komari-monitor/komari-agent/requestheaders"
	"github.com/komari-monitor/komari-agent/server"
	"github.com/komari-monitor/komari-agent/terminal"
	agentv1 "github.com/r11234567/komari-proto/gen/go/komari/agent/v1"
	agentv1connect "github.com/r11234567/komari-proto/gen/go/komari/agent/v1/agentv1connect"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configv1connect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
	execv1connect "github.com/r11234567/komari-proto/gen/go/komari/exec/v1/execv1connect"
	filev1connect "github.com/r11234567/komari-proto/gen/go/komari/file/v1/filev1connect"
	hostv1connect "github.com/r11234567/komari-proto/gen/go/komari/host/v1/hostv1connect"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	metricsv1connect "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1/metricsv1connect"
	networkv1 "github.com/r11234567/komari-proto/gen/go/komari/network/v1"
	networkv1connect "github.com/r11234567/komari-proto/gen/go/komari/network/v1/networkv1connect"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	reportv1connect "github.com/r11234567/komari-proto/gen/go/komari/report/v1/reportv1connect"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	websshv1connect "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1/websshv1connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	requestDeadline    = 15 * time.Second
	configDeadline     = 30 * time.Second
	configPollInterval = 5 * time.Minute
)

var (
	ErrLegacyFallback   = errors.New("Connect transport is unavailable; use legacy compatibility transport")
	ErrUnconfigured     = errors.New("neither endpoint nor token is configured; specify --endpoint and --token or enroll via 'komari-agent login'")
	ErrPermissionDenied = errors.New("panel revoked credentials or permission was denied (HTTP 403 / PERMISSION_DENIED)")
)

type Client struct {
	host              hostv1connect.HostServiceClient
	hostManifest      *hostops.Manifest
	hostPolicy        *hostops.Policy
	hostTrust         *hostops.Trust
	startupID         string
	receiptMu         sync.Mutex
	privilegedMu      sync.Mutex
	runtimeSyncMu     sync.Mutex
	runtimeReconciled bool

	config     configv1connect.ConfigServiceClient
	privileged configv1connect.PrivilegedDeliveryServiceClient
	events     agentv1connect.AgentEventServiceClient
	report     reportv1connect.AgentReportServiceClient
	metrics    metricsv1connect.MetricsServiceClient
	network    networkv1connect.NetworkProbeServiceClient
	execution  execv1connect.ExecutionServiceClient
	webssh     websshv1connect.WebSSHServiceClient
	files      filev1connect.FileServiceClient
	endpoint   string
	tokenMu    sync.RWMutex
	token      string
	refreshMu  sync.Mutex
	agentMu    sync.RWMutex
	agentID    string
	sequence   atomic.Uint64
	store      *runtimeconfig.Store
	// privilegedStore is daemon-owned. Only a verified current v2 approval can
	// activate a same-identity candidate; host actions remain unavailable.
	privilegedStore *privileged.Store
	// credentialStore holds the enrolled identity, including the panel signing
	// keys this Agent pinned. It is what makes a delivered instruction
	// attributable rather than merely well-formed.
	credentialStore *credentials.Store
	// replayGuard remembers which instruction nonces were already carried out,
	// persisted so a restart cannot reopen the window.
	replayGuard *signing.ReplayGuard
	cfg         *flags_pkg.Config

	probeCancelMu sync.Mutex
	probeCancel   context.CancelFunc
}

func (c *Client) setProbeCancel(cancel context.CancelFunc) {
	c.probeCancelMu.Lock()
	defer c.probeCancelMu.Unlock()
	c.probeCancel = cancel
}

func (c *Client) cancelProbes() {
	c.probeCancelMu.Lock()
	defer c.probeCancelMu.Unlock()
	if c.probeCancel != nil {
		c.probeCancel()
	}
}

// identity returns the enrolled identity, if this Agent has one.
func (c *Client) identity() (credentials.Identity, bool) {
	if c.credentialStore == nil {
		return credentials.Identity{}, false
	}
	id, ok := c.credentialStore.Identity()
	if ok && c.hostTrust != nil {
		if id.AgentID != c.hostTrust.AgentID || id.Endpoint != c.hostTrust.Endpoint {
			return credentials.Identity{}, false
		}
		id.ControlPlaneKeys = c.hostTrust.PanelKeys
		id.PolicyAlgorithms = []int32{1}
		id.PolicyRequireAll = false
		id.PolicyMinimumSignatures = 1
	}
	return id, ok
}

func (c *Client) tokenValue() string {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()
	return c.token
}

func (c *Client) updateToken(token string) {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()
	c.token = token
}

func (c *Client) refreshCredentials(ctx context.Context, oldToken string) error {
	c.refreshMu.Lock()
	defer c.refreshMu.Unlock()

	if c.tokenValue() != oldToken && c.tokenValue() != "" {
		return nil
	}

	identity, ok := c.identity()
	if !ok || strings.TrimSpace(identity.RefreshToken) == "" {
		return errors.New("no refresh token available for credential refresh")
	}

	endpoint := c.endpoint
	if endpoint == "" {
		endpoint = identity.Endpoint
	}
	refreshClient := dnsresolver.GetHTTPClientWithPreference(requestDeadline, flags_pkg.GlobalConfig.PreferIPVersion)
	enrollClient, err := enrollment.New(endpoint, refreshClient)
	if err != nil {
		return fmt.Errorf("create enrollment client: %w", err)
	}

	refreshed, err := enrollClient.Refresh(ctx, identity)
	if err != nil {
		return fmt.Errorf("refresh credentials: %w", err)
	}

	if err := c.credentialStore.Save(refreshed); err != nil {
		return fmt.Errorf("save refreshed identity: %w", err)
	}

	c.updateToken(refreshed.AccessToken)
	log.Printf("Successfully refreshed and persisted access token (expires at %s)", refreshed.AccessTokenExpiresAt)
	return nil
}

func wrapWithDPoP(httpClient *http.Client, client *Client) *http.Client {
	return requestheaders.WrapWithDPoP(httpClient, func() (credentials.Identity, bool) {
		return client.identity()
	}, func() string {
		return client.tokenValue()
	}, func(ctx context.Context, oldToken string) error {
		return client.refreshCredentials(ctx, oldToken)
	})
}

func (c *Client) agentIDValue() string {
	c.agentMu.RLock()
	defer c.agentMu.RUnlock()
	return c.agentID
}

func (c *Client) rememberAgentID(agentID string) {
	if strings.TrimSpace(agentID) == "" {
		return
	}
	c.agentMu.Lock()
	if c.agentID == "" {
		c.agentID = agentID
	}
	c.agentMu.Unlock()
}

var processStartupID = uuid.NewString()

func New(config *flags_pkg.Config, store *runtimeconfig.Store) (*Client, error) {
	// A credential store holds the enrolled identity (from device-code login).
	// Open it first so an Agent started without CLI flags can load its persisted
	// endpoint, token, and agent ID automatically.
	credentialStore, credentialErr := credentials.Open(config.CredentialsFile)
	if credentialErr != nil {
		log.Printf("Enrolled identity unavailable; privileged delivery is disabled: %v", credentialErr)
		credentialStore = nil
	}

	var endpoint, token, agentID string
	if credentialStore != nil {
		if identity, ok := credentialStore.Identity(); ok && identity.AgentID != "" && identity.AccessToken != "" {
			endpoint = strings.TrimSpace(identity.Endpoint)
			token = strings.TrimSpace(identity.AccessToken)
			agentID = strings.TrimSpace(identity.AgentID)
		}
	}

	if endpoint == "" {
		endpoint = strings.TrimSpace(config.Endpoint)
	}
	if token == "" {
		token = strings.TrimSpace(config.Token)
	}

	if endpoint == "" || token == "" {
		path := config.CredentialsFile
		if path == "" {
			path = credentials.DefaultPath()
		}
		if credentialErr != nil {
			return nil, fmt.Errorf("%w; credentials file %s: %v", ErrUnconfigured, path, credentialErr)
		}
		return nil, fmt.Errorf("%w; no usable credentials at %s (login must use the same --credentials-file and service account)", ErrUnconfigured, path)
	}

	config.Endpoint = endpoint
	config.Token = token

	baseURL, err := connectBaseURL(endpoint)
	if err != nil {
		return nil, err
	}
	// A privileged state file that cannot be opened must not stop the Agent
	// from reporting: the settings in force are already the restrictive
	// default, and refusing to start would turn a storage problem into an
	// outage. The privileged watch is skipped instead.
	privilegedStore, privilegedErr := privileged.Open(config.PrivilegedStateFile)
	if privilegedErr != nil {
		log.Printf("Privileged configuration state unavailable; privileged delivery is disabled: %v", privilegedErr)
		privilegedStore = nil
	}
	if credentialStore == nil {
		privilegedStore = nil
	}
	if privilegedStore != nil {
		privileged.SetActive(privilegedStore)
	}
	c := &Client{
		startupID:       processStartupID,
		endpoint:        endpoint,
		token:           token,
		agentID:         agentID,
		store:           store,
		privilegedStore: privilegedStore,
		credentialStore: credentialStore,
		replayGuard:     signing.NewReplayGuard(config.ReplayStateFile),
		cfg:             config,
	}
	httpClient := dnsresolver.GetHTTPClientWithPreference(requestDeadline, config.PreferIPVersion)
	networkHTTPClient := dnsresolver.GetHTTPClientWithPreference(35*time.Second, config.PreferIPVersion)
	streamHTTPClient := dnsresolver.GetStreamingHTTPClientWithPreference(config.PreferIPVersion)

	c.host = hostv1connect.NewHostServiceClient(wrapWithDPoP(httpClient, c), baseURL)
	if config.ServiceManifestFile != "" {
		m, e := hostops.ReadManifest(config.ServiceManifestFile)
		if e == nil {
			c.hostPolicy, e = hostops.ReadPolicy(m)
			if e == nil {
				c.hostManifest = m
			}
		}
		if e != nil {
			log.Printf("Privileged v2 installation policy unavailable: %v", e)
		}
		if c.hostManifest != nil {
			trust, trustErr := hostops.ReadTrust(c.hostManifest)
			if trustErr == nil {
				if trust.AgentID != agentID || trust.Endpoint != endpoint {
					return nil, errors.New("enrollment identity differs from protected host trust")
				}
				c.hostTrust = trust
				if err := c.validatePersistedPrivileged(); err != nil {
					return nil, err
				}
			} else if !os.IsNotExist(trustErr) {
				return nil, fmt.Errorf("protected host trust invalid: %w", trustErr)
			}
		}
	}
	c.config = configv1connect.NewConfigServiceClient(wrapWithDPoP(streamHTTPClient, c), baseURL)
	c.privileged = configv1connect.NewPrivilegedDeliveryServiceClient(wrapWithDPoP(streamHTTPClient, c), baseURL)
	c.events = agentv1connect.NewAgentEventServiceClient(wrapWithDPoP(streamHTTPClient, c), baseURL)
	c.report = reportv1connect.NewAgentReportServiceClient(wrapWithDPoP(httpClient, c), baseURL)
	c.metrics = metricsv1connect.NewMetricsServiceClient(wrapWithDPoP(streamHTTPClient, c), baseURL)
	c.network = networkv1connect.NewNetworkProbeServiceClient(wrapWithDPoP(networkHTTPClient, c), baseURL)
	c.execution = execv1connect.NewExecutionServiceClient(wrapWithDPoP(streamHTTPClient, c), baseURL)
	c.webssh = websshv1connect.NewWebSSHServiceClient(wrapWithDPoP(streamHTTPClient, c), baseURL)
	c.files = filev1connect.NewFileServiceClient(wrapWithDPoP(streamHTTPClient, c), baseURL)

	return c, nil
}

func (c *Client) Run(ctx context.Context) error {
	// Startup trust bundle self-healing: ensure control plane keys are pinned
	_ = c.ensureTrustBundle(ctx)

	initPending := false
	if err := c.initializeHost(ctx); err != nil {
		initPending = true
		log.Printf("Host protocol/baseline initialization pending: %v", err)
	}
	// Startup is where a rejection is most expensive: returning an error here
	// sends the caller back through New + the whole handshake, so a panel that
	// is rate limiting or briefly refusing the token would be re-handshaked at
	// connection cadence indefinitely. Wait it out here instead, and only give
	// up on failures that genuinely need a fresh client.
	var startRetry retryPolicy
	for {
		err := c.SyncConfig(ctx)
		if err == nil {
			break
		}
		if isPermissionDenied(err) {
			log.Printf("[FATAL] Panel revoked credentials or permission was denied (HTTP 403 / PERMISSION_DENIED). Stopping. Please re-enroll via 'komari-agent login'")
			return classify(err)
		}
		if !isTransientRejection(err) {
			return classify(err)
		}
		logTransientRejection("configuration sync", err)
		if !startRetry.Wait(ctx, err) {
			return nil
		}
	}
	for {
		err := c.SubmitReport(ctx)
		if err == nil {
			break
		}
		if isPermissionDenied(err) {
			log.Printf("[FATAL] Panel revoked credentials or permission was denied (HTTP 403 / PERMISSION_DENIED). Stopping. Please re-enroll via 'komari-agent login'")
			return classify(err)
		}
		if !isTransientRejection(err) {
			return classify(err)
		}
		logTransientRejection("initial basic info report", err)
		if !startRetry.Wait(ctx, err) {
			return nil
		}
	}
	if err := c.publishAgentEvent(ctx, agentv1.AgentEventType_AGENT_EVENT_TYPE_STARTED, "Connect transport started"); err != nil && !isUnsupported(err) {
		log.Printf("Failed to publish Agent lifecycle event: %v", err)
	}
	probeCtx, stopProbes := context.WithCancel(ctx)
	c.setProbeCancel(stopProbes)

	var probes sync.WaitGroup
	start := func(worker func(context.Context)) {
		probes.Add(1)
		go func() {
			defer probes.Done()
			worker(probeCtx)
		}()
	}
	capabilities := capability.Detect(runtimeconfig.RemoteControlEnabled())
	if initPending {
		start(c.runHostInitialization)
	}
	start(c.runAgentEvents)
	start(c.runConfigUpdates)
	start(c.runReceiptOutbox)
	if c.privilegedStore != nil {
		start(c.runPrivilegedUpdates)
	}
	start(c.runPingProbes)
	start(c.runExecutions)
	start(c.runRemoteSessions)
	start(c.runFileOperations)
	if capabilities.ReturnRouteProbe != nil && capabilities.ReturnRouteProbe.Available {
		start(c.runReturnRouteProbes)
	}
	defer func() {
		c.setProbeCancel(nil)
		stopProbes()
		probes.Wait()
		if ctx.Err() == nil {
			return
		}
		shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), requestDeadline)
		defer shutdownCancel()
		if err := c.publishAgentEvent(shutdownCtx, agentv1.AgentEventType_AGENT_EVENT_TYPE_STOPPING, "Connect transport stopped"); err != nil && !isUnsupported(err) {
			log.Printf("Failed to publish Agent shutdown event: %v", err)
		}
	}()
	// Periodic metric batches are unary by default. Connect bidi streams require
	// end-to-end HTTP/2 support and can stall behind otherwise valid HTTP/3 or
	// HTTP/1.1 reverse proxies, while unary Connect works across all transports.
	return c.runUnaryMetricLoop(ctx)
}

func (c *Client) ensureTrustBundle(ctx context.Context) error {
	if c.credentialStore == nil {
		return nil
	}
	identity, ok := c.credentialStore.Identity()
	if !ok || identity.AgentID == "" {
		return nil
	}
	if len(identity.ControlPlaneKeys) > 0 {
		return nil
	}
	return c.fetchAndPinTrustBundle(ctx, identity.AgentID)
}

func (c *Client) fetchAndPinTrustBundle(ctx context.Context, agentID string) error {
	if c.credentialStore == nil {
		return nil
	}
	endpoint := c.endpoint
	if endpoint == "" && c.cfg != nil {
		endpoint = c.cfg.Endpoint
	}
	if endpoint == "" {
		if id, ok := c.credentialStore.Identity(); ok && id.Endpoint != "" {
			endpoint = id.Endpoint
		}
	}
	if endpoint == "" {
		return errors.New("cannot fetch trust bundle: empty endpoint")
	}
	enrollClient, err := enrollment.New(endpoint, nil)
	if err != nil {
		return err
	}
	fetchCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	keys, algorithms, requireAll, minimum, err := enrollClient.FetchTrustBundle(fetchCtx, agentID)
	if err != nil {
		return err
	}
	if len(keys) == 0 {
		return errors.New("control plane returned empty trust bundle")
	}
	if err := c.credentialStore.PinTrustBundle(keys, algorithms, requireAll, minimum); err != nil {
		return err
	}
	log.Printf("[SECURITY] Successfully self-healed and pinned %d control plane keys", len(keys))
	return nil
}

func (c *Client) runAgentEvents(ctx context.Context) {
	after := ""
	var retry retryPolicy
	for ctx.Err() == nil {
		req := connect.NewRequest(&agentv1.SubscribeEventsRequest{AgentId: c.agentIDValue(), AfterEventId: after})
		c.authorize(req.Header())
		stream, err := c.events.SubscribeEvents(ctx, req)
		if err != nil {
			if isUnsupported(err) || !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		received := false
		for stream.Receive() {
			received = true
			event := stream.Msg().Event
			if event == nil {
				continue
			}
			ackCtx, cancel := context.WithTimeout(ctx, requestDeadline)
			ack := connect.NewRequest(&agentv1.AcknowledgeEventRequest{AgentId: c.agentIDValue(), EventId: event.EventId})
			c.authorize(ack.Header())
			_, err := c.events.AcknowledgeEvent(ackCtx, ack)
			cancel()
			if err != nil {
				log.Printf("Failed to acknowledge Connect Agent event: %v", err)
				continue
			}
			after = event.EventId
		}
		// A subscription that delivered events was healthy; start the next
		// backoff from the base interval rather than from where the previous
		// failure streak left off.
		if received {
			retry.Reset()
		}
		if err := stream.Err(); err != nil && isUnsupported(err) {
			return
		}
		if !retry.Wait(ctx, stream.Err()) {
			return
		}
	}
}

func (c *Client) runConfigUpdates(ctx context.Context) {
	var retry retryPolicy
	for ctx.Err() == nil {
		req := connect.NewRequest(&configv1.WatchDesiredConfigRequest{
			AgentId: c.agentIDValue(), AfterRevision: c.store.Current().Revision,
		})
		c.authorize(req.Header())
		stream, err := c.config.WatchDesiredConfig(ctx, req)
		if err != nil {
			if isUnsupported(err) {
				c.runConfigPolling(ctx)
				return
			}
			if !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		received := false
		for stream.Receive() {
			received = true
			desired := stream.Msg().Desired
			if desired == nil {
				continue
			}
			if err := c.applyDesiredConfig(ctx, desired); err != nil {
				log.Printf("Failed to apply streamed Connect config: %v", err)
			}
		}
		if received {
			retry.Reset()
		}
		if err := stream.Err(); err != nil && isUnsupported(err) {
			c.runConfigPolling(ctx)
			return
		}
		if ctx.Err() != nil || !retry.Wait(ctx, stream.Err()) {
			return
		}
	}
}

// runPrivilegedUpdates follows approval changes, including changes to the same revision.
func (c *Client) runPrivilegedUpdates(ctx context.Context) {
	var retry retryPolicy
	var sequence uint64
	for ctx.Err() == nil {
		req := connect.NewRequest(&configv1.WatchPrivilegedDeliveryRequest{
			AgentId: c.agentIDValue(), ProtocolVersion: 2, AfterSequence: sequence,
		})
		c.authorize(req.Header())
		stream, err := c.privileged.WatchPrivilegedDelivery(ctx, req)
		if err != nil {
			// A panel without the privileged track is not an error: it simply
			// never delivers these, and retrying forever would log noise on
			// every older deployment.
			if isUnsupported(err) || !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		received := false
		for stream.Receive() {
			received = true
			revision := stream.Msg().GetRevision()
			if revision == nil {
				continue
			}
			c.rememberAgentID(revision.GetAgentId())
			if err := c.recordPrivilegedRevision(ctx, revision); err != nil {
				log.Printf("Failed to apply privileged revision %d: %v", revision.GetRevision(), err)
				sequence = 0
				stream.Close()
				break
			}
			sequence = stream.Msg().UpdateSequence
		}
		if received {
			retry.Reset()
		}
		if err := stream.Err(); err != nil && isUnsupported(err) {
			return
		}
		if ctx.Err() != nil || !retry.Wait(ctx, stream.Err()) {
			return
		}
	}
}

func (c *Client) runConfigPolling(ctx context.Context) {
	for ctx.Err() == nil {
		timer := time.NewTimer(configPollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if err := c.SyncConfig(ctx); err != nil {
			log.Printf("Failed to poll Connect config compatibility endpoint: %v", err)
		}
	}
}

func (c *Client) publishAgentEvent(parent context.Context, eventType agentv1.AgentEventType, message string) error {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	req := connect.NewRequest(&agentv1.PublishEventRequest{Event: &agentv1.AgentEvent{
		AgentId: c.agentIDValue(), EventId: uuid.NewString(), OccurredAt: timestamppb.Now(), Type: eventType, Message: message,
	}})
	c.authorize(req.Header())
	_, err := c.events.PublishEvent(ctx, req)
	return err
}

func (c *Client) runExecutions(ctx context.Context) {
	semaphore := make(chan struct{}, 4)
	var jobs sync.Map
	var retry retryPolicy
	for ctx.Err() == nil {
		if !waitForCapability(ctx, capability.ExecutionAllowed) {
			continue
		}
		req := connect.NewRequest(&execv1.LeaseExecutionRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		stream, err := c.execution.LeaseExecution(ctx, req)
		if err != nil {
			if isUnsupported(err) || !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		received := false
		for stream.Receive() {
			received = true
			message := stream.Msg()
			if cancellation := message.Cancellation; cancellation != nil {
				if value, ok := jobs.Load(cancellation.ExecutionId); ok {
					value.(context.CancelFunc)()
				}
				continue
			}
			assignment := message.Assignment
			if assignment == nil || assignment.Execution == nil || assignment.Envelope == nil {
				continue
			}
			if ok, _ := capability.ExecutionAllowed(); !ok {
				continue
			}
			spec, err := c.verifyExecutionAssignment(assignment)
			if err != nil {
				log.Printf("Rejecting execution %s signature/nonce: %v", assignment.Execution.ExecutionId, err)
				reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(ctx), requestDeadline)
				code := int32(-1)
				_, _ = c.reportExecutionEvent(reportCtx, &execv1.ExecutionEvent{
					ExecutionId: assignment.Execution.ExecutionId,
					Sequence:    1,
					OccurredAt:  timestamppb.Now(),
					State:       commonv1.OperationState_OPERATION_STATE_FAILED,
					ExitCode:    &code,
					Error: &commonv1.ErrorDetail{
						Code:    "SIGNATURE_VERIFICATION_FAILED",
						Message: err.Error(),
					},
				})
				reportCancel()
				continue
			}
			executionID := assignment.Execution.ExecutionId
			jobParent, jobCancel := context.WithCancel(ctx)
			if _, loaded := jobs.LoadOrStore(executionID, context.CancelFunc(jobCancel)); loaded {
				jobCancel()
				continue
			}
			go func() {
				defer jobs.Delete(executionID)
				defer jobCancel()
				select {
				case semaphore <- struct{}{}:
					defer func() { <-semaphore }()
				case <-jobParent.Done():
					if ctx.Err() == nil {
						reportCtx, reportCancel := context.WithTimeout(context.WithoutCancel(ctx), requestDeadline)
						code := int32(-1)
						_, _ = c.reportExecutionEvent(reportCtx, &execv1.ExecutionEvent{
							ExecutionId: executionID, Sequence: 1, OccurredAt: timestamppb.Now(),
							State: commonv1.OperationState_OPERATION_STATE_CANCELLED, ExitCode: &code,
						})
						reportCancel()
					}
					return
				}
				if err := c.executeAssignment(jobParent, assignment, spec); err != nil && ctx.Err() == nil {
					log.Printf("Connect execution %s failed: %v", executionID, err)
				}
			}()
		}
		if received {
			retry.Reset()
		}
		if err := stream.Err(); err != nil && isUnsupported(err) {
			return
		}
		if !retry.Wait(ctx, stream.Err()) {
			return
		}
	}
}

func (c *Client) verifyExecutionAssignment(assignment *execv1.ExecutionAssignment) (*execv1.ExecutionSpec, error) {
	if assignment == nil {
		return nil, errors.New("nil execution assignment")
	}
	envelope := assignment.GetEnvelope()
	if envelope == nil {
		return nil, errors.New("the panel sent an execution assignment without a SignedEnvelope")
	}
	identity, ok := c.identity()
	if !ok || len(identity.ControlPlaneKeys) == 0 {
		if err := c.ensureTrustBundle(context.Background()); err == nil {
			identity, ok = c.identity()
		}
	}
	if !ok || len(identity.ControlPlaneKeys) == 0 {
		return nil, errors.New("no panel signing keys are pinned; cannot verify signed execution assignment")
	}
	if identity.AgentID == "" {
		identity.AgentID = c.agentIDValue()
	}
	verifier := signing.New(identity, c.replayGuard)
	instruction, err := verifier.Verify(envelope)
	if err != nil {
		return nil, fmt.Errorf("verify execution envelope: %w", err)
	}
	if instruction.InstructionType != "exec:v1" {
		return nil, fmt.Errorf("the signature authorizes %q, not an execution instruction (exec:v1)", instruction.InstructionType)
	}
	var spec execv1.ExecutionSpec
	if err := proto.Unmarshal(instruction.Body, &spec); err != nil {
		return nil, fmt.Errorf("unmarshal execution spec from signed instruction body: %w", err)
	}
	return &spec, nil
}

func (c *Client) executeAssignment(parent context.Context, assignment *execv1.ExecutionAssignment, spec *execv1.ExecutionSpec) error {
	timeout := 5 * time.Minute
	if spec.Timeout != nil && spec.Timeout.CheckValid() == nil && spec.Timeout.AsDuration() > 0 {
		timeout = spec.Timeout.AsDuration()
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	var sequence uint64
	report := func(event *execv1.ExecutionEvent) error {
		candidate := sequence + 1
		event.ExecutionId = assignment.Execution.ExecutionId
		event.Sequence = candidate
		event.OccurredAt = timestamppb.Now()
		var err error
		for attempt := 0; attempt < 3; attempt++ {
			var accepted uint64
			accepted, err = c.reportExecutionEvent(ctx, event)
			if err == nil {
				sequence = max(candidate, accepted)
				return nil
			}
			if ctx.Err() != nil {
				break
			}
			timer := time.NewTimer(200 * time.Millisecond)
			select {
			case <-ctx.Done():
				timer.Stop()
				return ctx.Err()
			case <-timer.C:
			}
		}
		return err
	}
	if err := report(&execv1.ExecutionEvent{State: commonv1.OperationState_OPERATION_STATE_RUNNING}); err != nil {
		return err
	}
	exitCode, runErr := server.RunTypedExecution(ctx, spec, func(output server.ExecutionOutput) error {
		return report(&execv1.ExecutionEvent{State: commonv1.OperationState_OPERATION_STATE_RUNNING, Stream: output.Stream, Output: output.Data})
	})
	state := commonv1.OperationState_OPERATION_STATE_SUCCEEDED
	var detail *commonv1.ErrorDetail
	if runErr != nil {
		switch {
		case errors.Is(ctx.Err(), context.DeadlineExceeded):
			state = commonv1.OperationState_OPERATION_STATE_DEADLINE_EXCEEDED
		case errors.Is(ctx.Err(), context.Canceled):
			state = commonv1.OperationState_OPERATION_STATE_CANCELLED
		default:
			state = commonv1.OperationState_OPERATION_STATE_FAILED
		}
		detail = &commonv1.ErrorDetail{Code: state.String(), Message: runErr.Error()}
	}
	code := int32(exitCode)
	terminalCtx, terminalCancel := context.WithTimeout(context.WithoutCancel(parent), requestDeadline)
	defer terminalCancel()
	event := &execv1.ExecutionEvent{State: state, ExitCode: &code, Error: detail}
	for attempt := 0; attempt < 3; attempt++ {
		candidate := sequence + 1
		event.ExecutionId = assignment.Execution.ExecutionId
		event.Sequence = candidate
		event.OccurredAt = timestamppb.Now()
		accepted, err := c.reportExecutionEvent(terminalCtx, event)
		if err == nil {
			sequence = max(candidate, accepted)
			return nil
		}
		if terminalCtx.Err() != nil {
			return err
		}
	}
	return errors.New("failed to report terminal execution state")
}

func (c *Client) reportExecutionEvent(parent context.Context, event *execv1.ExecutionEvent) (uint64, error) {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	req := connect.NewRequest(&execv1.ReportExecutionEventRequest{AgentId: c.agentIDValue(), Event: event})
	c.authorize(req.Header())
	response, err := c.execution.ReportExecutionEvent(ctx, req)
	if err != nil {
		return 0, err
	}
	return response.Msg.AcceptedSequence, nil
}

func (c *Client) runRemoteSessions(ctx context.Context) {
	semaphore := make(chan struct{}, 4)
	var retry retryPolicy
	for ctx.Err() == nil {
		if !waitForCapability(ctx, capability.WebSSHAllowed) {
			continue
		}
		req := connect.NewRequest(&websshv1.LeaseSessionsRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		req.Header().Set("X-Komari-Workspace-Identity", "v1")
		stream, err := c.webssh.LeaseSessions(ctx, req)
		if err != nil {
			if isUnsupported(err) || !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		received := false
		for stream.Receive() {
			received = true
			assignment := stream.Msg().Assignment
			if assignment == nil {
				continue
			}
			if ok, _ := capability.WebSSHAllowed(); !ok {
				continue
			}
			select {
			case semaphore <- struct{}{}:
				go func() {
					defer func() { <-semaphore }()
					if err := c.attachRemoteSession(ctx, assignment); err != nil && ctx.Err() == nil {
						log.Printf("Remote session failed: %v", err)
					}
				}()
			case <-ctx.Done():
				return
			}
		}
		if received {
			retry.Reset()
		}
		if err := stream.Err(); err != nil && isUnsupported(err) {
			return
		}
		if !retry.Wait(ctx, stream.Err()) {
			return
		}
	}
}

func (c *Client) attachRemoteSession(ctx context.Context, assignment *websshv1.SessionAssignment) error {
	cols, rows := 80, 24
	if assignment.Size != nil {
		cols, rows = int(assignment.Size.Columns), int(assignment.Size.Rows)
	}
	pty, err := terminal.OpenSessionAs(cols, rows, assignment.GetSystemUser(), assignment.GetShell(), assignment.GetWorkingDirectory())
	if err != nil {
		failed := c.webssh.AttachSession(ctx)
		c.authorize(failed.RequestHeader())
		failed.RequestHeader().Set("X-Komari-Workspace-Identity", "v1")
		if attachErr := failed.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Attach{Attach: &websshv1.AgentSessionAttach{AgentId: c.agentIDValue(), AssignmentId: assignment.AssignmentId, SessionId: assignment.SessionId}}}); attachErr == nil {
			_ = failed.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Event{Event: &websshv1.AgentSessionEvent{Sequence: 1, Event: &websshv1.AgentSessionEvent_Closed{Closed: &websshv1.SessionClosed{SessionId: assignment.SessionId, Reason: websshv1.CloseReason_CLOSE_REASON_FAILED, ClosedAt: timestamppb.Now()}}}}})
		}
		_ = failed.CloseRequest()
		_ = failed.CloseResponse()
		return err
	}
	defer pty.Close()
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go capability.CancelOnRevocation(sessionCtx, cancel, capability.WebSSHAllowed)
	stream := c.webssh.AttachSession(sessionCtx)
	c.authorize(stream.RequestHeader())
	stream.RequestHeader().Set("X-Komari-Workspace-Identity", "v1")
	if err := stream.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Attach{Attach: &websshv1.AgentSessionAttach{
		AgentId: c.agentIDValue(), AssignmentId: assignment.AssignmentId, SessionId: assignment.SessionId,
	}}}); err != nil {
		return err
	}
	type outbound struct {
		event *websshv1.AgentSessionEvent
	}
	outboundEvents := make(chan outbound, 32)
	sendErr := make(chan error, 1)
	var accepted atomic.Uint64
	go func() {
		var sequence uint64
		for {
			var message outbound
			select {
			case message = <-outboundEvents:
			case <-sessionCtx.Done():
				return
			}
			message.event.AcceptedCommandSequence = accepted.Load()
			if message.event.Event != nil {
				sequence++
				message.event.Sequence = sequence
				message.event.OccurredAt = timestamppb.Now()
			}
			if err := stream.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Event{Event: message.event}}); err != nil {
				sendErr <- err
				return
			}
		}
	}()
	go func() {
		buffer := make([]byte, 32<<10)
		for {
			n, err := pty.Read(buffer)
			if n > 0 {
				data := append([]byte(nil), buffer[:n]...)
				select {
				case outboundEvents <- outbound{event: &websshv1.AgentSessionEvent{Event: &websshv1.AgentSessionEvent_Output{Output: data}}}:
				case <-sessionCtx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	go func() {
		err := pty.Wait()
		reason := websshv1.CloseReason_CLOSE_REASON_NORMAL
		var exitCode *int32
		if err != nil {
			reason = websshv1.CloseReason_CLOSE_REASON_FAILED
			code := int32(-1)
			exitCode = &code
		}
		closed := &websshv1.AgentSessionEvent{Event: &websshv1.AgentSessionEvent_Closed{Closed: &websshv1.SessionClosed{
			SessionId: assignment.SessionId, Reason: reason, ExitCode: exitCode, ClosedAt: timestamppb.Now(),
		}}}
		select {
		case outboundEvents <- outbound{event: closed}:
		case <-sessionCtx.Done():
		}
	}()
	for {
		response, err := stream.Receive()
		if err != nil {
			return err
		}
		if ok, reason := capability.WebSSHAllowed(); !ok {
			return fmt.Errorf("WebSSH authorization withdrawn: %s", reason)
		}
		switch command := response.Command.(type) {
		case *websshv1.AttachSessionResponse_Input:
			_, err = pty.Write(command.Input)
		case *websshv1.AttachSessionResponse_Resize:
			if command.Resize != nil {
				err = pty.Resize(int(command.Resize.Columns), int(command.Resize.Rows))
			}
		case *websshv1.AttachSessionResponse_File:
			err = errors.New("terminal file commands are disabled; use the account-isolated FileService")
		case *websshv1.AttachSessionResponse_CloseReason:
			return nil
		default:
			err = errors.New("empty remote session command")
		}
		if err != nil {
			return err
		}
		accepted.Store(response.Sequence)
		select {
		case outboundEvents <- outbound{event: &websshv1.AgentSessionEvent{}}:
		case err := <-sendErr:
			return err
		case <-sessionCtx.Done():
			return sessionCtx.Err()
		}
	}
}

func isUnsupported(err error) bool {
	var connectErr *connect.Error
	return errors.As(err, &connectErr) && (connectErr.Code() == connect.CodeUnimplemented || connectErr.Code() == connect.CodeNotFound)
}

func (c *Client) runPingProbes(ctx context.Context) {
	var retry retryPolicy
	for ctx.Err() == nil {
		leaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req := connect.NewRequest(&networkv1.LeasePingProbeRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		response, err := c.network.LeasePingProbe(leaseCtx, req)
		cancel()
		if err != nil {
			if isUnsupported(err) {
				return
			}
			if !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		retry.Reset()
		assignment := response.Msg.Assignment
		if assignment == nil {
			// A lease normally long-polls. If a proxy or server returns an empty
			// lease immediately, avoid turning it into a busy request loop.
			if !retry.Wait(ctx, nil) {
				return
			}
			continue
		}
		timeout := 3 * time.Second
		if assignment.Timeout != nil {
			if err := assignment.Timeout.CheckValid(); err == nil && assignment.Timeout.AsDuration() > 0 {
				timeout = assignment.Timeout.AsDuration()
			}
		}
		latency := server.ProbePing(assignment.Protocol, assignment.Target, timeout)
		reportCtx, reportCancel := context.WithTimeout(ctx, requestDeadline)
		report := connect.NewRequest(&networkv1.SubmitPingProbeResultRequest{
			AgentId: c.agentIDValue(), AssignmentId: assignment.AssignmentId, TaskId: assignment.TaskId,
			Protocol: assignment.Protocol, LatencyMs: latency, FinishedAt: timestamppb.Now(),
		})
		c.authorize(report.Header())
		_, reportErr := c.network.SubmitPingProbeResult(reportCtx, report)
		reportCancel()
		if reportErr != nil {
			log.Printf("Failed to submit ping result: %v", reportErr)
		}
	}
}

func (c *Client) runReturnRouteProbes(ctx context.Context) {
	var retry retryPolicy
	for ctx.Err() == nil {
		leaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req := connect.NewRequest(&networkv1.LeaseReturnRouteProbeRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		response, err := c.network.LeaseReturnRouteProbe(leaseCtx, req)
		cancel()
		if err != nil {
			if isUnsupported(err) {
				return
			}
			if !retry.Wait(ctx, err) {
				return
			}
			continue
		}
		retry.Reset()
		assignment := response.Msg.Assignment
		if assignment == nil {
			if !retry.Wait(ctx, nil) {
				return
			}
			continue
		}
		hops, probeErr := server.ProbeReturnRoute(ctx, assignment)
		result := &networkv1.SubmitReturnRouteProbeResultRequest{
			AgentId: c.agentIDValue(), AssignmentId: assignment.AssignmentId, TaskId: assignment.TaskId,
			Hops: hops, FinishedAt: timestamppb.Now(),
		}
		if probeErr != nil {
			result.Error = probeErr.Error()
		}
		reportCtx, reportCancel := context.WithTimeout(ctx, requestDeadline)
		report := connect.NewRequest(result)
		c.authorize(report.Header())
		_, reportErr := c.network.SubmitReturnRouteProbeResult(reportCtx, report)
		reportCancel()
		if reportErr != nil {
			log.Printf("Failed to submit return route result: %v", reportErr)
		}
	}
}

// waitRetry paces a single one-off retry at the operator's reconnect interval
// with jitter. Loops that can fail repeatedly own a retryPolicy instead, so
// their delay grows and they honour a server's Retry-After.
func waitRetry(ctx context.Context) bool {
	timer := time.NewTimer(jitter(baseInterval()))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *Client) SubmitMetrics(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	report := monitoring.CollectReport()
	req := connect.NewRequest(&metricsv1.SubmitMetricsRequest{AgentId: c.agentIDValue(), Sequence: c.sequence.Add(1), Points: report.Metrics(time.Now().UTC())})
	c.authorize(req.Header())
	response, err := c.metrics.SubmitMetrics(ctx, req)
	if err == nil {
		c.advanceSequence(response.Msg.AcceptedSequence)
	}
	return err
}

func (c *Client) advanceSequence(accepted uint64) {
	for {
		current := c.sequence.Load()
		if accepted <= current || c.sequence.CompareAndSwap(current, accepted) {
			return
		}
	}
}

func (c *Client) runMetricStream(ctx context.Context) error {
	var pending *metricsv1.SubmitMetricsRequest
	var streamRetry retryPolicy
	infoInterval := time.Duration(max(flags_pkg.GlobalConfig.InfoReportInterval, 1)) * time.Minute
	nextInfoReport := time.Now().Add(infoInterval)
	for ctx.Err() == nil {
		stream := c.metrics.StreamMetrics(ctx)
		c.authorize(stream.RequestHeader())
		var streamErr error
		for ctx.Err() == nil {
			if pending == nil {
				report := monitoring.CollectReport()
				pending = &metricsv1.SubmitMetricsRequest{
					AgentId:  c.agentIDValue(),
					Sequence: c.sequence.Add(1),
					Points:   report.Metrics(time.Now().UTC()),
				}
			}
			if err := stream.Send(&metricsv1.StreamMetricsRequest{Batch: pending}); err != nil {
				_, receiveErr := stream.Receive()
				if receiveErr != nil {
					streamErr = receiveErr
				} else {
					streamErr = err
				}
				break
			}
			ack, err := stream.Receive()
			if err != nil {
				streamErr = err
				break
			}
			if ack.AcceptedSequence < pending.Sequence {
				streamErr = fmt.Errorf("metrics ACK sequence %d is behind sent sequence %d", ack.AcceptedSequence, pending.Sequence)
				break
			}
			c.advanceSequence(ack.AcceptedSequence)
			// The stream is delivering. A later interruption starts its backoff
			// from the base interval rather than from an earlier failure streak.
			streamRetry.Reset()
			pending = nil
			if !time.Now().Before(nextInfoReport) {
				if streamErr = c.SubmitReport(ctx); streamErr != nil {
					break
				}
				nextInfoReport = time.Now().Add(infoInterval)
			}
			interval := runtimeconfig.Current().ReportInterval
			if interval <= 0 {
				interval = 3 * time.Second
			}
			timer := time.NewTimer(interval)
			select {
			case <-ctx.Done():
				timer.Stop()
				streamErr = ctx.Err()
			case <-timer.C:
			}
			if streamErr != nil {
				break
			}
		}
		_ = stream.CloseRequest()
		_ = stream.CloseResponse()
		if ctx.Err() != nil {
			return nil
		}
		if isUnsupported(streamErr) {
			return c.runUnaryMetricLoop(ctx)
		}
		if streamErr != nil {
			log.Printf("Connect metrics stream interrupted: %v", streamErr)
		}
		if !streamRetry.Wait(ctx, streamErr) {
			return nil
		}
	}
	return nil
}

func (c *Client) runUnaryMetricLoop(ctx context.Context) error {
	infoInterval := time.Duration(max(flags_pkg.GlobalConfig.InfoReportInterval, 1)) * time.Minute
	nextInfoReport := time.Now().Add(infoInterval)
	var retry retryPolicy
	for {
		if err := c.SubmitMetrics(ctx); err != nil {
			if isPermissionDenied(err) {
				log.Printf("[FATAL] Panel revoked credentials or permission was denied (HTTP 403 / PERMISSION_DENIED). Stopping all probes and polling. Please re-enroll via 'komari-agent login'")
				c.cancelProbes()
				return classify(err)
			}
			if isAuthRejection(err) {
				oldToken := c.tokenValue()
				if refreshErr := c.refreshCredentials(ctx, oldToken); refreshErr != nil {
					log.Printf("Credential refresh failed after auth rejection: %v", refreshErr)
					if isPermissionDenied(refreshErr) {
						log.Printf("[FATAL] Panel revoked credentials during refresh (HTTP 403 / PERMISSION_DENIED). Stopping all probes and polling.")
						c.cancelProbes()
						return classify(refreshErr)
					}
					if isAuthRejection(refreshErr) || errors.Is(refreshErr, context.Canceled) {
						return classify(refreshErr)
					}
					if c.credentialStore == nil || !c.credentialStore.Enrolled() {
						return classify(err)
					}
				} else {
					if err := c.SubmitMetrics(ctx); err == nil {
						retry.Reset()
						goto metricsDone
					}
				}
			}
			if !isTransientRejection(err) {
				return classify(err)
			}
			logTransientRejection("metric submission", err)
			if !retry.Wait(ctx, err) {
				return nil
			}
			continue
		}
	metricsDone:
		if !time.Now().Before(nextInfoReport) {
			if err := c.SubmitReport(ctx); err != nil {
				if isPermissionDenied(err) {
					log.Printf("[FATAL] Panel revoked credentials or permission was denied (HTTP 403 / PERMISSION_DENIED). Stopping all probes and polling. Please re-enroll via 'komari-agent login'")
					c.cancelProbes()
					return classify(err)
				}
				if isAuthRejection(err) {
					oldToken := c.tokenValue()
					if refreshErr := c.refreshCredentials(ctx, oldToken); refreshErr != nil {
						log.Printf("Credential refresh failed after auth rejection: %v", refreshErr)
						if isPermissionDenied(refreshErr) {
							log.Printf("[FATAL] Panel revoked credentials during refresh (HTTP 403 / PERMISSION_DENIED). Stopping all probes and polling.")
							c.cancelProbes()
							return classify(refreshErr)
						}
						if isAuthRejection(refreshErr) || errors.Is(refreshErr, context.Canceled) {
							return classify(refreshErr)
						}
						if c.credentialStore == nil || !c.credentialStore.Enrolled() {
							return classify(err)
						}
					} else {
						if err := c.SubmitReport(ctx); err == nil {
							nextInfoReport = time.Now().Add(infoInterval)
							retry.Reset()
							goto reportDone
						}
					}
				}
				if !isTransientRejection(err) {
					return classify(err)
				}
				logTransientRejection("basic info report", err)
				if !retry.Wait(ctx, err) {
					return nil
				}
				continue
			}
			nextInfoReport = time.Now().Add(infoInterval)
		}
	reportDone:
		retry.Reset()
		interval := runtimeconfig.Current().ReportInterval
		if interval <= 0 {
			interval = 3 * time.Second
		}
		timer := time.NewTimer(interval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case <-timer.C:
		}
	}
}

// logTransientRejection reports a rejection or network failure the Agent is riding out,
// naming the reason so an operator reading Agent logs can tell rate limits, auth errors,
// and transport interruptions apart.
func logTransientRejection(what string, err error) {
	switch {
	case isRateLimited(err):
		log.Printf("Panel is rate limiting %s; backing off: %v", what, err)
	case isAuthRejection(err):
		log.Printf("Panel rejected %s credential; backing off pending token recovery: %v", what, err)
	default:
		log.Printf("Panel %s transport failure; backing off: %v", what, err)
	}
}

func (c *Client) SubmitReport(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	report := monitoring.CollectReport().Proto(c.agentIDValue(), c.sequence.Add(1))
	report.Metadata.Installation = installation.Observe(c.cfg, c.startupID, report.Metadata.GetCapabilities().GetPrivilegeMode())
	req := connect.NewRequest(&reportv1.SubmitReportRequest{Report: report})
	c.authorize(req.Header())
	_, err := c.report.SubmitReport(ctx, req)
	return err
}

func (c *Client) SyncConfig(parent context.Context) error {
	c.runtimeSyncMu.Lock()
	defer c.runtimeSyncMu.Unlock()
	ctx, cancel := context.WithTimeout(parent, configDeadline)
	defer cancel()
	after := c.store.Current().Revision
	if !c.runtimeReconciled {
		// Revision equality from a persisted file is not a current-startup ACK.
		after = 0
	}
	req := connect.NewRequest(&configv1.GetDesiredConfigRequest{AgentId: c.agentIDValue(), AppliedRevision: after})
	c.authorize(req.Header())
	response, err := c.config.GetDesiredConfig(ctx, req)
	if err != nil || response.Msg.Desired == nil {
		return err
	}
	c.rememberAgentID(response.Msg.Desired.AgentId)
	if err := c.applyDesiredConfig(parent, response.Msg.Desired); err != nil {
		return err
	}
	c.runtimeReconciled = true
	return nil
}

func (c *Client) applyDesiredConfig(parent context.Context, desired *configv1.DesiredConfig) error {
	if desired == nil {
		return nil
	}
	c.rememberAgentID(desired.AgentId)
	ack := &configv1.AcknowledgeConfigRequest{AgentId: c.agentIDValue(), Revision: desired.Revision, Status: configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_APPLIED, FinishedAt: timestamppb.Now()}
	payload, err := proto.Marshal(ack)
	if err != nil {
		return err
	}
	_, applyErr := c.store.ApplyWithReceipt(desired, payload)
	if applyErr != nil {
		log.Printf("Runtime configuration revision %d rejected: %v", desired.Revision, applyErr)
		ack.Status = configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_REJECTED
		ack.Errors = []*commonv1.ErrorDetail{{Code: "CONFIG_REJECTED", Message: applyErr.Error()}}
		payload, err = proto.Marshal(ack)
		if err != nil {
			return err
		}
		if err = c.store.QueueReceipt(payload); err != nil {
			return err
		}
	}
	if err := c.flushReceipts(parent); err != nil {
		return err
	}
	if applyErr == nil {
		log.Printf("Runtime configuration revision %d validated against panel snapshot and loaded", desired.Revision)
	}
	return nil
}

func (c *Client) authorize(headers http.Header) {
	requestheaders.ApplyAgentAuthentication(headers, c.tokenValue(), flags_pkg.GlobalConfig.CFAccessClientID, flags_pkg.GlobalConfig.CFAccessClientSecret)
}

func connectBaseURL(endpoint string) (string, error) {
	value := strings.TrimSpace(endpoint)
	if value == "" {
		return "", errors.New("Connect endpoint is required")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", fmt.Errorf("invalid Connect endpoint %q", endpoint)
	}
	return strings.TrimRight(parsed.String(), "/"), nil
}

func classify(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if isPermissionDenied(err) {
		return fmt.Errorf("%w: %v", ErrPermissionDenied, err)
	}
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		switch connectErr.Code() {
		case connect.CodeUnavailable, connect.CodeUnimplemented:
			return fmt.Errorf("%w: %v", ErrLegacyFallback, err)
		default:
			return err
		}
	}
	var urlErr *url.Error
	var networkErr net.Error
	if errors.As(err, &urlErr) || errors.As(err, &networkErr) {
		return fmt.Errorf("%w: %v", ErrLegacyFallback, err)
	}
	return err
}

func isPermissionDenied(err error) bool {
	var connectErr *connect.Error
	if errors.As(err, &connectErr) {
		return connectErr.Code() == connect.CodePermissionDenied
	}
	return false
}
