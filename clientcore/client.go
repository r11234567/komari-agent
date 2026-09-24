// Package clientcore owns the Agent's Connect transport. Legacy v1/v2 remains
// outside this package and is selected only when the Connect endpoint is absent
// or the transport cannot be reached.
package clientcore

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/credentials"
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

var ErrLegacyFallback = errors.New("Connect transport is unavailable; use legacy compatibility transport")

type Client struct {
	config     configv1connect.ConfigServiceClient
	privileged configv1connect.PrivilegedDeliveryServiceClient
	events     agentv1connect.AgentEventServiceClient
	report     reportv1connect.AgentReportServiceClient
	metrics    metricsv1connect.MetricsServiceClient
	network    networkv1connect.NetworkProbeServiceClient
	execution  execv1connect.ExecutionServiceClient
	webssh     websshv1connect.WebSSHServiceClient
	token      string
	agentMu    sync.RWMutex
	agentID    string
	sequence   atomic.Uint64
	store      *runtimeconfig.Store
	// privilegedStore records privileged revisions without applying them. The
	// Agent only ever writes a pending revision here; promoting it is an
	// explicit local decision made through the CLI.
	privilegedStore *privileged.Store
	// credentialStore holds the enrolled identity, including the panel signing
	// keys this Agent pinned. It is what makes a delivered instruction
	// attributable rather than merely well-formed.
	credentialStore *credentials.Store
	// replayGuard remembers which instruction nonces were already carried out,
	// persisted so a restart cannot reopen the window.
	replayGuard *signing.ReplayGuard
}

// identity returns the enrolled identity, if this Agent has one.
func (c *Client) identity() (credentials.Identity, bool) {
	if c.credentialStore == nil {
		return credentials.Identity{}, false
	}
	return c.credentialStore.Identity()
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

func New(config *flags_pkg.Config, store *runtimeconfig.Store) (*Client, error) {
	if strings.TrimSpace(config.Endpoint) == "" || strings.TrimSpace(config.Token) == "" {
		return nil, ErrLegacyFallback
	}
	baseURL, err := connectBaseURL(config.Endpoint)
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
	// A credential store that will not open leaves the Agent unable to verify
	// which panel composed an instruction, so the privileged watch is disabled
	// rather than run without attribution.
	credentialStore, credentialErr := credentials.Open(config.CredentialsFile)
	if credentialErr != nil {
		log.Printf("Enrolled identity unavailable; privileged delivery is disabled: %v", credentialErr)
		credentialStore = nil
		privilegedStore = nil
	}
	httpClient := dnsresolver.GetHTTPClientWithPreference(requestDeadline, config.PreferIPVersion)
	networkHTTPClient := dnsresolver.GetHTTPClientWithPreference(35*time.Second, config.PreferIPVersion)
	streamHTTPClient := dnsresolver.GetStreamingHTTPClientWithPreference(config.PreferIPVersion)
	return &Client{
		// WatchDesiredConfig is a durable server stream. It must not inherit the
		// unary client's whole-request timeout, otherwise the Agent disconnects
		// a healthy configuration watch every requestDeadline.
		config:     configv1connect.NewConfigServiceClient(streamHTTPClient, baseURL),
		privileged: configv1connect.NewPrivilegedDeliveryServiceClient(streamHTTPClient, baseURL),
		events:     agentv1connect.NewAgentEventServiceClient(streamHTTPClient, baseURL),
		report:     reportv1connect.NewAgentReportServiceClient(httpClient, baseURL),
		metrics:    metricsv1connect.NewMetricsServiceClient(streamHTTPClient, baseURL),
		network:    networkv1connect.NewNetworkProbeServiceClient(networkHTTPClient, baseURL),
		execution:  execv1connect.NewExecutionServiceClient(streamHTTPClient, baseURL),
		webssh:     websshv1connect.NewWebSSHServiceClient(streamHTTPClient, baseURL),
		token:      config.Token, store: store,
		privilegedStore: privilegedStore,
		credentialStore: credentialStore,
		replayGuard:     signing.NewReplayGuard(config.ReplayStateFile),
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
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
	var probes sync.WaitGroup
	start := func(worker func(context.Context)) {
		probes.Add(1)
		go func() {
			defer probes.Done()
			worker(probeCtx)
		}()
	}
	capabilities := capability.Detect(runtimeconfig.RemoteControlEnabled())
	start(c.runAgentEvents)
	start(c.runConfigUpdates)
	if c.privilegedStore != nil {
		start(c.runPrivilegedUpdates)
	}
	start(c.runPingProbes)
	if capabilities.Execution != nil && capabilities.Execution.Available {
		start(c.runExecutions)
	}
	if capabilities.Webssh != nil && capabilities.Webssh.Available {
		start(c.runRemoteSessions)
	}
	if capabilities.ReturnRouteProbe != nil && capabilities.ReturnRouteProbe.Available {
		start(c.runReturnRouteProbes)
	}
	defer func() {
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

// runPrivilegedUpdates records privileged revisions delivered by the panel.
//
// This loop deliberately never applies anything. Its whole job is to persist
// what was delivered so an operator on the host can see a pending change and
// decide about it through the CLI. An Agent that applied these on receipt
// would let whoever controls the panel widen privileges on every machine at
// once, which is the failure this separation exists to prevent.
func (c *Client) runPrivilegedUpdates(ctx context.Context) {
	var retry retryPolicy
	for ctx.Err() == nil {
		req := connect.NewRequest(&configv1.WatchPrivilegedDeliveryRequest{
			AgentId: c.agentIDValue(), AfterRevision: c.privilegedStore.State().AppliedRevision,
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
				log.Printf("Failed to record privileged revision %d: %v", revision.GetRevision(), err)
			}
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

// recordPrivilegedRevision stores a delivered revision and reports the state
// it is waiting in.
//
// An automatic class is reported as failed rather than applied. The panel
// classifies, but these settings are privileged by construction, so a
// revision claiming it needs no human is a classification the Agent must not
// honour: doing so would turn the panel's mistake into a silent privilege
// grant.
func (c *Client) recordPrivilegedRevision(parent context.Context, revision *configv1.PrivilegedRevision) error {
	state := configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_CONFIRMATION
	var detail *commonv1.ErrorDetail

	// Verification happens before the revision is stored. A revision that
	// cannot be attributed to the panel this Agent enrolled with is refused
	// outright rather than recorded as pending: leaving it visible to the
	// operator would invite them to approve something nobody vouched for.
	if err := c.verifyPrivilegedRevision(revision); err != nil {
		return c.reportPrivilegedState(parent, revision.GetRevision(),
			configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_FAILED,
			&commonv1.ErrorDetail{Code: "PRIVILEGED_SIGNATURE_REJECTED", Message: err.Error()})
	}

	recordErr := c.privilegedStore.RecordPending(revision)
	switch {
	case recordErr != nil:
		state = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_FAILED
		detail = &commonv1.ErrorDetail{Code: "PRIVILEGED_REJECTED", Message: recordErr.Error()}
	case revision.GetPlan().GetUpgradeClass() == configv1.UpgradeClass_UPGRADE_CLASS_AUTOMATIC:
		state = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_FAILED
		detail = &commonv1.ErrorDetail{
			Code:    "PRIVILEGED_REQUIRES_LOCAL_APPROVAL",
			Message: "privileged settings are never applied automatically; run komari-agent upgrade on the host",
		}
	case revision.GetPlan().GetUpgradeClass() == configv1.UpgradeClass_UPGRADE_CLASS_MANUAL_PRIVILEGED:
		state = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_MANUAL_AUTHORIZATION
	}

	if err := c.reportPrivilegedState(parent, revision.GetRevision(), state, detail); err != nil {
		return err
	}
	if recordErr != nil {
		return recordErr
	}
	return nil
}

// reportPrivilegedState tells the panel which state a revision is waiting in.
func (c *Client) reportPrivilegedState(parent context.Context, revision uint64, state configv1.PrivilegedDeliveryState, detail *commonv1.ErrorDetail) error {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	report := connect.NewRequest(&configv1.ReportPrivilegedDeliveryRequest{
		AgentId:             c.agentIDValue(),
		Revision:            revision,
		State:               state,
		FinishedAt:          timestamppb.Now(),
		ActivePrivilegeMode: capability.Detect(runtimeconfig.RemoteControlEnabled()).GetPrivilegeMode(),
	})
	if detail != nil {
		report.Msg.Errors = []*commonv1.ErrorDetail{detail}
	}
	c.authorize(report.Header())
	if _, err := c.privileged.ReportPrivilegedDelivery(ctx, report); err != nil && !isUnsupported(err) {
		return err
	}
	return nil
}

// verifyPrivilegedRevision establishes that the panel composed this revision.
//
// The check is skipped only when no keys are pinned, which is the state of an
// Agent enrolled against a panel that does not sign yet. That is a deliberate
// migration allowance, not a fallback: once an Agent has pinned a key it will
// never again act on an unsigned revision, so a stripped signature cannot
// downgrade a configured Agent.
func (c *Client) verifyPrivilegedRevision(revision *configv1.PrivilegedRevision) error {
	identity, ok := c.identity()
	if !ok || len(identity.ControlPlaneKeys) == 0 {
		return nil
	}
	envelope := revision.GetSignature()
	if envelope == nil {
		return errors.New("the panel sent a privileged revision without a signature, but this Agent has pinned signing keys")
	}
	verifier := signing.New(identity, c.replayGuard)
	instruction, err := verifier.Verify(envelope)
	if err != nil {
		return err
	}
	// The signature covers an instruction, and that instruction has to be
	// about this revision. Without this a valid signature over revision 3
	// would authorize revision 4.
	if instruction.InstructionType != privilegedInstructionType {
		return fmt.Errorf("the signature authorizes %q, not a privileged configuration change", instruction.InstructionType)
	}
	if !bytes.Equal(instruction.Body, privilegedRevisionBody(revision)) {
		return errors.New("the signature does not match the delivered privileged configuration")
	}
	return nil
}

// privilegedInstructionType names what a privileged revision signature covers.
const privilegedInstructionType = "komari.config.v1.PrivilegedRevision"

// privilegedRevisionBody is the canonical bytes a signature commits to.
//
// The settings and the revision number are covered, so neither the contents
// nor the ordering can be altered under a valid signature. Deterministic
// marshalling matters here: protobuf field ordering is not guaranteed
// otherwise, and a re-serialization that differed would reject a legitimate
// revision.
func privilegedRevisionBody(revision *configv1.PrivilegedRevision) []byte {
	body := &configv1.PrivilegedRevision{
		AgentId:    revision.GetAgentId(),
		Revision:   revision.GetRevision(),
		Privileged: revision.GetPrivileged(),
		Plan:       revision.GetPlan(),
	}
	encoded, err := proto.MarshalOptions{Deterministic: true}.Marshal(body)
	if err != nil {
		return nil
	}
	return encoded
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
			if assignment == nil || assignment.Execution == nil || assignment.Spec == nil {
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
				if err := c.executeAssignment(jobParent, assignment); err != nil && ctx.Err() == nil {
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

func (c *Client) executeAssignment(parent context.Context, assignment *execv1.ExecutionAssignment) error {
	timeout := 5 * time.Minute
	if assignment.Spec.Timeout != nil && assignment.Spec.Timeout.CheckValid() == nil && assignment.Spec.Timeout.AsDuration() > 0 {
		timeout = assignment.Spec.Timeout.AsDuration()
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
	exitCode, runErr := server.RunTypedExecution(ctx, assignment.Spec, func(output server.ExecutionOutput) error {
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
		req := connect.NewRequest(&websshv1.LeaseSessionsRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
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
	pty, err := terminal.OpenSession(cols, rows)
	if err != nil {
		return err
	}
	defer pty.Close()
	sessionCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stream := c.webssh.AttachSession(sessionCtx)
	c.authorize(stream.RequestHeader())
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
	files := terminal.NewFileManager(sessionCtx, func(event *websshv1.FileEvent) error {
		select {
		case outboundEvents <- outbound{event: &websshv1.AgentSessionEvent{Event: &websshv1.AgentSessionEvent_File{File: event}}}:
			return nil
		case <-sessionCtx.Done():
			return sessionCtx.Err()
		}
	})
	defer files.Close()
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
		switch command := response.Command.(type) {
		case *websshv1.AttachSessionResponse_Input:
			_, err = pty.Write(command.Input)
		case *websshv1.AttachSessionResponse_Resize:
			if command.Resize != nil {
				err = pty.Resize(int(command.Resize.Columns), int(command.Resize.Rows))
			}
		case *websshv1.AttachSessionResponse_File:
			err = files.Handle(command.File)
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
		// A rejection that says "later" or "your credential was not accepted
		// right now" is ridden out in place. Returning here would unwind to
		// Run's caller, which rebuilds the client and replays SyncConfig,
		// SubmitReport, the lifecycle event and six stream subscriptions -
		// turning one refused request into a burst of them, on a fixed period,
		// for as long as the condition lasts. That shape is indistinguishable
		// from an attack to any log-driven banning layer in front of the panel.
		if err := c.SubmitMetrics(ctx); err != nil {
			if !isTransientRejection(err) {
				return classify(err)
			}
			logTransientRejection("metric submission", err)
			if !retry.Wait(ctx, err) {
				return nil
			}
			continue
		}
		if !time.Now().Before(nextInfoReport) {
			if err := c.SubmitReport(ctx); err != nil {
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

// logTransientRejection reports a rejection the Agent is riding out, naming the
// reason so an operator reading Agent logs can tell a rate limit apart from a
// rotated or revoked token without correlating against panel logs.
func logTransientRejection(what string, err error) {
	switch {
	case isRateLimited(err):
		log.Printf("Panel is rate limiting %s; backing off: %v", what, err)
	default:
		log.Printf("Panel rejected %s credential; backing off pending token recovery: %v", what, err)
	}
}

func (c *Client) SubmitReport(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	req := connect.NewRequest(&reportv1.SubmitReportRequest{Report: monitoring.CollectReport().Proto(c.agentIDValue(), c.sequence.Add(1))})
	c.authorize(req.Header())
	_, err := c.report.SubmitReport(ctx, req)
	return err
}

func (c *Client) SyncConfig(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, configDeadline)
	defer cancel()
	req := connect.NewRequest(&configv1.GetDesiredConfigRequest{AgentId: c.agentIDValue(), AppliedRevision: c.store.Current().Revision})
	c.authorize(req.Header())
	response, err := c.config.GetDesiredConfig(ctx, req)
	if err != nil || response.Msg.Desired == nil {
		return err
	}
	c.rememberAgentID(response.Msg.Desired.AgentId)
	return c.applyDesiredConfig(parent, response.Msg.Desired)
}

func (c *Client) applyDesiredConfig(parent context.Context, desired *configv1.DesiredConfig) error {
	if desired == nil {
		return nil
	}
	c.rememberAgentID(desired.AgentId)
	_, applyErr := c.store.Apply(desired)
	status := configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_APPLIED
	if applyErr != nil {
		status = configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_REJECTED
	}
	ackCtx, ackCancel := context.WithTimeout(parent, requestDeadline)
	defer ackCancel()
	ack := connect.NewRequest(&configv1.AcknowledgeConfigRequest{
		AgentId: c.agentIDValue(), Revision: desired.Revision, Status: status, FinishedAt: timestamppb.Now(),
	})
	if applyErr != nil {
		ack.Msg.Errors = []*commonv1.ErrorDetail{{Code: "CONFIG_REJECTED", Message: applyErr.Error()}}
	}
	c.authorize(ack.Header())
	if _, err := c.config.AcknowledgeConfig(ackCtx, ack); err != nil {
		return err
	}
	// A rejected configuration is a successfully acknowledged business terminal
	// state. Continue reporting with the previous immutable snapshot.
	return nil
}

func (c *Client) authorize(headers http.Header) {
	requestheaders.ApplyAgentAuthentication(headers, c.token, flags_pkg.GlobalConfig.CFAccessClientID, flags_pkg.GlobalConfig.CFAccessClientSecret)
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
