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
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
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
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	requestDeadline    = 15 * time.Second
	configDeadline     = 30 * time.Second
	configPollInterval = 5 * time.Minute
)

var ErrLegacyFallback = errors.New("Connect transport is unavailable; use legacy compatibility transport")

type Client struct {
	config    configv1connect.ConfigServiceClient
	events    agentv1connect.AgentEventServiceClient
	report    reportv1connect.AgentReportServiceClient
	metrics   metricsv1connect.MetricsServiceClient
	network   networkv1connect.NetworkProbeServiceClient
	execution execv1connect.ExecutionServiceClient
	webssh    websshv1connect.WebSSHServiceClient
	token     string
	agentMu   sync.RWMutex
	agentID   string
	sequence  atomic.Uint64
	store     *runtimeconfig.Store
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
	httpClient := dnsresolver.GetHTTPClientWithPreference(requestDeadline, config.PreferIPVersion)
	networkHTTPClient := dnsresolver.GetHTTPClientWithPreference(35*time.Second, config.PreferIPVersion)
	streamHTTPClient := dnsresolver.GetStreamingHTTPClientWithPreference(config.PreferIPVersion)
	return &Client{
		// WatchDesiredConfig is a durable server stream. It must not inherit the
		// unary client's whole-request timeout, otherwise the Agent disconnects
		// a healthy configuration watch every requestDeadline.
		config:    configv1connect.NewConfigServiceClient(streamHTTPClient, baseURL),
		events:    agentv1connect.NewAgentEventServiceClient(streamHTTPClient, baseURL),
		report:    reportv1connect.NewAgentReportServiceClient(httpClient, baseURL),
		metrics:   metricsv1connect.NewMetricsServiceClient(streamHTTPClient, baseURL),
		network:   networkv1connect.NewNetworkProbeServiceClient(networkHTTPClient, baseURL),
		execution: execv1connect.NewExecutionServiceClient(streamHTTPClient, baseURL),
		webssh:    websshv1connect.NewWebSSHServiceClient(streamHTTPClient, baseURL),
		token:     config.Token, store: store,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	if err := c.SyncConfig(ctx); err != nil {
		return classify(err)
	}
	if err := c.SubmitReport(ctx); err != nil {
		return classify(err)
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
	return c.runMetricStream(ctx)
}

func (c *Client) runAgentEvents(ctx context.Context) {
	after := ""
	for ctx.Err() == nil {
		req := connect.NewRequest(&agentv1.SubscribeEventsRequest{AgentId: c.agentIDValue(), AfterEventId: after})
		c.authorize(req.Header())
		stream, err := c.events.SubscribeEvents(ctx, req)
		if err != nil {
			if isUnsupported(err) || !waitRetry(ctx) {
				return
			}
			continue
		}
		for stream.Receive() {
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
		if err := stream.Err(); err != nil && !isUnsupported(err) {
			if !waitRetry(ctx) {
				return
			}
			continue
		}
		if stream.Err() != nil && isUnsupported(stream.Err()) {
			return
		}
		if !waitRetry(ctx) {
			return
		}
	}
}

func (c *Client) runConfigUpdates(ctx context.Context) {
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
			if !waitRetry(ctx) {
				return
			}
			continue
		}
		for stream.Receive() {
			desired := stream.Msg().Desired
			if desired == nil {
				continue
			}
			if err := c.applyDesiredConfig(ctx, desired); err != nil {
				log.Printf("Failed to apply streamed Connect config: %v", err)
			}
		}
		if err := stream.Err(); err != nil && isUnsupported(err) {
			c.runConfigPolling(ctx)
			return
		}
		if ctx.Err() != nil || !waitRetry(ctx) {
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
	for ctx.Err() == nil {
		req := connect.NewRequest(&execv1.LeaseExecutionRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		stream, err := c.execution.LeaseExecution(ctx, req)
		if err != nil {
			if isUnsupported(err) || !waitRetry(ctx) {
				return
			}
			continue
		}
		for stream.Receive() {
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
		if err := stream.Err(); err != nil && !isUnsupported(err) {
			if !waitRetry(ctx) {
				return
			}
			continue
		}
		if stream.Err() != nil && isUnsupported(stream.Err()) {
			return
		}
		if !waitRetry(ctx) {
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
	for ctx.Err() == nil {
		req := connect.NewRequest(&websshv1.LeaseSessionsRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		stream, err := c.webssh.LeaseSessions(ctx, req)
		if err != nil {
			if isUnsupported(err) || !waitRetry(ctx) {
				return
			}
			continue
		}
		for stream.Receive() {
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
		if err := stream.Err(); err != nil && !isUnsupported(err) {
			if !waitRetry(ctx) {
				return
			}
			continue
		}
		if stream.Err() != nil && isUnsupported(stream.Err()) {
			return
		}
		if !waitRetry(ctx) {
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
	for ctx.Err() == nil {
		leaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req := connect.NewRequest(&networkv1.LeasePingProbeRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		response, err := c.network.LeasePingProbe(leaseCtx, req)
		cancel()
		if err != nil {
			var connectErr *connect.Error
			if errors.As(err, &connectErr) && (connectErr.Code() == connect.CodeUnimplemented || connectErr.Code() == connect.CodeNotFound) {
				return
			}
			if !waitRetry(ctx) {
				return
			}
			continue
		}
		assignment := response.Msg.Assignment
		if assignment == nil {
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
	for ctx.Err() == nil {
		leaseCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		req := connect.NewRequest(&networkv1.LeaseReturnRouteProbeRequest{AgentId: c.agentIDValue()})
		c.authorize(req.Header())
		response, err := c.network.LeaseReturnRouteProbe(leaseCtx, req)
		cancel()
		if err != nil {
			var connectErr *connect.Error
			if errors.As(err, &connectErr) && (connectErr.Code() == connect.CodeUnimplemented || connectErr.Code() == connect.CodeNotFound) {
				return
			}
			if !waitRetry(ctx) {
				return
			}
			continue
		}
		assignment := response.Msg.Assignment
		if assignment == nil {
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

func waitRetry(ctx context.Context) bool {
	timer := time.NewTimer(time.Duration(max(flags_pkg.GlobalConfig.ReconnectInterval, 1)) * time.Second)
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
		if !waitRetry(ctx) {
			return nil
		}
	}
	return nil
}

func (c *Client) runUnaryMetricLoop(ctx context.Context) error {
	infoInterval := time.Duration(max(flags_pkg.GlobalConfig.InfoReportInterval, 1)) * time.Minute
	nextInfoReport := time.Now().Add(infoInterval)
	for {
		if err := c.SubmitMetrics(ctx); err != nil {
			return classify(err)
		}
		if !time.Now().Before(nextInfoReport) {
			if err := c.SubmitReport(ctx); err != nil {
				return classify(err)
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
			return nil
		case <-timer.C:
		}
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
