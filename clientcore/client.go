// Package clientcore owns the Agent's Connect transport. Legacy v1/v2 remains
// outside this package and is selected only when the Connect endpoint is absent
// or the transport cannot be reached.
package clientcore

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"connectrpc.com/connect"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/monitoring"
	commonv1 "github.com/r11234567/komari-proto/gen/go/komari/common/v1"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configv1connect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	metricsv1connect "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1/metricsv1connect"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	reportv1connect "github.com/r11234567/komari-proto/gen/go/komari/report/v1/reportv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	requestDeadline = 15 * time.Second
	configDeadline  = 30 * time.Second
)

var ErrLegacyFallback = errors.New("Connect transport is unavailable; use legacy compatibility transport")

type Client struct {
	config   configv1connect.ConfigServiceClient
	report   reportv1connect.AgentReportServiceClient
	metrics  metricsv1connect.MetricsServiceClient
	token    string
	agentID  string
	sequence atomic.Uint64
	store    *runtimeconfig.Store
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
	return &Client{
		config:  configv1connect.NewConfigServiceClient(httpClient, baseURL),
		report:  reportv1connect.NewAgentReportServiceClient(httpClient, baseURL),
		metrics: metricsv1connect.NewMetricsServiceClient(httpClient, baseURL),
		token:   config.Token, store: store,
	}, nil
}

func (c *Client) Run(ctx context.Context) error {
	if err := c.SyncConfig(ctx); err != nil {
		return classify(err)
	}
	if err := c.SubmitReport(ctx); err != nil {
		return classify(err)
	}
	for {
		if err := c.SubmitMetrics(ctx); err != nil {
			return classify(err)
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
		if err := c.SyncConfig(ctx); err != nil {
			return classify(err)
		}
	}
}

func (c *Client) SubmitMetrics(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	report := monitoring.CollectReport()
	req := connect.NewRequest(&metricsv1.SubmitMetricsRequest{AgentId: c.agentID, Sequence: c.sequence.Add(1), Points: report.Metrics(time.Now().UTC())})
	c.authorize(req.Header())
	_, err := c.metrics.SubmitMetrics(ctx, req)
	return err
}

func (c *Client) SubmitReport(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, requestDeadline)
	defer cancel()
	req := connect.NewRequest(&reportv1.SubmitReportRequest{Report: monitoring.CollectReport().Proto(c.agentID, c.sequence.Add(1))})
	c.authorize(req.Header())
	_, err := c.report.SubmitReport(ctx, req)
	return err
}

func (c *Client) SyncConfig(parent context.Context) error {
	ctx, cancel := context.WithTimeout(parent, configDeadline)
	defer cancel()
	req := connect.NewRequest(&configv1.GetDesiredConfigRequest{AgentId: c.agentID, AppliedRevision: c.store.Current().Revision})
	c.authorize(req.Header())
	response, err := c.config.GetDesiredConfig(ctx, req)
	if err != nil || response.Msg.Desired == nil {
		return err
	}
	if c.agentID == "" {
		c.agentID = response.Msg.Desired.AgentId
	}
	_, applyErr := c.store.Apply(response.Msg.Desired)
	status := configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_APPLIED
	if applyErr != nil {
		status = configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_REJECTED
	}
	ackCtx, ackCancel := context.WithTimeout(parent, requestDeadline)
	defer ackCancel()
	ack := connect.NewRequest(&configv1.AcknowledgeConfigRequest{
		AgentId: c.agentID, Revision: response.Msg.Desired.Revision, Status: status, FinishedAt: timestamppb.Now(),
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

func (c *Client) authorize(headers http.Header) { headers.Set("Authorization", "Bearer "+c.token) }

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
