package clientcore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"connectrpc.com/connect"
	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/metrics/v1/metricsv1connect"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/report/v1/reportv1connect"
)

type monitoringReportPanel struct {
	metricsv1connect.UnimplementedMetricsServiceHandler
	reports chan *reportv1.TrafficMonitoringStatus
}

func (*monitoringReportPanel) SubmitMetrics(_ context.Context, req *connect.Request[metricsv1.SubmitMetricsRequest]) (*connect.Response[metricsv1.SubmitMetricsResponse], error) {
	return connect.NewResponse(&metricsv1.SubmitMetricsResponse{AcceptedSequence: req.Msg.Sequence}), nil
}

func (*monitoringReportPanel) StreamMetrics(_ context.Context, stream *connect.BidiStream[metricsv1.StreamMetricsRequest, metricsv1.StreamMetricsResponse]) error {
	for {
		req, err := stream.Receive()
		if err != nil {
			return err
		}
		if err := stream.Send(&metricsv1.StreamMetricsResponse{AcceptedSequence: req.GetBatch().GetSequence()}); err != nil {
			return err
		}
	}
}

func (panel *monitoringReportPanel) SubmitReport(ctx context.Context, req *connect.Request[reportv1.SubmitReportRequest]) (*connect.Response[reportv1.SubmitReportResponse], error) {
	select {
	case panel.reports <- req.Msg.GetReport().GetMetadata().GetCapabilities().GetTrafficMonitoring():
		return connect.NewResponse(&reportv1.SubmitReportResponse{Accepted: true}), nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestTrafficMonitoringChangesReachPanelBeforeBasicReportInterval(t *testing.T) {
	config := flags.GlobalConfig
	oldIPv4, oldIPv6 := config.CustomIpv4, config.CustomIpv6
	config.CustomIpv4, config.CustomIpv6 = "192.0.2.10", "2001:db8::10"
	t.Cleanup(func() { config.CustomIpv4, config.CustomIpv6 = oldIPv4, oldIPv6 })

	for _, mode := range []string{"stream", "unary"} {
		t.Run(mode, func(t *testing.T) {
			panel := &monitoringReportPanel{reports: make(chan *reportv1.TrafficMonitoringStatus, 2)}
			mux := http.NewServeMux()
			mux.Handle(metricsv1connect.NewMetricsServiceHandler(panel))
			mux.Handle(reportv1connect.NewAgentReportServiceHandler(panel))
			server := httptest.NewUnstartedServer(mux)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()

			c := &Client{
				agentID: "monitoring-report-test",
				metrics: metricsv1connect.NewMetricsServiceClient(server.Client(), server.URL),
				report:  reportv1connect.NewAgentReportServiceClient(server.Client(), server.URL),
			}
			disabled := &reportv1.TrafficMonitoringStatus{State: reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_DISABLED}
			running := &reportv1.TrafficMonitoringStatus{State: reportv1.TrafficMonitoringState_TRAFFIC_MONITORING_STATE_RUNNING, InterfaceName: "eth0"}
			c.reportedTrafficMonitoring.Store(disabled)
			c.trafficMonitoring.Store(running)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			done := make(chan struct{})
			defer func() { cancel(); <-done }()
			go func() {
				defer close(done)
				if mode == "stream" {
					_ = c.runMetricStream(ctx)
				} else {
					_ = c.runUnaryMetricLoop(ctx)
				}
			}()

			for _, expected := range []*reportv1.TrafficMonitoringStatus{running, disabled} {
				select {
				case got := <-panel.reports:
					if got.GetState() != expected.State || got.GetInterfaceName() != expected.InterfaceName {
						t.Fatalf("status report = %v, want %v", got, expected)
					}
					c.trafficMonitoring.Store(disabled)
				case <-ctx.Done():
					t.Fatalf("status %s was not reported in the metrics loop", expected.State)
				}
			}
		})
	}
}
