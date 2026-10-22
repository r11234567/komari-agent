package clientcore

import (
	"connectrpc.com/connect"
	"context"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

type startupConfigService struct {
	configv1connect.UnimplementedConfigServiceHandler
	desired *configv1.DesiredConfig
	after   []uint64
	acks    []configv1.ConfigApplyStatus
}

func (s *startupConfigService) GetDesiredConfig(_ context.Context, req *connect.Request[configv1.GetDesiredConfigRequest]) (*connect.Response[configv1.GetDesiredConfigResponse], error) {
	s.after = append(s.after, req.Msg.AppliedRevision)
	response := &configv1.GetDesiredConfigResponse{}
	if req.Msg.AppliedRevision < s.desired.Revision {
		response.Desired = s.desired
	}
	return connect.NewResponse(response), nil
}
func (s *startupConfigService) AcknowledgeConfig(_ context.Context, req *connect.Request[configv1.AcknowledgeConfigRequest]) (*connect.Response[configv1.AcknowledgeConfigResponse], error) {
	s.acks = append(s.acks, req.Msg.Status)
	return connect.NewResponse(&configv1.AcknowledgeConfigResponse{Accepted: true}), nil
}
func TestStartupFetchesAndAcknowledgesPersistedSameRevision(t *testing.T) {
	for _, mismatch := range []bool{false, true} {
		name := "matching"
		if mismatch {
			name = "mismatched"
		}
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "runtime.json")
			initial := runtimeconfig.FromFlags(&flags_pkg.Config{Interval: 3})
			store, err := runtimeconfig.New(initial, path)
			if err != nil {
				t.Fatal(err)
			}
			day := uint32(7)
			if _, err = store.Apply(&configv1.DesiredConfig{Revision: 4, Runtime: &configv1.RuntimeConfig{TrafficResetDay: &day}}); err != nil {
				t.Fatal(err)
			}
			store, err = runtimeconfig.New(initial, path)
			if err != nil {
				t.Fatal(err)
			}
			if mismatch {
				day = 9
			}
			service := &startupConfigService{desired: &configv1.DesiredConfig{AgentId: "old-node", Revision: 4, Runtime: &configv1.RuntimeConfig{TrafficResetDay: &day}}}
			route, handler := configv1connect.NewConfigServiceHandler(service)
			mux := http.NewServeMux()
			mux.Handle(route, handler)
			server := httptest.NewServer(mux)
			defer server.Close()
			c := &Client{agentID: "old-node", store: store, config: configv1connect.NewConfigServiceClient(server.Client(), server.URL)}
			if err = c.SyncConfig(context.Background()); err != nil {
				t.Fatal(err)
			}
			if err = c.SyncConfig(context.Background()); err != nil {
				t.Fatal(err)
			}
			if len(service.after) != 2 || service.after[0] != 0 || service.after[1] != 4 {
				t.Fatalf("startup skipped authoritative snapshot: %v", service.after)
			}
			want := configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_APPLIED
			if mismatch {
				want = configv1.ConfigApplyStatus_CONFIG_APPLY_STATUS_REJECTED
			}
			if len(service.acks) != 1 || service.acks[0] != want {
				t.Fatalf("incorrect same-revision startup ACK: %v", service.acks)
			}
			if store.Current().Revision != 4 || store.Current().TrafficResetDay != 7 {
				t.Fatal("startup corrupted local configuration")
			}
		})
	}
}
