package clientcore

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	"github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/file/v1/filev1connect"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/webssh/v1/websshv1connect"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/h2c"
)

func TestPanelDuplexPreferenceSelectsRealWireProtocol(t *testing.T) {
	var grpcEnabled atomic.Bool
	types := make(chan string, 2)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case configv1connect.ConfigServiceGetDesiredConfigProcedure:
			if grpcEnabled.Load() {
				w.Header().Set(agentDuplexProtocolHeader, "grpc")
			}
			w.Header().Set("Content-Type", "application/proto")
		case websshv1connect.WebSSHServiceAttachSessionProcedure, filev1connect.FileServiceAttachFileOperationsProcedure:
			types <- r.Header.Get("Content-Type")
			http.Error(w, "stop after capturing transport", http.StatusBadRequest)
		default:
			t.Errorf("unexpected procedure %s", r.URL.Path)
			http.NotFound(w, r)
		}
	})
	panel := httptest.NewServer(h2c.NewHandler(handler, &http2.Server{}))
	defer panel.Close()
	dir := t.TempDir()
	cfg := &flags.Config{Endpoint: panel.URL, Token: "test-token", Interval: 3,
		CredentialsFile: filepath.Join(dir, "credentials.json"), PrivilegedStateFile: filepath.Join(dir, "privileged.json")}
	store, err := runtimeconfig.New(runtimeconfig.FromFlags(cfg), filepath.Join(dir, "runtime.json"))
	if err != nil {
		t.Fatal(err)
	}
	agent, err := New(cfg, store)
	if err != nil {
		t.Fatal(err)
	}
	for _, enabled := range []bool{false, true, false} {
		grpcEnabled.Store(enabled)
		if err := agent.SyncConfig(context.Background()); err != nil {
			t.Fatal(err)
		}
		want := "application/connect+proto"
		if enabled {
			want = "application/grpc"
		}
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		terminal := agent.terminalAttachClient().AttachSession(ctx)
		_ = terminal.Send(&websshv1.AttachSessionRequest{})
		_ = terminal.CloseRequest()
		_, _ = terminal.Receive()
		_ = terminal.CloseResponse()
		file := agent.fileAttachClient().AttachFileOperations(ctx)
		_ = file.Send(&filev1.AttachFileOperationsRequest{})
		_ = file.CloseRequest()
		_, _ = file.Receive()
		_ = file.CloseResponse()
		for range 2 {
			select {
			case actual := <-types:
				if actual != want {
					t.Errorf("mode enabled=%t: got %s, want %s", enabled, actual, want)
				}
			case <-ctx.Done():
				cancel()
				t.Fatal("Agent attach request did not reach the server")
			}
		}
		cancel()
	}
}
