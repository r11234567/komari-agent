package files

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestWorkerTransferRelayIsSingleUseAndKeepsAgentToken(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "agent-token" || r.URL.Path != "/api/clients/transfer/fixed-transfer" {
			t.Error("parent relay lost fixed authenticated upstream")
		}
		_, _ = io.WriteString(w, "chunk")
	}))
	defer upstream.Close()
	preserveAgentConfig(t, upstream.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint, closeRelay, err := newWorkerTransferRelay(ctx, map[string]any{"transfer_id": "fixed-transfer", "transfer_token": "one-shot-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeRelay()
	if strings.Contains(endpoint, "agent-token") || strings.Contains(endpoint, upstream.URL) {
		t.Fatal("worker received Agent credentials or upstream URL")
	}
	client := &http.Client{}
	for _, attempt := range []struct {
		path   string
		status int
	}{{endpoint + "/wrong", 404}, {endpoint, 200}, {endpoint, 409}} {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, attempt.path, nil)
		if err != nil {
			t.Fatal(err)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = io.Copy(io.Discard, response.Body)
		_ = response.Body.Close()
		if response.StatusCode != attempt.status {
			t.Fatalf("relay status=%d, want %d", response.StatusCode, attempt.status)
		}
	}
}

func TestWorkerTransferRelayRedactsUpstreamErrors(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	upstream.Close()
	preserveAgentConfig(t, upstream.URL)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	endpoint, closeRelay, err := newWorkerTransferRelay(ctx, map[string]any{"transfer_id": "fixture", "transfer_token": "scoped-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeRelay()
	request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusBadGateway || strings.Contains(string(body), "agent-token") || strings.Contains(string(body), upstream.URL) {
		t.Fatalf("upstream failure was not safely reported: %d %s", response.StatusCode, body)
	}
}
