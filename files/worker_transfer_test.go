package files

import (
	"bytes"
	"context"
	"crypto/tls"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	pkg_flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/requestheaders"
)

func TestWorkerTransferRelayIsSingleUseAndKeepsAgentToken(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer agent-token" || r.URL.Query().Get("token") != "" || r.URL.Path != "/api/clients/transfer/fixed-transfer" {
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

func TestWorkspaceTransferClientIsolatesConfiguredTransport(t *testing.T) {
	preserveAgentConfig(t, "http://127.0.0.1")
	pkg_flags.GlobalConfig.PreferIPVersion = "4"
	configured := dnsresolver.GetHTTPClientWithPreference(15*time.Second, "4")
	shared := configured.Transport.(*http.Transport)
	client := workspaceTransferHTTPClient()
	defer client.CloseIdleConnections()
	transport := client.Transport.(*http.Transport)
	if transport == shared || transport.TLSClientConfig == shared.TLSClientConfig {
		t.Fatal("relay must own its transport and TLS configuration")
	}
	if transport.TLSClientConfig == nil || transport.TLSClientConfig.InsecureSkipVerify {
		t.Fatal("upstream certificate verification must remain enabled by default")
	}
	if transport.DialContext == nil || transport.TLSHandshakeTimeout != shared.TLSHandshakeTimeout {
		t.Fatal("configured resolver/dialer or bounded TLS handshake was lost")
	}
	if !transport.Protocols.HTTP1() || !transport.Protocols.HTTP2() || transport.Protocols.UnencryptedHTTP2() {
		t.Fatal("raw transfer endpoint must negotiate HTTPS HTTP/2 and retain plain HTTP/1.1 compatibility")
	}
	if !shared.Protocols.UnencryptedHTTP2() || client.Timeout != fileStreamHTTPTimeout {
		t.Fatal("relay changed the shared control transport or transfer lifetime")
	}
}

func TestWorkerTransferRelayHTTPSHTTP2AndFreshCredentials(t *testing.T) {
	data := []byte("file contents over negotiated HTTP/2")
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.ProtoMajor != 2 {
			t.Errorf("upstream protocol = %s, want HTTP/2", r.Proto)
		}
		if r.Header.Get("Authorization") != "Bearer latest-parent-token" || r.URL.Query().Has("token") {
			t.Error("transfer did not use the current parent credential exclusively in its header")
		}
		if r.Header.Get("CF-Access-Client-Id") != "fixture-id" || r.Header.Get("CF-Access-Client-Secret") != "fixture-secret" {
			t.Error("parent Cloudflare Access headers missing")
		}
		if r.URL.Query().Get("transfer_token") != "scoped-transfer-token" || r.Header.Get("X-Komari-Transfer-Token") != "scoped-transfer-token" {
			t.Error("scoped transfer authorization lost")
		}
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("upstream read: %v", err)
			return
		}
		switch r.URL.Path {
		case "/api/clients/transfer/download":
			if !bytes.Equal(body, data) || r.ContentLength != int64(len(data)) {
				t.Error("download body or content length changed")
			}
			_, _ = io.WriteString(w, "received")
		case "/api/clients/transfer/upload":
			if len(body) != 0 {
				t.Error("upload fetch must have an empty request body")
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			_, _ = w.Write(data)
		default:
			t.Error("unexpected transfer route")
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	upstream.EnableHTTP2 = true
	upstream.StartTLS()
	defer upstream.Close()
	preserveAgentConfig(t, upstream.URL)
	// Only this self-signed fixture opts into the existing compatibility flag.
	// A separate test below requires default certificate rejection.
	pkg_flags.GlobalConfig.IgnoreUnsafeCert = true
	var currentToken atomic.Value
	var authorizationCalls atomic.Int32
	authorize := func(header http.Header) {
		authorizationCalls.Add(1)
		requestheaders.ApplyAgentAuthentication(header, currentToken.Load().(string), "fixture-id", "fixture-secret")
	}
	for _, direction := range []string{"download", "upload"} {
		t.Run(direction, func(t *testing.T) {
			currentToken.Store("old-parent-token")
			endpoint, closeRelay, err := newWorkerTransferRelay(t.Context(), map[string]any{
				"transfer_id": direction, "transfer_token": "scoped-transfer-token",
			}, authorize)
			if err != nil {
				t.Fatal(err)
			}
			defer closeRelay()
			currentToken.Store("latest-parent-token") // Refresh after relay creation.
			var body io.Reader
			want := data
			if direction == "download" {
				body = bytes.NewReader(data)
				want = []byte("received")
			}
			request, err := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, body)
			if err != nil {
				t.Fatal(err)
			}
			request.Header.Set("Authorization", "Bearer worker-chosen-token")
			request.Header.Set("CF-Access-Client-Secret", "worker-chosen-secret")
			request.Header.Set("X-Komari-Transfer-Token", "scoped-transfer-token")
			response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
			if err != nil {
				t.Fatal(err)
			}
			defer response.Body.Close()
			got, err := io.ReadAll(response.Body)
			if err != nil || response.StatusCode != http.StatusOK || !bytes.Equal(got, want) {
				t.Fatalf("relay status=%d body=%q err=%v", response.StatusCode, got, err)
			}
		})
	}
	if authorizationCalls.Load() != 2 {
		t.Fatal("authorization must be evaluated once per upstream request")
	}
}

func TestWorkerTransferRelayRejectsUntrustedTLSByDefault(t *testing.T) {
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Error("untrusted upstream must not receive credentials or file bytes")
	}))
	upstream.Config.ErrorLog = log.New(io.Discard, "", 0)
	upstream.StartTLS()
	defer upstream.Close()
	preserveAgentConfig(t, upstream.URL)
	endpoint, closeRelay, err := newWorkerTransferRelay(t.Context(), map[string]any{"transfer_id": "fixture", "transfer_token": "secret-scoped-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeRelay()
	request, _ := http.NewRequestWithContext(t.Context(), http.MethodPost, endpoint, nil)
	response, err := (&http.Client{Timeout: 10 * time.Second}).Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, _ := io.ReadAll(response.Body)
	if response.StatusCode != http.StatusBadGateway || string(body) != "workspace transfer relay failed: upstream TLS certificate verification failed\n" {
		t.Fatalf("certificate error status=%d body=%q", response.StatusCode, body)
	}
}

func TestWorkerTransferRelayStreamsRequestBeforeEOF(t *testing.T) {
	firstChunk := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		prefix := make([]byte, 5)
		if _, err := io.ReadFull(r.Body, prefix); err != nil {
			t.Errorf("read prefix: %v", err)
			return
		}
		close(firstChunk)
		rest, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read remaining stream: %v", err)
			return
		}
		_, _ = w.Write(append(prefix, rest...))
	}))
	defer upstream.Close()
	preserveAgentConfig(t, upstream.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	endpoint, closeRelay, err := newWorkerTransferRelay(ctx, map[string]any{"transfer_id": "stream", "transfer_token": "scoped-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeRelay()
	reader, writer := io.Pipe()
	defer writer.Close()
	defer reader.Close()
	done := make(chan error, 1)
	go func() {
		request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, reader)
		if err != nil {
			done <- err
			return
		}
		response, err := http.DefaultClient.Do(request)
		if err != nil {
			done <- err
			return
		}
		defer response.Body.Close()
		got, err := io.ReadAll(response.Body)
		if err == nil && (response.StatusCode != http.StatusOK || string(got) != "first-rest") {
			err = errors.New("streamed bytes or status changed")
		}
		done <- err
	}()
	if _, err := writer.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-firstChunk:
	case <-ctx.Done():
		t.Fatal("relay buffered request until EOF")
	}
	if _, err := writer.Write([]byte("-rest")); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("stream did not complete")
	}
}

func TestWorkerTransferRelayCancellationStopsUpstream(t *testing.T) {
	started := make(chan struct{})
	stopped := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(started)
		<-r.Context().Done()
		close(stopped)
	}))
	defer upstream.Close()
	preserveAgentConfig(t, upstream.URL)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	endpoint, closeRelay, err := newWorkerTransferRelay(ctx, map[string]any{"transfer_id": "cancel", "transfer_token": "scoped-token"})
	if err != nil {
		t.Fatal(err)
	}
	defer closeRelay()
	done := make(chan struct{})
	go func() {
		defer close(done)
		request, _ := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, nil)
		response, err := http.DefaultClient.Do(request)
		if err == nil {
			_ = response.Body.Close()
		}
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("upstream request never started")
	}
	cancel()
	select {
	case <-stopped:
	case <-time.After(5 * time.Second):
		t.Fatal("upstream request survived workspace cancellation")
	}
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("worker request survived cancellation")
	}
}

func TestTransferFailureReasonDoesNotExposeURLsOrCredentials(t *testing.T) {
	for _, test := range []struct {
		name string
		err  error
		want string
	}{
		{"canceled", context.Canceled, "request canceled"},
		{"deadline", context.DeadlineExceeded, "upstream timeout"},
		{"dns", &net.DNSError{Err: "secret resolver detail", Name: "private-host"}, "DNS lookup failed"},
		{"certificate", &tls.CertificateVerificationError{Err: errors.New("secret certificate detail")}, "upstream TLS certificate verification failed"},
		{"refused", syscall.ECONNREFUSED, "upstream connection refused"},
		{"reset", syscall.ECONNRESET, "upstream connection reset"},
		{"eof", io.EOF, "upstream connection ended unexpectedly"},
		{"truncated", io.ErrUnexpectedEOF, "upstream connection ended unexpectedly"},
		{"unknown", errors.New("secret transport detail"), "upstream transport or TLS failure"},
	} {
		t.Run(test.name, func(t *testing.T) {
			wrapped := &url.Error{Op: "Post", URL: "https://private-host/api/clients/transfer/id?token=secret&transfer_token=secret-scoped", Err: test.err}
			if got := transferFailureReason(wrapped); got != test.want {
				t.Errorf("category=%q, want %q", got, test.want)
			}
		})
	}
}
