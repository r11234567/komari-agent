package files

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"sync/atomic"
	"syscall"
	"time"

	pkg_flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/dnsresolver"
	"github.com/komari-monitor/komari-agent/requestheaders"
)

const workerTransferURL = "_workspace_transfer_url"

// A demoted worker must not load the Agent config or receive its long-lived
// token. This parent-owned relay gives it one fixed transfer over loopback,
// retaining the existing authenticated server endpoint and bounded streaming.
func newWorkerTransferRelay(ctx context.Context, args map[string]any, authorizers ...func(http.Header)) (string, func(), error) {
	upstream, err := buildFileTransferURL(args)
	if err != nil {
		return "", nil, err
	}
	// The server accepts Bearer authentication. Never keep a stale access
	// token in a URL: query tokens take precedence over refreshed headers.
	upstreamURL, err := url.Parse(upstream)
	if err != nil {
		return "", nil, err
	}
	query := upstreamURL.Query()
	query.Del("token")
	upstreamURL.RawQuery = query.Encode()
	upstream = upstreamURL.String()
	authorize := func(header http.Header) {
		requestheaders.ApplyAgentAuthentication(header, pkg_flags.GlobalConfig.Token, pkg_flags.GlobalConfig.CFAccessClientID, pkg_flags.GlobalConfig.CFAccessClientSecret)
	}
	if len(authorizers) > 0 && authorizers[0] != nil {
		authorize = authorizers[0]
	}
	var secret [32]byte
	if _, err := rand.Read(secret[:]); err != nil {
		return "", nil, err
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}
	path := "/" + hex.EncodeToString(secret[:])
	var consumed atomic.Bool
	client := workspaceTransferHTTPClient()
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	relayContext, stop := context.WithCancel(ctx)
	server := &http.Server{ReadHeaderTimeout: 5 * time.Second, IdleTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	server.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != path || r.URL.RawQuery != "" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		if consumed.Swap(true) {
			http.Error(w, "transfer already consumed", http.StatusConflict)
			return
		}
		requestContext, cancel := context.WithCancel(r.Context())
		stopCancel := context.AfterFunc(relayContext, cancel)
		defer stopCancel()
		defer cancel()
		if relayContext.Err() != nil {
			cancel()
		}
		request, err := http.NewRequestWithContext(requestContext, http.MethodPost, upstream, r.Body)
		if err != nil {
			http.Error(w, "cannot create transfer request", http.StatusBadGateway)
			return
		}
		request.ContentLength = r.ContentLength
		for _, name := range []string{"Content-Type", "Accept", "Accept-Encoding", "Content-Range", "X-Komari-Transfer-ID", "X-Komari-Transfer-Token", "X-Komari-Transfer-Offset", "X-Komari-Transfer-Length"} {
			if value := r.Header.Get(name); value != "" {
				request.Header.Set(name, value)
			}
		}
		authorize(request.Header)
		response, err := client.Do(request)
		if err != nil {
			// net/http errors include the upstream URL (and Agent token).
			// Never return that URL to a less privileged child or its logs.
			http.Error(w, "workspace transfer relay failed: "+transferFailureReason(err), http.StatusBadGateway)
			return
		}
		defer response.Body.Close()
		for _, name := range []string{"Content-Type", "Content-Length", "Content-Range"} {
			if value := response.Header.Get(name); value != "" {
				w.Header().Set(name, value)
			}
		}
		w.WriteHeader(response.StatusCode)
		buffer := fileStreamBufferPool.Get().([]byte)
		_, _ = io.CopyBuffer(w, response.Body, buffer)
		fileStreamBufferPool.Put(buffer)
	})
	go func() { _ = server.Serve(listener) }()
	return "http://" + listener.Addr().String() + path, func() {
		stop()
		_ = server.Close()
		client.CloseIdleConnections()
	}, nil
}

// Only the worker-to-parent hop is HTTP/1.1 loopback. The upstream hop must
// honor the same DNS/IP/TLS settings and HTTPS HTTP/2 negotiation as the Agent
// control connection. Clone it so relay cleanup cannot close shared clients.
func workspaceTransferHTTPClient() *http.Client {
	// Bound connection establishment independently of the transfer lifetime.
	configured := dnsresolver.GetHTTPClientWithPreference(15*time.Second, pkg_flags.GlobalConfig.PreferIPVersion)
	transport := configured.Transport.(*http.Transport).Clone()
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	protocols.SetHTTP2(true)
	transport.Protocols = protocols
	return &http.Client{Transport: transport, Timeout: fileStreamHTTPTimeout}
}

// Categorize without formatting url.Error, which embeds authenticated URLs.
// These fixed strings are safe to return to a demoted worker and the panel.
func transferFailureReason(err error) string {
	var networkError net.Error
	var dnsError *net.DNSError
	var certificateError *tls.CertificateVerificationError
	switch {
	case errors.Is(err, context.Canceled):
		return "request canceled"
	case errors.As(err, &networkError) && networkError.Timeout():
		return "upstream timeout"
	case errors.As(err, &dnsError):
		return "DNS lookup failed"
	case errors.As(err, &certificateError):
		return "upstream TLS certificate verification failed"
	case errors.Is(err, syscall.ECONNREFUSED):
		return "upstream connection refused"
	case errors.Is(err, syscall.ECONNRESET):
		return "upstream connection reset"
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "upstream connection ended unexpectedly"
	default:
		return "upstream transport or TLS failure"
	}
}
