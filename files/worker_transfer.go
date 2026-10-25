package files

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"
)

const workerTransferURL = "_workspace_transfer_url"

// A demoted worker must not load the Agent config or receive its long-lived
// token. This parent-owned relay gives it one fixed transfer over loopback,
// retaining the existing authenticated server endpoint and bounded streaming.
func newWorkerTransferRelay(ctx context.Context, args map[string]any) (string, func(), error) {
	upstream, err := buildFileTransferURL(args)
	if err != nil {
		return "", nil, err
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
	client := fileStreamHTTPClient()
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
		response, err := client.Do(request)
		if err != nil {
			// net/http errors include the upstream URL (and Agent token).
			// Never return that URL to a less privileged child or its logs.
			http.Error(w, "workspace transfer relay failed", http.StatusBadGateway)
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
