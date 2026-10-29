package rescue

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/requestheaders"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	configconnect "github.com/r11234567/komari-proto/gen/go/komari/config/v1/configv1connect"
)

type continuousHeartbeatPanel struct {
	configconnect.UnimplementedPrivilegedDeliveryServiceHandler
	sign     func(time.Time, uint64) *configv1.PrivilegedRevision
	requests atomic.Int32
}

func (s *continuousHeartbeatPanel) WatchPrivilegedDelivery(ctx context.Context, req *connect.Request[configv1.WatchPrivilegedDeliveryRequest], stream *connect.ServerStream[configv1.WatchPrivilegedDeliveryResponse]) error {
	s.requests.Add(1)
	stream.ResponseHeader().Set(authorizationWatchHeader, "v1")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		if err := stream.Send(&configv1.WatchPrivilegedDeliveryResponse{Revision: s.sign(time.Now(), 1)}); err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
		}
	}
}

func TestRescueAuthorizationWatchSurvivesThirtySeconds(t *testing.T) {
	trust, sign := heartbeatFixture(t)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	id := credentials.Identity{AgentID: "node", AccessToken: "synthetic-watch-token", PrivateKey: base64.StdEncoding.EncodeToString(private)}
	panel := &continuousHeartbeatPanel{sign: sign}
	_, handler := configconnect.NewPrivilegedDeliveryServiceHandler(panel)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Verify that the dedicated production client still signs the actual
		// HTTP request. Only isolated synthetic credentials are used here.
		body, err := io.ReadAll(r.Body)
		if err != nil {
			http.Error(w, "read body", http.StatusBadRequest)
			return
		}
		r.Body = io.NopCloser(strings.NewReader(string(body)))
		payload := fmt.Sprintf("%s\n%s\n%s\n%s\n%x\n%x", r.Method, r.URL.Path,
			r.Header.Get("X-Komari-Timestamp"), r.Header.Get("X-Komari-Nonce"), sha256.Sum256([]byte(id.AccessToken)), sha256.Sum256(body))
		sig, err := base64.StdEncoding.DecodeString(r.Header.Get("X-Komari-Signature"))
		if err != nil || !ed25519.Verify(public, []byte(payload), sig) || r.Header.Get("Authorization") != "Bearer "+id.AccessToken {
			http.Error(w, "invalid synthetic DPoP", http.StatusUnauthorized)
			return
		}
		handler.ServeHTTP(w, r)
	}))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	client := newAuthorizationWatchClient(id)
	rpc := configconnect.NewPrivilegedDeliveryServiceClient(client, server.URL)
	frames := make(chan authorizationFrame, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		receiveAuthorization(ctx, rpc, connect.NewRequest(&configv1.WatchPrivilegedDeliveryRequest{AgentId: "node", ProtocolVersion: 2}), frames)
	}()
	start := time.Now()
	var cursor heartbeatCursor
	count := 0
	for time.Since(start) < 32*time.Second {
		select {
		case frame := <-frames:
			if frame.err != nil {
				t.Fatalf("stream ended at %s: %v", time.Since(start), frame.err)
			}
			if err := cursor.accept(trust, frame.revision, time.Now()); err != nil {
				t.Fatal(err)
			}
			count++
		case <-ctx.Done():
			t.Fatal("signed stream stopped delivering before 32 seconds")
		}
	}
	if count < 30 || panel.requests.Load() != 1 {
		t.Fatalf("frames=%d requests=%d; expected continuous fresh heartbeats without reconnect", count, panel.requests.Load())
	}
	cancel()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("stream receiver survived context cancellation")
	}
	t.Logf("verified %d signed heartbeats over %s on one DPoP-authenticated request", count, time.Since(start))
}

func TestRescueAuthorizationWatchTransportBoundsAndRedirects(t *testing.T) {
	client := newAuthorizationWatchClient(credentials.Identity{})
	if client.Timeout != 0 || authorizationWatchTransport.DialContext == nil || authorizationWatchTransport.TLSHandshakeTimeout <= 0 || authorizationWatchTransport.ResponseHeaderTimeout <= 0 {
		t.Fatal("stream requires no total timeout and bounded connection/header establishment")
	}
	if requestheaders.WrapWithStaticDPoP(nil, credentials.Identity{}).Timeout != 30*time.Second {
		t.Fatal("ordinary unary timeout was changed")
	}
	var redirected atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Add(1) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL, http.StatusTemporaryRedirect)
	}))
	defer server.Close()
	response, err := client.Get(server.URL)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || redirected.Load() != 0 {
		t.Fatalf("redirect escaped pinned endpoint: err=%v requests=%d", err, redirected.Load())
	}
}

func TestRescueAuthorizationWatchContextCancelsStalledHeaders(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	response, err := newAuthorizationWatchClient(credentials.Identity{}).Do(req)
	if response != nil {
		response.Body.Close()
	}
	if err == nil || ctx.Err() == nil || time.Since(start) > 2*time.Second {
		t.Fatalf("stalled response ignored context: elapsed=%s err=%v", time.Since(start), err)
	}
}
