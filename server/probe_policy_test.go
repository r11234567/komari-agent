package server

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestProbeAddressPolicyUsesPermittedResolvedIP(t *testing.T) {
	t.Setenv(probeAllowIPsEnv, "")
	for _, target := range []string{"127.0.0.1", "10.0.0.20", "169.254.169.254", "100.64.0.2", "::1", "::ffff:127.0.0.1", "fd00::1", "64:ff9b::7f00:1"} {
		if _, err := resolveIP(t.Context(), target); err == nil {
			t.Errorf("accepted non-public address %s", target)
		}
	}
	lookup := func(_ context.Context, _, host string) ([]netip.Addr, error) {
		if host != "probe.example" {
			t.Fatalf("resolved unexpected host %s", host)
		}
		return []netip.Addr{netip.MustParseAddr("10.0.0.20"), netip.MustParseAddr("1.1.1.1")}, nil
	}
	ip, err := resolveProbeAddress(t.Context(), "probe.example", lookup)
	if err != nil || ip != "1.1.1.1" {
		t.Fatalf("selected %q, %v", ip, err)
	}
	t.Setenv(probeAllowIPsEnv, "127.0.0.0/8")
	if _, err := resolveIP(t.Context(), "1.1.1.1"); err == nil {
		t.Fatal("an invalid local policy failed open")
	}
}

func TestProbeLoopbackRequiresExplicitLocalIP(t *testing.T) {
	t.Setenv(probeAllowIPsEnv, "")
	var hits atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	t.Cleanup(server.Close)
	const timeout = time.Second
	if value := ProbePing("http", server.URL, timeout); value != -1 || hits.Load() != 0 {
		t.Fatalf("loopback HTTP probe returned %d and made %d requests", value, hits.Load())
	}
	tcpAddress := strings.TrimPrefix(server.URL, "http://")
	if value := ProbePing("tcp", tcpAddress, timeout); value != -1 {
		t.Fatalf("loopback TCP probe returned %d", value)
	}
	t.Setenv(probeAllowIPsEnv, "127.0.0.1")
	if value := ProbePing("http", server.URL, timeout); value < 0 || hits.Load() != 1 {
		t.Fatalf("permitted HTTP probe returned %d and made %d requests", value, hits.Load())
	}
	if value := ProbePing("tcp", tcpAddress, timeout); value < 0 {
		t.Fatalf("permitted TCP probe returned %d", value)
	}
	if _, err := resolveIP(t.Context(), "127.0.0.2"); err == nil {
		t.Fatal("permission for one IP admitted a second IP")
	}
}
