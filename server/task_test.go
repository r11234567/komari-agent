package server

import (
	"net/url"
	"testing"
	"time"
)

var testTargets = []struct {
	target string
}{
	{"v6-sh-cm.oojj.de"},
	{"2409:8c1e:8f80:2:6a::"},
	{"[2409:8c1e:8f80:2:6a::]"},
	{"[2409:8c1e:8f80:2:6a::]:80"},
	{"v4-sh-cm.oojj.de"},
	{"117.185.125.154"},
	{"117.185.125.154:80"},
}

func TestICMPPing(t *testing.T) {
	timeout := 3 * time.Second
	for _, tt := range testTargets {
		t.Run(tt.target, func(t *testing.T) {
			latency, err := icmpPing(tt.target, timeout)
			if latency < -1 {
				t.Errorf("ICMP ping %s: invalid latency %d", tt.target, latency)
			}
			if err != nil {
				t.Errorf("ICMP ping %s error: %v", tt.target, err)
			}
		})
	}
}

func TestTCPPing(t *testing.T) {
	timeout := 3 * time.Second
	for _, tt := range testTargets {
		t.Run(tt.target, func(t *testing.T) {
			latency, err := tcpPing(tt.target, timeout)
			if latency < -1 {
				t.Errorf("TCP ping %s: invalid latency %d", tt.target, latency)
			}
			if err != nil {
				t.Errorf("TCP ping %s error: %v", tt.target, err)
			}
		})
	}
}

func TestHTTPPing(t *testing.T) {
	timeout := 3 * time.Second
	for _, tt := range testTargets {
		t.Run(tt.target, func(t *testing.T) {
			latency, err := httpPing(tt.target, timeout)
			if latency < -1 {
				t.Errorf("HTTP ping %s: invalid latency %d", tt.target, latency)
			}
			if err != nil {
				t.Errorf("HTTP ping %s error: %v", tt.target, err)
			}
		})
	}
}

func TestNormalizeHTTPPingTarget(t *testing.T) {
	tests := []struct {
		name   string
		target string
		want   string
	}{
		{name: "hostname", target: "example.com", want: "http://example.com"},
		{name: "HTTPS path", target: "https://example.com/health", want: "https://example.com/health"},
		{name: "IPv6", target: "2001:db8::1", want: "http://[2001:db8::1]"},
		{name: "private target", target: "http://10.0.0.1:8080/status", want: "http://10.0.0.1:8080/status"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeHTTPPingTarget(tt.target)
			if err != nil {
				t.Fatalf("normalize target: %v", err)
			}
			if got.String() != tt.want {
				t.Fatalf("normalized target = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNormalizeHTTPPingTargetRejectsUnsafeInput(t *testing.T) {
	tests := []string{
		"",
		"ftp://example.com/file",
		"http://user:password@example.com",
		"http://example.com:invalid",
		"http://example.com/path#fragment",
	}
	for _, target := range tests {
		t.Run(url.PathEscape(target), func(t *testing.T) {
			if _, err := normalizeHTTPPingTarget(target); err == nil {
				t.Fatalf("expected target %q to be rejected", target)
			}
		})
	}
}

func TestProbePingRejectsUnsupportedProtocol(t *testing.T) {
	if got := ProbePing("unsupported", "example.com", time.Second); got != -1 {
		t.Fatalf("ProbePing returned %d, want -1", got)
	}
}
