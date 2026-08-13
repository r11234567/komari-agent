package server

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	networkv1 "github.com/r11234567/komari-proto/gen/go/komari/network/v1"
)

func TestResolveRouteTargetLiteralAddress(t *testing.T) {
	ip, err := resolveRouteTarget(context.Background(), "1.1.1.1", 4)
	if err != nil || ip.String() != "1.1.1.1" {
		t.Fatalf("resolve IPv4 literal = %v, %v", ip, err)
	}
	if _, err := resolveRouteTarget(context.Background(), "1.1.1.1", 6); err == nil {
		t.Fatal("IPv4 literal unexpectedly accepted for IPv6 task")
	}
}

func TestProbeReturnRouteConvertsPanicsToErrors(t *testing.T) {
	assignment := &networkv1.ReturnRouteProbeAssignment{
		Target: "192.0.2.1", IpVersion: 4, Protocol: "icmp", MaxHops: 1,
	}
	panicProbe := func(context.Context, net.IP, int, time.Duration) ([]*networkv1.ReturnRouteHop, error) {
		panic("probe panic")
	}
	_, err := probeReturnRoute(context.Background(), assignment, panicProbe, traceRouteICMPv6)
	if err == nil || !strings.Contains(err.Error(), "probe panic") {
		t.Fatalf("probeReturnRoute() error = %v, want recovered panic", err)
	}
}
