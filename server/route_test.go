package server

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	networkv1 "github.com/r11234567/komari-proto/gen/go/komari/network/v1"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
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

func TestMatchesIPv4RouteReplyRejectsUnrelatedEchoReply(t *testing.T) {
	destination := net.ParseIP("61.128.192.68")
	reply := &icmp.Message{
		Type: ipv4.ICMPTypeEchoReply,
		Body: &icmp.Echo{ID: 1234, Seq: 9},
	}
	if matchesIPv4RouteReply(reply, destination, 1234, 9, "1.1.1.1") {
		t.Fatal("accepted an echo reply from an unrelated destination")
	}
	if !matchesIPv4RouteReply(reply, destination, 1234, 9, destination.String()) {
		t.Fatal("rejected the matching destination echo reply")
	}
}

func TestMatchesIPv4RouteReplyChecksQuotedProbe(t *testing.T) {
	destination := net.ParseIP("61.128.192.68")
	inner, err := (&icmp.Message{
		Type: ipv4.ICMPTypeEcho,
		Body: &icmp.Echo{ID: 4321, Seq: 7},
	}).Marshal(nil)
	if err != nil {
		t.Fatal(err)
	}
	header, err := (&ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TotalLen: ipv4.HeaderLen + len(inner),
		TTL:      1,
		Protocol: 1,
		Src:      net.ParseIP("192.0.2.10"),
		Dst:      destination,
	}).Marshal()
	if err != nil {
		t.Fatal(err)
	}
	reply := &icmp.Message{
		Type: ipv4.ICMPTypeTimeExceeded,
		Body: &icmp.TimeExceeded{Data: append(header, inner...)},
	}
	if !matchesIPv4RouteReply(reply, destination, 4321, 7, "192.0.2.1") {
		t.Fatal("rejected the matching quoted probe")
	}
	if matchesIPv4RouteReply(reply, destination, 4321, 8, "192.0.2.1") {
		t.Fatal("accepted a quoted probe with the wrong sequence")
	}
	if matchesIPv4RouteReply(reply, net.ParseIP("203.0.113.1"), 4321, 7, "192.0.2.1") {
		t.Fatal("accepted a quoted probe for the wrong destination")
	}
}
