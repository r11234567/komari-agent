package server

import (
	"context"
	cryptorand "crypto/rand"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	v2 "github.com/komari-monitor/komari-agent/protocol/v2"
	"github.com/komari-monitor/komari-agent/ws"
	networkv1 "github.com/r11234567/komari-proto/gen/go/komari/network/v1"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

var routeProbeMu sync.Mutex

// ProbeReturnRoute executes the built-in ICMP traceroute used by both the
// Connect service and the legacy v2 compatibility adapter.
func ProbeReturnRoute(ctx context.Context, assignment *networkv1.ReturnRouteProbeAssignment) ([]*networkv1.ReturnRouteHop, error) {
	return probeReturnRoute(ctx, assignment, traceRouteICMPv4, traceRouteICMPv6)
}

func probeReturnRoute(
	ctx context.Context,
	assignment *networkv1.ReturnRouteProbeAssignment,
	probeIPv4 func(context.Context, net.IP, int, time.Duration) ([]*networkv1.ReturnRouteHop, error),
	probeIPv6 func(context.Context, net.IP, int, time.Duration) ([]*networkv1.ReturnRouteHop, error),
) (hops []*networkv1.ReturnRouteHop, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			hops = nil
			err = fmt.Errorf("built-in route probe failed unexpectedly: %v", recovered)
		}
	}()
	if assignment == nil || strings.TrimSpace(assignment.Target) == "" {
		return nil, fmt.Errorf("return route target is required")
	}
	version := int(assignment.IpVersion)
	if version != 4 && version != 6 {
		return nil, fmt.Errorf("unsupported IP version %d", version)
	}
	if assignment.Protocol != "" && !strings.EqualFold(assignment.Protocol, "icmp") {
		return nil, fmt.Errorf("unsupported return route protocol %q", assignment.Protocol)
	}
	maxHops := int(assignment.MaxHops)
	if maxHops < 1 || maxHops > 64 {
		maxHops = 30
	}
	hopTimeout := 900 * time.Millisecond
	if assignment.HopTimeout != nil && assignment.HopTimeout.IsValid() && assignment.HopTimeout.AsDuration() > 0 {
		hopTimeout = assignment.HopTimeout.AsDuration()
	}
	destination, err := resolveRouteTarget(ctx, assignment.Target, version)
	if err != nil {
		return nil, err
	}
	routeProbeMu.Lock()
	defer routeProbeMu.Unlock()
	if version == 6 {
		return probeIPv6(ctx, destination, maxHops, hopTimeout)
	}
	return probeIPv4(ctx, destination, maxHops, hopTimeout)
}

func runLegacyRouteTask(conn *ws.SafeConn, task v2.RouteParams) {
	assignment := &networkv1.ReturnRouteProbeAssignment{
		TaskId: uint64(task.TaskID), Protocol: task.Protocol, Target: task.Target,
		IpVersion: uint32(task.IPVersion), MaxHops: uint32(task.MaxHops),
	}
	hops, err := ProbeReturnRoute(context.Background(), assignment)
	errText := ""
	if err != nil {
		errText = err.Error()
	}
	legacyHops := make([]v2.RouteHop, 0, len(hops))
	for _, hop := range hops {
		legacyHops = append(legacyHops, v2.RouteHop{TTL: int(hop.Ttl), IP: hop.Ip, LatencyMS: hop.LatencyMs, Timeout: hop.Timeout})
	}
	payload := v2.BuildRouteResultPayload(task, legacyHops, errText, time.Now())
	if conn == nil {
		if err := postV2RPC(payload); err != nil {
			log.Printf("Failed to upload return route result over POST: %v", err)
		}
		return
	}
	if err := conn.WriteJSON(payload); err != nil {
		log.Printf("Failed to upload return route result: %v", err)
	}
}

func resolveRouteTarget(ctx context.Context, target string, version int) (net.IP, error) {
	if host, _, err := net.SplitHostPort(target); err == nil {
		target = host
	}
	if ip := net.ParseIP(strings.Trim(target, "[]")); ip != nil {
		if (version == 4 && ip.To4() != nil) || (version == 6 && ip.To4() == nil) {
			return ip, nil
		}
		return nil, fmt.Errorf("target does not have the requested IPv%d address", version)
	}
	resolveCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	addresses, err := net.DefaultResolver.LookupIP(resolveCtx, "ip", target)
	if err != nil {
		return nil, fmt.Errorf("resolve target: %w", err)
	}
	for _, ip := range addresses {
		if (version == 4 && ip.To4() != nil) || (version == 6 && ip.To4() == nil) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("target does not have the requested IPv%d address", version)
}

func traceRouteICMPv4(ctx context.Context, destination net.IP, maxHops int, timeout time.Duration) ([]*networkv1.ReturnRouteHop, error) {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		return nil, fmt.Errorf("open built-in ICMP route probe (root/CAP_NET_RAW may be required): %w", err)
	}
	defer conn.Close()
	packet := conn.IPv4PacketConn()
	if packet == nil {
		return nil, fmt.Errorf("open built-in IPv4 route probe: packet connection is unavailable")
	}
	hops := make([]*networkv1.ReturnRouteHop, 0, maxHops)
	id := nextRouteProbeID()
	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			return hops, err
		}
		if err := packet.SetTTL(ttl); err != nil {
			return hops, fmt.Errorf("set IPv4 TTL: %w", err)
		}
		message := icmp.Message{Type: ipv4.ICMPTypeEcho, Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("komari-route")}}
		payload, err := message.Marshal(nil)
		if err != nil {
			return hops, err
		}
		start := time.Now()
		deadline := start.Add(timeout)
		_ = conn.SetDeadline(deadline)
		if _, err := conn.WriteTo(payload, &net.IPAddr{IP: destination}); err != nil {
			return hops, fmt.Errorf("send IPv4 route probe: %w", err)
		}

		matched, reached, hop, err := readIPv4RouteReply(conn, destination, id, ttl, start, deadline)
		if err != nil {
			return hops, err
		}
		if !matched {
			hops = append(hops, &networkv1.ReturnRouteHop{Ttl: uint32(ttl), Timeout: true})
			continue
		}
		hops = append(hops, hop)
		if reached {
			break
		}
	}
	return hops, nil
}

func traceRouteICMPv6(ctx context.Context, destination net.IP, maxHops int, timeout time.Duration) ([]*networkv1.ReturnRouteHop, error) {
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("open built-in IPv6 ICMP route probe (root/CAP_NET_RAW may be required): %w", err)
	}
	defer conn.Close()
	packet := conn.IPv6PacketConn()
	if packet == nil {
		return nil, fmt.Errorf("open built-in IPv6 route probe: packet connection is unavailable")
	}
	hops := make([]*networkv1.ReturnRouteHop, 0, maxHops)
	id := nextRouteProbeID()
	for ttl := 1; ttl <= maxHops; ttl++ {
		if err := ctx.Err(); err != nil {
			return hops, err
		}
		if err := packet.SetHopLimit(ttl); err != nil {
			return hops, fmt.Errorf("set IPv6 hop limit: %w", err)
		}
		message := icmp.Message{Type: ipv6.ICMPTypeEchoRequest, Body: &icmp.Echo{ID: id, Seq: ttl, Data: []byte("komari-route")}}
		payload, err := message.Marshal(nil)
		if err != nil {
			return hops, err
		}
		start := time.Now()
		deadline := start.Add(timeout)
		_ = conn.SetDeadline(deadline)
		if _, err := conn.WriteTo(payload, &net.IPAddr{IP: destination}); err != nil {
			return hops, fmt.Errorf("send IPv6 route probe: %w", err)
		}

		matched, reached, hop, err := readIPv6RouteReply(conn, destination, id, ttl, start, deadline)
		if err != nil {
			return hops, err
		}
		if !matched {
			hops = append(hops, &networkv1.ReturnRouteHop{Ttl: uint32(ttl), Timeout: true})
			continue
		}
		hops = append(hops, hop)
		if reached {
			break
		}
	}
	return hops, nil
}

func nextRouteProbeID() int {
	var bytes [2]byte
	if _, err := cryptorand.Read(bytes[:]); err == nil {
		return int(binary.BigEndian.Uint16(bytes[:]))
	}
	return (os.Getpid() ^ int(time.Now().UnixNano())) & 0xffff
}

func readIPv4RouteReply(conn *icmp.PacketConn, destination net.IP, id, sequence int, start, deadline time.Time) (bool, bool, *networkv1.ReturnRouteHop, error) {
	buffer := make([]byte, 1500)
	for {
		_ = conn.SetDeadline(deadline)
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return false, false, nil, nil
			}
			return false, false, nil, fmt.Errorf("read IPv4 route probe: %w", err)
		}
		reply, err := icmp.ParseMessage(1, buffer[:n])
		if err != nil || !matchesIPv4RouteReply(reply, destination, id, sequence, routePeerIP(peer)) {
			continue
		}
		ip := routePeerIP(peer)
		return true, reply.Type == ipv4.ICMPTypeEchoReply, &networkv1.ReturnRouteHop{
			Ttl: uint32(sequence), Ip: ip, LatencyMs: float64(time.Since(start).Microseconds()) / 1000,
		}, nil
	}
}

func readIPv6RouteReply(conn *icmp.PacketConn, destination net.IP, id, sequence int, start, deadline time.Time) (bool, bool, *networkv1.ReturnRouteHop, error) {
	buffer := make([]byte, 1500)
	for {
		_ = conn.SetDeadline(deadline)
		n, peer, err := conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				return false, false, nil, nil
			}
			return false, false, nil, fmt.Errorf("read IPv6 route probe: %w", err)
		}
		reply, err := icmp.ParseMessage(58, buffer[:n])
		if err != nil || !matchesIPv6RouteReply(reply, destination, id, sequence, routePeerIP(peer)) {
			continue
		}
		ip := routePeerIP(peer)
		return true, reply.Type == ipv6.ICMPTypeEchoReply, &networkv1.ReturnRouteHop{
			Ttl: uint32(sequence), Ip: ip, LatencyMs: float64(time.Since(start).Microseconds()) / 1000,
		}, nil
	}
}

func matchesIPv4RouteReply(reply *icmp.Message, destination net.IP, id, sequence int, peer string) bool {
	if reply == nil {
		return false
	}
	if reply.Type == ipv4.ICMPTypeEchoReply {
		echo, ok := reply.Body.(*icmp.Echo)
		return ok && echo.ID == id && echo.Seq == sequence && net.ParseIP(peer).Equal(destination)
	}
	quoted := quotedICMPData(reply.Body)
	if quoted == nil {
		return false
	}
	header, err := ipv4.ParseHeader(quoted)
	if err != nil || header.Version != ipv4.Version || header.Protocol != 1 || !header.Dst.Equal(destination) || len(quoted) < header.Len {
		return false
	}
	inner, err := icmp.ParseMessage(1, quoted[header.Len:])
	if err != nil {
		return false
	}
	echo, ok := inner.Body.(*icmp.Echo)
	return ok && inner.Type == ipv4.ICMPTypeEcho && echo.ID == id && echo.Seq == sequence
}

func matchesIPv6RouteReply(reply *icmp.Message, destination net.IP, id, sequence int, peer string) bool {
	if reply == nil {
		return false
	}
	if reply.Type == ipv6.ICMPTypeEchoReply {
		echo, ok := reply.Body.(*icmp.Echo)
		return ok && echo.ID == id && echo.Seq == sequence && net.ParseIP(peer).Equal(destination)
	}
	quoted := quotedICMPData(reply.Body)
	if quoted == nil {
		return false
	}
	header, err := ipv6.ParseHeader(quoted)
	if err != nil || header.Version != ipv6.Version || header.NextHeader != 58 || !header.Dst.Equal(destination) || len(quoted) < ipv6.HeaderLen {
		return false
	}
	inner, err := icmp.ParseMessage(58, quoted[ipv6.HeaderLen:])
	if err != nil {
		return false
	}
	echo, ok := inner.Body.(*icmp.Echo)
	return ok && inner.Type == ipv6.ICMPTypeEchoRequest && echo.ID == id && echo.Seq == sequence
}

func quotedICMPData(body icmp.MessageBody) []byte {
	switch value := body.(type) {
	case *icmp.TimeExceeded:
		return value.Data
	case *icmp.DstUnreach:
		return value.Data
	case *icmp.PacketTooBig:
		return value.Data
	case *icmp.ParamProb:
		return value.Data
	default:
		return nil
	}
}

func routePeerIP(addr net.Addr) string {
	switch value := addr.(type) {
	case *net.IPAddr:
		return value.IP.String()
	case *net.UDPAddr:
		return value.IP.String()
	default:
		return strings.Split(addr.String(), "%")[0]
	}
}
