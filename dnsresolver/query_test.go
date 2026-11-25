package dnsresolver

import (
	"context"
	"net"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCustomDNSFallsBackOnAnUnansweredQuestion(t *testing.T) {
	unresponsive, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer unresponsive.Close()
	responding, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer responding.Close()

	seen := make(chan struct{}, 1)
	go func() {
		var buf [4096]byte
		if _, _, err := unresponsive.ReadFrom(buf[:]); err == nil {
			seen <- struct{}{}
		}
	}()
	go func() {
		var buf [4096]byte
		n, peer, err := responding.ReadFrom(buf[:])
		if err != nil {
			return
		}
		var query dnsmessage.Message
		if err := query.Unpack(buf[:n]); err != nil || len(query.Questions) != 1 {
			return
		}
		response := dnsmessage.Message{
			Header:    dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true},
			Questions: query.Questions,
			Answers: []dnsmessage.Resource{{
				Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Class: dnsmessage.ClassINET},
				Body:   &dnsmessage.AResource{A: [4]byte{192, 0, 2, 32}},
			}},
		}
		if packed, err := response.Pack(); err == nil {
			_, _ = responding.WriteTo(packed, peer)
		}
	}()

	resolver := resolverForServer(unresponsive.LocalAddr().String(), []string{responding.LocalAddr().String()})
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := resolver.LookupIP(ctx, "ip4", "fixture.test.")
	if err != nil || len(ips) != 1 || ips[0].String() != "192.0.2.32" {
		t.Fatalf("fallback returned %v: %v", ips, err)
	}
	select {
	case <-seen:
	default:
		t.Fatal("custom DNS server never received a question")
	}
}

func TestDNSChangeReplacesUnaryAndStreamingClients(t *testing.T) {
	t.Cleanup(func() { SetCustomDNSServer("") })
	SetCustomDNSServer("127.0.0.1:10253")
	unary := GetHTTPClient(time.Second)
	stream := GetStreamingHTTPClientWithPreference("4")
	SetCustomDNSServer("127.0.0.1:20253")
	if GetHTTPClient(time.Second) == unary || GetStreamingHTTPClientWithPreference("4") == stream {
		t.Fatal("a client retained the previous DNS configuration")
	}
}
