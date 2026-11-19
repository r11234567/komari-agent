package dnsresolver

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestPreferredUnreachableFamilyFallsBackBeforeItsConnectionTimeout(t *testing.T) {
	for _, preference := range []string{"4", "6"} {
		t.Run(preference, func(t *testing.T) {
			primary := "tcp" + preference
			entered := make(chan string, 2)
			cancelled := make(chan struct{})
			client, peer := net.Pipe()
			defer peer.Close()
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			started := time.Now()
			conn, err := raceIPFamilies(ctx, "fixture.invalid:443", preference, 20*time.Millisecond, func(ctx context.Context, family, _ string) (net.Conn, error) {
				entered <- family
				if family == primary {
					<-ctx.Done()
					close(cancelled)
					return nil, ctx.Err()
				}
				return client, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if first := <-entered; first != primary {
				t.Fatalf("preference ignored: %s", first)
			}
			if time.Since(started) > 500*time.Millisecond {
				t.Fatal("fallback waited for the unreachable family's timeout")
			}
			select {
			case <-cancelled:
			case <-time.After(time.Second):
				t.Fatal("losing connection attempt was not cancelled")
			}
		})
	}
}

func TestIPFamilyRaceClosesLateSuccessfulLoser(t *testing.T) {
	primaryClient, primaryPeer := net.Pipe()
	defer primaryPeer.Close()
	secondaryClient, secondaryPeer := net.Pipe()
	defer secondaryPeer.Close()
	secondaryStarted := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, err := raceIPFamilies(ctx, "fixture.invalid:443", "4", time.Millisecond, func(ctx context.Context, family, _ string) (net.Conn, error) {
		if family == "tcp4" {
			<-secondaryStarted
			return primaryClient, nil
		}
		close(secondaryStarted)
		<-ctx.Done()
		return secondaryClient, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = secondaryPeer.SetReadDeadline(time.Now().Add(time.Second))
	_, err = secondaryPeer.Read(make([]byte, 1))
	if err == nil {
		t.Fatal("losing socket remained open")
	}
	if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
		t.Fatal("losing socket leaked until test deadline")
	}
}

func TestIPFamilyRaceCancellationAndBothFailures(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := raceIPFamilies(ctx, "fixture.invalid:443", "4", time.Millisecond, func(context.Context, string, string) (net.Conn, error) {
		t.Error("cancelled request dialled")
		return nil, errors.New("bad")
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	first, second := errors.New("ipv4 failed"), errors.New("ipv6 failed")
	_, err = raceIPFamilies(context.Background(), "fixture.invalid:443", "4", time.Hour, func(_ context.Context, family, _ string) (net.Conn, error) {
		if family == "tcp4" {
			return nil, first
		}
		return nil, second
	})
	if !errors.Is(err, first) || !errors.Is(err, second) {
		t.Fatalf("lost address-family errors: %v", err)
	}
}

func TestConnectionDeadlineIncludesCustomDNSResolution(t *testing.T) {
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, _, _ string) (net.Conn, error) { <-ctx.Done(); return nil, ctx.Err() }}
	started := time.Now()
	_, err := dialWithPreference(context.Background(), "tcp", "synthetic.invalid:443", "", 40*time.Millisecond, resolver)
	if err == nil {
		t.Fatal("blocked DNS unexpectedly connected")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("DNS escaped the connection deadline")
	}
}
