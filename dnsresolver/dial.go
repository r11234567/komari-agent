package dnsresolver

import (
	"context"
	"errors"
	"net"
	"time"
)

const ipFamilyFallbackDelay = 300 * time.Millisecond

// Let net.Dialer resolve and race addresses. Dialling LookupHost results one
// at a time both disabled Happy Eyeballs and gave each bad IP a full timeout;
// LookupHost itself was outside the connection timeout on streaming clients.
func dialWithPreference(ctx context.Context, network, address, preference string, timeout time.Duration, resolver *net.Resolver) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: 30 * time.Second, Resolver: resolver, FallbackDelay: ipFamilyFallbackDelay}
	if network != "tcp" || preference == "" {
		return dialer.DialContext(ctx, network, address)
	}
	bounded, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	return raceIPFamilies(bounded, address, preference, ipFamilyFallbackDelay, dialer.DialContext)
}

// Explicit 4/6 is a preference, matching the old fallback semantics. Start its
// family first, then race the other after a short head start instead of waiting
// 15 seconds per unusable address. Each family retains Go's own address budget.
func raceIPFamilies(ctx context.Context, address, preference string, delay time.Duration, dial func(context.Context, string, string) (net.Conn, error)) (net.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	primary, secondary := "tcp4", "tcp6"
	if preference == "6" {
		primary, secondary = secondary, primary
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		connection net.Conn
		err        error
	}
	results := make(chan result)
	done := make(chan struct{})
	defer close(done)
	start := func(network string) {
		go func() {
			conn, err := dial(ctx, network, address)
			if err != nil && conn != nil {
				_ = conn.Close()
				conn = nil
			}
			select {
			case results <- result{conn, err}:
			case <-done:
				if conn != nil {
					_ = conn.Close()
				}
			case <-ctx.Done():
				if conn != nil {
					_ = conn.Close()
				}
			}
		}()
	}
	start(primary)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	fallback := timer.C
	secondaryStarted := false
	startSecondary := func() {
		if !secondaryStarted {
			secondaryStarted = true
			start(secondary)
		}
		fallback = nil
	}
	var failures []error
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-fallback:
			startSecondary()
		case result := <-results:
			if result.err == nil && result.connection != nil {
				if err := ctx.Err(); err != nil {
					_ = result.connection.Close()
					return nil, err
				}
				return result.connection, nil
			}
			failures = append(failures, result.err)
			startSecondary()
			if len(failures) == 2 {
				return nil, errors.Join(failures...)
			}
		}
	}
}
