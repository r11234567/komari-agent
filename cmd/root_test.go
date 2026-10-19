package cmd

import (
	"errors"
	"fmt"
	"net"
	"testing"

	"connectrpc.com/connect"
	"github.com/komari-monitor/komari-agent/clientcore"
)

func TestHandleSessionOutcome_TransientFailuresMustNotExit(t *testing.T) {
	// 1. ErrLegacyFallback (caused by server restart or CodeUnavailable) must NOT cause exit
	shouldExit, exitErr := handleSessionOutcome(clientcore.ErrLegacyFallback)
	if shouldExit || exitErr != nil {
		t.Fatalf("ErrLegacyFallback caused fatal exit (shouldExit=%v, err=%v); must retry instead", shouldExit, exitErr)
	}

	// 2. Wrapped ErrLegacyFallback must NOT cause exit
	wrappedLegacy := fmt.Errorf("%w: %v", clientcore.ErrLegacyFallback, connect.NewError(connect.CodeUnavailable, errors.New("backend restart")))
	shouldExit, exitErr = handleSessionOutcome(wrappedLegacy)
	if shouldExit || exitErr != nil {
		t.Fatalf("wrapped ErrLegacyFallback caused fatal exit (shouldExit=%v, err=%v); must retry instead", shouldExit, exitErr)
	}

	// 3. Transient network error must NOT cause exit
	netErr := &net.OpError{Op: "dial", Err: errors.New("connection refused")}
	shouldExit, exitErr = handleSessionOutcome(netErr)
	if shouldExit || exitErr != nil {
		t.Fatalf("network error caused fatal exit (shouldExit=%v, err=%v); must retry instead", shouldExit, exitErr)
	}

	// 4. Clean exit (nil error) must NOT cause fatal exit
	shouldExit, exitErr = handleSessionOutcome(nil)
	if shouldExit || exitErr != nil {
		t.Fatalf("nil error caused fatal exit (shouldExit=%v, err=%v)", shouldExit, exitErr)
	}
}

func TestHandleSessionOutcome_FatalFailuresMustExit(t *testing.T) {
	// 1. Unconfigured agent must exit so CLI doesn't spin infinitely
	shouldExit, exitErr := handleSessionOutcome(clientcore.ErrUnconfigured)
	if !shouldExit || !errors.Is(exitErr, clientcore.ErrUnconfigured) {
		t.Fatalf("expected ErrUnconfigured to cause exit (shouldExit=%v, err=%v)", shouldExit, exitErr)
	}

	// 2. Revoked credentials (403 PERMISSION_DENIED) must exit
	shouldExit, exitErr = handleSessionOutcome(clientcore.ErrPermissionDenied)
	if !shouldExit || !errors.Is(exitErr, clientcore.ErrPermissionDenied) {
		t.Fatalf("expected ErrPermissionDenied to cause exit (shouldExit=%v, err=%v)", shouldExit, exitErr)
	}
}
