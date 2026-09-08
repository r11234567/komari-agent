package clientcore

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"connectrpc.com/connect"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
)

// withReconnectInterval pins the operator-configured interval for one test.
func withReconnectInterval(t *testing.T, seconds int) {
	t.Helper()
	previous := flags_pkg.GlobalConfig.ReconnectInterval
	flags_pkg.GlobalConfig.ReconnectInterval = seconds
	t.Cleanup(func() { flags_pkg.GlobalConfig.ReconnectInterval = previous })
}

// connectErrorWithHeader builds a Connect error carrying response metadata, the
// way the client surfaces one from a real HTTP response.
func connectErrorWithHeader(code connect.Code, header http.Header) error {
	err := connect.NewError(code, errors.New("synthetic"))
	for key, values := range header {
		for _, value := range values {
			err.Meta().Add(key, value)
		}
	}
	return err
}

func TestRetryPolicyEscalatesTransportFailures(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	failure := connect.NewError(connect.CodeUnavailable, errors.New("transport"))

	// Jitter only shortens, so each delay is bounded above by the ideal value
	// and must still be strictly growing across the doubling range.
	previous := time.Duration(0)
	for attempt := 1; attempt <= 4; attempt++ {
		delay := policy.next(failure)
		if delay <= previous {
			t.Fatalf("attempt %d delay %v did not grow beyond %v", attempt, delay, previous)
		}
		ideal := 5 * time.Second * (1 << (attempt - 1))
		if delay > ideal {
			t.Fatalf("attempt %d delay %v exceeded un-jittered bound %v", attempt, delay, ideal)
		}
		previous = delay
	}
}

func TestRetryPolicyCapsTransportBackoff(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	failure := connect.NewError(connect.CodeUnavailable, errors.New("transport"))
	for i := 0; i < 40; i++ {
		policy.next(failure)
	}
	if delay := policy.next(failure); delay > retryMaxDelay {
		t.Fatalf("sustained failures produced %v, above the %v cap", delay, retryMaxDelay)
	}
}

func TestRetryPolicyFloorsAuthRejections(t *testing.T) {
	withReconnectInterval(t, 5)
	// A rotated or revoked token must not be retried at connection cadence:
	// that is the burst which gets an Agent's address banned.
	for _, code := range []connect.Code{connect.CodeUnauthenticated, connect.CodePermissionDenied} {
		var policy retryPolicy
		delay := policy.next(connect.NewError(code, errors.New("rejected")))
		if delay < retryAuthMinDelay-time.Duration(float64(retryAuthMinDelay)*retryJitterFraction) {
			t.Fatalf("%v retried after %v, far below the %v floor", code, delay, retryAuthMinDelay)
		}
		if delay > retryAuthMinDelay {
			t.Fatalf("%v first delay %v exceeded un-jittered floor %v", code, delay, retryAuthMinDelay)
		}
	}
}

func TestRetryPolicyCapsAuthBackoffSoRotationRecovers(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	rejected := connect.NewError(connect.CodeUnauthenticated, errors.New("rejected"))
	for i := 0; i < 40; i++ {
		policy.next(rejected)
	}
	// The Agent has to pick up a repaired token eventually without an operator
	// restarting it, so the auth backoff is capped rather than unbounded.
	if delay := policy.next(rejected); delay > retryAuthMaxDelay {
		t.Fatalf("auth backoff reached %v, above the %v cap", delay, retryAuthMaxDelay)
	}
}

func TestRetryPolicyHonoursRetryAfterSeconds(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	err := connectErrorWithHeader(connect.CodeResourceExhausted, http.Header{"Retry-After": {"45"}})
	delay := policy.next(err)
	if delay > 45*time.Second {
		t.Fatalf("delay %v exceeded the server hint of 45s", delay)
	}
	if delay < 30*time.Second {
		t.Fatalf("delay %v ignored the server hint of 45s", delay)
	}
}

func TestRetryPolicyHonoursRetryAfterHTTPDate(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	at := time.Now().UTC().Add(90 * time.Second)
	err := connectErrorWithHeader(connect.CodeResourceExhausted,
		http.Header{"Retry-After": {at.Format(http.TimeFormat)}})
	delay := policy.next(err)
	if delay > 90*time.Second {
		t.Fatalf("delay %v exceeded the HTTP-date hint", delay)
	}
	if delay < 45*time.Second {
		t.Fatalf("delay %v ignored the HTTP-date hint", delay)
	}
}

func TestRetryPolicyClampsHostileRetryAfter(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	// A misconfigured or hostile intermediary must not be able to park an Agent
	// for a day, nor to defeat the backoff by asking for an immediate retry.
	long := connectErrorWithHeader(connect.CodeResourceExhausted, http.Header{"Retry-After": {"86400"}})
	if delay := policy.next(long); delay > retryServerHintCap {
		t.Fatalf("hint of 86400s produced %v, above the %v clamp", delay, retryServerHintCap)
	}
	short := connectErrorWithHeader(connect.CodeResourceExhausted, http.Header{"Retry-After": {"1"}})
	if delay := policy.next(short); delay < time.Second {
		t.Fatalf("hint of 1s produced %v, below a one second floor", delay)
	}
}

func TestRetryPolicyIgnoresMalformedRetryAfter(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	err := connectErrorWithHeader(connect.CodeResourceExhausted, http.Header{"Retry-After": {"soon"}})
	// An unparseable hint falls back to local backoff rather than to no wait.
	if delay := policy.next(err); delay < time.Second {
		t.Fatalf("malformed hint produced %v", delay)
	}
}

func TestRetryPolicyTreatsCleanStreamCloseAsProgress(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	failure := connect.NewError(connect.CodeUnavailable, errors.New("transport"))
	policy.next(failure)
	policy.next(failure)
	policy.next(failure)

	// A server stream closing without error is a normal re-subscribe. It must
	// not inherit an earlier failure streak's backoff, or a healthy Agent would
	// drift towards multi-minute gaps in its event subscription.
	delay := policy.next(nil)
	if delay > 5*time.Second {
		t.Fatalf("clean stream close waited %v, beyond the base interval", delay)
	}
	if next := policy.next(failure); next > 5*time.Second {
		t.Fatalf("attempt counter was not reset: next failure waited %v", next)
	}
}

func TestRetryPolicyResetReturnsToBaseInterval(t *testing.T) {
	withReconnectInterval(t, 5)
	var policy retryPolicy
	failure := connect.NewError(connect.CodeUnavailable, errors.New("transport"))
	for i := 0; i < 6; i++ {
		policy.next(failure)
	}
	policy.Reset()
	if delay := policy.next(failure); delay > 5*time.Second {
		t.Fatalf("Reset left the delay at %v", delay)
	}
}

func TestRetryPolicyWaitStopsOnCancelledContext(t *testing.T) {
	withReconnectInterval(t, 5)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var policy retryPolicy
	if policy.Wait(ctx, connect.NewError(connect.CodeUnavailable, errors.New("x"))) {
		t.Fatal("Wait reported continue on a cancelled context")
	}
}

func TestJitterOnlyShortens(t *testing.T) {
	// The whole backoff design relies on jitter never exceeding the requested
	// delay, so every documented cap stays a true upper bound.
	for i := 0; i < 500; i++ {
		if got := jitter(time.Minute); got > time.Minute {
			t.Fatalf("jitter returned %v, above the requested minute", got)
		}
	}
}

func TestJitterKeepsPositiveFloor(t *testing.T) {
	if got := jitter(0); got <= 0 {
		t.Fatalf("jitter(0) returned %v", got)
	}
	if got := jitter(time.Millisecond); got < time.Second {
		t.Fatalf("jitter of a sub-second delay returned %v", got)
	}
}

func TestRejectionClassification(t *testing.T) {
	tests := []struct {
		name      string
		err       error
		auth      bool
		limited   bool
		transient bool
	}{
		{"unauthenticated", connect.NewError(connect.CodeUnauthenticated, errors.New("x")), true, false, true},
		{"permission denied", connect.NewError(connect.CodePermissionDenied, errors.New("x")), true, false, true},
		{"resource exhausted", connect.NewError(connect.CodeResourceExhausted, errors.New("x")), false, true, true},
		{"unavailable", connect.NewError(connect.CodeUnavailable, errors.New("x")), false, false, false},
		{"unimplemented", connect.NewError(connect.CodeUnimplemented, errors.New("x")), false, false, false},
		{"plain error", errors.New("dial tcp: timeout"), false, false, false},
		{"nil", nil, false, false, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := isAuthRejection(test.err); got != test.auth {
				t.Errorf("isAuthRejection = %t, want %t", got, test.auth)
			}
			if got := isRateLimited(test.err); got != test.limited {
				t.Errorf("isRateLimited = %t, want %t", got, test.limited)
			}
			if got := isTransientRejection(test.err); got != test.transient {
				t.Errorf("isTransientRejection = %t, want %t", got, test.transient)
			}
		})
	}
}

func TestRestartDelayEscalatesAndCaps(t *testing.T) {
	withReconnectInterval(t, 5)
	first := RestartDelay(1)
	if first > 5*time.Second {
		t.Fatalf("first restart waited %v, beyond the base interval", first)
	}
	if later := RestartDelay(3); later <= first {
		t.Fatalf("restart delay did not grow: %v then %v", first, later)
	}
	if capped := RestartDelay(1000); capped > retryMaxDelay {
		t.Fatalf("restart delay reached %v, above the %v cap", capped, retryMaxDelay)
	}
	// Callers pass a 1-based attempt; a defensive zero must not panic or return
	// a non-positive delay that would spin the supervision loop.
	if zero := RestartDelay(0); zero <= 0 {
		t.Fatalf("RestartDelay(0) returned %v", zero)
	}
}

func TestUnsupportedIsNotTransient(t *testing.T) {
	// Unsupported drives capability fallback, never a retry. Conflating the two
	// would make an old panel look like a rate-limited one and stall fallback.
	for _, code := range []connect.Code{connect.CodeUnimplemented, connect.CodeNotFound} {
		err := connect.NewError(code, errors.New("x"))
		if !isUnsupported(err) {
			t.Fatalf("%v was not recognised as unsupported", code)
		}
		if isTransientRejection(err) {
			t.Fatalf("%v was treated as a transient rejection", code)
		}
	}
}
