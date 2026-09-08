package clientcore

import (
	"context"
	"errors"
	"math/rand"
	"net/http"
	"strconv"
	"time"

	"connectrpc.com/connect"
	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
)

// Retry pacing. The Agent used to re-dial every failure after a fixed
// ReconnectInterval, which made a transient rejection indistinguishable from an
// attack to any log-driven IP banning layer in front of the panel: one Agent
// produced a steady stream of 4xx at a constant period, forever. The values
// below bound that to a handful of requests per minute per Agent and spread
// fleets that would otherwise re-dial in lockstep.
const (
	// retryJitterFraction is the proportion of a delay that is randomized. It
	// only ever shortens the wait, so the computed delay stays an upper bound.
	retryJitterFraction = 0.2
	// retryMaxDelay caps exponential growth for ordinary transport failures.
	retryMaxDelay = 5 * time.Minute
	// retryAuthMinDelay floors the wait after 401/403. Credentials are not
	// repaired by retrying sooner, and an Agent whose token was rotated or
	// revoked must not keep a rejection loop running at connection cadence.
	retryAuthMinDelay = 60 * time.Second
	// retryAuthMaxDelay caps the wait after 401/403. A token rotation has to be
	// picked up eventually without operator action.
	retryAuthMaxDelay = 15 * time.Minute
	// retryServerHintCap bounds a server-supplied Retry-After so a hostile or
	// misconfigured intermediary cannot park an Agent indefinitely.
	retryServerHintCap = 30 * time.Minute
)

// retryPolicy paces one retry loop. Each long-lived worker owns its own value so
// a failing subscription cannot slow down an unrelated healthy one.
//
// The zero value is ready to use and behaves as a fresh policy.
type retryPolicy struct {
	attempt int
}

// Reset returns the policy to its initial delay. Call it whenever the loop makes
// real progress, so a long-lived stream that is reconnecting after hours of
// healthy service starts over at the base interval rather than at the cap.
func (p *retryPolicy) Reset() {
	p.attempt = 0
}

// baseInterval is the operator-configured reconnect interval, floored at one
// second to match the historical flag semantics.
func baseInterval() time.Duration {
	return time.Duration(max(flags_pkg.GlobalConfig.ReconnectInterval, 1)) * time.Second
}

// Wait blocks until the next attempt is due, then reports whether the loop
// should continue. It returns false only when ctx is done.
//
// err is the failure that ended the previous attempt, and may be nil: a server
// stream that closes cleanly is a normal re-subscribe, not a failure, so it is
// paced at the base interval and does not escalate.
func (p *retryPolicy) Wait(ctx context.Context, err error) bool {
	delay := p.next(err)
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// next advances the attempt counter and returns the delay to apply.
func (p *retryPolicy) next(err error) time.Duration {
	if err == nil {
		// A clean stream close is not a failure. Keep the loop at its base
		// cadence and do not let normal re-subscribes escalate the backoff.
		p.attempt = 0
		return jitter(baseInterval())
	}

	p.attempt++

	// An explicit server hint outranks local guessing: honouring 429's
	// Retry-After is what lets the panel, rather than the Agent, decide the
	// recovery cadence. It is still clamped, and still jittered, because many
	// Agents receive the same hint at the same instant.
	if hint, ok := retryAfterHint(err); ok {
		return jitter(hint)
	}

	if isAuthRejection(err) {
		return jitter(backoffDelay(retryAuthMinDelay, retryAuthMaxDelay, p.attempt))
	}
	return jitter(backoffDelay(baseInterval(), retryMaxDelay, p.attempt))
}

// RestartDelay returns how long to wait before rebuilding the whole Connect
// client after its session ended. attempt is 1-based and counts consecutive
// restarts without a healthy session in between.
//
// It exists so the process-level supervision loop escalates like every retry
// loop inside the client: a panel that is down, or refusing this Agent, must not
// be re-handshaked at a fixed period forever.
func RestartDelay(attempt int) time.Duration {
	if attempt < 1 {
		attempt = 1
	}
	return jitter(backoffDelay(baseInterval(), retryMaxDelay, attempt))
}

// backoffDelay doubles base per attempt up to limit. attempt is 1-based, so the
// first retry waits exactly base.
func backoffDelay(base, limit time.Duration, attempt int) time.Duration {
	if base <= 0 {
		base = time.Second
	}
	if limit < base {
		limit = base
	}
	delay := base
	for i := 1; i < attempt; i++ {
		if delay >= limit/2 {
			return limit
		}
		delay *= 2
	}
	if delay > limit {
		return limit
	}
	return delay
}

// jitter shortens d by up to retryJitterFraction. Subtracting rather than
// spreading around d keeps the caller's cap a true maximum, and decorrelates a
// fleet of Agents that would otherwise re-dial simultaneously after a shared
// outage or a shared rate-limit window.
func jitter(d time.Duration) time.Duration {
	if d <= 0 {
		return time.Second
	}
	span := float64(d) * retryJitterFraction
	if span <= 0 {
		return d
	}
	reduced := d - time.Duration(rand.Float64()*span)
	if reduced < time.Second {
		return time.Second
	}
	return reduced
}

// retryAfterHint extracts a Retry-After value from a Connect error's response
// headers. Both the delay-seconds and the HTTP-date forms are accepted, since
// reverse proxies emit either one.
func retryAfterHint(err error) (time.Duration, bool) {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		return 0, false
	}
	raw := connectErr.Meta().Get("Retry-After")
	if raw == "" {
		return 0, false
	}
	if seconds, convErr := strconv.Atoi(raw); convErr == nil {
		if seconds <= 0 {
			return 0, false
		}
		return clampHint(time.Duration(seconds) * time.Second), true
	}
	if at, convErr := http.ParseTime(raw); convErr == nil {
		if until := time.Until(at); until > 0 {
			return clampHint(until), true
		}
	}
	return 0, false
}

// clampHint keeps a server hint inside a sane window: never shorter than the
// operator's reconnect interval, never longer than retryServerHintCap.
func clampHint(d time.Duration) time.Duration {
	if floor := baseInterval(); d < floor {
		return floor
	}
	if d > retryServerHintCap {
		return retryServerHintCap
	}
	return d
}

// isAuthRejection reports whether err is the panel refusing the Agent's
// credential (HTTP 401/403) rather than a transport or capacity failure.
func isAuthRejection(err error) bool {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		return false
	}
	switch connectErr.Code() {
	case connect.CodeUnauthenticated, connect.CodePermissionDenied:
		return true
	default:
		return false
	}
}

// isRateLimited reports whether err is the panel or an intermediary shedding
// load (HTTP 429). Such a rejection says "later", not "wrong", so callers keep
// the current connection strategy and only slow down.
func isRateLimited(err error) bool {
	var connectErr *connect.Error
	if !errors.As(err, &connectErr) {
		return false
	}
	return connectErr.Code() == connect.CodeResourceExhausted
}

// isTransientRejection reports whether err is a rejection the Agent should ride
// out in place instead of tearing down its whole session. A 401 may be a token
// rotation mid-flight, a 403 may be a permission change being rolled out, and a
// 429 is explicitly temporary. Rebuilding the transport for any of them
// multiplies one failed request into a full re-handshake plus six stream
// re-subscribes, which is the shape that gets an Agent's address banned.
func isTransientRejection(err error) bool {
	return isRateLimited(err) || isAuthRejection(err)
}
