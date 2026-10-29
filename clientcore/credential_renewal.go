package clientcore

import (
	"connectrpc.com/connect"
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
)

func permanentCredentialRejection(err error) bool {
	code := connect.CodeOf(err)
	return code == connect.CodeUnauthenticated || code == connect.CodePermissionDenied
}

// Stable per-machine jitter spreads renewal load without a polling loop.
func credentialRenewalDelay(identity credentials.Identity, now time.Time) time.Duration {
	if identity.PendingRefresh != nil || identity.AccessToken == "" {
		return 0
	}
	if identity.AccessTokenExpiresAt.IsZero() {
		return time.Hour
	}
	// At the fixed authorization horizon both tokens are capped to the same
	// deadline. Renewing early cannot extend either token and would loop on
	// successful rotations until expiry. Sleep to the boundary instead.
	if !identity.RefreshTokenExpiresAt.IsZero() && !identity.RefreshTokenExpiresAt.After(identity.AccessTokenExpiresAt) {
		return max(0, identity.RefreshTokenExpiresAt.Sub(now))
	}
	digest := sha256.Sum256([]byte(identity.AgentID))
	jitter := time.Duration((uint16(digest[0])<<8|uint16(digest[1]))%60) * time.Second
	return max(0, identity.AccessTokenExpiresAt.Add(-5*time.Minute-jitter).Sub(now))
}

func (c *Client) runCredentialRenewal(ctx context.Context) {
	backoff := 5 * time.Second
	for ctx.Err() == nil {
		identity, ok := c.identity()
		if !ok {
			return
		}
		delay := credentialRenewalDelay(identity, time.Now())
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		current, ok := c.identity()
		if !ok {
			return
		}
		// A reactive refresh may have completed while the timer was sleeping.
		if credentialRenewalDelay(current, time.Now()) > 0 {
			continue
		}
		attemptCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err := c.refreshCredentials(attemptCtx, current.AccessToken)
		cancel()
		if err == nil {
			backoff = 5 * time.Second
			continue
		}
		if ctx.Err() != nil {
			return
		}
		if permanentCredentialRejection(err) {
			log.Printf("Credential renewal requires administrator reapproval or device reenrollment; proactive retries stopped: %v", err)
			return
		}
		log.Printf("Proactive credential renewal failed; retrying in %s: %v", backoff, err)
		timer = time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		backoff = min(time.Minute, backoff*2)
	}
}
