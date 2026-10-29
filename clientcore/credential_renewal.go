package clientcore

import (
	"context"
	"crypto/sha256"
	"log"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
)

// Stable per-machine jitter spreads renewal load without a polling loop.
func credentialRenewalDelay(identity credentials.Identity, now time.Time) time.Duration {
	if identity.PendingRefresh != nil || identity.AccessToken == "" {
		return 0
	}
	if identity.AccessTokenExpiresAt.IsZero() {
		return time.Hour
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
