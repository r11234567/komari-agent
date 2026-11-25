package clientcore

import (
	"context"
	"log"
	"reflect"
	"time"

	flags "github.com/komari-monitor/komari-agent/cmd/flags"
	"github.com/komari-monitor/komari-agent/core/enrollment"
	"github.com/komari-monitor/komari-agent/dnsresolver"
)

func (c *Client) runVerifiedTrustRenewal(ctx context.Context) {
	if c.hostTrust != nil || c.credentialStore == nil {
		return
	}
	before, ok := c.credentialStore.Identity()
	if !ok || len(before.ControlPlaneKeys) == 0 {
		return
	}
	client, err := enrollment.New(before.Endpoint, dnsresolver.GetHTTPClientWithPreference(5*time.Second, flags.GlobalConfig.PreferIPVersion))
	if err != nil {
		return
	}
	ticker := time.NewTicker(15 * time.Minute)
	defer ticker.Stop()
	for ctx.Err() == nil {
		before, ok := c.credentialStore.Identity()
		if !ok || len(before.ControlPlaneKeys) == 0 || before.Endpoint != client.Endpoint() {
			return
		}
		fetchCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		next, err := client.FetchVerifiedTrustBundle(fetchCtx, before)
		cancel()
		if err == nil && !reflect.DeepEqual(next, before) {
			if err := c.credentialStore.ApplyVerifiedTrustBundle(before, next); err != nil && ctx.Err() == nil {
				log.Printf("Panel trust update was deferred: %v", err)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
