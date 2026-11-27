//go:build !linux

package clientcore

import (
	"context"
	"log"

	"github.com/komari-monitor/komari-agent/core/credentials"
)

func (*Client) runTrafficEvidence(context.Context, credentials.Identity, string) {
	log.Print("Traffic evidence upload is available on Linux")
}
