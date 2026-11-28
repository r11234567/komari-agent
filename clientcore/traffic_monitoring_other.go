//go:build !linux

package clientcore

import (
	"context"

	"github.com/komari-monitor/komari-agent/core/credentials"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

func (*Client) runManagedTrafficMonitoring(context.Context, credentials.Identity) {}

func (*Client) trafficMonitoringStatus() *reportv1.TrafficMonitoringStatus { return nil }
