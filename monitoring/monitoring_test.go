package monitoring

import (
	"testing"
	"time"
)

func TestMetricsPreserveLegacyAggregateSurface(t *testing.T) {
	report := Report{
		CPU: cpuReport{Usage: 1}, Ram: usageReport{Total: 2, Used: 3}, Swap: usageReport{Total: 4, Used: 5},
		Load: loadReport{Load1: 6, Load5: 7, Load15: 8}, Disk: usageReport{Total: 9, Used: 10},
		Network:     networkReport{Up: 11, Down: 12, TotalUp: 13, TotalDown: 14},
		Connections: connectionsReport{TCP: 15, UDP: 16}, Uptime: 17, Process: 18,
	}
	points := report.Metrics(time.Unix(1, 0))
	if len(points) != 18 {
		t.Fatalf("metric count = %d, want 18", len(points))
	}
	if points[10].Metric != "network.up_bytes_per_second" || points[10].Value != 11 {
		t.Fatalf("network metric mismatch: %+v", points[10])
	}
}
