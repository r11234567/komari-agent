package monitoring

import (
	"strconv"
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

func TestMetricsGPUUsesCanonicalDeviceInventory(t *testing.T) {
	report := Report{GPUs: []GPUDevice{
		{Name: "GPU A", Utilization: 25, MemoryUsed: 1 << 30, MemoryTotal: 8 << 30, Temperature: 50},
		{Name: "GPU B", Utilization: 75, MemoryUsed: 2 << 30, MemoryTotal: 16 << 30, Temperature: 60},
	}}
	points := report.Metrics(time.Unix(1, 0))
	wanted := []string{"gpu.device.usage", "gpu.memory.used", "gpu.memory.total", "gpu.temperature"}
	if len(points) != 18+2*len(wanted) {
		t.Fatalf("wrong GPU metric count: %d", len(points))
	}
	for device, name := range []string{"GPU A", "GPU B"} {
		for field, metric := range wanted {
			point := points[18+device*len(wanted)+field]
			if point.Metric != metric || point.Labels["device_index"] != strconv.Itoa(device) || point.Labels["device_name"] != name || len(point.Labels) != 2 {
				t.Fatalf("incompatible GPU point: %+v", point)
			}
		}
	}
	report.GPUs = []GPUDevice{{Name: "Unavailable counters", Utilization: -1, MemoryUsed: ^uint64(0), MemoryTotal: ^uint64(0), Temperature: ^uint64(0)}}
	if points := report.Metrics(time.Unix(1, 0)); len(points) != 18 {
		t.Fatal("unavailable GPU counters emitted invalid metric points")
	}
}
