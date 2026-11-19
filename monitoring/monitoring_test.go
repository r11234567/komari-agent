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

func floatPtr(v float64) *float64 { return &v }

func TestMetricsGPUUsesCanonicalDeviceInventory(t *testing.T) {
	report := Report{GPUs: []GPUDevice{
		{Name: "GPU A", Utilization: 25, MemoryUsed: 1 << 30, MemoryTotal: 8 << 30, Temperature: floatPtr(50.5)},
		{Name: "GPU B", Utilization: 75, MemoryUsed: 2 << 30, MemoryTotal: 16 << 30, Temperature: floatPtr(0.0)},
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
	if points[18+3].Value != 50.5 || points[18+4+3].Value != 0.0 {
		t.Fatalf("GPU temperatures lost decimal or true zero: %v, %v", points[18+3].Value, points[18+4+3].Value)
	}
	// Missing temperature (nil) on an otherwise measured GPU must NOT emit a fake 0°C metric or proto field.
	report.GPUs = []GPUDevice{{Name: "GPU NoTemp", Utilization: 40, MemoryUsed: 1 << 30, MemoryTotal: 8 << 30, Temperature: nil}}
	noTempPoints := report.Metrics(time.Unix(1, 0))
	if len(noTempPoints) != 18+3 {
		t.Fatalf("expected 3 GPU metrics without temperature, got %d", len(noTempPoints)-18)
	}
	for _, pt := range noTempPoints[18:] {
		if pt.Metric == "gpu.temperature" {
			t.Fatalf("missing GPU temperature emitted fake metric point: %+v", pt)
		}
	}
	typedReport := report.Proto("agent-1", 1)
	if len(typedReport.Resources.Gpus) != 1 || typedReport.Resources.Gpus[0].TemperatureCelsius != nil {
		t.Fatalf("missing GPU temperature emitted non-nil TemperatureCelsius: %+v", typedReport.Resources.Gpus)
	}

	report.GPUs = []GPUDevice{{Name: "Unavailable counters", Utilization: -1, MemoryUsed: ^uint64(0), MemoryTotal: ^uint64(0), Temperature: nil}}
	if points := report.Metrics(time.Unix(1, 0)); len(points) != 18 {
		t.Fatal("unavailable GPU counters emitted invalid metric points")
	}
}
