//go:build windows

package monitoring

import (
	"os"
	"strings"
	"testing"
	"time"

	unit "github.com/komari-monitor/komari-agent/monitoring/unit"
)

// Opt in on a Windows host with an NVIDIA driver. A collector error must fail
// this hardware regression instead of looking like a machine without a GPU.
func TestWindowsNVIDIAHardwareMetrics(t *testing.T) {
	if os.Getenv("KOMARI_TEST_NVIDIA_GPU") != "1" {
		t.Skip("set KOMARI_TEST_NVIDIA_GPU=1 on an NVIDIA Windows host")
	}
	devices, err := unit.GetDetailedGPUInfo()
	if err != nil {
		t.Fatal(err)
	}
	var report Report
	for _, device := range devices {
		if !strings.Contains(device.Name, "NVIDIA") {
			continue
		}
		if device.MemoryTotal == 0 || device.MemoryUsed > device.MemoryTotal || device.Utilization < 0 || device.Utilization > 100 || device.Temperature == 0 {
			t.Fatalf("invalid NVIDIA counters: %+v", device)
		}
		report.GPUs = append(report.GPUs, GPUDevice{
			Name: device.Name, MemoryTotal: device.MemoryTotal, MemoryUsed: device.MemoryUsed,
			Utilization: device.Utilization, Temperature: device.Temperature,
		})
		t.Logf("GPU=%s totalMiB=%d usedMiB=%d utilization=%.1f temperature=%d", device.Name, device.MemoryTotal>>20, device.MemoryUsed>>20, device.Utilization, device.Temperature)
	}
	if len(report.GPUs) == 0 {
		t.Fatal("NVIDIA GPU was not collected")
	}
	points := report.Metrics(time.Now())
	if len(points) != 18+4*len(report.GPUs) {
		t.Fatalf("hardware GPU counters missing from metric batch: %d", len(points))
	}
	for _, point := range points[18:] {
		if point.Labels["device_name"] == "" || point.Labels["device_index"] == "" {
			t.Fatalf("GPU identity missing from metric batch: %+v", point)
		}
	}
}
