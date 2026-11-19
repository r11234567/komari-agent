package monitoring

import (
	"testing"
)

func TestDetailedGPUDetection(t *testing.T) {
	models, err := GetDetailedGPUHost()
	if err != nil {
		t.Logf("Detailed GPU detection failed (may be normal on non-Linux or non-GPU systems): %v", err)
		return
	}

	t.Logf("Detected GPUs: %v", models)

	if len(models) > 0 {
		usage, err := GetDetailedGPUState()
		if err != nil {
			t.Logf("GPU state collection failed: %v", err)
		} else {
			t.Logf("GPU usage: %v", usage)
		}

		// 测试详细信息获取
		detailedInfo, err := GetDetailedGPUInfo()
		if err != nil {
			t.Logf("GPU detailed info collection failed: %v", err)
		} else {
			for i, info := range detailedInfo {
				t.Logf("GPU %d: %s - Memory: %dMB/%dMB, Usage: %.1f%%, Temp: %.1f°C",
					i, info.Name, info.MemoryUsed, info.MemoryTotal, info.Utilization, info.Temperature)
			}
		}
	}
}

func TestDetailedGPUInfo(t *testing.T) {
	detailedInfo, err := GetDetailedGPUInfo()
	if err != nil {
		t.Logf("GPU detailed info test failed (may be normal): %v", err)
		return
	}

	if len(detailedInfo) == 0 {
		t.Log("No detailed GPU info available")
		return
	}

	for i, info := range detailedInfo {
		t.Logf("GPU %d Details:", i)
		t.Logf("  Name: %s", info.Name)
		t.Logf("  Memory Total: %d MB", info.MemoryTotal)
		t.Logf("  Memory Used: %d MB", info.MemoryUsed)
		//t.Logf("  Memory Free: %d MB", info.MemoryFree)
		t.Logf("  Utilization: %.1f%%", info.Utilization)
		t.Logf("  Temperature: %.1f°C", info.Temperature)

		// 验证数据的合理性
		//if info.MemoryTotal > 0 && info.MemoryUsed+info.MemoryFree != info.MemoryTotal {
		//	t.Logf("Warning: Memory usage calculation may be inconsistent for %s", info.Name)
		//}

		if info.Utilization < 0 || info.Utilization > 100 {
			t.Errorf("Invalid utilization value for %s: %.1f%%", info.Name, info.Utilization)
		}
	}
}

func TestParseGPUTemperaturePreservesDecimals(t *testing.T) {
	amdTemp, err := parseAMDTemperature("64.5 C")
	if err != nil || amdTemp != 64.5 {
		t.Fatalf("parseAMDTemperature(64.5 C) = %v, %v, want 64.5", amdTemp, err)
	}
	nvidiaTemp, err := parseTemperatureValue("51.25 C")
	if err != nil || nvidiaTemp != 51.25 {
		t.Fatalf("parseTemperatureValue(51.25 C) = %v, %v, want 51.25", nvidiaTemp, err)
	}
}
