package monitoring

import (
	"runtime"
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
				t.Logf("GPU %d: %s - Memory: %dMB/%dMB, Usage: %.1f%%, Temp: %v°C",
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
		t.Logf("  Temperature: %v°C", info.Temperature)

		// 验证数据的合理性
		//if info.MemoryTotal > 0 && info.MemoryUsed+info.MemoryFree != info.MemoryTotal {
		//	t.Logf("Warning: Memory usage calculation may be inconsistent for %s", info.Name)
		//}

		if info.Utilization < 0 || info.Utilization > 100 {
			t.Errorf("Invalid utilization value for %s: %.1f%%", info.Name, info.Utilization)
		}
	}
}

func TestParseGPUTemperaturePreservesDecimalsAndRejectsMissing(t *testing.T) {
	amdTemp, err := parseAMDTemperature("64.5 C")
	if err != nil || amdTemp != 64.5 {
		t.Fatalf("parseAMDTemperature(64.5 C) = %v, %v, want 64.5", amdTemp, err)
	}
	amdZero, err := parseAMDTemperature("0.0")
	if err != nil || amdZero != 0.0 {
		t.Fatalf("parseAMDTemperature(0.0) = %v, %v, want 0.0", amdZero, err)
	}
	if _, err := parseAMDTemperature(""); err == nil {
		t.Fatal("parseAMDTemperature empty string must return error instead of fake 0°C")
	}
	if _, err := parseAMDTemperature("N/A"); err == nil {
		t.Fatal("parseAMDTemperature N/A must return error instead of fake 0°C")
	}

	nvidiaTemp, err := parseTemperatureValue("51.25 C")
	if err != nil || nvidiaTemp != 51.25 {
		t.Fatalf("parseTemperatureValue(51.25 C) = %v, %v, want 51.25", nvidiaTemp, err)
	}
	nvidiaZero, err := parseTemperatureValue("0 C")
	if err != nil || nvidiaZero != 0.0 {
		t.Fatalf("parseTemperatureValue(0 C) = %v, %v, want 0.0", nvidiaZero, err)
	}
	if _, err := parseTemperatureValue(""); err == nil {
		t.Fatal("parseTemperatureValue empty string must return error instead of fake 0°C")
	}
	if _, err := parseTemperatureValue("[N/A]"); err == nil {
		t.Fatal("parseTemperatureValue [N/A] must return error instead of fake 0°C")
	}

	// Verify real NVIDIA collector leaves Temperature nil when sensor reports [N/A]
	// and preserves 0.0 when sensor reports 0 C.
	nvidiaPayload := []byte(`<nvidia_smi_log>
		<gpu><product_name>GPU NA</product_name><utilization><gpu_util>10 %</gpu_util></utilization><fb_memory_usage><total>8192 MiB</total><used>1024 MiB</used></fb_memory_usage><temperature><gpu_temp>[N/A]</gpu_temp></temperature></gpu>
		<gpu><product_name>GPU Zero</product_name><utilization><gpu_util>15 %</gpu_util></utilization><fb_memory_usage><total>8192 MiB</total><used>2048 MiB</used></fb_memory_usage><temperature><gpu_temp>0 C</gpu_temp></temperature></gpu>
	</nvidia_smi_log>`)
	if runtime.GOOS == "windows" {
		nvidiaPayload = []byte("GPU NA, 10, 8192, 1024, [N/A]\nGPU Zero, 15, 8192, 2048, 0\n")
	}
	smi := &NvidiaSMI{data: nvidiaPayload}
	nvidiaInfos, err := smi.GatherDetailedInfo()
	if err != nil || len(nvidiaInfos) != 2 {
		t.Fatalf("GatherDetailedInfo NVIDIA failed: %v, %+v", err, nvidiaInfos)
	}
	if nvidiaInfos[0].Temperature != nil {
		t.Fatalf("NVIDIA [N/A] temperature must be nil, got %v", *nvidiaInfos[0].Temperature)
	}
	if nvidiaInfos[1].Temperature == nil || *nvidiaInfos[1].Temperature != 0.0 {
		t.Fatalf("NVIDIA 0 C temperature must be preserved as 0.0, got %v", nvidiaInfos[1].Temperature)
	}

	// Verify real AMD collector leaves Temperature nil when sensor key is absent
	// and preserves 0.0 when sensor reports 0.0.
	rsmi := &ROCmSMI{data: []byte(`{
		"card0": {"Card series": "AMD NoTemp", "GPU use (%)": "20", "VRAM Total Memory (B)": "4096", "VRAM Total Used Memory (B)": "1024"},
		"card1": {"Card series": "AMD Zero", "GPU use (%)": "25", "VRAM Total Memory (B)": "4096", "VRAM Total Used Memory (B)": "2048", "Temperature (Sensor junction) (C)": "0.0"}
	}`)}
	amdInfos, err := rsmi.GatherDetailedInfo()
	if err != nil || len(amdInfos) != 2 {
		t.Fatalf("GatherDetailedInfo AMD failed: %v, %+v", err, amdInfos)
	}
	var gotNoTemp, gotZero bool
	for _, item := range amdInfos {
		switch item.Name {
		case "AMD NoTemp":
			if item.Temperature != nil {
				t.Fatalf("AMD missing temperature must be nil, got %v", *item.Temperature)
			}
			gotNoTemp = true
		case "AMD Zero":
			if item.Temperature == nil || *item.Temperature != 0.0 {
				t.Fatalf("AMD 0.0 temperature must be preserved as 0.0, got %v", item.Temperature)
			}
			gotZero = true
		}
	}
	if !gotNoTemp || !gotZero {
		t.Fatalf("missing expected AMD devices: %+v", amdInfos)
	}
}
