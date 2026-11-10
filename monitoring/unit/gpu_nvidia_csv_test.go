package monitoring

import "testing"

func TestNvidiaGPUCSVWithoutProcessList(t *testing.T) {
	data := []byte("NVIDIA GeForce RTX 4060 Laptop GPU, 7, 8188, 4323, 50\r\n\"GPU, second\", 30, 16384, 2048, 60\r\n")
	stats, err := parseNvidiaGPUCSV(data)
	if err != nil || len(stats.GPUs) != 2 {
		t.Fatalf("GPU CSV failed: %+v, %v", stats, err)
	}
	first := stats.GPUs[0]
	used, err := parseMemoryValue(first.FrameBufferMemoryUsage.Used)
	if err != nil || used != 4323*1024*1024 || first.Utilization.GPUUtil != "7" || first.Temperature.GPUTemp != "50" {
		t.Fatalf("GPU counters lost or converted incorrectly: %+v, %v", first, err)
	}
	if stats.GPUs[1].ProductName != "GPU, second" {
		t.Fatal("quoted GPU name was split")
	}
	if _, err := parseNvidiaGPUCSV([]byte("GPU, 7, 8192\n")); err == nil {
		t.Fatal("incomplete GPU counters accepted")
	}
}
