package monitoring

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestGPUCommandsTimeOut(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gpu-probe")
	if err := os.WriteFile(path, []byte("#!/bin/sh\nexec sleep 30\n"), 0700); err != nil {
		t.Fatal(err)
	}
	nvidia := &NvidiaSMI{BinPath: path}
	rocm := &ROCmSMI{BinPath: path}
	for name, start := range map[string]func() error{"NVIDIA": nvidia.Start, "ROCm": rocm.Start} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			started := time.Now()
			if err := start(); !errors.Is(err, context.DeadlineExceeded) {
				t.Fatalf("GPU probe returned %v", err)
			}
			if elapsed := time.Since(started); elapsed > 8*time.Second {
				t.Fatalf("GPU probe remained blocked for %v", elapsed)
			}
		})
	}
}
