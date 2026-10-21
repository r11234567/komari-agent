package statelock

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestRegressionDaemonHasSingleWriter(t *testing.T) {
	if path := os.Getenv("KOMARI_TEST_LOCK"); path != "" {
		if release, err := Acquire(path); err == nil {
			release()
			os.Exit(2)
		}
		return
	}
	path := filepath.Join(t.TempDir(), "daemon.lock")
	release, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestRegressionDaemonHasSingleWriter$")
	cmd.Env = append(os.Environ(), "KOMARI_TEST_LOCK="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("second process acquired live writer lock: %v %s", err, output)
	}
	release()
	again, err := Acquire(path)
	if err != nil {
		t.Fatal(err)
	}
	again()
}
