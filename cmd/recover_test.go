package cmd

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFileSHA256(t *testing.T) {
	path := filepath.Join(t.TempDir(), "artifact")
	if err := os.WriteFile(path, []byte("komari"), 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := fileSHA256(path)
	if err != nil {
		t.Fatal(err)
	}
	const want = "c0c63527b63764c3791565f32245f1a7516b41d03e081ccbf6437b12127fdfc0"
	if got != want {
		t.Fatalf("checksum = %s, want %s", got, want)
	}
}

func TestWriteRecoverOutputLimit(t *testing.T) {
	if err := writeRecoverOutput(string(make([]byte, recoverOutputLimit+1))); err == nil {
		t.Fatal("expected output limit failure")
	}
}
