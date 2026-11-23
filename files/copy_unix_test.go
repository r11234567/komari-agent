//go:build linux || darwin || freebsd

package files

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestCopyDirectoryPreservesMetadataAndLinks(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "source")
	dst := filepath.Join(root, "destination")
	if err := os.Mkdir(src, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(src, "file"), []byte("content"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("file", filepath.Join(src, "link")); err != nil {
		t.Fatal(err)
	}
	stamp := time.Unix(1700000000, 0)
	for _, path := range []string{src, filepath.Join(src, "file")} {
		if err := os.Chtimes(path, stamp, stamp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := copyPath(src, dst, true, false); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{dst: 0o750, filepath.Join(dst, "file"): 0o640} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != mode || !info.ModTime().Equal(stamp) {
			t.Fatalf("%s: mode=%o modified=%v", path, info.Mode().Perm(), info.ModTime())
		}
	}
	if target, err := os.Readlink(filepath.Join(dst, "link")); target != "file" || err != nil {
		t.Fatalf("copied link target = %q, err = %v", target, err)
	}
	if _, err := copyPath(src, dst, true, false); !errors.Is(err, os.ErrExist) {
		t.Fatalf("copy without overwrite = %v", err)
	}
	if _, err := copyPath(src, dst, true, true); err != nil {
		t.Fatal(err)
	}
}

func TestCrossDeviceMoveFallbackCopiesAndRemovesSource(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	src := filepath.Join(root, "original")
	dst := filepath.Join(root, "copy")
	if err := os.WriteFile(src, []byte("content"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := copyPathSafe(src, dst, true, false, true); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(src); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source stat = %v", err)
	}
	if content, err := os.ReadFile(dst); string(content) != "content" || err != nil {
		t.Fatalf("destination = %q, err = %v", content, err)
	}
}
