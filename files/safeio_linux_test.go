//go:build linux

package files

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxSafeIORejectsSymlinkTraversalAndTargets(t *testing.T) {
	root := t.TempDir()
	realDir := filepath.Join(root, "real-dir")
	if err := os.Mkdir(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	secretFile := filepath.Join(realDir, "secret.txt")
	if err := os.WriteFile(secretFile, []byte("top-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	dirLink := filepath.Join(root, "dir-link")
	if err := os.Symlink(realDir, dirLink); err != nil {
		t.Fatal(err)
	}
	fileLink := filepath.Join(root, "file-link")
	if err := os.Symlink(secretFile, fileLink); err != nil {
		t.Fatal(err)
	}

	// Opening through a symlink directory or symlink file must fail closed.
	if _, _, err := openRegularNoSymlinks(filepath.Join(dirLink, "secret.txt"), os.O_RDONLY, 0); err == nil {
		t.Fatal("openRegularNoSymlinks traversed parent symlink directory")
	}
	if _, _, err := openRegularNoSymlinks(fileLink, os.O_RDONLY, 0); err == nil {
		t.Fatal("openRegularNoSymlinks opened symlink target")
	}

	// Regular direct path succeeds and verifies via fstat.
	f, info, err := openRegularNoSymlinks(secretFile, os.O_RDONLY, 0)
	if err != nil {
		t.Fatalf("openRegularNoSymlinks on real regular file failed: %v", err)
	}
	_ = f.Close()
	if !info.Mode().IsRegular() || info.Size() != int64(len("top-secret")) {
		t.Fatalf("unexpected fstat info: %+v", info)
	}

	// Chmod through symlink parent or onto symlink target must fail closed.
	if err := chmodSafe(filepath.Join(dirLink, "secret.txt"), 0o644); err == nil {
		t.Fatal("chmodSafe traversed symlink directory")
	}
	if err := chmodSafe(fileLink, 0o644); err == nil {
		t.Fatal("chmodSafe accepted symlink target")
	}

	// Creating/overwriting through symlink parent must fail closed.
	if err := createEmptyRegularFileSafe(filepath.Join(dirLink, "new.txt"), true, 0o600); err == nil {
		t.Fatal("createEmptyRegularFileSafe traversed symlink parent directory")
	}
	if _, err := os.Stat(filepath.Join(realDir, "new.txt")); !os.IsNotExist(err) {
		t.Fatalf("file was unexpectedly created inside symlink target dir: %v", err)
	}
}
