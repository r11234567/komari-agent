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

func TestUploadPartIdentitySurvivesReopenAndRejectsOtherPart(t *testing.T) {
	root := t.TempDir()
	first := uploadPartPathFor(filepath.Join(root, "one"), "upload-one")
	second := uploadPartPathFor(filepath.Join(root, "two"), "upload-two")
	file, err := openUploadPartSafe(first, true)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := uploadPartIdentity(file)
	_ = file.Close()
	if err != nil || identity == "" {
		t.Fatalf("upload part identity = %q, err = %v", identity, err)
	}
	for _, check := range []struct {
		path   string
		create bool
		valid  bool
	}{
		{first, false, true},
		{second, true, false},
	} {
		file, err := openUploadPartSafe(check.path, check.create)
		if err != nil {
			t.Fatal(err)
		}
		err = checkUploadPartIdentity(file, identity)
		_ = file.Close()
		if (err == nil) != check.valid {
			t.Errorf("check identity for %s = %v, valid = %t", check.path, err, check.valid)
		}
	}
}

func TestUploadCommitKeepsOrdinaryPermissionsOnly(t *testing.T) {
	target := filepath.Join(t.TempDir(), "existing")
	if err := os.WriteFile(target, []byte("old"), 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(target, 0o750|os.ModeSetuid|os.ModeSetgid|os.ModeSticky); err != nil {
		t.Fatal(err)
	}
	part := uploadPartPathFor(target, "replacement")
	file, err := openUploadPartSafe(part, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	if _, err := file.WriteString("replacement"); err != nil {
		t.Fatal(err)
	}
	identity, err := uploadPartIdentity(file)
	if err != nil {
		t.Fatal(err)
	}
	if err := commitUploadPartSafe(part, target, int64(len("replacement")), identity); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode() != 0o750 {
		t.Fatalf("replacement mode = %v, want ordinary permissions 0750", info.Mode())
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "replacement" {
		t.Fatalf("replacement contents = %q, err = %v", data, err)
	}
	if _, err := os.Stat(filepath.Dir(part)); !os.IsNotExist(err) {
		t.Fatalf("publication left its private stage behind: %v", err)
	}
}
