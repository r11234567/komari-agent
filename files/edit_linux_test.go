package files

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEditPreservesLinuxAccessACL(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "editor.txt")
	data := []byte("old bytes")
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	// ACL version 2 with one named user. The mask matches the group mode bits.
	acl := binary.LittleEndian.AppendUint32(nil, 2)
	for _, entry := range []struct {
		tag, permission uint16
		id              uint32
	}{
		{1, 7, ^uint32(0)}, {2, 4, 12345}, {4, 5, ^uint32(0)}, {16, 5, ^uint32(0)}, {32, 5, ^uint32(0)},
	} {
		acl = binary.LittleEndian.AppendUint16(acl, entry.tag)
		acl = binary.LittleEndian.AppendUint16(acl, entry.permission)
		acl = binary.LittleEndian.AppendUint32(acl, entry.id)
	}
	if err := unix.Setxattr(path, "system.posix_acl_access", acl, 0); err == unix.EOPNOTSUPP {
		t.Skip("filesystem does not support POSIX ACLs")
	} else if err != nil {
		t.Fatal(err)
	}
	if err := unix.Setxattr(dir, "system.posix_acl_default", acl, 0); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(data)
	replacement := []byte("new bytes")
	if err := replaceEditedFileSafe(path, replacement, expected[:]); err != nil {
		t.Fatal(err)
	}
	assertACL := func(name, attr string, expected []byte) {
		t.Helper()
		file, err := os.Open(name)
		if err != nil {
			t.Fatal(err)
		}
		defer file.Close()
		if result, err := readEditAttribute(file, attr); err != nil || !bytes.Equal(result, expected) {
			t.Fatalf("unexpected ACL for %s: %x %v", name, result, err)
		}
	}
	assertACL(path, "system.posix_acl_access", acl)
	assertACL(dir, "system.posix_acl_default", acl)
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	oldOwner, newOwner := before.Sys().(*syscall.Stat_t), after.Sys().(*syscall.Stat_t)
	if before.Mode() != after.Mode() || newOwner.Uid != oldOwner.Uid || newOwner.Gid != oldOwner.Gid {
		t.Fatal("edit changed file mode, owner or group")
	}
	if err := unix.Removexattr(path, "system.posix_acl_access"); err != nil {
		t.Fatal(err)
	}
	expected = sha256.Sum256(replacement)
	if err := replaceEditedFileSafe(path, data, expected[:]); err != nil {
		t.Fatal(err)
	}
	assertACL(path, "system.posix_acl_access", nil)
	assertACL(dir, "system.posix_acl_default", acl)
}

func TestEditRefusesPrivilegedMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "setuid")
	data := []byte("original")
	if err := os.WriteFile(path, data, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, os.ModeSetuid|0o755); err != nil {
		t.Fatal(err)
	}
	expected := sha256.Sum256(data)
	if err := replaceEditedFileSafe(path, []byte("edited"), expected[:]); err == nil {
		t.Fatal("file with setuid mode was replaced")
	}
	if actual, err := os.ReadFile(path); err != nil || !bytes.Equal(data, actual) {
		t.Fatalf("original contents changed: %q %v", actual, err)
	}
	if actual, err := os.Stat(path); err != nil || actual.Mode()&(os.ModeSetuid|os.ModePerm) != os.ModeSetuid|0o755 {
		t.Fatalf("original mode changed: %v %v", actual, err)
	}
}
