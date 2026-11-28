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

func TestEditPreservesNestedPathPermissions(t *testing.T) {
	tests := []struct {
		name                   string
		file, parent, ancestor os.FileMode
	}{
		{"public script", 0o755, 0o755, 0o755},
		{"private file in public path", 0o600, 0o755, 0o750},
		{"public file in private path", 0o644, 0o700, 0o710},
		{"group-shared file", 0o660, 0o770 | os.ModeSetgid, 0o750},
		{"group-readable configuration", 0o640, 0o750 | os.ModeSetgid, 0o711},
		{"read-only file in sticky directory", 0o444, 0o777 | os.ModeSticky, 0o755},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			ancestor := filepath.Join(t.TempDir(), "outer")
			parent := filepath.Join(ancestor, "inner")
			path := filepath.Join(parent, "editor.txt")
			if err := os.MkdirAll(parent, 0o700); err != nil {
				t.Fatal(err)
			}
			original := []byte("first version")
			if err := os.WriteFile(path, original, 0o600); err != nil {
				t.Fatal(err)
			}
			for name, mode := range map[string]os.FileMode{path: test.file, parent: test.parent, ancestor: test.ancestor} {
				if err := os.Chmod(name, mode); err != nil {
					t.Fatal(err)
				}
			}
			type permissions struct {
				mode     os.FileMode
				uid, gid uint32
			}
			statPermissions := func(name string) permissions {
				t.Helper()
				info, err := os.Stat(name)
				if err != nil {
					t.Fatal(err)
				}
				stat := info.Sys().(*syscall.Stat_t)
				return permissions{info.Mode(), stat.Uid, stat.Gid}
			}
			names := []string{path, parent, ancestor}
			baseline := make([]permissions, len(names))
			for i, name := range names {
				baseline[i] = statPermissions(name)
			}
			if baseline[0].mode != test.file || baseline[1].mode != test.parent|os.ModeDir ||
				baseline[2].mode != test.ancestor|os.ModeDir {
				t.Fatalf("fixture mode mismatch: %v", baseline)
			}
			expected := sha256.Sum256(original)
			for _, replacement := range [][]byte{[]byte("different content"), nil} {
				if err := replaceEditedFileSafe(path, replacement, expected[:]); err != nil {
					t.Fatal(err)
				}
				actual, err := os.ReadFile(path)
				if err != nil || !bytes.Equal(actual, replacement) {
					t.Fatalf("unexpected saved content: %q %v", actual, err)
				}
				for i, name := range names {
					if got := statPermissions(name); got != baseline[i] {
						t.Fatalf("permissions of %s changed from %+v to %+v", name, baseline[i], got)
					}
				}
				expected = sha256.Sum256(replacement)
			}
		})
	}
}

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
