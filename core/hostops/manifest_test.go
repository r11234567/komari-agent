package hostops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicMetadataRejectsSymlinkAndTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "manifest.json")
	if err := os.WriteFile(path, []byte(`{} {}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := ReadJSON(path, &m, false); err == nil {
		t.Fatal("trailing metadata accepted")
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Skipf("symlink unsupported: %v", err)
	}
	if err := AtomicWrite(link, []byte(`{}`), 0o600); err == nil {
		t.Fatal("symlink destination accepted")
	}
}
func TestDaemonOwnedAncestorIsNotTrusted(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tool")
	if err := os.WriteFile(path, []byte("test"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := TrustedPath(path); err == nil {
		t.Fatal("user-writable ancestor trusted")
	}
}
