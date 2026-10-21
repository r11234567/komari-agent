package hostops

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAtomicMetadataCreateAndReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.json")
	for _, revision := range []uint64{1, 2} {
		want := Policy{Version: ManifestVersion, ServiceID: "metadata-test", HostRevision: revision}
		if err := WriteJSON(path, &want, 0o600); err != nil {
			t.Fatalf("publish revision %d: %v", revision, err)
		}
		var got Policy
		if err := ReadJSON(path, &got, false); err != nil {
			t.Fatal(err)
		}
		if got.Version != want.Version || got.ServiceID != want.ServiceID || got.HostRevision != revision {
			t.Fatalf("read after replacement: got %+v, want %+v", got, want)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "policy.json" {
		t.Fatalf("temporary files remain after successful replacement: %v", entries)
	}
}

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
