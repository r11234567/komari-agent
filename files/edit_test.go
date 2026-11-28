package files

import (
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"

	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
)

func TestConditionalFileEdit(t *testing.T) {
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	parentBefore, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "editor.txt")
	initial := []byte("initial")
	if err := os.WriteFile(path, initial, 0o755); err != nil {
		t.Fatal(err)
	}
	old, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	save := func(expected, content []byte) *filev1.AgentFileEvent {
		hash := sha256.Sum256(expected)
		return ExecuteAssignment(&filev1.FileAssignment{
			Operation: filev1.FileOperation_FILE_OPERATION_REPLACE,
			Payload: &filev1.FileAssignment_Replace{Replace: &filev1.FileReplacePayload{
				Path: path, Content: content, ExpectedSha256: hash[:],
			}},
		})
	}
	external := []byte("changed")
	if err := os.WriteFile(path, external, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, old.ModTime(), old.ModTime()); err != nil {
		t.Fatal(err)
	}
	if event := save(initial, []byte("draft")); event.GetSuccess() || event.GetError() != errFileEditConflict.Error() {
		t.Fatalf("same-size overwrite restoring mtime was not detected: %v", event)
	}
	if actual, err := os.ReadFile(path); err != nil || string(actual) != string(external) {
		t.Fatalf("stale edit modified live data: %q %v", actual, err)
	}
	results := make(chan *filev1.AgentFileEvent, 2)
	go func() { results <- save(external, []byte("one")) }()
	go func() { results <- save(external, []byte("two")) }()
	first, second := <-results, <-results
	if first.GetSuccess() == second.GetSuccess() {
		t.Fatalf("concurrent edits both succeeded or both failed: %v / %v", first, second)
	}
	winner, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if event := save(winner, nil); !event.GetSuccess() {
		t.Fatalf("zero-byte replacement failed: %v", event)
	}
	if info, err := os.Stat(path); err != nil || info.Size() != 0 || info.Mode().Perm() != old.Mode().Perm() {
		t.Fatalf("replacement did not preserve permissions or truncate: %v %v", info, err)
	}
	if parent, err := os.Stat(dir); err != nil || !os.SameFile(parentBefore, parent) || parent.Mode() != parentBefore.Mode() {
		t.Fatalf("editing a file changed the containing directory: %v %v", parent, err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if event := save(nil, []byte("recreate")); event.GetSuccess() || event.GetError() != errFileEditConflict.Error() {
		t.Fatalf("stale edit recreated a missing file: %v", event)
	}
}

func TestGrowingDownloadSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "log")
	if err := os.WriteFile(path, []byte("original content"), 0o600); err != nil {
		t.Fatal(err)
	}
	first, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	id := fileInstanceID(first)
	if id == "" {
		t.Skip("file instance IDs are unavailable")
	}
	if err := os.WriteFile(path, []byte("original content\nappended"), 0o600); err != nil {
		t.Fatal(err)
	}
	grown, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"file_size": first.Size(), "follow_instance_id": id}
	if !matchesDownloadSnapshot(grown, args) {
		t.Fatal("tail did not permit appends to the observed inode")
	}
	rotated := path + ".1"
	if err := os.Rename(path, rotated); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement log plus new line"), 0o600); err != nil {
		t.Fatal(err)
	}
	next, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if matchesDownloadSnapshot(next, args) {
		t.Fatal("tail accepted a replacement file under the old instance")
	}
}
