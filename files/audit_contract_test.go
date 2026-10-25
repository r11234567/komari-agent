package files

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
)

// These regressions exercise only isolated temporary files. They protect the
// published operation flags and the existing file type from accidental loss.
func TestAuditCopyWithoutOverwritePreservesDestination(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source.txt")
	destination := filepath.Join(root, "destination.txt")
	if err := os.WriteFile(source, []byte("new contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(destination, []byte("keep existing contents"), 0o600); err != nil {
		t.Fatal(err)
	}
	event := Execute(filev1.FileOperation_FILE_OPERATION_COPY, map[string]any{
		"source": source, "destination": destination, "overwrite": false,
	})
	contents, err := os.ReadFile(destination)
	if err != nil {
		t.Fatal(err)
	}
	if event.GetSuccess() || string(contents) != "keep existing contents" {
		t.Fatalf("overwrite=false must reject the copy and preserve the existing destination; success=%v error=%q contents=%q", event.GetSuccess(), event.GetError(), contents)
	}
}

func TestAuditNonRecursiveDeletePreservesNonEmptyDirectory(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "non-empty")
	if err := os.Mkdir(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	child := filepath.Join(directory, "keep.txt")
	if err := os.WriteFile(child, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	event := Execute(filev1.FileOperation_FILE_OPERATION_DELETE, map[string]any{
		"path": directory, "recursive": false,
	})
	contents, err := os.ReadFile(child)
	if event.GetSuccess() || err != nil || string(contents) != "keep" {
		t.Fatalf("recursive=false must reject deletion of a non-empty directory; success=%v error=%q read_error=%v contents=%q", event.GetSuccess(), event.GetError(), err, contents)
	}
}

func TestAuditEmptySaveDoesNotReplaceSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires a Windows host policy unavailable on standard runners")
	}
	root := t.TempDir()
	target := filepath.Join(root, "target.txt")
	link := filepath.Join(root, "link.txt")
	if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	_, saveErr := createFile(link)
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("saving via a symlink must preserve the link or reject the operation; save_error=%v mode=%v", saveErr, info.Mode())
	}
}

func TestAuditMoveWithoutOverwritePreservesBothFiles(t *testing.T) {
	root := t.TempDir()
	source, destination := filepath.Join(root, "source"), filepath.Join(root, "destination")
	for path, content := range map[string]string{source: "source", destination: "keep"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	event := Execute(filev1.FileOperation_FILE_OPERATION_MOVE, map[string]any{
		"source": source, "destination": destination, "overwrite": false,
	})
	if event.GetSuccess() {
		t.Fatal("move overwrote an existing file")
	}
	for path, expected := range map[string]string{source: "source", destination: "keep"} {
		if content, err := os.ReadFile(path); err != nil || string(content) != expected {
			t.Fatalf("move changed %s: content=%q error=%v", path, content, err)
		}
	}
}

func TestAuditCopyDirectoryRequiresRecursive(t *testing.T) {
	root := t.TempDir()
	source := filepath.Join(root, "source")
	if err := os.Mkdir(source, 0o700); err != nil {
		t.Fatal(err)
	}
	event := Execute(filev1.FileOperation_FILE_OPERATION_COPY, map[string]any{
		"source": source, "destination": filepath.Join(root, "copy"), "recursive": false,
	})
	if event.GetSuccess() {
		t.Fatal("directory copy ignored recursive=false")
	}
}
