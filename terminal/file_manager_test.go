package terminal

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
)

func TestFileManagerUploadChecksSizeAndHash(t *testing.T) {
	directory := t.TempDir()
	target := filepath.Join(directory, "payload.bin")
	payload := []byte("typed-connect-upload")
	digest := sha256.Sum256(payload)
	var events []*websshv1.FileEvent
	manager := NewFileManager(context.Background(), func(event *websshv1.FileEvent) error {
		events = append(events, event)
		return nil
	})
	defer manager.Close()
	start := &websshv1.FileCommand{RequestId: "start", Operation: websshv1.FileOperation_FILE_OPERATION_UPLOAD_START, Path: target, Size: uint64(len(payload))}
	if err := manager.Handle(start); err != nil || len(events) != 1 || events[0].UploadId == "" {
		t.Fatalf("start upload: events=%#v err=%v", events, err)
	}
	uploadID := events[0].UploadId
	if err := manager.Handle(&websshv1.FileCommand{RequestId: "chunk", Operation: websshv1.FileOperation_FILE_OPERATION_UPLOAD_CHUNK, UploadId: uploadID, Data: payload}); err != nil {
		t.Fatal(err)
	}
	if err := manager.Handle(&websshv1.FileCommand{RequestId: "finish", Operation: websshv1.FileOperation_FILE_OPERATION_UPLOAD_FINISH, UploadId: uploadID, Sha256: hex.EncodeToString(digest[:])}); err != nil {
		t.Fatal(err)
	}
	content, err := os.ReadFile(target)
	if err != nil || string(content) != string(payload) {
		t.Fatalf("uploaded content=%q err=%v", content, err)
	}
}

func TestFileManagerRejectsRootDeletion(t *testing.T) {
	var event *websshv1.FileEvent
	manager := NewFileManager(context.Background(), func(value *websshv1.FileEvent) error {
		event = value
		return nil
	})
	defer manager.Close()
	if err := manager.Handle(&websshv1.FileCommand{RequestId: "delete", Operation: websshv1.FileOperation_FILE_OPERATION_DELETE, Path: filesystemRoots()[0], Recursive: true}); err != nil {
		t.Fatal(err)
	}
	if event == nil || event.Success || event.Error == "" {
		t.Fatalf("root deletion response=%#v", event)
	}
}

func TestCopyPathRejectsDestinationInsideSource(t *testing.T) {
	source := filepath.Join(t.TempDir(), "source")
	if err := os.Mkdir(source, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := copyPath(source, filepath.Join(source, "copy")); err == nil {
		t.Fatal("directory copied into itself")
	}
}
