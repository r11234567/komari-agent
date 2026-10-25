//go:build !windows

package files

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
)

func TestWorkerRealOSPermissionsAndScope(t *testing.T) {
	target := os.Getenv("KOMARI_IDENTITY_TEST_USER")
	if target == "" {
		current, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		target = current.Username
	}
	t.Setenv("KOMARI_WORKSPACE_USERS", target)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	executor := NewExecutor(ctx)
	defer executor.Close()
	if event := executor.Execute(ctx, "", target, "invalid", filev1.FileOperation_FILE_OPERATION_LIST, nil); event.Success {
		t.Fatal("empty workspace allowed")
	}
	directory, err := os.MkdirTemp("/tmp", "komari-identity-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0755); err != nil {
		t.Fatal(err)
	}
	secret := filepath.Join(directory, "owner-only")
	if err := os.Mkdir(secret, 0700); err != nil {
		t.Fatal(err)
	}
	event := executor.Execute(ctx, "workspace-a", target, "list-public", filev1.FileOperation_FILE_OPERATION_LIST, map[string]any{"path": directory})
	if !event.Success {
		t.Fatalf("public directory failed: %s", event.Error)
	}
	if target != os.Getenv("USER") && os.Geteuid() == 0 {
		event = executor.Execute(ctx, "workspace-a", target, "list-private", filev1.FileOperation_FILE_OPERATION_LIST, map[string]any{"path": secret})
		if event.Success {
			t.Fatal("selected non-root account read a root-only directory")
		}
	}
	event = executor.Execute(ctx, "workspace-a", "a-different-account", "scope-change", filev1.FileOperation_FILE_OPERATION_LIST, nil)
	if event.Success {
		t.Fatal("workspace identity changed")
	}
	cancelled, stop := context.WithCancel(ctx)
	stop()
	event = executor.Execute(cancelled, "workspace-b", target, "cancelled", filev1.FileOperation_FILE_OPERATION_LIST, map[string]any{"path": directory})
	if event.Success {
		t.Fatal("cancelled request completed")
	}
}

func TestWorkerTransfersPreserveUploadStateAndOSAccount(t *testing.T) {
	target := os.Getenv("KOMARI_IDENTITY_TEST_USER")
	if target == "" {
		current, err := user.Current()
		if err != nil {
			t.Fatal(err)
		}
		target = current.Username
	}
	t.Setenv("KOMARI_WORKSPACE_USERS", target)
	directory, err := os.MkdirTemp("/tmp", "komari-worker-transfer-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(directory)
	if os.Geteuid() == 0 {
		account, err := user.Lookup(target)
		if err != nil {
			t.Fatal(err)
		}
		uid, err := strconv.Atoi(account.Uid)
		if err != nil {
			t.Fatal(err)
		}
		gid, err := strconv.Atoi(account.Gid)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(directory, uid, gid); err != nil {
			t.Fatal(err)
		}
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("token") != "agent-token" {
			t.Error("upstream Agent authentication missing")
		}
		switch r.URL.Path {
		case "/api/clients/transfer/chunk-0":
			_, _ = io.WriteString(w, "aaaa")
		case "/api/clients/transfer/chunk-1":
			_, _ = io.WriteString(w, "bbbb")
		case "/api/clients/transfer/download":
			body, _ := io.ReadAll(r.Body)
			if string(body) != "aaaabbbb" {
				t.Errorf("worker download=%q", body)
			}
			_, _ = io.WriteString(w, "ok")
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	preserveAgentConfig(t, server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	executor := NewExecutor(ctx)
	defer executor.Close()
	path := filepath.Join(directory, "account-owned.bin")
	for index := 0; index < 2; index++ {
		event := executor.Execute(ctx, "upload-workspace", target, fmt.Sprintf("chunk-%d", index), filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM, map[string]any{
			"path": path, "upload_id": "stateful-upload", "transfer_id": fmt.Sprintf("chunk-%d", index), "transfer_token": "scoped-token",
			"offset": index * 4, "chunk_index": index, "chunk_count": 2, "total_size": 8, "chunk_size": 4, "first": index == 0,
		})
		if !event.Success {
			t.Fatalf("worker upload chunk %d: %s", index, event.Error)
		}
	}
	commit := map[string]any{"_op": "upload_commit", "path": path, "upload_id": "stateful-upload", "chunk_count": 2, "total_size": 8, "chunk_size": 4}
	if event := executor.Execute(ctx, "other-workspace", target, "wrong-commit", filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM, commit); event.Success {
		t.Fatal("another workspace committed the upload")
	}
	if event := executor.Execute(ctx, "upload-workspace", target, "commit", filev1.FileOperation_FILE_OPERATION_UPLOAD_STREAM, commit); !event.Success {
		t.Fatalf("worker lost chunk state before commit: %s", event.Error)
	}
	if event := executor.Execute(ctx, "upload-workspace", target, "download", filev1.FileOperation_FILE_OPERATION_DOWNLOAD_STREAM, map[string]any{
		"path": path, "offset": 0, "length": 8, "file_size": 8, "transfer_id": "download", "transfer_token": "scoped-token",
	}); !event.Success {
		t.Fatalf("worker download failed: %s", event.Error)
	}
	content, err := os.ReadFile(path)
	if err != nil || string(content) != "aaaabbbb" {
		t.Fatalf("committed bytes=%q: %v", content, err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	_, _, owner, _ := fileOwnership(info)
	if owner != target {
		t.Fatalf("file owner=%q, want selected account %q", owner, target)
	}
}
