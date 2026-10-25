//go:build !windows

package files

import (
	"context"
	"os"
	"os/user"
	"path/filepath"
	"testing"

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
