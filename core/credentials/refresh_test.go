package credentials

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestCredentialRefreshPendingSurvivesReopenAndCommitFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Save(Identity{AgentID: "node", AccessToken: "old-at", RefreshToken: "old-rt"}); err != nil {
		t.Fatal(err)
	}
	pending, err := store.BeginRefresh()
	if err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	retry, err := reopened.BeginRefresh()
	if err != nil {
		t.Fatal(err)
	}
	if retry.PendingRefresh.RequestID != pending.PendingRefresh.RequestID {
		t.Fatal("restart created a different refresh request")
	}
	generation := uint64(1)
	next := retry
	next.AccessToken = "new-at"
	next.RefreshToken = "new-rt"
	next.Generation = &generation
	if err = os.Rename(path, path+".retained"); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(path, 0700); err != nil {
		t.Fatal(err)
	}
	if err = reopened.CommitRefresh(retry, next); err == nil {
		t.Fatal("expected real filesystem persistence failure")
	}
	failed, _ := reopened.Identity()
	if failed.AccessToken != "old-at" || failed.PendingRefresh == nil {
		t.Fatal("failed commit published unsaved credentials")
	}
	if err = os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err = os.Rename(path+".retained", path); err != nil {
		t.Fatal(err)
	}
	if err = reopened.CommitRefresh(retry, next); err != nil {
		t.Fatal(err)
	}
	final, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	saved, _ := final.Identity()
	if saved.AccessToken != "new-at" || saved.PendingRefresh != nil || saved.Generation == nil || *saved.Generation != 1 {
		t.Fatal("commit did not persist the complete new generation")
	}
	if err = reopened.CommitRefresh(retry, next); err == nil {
		t.Fatal("stale operation committed twice")
	}
	clone, _ := final.Identity()
	*clone.Generation = 999
	original, _ := final.Identity()
	if *original.Generation != 1 {
		t.Fatal("identity copy mutated stored generation")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0600 {
		t.Fatalf("credential file permissions=%v", info.Mode())
	}
}

func TestCredentialFileWatchAtomicRenameAndCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "credentials.json")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Save(Identity{AgentID: "node", RefreshToken: "synthetic"}); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	changes, err := WatchChanges(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if err = store.Save(Identity{AgentID: "node", RefreshToken: "rotated"}); err != nil {
		t.Fatal(err)
	}
	select {
	case _, open := <-changes:
		if !open {
			t.Fatal("watch ended before replacement")
		}
	case <-time.After(7 * time.Second):
		t.Fatal("atomic rename did not notify credential consumer")
	}
	cancel()
	timeout := time.After(time.Second)
	for {
		select {
		case _, open := <-changes:
			if !open {
				return
			}
		case <-timeout:
			t.Fatal("credential watcher leaked after cancellation")
		}
	}
}
