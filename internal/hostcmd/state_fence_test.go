//go:build linux

package hostcmd

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/komari-monitor/komari-agent/core/hostops"
)

func TestStateFileStreamPreservesLargeLegacyBinaryAndReplacesInode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent")
	old, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer old.Close()
	const size = int64(19550635) // The retired SJC Agent binary that broke apply.
	if err = old.Truncate(size); err != nil {
		t.Fatal(err)
	}
	marker := []byte("legacy executable")
	if _, err = old.WriteAt(marker, size-int64(len(marker))); err != nil {
		t.Fatal(err)
	}
	before, _ := old.Stat()
	n, err := copySealedStateFile(path, old, maxStateFileBytes)
	if err != nil || n != size {
		t.Fatalf("copy: bytes=%d error=%v", n, err)
	}
	after, err := os.Stat(path)
	if err != nil || after.Size() != size || after.Mode().Perm() != 0o600 || os.SameFile(before, after) {
		t.Fatalf("state was not published as a fresh private inode: %v %v", after, err)
	}
	// A former service process's writable FD must not affect the new inode.
	if _, err = old.WriteAt([]byte("changed"), size-int64(len(marker))); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	got := make([]byte, len(marker))
	if _, err = f.ReadAt(got, size-int64(len(marker))); err != nil || !bytes.Equal(got, marker) {
		t.Fatalf("old writable FD changed sealed state: %q %v", got, err)
	}
}

func TestStateFileStreamGrowthLimitPreservesDestination(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, []byte("original"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := copySealedStateFile(path, strings.NewReader("too large"), 3)
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Fatalf("growth limit needs the failing path: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != "original" {
		t.Fatalf("failed stream replaced original state: %q %v", data, err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil || len(entries) != 1 {
		t.Fatalf("failed stream retained staging files: %v %v", entries, err)
	}
}

func TestHostStateFenceEarlyFailureRestores(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership fence is exercised as root on disposable CI")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	small := filepath.Join(dir, "credentials.json")
	large := filepath.Join(dir, "oversized-artifact")
	if err := os.WriteFile(small, []byte("preserve credentials"), 0o640); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{dir: 0o750, small: 0o640} {
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Create(large)
	if err != nil {
		t.Fatal(err)
	}
	if err = f.Truncate(maxStateFileBytes + 1); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	for _, path := range []string{dir, small, large} {
		if err = os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
	}
	before, _ := os.Stat(large)
	j := &hostJournal{Version: hostJournalVersion, Phase: "mutating", dir: t.TempDir()}
	err = j.fenceStateDirectories([]string{dir}, 65534, false)
	if err == nil || !strings.Contains(err.Error(), large) {
		t.Fatalf("oversized artifact must fail with its path: %v", err)
	}
	after, _ := os.Stat(large)
	if before.Mode() != after.Mode() || after.Sys().(*syscall.Stat_t).Uid != 65534 {
		t.Fatal("unsupported file was mutated before its size was checked")
	}
	sealedRoot, _ := os.Stat(dir)
	if sealedRoot.Sys().(*syscall.Stat_t).Uid != 0 {
		t.Fatal("fixture did not reproduce a partially fenced tree")
	}
	// Simulate a crash/restart during restoration. The durable marker must let
	// us restore all touched metadata without hitting the same copy limit again.
	var loaded hostJournal
	if err = hostops.ReadJSON(filepath.Join(j.dir, "transaction.json"), &loaded, false); err != nil {
		t.Fatal(err)
	}
	loaded.dir = j.dir
	if loaded.FenceStage != "sealing" {
		t.Fatal("initial fence stage was not persisted")
	}
	if err = loaded.fenceStateDirectories([]string{dir}, 65534, true); err != nil {
		t.Fatal("recovery repeated the failed copy:", err)
	}
	if err = restoreStateOwnership(&loaded, []string{dir}); err != nil {
		t.Fatal(err)
	}
	for path, mode := range map[string]os.FileMode{dir: 0o750, small: 0o640, large: before.Mode().Perm()} {
		st, err := os.Stat(path)
		if err != nil || st.Mode().Perm() != mode || st.Sys().(*syscall.Stat_t).Uid != 65534 {
			t.Fatalf("original state access was not restored for %s: %v %v", path, st, err)
		}
	}
	data, err := os.ReadFile(small)
	if err != nil || string(data) != "preserve credentials" {
		t.Fatalf("credential contents changed: %q %v", data, err)
	}
}

func TestHostStateFenceLegacyAndPublishedProfileRestore(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("ownership fence is exercised as root on disposable CI")
	}
	for _, stage := range []string{"", "profile"} {
		t.Run("stage="+stage, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "state")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "agent")
			f, err := os.Create(path)
			if err != nil {
				t.Fatal(err)
			}
			if err = f.Truncate(19550635); err != nil {
				f.Close()
				t.Fatal(err)
			}
			f.Close()
			before, _ := os.Stat(path)
			j := &hostJournal{Version: hostJournalVersion, FenceStage: stage, dir: t.TempDir(), Ownership: []ownership{{Path: dir, UID: 65534, GID: 65534, Mode: 0o750}, {Path: path, UID: 65534, GID: 65534, Mode: 0o640}}}
			if err = j.fenceStateDirectories([]string{dir}, 65534, true); err != nil {
				t.Fatal("recovery cannot fence a legacy Agent ELF:", err)
			}
			after, _ := os.Stat(path)
			if os.SameFile(before, after) || len(j.RecoveryOwnership) != 2 {
				t.Fatal("legacy journals and published profiles must fence fresh inodes on recovery")
			}
			if err = restoreStateOwnership(j, []string{dir}); err != nil {
				t.Fatal(err)
			}
			f, err = os.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			defer f.Close()
			n, err := io.Copy(io.Discard, f)
			if err != nil || n != 19550635 {
				t.Fatalf("recovery lost legacy file contents: bytes=%d error=%v", n, err)
			}
		})
	}
}
