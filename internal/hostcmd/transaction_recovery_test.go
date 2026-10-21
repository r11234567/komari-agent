//go:build linux

package hostcmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/komari-monitor/komari-agent/core/hostops"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	"google.golang.org/protobuf/proto"
)

func TestRecoveryReceiptKeepsIdentityAcrossRestartAndExplicitRestore(t *testing.T) {
	request := &hostv1.ReportHostOperationRequest{OperationId: "operation", ReceiptId: "durable-restoration", Phase: hostv1.HostOperationPhase_HOST_OPERATION_PHASE_RESTORED, Operator: "original-operator", Error: "original-detail"}
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	j := hostJournal{Version: hostJournalVersion, Phase: "restored", Receipt: payload, dir: t.TempDir()}
	for attempt := 0; attempt < 3; attempt++ {
		if err = j.prepareRestorationReceipt(); err != nil {
			t.Fatal(err)
		}
		var disk hostJournal
		if err = hostops.ReadJSON(filepath.Join(j.dir, "transaction.json"), &disk, false); err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(disk.Receipt, payload) || len(disk.SupersededReceipts) != 0 {
			t.Fatal("recovery retry replaced the immutable receipt")
		}
		disk.dir = j.dir
		j = disk
	}
}

func TestStateAccessRecoveryKeepsOriginalModesAndAdoptsNewFiles(t *testing.T) {
	dir := t.TempDir()
	existing := filepath.Join(dir, "existing.json")
	created := filepath.Join(dir, "created.json")
	for _, path := range []string{existing, created} {
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	uid, gid := os.Geteuid(), os.Getegid()
	j := &hostJournal{Ownership: []ownership{{Path: dir, UID: uid, GID: gid, Mode: 0o750}, {Path: existing, UID: uid, GID: gid, Mode: 0o640}}, RecoveryOwnership: []ownership{{Path: dir, UID: uid, GID: gid, Mode: 0o700}, {Path: existing, UID: uid, GID: gid, Mode: 0o600}, {Path: created, UID: uid, GID: gid, Mode: 0o644}}}
	if err := restoreStateOwnership(j, []string{dir}); err != nil {
		t.Fatal(err)
	}
	for path, want := range map[string]os.FileMode{dir: 0o750, existing: 0o640, created: 0o600} {
		st, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if st.Mode().Perm() != want {
			t.Errorf("%s: mode %o, want %o", path, st.Mode().Perm(), want)
		}
	}
}

func TestRecoveryRetainsCancelledSuccessReceiptForAudit(t *testing.T) {
	request := &hostv1.ReportHostOperationRequest{OperationId: "operation", ReceiptId: "unconfirmed-success", Phase: hostv1.HostOperationPhase_HOST_OPERATION_PHASE_LOCAL_APPLIED}
	payload, err := proto.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	j := hostJournal{Version: hostJournalVersion, Phase: "restored", Receipt: payload, dir: t.TempDir()}
	if err = j.prepareRestorationReceipt(); err != nil {
		t.Fatal(err)
	}
	var disk hostJournal
	if err = hostops.ReadJSON(filepath.Join(j.dir, "transaction.json"), &disk, false); err != nil {
		t.Fatal(err)
	}
	if len(disk.Receipt) != 0 || len(disk.SupersededReceipts) != 1 || !bytes.Equal(disk.SupersededReceipts[0], payload) {
		t.Fatal("cancelled success must be preserved without being replayed after restoration")
	}
}
