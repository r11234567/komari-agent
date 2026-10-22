//go:build linux

package hostcmd

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/credentials"
	"github.com/komari-monitor/komari-agent/core/hostops"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	hostconnect "github.com/r11234567/komari-proto/gen/go/komari/host/v1/hostv1connect"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestRecoveryRejectsIncompleteOrUnsupportedJournalIdentity(t *testing.T) {
	for _, tc := range []struct {
		journal hostJournal
		want    string
	}{
		{journal: hostJournal{Version: hostJournalVersion - 1, ID: "operation", Manifest: "/unused"}, want: "unsupported transaction journal version"},
		{journal: hostJournal{Version: hostJournalVersion, Manifest: "/unused"}, want: "missing its operation ID or manifest"},
		{journal: hostJournal{Version: hostJournalVersion, ID: "operation"}, want: "missing its operation ID or manifest"},
	} {
		_, err := resolveJournalManifest(&hostops.Manifest{}, &tc.journal)
		if err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("invalid journal identity was not rejected precisely: %v", err)
		}
	}
}

func TestRecoveryReconcilesAlreadyAcceptedRestorationWithoutAnotherReceipt(t *testing.T) {
	for _, tc := range []struct {
		name       string
		pending    bool
		wrongGrant bool
	}{
		{name: "legacy cleared receipt"},
		{name: "new receipt rejected by terminal operation", pending: true},
		{name: "signed result for a different grant is rejected", pending: true, wrongGrant: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pub, key, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatal(err)
			}
			fixture := &hostTestPanel{key: key, receipts: map[string][]byte{}}
			fixture.set("unit-service", 2, false)
			// Restoration can be reconciled after the execution grant has expired.
			fixture.current.Authorization.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
			original := fixture.revision()
			grant := proto.Clone(original.Authorization).(*hostv1.HostAuthorization)
			if tc.wrongGrant {
				grant.Nonce = "different-grant"
			}
			fixture.op = &hostv1.HostOperation{OperationId: "old-operation", Authorization: grant, Phase: hostv1.HostOperationPhase_HOST_OPERATION_PHASE_RESTORED, LeaseExpiresAt: grant.ExpiresAt}
			mux := http.NewServeMux()
			path, handler := hostconnect.NewHostServiceHandler(fixture)
			mux.Handle(path, handler)
			server := httptest.NewServer(mux)
			defer server.Close()
			p := &panel{trust: &hostops.Trust{AgentID: "stage6-node", PanelKeys: []credentials.PinnedKey{{Algorithm: 1, KeyID: "stage6", Value: base64.StdEncoding.EncodeToString(pub)}}}, host: hostconnect.NewHostServiceClient(server.Client(), server.URL)}
			j := &hostJournal{Version: hostJournalVersion, ID: "old-operation", Phase: "restored", dir: filepath.Join(t.TempDir(), "service")}
			if err = os.Mkdir(j.dir, 0o700); err != nil {
				t.Fatal(err)
			}
			j.Revision, err = proto.Marshal(original)
			if err != nil {
				t.Fatal(err)
			}
			if tc.pending {
				j.Receipt, err = proto.Marshal(&hostv1.ReportHostOperationRequest{AgentId: "stage6-node", OperationId: j.ID, ReceiptId: "new-receipt", Phase: hostv1.HostOperationPhase_HOST_OPERATION_PHASE_RESTORED})
				if err != nil {
					t.Fatal(err)
				}
			}
			err = j.reportRestoration(context.Background(), p, "restore retry")
			if tc.wrongGrant {
				if err == nil || len(j.Receipt) == 0 {
					t.Fatal("mismatched signed operation cleared pending recovery")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(j.Receipt) != 0 || len(fixture.receipts) != 0 {
				t.Fatal("confirmed terminal restoration was reported again")
			}
			if tc.pending && len(j.SupersededReceipts) != 1 {
				t.Fatal("rejected recovery receipt was discarded instead of retained for audit")
			}
			if err = archiveJournal(j); err != nil {
				t.Fatal(err)
			}
			if _, err = os.Stat(filepath.Join(j.dir+"-"+j.ID, "transaction.json")); err != nil {
				t.Fatal("recovered transaction history missing:", err)
			}
		})
	}
}

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
