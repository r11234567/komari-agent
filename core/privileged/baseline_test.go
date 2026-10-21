package privileged

import (
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"path/filepath"
	"testing"
)

func TestBaselineAndReceiptSurviveRestartWithoutGrantingIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privileged.json")
	s, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	local := Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT}
	r := &configv1.PrivilegedRevision{Revision: 1, ProtocolVersion: 2, InstallationBaseline: true, ApprovalGeneration: 1, ConfigHash: Hash(local), Privileged: local.Proto(), Authorization: &hostv1.HostAuthorization{ServiceId: "custom"}}
	receipt := Receipt{ID: "stable-id", Kind: "privileged", Payload: []byte("immutable-ack")}
	if err = s.AdoptBaseline(r, local, reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, receipt); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	state := reopened.State()
	if state.AppliedRevision != 1 || len(state.Outbox) != 1 || state.Outbox[0].ID != "stable-id" {
		t.Fatalf("lost durable snapshot or ACK: %+v", state)
	}
	if err = reopened.AdoptBaseline(r, local, reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT, receipt); err == nil {
		t.Fatal("CLI root identity changed baseline identity")
	}
	r.Revision = 2
	if err = reopened.AdoptBaseline(r, local, reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, receipt); err == nil {
		t.Fatal("baseline used for r2")
	}
	if err = reopened.FinishReceipt("stable-id", "stale revision"); err != nil {
		t.Fatal(err)
	}
	reopened, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(reopened.State().RejectedReceipts) != 1 || len(reopened.State().Outbox) != 0 {
		t.Fatal("rejected ACK evidence lost")
	}
}
func TestRequiredModeParticipatesInCanonicalHash(t *testing.T) {
	one := Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT}
	two := one
	two.RequiredPrivilegeMode = reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT
	if Hash(one) == Hash(two) {
		t.Fatal("hash does not bind target identity")
	}
}
