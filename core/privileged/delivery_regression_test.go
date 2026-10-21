package privileged

import (
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	securityv1 "github.com/r11234567/komari-proto/gen/go/komari/security/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
	"path/filepath"
	"testing"
	"time"
)

func approvedFixture(rev uint64, settings Settings) *configv1.PrivilegedRevision {
	hash := Hash(settings)
	return &configv1.PrivilegedRevision{AgentId: "node", Revision: rev, ProtocolVersion: 2, ApprovalGeneration: 1, UpdateSequence: rev, ConfigHash: hash, Privileged: settings.Proto(), State: configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_AWAITING_AGENT, Signature: &securityv1.SignedEnvelope{}, Authorization: &hostv1.HostAuthorization{AgentId: "node", Revision: rev, ConfigHash: hash, ApprovalGeneration: 1, ServiceId: "custom", TargetPrivilegeMode: settings.RequiredPrivilegeMode, Nonce: "fresh", ApprovedBy: "operator", IssuedAt: timestamppb.Now(), ExpiresAt: timestamppb.New(time.Now().Add(time.Minute))}}
}
func TestRegressionSecondRollbackCanWidenWithoutAuthentication(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "privileged.json"))
	settings := Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, RemoteControlEnabled: true}
	if err := s.ApplyApproved(approvedFixture(1, settings), settings.RequiredPrivilegeMode, Receipt{ID: "apply"}); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Rollback(); err != nil {
		t.Fatal(err)
	}
	restored, _, err := s.Rollback()
	if err == nil && restored.RemoteControlEnabled {
		t.Fatal("second rollback widened remote control without authentication")
	}
	if s.Active().RemoteControlEnabled {
		t.Fatal("withdrawn grant became active again")
	}
}
func TestRegressionDaemonStoreOverwritesCLIChange(t *testing.T) {
	path := filepath.Join(t.TempDir(), "privileged.json")
	daemon, _ := Open(path)
	local := Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, RemoteControlEnabled: true}
	rev := approvedFixture(1, local)
	if err := daemon.RecordPending(rev); err != nil {
		t.Fatal(err)
	}
	other, _ := Open(path)
	if err := other.ApplyApproved(rev, local.RequiredPrivilegeMode, Receipt{ID: "apply"}); err != nil {
		t.Fatal(err)
	}
	// A stale daemon object must reject rather than erase another writer's commit.
	if err := daemon.RecordPending(approvedFixture(2, local)); err == nil {
		t.Fatal("stale in-memory writer accepted")
	}
	disk, _ := Open(path)
	if disk.State().AppliedRevision != 1 {
		t.Fatal("stale daemon overwrote applied r1")
	}
	if _, err := other.Promote(local.RequiredPrivilegeMode); err == nil {
		t.Fatal("legacy unsigned CLI promotion remains open")
	}
}
func TestRegressionApprovalBindingAndDurableOutbox(t *testing.T) {
	local := Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT, RemoteControlEnabled: true, WebSSHEnabled: true}
	valid := approvedFixture(2, local)
	changes := map[string]func(*configv1.PrivilegedRevision){
		"service":    func(r *configv1.PrivilegedRevision) { r.Authorization.ServiceId = "other" },
		"generation": func(r *configv1.PrivilegedRevision) { r.Authorization.ApprovalGeneration++ },
		"identity": func(r *configv1.PrivilegedRevision) {
			r.Privileged.RequiredPrivilegeMode = reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT
		},
		"expired": func(r *configv1.PrivilegedRevision) {
			r.Authorization.ExpiresAt = timestamppb.New(time.Now().Add(-time.Minute))
		},
		"actions": func(r *configv1.PrivilegedRevision) { r.Authorization.Actions = []hostv1.HostAction{1} },
		"unapproved": func(r *configv1.PrivilegedRevision) {
			r.State = configv1.PrivilegedDeliveryState_PRIVILEGED_DELIVERY_STATE_NEEDS_CONFIRMATION
		},
	}
	for name, change := range changes {
		t.Run(name, func(t *testing.T) {
			r := proto.Clone(valid).(*configv1.PrivilegedRevision)
			change(r)
			if err := ValidateApproval(r, "node", "custom", local.RequiredPrivilegeMode); err == nil {
				t.Fatal("invalid binding accepted")
			}
		})
	}
	s, _ := Open(filepath.Join(t.TempDir(), "privileged.json"))
	if err := s.ApplyApproved(valid, local.RequiredPrivilegeMode, Receipt{ID: "immutable", Kind: "privileged", Payload: []byte("original")}); err != nil {
		t.Fatal(err)
	}
	reopened, _ := Open(s.Path())
	if reopened.State().AppliedRevision != 2 || string(reopened.State().Outbox[0].Payload) != "original" {
		t.Fatal("ACK and active snapshot did not survive restart")
	}
	withdrawn := local
	withdrawn.WebSSHEnabled = false
	if err := reopened.RecordPending(approvedFixture(3, withdrawn)); err != nil {
		t.Fatal(err)
	}
	if reopened.Effective().WebSSHEnabled || !reopened.Effective().RemoteControlEnabled {
		t.Fatal("pending revocation did not restrict only the withdrawn grant")
	}
}
