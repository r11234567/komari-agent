package privileged

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	hostv1 "github.com/r11234567/komari-proto/gen/go/komari/host/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
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

func TestHashMatchesProtocolVectors(t *testing.T) {
	path := filepath.Join("..", "..", "third_party", "komari-proto", "testdata", "privileged-settings-v1.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var vectors []struct {
		Booleans                 [5]int                 `json:"booleans"`
		Mode                     reportv1.PrivilegeMode `json:"required_privilege_mode"`
		RootExecutionAllowed     bool                   `json:"root_execution_allowed"`
		TrafficMonitoringEnabled bool                   `json:"traffic_monitoring_enabled"`
		Hash                     string                 `json:"sha256"`
	}
	if err := json.Unmarshal(data, &vectors); err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("missing protocol hash vectors")
	}
	for i, vector := range vectors {
		settings := Settings{
			RemoteControlEnabled:     vector.Booleans[0] != 0,
			WebSSHEnabled:            vector.Booleans[1] != 0,
			ExecutionEnabled:         vector.Booleans[2] != 0,
			EnableGPU:                vector.Booleans[3] != 0,
			RescueHelperEnabled:      vector.Booleans[4] != 0,
			RequiredPrivilegeMode:    vector.Mode,
			RootExecutionAllowed:     vector.RootExecutionAllowed,
			TrafficMonitoringEnabled: vector.TrafficMonitoringEnabled,
		}
		if got := Hash(settings); got != vector.Hash {
			t.Errorf("protocol vector %d: hash = %q, want %q", i, got, vector.Hash)
		}
	}
}

func TestHashBindsRootExecutionPermission(t *testing.T) {
	settings := Settings{
		RemoteControlEnabled: true, WebSSHEnabled: true, ExecutionEnabled: true,
		RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT,
	}
	for _, tc := range []struct {
		allowed bool
		hash    string
	}{
		{false, "732d1dcb21b8c7f11ee60fb34e3fb182658abed2d5b0a2e8f7f535cb22d71be2"},
		{true, "905ed93eb53892e1f086adcd3c2cd46ad0cdcd913568879d0275c501790e01fa"},
	} {
		settings.RootExecutionAllowed = tc.allowed
		if got := Hash(settings); got != tc.hash {
			t.Errorf("root execution allowed = %t: hash = %q, want %q", tc.allowed, got, tc.hash)
		}
	}
}
