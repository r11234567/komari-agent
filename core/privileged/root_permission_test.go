package privileged

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
)

func TestRootPermissionDefaultsDeniedAndIsBoundToApproval(t *testing.T) {
	base := Settings{RemoteControlEnabled: true, RequiredPrivilegeMode: 1}
	root := base
	root.RootExecutionAllowed = true
	if Hash(base) == Hash(root) || Subset(root, base) || !Subset(base, root) {
		t.Fatal("root permission is absent from the hash or reduction boundary")
	}
	if SettingsFromProto(root.Proto()) != root {
		t.Fatal("root permission was lost in the signed configuration")
	}
	path := filepath.Join(t.TempDir(), "privileged.json")
	if err := os.WriteFile(path, []byte(`{"applied_revision":1,"active":{"remote_control_enabled":true}}`), 0600); err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil || store.Effective().RootExecutionAllowed {
		t.Fatal("historical state implicitly allowed root")
	}
	if err := store.RecordPending(&configv1.PrivilegedRevision{Revision: 2, Privileged: root.Proto()}); err != nil {
		t.Fatal(err)
	}
	if store.Effective().RootExecutionAllowed {
		t.Fatal("unapproved root candidate activated permission")
	}
	data, _ := json.Marshal(State{AppliedRevision: 2, Active: root, PendingRevision: 3, Pending: &base})
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err = Open(path)
	if err != nil || store.Effective().RootExecutionAllowed {
		t.Fatal("pending withdrawal failed to restrict active root permission")
	}
}
