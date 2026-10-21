package privileged

import (
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"path/filepath"
	"testing"
)

func TestRequiredPrivilegeModeCannotBeDropped(t *testing.T) {
	s, _ := Open(filepath.Join(t.TempDir(), "privileged.json"))
	r := &configv1.PrivilegedRevision{Revision: 1, Privileged: &configv1.PrivilegedConfig{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT}}
	if err := s.RecordPending(r); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Promote(reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT); err == nil {
		t.Fatal("required_privilege_mode=root was dropped; non-root promotion succeeded")
	}
}
