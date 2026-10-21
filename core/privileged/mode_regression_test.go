package privileged

import (
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
	"testing"
)

func TestRequiredPrivilegeModeCannotBeDropped(t *testing.T) {
	local := Settings{RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT}
	r := approvedFixture(1, local)
	if err := ValidateApproval(r, "node", "custom", reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT); err == nil {
		t.Fatal("required root mode was dropped for non-root daemon")
	}
}
