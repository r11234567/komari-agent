//go:build linux

package hostcmd

import (
	"os"
	"os/user"
	"testing"
)

func TestEnsureExecutionAccountPreservesDaemonIdentity(t *testing.T) {
	if os.Getenv("KOMARI_ROOT_EXECUTION_TEST") != "1" {
		t.Skip("requires an administrator-owned disposable account fixture")
	}
	if os.Geteuid() != 0 {
		t.Fatal("account provisioning requires a disposable root runner")
	}
	before := os.Geteuid()
	for range 2 {
		if err := ensureExecutionAccount(); err != nil {
			t.Fatal(err)
		}
	}
	account, err := user.Lookup("komari")
	if err != nil || account.Uid == "0" || os.Geteuid() != before {
		t.Fatal("execution account was privileged or changed the daemon identity")
	}
}
