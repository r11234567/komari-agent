//go:build linux

package server

import (
	"context"
	"encoding/json"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/osidentity"
	"github.com/komari-monitor/komari-agent/core/privileged"
	"github.com/komari-monitor/komari-agent/terminal"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

func rootExecutionFixture(t *testing.T, allowed bool) *privileged.Store {
	t.Helper()
	if os.Getenv("KOMARI_ROOT_EXECUTION_TEST") != "1" {
		t.Skip("requires disposable root runner with a komari account")
	}
	if os.Geteuid() != 0 {
		t.Fatal("root execution component test requires a root runner")
	}
	account, err := user.Lookup("komari")
	if err != nil || account.Uid == "0" {
		t.Fatal("component fixture needs a non-root komari account")
	}
	settings := privileged.Settings{RemoteControlEnabled: true, WebSSHEnabled: true, ExecutionEnabled: true, RootExecutionAllowed: allowed, RequiredPrivilegeMode: reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT}
	data, err := json.Marshal(privileged.State{AppliedRevision: 2, Active: settings})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "privileged.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	store, err := privileged.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := privileged.ActiveStore()
	privileged.SetActive(store)
	t.Cleanup(func() { privileged.SetActive(previous) })
	return store
}

func TestRootExecutionRevocationStopsRunningShell(t *testing.T) {
	store := rootExecutionFixture(t, true)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	started := make(chan struct{}, 1)
	finished := make(chan error, 1)
	go func() {
		_, err := RunTypedExecution(ctx, &execv1.ExecutionSpec{Command: "printf ready; sleep 60", MaxOutputBytes: 8192, RunAsRoot: true}, func(chunk ExecutionOutput) error {
			select {
			case started <- struct{}{}:
			default:
			}
			return nil
		})
		finished <- err
	}()
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("root execution failed to start")
	}
	reduced := store.Effective()
	reduced.RootExecutionAllowed = false
	if err := store.RecordPending(&configv1.PrivilegedRevision{Revision: 3, Privileged: reduced.Proto()}); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-finished:
		if err == nil || ctx.Err() != nil {
			t.Fatalf("root task survived permission withdrawal: %v", err)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("root shell or child survived permission withdrawal")
	}
}

func TestRemoteExecutionDropsRootUnlessExplicitlyApprovedAndSelected(t *testing.T) {
	for _, grant := range []bool{false, true} {
		for _, requested := range []bool{false, true} {
			name := "ordinary"
			if grant {
				name = "approved"
			}
			if requested {
				name += "-root"
			}
			t.Run(name, func(t *testing.T) {
				rootExecutionFixture(t, grant)
				t.Setenv("AGENT_TOKEN", "must-not-reach-child")
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				var output strings.Builder
				code, err := RunTypedExecution(ctx, &execv1.ExecutionSpec{Command: "printf 'identity=%s secret=%s\\n' \"$(id -u)\" \"${AGENT_TOKEN-unset}\"; grep '^NoNewPrivs:' /proc/self/status", MaxOutputBytes: 8192, RunAsRoot: requested}, func(chunk ExecutionOutput) error {
					output.Write(chunk.Data)
					return nil
				})
				if requested && !grant {
					if err == nil || output.Len() != 0 {
						t.Fatalf("unapproved root process ran: %v %s", err, output.String())
					}
					return
				}
				if err != nil || code != 0 {
					t.Fatalf("execution failed: %d %v %s", code, err, output.String())
				}
				uid := "0"
				if !requested {
					account, _ := user.Lookup("komari")
					uid = account.Uid
					if !strings.Contains(output.String(), "NoNewPrivs:\t1") {
						t.Fatalf("ordinary execution could regain privileges: %s", output.String())
					}
				}
				if !strings.Contains(output.String(), "identity="+uid+" secret=unset") {
					t.Fatalf("wrong OS identity or leaked credentials: %s", output.String())
				}
			})
		}
	}
}

func TestRootWebSSHGrantOverridesNeitherDefaultDenyNorLocalUserList(t *testing.T) {
	rootExecutionFixture(t, false)
	t.Setenv("KOMARI_WORKSPACE_USERS", "root")
	if _, err := terminal.OpenSessionAs(80, 24, "root", "/bin/sh", "/"); err == nil {
		t.Fatal("root terminal bypassed default-deny through the local allowlist")
	}
	if _, err := osidentity.ResolveRemote("root", false); err == nil {
		t.Fatal("UID-0 account bypassed the remote grant")
	}
	if _, err := osidentity.ResolveRemote("root", true); err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMARI_WORKSPACE_USERS", "komari")
	if _, err := osidentity.ResolveRemote("root", true); err == nil {
		t.Fatal("remote root permission bypassed the explicit local list")
	}
}

func TestRootWebSSHGrantUsesSelectedUIDAndRestrictsOrdinaryPTY(t *testing.T) {
	rootExecutionFixture(t, true)
	t.Setenv("KOMARI_WORKSPACE_USERS", "root,komari")
	for _, name := range []string{"root", "komari"} {
		t.Run(name, func(t *testing.T) {
			account, err := user.Lookup(name)
			if err != nil {
				t.Fatal(err)
			}
			session, err := terminal.OpenSessionAs(80, 24, name, "/bin/sh", "/")
			if err != nil {
				t.Fatal(err)
			}
			defer session.Close()
			_, err = session.Write([]byte("printf '__PTY_UID__%s\\n' \"$(id -u)\"; grep '^NoNewPrivs:' /proc/self/status\n"))
			if err != nil {
				t.Fatal(err)
			}
			result := make(chan string, 1)
			go func() {
				var output strings.Builder
				buffer := make([]byte, 4096)
				for output.Len() < 64<<10 {
					n, err := session.Read(buffer)
					output.Write(buffer[:n])
					if err != nil || strings.Contains(output.String(), "NoNewPrivs:\t0\r\n") || strings.Contains(output.String(), "NoNewPrivs:\t1\r\n") {
						break
					}
				}
				result <- output.String()
			}()
			select {
			case output := <-result:
				if !strings.Contains(output, "__PTY_UID__"+account.Uid+"\r\n") {
					t.Fatalf("terminal used the wrong account: %q", output)
				}
				if name == "komari" && !strings.Contains(output, "NoNewPrivs:\t1") {
					t.Fatalf("ordinary terminal could elevate after root permission withdrawal: %q", output)
				}
			case <-time.After(3 * time.Second):
				t.Fatal("terminal did not report its OS identity")
			}
		})
	}
}
