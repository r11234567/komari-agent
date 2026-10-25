//go:build !windows

package terminal

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLoginShellUsesSelectedAccount(t *testing.T) {
	passwd := "daemon:x:1:1::/:/usr/sbin/nologin\nalice:x:1001:1001::/home/alice:/bin/bash\n"
	for _, test := range []struct{ name, uid, want string }{
		{"alice", "1001", "/bin/bash"},
		{"daemon", "1", "/usr/sbin/nologin"},
	} {
		got, err := loginShellFromPasswd(strings.NewReader(passwd), test.name, test.uid)
		if err != nil || got != test.want {
			t.Fatalf("account %s: shell=%q err=%v", test.name, got, err)
		}
	}
	for _, passwd := range []string{
		"alice:x:2001:1001::/home/alice:/bin/bash\n",
		"other:x:1001:1001::/home/other:/bin/bash\n",
		"alice:x:1001:1001::/home/alice:bash\n",
	} {
		if _, err := loginShellFromPasswd(strings.NewReader(passwd), "alice", "1001"); err == nil {
			t.Fatalf("invalid account entry accepted: %q", passwd)
		}
	}
}

// CI explicitly supplies a disposable account with a known bash login profile.
// This checks the real PTY/account boundary without a browser or panel E2E.
func TestSelectedAccountInteractiveLoginPTY(t *testing.T) {
	target := os.Getenv("KOMARI_TERMINAL_TEST_USER")
	if target == "" {
		t.Skip("requires disposable CI login account")
	}
	account, err := user.Lookup(target)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("KOMARI_WORKSPACE_USERS", target)
	t.Setenv("SHELL", "/bin/false")
	t.Setenv("AGENT_TOKEN", "must-not-reach-the-shell")
	terminal, err := newTerminalAs(target, "", "")
	if err != nil {
		t.Fatal(err)
	}
	defer terminal.term.Close()
	if filepath.Base(terminal.shell) != "bash" || terminal.workingDir != account.HomeDir {
		t.Fatalf("wrong shell/home: %q %q", terminal.shell, terminal.workingDir)
	}
	if _, err := terminal.term.Write([]byte("printf '__ACCOUNT__%s|%s|%s|%s|%s\\n' \"$USER\" \"$HOME\" \"$SHELL\" \"$-\" \"${AGENT_TOKEN-unset}\"\n")); err != nil {
		t.Fatal(err)
	}
	output := make(chan string, 1)
	readError := make(chan error, 1)
	go func() {
		var transcript strings.Builder
		buffer := make([]byte, 4096)
		for transcript.Len() < 64<<10 {
			n, err := terminal.term.Read(buffer)
			transcript.Write(buffer[:n])
			value := transcript.String()
			if strings.Contains(value, "|unset\r\n") && strings.Contains(value, target+"@") {
				output <- value
				return
			}
			if err != nil {
				readError <- fmt.Errorf("PTY: %w; transcript=%q", err, value)
				return
			}
		}
		readError <- fmt.Errorf("PTY output exceeded test limit")
	}()
	select {
	case value := <-output:
		if !strings.Contains(value, "WORKSPACE_LOGIN_PROFILE_LOADED") || !strings.Contains(value, "__ACCOUNT__"+target+"|"+account.HomeDir+"|") || strings.Contains(value, "must-not-reach-the-shell") {
			t.Fatalf("login profile/account environment was lost: %q", value)
		}
		t.Logf("selected-account PTY startup and prompt: %q", value)
	case err := <-readError:
		t.Fatal(err)
	case <-time.After(8 * time.Second):
		t.Fatal("selected-account login shell did not produce an interactive prompt within 8s")
	}
}
