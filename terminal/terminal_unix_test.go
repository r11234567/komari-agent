//go:build !windows

package terminal

import (
	"errors"
	"github.com/creack/pty"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"
)

func TestUnixTerminalCloseSharesReaperAndReleasesPTY(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "sleep 30")
	tty, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	term := &unixTerminal{tty: tty, cmd: cmd}
	t.Cleanup(func() { _ = term.Close() })
	waits := make(chan error, 2)
	go func() { waits <- term.Wait() }()
	go func() { waits <- term.Wait() }()
	readDone := make(chan struct{})
	go func() { _, _ = term.Read(make([]byte, 1)); close(readDone) }()
	_ = term.Close()
	for range 2 {
		select {
		case <-waits:
		case <-time.After(time.Second):
			t.Fatal("concurrent Wait was not released")
		}
	}
	select {
	case <-readDone:
	case <-time.After(time.Second):
		t.Fatal("PTY read leaked after Close")
	}
	if _, err := tty.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("PTY descriptor remains open: %v", err)
	}
}

func TestUnixTerminalCloseReleasesDescriptorAfterNaturalExit(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-c", "exit 0")
	tty, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	term := &unixTerminal{tty: tty, cmd: cmd}
	if err := term.Wait(); err != nil {
		t.Fatal(err)
	}
	if err := term.Close(); err != nil {
		t.Fatal(err)
	}
	if err := term.Wait(); err != nil {
		t.Fatalf("repeated Wait: %v", err)
	}
	if _, err := tty.Stat(); !errors.Is(err, os.ErrClosed) {
		t.Fatalf("PTY descriptor remains open: %v", err)
	}
}

func TestBuildMotdShellCommandUsesPOSIXShell(t *testing.T) {
	const userShell = "/usr/bin/fish"

	cmd := buildMotdShellCommand(userShell)

	if cmd.Path != "/bin/sh" {
		t.Fatalf("expected MOTD prelude to run with /bin/sh, got %q", cmd.Path)
	}

	wantArgs := []string{"/bin/sh", "-c", motdShellPrelude, "komari-motd", userShell}
	if !reflect.DeepEqual(cmd.Args, wantArgs) {
		t.Fatalf("unexpected command args:\nwant %#v\n got %#v", wantArgs, cmd.Args)
	}
}

func TestMotdShellPreludeExecsSelectedShellFromArgument(t *testing.T) {
	if !strings.Contains(motdShellPrelude, `exec "$1"`) {
		t.Fatalf("expected prelude to exec selected shell from $1, got %q", motdShellPrelude)
	}
	if strings.Contains(motdShellPrelude, `exec "$0"`) {
		t.Fatalf("prelude should not exec $0 because it is reserved for the wrapper name: %q", motdShellPrelude)
	}
}

func TestMotdShellPreludeIsPOSIXShSyntax(t *testing.T) {
	cmd := exec.Command("/bin/sh", "-n", "-c", motdShellPrelude)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("MOTD prelude is not valid POSIX sh syntax: %v\n%s", err, output)
	}
}
