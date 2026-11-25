//go:build !windows

package terminal

import (
	"errors"
	"github.com/creack/pty"
	"os"
	"os/exec"
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
