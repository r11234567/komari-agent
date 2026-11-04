//go:build !windows

package clientcore

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/creack/pty"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
)

type retainedTestPTY struct {
	file     *os.File
	cmd      *exec.Cmd
	once     sync.Once
	waitOnce sync.Once
	waitErr  error
}

func (p *retainedTestPTY) Read(b []byte) (int, error)  { return p.file.Read(b) }
func (p *retainedTestPTY) Write(b []byte) (int, error) { return p.file.Write(b) }
func (p *retainedTestPTY) Resize(cols, rows int) error {
	return pty.Setsize(p.file, &pty.Winsize{Cols: uint16(cols), Rows: uint16(rows)})
}
func (p *retainedTestPTY) Wait() error {
	p.waitOnce.Do(func() { p.waitErr = p.cmd.Wait() })
	return p.waitErr
}
func (p *retainedTestPTY) Close() error {
	p.once.Do(func() { _ = p.file.Close(); _ = p.cmd.Process.Kill() })
	return nil
}

func TestActualPTYKeepsPIDAndWorkingDirectoryAcrossTransportLoss(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-i")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TERM=xterm-256color"}
	file, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	terminal := &retainedTestPTY{file: file, cmd: cmd}
	defer terminal.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	var serverAck atomic.Uint64
	var attempts atomic.Uint32
	opened := make(chan *resumeConnection, 4)
	cursors := make(chan uint64, 4)
	stream := newResumableTerminal(ctx, cancel, time.Now().Add(3*time.Second), func(attempt context.Context, after uint64) (terminalConnection, error) {
		if attempts.Add(1) > 1 {
			// Keep the transport offline while the original shell emits output.
			select {
			case <-time.After(400 * time.Millisecond):
			case <-attempt.Done():
				return nil, attempt.Err()
			}
		}
		c := &resumeConnection{ctx: attempt, frames: make(chan *websshv1.AttachSessionResponse, 32), sent: make(chan *websshv1.AgentSessionEvent, 32)}
		c.frames <- resumeFrame(serverAck.Load())
		opened <- c
		cursors <- after
		return c, nil
	})
	defer stream.close()
	done := make(chan error, 1)
	go func() {
		done <- runRemoteTerminal(ctx, cancel, stream, terminal, "real-pty", time.Now(), func() (bool, string) { return true, "" })
	}()
	first := <-opened
	<-cursors
	input := fmt.Sprintf("cd '%s'; printf 'STATE:%%s:%%s\\n' \"$$\" \"$PWD\"; sleep 0.2; printf 'OFFLINE:%%s:%%s\\n' \"$$\" \"$PWD\"\n", dir)
	frame := resumeFrame(0)
	frame.Sequence = 1
	frame.Command = &websshv1.AttachSessionResponse_Input{Input: []byte(input)}
	first.frames <- frame
	consume := func(c *resumeConnection, marker string) string {
		t.Helper()
		var output strings.Builder
		pattern := regexp.MustCompile(marker + `:[0-9]+:` + regexp.QuoteMeta(dir))
		for {
			select {
			case event := <-c.sent:
				if event.Sequence > 0 {
					serverAck.Store(event.Sequence)
					c.frames <- resumeFrame(event.Sequence)
				}
				output.Write(event.GetOutput())
				if value := pattern.FindString(output.String()); value != "" {
					return value
				}
			case <-ctx.Done():
				t.Fatalf("missing %s in output", marker)
				return ""
			}
		}
	}
	before := consume(first, "STATE")
	close(first.frames)
	var second *resumeConnection
	select {
	case second = <-opened:
	case <-ctx.Done():
		t.Fatal("did not reattach")
	}
	if after := <-cursors; after != 1 {
		t.Fatalf("applied command cursor lost: %d", after)
	}
	offline := consume(second, "OFFLINE")
	if strings.TrimPrefix(before, "STATE:") != strings.TrimPrefix(offline, "OFFLINE:") {
		t.Fatalf("output produced while offline lost its shell identity: %s -> %s", before, offline)
	}
	// Even a duplicate delivered by an interrupted transport cannot execute twice.
	duplicate := resumeFrame(serverAck.Load())
	duplicate.Sequence = 1
	duplicate.Command = &websshv1.AttachSessionResponse_Input{Input: []byte("cd /\n")}
	second.frames <- duplicate
	next := resumeFrame(serverAck.Load())
	next.Sequence = 2
	next.Command = &websshv1.AttachSessionResponse_Input{Input: []byte("printf 'AFTER:%s:%s\\n' \"$$\" \"$PWD\"\n")}
	second.frames <- next
	after := consume(second, "AFTER")
	if strings.TrimPrefix(before, "STATE:") != strings.TrimPrefix(after, "AFTER:") {
		t.Fatalf("shell or directory changed: %s -> %s", before, after)
	}
	t.Logf("same shell and directory before/offline/after: %s -> %s -> %s", before, offline, after)
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("PTY cleanup stuck")
	}
}
