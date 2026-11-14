package clientcore

import (
	"bytes"
	"context"
	"errors"
	"io"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/komari-monitor/komari-agent/core/capability"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/proto"
)

func TestTerminalIdleLocalRevocationCancelsOutputPressure(t *testing.T) {
	ctx, cancel, p, s := terminalPressureFixture(t, 80, false)
	s.gate = make(chan struct{})
	var allowed atomic.Bool
	allowed.Store(true)
	check := func() (bool, string) { return allowed.Load(), "local policy withdrawn" }
	go capability.CancelOnRevocation(ctx, cancel, check)
	done := make(chan error, 1)
	go func() { done <- runRemoteTerminal(ctx, cancel, s, p, "local-revoke", time.Now(), check) }()
	select {
	case <-s.blocked:
	case <-ctx.Done():
		t.Fatal("output did not block")
	}
	allowed.Store(false)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("idle local revocation did not close pressured PTY")
	}
	select {
	case <-p.closed:
	default:
		t.Fatal("revocation leaked PTY")
	}
}

func TestTerminalCancelledStreamCannotDispatchBufferedInput(t *testing.T) {
	ctx, cancel, p, s := terminalPressureFixture(t, 0, false)
	s.commands <- &websshv1.AttachSessionResponse{Sequence: 1, Command: &websshv1.AttachSessionResponse_Input{Input: []byte("stale")}}
	cancel()
	if err := runRemoteTerminal(ctx, cancel, s, p, "cancelled", time.Now(), func() (bool, string) { return true, "" }); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel result: %v", err)
	}
	if len(p.writes) != 0 {
		t.Fatal("cancelled stream dispatched buffered input")
	}
}

type pressureTerminal struct {
	chunks    [][]byte
	readIndex atomic.Int32
	closed    chan struct{}
	once      sync.Once
	writes    chan []byte
	resizes   chan struct{}
	finished  bool
}

func (p *pressureTerminal) Read(b []byte) (int, error) {
	i := int(p.readIndex.Add(1)) - 1
	if i < len(p.chunks) {
		return copy(b, p.chunks[i]), nil
	}
	if p.finished {
		return 0, io.EOF
	}
	<-p.closed
	return 0, io.EOF
}
func (p *pressureTerminal) Write(b []byte) (int, error) {
	p.writes <- bytes.Clone(b)
	return len(b), nil
}
func (p *pressureTerminal) Resize(int, int) error { p.resizes <- struct{}{}; return nil }
func (p *pressureTerminal) Wait() error {
	if !p.finished {
		<-p.closed
	}
	return nil
}
func (p *pressureTerminal) Close() error { p.once.Do(func() { close(p.closed) }); return nil }

type pressureStream struct {
	ctx      context.Context
	commands chan *websshv1.AttachSessionResponse
	events   chan *websshv1.AgentSessionEvent
	blocked  chan struct{}
	gate     chan struct{}
	once     sync.Once
	fail     error
}

func (s *pressureStream) Send(r *websshv1.AttachSessionRequest) error {
	if s.fail != nil {
		return s.fail
	}
	if len(r.GetEvent().GetOutput()) > 0 && s.gate != nil {
		s.once.Do(func() { close(s.blocked) })
		select {
		case <-s.gate:
		case <-s.ctx.Done():
			return s.ctx.Err()
		}
	}
	select {
	case s.events <- proto.Clone(r.GetEvent()).(*websshv1.AgentSessionEvent):
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *pressureStream) Receive() (*websshv1.AttachSessionResponse, error) {
	select {
	case c := <-s.commands:
		return c, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func terminalPressureFixture(t *testing.T, chunks int, finished bool) (context.Context, context.CancelFunc, *pressureTerminal, *pressureStream) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	t.Cleanup(cancel)
	p := &pressureTerminal{closed: make(chan struct{}), writes: make(chan []byte, 8), resizes: make(chan struct{}, 8), finished: finished}
	for i := 0; i < chunks; i++ {
		p.chunks = append(p.chunks, bytes.Repeat([]byte{byte(i)}, 32<<10))
	}
	s := &pressureStream{ctx: ctx, commands: make(chan *websshv1.AttachSessionResponse, 8), events: make(chan *websshv1.AgentSessionEvent, 128), blocked: make(chan struct{})}
	return ctx, cancel, p, s
}

func TestTerminalOutputPressureDoesNotBlockInterruptResizeOrCancellation(t *testing.T) {
	ctx, cancel, p, s := terminalPressureFixture(t, 80, false)
	s.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runRemoteTerminal(ctx, cancel, s, p, "pressure", time.Now(), func() (bool, string) { return true, "" })
	}()
	select {
	case <-s.blocked:
	case <-ctx.Done():
		t.Fatal("sender did not block")
	}
	// Wait for one in-flight chunk, the bounded 32-slot queue and a reader chunk.
	deadline := time.Now().Add(time.Second)
	for p.readIndex.Load() < 34 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := p.readIndex.Load(); got != 34 {
		t.Fatalf("output is not bounded at 34 chunks: %d", got)
	}
	for i := uint64(1); i <= 3; i++ {
		s.commands <- &websshv1.AttachSessionResponse{Sequence: i, Command: &websshv1.AttachSessionResponse_Input{Input: []byte{3}}}
		select {
		case b := <-p.writes:
			if !bytes.Equal(b, []byte{3}) {
				t.Fatal("interrupt changed")
			}
		case <-time.After(time.Second):
			t.Fatal("full output queue blocked input")
		}
	}
	s.commands <- &websshv1.AttachSessionResponse{Sequence: 4, Command: &websshv1.AttachSessionResponse_Resize{Resize: &websshv1.TerminalSize{Rows: 40, Columns: 100}}}
	select {
	case <-p.resizes:
	case <-time.After(time.Second):
		t.Fatal("full output queue blocked resize")
	}
	// Resume one sender to observe a coalesced latest acknowledgment ahead of
	// the remaining output, then cancel with the output queue still occupied.
	close(s.gate)
	var latest uint64
	ackDeadline := time.After(time.Second)
	for latest < 4 {
		select {
		case e := <-s.events:
			latest = max(latest, e.AcceptedCommandSequence)
		case <-ackDeadline:
			t.Fatal("missing acknowledgment")
		}
	}
	if latest != 4 {
		t.Fatalf("latest command acknowledgment=%d", latest)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("cancel did not release blocked workers")
	}
	select {
	case <-p.closed:
	default:
		t.Fatal("PTY left open")
	}
}

func TestTerminalPreservesOutputTailBeforeClose(t *testing.T) {
	ctx, cancel, p, s := terminalPressureFixture(t, 80, true)
	done := make(chan error, 1)
	go func() {
		done <- runRemoteTerminal(ctx, cancel, s, p, "tail", time.Now(), func() (bool, string) { return true, "" })
	}()
	for i := 0; i < 81; i++ {
		select {
		case e := <-s.events:
			if e.Sequence != uint64(i+1) {
				t.Fatalf("sequence=%d want=%d", e.Sequence, i+1)
			}
			if i < 80 {
				if !bytes.Equal(e.GetOutput(), p.chunks[i]) {
					t.Fatalf("lost/reordered chunk %d", i)
				}
			} else if e.GetClosed() == nil {
				t.Fatal("missing final close")
			}
		case <-ctx.Done():
			t.Fatal("output did not drain")
		}
	}
	s.commands <- &websshv1.AttachSessionResponse{Sequence: 1, Command: &websshv1.AttachSessionResponse_CloseReason{CloseReason: "normal"}}
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("normal close stuck")
	}
}

func TestTerminalSendFailureCancelsQuietReceive(t *testing.T) {
	ctx, cancel, p, s := terminalPressureFixture(t, 1, false)
	want := errors.New("transport send failed")
	s.fail = want
	done := make(chan error, 1)
	go func() {
		done <- runRemoteTerminal(ctx, cancel, s, p, "failed", time.Now(), func() (bool, string) { return true, "" })
	}()
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("error=%v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("send failure left Receive/PTY alive")
	}
}

func TestTerminalRevocationRejectsInputUnderOutputPressure(t *testing.T) {
	ctx, cancel, p, s := terminalPressureFixture(t, 80, false)
	s.gate = make(chan struct{})
	done := make(chan error, 1)
	go func() {
		done <- runRemoteTerminal(ctx, cancel, s, p, "revoked", time.Now(), func() (bool, string) { return false, "revoked" })
	}()
	<-s.blocked
	s.commands <- &websshv1.AttachSessionResponse{Sequence: 1, Command: &websshv1.AttachSessionResponse_Input{Input: []byte("denied")}}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("revocation accepted")
		}
	case <-time.After(time.Second):
		t.Fatal("revocation blocked")
	}
	if len(p.writes) != 0 {
		t.Fatal("input reached revoked PTY")
	}
}
