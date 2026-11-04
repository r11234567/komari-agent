package clientcore

import (
	"context"
	"errors"
	"io"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type resumeConnection struct {
	ctx    context.Context
	frames chan *websshv1.AttachSessionResponse
	sent   chan *websshv1.AgentSessionEvent
}

func (s *resumeConnection) Send(r *websshv1.AttachSessionRequest) error {
	select {
	case s.sent <- r.GetEvent():
		return nil
	case <-s.ctx.Done():
		return s.ctx.Err()
	}
}
func (s *resumeConnection) Receive() (*websshv1.AttachSessionResponse, error) {
	select {
	case f, ok := <-s.frames:
		if !ok {
			return nil, io.EOF
		}
		return f, nil
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}
func (s *resumeConnection) CloseRequest() error  { return nil }
func (s *resumeConnection) CloseResponse() error { return nil }
func resumeFrame(ack uint64) *websshv1.AttachSessionResponse {
	return &websshv1.AttachSessionResponse{AcceptedEventSequence: ack, ResumeUntil: timestamppb.New(time.Now().Add(3 * time.Second))}
}

func TestTerminalResumeReplaysUnconfirmedOutputAndPreservesCommandCursor(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	opened := make(chan *resumeConnection, 4)
	cursors := make(chan uint64, 4)
	var mu sync.Mutex
	attempt := 0
	r := newResumableTerminal(ctx, cancel, time.Now().Add(3*time.Second), func(attemptCtx context.Context, after uint64) (terminalConnection, error) {
		s := &resumeConnection{ctx: attemptCtx, frames: make(chan *websshv1.AttachSessionResponse, 8), sent: make(chan *websshv1.AgentSessionEvent, 8)}
		mu.Lock()
		attempt++
		n := attempt
		mu.Unlock()
		ack := uint64(0)
		if n > 1 {
			ack = 1
		}
		s.frames <- resumeFrame(ack)
		opened <- s
		cursors <- after
		return s, nil
	})
	defer r.close()
	first := <-opened
	for sequence := uint64(1); sequence <= 2; sequence++ {
		if err := r.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Event{Event: &websshv1.AgentSessionEvent{Sequence: sequence, Event: &websshv1.AgentSessionEvent_Output{Output: []byte{byte(sequence)}}}}}); err != nil {
			t.Fatal(err)
		}
	}
	for range 2 {
		select {
		case <-first.sent:
		case <-ctx.Done():
			t.Fatal("no output")
		}
	}
	r.AcceptCommand(7)
	first.frames <- resumeFrame(1)
	// The first output was accepted; the second send's outcome is ambiguous.
	close(first.frames)
	var second *resumeConnection
	select {
	case second = <-opened:
	case <-ctx.Done():
		t.Fatal("transport did not resume")
	}
	<-cursors
	if after := <-cursors; after != 7 {
		t.Fatalf("lost command cursor: %d", after)
	}
	var replay *websshv1.AgentSessionEvent
	for replay == nil {
		select {
		case event := <-second.sent:
			if event.Event != nil {
				replay = event
			}
		case <-ctx.Done():
			t.Fatal("no replay")
		}
	}
	if replay.Sequence != 2 || replay.GetOutput()[0] != 2 {
		t.Fatalf("duplicated accepted output or lost pending output: %v", replay)
	}
	second.frames <- resumeFrame(2)
	second.frames <- &websshv1.AttachSessionResponse{Sequence: 8, AcceptedEventSequence: 2, ResumeUntil: timestamppb.New(time.Now().Add(3 * time.Second)), Command: &websshv1.AttachSessionResponse_Input{Input: []byte("next")}}
	command, err := r.Receive()
	if err != nil || command.Sequence != 8 {
		t.Fatalf("resumed input: %v %v", command, err)
	}
}

func TestTerminalResumeIsBoundedAndExpiryCancelsBlockedProducer(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newResumableTerminal(ctx, cancel, time.Now().Add(150*time.Millisecond), func(context.Context, uint64) (terminalConnection, error) {
		return nil, connect.NewError(connect.CodeUnavailable, errors.New("offline"))
	})
	defer r.close()
	for sequence := uint64(1); sequence <= 32; sequence++ {
		if err := r.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Event{Event: &websshv1.AgentSessionEvent{Sequence: sequence, Event: &websshv1.AgentSessionEvent_Output{Output: make([]byte, 32<<10)}}}}); err != nil {
			t.Fatal(err)
		}
	}
	done := make(chan error, 1)
	go func() {
		done <- r.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Event{Event: &websshv1.AgentSessionEvent{Sequence: 33, Event: &websshv1.AgentSessionEvent_Output{Output: []byte{1}}}}})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unbounded replay")
		}
	case <-time.After(time.Second):
		t.Fatal("offline lease did not expire")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.events) != 32 {
		t.Fatalf("unbounded retained events=%d", len(r.events))
	}
}

func TestTerminalResumeRejectsLostStateAndNeverRecreatesShell(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := newResumableTerminal(ctx, cancel, time.Now().Add(time.Second), func(context.Context, uint64) (terminalConnection, error) {
		return nil, connect.NewError(connect.CodeNotFound, errors.New("panel lost original session"))
	})
	defer r.close()
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("lost server session was retried")
	}
	if r.failure() == nil {
		t.Fatal("missing state-loss error")
	}
}
