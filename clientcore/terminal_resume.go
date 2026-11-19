package clientcore

import (
	"context"
	"errors"
	"io"
	"log"
	"net"
	"sync"
	"time"

	"connectrpc.com/connect"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/proto"
)

const (
	terminalHandshakeTimeout  = 10 * time.Second
	terminalCheckpointTimeout = 12 * time.Second // backend heartbeats every five seconds
)

// The PTY belongs to the authorization, not to one HTTP connection. Output is
// retained until the backend checkpoints it; command execution cursors survive
// reconnects. Neither side creates a new shell under an old session identity.
type resumableTerminal struct {
	ctx                     context.Context
	cancel                  context.CancelFunc
	open                    func(context.Context, uint64) (terminalConnection, error)
	mu                      sync.Mutex
	events                  []*websshv1.AgentSessionEvent
	highest, acked, command uint64
	notify                  chan struct{}
	commands                chan *websshv1.AttachSessionResponse
	deadline                *time.Timer
	err                     error
	done                    chan struct{}
	sessionID               string
}

type terminalConnection interface {
	remoteTerminalStream
	CloseRequest() error
	CloseResponse() error
}

func newResumableTerminal(ctx context.Context, cancel context.CancelFunc, until time.Time, sessionID string, open func(context.Context, uint64) (terminalConnection, error)) *resumableTerminal {
	r := &resumableTerminal{ctx: ctx, cancel: cancel, open: open, notify: make(chan struct{}), commands: make(chan *websshv1.AttachSessionResponse), done: make(chan struct{}), sessionID: sessionID}
	if until.After(time.Now().Add(30 * time.Second)) {
		until = time.Now().Add(30 * time.Second)
	}
	r.deadline = time.AfterFunc(max(time.Until(until), 0), func() { r.fail(errors.New("terminal transport lease expired; original shell closed")) })
	go r.run()
	return r
}

func (r *resumableTerminal) signalLocked() { close(r.notify); r.notify = make(chan struct{}) }
func (r *resumableTerminal) failure() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.err != nil {
		return r.err
	}
	return r.ctx.Err()
}
func (r *resumableTerminal) fail(err error) {
	r.mu.Lock()
	if r.err == nil {
		r.err = err
	}
	r.mu.Unlock()
	r.cancel()
}
func (r *resumableTerminal) close() { r.cancel(); <-r.done; r.deadline.Stop() }

func (r *resumableTerminal) AcceptCommand(sequence uint64) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if sequence > r.command {
		r.command = sequence
		r.signalLocked()
	}
}
func (r *resumableTerminal) Send(request *websshv1.AttachSessionRequest) error {
	event := request.GetEvent()
	if event == nil {
		return errors.New("resumable terminal requires an event")
	}
	if len(event.GetOutput()) > 32<<10 {
		return errors.New("terminal output frame too large")
	}
	for {
		if r.ctx.Err() != nil {
			return r.failure()
		}
		r.mu.Lock()
		if event.AcceptedCommandSequence > r.command {
			r.command = event.AcceptedCommandSequence
			r.signalLocked()
		}
		if event.Event == nil {
			r.mu.Unlock()
			return nil
		}
		if len(r.events) < 32 {
			if event.Sequence != r.highest+1 {
				r.mu.Unlock()
				return errors.New("terminal event sequence is invalid")
			}
			r.highest = event.Sequence
			r.events = append(r.events, proto.Clone(event).(*websshv1.AgentSessionEvent))
			r.signalLocked()
			r.mu.Unlock()
			return nil
		}
		signal := r.notify
		r.mu.Unlock()
		select {
		case <-r.ctx.Done():
			return r.failure()
		case <-signal:
		}
	}
}

func (r *resumableTerminal) Receive() (*websshv1.AttachSessionResponse, error) {
	select {
	case <-r.ctx.Done():
		return nil, r.failure()
	case command := <-r.commands:
		return command, nil
	}
}

func (r *resumableTerminal) checkpoint(frame *websshv1.AttachSessionResponse) error {
	if frame.ResumeUntil == nil || !frame.ResumeUntil.IsValid() {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("backend does not support terminal transport resumption"))
	}
	until := frame.ResumeUntil.AsTime()
	if !until.After(time.Now()) {
		return errors.New("terminal authorization/transport lease expired")
	}
	until = minTime(until, time.Now().Add(30*time.Second))
	r.mu.Lock()
	defer r.mu.Unlock()
	if frame.AcceptedEventSequence < r.acked || frame.AcceptedEventSequence > r.highest {
		return connect.NewError(connect.CodeFailedPrecondition, errors.New("backend terminal replay state was lost"))
	}
	r.acked = frame.AcceptedEventSequence
	kept := r.events[:0]
	for _, event := range r.events {
		if event.Sequence > r.acked {
			kept = append(kept, event)
		}
	}
	clear(r.events[len(kept):])
	r.events = kept
	r.deadline.Reset(time.Until(until))
	r.signalLocked()
	return nil
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}

func (r *resumableTerminal) sendLoop(ctx context.Context, stream terminalConnection) error {
	var sent, sentCommand uint64
	r.mu.Lock()
	sent = r.acked
	r.mu.Unlock()
	for {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		r.mu.Lock()
		var event *websshv1.AgentSessionEvent
		if r.command > sentCommand {
			event = &websshv1.AgentSessionEvent{AcceptedCommandSequence: r.command}
		}
		if event == nil {
			for _, candidate := range r.events {
				if candidate.Sequence > sent {
					event = proto.Clone(candidate).(*websshv1.AgentSessionEvent)
					event.AcceptedCommandSequence = r.command
					break
				}
			}
		}
		signal := r.notify
		r.mu.Unlock()
		if event == nil {
			select {
			case <-ctx.Done():
				return ctx.Err()
			case <-signal:
			}
			continue
		}
		if err := stream.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Event{Event: event}}); err != nil {
			return err
		}
		sentCommand = event.AcceptedCommandSequence
		if event.Sequence > 0 {
			sent = event.Sequence
		}
	}
}

func terminalRetryable(err error) bool {
	switch connect.CodeOf(err) {
	case connect.CodeUnavailable, connect.CodeDeadlineExceeded, connect.CodeCanceled:
		return true
	case connect.CodePermissionDenied, connect.CodeUnauthenticated, connect.CodeNotFound, connect.CodeFailedPrecondition, connect.CodeInvalidArgument, connect.CodeResourceExhausted:
		return false
	}
	// Connect wraps an abruptly truncated stream in CodeInternal, retaining the
	// underlying io.ErrUnexpectedEOF. Only local transport failures qualify;
	// an explicit server error must not become retryable because of its text.
	if connect.IsWireError(err) {
		return false
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) || errors.Is(err, io.ErrClosedPipe) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var networkError net.Error
	return errors.As(err, &networkError)
}

func (r *resumableTerminal) run() {
	defer close(r.done)
	defer r.deadline.Stop()
	var attempts uint64
	for r.ctx.Err() == nil {
		attempts++
		attempt, cancel := context.WithCancel(r.ctx)
		// Bound dialing/first Send as well as Receive. Once attached, a silent
		// half-open stream must be retried before the original retention lease
		// expires. This timer cancels only this HTTP request, never the PTY.
		activityTimer := time.AfterFunc(terminalHandshakeTimeout, cancel)
		r.mu.Lock()
		command := r.command
		r.mu.Unlock()
		stream, err := r.open(attempt, command)
		var senderDone chan error
		if err == nil {
			// Do not send/replay until the authenticated server validates the same
			// session and returns its existing event cursor and authorization bound.
			var first *websshv1.AttachSessionResponse
			first, err = stream.Receive()
			if err == nil {
				err = r.checkpoint(first)
			}
			if err == nil {
				activityTimer.Reset(terminalCheckpointTimeout)
				log.Printf("WebSSH session=%s stage=transport-attached attempt=%d after_event=%d after_command=%d", r.sessionID, attempts, first.AcceptedEventSequence, command)
				senderDone = make(chan error, 1)
				go func() { e := r.sendLoop(attempt, stream); senderDone <- e; cancel() }()
				for err == nil {
					var frame *websshv1.AttachSessionResponse
					frame, err = stream.Receive()
					if err != nil {
						break
					}
					if err = r.checkpoint(frame); err != nil {
						break
					}
					activityTimer.Reset(terminalCheckpointTimeout)
					if frame.Command != nil {
						select {
						case r.commands <- frame:
						case <-attempt.Done():
							err = attempt.Err()
						}
					}
				}
			}
		}
		activityTimer.Stop()
		cancel()
		if stream != nil {
			_ = stream.CloseRequest()
			_ = stream.CloseResponse()
		}
		if senderDone != nil {
			sendError := <-senderDone
			if err == nil {
				err = sendError
			}
		}
		if r.ctx.Err() != nil {
			return
		}
		retry := terminalRetryable(err)
		log.Printf("WebSSH session=%s stage=transport-interrupted attempt=%d code=%s retry=%t error=%q", r.sessionID, attempts, connect.CodeOf(err), retry, err)
		if !retry {
			r.fail(err)
			return
		}
		timer := time.NewTimer(300 * time.Millisecond)
		select {
		case <-r.ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
