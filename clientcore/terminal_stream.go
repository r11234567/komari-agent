package clientcore

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"sync/atomic"
	"time"

	"github.com/komari-monitor/komari-agent/terminal"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type remoteTerminalStream interface {
	Send(*websshv1.AttachSessionRequest) error
	Receive() (*websshv1.AttachSessionResponse, error)
}

// The caller creates the stream with sessionCtx. Cancelling it must interrupt
// both transport directions, including a sender blocked by a slow receiver.
func runRemoteTerminal(sessionCtx context.Context, cancel context.CancelFunc, stream remoteTerminalStream, pty terminal.Terminal, sessionID string, startupAt time.Time, allowed func() (bool, string)) error {
	var workers sync.WaitGroup
	stopClose := context.AfterFunc(sessionCtx, func() { _ = pty.Close() })
	defer func() {
		cancel()
		_ = pty.Close()
		workers.Wait()
		stopClose()
	}()
	type outbound struct {
		event *websshv1.AgentSessionEvent
	}
	outboundEvents := make(chan outbound, 32)
	// Command acknowledgments must not block PTY input/resize behind a full
	// output queue. Coalesce them; the sender always reads the latest cursor.
	acknowledge := make(chan struct{}, 1)
	sendErr := make(chan error, 1)
	var accepted atomic.Uint64
	workers.Add(1)
	go func() {
		defer workers.Done()
		var sequence uint64
		for {
			var message outbound
			select {
			case <-sessionCtx.Done():
				return
			default:
			}
			select {
			case <-acknowledge:
				message.event = &websshv1.AgentSessionEvent{}
			default:
				select {
				case message = <-outboundEvents:
				case <-acknowledge:
					message.event = &websshv1.AgentSessionEvent{}
				case <-sessionCtx.Done():
					return
				}
			}
			message.event.AcceptedCommandSequence = accepted.Load()
			if message.event.Event != nil {
				sequence++
				message.event.Sequence = sequence
				message.event.OccurredAt = timestamppb.Now()
			}
			if err := stream.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Event{Event: message.event}}); err != nil {
				sendErr <- err
				cancel() // also interrupt a quiet Receive and release the PTY
				return
			}
		}
	}()
	readDone := make(chan struct{})
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer close(readDone)
		buffer := make([]byte, 32<<10)
		firstOutput := true
		for {
			n, err := pty.Read(buffer)
			if n > 0 {
				if firstOutput {
					log.Printf("WebSSH session=%s stage=first-output elapsed=%s", sessionID, time.Since(startupAt).Round(time.Millisecond))
					firstOutput = false
				}
				data := append([]byte(nil), buffer[:n]...)
				select {
				case outboundEvents <- outbound{event: &websshv1.AgentSessionEvent{Event: &websshv1.AgentSessionEvent_Output{Output: data}}}:
				case <-sessionCtx.Done():
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	workers.Add(1)
	go func() {
		defer workers.Done()
		err := pty.Wait()
		// Wait may complete while the final PTY bytes are still being read.
		// Keep the close event after all successfully queued output.
		select {
		case <-readDone:
		case <-sessionCtx.Done():
			return
		}
		reason := websshv1.CloseReason_CLOSE_REASON_NORMAL
		var exitCode *int32
		if err != nil {
			reason = websshv1.CloseReason_CLOSE_REASON_FAILED
			code := int32(-1)
			exitCode = &code
		}
		closed := &websshv1.AgentSessionEvent{Event: &websshv1.AgentSessionEvent_Closed{Closed: &websshv1.SessionClosed{
			SessionId: sessionID, Reason: reason, ExitCode: exitCode, ClosedAt: timestamppb.Now(),
		}}}
		select {
		case outboundEvents <- outbound{event: closed}:
		case <-sessionCtx.Done():
		}
	}()
	for {
		response, err := stream.Receive()
		if err != nil {
			select {
			case sendError := <-sendErr:
				return sendError
			default:
			}
			return err
		}
		if err := sessionCtx.Err(); err != nil {
			return err
		}
		if ok, reason := allowed(); !ok {
			return fmt.Errorf("WebSSH authorization withdrawn: %s", reason)
		}
		switch command := response.Command.(type) {
		case *websshv1.AttachSessionResponse_Input:
			_, err = pty.Write(command.Input)
		case *websshv1.AttachSessionResponse_Resize:
			if command.Resize != nil {
				err = pty.Resize(int(command.Resize.Columns), int(command.Resize.Rows))
			}
		case *websshv1.AttachSessionResponse_File:
			err = errors.New("terminal file commands are disabled; use the account-isolated FileService")
		case *websshv1.AttachSessionResponse_CloseReason:
			return nil
		default:
			err = errors.New("empty remote session command")
		}
		if err != nil {
			return err
		}
		accepted.Store(response.Sequence)
		select {
		case acknowledge <- struct{}{}:
		default:
		}
	}
}
