//go:build !windows

package clientcore

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/creack/pty"
	websshv1 "github.com/r11234567/komari-proto/gen/go/komari/webssh/v1"
	"github.com/r11234567/komari-proto/gen/go/komari/webssh/v1/websshv1connect"
	"google.golang.org/protobuf/types/known/timestamppb"
)

type resumeHTTP2Peer struct {
	websshv1connect.UnimplementedWebSSHServiceHandler
	accepted atomic.Uint64
	opened   chan chan *websshv1.AttachSessionResponse
	output   chan []byte
	reject   error
}

func (p *resumeHTTP2Peer) AttachSession(ctx context.Context, stream *connect.BidiStream[websshv1.AttachSessionRequest, websshv1.AttachSessionResponse]) error {
	first, err := stream.Receive()
	if err != nil || first.GetAttach() == nil {
		return err
	}
	if p.reject != nil {
		return p.reject
	}
	checkpoint := func() *websshv1.AttachSessionResponse {
		return &websshv1.AttachSessionResponse{AcceptedEventSequence: p.accepted.Load(), ResumeUntil: timestamppb.New(time.Now().Add(5 * time.Second))}
	}
	if err := stream.Send(checkpoint()); err != nil {
		return err
	}
	commands := make(chan *websshv1.AttachSessionResponse, 4)
	select {
	case p.opened <- commands:
	case <-ctx.Done():
		return ctx.Err()
	}
	received := make(chan *websshv1.AgentSessionEvent)
	errors := make(chan error, 1)
	go func() {
		for {
			request, err := stream.Receive()
			if err != nil {
				errors <- err
				return
			}
			select {
			case received <- request.GetEvent():
			case <-ctx.Done():
				return
			}
		}
	}()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errors:
			return err
		case command := <-commands:
			frame := checkpoint()
			frame.Sequence, frame.Command = command.Sequence, command.Command
			if err := stream.Send(frame); err != nil {
				return err
			}
		case event := <-received:
			if event.Sequence > p.accepted.Load() {
				p.accepted.Store(event.Sequence)
				select {
				case p.output <- append([]byte(nil), event.GetOutput()...):
				case <-ctx.Done():
					return ctx.Err()
				}
			}
			if err := stream.Send(checkpoint()); err != nil {
				return err
			}
		}
	}
}

func TestTerminalResumeStopsAtAuthoritativeHTTP2Rejection(t *testing.T) {
	for _, code := range []connect.Code{connect.CodePermissionDenied, connect.CodeUnauthenticated, connect.CodeNotFound, connect.CodeFailedPrecondition, connect.CodeInternal} {
		t.Run(code.String(), func(t *testing.T) {
			// A server-sent error containing this text is not a local broken socket.
			peer := &resumeHTTP2Peer{reject: connect.NewError(code, io.ErrUnexpectedEOF)}
			path, handler := websshv1connect.NewWebSSHServiceHandler(peer)
			mux := http.NewServeMux()
			mux.Handle(path, handler)
			server := httptest.NewUnstartedServer(mux)
			server.EnableHTTP2 = true
			server.StartTLS()
			defer server.Close()
			client := websshv1connect.NewWebSSHServiceClient(server.Client(), server.URL)
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			var attempts atomic.Uint32
			stream := newResumableTerminal(ctx, cancel, time.Now().Add(time.Second), "rejected", func(attempt context.Context, after uint64) (terminalConnection, error) {
				attempts.Add(1)
				connection := client.AttachSession(attempt)
				err := connection.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Attach{Attach: &websshv1.AgentSessionAttach{SessionId: "original", Resumable: true}}})
				return connection, err
			})
			defer stream.close()
			<-ctx.Done()
			if attempts.Load() != 1 || connect.CodeOf(stream.failure()) != code || !connect.IsWireError(stream.failure()) {
				t.Fatalf("server rejection was lost or retried: attempts=%d failure=%v", attempts.Load(), stream.failure())
			}
		})
	}
}

type observedTerminalConnection struct {
	terminalConnection
	errors chan error
}

func (c *observedTerminalConnection) Receive() (*websshv1.AttachSessionResponse, error) {
	frame, err := c.terminalConnection.Receive()
	if err != nil {
		select {
		case c.errors <- err:
		default:
		}
	}
	return frame, err
}

func TestActualPTYResumesAfterHTTP2ConnectionIsSevered(t *testing.T) {
	dir := t.TempDir()
	cmd := exec.Command("/bin/sh", "-i")
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + dir, "TERM=xterm-256color"}
	file, err := pty.Start(cmd)
	if err != nil {
		t.Fatal(err)
	}
	terminal := &retainedTestPTY{file: file, cmd: cmd}
	defer terminal.Close()
	peer := &resumeHTTP2Peer{opened: make(chan chan *websshv1.AttachSessionResponse, 4), output: make(chan []byte, 128)}
	path, handler := websshv1connect.NewWebSSHServiceHandler(peer)
	mux := http.NewServeMux()
	mux.Handle(path, handler)
	server := httptest.NewUnstartedServer(mux)
	server.EnableHTTP2 = true
	server.StartTLS()
	defer server.Close()
	client := websshv1connect.NewWebSSHServiceClient(server.Client(), server.URL)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	transportErrors := make(chan error, 16)
	stream := newResumableTerminal(ctx, cancel, time.Now().Add(5*time.Second), "same-shell", func(attempt context.Context, after uint64) (terminalConnection, error) {
		connection := client.AttachSession(attempt)
		err := connection.Send(&websshv1.AttachSessionRequest{Message: &websshv1.AttachSessionRequest_Attach{Attach: &websshv1.AgentSessionAttach{AgentId: "test-agent", AssignmentId: "same-assignment", SessionId: "same-shell", AfterCommandSequence: after, Resumable: true}}})
		return &observedTerminalConnection{terminalConnection: connection, errors: transportErrors}, err
	})
	defer stream.close()
	done := make(chan error, 1)
	go func() {
		done <- runRemoteTerminal(ctx, cancel, stream, terminal, "same-shell", time.Now(), func() (bool, string) { return true, "" })
	}()
	awaitConnection := func() chan *websshv1.AttachSessionResponse {
		t.Helper()
		select {
		case commands := <-peer.opened:
			return commands
		case err := <-done:
			t.Fatalf("original PTY ended before transport recovery: %v", err)
		case <-time.After(3 * time.Second):
			for len(transportErrors) > 0 {
				err := <-transportErrors
				t.Logf("wire failure: code=%s EOF=%t unexpectedEOF=%t error=%v", connect.CodeOf(err), err == io.EOF, strings.Contains(err.Error(), "unexpected EOF"), err)
			}
			t.Fatal("real HTTP/2 transport did not reattach")
		}
		return nil
	}
	consume := func(marker string) string {
		t.Helper()
		var output strings.Builder
		pattern := regexp.MustCompile(marker + `:[0-9]+:` + regexp.QuoteMeta(dir))
		for {
			select {
			case bytes := <-peer.output:
				output.Write(bytes)
				if value := pattern.FindString(output.String()); value != "" {
					return value
				}
			case <-ctx.Done():
				t.Fatalf("missing %s in real-wire PTY output", marker)
				return ""
			}
		}
	}
	first := awaitConnection()
	first <- &websshv1.AttachSessionResponse{Sequence: 1, Command: &websshv1.AttachSessionResponse_Input{Input: []byte(fmt.Sprintf("cd '%s'; printf 'BEFORE:%%s:%%s\\n' \"$$\" \"$PWD\"\n", dir))}}
	before := consume("BEFORE")
	server.CloseClientConnections()
	second := awaitConnection()
	second <- &websshv1.AttachSessionResponse{Sequence: 2, Command: &websshv1.AttachSessionResponse_Input{Input: []byte("printf 'AFTER:%s:%s\\n' \"$$\" \"$PWD\"\n")}}
	after := consume("AFTER")
	if strings.TrimPrefix(before, "BEFORE:") != strings.TrimPrefix(after, "AFTER:") {
		t.Fatalf("HTTP/2 reconnection replaced original shell: %s -> %s", before, after)
	}
	for len(transportErrors) > 0 {
		t.Logf("observed real HTTP/2 interruption: %v", <-transportErrors)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("real-wire PTY cleanup stuck")
	}
}
