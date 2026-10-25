package files

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"sync"
	"time"

	"github.com/komari-monitor/komari-agent/core/osidentity"
	filev1 "github.com/r11234567/komari-proto/gen/go/komari/file/v1"
)

const WorkerArgument = "--workspace-file-worker"

type workerRequest struct {
	ID        string
	Operation filev1.FileOperation
	Args      map[string]any
}
type workerResponse struct {
	ID    string
	Event *filev1.AgentFileEvent
}

// ServeWorker runs only after exec has applied the target credentials. Keeping
// one worker per grant preserves upload state without sharing it across users.
func ServeWorker(input io.Reader, output io.Writer) error {
	decoder, encoder := json.NewDecoder(input), json.NewEncoder(output)
	var outputMu sync.Mutex
	var tasks sync.WaitGroup
	slots := make(chan struct{}, 4)
	for {
		var request workerRequest
		if err := decoder.Decode(&request); err != nil {
			if errors.Is(err, io.EOF) {
				tasks.Wait()
				return nil
			}
			return err
		}
		slots <- struct{}{}
		tasks.Add(1)
		go func(request workerRequest) {
			defer tasks.Done()
			defer func() { <-slots }()
			event := Execute(request.Operation, request.Args)
			outputMu.Lock()
			defer outputMu.Unlock()
			_ = encoder.Encode(workerResponse{ID: request.ID, Event: event})
		}(request)
	}
}

type Executor struct {
	ctx               context.Context
	mu                sync.Mutex
	workers           map[string]*fileWorker
	authorizeTransfer func(http.Header)
}

type ExecutorOptions struct {
	// Evaluated in the parent for each transfer, after token refreshes. The
	// callback and its credentials are never sent to account workers.
	AuthorizeTransfer func(http.Header)
}
type fileWorker struct {
	username string
	cmd      *exec.Cmd
	input    io.WriteCloser
	encoder  *json.Encoder
	writeMu  sync.Mutex
	mu       sync.Mutex
	pending  map[string]chan *filev1.AgentFileEvent
	lastUsed time.Time
	closed   bool
	done     chan struct{}
}

func NewExecutor(ctx context.Context, options ...ExecutorOptions) *Executor {
	e := &Executor{ctx: ctx, workers: make(map[string]*fileWorker)}
	if len(options) > 0 {
		e.authorizeTransfer = options[0].AuthorizeTransfer
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				e.Close()
				return
			case <-ticker.C:
				e.mu.Lock()
				for scope, w := range e.workers {
					w.mu.Lock()
					idle := len(w.pending) == 0 && time.Since(w.lastUsed) >= 3*time.Minute
					closed := w.closed
					w.mu.Unlock()
					if idle || closed {
						w.stop()
						delete(e.workers, scope)
					}
				}
				e.mu.Unlock()
			}
		}
	}()
	return e
}

func (e *Executor) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	for key, w := range e.workers {
		w.stop()
		delete(e.workers, key)
	}
}

func (e *Executor) Execute(ctx context.Context, scope, username, requestID string, operation filev1.FileOperation, args map[string]any) *filev1.AgentFileEvent {
	failure := func(err error) *filev1.AgentFileEvent {
		return &filev1.AgentFileEvent{Operation: operation, Error: err.Error()}
	}
	if err := ctx.Err(); err != nil {
		return failure(err)
	}
	if scope == "" || requestID == "" {
		return failure(errors.New("a scoped workspace assignment is required"))
	}
	// Never accept a relay override from remote metadata, and never mutate a
	// caller's map while sibling operations may still be using it.
	workerArgs := make(map[string]any, len(args)+1)
	for key, value := range args {
		if key != workerTransferURL {
			workerArgs[key] = value
		}
	}
	name := operationName(operation)
	if override := argString(workerArgs, "_op"); override != "" {
		name = override
	}
	if name == "upload_stream" || name == "download_stream" {
		endpoint, closeRelay, err := newWorkerTransferRelay(ctx, workerArgs, e.authorizeTransfer)
		if err != nil {
			return failure(err)
		}
		defer closeRelay()
		workerArgs[workerTransferURL] = endpoint
	}
	e.mu.Lock()
	w := e.workers[scope]
	if w != nil {
		w.mu.Lock()
		closed := w.closed
		w.mu.Unlock()
		if closed {
			delete(e.workers, scope)
			w = nil
		}
	}
	if w == nil {
		var err error
		w, err = startFileWorker(e.ctx, username)
		if err != nil {
			e.mu.Unlock()
			return failure(err)
		}
		e.workers[scope] = w
	}
	e.mu.Unlock()
	if w.username != username {
		return failure(errors.New("workspace OS account cannot change"))
	}
	response := make(chan *filev1.AgentFileEvent, 1)
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return failure(errors.New("file worker is closed"))
	}
	if _, exists := w.pending[requestID]; exists {
		w.mu.Unlock()
		return failure(errors.New("duplicate worker request"))
	}
	w.pending[requestID] = response
	w.lastUsed = time.Now()
	w.mu.Unlock()
	defer func() { w.mu.Lock(); delete(w.pending, requestID); w.lastUsed = time.Now(); w.mu.Unlock() }()
	w.writeMu.Lock()
	err := w.encoder.Encode(workerRequest{ID: requestID, Operation: operation, Args: workerArgs})
	w.writeMu.Unlock()
	if err != nil {
		w.stop()
		return failure(fmt.Errorf("send file worker request: %w", err))
	}
	select {
	case event := <-response:
		return event
	case <-ctx.Done():
		w.stop()
		return failure(ctx.Err())
	case <-w.done:
		return failure(errors.New("OS account file worker exited or was cancelled"))
	}
}

func startFileWorker(ctx context.Context, username string) (*fileWorker, error) {
	identity, err := osidentity.Resolve(username)
	if err != nil {
		return nil, err
	}
	executable, err := os.Executable()
	if err != nil {
		return nil, err
	}
	cmd := exec.CommandContext(ctx, executable, WorkerArgument)
	if err := identity.Configure(cmd, ""); err != nil {
		return nil, err
	}
	// Never inherit Agent environment/secrets, nor put transfer tokens in argv.
	input, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	output, err := cmd.StdoutPipe()
	if err != nil {
		input.Close()
		return nil, err
	}
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		input.Close()
		output.Close()
		return nil, err
	}
	w := &fileWorker{username: username, cmd: cmd, input: input, encoder: json.NewEncoder(input), pending: make(map[string]chan *filev1.AgentFileEvent), lastUsed: time.Now(), done: make(chan struct{})}
	go func() {
		decoder := json.NewDecoder(output)
		for {
			var response workerResponse
			if err := decoder.Decode(&response); err != nil {
				break
			}
			if response.Event == nil {
				break
			}
			w.mu.Lock()
			ch := w.pending[response.ID]
			w.mu.Unlock()
			if ch != nil {
				select {
				case ch <- response.Event:
				default:
				}
			}
		}
		w.stop()
		_ = cmd.Wait()
	}()
	return w, nil
}

func (w *fileWorker) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	close(w.done)
	_ = w.input.Close()
	if w.cmd.Process != nil {
		_ = w.cmd.Process.Kill()
	}
}
