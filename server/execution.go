package server

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"sync"

	"github.com/komari-monitor/komari-agent/core/capability"
	"github.com/komari-monitor/komari-agent/core/runtimeconfig"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
)

var ErrExecutionOutputLimit = errors.New("execution output limit exceeded")

type ExecutionOutput struct {
	Stream execv1.OutputStream
	Data   []byte
}

func RunTypedExecution(ctx context.Context, spec *execv1.ExecutionSpec, emit func(ExecutionOutput) error) (int, error) {
	if allowed, reason := capability.RemoteControlAllowed(runtimeconfig.RemoteControlEnabled()); !allowed {
		return -1, fmt.Errorf("remote control is unavailable: %s", reason)
	}
	if spec == nil || strings.TrimSpace(spec.Command) == "" {
		return -1, errors.New("execution command is required")
	}
	if emit == nil {
		return -1, errors.New("execution output handler is required")
	}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	command, cleanup, err := buildTypedCommand(processCtx, spec)
	if err != nil {
		return -1, err
	}
	defer cleanup()
	if spec.WorkingDirectory != "" {
		command.Dir = spec.WorkingDirectory
	}
	if len(spec.Environment) > 0 {
		command.Env = append([]string{}, os.Environ()...)
		for key, value := range spec.Environment {
			if strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
				return -1, errors.New("execution environment contains an invalid entry")
			}
			command.Env = append(command.Env, key+"="+value)
		}
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return -1, err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return -1, err
	}
	if err := command.Start(); err != nil {
		return -1, err
	}
	output := make(chan ExecutionOutput, 32)
	readerError := make(chan error, 2)
	var readers sync.WaitGroup
	readers.Add(2)
	go readExecutionOutput(stdout, execv1.OutputStream_OUTPUT_STREAM_STDOUT, output, readerError, &readers)
	go readExecutionOutput(stderr, execv1.OutputStream_OUTPUT_STREAM_STDERR, output, readerError, &readers)
	wait := make(chan error, 1)
	go func() {
		err := command.Wait()
		readers.Wait()
		close(output)
		wait <- err
	}()
	var outputBytes uint64
	var outputErr error
	for chunk := range output {
		if outputErr != nil {
			continue
		}
		if uint64(len(chunk.Data))+outputBytes > spec.MaxOutputBytes {
			outputErr = ErrExecutionOutputLimit
			cancel()
			continue
		}
		outputBytes += uint64(len(chunk.Data))
		if err := emit(chunk); err != nil {
			outputErr = err
			cancel()
		}
	}
	waitErr := <-wait
	select {
	case err := <-readerError:
		if outputErr == nil && !errors.Is(err, os.ErrClosed) {
			outputErr = err
		}
	default:
	}
	if outputErr != nil {
		return exitCode(waitErr), outputErr
	}
	if ctx.Err() != nil {
		return exitCode(waitErr), ctx.Err()
	}
	return exitCode(waitErr), waitErr
}

func readExecutionOutput(reader io.Reader, stream execv1.OutputStream, output chan<- ExecutionOutput, failures chan<- error, wait *sync.WaitGroup) {
	defer wait.Done()
	buffer := make([]byte, 32<<10)
	for {
		n, err := reader.Read(buffer)
		if n > 0 {
			output <- ExecutionOutput{Stream: stream, Data: append([]byte(nil), buffer[:n]...)}
		}
		if err != nil {
			if !errors.Is(err, io.EOF) {
				select {
				case failures <- err:
				default:
				}
			}
			return
		}
	}
}

func buildTypedCommand(ctx context.Context, spec *execv1.ExecutionSpec) (*exec.Cmd, func(), error) {
	if len(spec.Arguments) > 0 {
		return exec.CommandContext(ctx, spec.Command, spec.Arguments...), func() {}, nil
	}
	if runtime.GOOS != "windows" {
		command := exec.CommandContext(ctx, "sh", "-s")
		command.Stdin = strings.NewReader(spec.Command)
		return command, func() {}, nil
	}
	file, err := os.CreateTemp("", "komari-connect-exec-*.ps1")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	if _, err := file.Write([]byte{0xEF, 0xBB, 0xBF}); err == nil {
		_, err = file.WriteString("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n" + spec.Command)
	}
	closeErr := file.Close()
	if err != nil {
		cleanup()
		return nil, func() {}, err
	}
	if closeErr != nil {
		cleanup()
		return nil, func() {}, closeErr
	}
	return exec.CommandContext(ctx, "powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-File", file.Name()), cleanup, nil
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitError *exec.ExitError
	if errors.As(err, &exitError) {
		return exitError.ExitCode()
	}
	return -1
}
