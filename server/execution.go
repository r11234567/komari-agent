package server

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"

	"github.com/komari-monitor/komari-agent/core/capability"
	execv1 "github.com/r11234567/komari-proto/gen/go/komari/exec/v1"
)

var ErrExecutionOutputLimit = errors.New("execution output limit exceeded")

type ExecutionOutput struct {
	Stream execv1.OutputStream
	Data   []byte
}

func RunTypedExecution(ctx context.Context, spec *execv1.ExecutionSpec, emit func(ExecutionOutput) error) (int, error) {
	if spec == nil || strings.TrimSpace(spec.Command) == "" {
		return -1, errors.New("execution command is required")
	}
	allowed := func() (bool, string) {
		if ok, reason := capability.ExecutionAllowed(); !ok {
			return false, reason
		}
		if spec.RunAsRoot {
			return capability.RootExecutionAllowed()
		}
		return true, ""
	}
	if ok, reason := allowed(); !ok {
		return -1, fmt.Errorf("execution is unavailable: %s", reason)
	}
	if emit == nil {
		return -1, errors.New("execution output handler is required")
	}
	processCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	go capability.CancelOnRevocation(processCtx, cancel, allowed)
	command, cleanup, err := buildTypedCommand(processCtx, spec)
	if err != nil {
		return -1, err
	}
	defer cleanup()
	if err := configureExecutionIdentity(command, spec); err != nil {
		return -1, err
	}
	if len(spec.Environment) > 0 {
		for key, value := range spec.Environment {
			if strings.ContainsAny(key, "=\x00") || strings.ContainsRune(value, '\x00') {
				return -1, errors.New("execution environment contains an invalid entry")
			}
			command.Env = append(command.Env, key+"="+value)
		}
	}
	output := make(chan ExecutionOutput, 32)
	command.Stdout = executionWriter{stream: execv1.OutputStream_OUTPUT_STREAM_STDOUT, output: output}
	command.Stderr = executionWriter{stream: execv1.OutputStream_OUTPUT_STREAM_STDERR, output: output}
	command.WaitDelay = 2 * time.Second
	if err := command.Start(); err != nil {
		return -1, err
	}
	wait := make(chan error, 1)
	go func() {
		wait <- command.Wait()
		close(output)
	}()
	maxOutput := spec.MaxOutputBytes
	if maxOutput == 0 {
		maxOutput = 1 << 20
	}
	var outputBytes uint64
	var outputErr error
	for chunk := range output {
		if outputErr != nil {
			continue
		}
		if uint64(len(chunk.Data))+outputBytes > maxOutput {
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
	if outputErr != nil {
		return exitCode(waitErr), outputErr
	}
	if ctx.Err() != nil {
		return exitCode(waitErr), ctx.Err()
	}
	return exitCode(waitErr), waitErr
}

type executionWriter struct {
	stream execv1.OutputStream
	output chan<- ExecutionOutput
}

func (w executionWriter) Write(data []byte) (int, error) {
	w.output <- ExecutionOutput{Stream: w.stream, Data: append([]byte(nil), data...)}
	return len(data), nil
}

func buildTypedCommand(ctx context.Context, spec *execv1.ExecutionSpec) (*exec.Cmd, func(), error) {
	if len(spec.Arguments) > 0 {
		return exec.CommandContext(ctx, spec.Command, spec.Arguments...), func() {}, nil
	}
	if runtime.GOOS != "windows" {
		command := exec.CommandContext(ctx, "/bin/sh", "-s")
		command.Stdin = strings.NewReader(spec.Command)
		return command, func() {}, nil
	}
	file, err := os.CreateTemp("", "komari-connect-exec-*.ps1")
	if err != nil {
		return nil, func() {}, err
	}
	cleanup := func() { _ = os.Remove(file.Name()) }
	_, writeErr := file.Write([]byte{0xEF, 0xBB, 0xBF})
	if writeErr == nil {
		_, writeErr = file.WriteString("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n" + spec.Command)
	}
	closeErr := file.Close()
	if writeErr != nil {
		cleanup()
		return nil, func() {}, writeErr
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
