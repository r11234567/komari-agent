//go:build linux

package hostcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

func systemctl(args ...string) (string, error) {
	const bin = "/usr/bin/systemctl"
	if err := hostops.TrustedPath(bin); err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	c := exec.CommandContext(ctx, bin, args...)
	var out limitedBuffer
	c.Stdout = &out
	c.Stderr = &out
	if err := c.Run(); err != nil {
		return "", fmt.Errorf("systemctl %s failed: %w: %s", args[0], err, strings.TrimSpace(out.String()))
	}
	if out.exceeded {
		return "", errors.New("systemctl output exceeds limit")
	}
	return out.String(), nil
}

// Each call is an explicit authenticated transaction/recovery action, not an
// automatic restart loop. A broken target can exhaust systemd's start counter;
// restoring the reviewed original profile must not remain blocked by that
// counter. Normal Restart= policy and its rate limits remain configured.
func restartReviewedService(service string) error {
	if _, err := systemctl("reset-failed", service); err != nil {
		return err
	}
	_, err := systemctl("restart", service)
	return err
}

type limitedBuffer struct {
	bytes.Buffer
	exceeded bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	n := len(p)
	if b.Len()+n > 1<<20 {
		b.exceeded = true
		return n, nil
	}
	return b.Buffer.Write(p)
}

type serviceObservation struct{ User, WorkingDirectory, FragmentPath, DropInPaths, MainPID, ExecStart string }

func observe(service string) (serviceObservation, error) {
	var o serviceObservation
	if !hostops.ValidService(service) {
		return o, errors.New("invalid service ID")
	}
	value, err := systemctl("show", service, "--property=User,WorkingDirectory,FragmentPath,DropInPaths,MainPID,ExecStart")
	if err != nil {
		return o, err
	}
	for _, line := range strings.Split(value, "\n") {
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		switch k {
		case "User":
			o.User = v
		case "WorkingDirectory":
			o.WorkingDirectory = v
		case "FragmentPath":
			o.FragmentPath = v
		case "DropInPaths":
			o.DropInPaths = v
		case "MainPID":
			o.MainPID = v
		case "ExecStart":
			o.ExecStart = v
		}
	}
	if o.FragmentPath == "" || o.ExecStart == "" {
		return o, errors.New("service not found or has no executable")
	}
	return o, nil
}

// Parse systemctl's argv serialization, never execute it as shell. Ambiguous
// separators, command prefixes, environment expansion and multiple commands fail.
func parseExecStart(value string) ([]string, error) {
	if strings.Count(value, "{ path=") != 1 {
		return nil, errors.New("migration requires one simple ExecStart command")
	}
	_, tail, ok := strings.Cut(value, " ; argv[]=")
	if !ok {
		return nil, errors.New("unsupported ExecStart serialization")
	}
	argv, _, ok := strings.Cut(tail, " ; ignore_errors=")
	if !ok || strings.Contains(argv, " ; ") {
		return nil, errors.New("ambiguous ExecStart argv")
	}
	args, err := splitWords(argv)
	if err != nil {
		return nil, err
	}
	if len(args) == 0 || !strings.HasPrefix(args[0], "/") {
		return nil, errors.New("ExecStart must use an absolute executable")
	}
	return args, nil
}
func splitWords(value string) ([]string, error) {
	var args []string
	var token strings.Builder
	var quote byte
	started := false
	for i := 0; i < len(value); i++ {
		c := value[i]
		if c == '\\' {
			if i+1 >= len(value) {
				return nil, errors.New("truncated escape")
			}
			i++
			c = value[i]
			if c == 'x' {
				if i+2 >= len(value) {
					return nil, errors.New("invalid hex escape")
				}
				n, e := strconv.ParseUint(value[i+1:i+3], 16, 8)
				if e != nil || n == 0 {
					return nil, errors.New("invalid escaped byte")
				}
				token.WriteByte(byte(n))
				i += 2
			} else if strings.ContainsRune("\\\"' ", rune(c)) {
				token.WriteByte(c)
			} else {
				return nil, errors.New("unsupported escape in service argv")
			}
			started = true
			continue
		}
		if c == '"' || c == '\'' {
			if quote == 0 {
				quote = c
				started = true
				continue
			}
			if quote == c {
				quote = 0
				continue
			}
		}
		if quote == 0 && (c == ' ' || c == '\t') {
			if started {
				args = append(args, token.String())
				token.Reset()
				started = false
			}
			continue
		}
		if c == '\n' || c == 0 {
			return nil, errors.New("invalid control byte in service argv")
		}
		token.WriteByte(c)
		started = true
	}
	if quote != 0 {
		return nil, errors.New("unclosed quote in service argv")
	}
	if started {
		args = append(args, token.String())
	}
	return args, nil
}
func unitQuote(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "%", "%%")
	s = strings.ReplaceAll(s, "$", "$$")
	return "\"" + s + "\""
}
