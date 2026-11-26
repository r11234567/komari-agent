package trafficwatch

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const flowPrefix = "nfcapd."

type nfdumpSampler struct {
	ctx       context.Context
	dir       string
	dump      string
	local     map[netip.Addr]bool
	lastStart time.Time
}

func (*nfdumpSampler) Name() string { return "nfpcapd" }

func startNFDump(ctx context.Context, cfg Config, dir string) (*nfdumpSampler, <-chan error, error) {
	dump, err := exec.LookPath("nfdump")
	if err != nil {
		return nil, nil, err
	}
	capture := exec.CommandContext(ctx, "nfpcapd",
		"-i", cfg.Interface, "-w", dir,
		"-t", "30", "-e", "30,15", "-B", "16384",
		"-C", filepath.Join(dir, "empty.conf"), "ip or ip6")
	capture.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	capture.Stdout, capture.Stderr = os.Stderr, os.Stderr
	capture.Cancel = func() error { return capture.Process.Signal(unix.SIGTERM) }
	capture.WaitDelay = 3 * time.Second
	if err = capture.Start(); err != nil {
		return nil, nil, err
	}
	done := make(chan error, 1)
	go func() { done <- capture.Wait() }()
	local := make(map[netip.Addr]bool, len(cfg.LocalAddresses))
	for _, addr := range cfg.LocalAddresses {
		local[addr.Unmap()] = true
	}
	return &nfdumpSampler{ctx: ctx, dir: dir, dump: dump, local: local}, done, nil
}

func (s *nfdumpSampler) Next() ([]sample, error) {
	files, err := os.ReadDir(s.dir)
	if err != nil {
		return nil, err
	}
	var result []sample
	var failures []error
	for _, file := range files {
		if !file.Type().IsRegular() || !strings.HasPrefix(file.Name(), flowPrefix) {
			continue
		}
		start, err := time.Parse("20060102150405", strings.TrimPrefix(file.Name(), flowPrefix))
		if err != nil {
			continue
		}
		if len(result)+len(failures) >= 8 {
			break
		}
		filePath := filepath.Join(s.dir, file.Name())
		if !start.After(s.lastStart) {
			failures = append(failures, fmt.Errorf("late flow slice %s", start.UTC()))
		} else {
			frame, loadErr := s.decode(filePath, start)
			if loadErr != nil {
				failures = append(failures, loadErr)
			}
			result = append(result, frame)
			s.lastStart = start
		}
		if err := os.Remove(filePath); err != nil && !errors.Is(err, os.ErrNotExist) {
			return result, errors.Join(errors.Join(failures...), err)
		}
	}
	return result, errors.Join(failures...)
}

func (s *nfdumpSampler) decode(path string, start time.Time) (sample, error) {
	ctx, cancel := context.WithTimeout(s.ctx, 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, s.dump, "-6", "-q", "-N", "-C", filepath.Join(s.dir, "empty.conf"), "-r", path,
		"-o", "fmt:%ts,%te,%sa,%da,%byt")
	cmd.Env = append(os.Environ(), "TZ=UTC", "LC_ALL=C")
	output, err := cmd.StdoutPipe()
	if err != nil {
		return sample{Start: start, End: start.Add(captureSlice), Partial: true}, err
	}
	if err = cmd.Start(); err != nil {
		return sample{Start: start, End: start.Add(captureSlice), Partial: true}, err
	}
	frame, parseErr := readFlows(output, start, s.local)
	if parseErr != nil {
		cancel()
	}
	err = errors.Join(parseErr, cmd.Wait())
	frame.Partial = frame.Partial || err != nil
	return frame, err
}

func readFlows(reader io.Reader, start time.Time, local map[netip.Addr]bool) (sample, error) {
	frame := sample{Start: start, End: start.Add(captureSlice), RX: make(map[netip.Addr]uint64), TX: make(map[netip.Addr]uint64)}
	lines := bufio.NewScanner(reader)
	lines.Buffer(make([]byte, 256), 512)
	for lines.Scan() {
		line := strings.TrimSpace(lines.Text())
		// nfdump emits this line on a healthy empty slice even with -q.
		if line == "" || line == "No matching flows" {
			continue
		}
		fields := strings.Split(line, ",")
		if len(fields) != 5 {
			return frame, errors.New("unexpected nfdump record format")
		}
		first, firstErr := time.Parse(time.DateTime, strings.TrimSpace(fields[0]))
		last, lastErr := time.Parse(time.DateTime, strings.TrimSpace(fields[1]))
		src, srcErr := netip.ParseAddr(strings.TrimSpace(fields[2]))
		dst, dstErr := netip.ParseAddr(strings.TrimSpace(fields[3]))
		bytes, countErr := strconv.ParseUint(strings.TrimSpace(fields[4]), 10, 63)
		if err := errors.Join(firstErr, lastErr, srcErr, dstErr, countErr); err != nil || last.Before(first) {
			// The row may contain IP addresses. Do not put the parser input in logs.
			return frame, errors.New("invalid nfdump timestamp, address or byte count")
		}
		if frame.FirstPacket.IsZero() || first.Before(frame.FirstPacket) {
			frame.FirstPacket = first
		}
		if last.After(frame.LastPacket) {
			frame.LastPacket = last
		}
		src, dst = src.Unmap(), dst.Unmap()
		switch {
		case !local[src] && local[dst]:
			if _, ok := frame.RX[src]; ok || len(frame.RX) < maxPeers {
				frame.RX[src] += bytes
			} else {
				frame.RXOverflow += bytes
			}
		case local[src] && !local[dst]:
			if _, ok := frame.TX[dst]; ok || len(frame.TX) < maxPeers {
				frame.TX[dst] += bytes
			} else {
				frame.TXOverflow += bytes
			}
		default:
			frame.Unknown += bytes
		}
	}
	return frame, lines.Err()
}
