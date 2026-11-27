// test-collector is built only for the disposable QEMU fixture. It sends the
// fixture's sealed observations to its runner over a test-only serial port.
package main

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"

	"github.com/komari-monitor/komari-agent/internal/qgastream"
	"github.com/r11234567/komari-proto/diagnostics"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) != 2 {
		return errors.New("fixture public key required")
	}
	public, err := base64.StdEncoding.DecodeString(os.Args[1])
	if err != nil || len(public) != 32 {
		return errors.New("invalid fixture public key")
	}
	result, err := exec.Command("systemctl", "show", "-p", "MainPID", "--value", "qemu-guest-agent.service").Output()
	if err != nil {
		return fmt.Errorf("find fixture QGA: %w", err)
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(result)))
	if err != nil {
		return errors.New("invalid fixture QGA PID")
	}
	spool, err := os.OpenFile("/dev/virtio-ports/org.komari.test.records", os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("open fixture output: %w", err)
	}
	defer spool.Close()
	capture, err := qgastream.Attach(pid)
	if err != nil {
		return err
	}
	defer capture.Close()
	if _, err := spool.WriteString("ready\n"); err != nil {
		return err
	}
	header := diagnostics.Header{Node: [16]byte{1}, Stream: [16]byte{2}, Sequence: 1}
	enc := json.NewEncoder(spool)
	var evidence qgastream.Evidence
	for {
		err := capture.Next(func(direction qgastream.Direction, frame qgastream.Frame) error {
			return evidence.Observe(direction, frame, func(record qgastream.Observation) error {
				if record.Gap {
					return errors.New("fixture capture lost fragments")
				}
				payload, err := json.Marshal(record)
				if err != nil {
					return errors.New("encode sealed observation")
				}
				defer clear(payload)
				sealed, err := diagnostics.Seal(public, header, payload)
				if err != nil {
					return err
				}
				header.Sequence++
				return enc.Encode(sealed)
			})
		})
		if err != nil {
			return err
		}
	}
}
