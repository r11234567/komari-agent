//go:build linux

package hostcmd

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"connectrpc.com/connect"
	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/internal/qgastream"
	"github.com/r11234567/komari-proto/diagnostics"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func runQGAForensics(args []string, out io.Writer) error {
	fs := flag.NewFlagSet("qga-forensics", flag.ContinueOnError)
	fs.SetOutput(out)
	manifest := fs.String("manifest", "", "protected manifest for the running root Agent")
	recipientKey := fs.String("recipient-public-key", "", "base64 X25519 public key verified on the panel")
	receiptKey := fs.String("receipt-public-key", "", "base64 Ed25519 receipt public key verified on the panel")
	duration := fs.Duration("duration", 15*time.Minute, "run in this SSH terminal for up to one hour")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *manifest == "" || fs.NArg() != 0 || *duration <= 0 || *duration > time.Hour {
		return errors.New("supply a protected --manifest and a duration between zero and one hour")
	}
	if os.Geteuid() != 0 {
		return errors.New("QGA forensic activation requires root")
	}
	uid, err := hostops.DirectSSHUID()
	if err != nil || uid != 0 {
		return errors.New("QGA forensic activation requires a direct interactive root SSH login")
	}
	public, err := base64.StdEncoding.DecodeString(*recipientKey)
	if err != nil || len(public) != 32 {
		return diagnostics.ErrKey
	}
	verifyKey, err := base64.StdEncoding.DecodeString(*receiptKey)
	if err != nil || len(verifyKey) != ed25519.PublicKeySize {
		return diagnostics.ErrReceipt
	}
	m, err := hostops.ReadManifest(*manifest)
	if err != nil {
		return err
	}
	p, err := hostops.ReadPolicy(m)
	if err != nil || p.PrivilegeMode != 1 || m.InitSystem != "systemd" {
		return errors.New("QGA forensic activation requires a protected root Agent installation")
	}
	if _, err := authenticateAccount("root"); err != nil {
		return err
	}
	if err := verifyService(m.ServiceName, 0, 1); err != nil {
		return err
	}
	service, err := observe(m.ServiceName)
	if err != nil {
		return err
	}
	agentPID, err := strconv.Atoi(service.MainPID)
	if err != nil || agentPID <= 1 {
		return errors.New("the installed root Agent is not running")
	}
	agentProcess, err := unix.PidfdOpen(agentPID, 0)
	if err != nil {
		return fmt.Errorf("track the running root Agent: %w", err)
	}
	defer unix.Close(agentProcess)
	if err := hostops.TrustedPath(m.Executable); err != nil {
		return err
	}
	installed, err := os.Stat(m.Executable)
	if err != nil {
		return err
	}
	actual, err := os.Stat(filepath.Join("/proc", service.MainPID, "exe"))
	if err != nil || !os.SameFile(installed, actual) {
		return errors.New("the running root process does not match the installed Agent")
	}
	if err := hostops.TrustedPath(m.CredentialsFile); err != nil {
		return err
	}
	trust, err := hostops.ReadTrust(m)
	if err != nil {
		return err
	}
	receiver, err := newPanel(m, trust)
	if err != nil {
		return err
	}
	identity := receiver.identity
	if !time.Now().Add(*duration).Before(identity.AccessTokenExpiresAt) {
		return errors.New("allow the running Agent to renew enrollment or select a shorter forensic session")
	}
	signing, err := identity.SigningKey()
	if err != nil {
		return err
	}
	clear(signing)
	node, err := uuid.Parse(identity.AgentID)
	if err != nil {
		return err
	}
	value, err := systemctl("show", "qemu-guest-agent.service", "--property=MainPID", "--value")
	if err != nil {
		return err
	}
	pid, err := strconv.Atoi(strings.TrimSpace(value))
	if err != nil {
		return errors.New("QGA process is unavailable")
	}
	capture, err := qgastream.Attach(pid)
	if err != nil {
		return err
	}
	defer capture.Close()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGHUP, syscall.SIGTERM)
	defer stop()
	ctx, cancel := context.WithTimeout(ctx, *duration)
	defer cancel()
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		defer capture.Stop()
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if n, err := unix.Poll([]unix.PollFd{{Fd: int32(agentProcess), Events: unix.POLLIN}}, 0); n != 0 || err != nil {
					cancel()
					return
				}
			}
		}
	}()
	defer func() { cancel(); <-stopped }()
	const procedure = "/komari.diag.v1.SealedRecordService/Submit"
	sender := connect.NewClient[wrapperspb.BytesValue, wrapperspb.BytesValue](receiver.client, strings.TrimRight(identity.Endpoint, "/")+procedure,
		connect.WithReadMaxBytes(4096), connect.WithSendMaxBytes(diagnostics.MaxEnvelopeSize+128))
	header := diagnostics.Header{Node: node, Stream: uuid.New(), Sequence: 1}
	var evidence qgastream.Evidence
	fmt.Fprintln(out, "QGA forensic capture active in this SSH session")
	for ctx.Err() == nil {
		err = capture.Next(func(direction qgastream.Direction, frame qgastream.Frame) error {
			return evidence.Observe(direction, frame, func(observation qgastream.Observation) error {
				payload, err := json.Marshal(observation)
				if err != nil {
					return errors.New("encode forensic observation")
				}
				defer clear(payload)
				sealed, err := diagnostics.Seal(public, header, payload)
				if err != nil {
					return err
				}
				upload, cancel := context.WithTimeout(ctx, 10*time.Second)
				defer cancel()
				response, err := sender.CallUnary(upload, auth(receiver, wrapperspb.Bytes(sealed)))
				if err != nil {
					return fmt.Errorf("forensic upload sequence %d failed (%s)", header.Sequence, connect.CodeOf(err))
				}
				var receipt diagnostics.Receipt
				if err := json.Unmarshal(response.Msg.GetValue(), &receipt); err != nil || receipt.Verify(verifyKey, sealed) != nil {
					return diagnostics.ErrReceipt
				}
				header.Sequence++
				return nil
			})
		})
		if err != nil && ctx.Err() == nil {
			return err
		}
	}
	return nil
}
