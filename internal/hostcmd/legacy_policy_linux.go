//go:build linux

package hostcmd

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/privileged"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
)

// Migration cannot infer whether a historical flag was an installer default or
// an administrator's decision. Preserve it until the local operator explicitly
// reviews a signed task and authenticates. Never release a newer explicit deny.
func legacyRemoteControlReview(p *hostops.Policy, r *configv1.PrivilegedRevision) (hostops.Policy, bool) {
	preview := *p
	review := p.ForceDenyRemoteControl && p.AllowRemoteControl &&
		p.DisableSource == "legacy-unknown-preserve" && r.GetPrivileged().GetRemoteControlEnabled()
	if review {
		preview.ForceDenyRemoteControl = false
	}
	return preview, review
}

func readLegacyRemoteControlConsent(reader io.Reader, writer io.Writer, service string, revision uint64) error {
	answer := fmt.Sprintf("authorize %s %d", service, revision)
	fmt.Fprintf(writer, "This installation preserved an old remote-control disable flag. The approved task requests remote control.\nRelease only this historical restriction as part of revision %d? Other local ceilings remain in force.\nType %q to confirm.\nLegacy remote-control consent: ", revision, answer)
	line, err := bufio.NewReader(io.LimitReader(reader, 512)).ReadString('\n')
	if err != nil || strings.TrimSpace(line) != answer {
		return errors.New("legacy remote-control restriction retained; no host operation was claimed or applied")
	}
	return nil
}

func confirmLegacyRemoteControl(service string, revision uint64) error {
	tty, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("reviewing a preserved legacy remote-control restriction requires a local controlling terminal")
	}
	defer tty.Close()
	return readLegacyRemoteControlConsent(tty, tty, service, revision)
}

func localCeilingViolations(p *hostops.Policy, s privileged.Settings, installingHelper bool) []string {
	var reasons []string
	if s.RemoteControlEnabled {
		if p.ForceDenyRemoteControl {
			reasons = append(reasons, "remote_control_enabled blocked by force_deny_remote_control=true (source="+p.DisableSource+")")
		}
		if !p.AllowRemoteControl {
			reasons = append(reasons, "remote_control_enabled blocked by allow_remote_control=false")
		}
	}
	for _, check := range []struct {
		requested bool
		allowed   bool
		field     string
		ceiling   string
	}{
		{s.WebSSHEnabled, p.AllowWebSSH, "webssh_enabled", "allow_webssh"},
		{s.ExecutionEnabled, p.AllowExecution, "execution_enabled", "allow_execution"},
		{s.EnableGPU, p.AllowGPU, "enable_gpu", "allow_gpu"},
	} {
		if check.requested && !check.allowed {
			reasons = append(reasons, check.field+" blocked by "+check.ceiling+"=false")
		}
	}
	if s.RescueHelperEnabled {
		if p.ForceDenyRescueHelper {
			reasons = append(reasons, "rescue_helper_enabled blocked by force_deny_rescue_helper=true")
		}
		if !p.AllowRescueHelper && !installingHelper {
			reasons = append(reasons, "rescue_helper_enabled blocked by allow_rescue_helper=false without a signed install action")
		}
	}
	return reasons
}
