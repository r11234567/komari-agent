package rescue

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

type sshWindowSetupError struct {
	code string
	err  error
}

func (e *sshWindowSetupError) Error() string { return e.err.Error() }
func (e *sshWindowSetupError) Unwrap() error { return e.err }

const (
	sshFirewallUnsupported = "SSH_FIREWALL_UNSUPPORTED"
	sshFirewallCheckFailed = "SSH_FIREWALL_CHECK_FAILED"
	sshWindowUFW           = "ufw"
	sshWindowNFT           = "nftables"
)

func sshWindowCommand(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	return cmd.CombinedOutput()
}

func checkSSHWindowFirewall(ctx context.Context) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()
	return inspectSSHWindowFirewall(ctx, sshWindowCommand)
}

// This probe is shared by local setup and a helper that has no SSH settings.
// Detect managers first: having nft installed says nothing about who owns INPUT.
func inspectSSHWindowFirewall(ctx context.Context, run func(context.Context, string, ...string) ([]byte, error)) (string, error) {
	unsupported := func(reason string) error {
		return &sshWindowSetupError{sshFirewallUnsupported, errors.New(reason +
			". Temporary SSH supports UFW with ipset or a native nftables inet input chain. WebSSH is available if the Agent is reachable.")}
	}
	probeFailed := func(name string, output []byte, err error) error {
		if err == nil {
			err = errors.New("unrecognized status")
		}
		return &sshWindowSetupError{sshFirewallCheckFailed, fmt.Errorf(
			"could not check %s; run setup-rescue-ssh --check on the node: %w (%s)", name, err, truncateError(string(output)))}
	}

	if output, err := run(ctx, "ufw", "status"); !errors.Is(err, exec.ErrNotFound) {
		status := ""
		for line := range strings.Lines(string(output)) {
			line = strings.TrimSpace(line)
			if line == "Status: active" || line == "Status: inactive" {
				if status != "" {
					return "", probeFailed("ufw status", output, err)
				}
				status = line
			}
		}
		switch {
		case err == nil && status == "Status: active":
			if output, err := run(ctx, "ipset", "list", "-name"); errors.Is(err, exec.ErrNotFound) {
				return "", &sshWindowSetupError{"SSH_UFW_IPSET_MISSING", errors.New("UFW is active; install the ipset package on the node and rerun setup-rescue-ssh")}
			} else if err != nil {
				return "", probeFailed("ipset list -name", output, err)
			}
			return sshWindowUFW, nil
		case err == nil && status == "Status: inactive":
		default:
			return "", probeFailed("ufw status", output, err)
		}
	}
	if output, err := run(ctx, "firewall-cmd", "--state"); !errors.Is(err, exec.ErrNotFound) {
		status := strings.TrimSpace(string(output))
		var exited *exec.ExitError
		switch {
		case err == nil && status == "running":
			return "", unsupported("firewalld is active and does not have a temporary SSH backend")
		case status == "not running" && errors.As(err, &exited) && exited.ExitCode() == 252:
		default:
			return "", probeFailed("firewall-cmd --state", output, err)
		}
	}
	if output, err := run(ctx, "nft", "-j", "list", "chains"); err == nil {
		var ruleset sshNftRuleset
		if err := json.Unmarshal(output, &ruleset); err != nil || ruleset.Entries == nil {
			return "", probeFailed("nft list chains", nil, err)
		}
		if len(sshInputHooks(ruleset)) == 0 {
			return "", unsupported("no native nftables inet input filter is loaded; direct iptables INPUT is unsupported, including iptables-nft")
		}
		return sshWindowNFT, nil
	} else if !errors.Is(err, exec.ErrNotFound) {
		return "", probeFailed("nft list chains", output, err)
	}
	return "", unsupported("UFW is inactive or unavailable and the nft command is missing")
}
