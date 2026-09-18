//go:build linux

// Package localauth verifies that a human with host credentials is present
// before a privilege change is adopted.
//
// The credential is collected and checked entirely on this machine. Neither
// the Agent nor the panel ever receives it: the panel learns only which method
// verified the operator, and that the upgrade succeeded. A control plane able
// to ask hosts for their root password would be a far worse problem than the
// one this solves.
//
// Passwordless sudo is deliberately not accepted as proof. A NOPASSWD rule
// exists so automation can run commands unattended, which is the opposite of
// what is needed here: the entire purpose of this check is that a person is
// present and consenting. Where sudo would not prompt, the operator's own
// password is verified directly instead.
package localauth

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Method names how an operator was verified, for the audit trail.
type Method string

const (
	// MethodSudoPassword is an ordinary sudo password prompt.
	MethodSudoPassword Method = "sudo-password"
	// MethodCallerPassword is the invoking user's password, verified directly
	// because sudo would not have prompted.
	MethodCallerPassword Method = "caller-password"
	// MethodRootPassword is the root password, used where sudo is absent.
	MethodRootPassword Method = "root-password"
)

// Result describes a successful verification.
type Result struct {
	Method   Method
	Operator string
}

// Options tunes verification. The zero value is correct for interactive use.
type Options struct {
	// Prompt is written before reading a password.
	Prompt string
	// Timeout bounds how long to wait for input, so an upgrade launched from a
	// detached context cannot hang forever holding a pending state.
	Timeout time.Duration
}

const defaultTimeout = 2 * time.Minute

// Verify confirms a human with host credentials is present.
//
// It reports the method used so the caller can record it. It never returns the
// credential, and no code path here writes one to a log, an argument list or
// an environment variable.
func Verify(options Options) (Result, error) {
	operator := callerName()
	if options.Timeout <= 0 {
		options.Timeout = defaultTimeout
	}

	// Already root means the operator authenticated to become root, typically
	// via sudo or a root login, and demanding another password would only
	// train people to retype it without reading the prompt. The interesting
	// case is the non-root one below.
	if os.Geteuid() == 0 && operator != "" && operator != "root" {
		return Result{Method: MethodSudoPassword, Operator: operator}, nil
	}

	state, err := inspectSudo()
	if err != nil {
		return Result{}, err
	}

	switch {
	case state.available && state.requiresPassword:
		// sudo will prompt, so let it do the verification: it is the path the
		// operator already knows and it respects the host's own sudo policy.
		if err := verifyThroughSudo(options, operator); err != nil {
			return Result{}, err
		}
		return Result{Method: MethodSudoPassword, Operator: operator}, nil

	case state.available && !state.requiresPassword:
		// Passwordless sudo would grant privileges without proving anyone is
		// present, so the operator's own password is checked directly.
		if err := verifyPassword(options, operator); err != nil {
			return Result{}, err
		}
		return Result{Method: MethodCallerPassword, Operator: operator}, nil

	default:
		// No usable sudo: fall back to the root password.
		if err := verifyPassword(options, "root"); err != nil {
			return Result{}, err
		}
		return Result{Method: MethodRootPassword, Operator: operator}, nil
	}
}

type sudoState struct {
	available        bool
	requiresPassword bool
}

// inspectSudo asks sudo what it would do, without running anything.
func inspectSudo() (sudoState, error) {
	binary, err := exec.LookPath("sudo")
	if err != nil {
		return sudoState{}, nil
	}
	// -l lists the invoking user's permitted commands. A NOPASSWD entry in the
	// output means sudo would not prompt, which is what has to be detected.
	command := exec.Command(binary, "-ln")
	command.Stdin = nil
	output, err := command.CombinedOutput()
	if err != nil {
		// Listing fails when the user has no sudo rights at all, or when sudo
		// itself wants a password it cannot read without a terminal. Treat the
		// former as "no sudo" and the latter as "sudo needs a password", which
		// is distinguishable by whether the error text mentions a password.
		text := strings.ToLower(string(output))
		if strings.Contains(text, "password") {
			return sudoState{available: true, requiresPassword: true}, nil
		}
		return sudoState{}, nil
	}
	return sudoState{
		available:        true,
		requiresPassword: !strings.Contains(string(output), "NOPASSWD"),
	}, nil
}

// verifyThroughSudo makes sudo perform its own prompt.
//
// `sudo -k` first so a cached credential from an earlier command in the same
// session cannot stand in for a deliberate confirmation now.
func verifyThroughSudo(options Options, operator string) error {
	binary, err := exec.LookPath("sudo")
	if err != nil {
		return errors.New("sudo is not available")
	}
	_ = exec.Command(binary, "-k").Run()

	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("a terminal is required to confirm this upgrade; run it from an interactive session")
	}
	defer terminal.Close()

	if options.Prompt != "" {
		fmt.Fprintln(terminal, options.Prompt)
	}
	command := exec.Command(binary, "-v")
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	if err := runBounded(command, options.Timeout); err != nil {
		return fmt.Errorf("sudo could not verify %s: %w", operator, err)
	}
	return nil
}

// verifyPassword has the system authenticate the operator, without granting
// anything.
//
// The check runs `su <account> -c true`, which validates the credential
// through the host's own PAM stack. That matters for two reasons: it honours
// whatever the host actually uses for authentication, and it works where sudo
// is configured not to ask.
//
// The prompt comes from su, not from here. The operator types their password
// to the system, and it never passes through this process at any point.
func verifyPassword(options Options, account string) error {
	binary, err := exec.LookPath("su")
	if err != nil {
		return errors.New("neither sudo nor su is available, so this host cannot verify an operator locally")
	}
	if locked, reason := accountLocked(account); locked {
		return fmt.Errorf("cannot verify %s locally: %s\n"+
			"set a password for %s, or grant it password-protected sudo, then run this again",
			account, reason, account)
	}

	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("a terminal is required to confirm this upgrade; run it from an interactive session")
	}
	defer terminal.Close()

	if options.Prompt != "" {
		fmt.Fprintln(terminal, options.Prompt)
	}

	// The terminal is handed to su, which prompts through PAM itself. This
	// process never reads, holds or forwards the password: the operator types
	// it to the system, not to the Agent. Reading it here and piping it in
	// would work, but it would put a host credential through an Agent's
	// address space for no benefit, and an Agent that can collect passwords is
	// a far worse problem than the one this check solves.
	command := exec.Command(binary, account, "-c", "true")
	command.Stdin, command.Stdout, command.Stderr = terminal, terminal, terminal
	// A fresh session with the tty as controlling terminal is what lets PAM
	// prompt at all; without it su refuses, having nowhere to ask.
	command.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true}
	if err := runBounded(command, options.Timeout); err != nil {
		return fmt.Errorf("authentication for %s failed", account)
	}
	return nil
}

// accountLocked reports whether an account has no usable password, which is
// the normal state of root on a cloud image and of a key-only login user.
// Detecting it lets the operator be told what to fix instead of watching an
// authentication attempt fail for no visible reason.
func accountLocked(account string) (bool, string) {
	if _, err := user.Lookup(account); err != nil {
		return true, "no such account on this host"
	}
	data, err := os.ReadFile("/etc/shadow")
	if err != nil {
		// Unreadable shadow is expected for a non-root caller; fall through to
		// a real authentication attempt rather than guessing.
		return false, ""
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 2 || fields[0] != account {
			continue
		}
		switch hash := fields[1]; {
		case hash == "":
			return true, "the account has an empty password"
		case hash == "*" || strings.HasPrefix(hash, "!"):
			return true, "password authentication is disabled for the account"
		}
		return false, ""
	}
	return false, ""
}

func callerName() string {
	// SUDO_USER identifies the human when this already runs under sudo, which
	// is the common case for an upgrade command.
	if value := strings.TrimSpace(os.Getenv("SUDO_USER")); value != "" {
		return value
	}
	if current, err := user.Current(); err == nil && current.Username != "" {
		return current.Username
	}
	return strconv.Itoa(os.Getuid())
}

func runBounded(command *exec.Cmd, timeout time.Duration) error {
	if err := command.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- command.Wait() }()
	select {
	case err := <-done:
		return err
	case <-time.After(timeout):
		_ = command.Process.Kill()
		return errors.New("timed out")
	}
}
