//go:build linux

package localauth

import (
	"errors"
	"testing"
)

func TestParseSudoOutput_NOPASSWD(t *testing.T) {
	output := []byte(`User operator may run the following commands on host:
    (ALL : ALL) NOPASSWD: ALL`)
	state := parseSudoOutput(output, nil)

	if !state.available {
		t.Fatal("expected sudo to be available")
	}
	if state.requiresPassword {
		t.Fatal("expected requiresPassword to be false when NOPASSWD is set in sudoers")
	}
	// Note: Because requiresPassword is false, Verify() will NOT trust sudo without authentication!
	// It will fall through to verifyPassword(options, operator) to enforce human presence via password.
}

func TestParseSudoOutput_RequiresPassword(t *testing.T) {
	output := []byte(`sudo: a password is required`)
	state := parseSudoOutput(output, errors.New("exit status 1"))

	if !state.available {
		t.Fatal("expected sudo to be marked available when password is required")
	}
	if !state.requiresPassword {
		t.Fatal("expected requiresPassword to be true")
	}
}

func TestParseSudoOutput_NotAvailable(t *testing.T) {
	output := []byte(`sudo: command not found`)
	state := parseSudoOutput(output, errors.New("exit status 127"))

	if state.available {
		t.Fatal("expected sudo to be unavailable")
	}
}
