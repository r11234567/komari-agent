//go:build !linux

package localauth

import (
	"errors"
	"time"
)

// Method names how an operator was verified, for the audit trail.
type Method string

const (
	MethodSudoPassword   Method = "sudo-password"
	MethodCallerPassword Method = "caller-password"
	MethodRootPassword   Method = "root-password"
)

// Result describes a successful verification.
type Result struct {
	Method   Method
	Operator string
}

// Options tunes verification.
type Options struct {
	Prompt  string
	Timeout time.Duration
}

// Verify is unimplemented outside Linux.
//
// The Linux path proves a human is present by checking a credential through
// the host's own PAM stack, and deliberately refuses to treat passwordless
// sudo as proof. An equivalent on another platform needs its own design
// rather than a partial port: returning success here would let a privilege
// change be adopted with nobody present, which is the single thing this
// package exists to prevent.
func Verify(options Options) (Result, error) {
	return Result{}, errors.New("local operator verification is currently supported only on Linux")
}
