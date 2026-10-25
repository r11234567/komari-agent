//go:build windows

package terminal

import "errors"

func newTerminalAs(username, shell, directory string) (*terminalImpl, error) {
	return nil, errors.New("workspace OS identity isolation is not supported on Windows yet")
}
