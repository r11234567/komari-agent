//go:build windows

package terminal

import (
	"context"

	"github.com/UserExistsError/conpty"
)

type windowsTerminal struct {
	tty    *conpty.ConPty
	closed bool
}

func (t *windowsTerminal) Close() error {
	if t.closed {
		return nil
	}
	if err := t.tty.Close(); err != nil {
		return err
	}
	t.closed = true
	return nil
}

func (t *windowsTerminal) Read(p []byte) (int, error) {
	return t.tty.Read(p)
}

func (t *windowsTerminal) Write(p []byte) (int, error) {
	return t.tty.Write(p)
}

func (t *windowsTerminal) Resize(cols, rows int) error {
	return t.tty.Resize(cols, rows)
}

func (t *windowsTerminal) Wait() error {
	_, err := t.tty.Wait(context.Background())
	return err
}
