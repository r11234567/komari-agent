//go:build !linux

package hostcmd

import (
	"errors"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"io"
)

func diagnose(*hostops.Manifest, *hostops.Policy, io.Writer) error {
	return errors.New("host administration supports Linux systemd only in this version")
}
func migrate([]string, io.Writer) error {
	return errors.New("host migration supports Linux systemd only in this version")
}
func update([]string, io.Writer) error {
	return errors.New("host update supports Linux systemd only in this version")
}

func install([]string, io.Writer) error {
	return errors.New("trusted v2 installation supports Linux systemd only in this version")
}
