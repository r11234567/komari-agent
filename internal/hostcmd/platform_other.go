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
func apply([]string, io.Writer) error {
	return errors.New("host apply requires Linux systemd; this platform has not passed host-transaction acceptance")
}
func trust([]string, io.Writer) error { return errors.New("host trust setup requires Linux systemd") }
func resume([]string, io.Writer, bool) error {
	return errors.New("host recovery requires Linux systemd")
}
func fetchHelper([]string, io.Writer) error {
	return errors.New("helper release staging requires the accepted Linux systemd adapter")
}
func upgradeInstalledRescue([]string, io.Writer) error {
	return errors.New("coordinated installed-rescue upgrades require Linux systemd")
}

func checkUpgrade([]string, io.Writer) error {
	return errors.New("upgrade preflight requires Linux systemd")
}
