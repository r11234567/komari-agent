//go:build !linux

package rescue

import (
	"context"
	"errors"

	"github.com/komari-monitor/komari-agent/core/hostops"
	rescuev1 "github.com/r11234567/komari-proto/gen/go/komari/rescue/v1"
)

func sshWindowStatus(context.Context, *hostops.Manifest, string, *rescuev1.RescueHelperStatus) {}
func checkSSHWindowIdentity(context.Context, *hostops.Manifest)                                {}
func revokeSSHWindowForEnrollment(context.Context, *hostops.Manifest, string) error            { return nil }

func executeSSHWindow(context.Context, *hostops.Manifest, *rescuev1.RescueSession, func() bool) (ActionResult, error) {
	return ActionResult{}, errors.New("temporary SSH windows require Linux nftables")
}
