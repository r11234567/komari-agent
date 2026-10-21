//go:build !linux

package hostops

import "errors"

func ReadHelperStatus(*Manifest) (*HelperStatus, error) {
	return nil, errors.New("helper host observation requires accepted Linux systemd adapter")
}
func HostActionsReady(*Manifest) bool { return false }
