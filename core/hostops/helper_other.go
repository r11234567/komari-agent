//go:build !linux

package hostops

import "errors"

func PrepareHelperStatus(*Manifest) error {
	return errors.New("helper host heartbeat requires accepted Linux systemd adapter")
}

func ReadHelperStatus(*Manifest) (*HelperStatus, error) {
	return nil, errors.New("helper host observation requires accepted Linux systemd adapter")
}
func HostActionsReady(*Manifest) bool { return false }
func ProcessStartTicks(int) (uint64, error) {
	return 0, errors.New("process observation requires Linux")
}
