//go:build windows

package hostops

import "errors"

func TrustedPath(string) error {
	return errors.New("trusted Windows host layout requires ACL validation; privileged v2 installation is not yet supported")
}
