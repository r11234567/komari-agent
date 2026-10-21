//go:build !linux

package hostops

import "errors"

func ReadCandidate(string) ([]byte, error) {
	return nil, errors.New("protected host candidate reader requires Linux")
}
