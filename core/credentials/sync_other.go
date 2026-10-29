//go:build !linux

package credentials

func syncCredentialDirectory(string) error { return nil }
