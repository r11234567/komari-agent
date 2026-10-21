//go:build !linux

package cmd

func diagnoseMissingManifest(string) error { return nil }
