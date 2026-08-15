//go:build !windows

package terminal

func filesystemRoots() []string { return []string{"/"} }
