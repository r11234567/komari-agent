//go:build linux || darwin || freebsd

package hostops

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// Every ancestor matters: a root-owned file inside an agent-writable directory
// can still be replaced. Symlinks are rejected, including ancestor symlinks.
func TrustedPath(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("trusted path must be absolute: %s", path)
	}
	for p := filepath.Clean(path); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		sys, ok := st.Sys().(*syscall.Stat_t)
		if !ok || sys.Uid != 0 || st.Mode().Perm()&0o022 != 0 || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("untrusted owner, permissions or symlink: %s", p)
		}
		if p == "/" {
			return nil
		}
	}
}
