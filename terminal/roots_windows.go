//go:build windows

package terminal

import (
	"fmt"
	"os"
)

func filesystemRoots() []string {
	roots := make([]string, 0, 4)
	for drive := 'A'; drive <= 'Z'; drive++ {
		root := fmt.Sprintf("%c:\\", drive)
		if _, err := os.Stat(root); err == nil {
			roots = append(roots, root)
		}
	}
	if len(roots) == 0 {
		return []string{`C:\`}
	}
	return roots
}
