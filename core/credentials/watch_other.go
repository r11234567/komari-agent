//go:build !linux

package credentials

import (
	"context"
	"os"
	"time"
)

// Compatibility fallback performs only local metadata checks, never RPCs.
func WatchChanges(ctx context.Context, path string) (<-chan struct{}, error) {
	changes := make(chan struct{}, 1)
	go func() {
		defer close(changes)
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		var previous time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				info, err := os.Stat(path)
				if err != nil {
					continue
				}
				if info.ModTime() != previous {
					previous = info.ModTime()
					select {
					case changes <- struct{}{}:
					default:
					}
				}
			}
		}
	}()
	return changes, nil
}
