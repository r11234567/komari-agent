package netstatic

import (
	"path/filepath"
	"sync"
	"testing"
)

func TestConcurrentTrafficLifecycle(t *testing.T) {
	previous := SaveFilePath
	SaveFilePath = filepath.Join(t.TempDir(), "network.json")
	t.Cleanup(func() {
		if err := Stop(); err != nil {
			t.Error(err)
		}
		SaveFilePath = previous
	})
	var workers sync.WaitGroup
	for _, operation := range []func() error{
		StartOrContinue,
		Stop,
		func() error {
			return SetNewConfig(NetStaticConfig{DetectInterval: .002, SaveInterval: .003, Nics: []string{"test"}})
		},
		func() error {
			_, err := GetTotalTrafficBetween(0, 0)
			return err
		},
	} {
		workers.Go(func() {
			for i := 0; i < 32; i++ {
				if err := operation(); err != nil {
					t.Error(err)
					return
				}
			}
		})
	}
	workers.Wait()
}
