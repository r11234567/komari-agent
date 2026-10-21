//go:build windows

package statelock

// Windows has no portable directory fsync. State writers sync the temporary
// file before atomically replacing it; a directory handle must not be passed
// to File.Sync, which rejects an otherwise successful legacy runtime update.
func SyncDirectory(string) error { return nil }
