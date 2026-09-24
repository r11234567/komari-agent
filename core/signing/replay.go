package signing

// Replay protection.
//
// A signature proves who composed an instruction, not how many times it may be
// obeyed. Without a record of what has already been accepted, anyone able to
// observe one valid instruction could send it again: a "roll back" or "enable
// remote control" captured once would stay usable for as long as its expiry
// allowed.
//
// The record is persisted because an Agent restart must not reopen that
// window. Keeping nonces only in memory would make a replay succeed simply by
// waiting for the process to restart, which an attacker who can send
// instructions can often arrange.

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	fileMode      = 0o600
	directoryMode = 0o700
	// maximumEntries bounds the file. Entries are pruned by expiry first, so
	// this only matters if a panel issues a very large number of instructions
	// with long expiries; dropping the oldest is safe because they are the
	// ones whose deadline passes soonest.
	maximumEntries = 4096
)

// ReplayGuard remembers which instruction nonces have been accepted.
type ReplayGuard struct {
	mu      sync.Mutex
	path    string
	entries map[string]time.Time
	loaded  bool
}

// NewReplayGuard opens the persisted nonce record.
func NewReplayGuard(path string) *ReplayGuard {
	if strings.TrimSpace(path) == "" {
		path = DefaultReplayPath()
	}
	return &ReplayGuard{path: path, entries: make(map[string]time.Time)}
}

// DefaultReplayPath sits beside the other Agent state files.
func DefaultReplayPath() string {
	directory, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(directory) == "" {
		return ".komari-nonces.json"
	}
	return filepath.Join(directory, "komari-agent", "nonces.json")
}

// Consume records a nonce, rejecting one that was already used.
//
// expiresAt is how long the nonce must be remembered. Remembering it for
// exactly as long as the instruction is valid is what makes the record
// bounded: once the instruction would be refused for being expired anyway,
// forgetting the nonce costs nothing.
func (g *ReplayGuard) Consume(nonce string, expiresAt time.Time) error {
	trimmed := strings.TrimSpace(nonce)
	if trimmed == "" {
		return errors.New("the instruction carries no nonce")
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	if err := g.load(); err != nil {
		// A record that cannot be read is treated as fatal rather than empty.
		// Continuing would silently disable replay protection, which is worse
		// than refusing one instruction and saying why.
		return fmt.Errorf("replay protection is unavailable: %w", err)
	}
	g.pruneLocked(time.Now())

	if _, seen := g.entries[trimmed]; seen {
		return errors.New("this instruction was already carried out; refusing to repeat it")
	}
	if expiresAt.IsZero() {
		return errors.New("the instruction has no expiry, so its nonce could not be retired")
	}
	g.entries[trimmed] = expiresAt

	// Persisting before returning is what makes the guarantee survive a crash.
	// Accepting the instruction first and writing afterwards would leave a
	// window in which the same nonce is accepted twice.
	if err := g.persistLocked(); err != nil {
		delete(g.entries, trimmed)
		return fmt.Errorf("could not record the instruction nonce: %w", err)
	}
	return nil
}

// Seen reports whether a nonce is already recorded, without consuming it.
func (g *ReplayGuard) Seen(nonce string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	if err := g.load(); err != nil {
		// Unable to tell, so report the safer answer.
		return true
	}
	g.pruneLocked(time.Now())
	_, seen := g.entries[strings.TrimSpace(nonce)]
	return seen
}

func (g *ReplayGuard) load() error {
	if g.loaded {
		return nil
	}
	data, err := os.ReadFile(g.path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			g.loaded = true
			return nil
		}
		return err
	}
	var stored map[string]time.Time
	if err := json.Unmarshal(data, &stored); err != nil {
		return err
	}
	if stored != nil {
		g.entries = stored
	}
	g.loaded = true
	return nil
}

func (g *ReplayGuard) pruneLocked(now time.Time) {
	for nonce, expiry := range g.entries {
		if now.After(expiry) {
			delete(g.entries, nonce)
		}
	}
	for len(g.entries) > maximumEntries {
		oldest := ""
		var oldestExpiry time.Time
		for nonce, expiry := range g.entries {
			if oldest == "" || expiry.Before(oldestExpiry) {
				oldest, oldestExpiry = nonce, expiry
			}
		}
		if oldest == "" {
			break
		}
		delete(g.entries, oldest)
	}
}

func (g *ReplayGuard) persistLocked() error {
	data, err := json.Marshal(g.entries)
	if err != nil {
		return err
	}
	directory := filepath.Dir(g.path)
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(directory, ".komari-nonces-*")
	if err != nil {
		return err
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(fileMode); err != nil {
		temporary.Close()
		return err
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	return os.Rename(name, g.path)
}
