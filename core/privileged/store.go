// Package privileged owns the settings an Agent never adopts on its own.
//
// The ordinary runtime config is a convergence loop: the panel names a desired
// state and the Agent reaches it unattended. These settings cannot work that
// way. Adopting one widens what the Agent is permitted to do, and an Agent
// that could widen its own privileges on the panel's word alone would make the
// panel a single point from which every host is escalated.
//
// So this store holds what was delivered, what is active, and what was active
// before. The gap between "delivered" and "active" is closed by a human: a
// confirmation in the panel within one privilege level, and additionally an
// authenticated upgrade run on the host itself when a privilege boundary is
// crossed. Nothing here ever closes that gap by itself.
package privileged

import (
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/komari-monitor/komari-agent/core/statelock"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
	reportv1 "github.com/r11234567/komari-proto/gen/go/komari/report/v1"
)

const (
	fileMode      = 0o600
	directoryMode = 0o700
)

// Settings is the active privileged configuration.
//
// Every field defaults to the restrictive value, so a missing or unreadable
// state file leaves the Agent with the narrowest capabilities rather than
// silently restoring something wider.
type Settings struct {
	RequiredPrivilegeMode reportv1.PrivilegeMode `json:"required_privilege_mode"`
	RemoteControlEnabled  bool                   `json:"remote_control_enabled"`
	WebSSHEnabled         bool                   `json:"webssh_enabled"`
	ExecutionEnabled      bool                   `json:"execution_enabled"`
	EnableGPU             bool                   `json:"enable_gpu"`
	RescueHelperEnabled   bool                   `json:"rescue_helper_enabled"`
}

// State is what this host persists about the privileged track.
type State struct {
	LastSequence         uint64    `json:"last_sequence,omitempty"`
	ActiveSignedRevision []byte    `json:"active_signed_revision,omitempty"`
	Outbox               []Receipt `json:"outbox,omitempty"`
	RejectedReceipts     []Receipt `json:"rejected_receipts,omitempty"`

	// AppliedRevision is the revision whose settings are active.
	AppliedRevision uint64 `json:"applied_revision"`
	// Active is what the Agent is running with now.
	Active Settings `json:"active"`
	// Previous is what a local rollback returns to. It is the whole point of
	// keeping history here: the host must be able to undo a privilege change
	// without the panel's cooperation, because the panel may be unreachable or
	// may itself be the source of the bad change.
	Previous         *Settings `json:"previous,omitempty"`
	PreviousRevision uint64    `json:"previous_revision,omitempty"`

	// PendingRevision is a delivered revision awaiting a human decision. It is
	// stored separately from Active so that receiving one never changes what
	// the Agent is doing.
	PendingRevision uint64    `json:"pending_revision,omitempty"`
	Pending         *Settings `json:"pending,omitempty"`
	// PendingClass records why the pending revision is not automatic, so the
	// CLI can tell an operator whether a panel confirmation is enough or an
	// on-host upgrade is required.
	PendingClass int32 `json:"pending_class,omitempty"`
	// PendingReasons is operator-facing text from the panel.
	PendingReasons []string `json:"pending_reasons,omitempty"`
	// PendingTaskID and PendingNonce belong to a manual upgrade task. The
	// nonce is what proves to the panel that the upgrade ran on this machine.
	PendingTaskID string    `json:"pending_task_id,omitempty"`
	PendingNonce  string    `json:"pending_nonce,omitempty"`
	PendingExpiry time.Time `json:"pending_expiry,omitempty"`

	UpdatedAt time.Time `json:"updated_at"`
}

// Store serializes access to the privileged state file.
type Store struct {
	mu       sync.RWMutex
	path     string
	state    State
	diskHash [32]byte
}

var active atomic.Pointer[Store]

// SetActive registers the process-wide active privileged store.
func SetActive(store *Store) { active.Store(store) }

// ActiveStore returns the active privileged store, if one has been set.
func ActiveStore() *Store { return active.Load() }

// DefaultPath sits beside the runtime config snapshot so an operator finds
// both in one place.
func DefaultPath() string {
	directory, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(directory) == "" {
		return ".komari-privileged.json"
	}
	return filepath.Join(directory, "komari-agent", "privileged.json")
}

// Open loads the state, treating a missing file as the restrictive default.
func Open(path string) (*Store, error) {
	if strings.TrimSpace(path) == "" {
		path = DefaultPath()
	}
	store := &Store{path: path}
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return store, nil
		}
		return nil, fmt.Errorf("read privileged state: %w", err)
	}
	if err := json.Unmarshal(data, &store.state); err != nil {
		return nil, fmt.Errorf("decode privileged state: %w", err)
	}
	store.diskHash = sha256.Sum256(data)
	return store, nil
}

// Path reports where this store persists.
func (s *Store) Path() string { return s.path }

// State returns a copy of the current state.
func (s *Store) State() State {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.clone()
}

// Active reports the settings in force.
func (s *Store) Active() Settings {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.state.Active
}

// RecordPending stores a delivered revision without applying any of it.
//
// This is the whole contract of the privileged track on the Agent side:
// delivery records an intention, and only an explicit local step turns it into
// active settings.
func (s *Store) RecordPending(revision *configv1.PrivilegedRevision) error {
	if revision == nil || revision.GetPrivileged() == nil {
		return errors.New("a privileged revision is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if revision.GetRevision() <= s.state.AppliedRevision {
		return fmt.Errorf("privileged revision %d is not newer than the applied revision %d",
			revision.GetRevision(), s.state.AppliedRevision)
	}
	if revision.Revision < s.state.PendingRevision || revision.UpdateSequence < s.state.LastSequence {
		return errors.New("stale pending revision or sequence")
	}
	next := s.state.clone()
	pending := settingsFromProto(revision.GetPrivileged())
	next.PendingRevision = revision.GetRevision()
	next.LastSequence = revision.UpdateSequence
	next.Pending = &pending
	next.PendingReasons = nil
	next.PendingTaskID = ""
	next.PendingNonce = ""
	next.PendingExpiry = time.Time{}
	next.PendingClass = 0
	if plan := revision.GetPlan(); plan != nil {
		next.PendingClass = int32(plan.GetUpgradeClass())
		next.PendingReasons = append([]string(nil), plan.GetReasons()...)
		if task := plan.GetManualTask(); task != nil {
			next.PendingTaskID = task.GetTaskId()
			next.PendingNonce = task.GetNonce()
			if expiry := task.GetExpiresAt(); expiry.IsValid() {
				next.PendingExpiry = expiry.AsTime()
			}
		}
	}
	return s.commit(next)
}

// Promote is a retired compatibility API; unsigned local promotion is forbidden.
func (s *Store) Promote(actual reportv1.PrivilegeMode) (Settings, error) {
	return s.Active(), errors.New("unsigned promotion retired; daemon requires a current signed v2 approval")
}

// Rollback restores the previous settings locally.
func (s *Store) Rollback() (Settings, uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Previous == nil {
		return s.state.Active, 0, errors.New("no previous privileged configuration to roll back to")
	}
	next := s.state.clone()
	restored := *next.Previous
	restoredRevision := next.PreviousRevision
	if !Subset(restored, next.Active) {
		return s.state.Active, 0, errors.New("rollback would widen capabilities; a fresh signed approval is required")
	}
	next.Active = restored
	next.AppliedRevision = restoredRevision
	next.ActiveSignedRevision = nil
	next.Previous = nil
	next.PreviousRevision = 0
	if err := s.commit(next); err != nil {
		return s.state.Active, 0, err
	}
	return next.Active, next.AppliedRevision, nil
}

// DiscardPending drops a delivered revision that was never adopted.
func (s *Store) DiscardPending() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Pending == nil {
		return nil
	}
	next := s.state.clone()
	next.clearPending()
	return s.commit(next)
}

// checkSupported validates actual identity and rejects unavailable host actions.
func checkSupported(settings Settings, actual reportv1.PrivilegeMode) error {
	if settings.RequiredPrivilegeMode != reportv1.PrivilegeMode_PRIVILEGE_MODE_UNSPECIFIED && settings.RequiredPrivilegeMode != actual {
		return errors.New("actual daemon identity does not match required privilege mode")
	}

	if settings.RescueHelperEnabled {
		return errors.New("rescue helper requires the separately installed host service")
	}
	return nil
}

func describePrivilege(mode reportv1.PrivilegeMode) string {
	switch mode {
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT:
		return "root"
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_NON_ROOT:
		return "a non-root user"
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_ADMINISTRATOR:
		return "an administrator"
	case reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_STANDARD_USER:
		return "a standard user"
	default:
		return "an unprivileged account"
	}
}

func settingsFromProto(value *configv1.PrivilegedConfig) Settings {
	return Settings{
		RequiredPrivilegeMode: value.GetRequiredPrivilegeMode(),
		RemoteControlEnabled:  value.GetRemoteControlEnabled(),
		WebSSHEnabled:         value.GetWebsshEnabled(),
		ExecutionEnabled:      value.GetExecutionEnabled(),
		EnableGPU:             value.GetEnableGpu(),
		RescueHelperEnabled:   value.GetRescueHelperEnabled(),
	}
}

// commit persists and then updates memory, so a failed write never leaves the
// process believing it adopted something that is not on disk.
func (s *Store) commit(next State) error {
	release, err := statelock.Acquire(s.path + ".write.lock")
	if err != nil {
		return err
	}
	defer release()
	disk, err := os.ReadFile(s.path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	var hash [32]byte
	if err == nil {
		hash = sha256.Sum256(disk)
	}
	if hash != s.diskHash {
		return errors.New("stale privileged store: another writer changed the snapshot; reopen required")
	}

	next.UpdatedAt = time.Now().UTC()
	data, err := json.MarshalIndent(next, "", "  ")
	if err != nil {
		return fmt.Errorf("encode privileged state: %w", err)
	}
	directory := filepath.Dir(s.path)
	if err := os.MkdirAll(directory, directoryMode); err != nil {
		return fmt.Errorf("create privileged state directory: %w", err)
	}
	temporary, err := os.CreateTemp(directory, ".komari-privileged-*")
	if err != nil {
		return fmt.Errorf("create privileged state temp file: %w", err)
	}
	name := temporary.Name()
	defer os.Remove(name)
	if err := temporary.Chmod(fileMode); err != nil {
		temporary.Close()
		return fmt.Errorf("restrict privileged state permissions: %w", err)
	}
	if _, err := temporary.Write(data); err != nil {
		temporary.Close()
		return fmt.Errorf("write privileged state: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return fmt.Errorf("flush privileged state: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close privileged state: %w", err)
	}
	if err := os.Rename(name, s.path); err != nil {
		return fmt.Errorf("replace privileged state: %w", err)
	}
	if err := statelock.SyncDirectory(directory); err != nil {
		return err
	}
	s.state = next
	s.diskHash = sha256.Sum256(data)
	return nil
}

func (state State) clone() State {
	copied := state
	copied.ActiveSignedRevision = append([]byte(nil), state.ActiveSignedRevision...)
	copied.Outbox = cloneReceipts(state.Outbox)
	copied.RejectedReceipts = cloneReceipts(state.RejectedReceipts)
	if state.Previous != nil {
		previous := *state.Previous
		copied.Previous = &previous
	}
	if state.Pending != nil {
		pending := *state.Pending
		copied.Pending = &pending
	}
	copied.PendingReasons = append([]string(nil), state.PendingReasons...)
	return copied
}

func (state *State) clearPending() {
	state.PendingRevision = 0
	state.Pending = nil
	state.PendingClass = 0
	state.PendingReasons = nil
	state.PendingTaskID = ""
	state.PendingNonce = ""
	state.PendingExpiry = time.Time{}
}
