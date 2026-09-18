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
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	RemoteControlEnabled bool `json:"remote_control_enabled"`
	WebSSHEnabled        bool `json:"webssh_enabled"`
	ExecutionEnabled     bool `json:"execution_enabled"`
	EnableGPU            bool `json:"enable_gpu"`
	RescueHelperEnabled  bool `json:"rescue_helper_enabled"`
}

// State is what this host persists about the privileged track.
type State struct {
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
	mu    sync.RWMutex
	path  string
	state State
}

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
	next := s.state.clone()
	pending := settingsFromProto(revision.GetPrivileged())
	next.PendingRevision = revision.GetRevision()
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

// Promote makes the pending revision active.
//
// It refuses when the resulting settings would exceed the privilege the Agent
// actually holds. That check is not redundant with the panel's classification:
// the panel decides what an upgrade requires, but only the host knows what it
// ended up with, and trusting the panel's expectation over the observed state
// is how a failed upgrade would silently look like a successful one.
func (s *Store) Promote(actual reportv1.PrivilegeMode) (Settings, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state.Pending == nil {
		return s.state.Active, errors.New("no privileged revision is pending")
	}
	pending := *s.state.Pending
	if err := checkSupported(pending, actual); err != nil {
		return s.state.Active, err
	}
	next := s.state.clone()
	previous := next.Active
	next.Previous = &previous
	next.PreviousRevision = next.AppliedRevision
	next.Active = pending
	next.AppliedRevision = next.PendingRevision
	next.clearPending()
	if err := s.commit(next); err != nil {
		return s.state.Active, err
	}
	return next.Active, nil
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
	// The settings being withdrawn become the rollback target, so a mistaken
	// rollback can itself be undone without the panel.
	current := next.Active
	currentRevision := next.AppliedRevision
	next.Active = restored
	next.AppliedRevision = restoredRevision
	next.Previous = &current
	next.PreviousRevision = currentRevision
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

// checkSupported refuses settings the host cannot honour.
//
// Remote control, WebSSH and execution all run commands with the Agent's own
// process identity, so enabling them on a non-privileged Agent would announce
// a capability that does not exist.
func checkSupported(settings Settings, actual reportv1.PrivilegeMode) error {
	privileged := actual == reportv1.PrivilegeMode_PRIVILEGE_MODE_LINUX_ROOT ||
		actual == reportv1.PrivilegeMode_PRIVILEGE_MODE_WINDOWS_ADMINISTRATOR
	if privileged {
		return nil
	}
	var blocked []string
	if settings.RemoteControlEnabled {
		blocked = append(blocked, "remote control")
	}
	if settings.WebSSHEnabled {
		blocked = append(blocked, "WebSSH")
	}
	if settings.ExecutionEnabled {
		blocked = append(blocked, "remote execution")
	}
	if settings.RescueHelperEnabled {
		blocked = append(blocked, "the rescue helper")
	}
	if len(blocked) == 0 {
		return nil
	}
	return fmt.Errorf("%s require a privileged Agent, but this Agent is running as %s",
		strings.Join(blocked, ", "), describePrivilege(actual))
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
		RemoteControlEnabled: value.GetRemoteControlEnabled(),
		WebSSHEnabled:        value.GetWebsshEnabled(),
		ExecutionEnabled:     value.GetExecutionEnabled(),
		EnableGPU:            value.GetEnableGpu(),
		RescueHelperEnabled:  value.GetRescueHelperEnabled(),
	}
}

// commit persists and then updates memory, so a failed write never leaves the
// process believing it adopted something that is not on disk.
func (s *Store) commit(next State) error {
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
	s.state = next
	return nil
}

func (state State) clone() State {
	copied := state
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
