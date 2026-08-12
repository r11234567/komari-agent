package runtimeconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	flags_pkg "github.com/komari-monitor/komari-agent/cmd/flags"
	configv1 "github.com/r11234567/komari-proto/gen/go/komari/config/v1"
)

const (
	minimumReportInterval = time.Second
	maximumReportInterval = 5 * time.Minute
)

// Snapshot is an immutable, transport-neutral view of the settings that may be
// changed online. Slice fields are copied whenever a snapshot crosses the API.
type Snapshot struct {
	Revision             uint64        `json:"revision"`
	MemoryIncludeCache   bool          `json:"memory_include_cache"`
	EnableGPU            bool          `json:"enable_gpu"`
	DetailedGPU          bool          `json:"detailed_gpu"`
	IncludeNics          []string      `json:"include_nics,omitempty"`
	ExcludeNics          []string      `json:"exclude_nics,omitempty"`
	IncludeMountpoints   []string      `json:"include_mountpoints,omitempty"`
	ReportInterval       time.Duration `json:"report_interval"`
	TrafficResetDay      uint32        `json:"traffic_reset_day"`
	RemoteControlEnabled bool          `json:"remote_control_enabled"`
}

type persistedState struct {
	Current  Snapshot  `json:"current"`
	Previous *Snapshot `json:"previous,omitempty"`
}

type Store struct {
	mu       sync.Mutex
	path     string
	current  atomic.Pointer[Snapshot]
	previous *Snapshot
}

var active atomic.Pointer[Store]

func FromFlags(config *flags_pkg.Config) Snapshot {
	interval := time.Duration(config.Interval * float64(time.Second))
	if interval == 0 {
		interval = 3 * time.Second
	}
	return Snapshot{
		MemoryIncludeCache:   config.MemoryIncludeCache,
		EnableGPU:            config.EnableGPU || config.LegacyDetailedGPU,
		DetailedGPU:          config.DetailedGPU || config.LegacyDetailedGPU,
		IncludeNics:          split(config.IncludeNics, ","),
		ExcludeNics:          split(config.ExcludeNics, ","),
		IncludeMountpoints:   split(config.IncludeMountpoints, ";"),
		ReportInterval:       interval,
		TrafficResetDay:      uint32(max(config.MonthRotate, 0)),
		RemoteControlEnabled: !config.DisableWebSsh && !config.DisableRemoteControl,
	}
}

func DefaultStatePath() string {
	dir, err := os.UserConfigDir()
	if err != nil || strings.TrimSpace(dir) == "" {
		return ".komari-runtime-config.json"
	}
	return filepath.Join(dir, "komari-agent", "runtime-config.json")
}

func New(initial Snapshot, path string) (*Store, error) {
	if path == "" {
		path = DefaultStatePath()
	}
	if err := validate(initial); err != nil {
		return nil, err
	}
	s := &Store{path: path}
	s.current.Store(clone(&initial))
	if err := s.load(); err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("load runtime config: %w", err)
	}
	return s, nil
}

func SetActive(store *Store) { active.Store(store) }

func Current() Snapshot {
	store := active.Load()
	if store == nil {
		return FromFlags(flags_pkg.GlobalConfig)
	}
	return store.Current()
}

func RemoteControlEnabled() bool { return Current().RemoteControlEnabled }

func (s *Store) Current() Snapshot { return *clone(s.current.Load()) }

func (s *Store) Previous() (Snapshot, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.previous == nil {
		return Snapshot{}, false
	}
	return *clone(s.previous), true
}

func (s *Store) Apply(desired *configv1.DesiredConfig) (Snapshot, error) {
	if desired == nil || desired.Runtime == nil {
		return s.Current(), errors.New("desired runtime config is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	current := s.current.Load()
	if desired.Revision == 0 {
		return *clone(current), errors.New("config revision must be greater than zero")
	}
	if desired.Revision < current.Revision {
		return *clone(current), fmt.Errorf("stale config revision %d; applied revision is %d", desired.Revision, current.Revision)
	}
	if desired.Revision == current.Revision {
		return *clone(current), nil
	}
	next, err := fromProto(*current, desired.Revision, desired.Runtime)
	if err != nil {
		return *clone(current), err
	}
	previous := clone(current)
	if err := s.persist(persistedState{Current: next, Previous: previous}); err != nil {
		return *clone(current), err
	}
	s.previous = previous
	s.current.Store(clone(&next))
	return *clone(&next), nil
}

func (s *Store) Rollback() (Snapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.previous == nil {
		return *clone(s.current.Load()), errors.New("no previous runtime config snapshot")
	}
	current := clone(s.current.Load())
	rolledBack := clone(s.previous)
	if err := s.persist(persistedState{Current: *rolledBack, Previous: current}); err != nil {
		return *current, err
	}
	s.previous = current
	s.current.Store(rolledBack)
	return *clone(rolledBack), nil
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.path)
	if err != nil {
		return err
	}
	var state persistedState
	if err := json.Unmarshal(data, &state); err != nil {
		return err
	}
	if err := validate(state.Current); err != nil {
		return err
	}
	s.current.Store(clone(&state.Current))
	s.previous = clone(state.Previous)
	return nil
}

func (s *Store) persist(state persistedState) error {
	if s.path == "" {
		return nil
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return fmt.Errorf("create runtime config directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".runtime-config-*")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if existing, err := os.ReadFile(s.path); err == nil {
		if err := writeBackup(s.path+".bak", existing); err != nil {
			return fmt.Errorf("backup runtime config: %w", err)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("read runtime config for backup: %w", err)
	}
	return os.Rename(tmpName, s.path)
}

func writeBackup(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".runtime-backup-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	defer os.Remove(name)
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(name, path)
}

func fromProto(base Snapshot, revision uint64, value *configv1.RuntimeConfig) (Snapshot, error) {
	result := *clone(&base)
	result.Revision = revision
	if value.MemoryIncludeCache != nil {
		result.MemoryIncludeCache = *value.MemoryIncludeCache
	}
	if value.EnableGpu != nil {
		return Snapshot{}, errors.New("GPU enablement is install-only and requires reinstalling the Agent")
	}
	if value.DetailedGpu != nil {
		result.DetailedGPU = *value.DetailedGpu
	}
	// Repeated fields are full replacements; the server always sends an entire desired snapshot.
	result.IncludeNics = clean(value.IncludeNics)
	result.ExcludeNics = clean(value.ExcludeNics)
	result.IncludeMountpoints = clean(value.IncludeMountpoints)
	if value.TrafficResetDay != nil {
		result.TrafficResetDay = *value.TrafficResetDay
	}
	if value.RemoteControlEnabled != nil {
		return Snapshot{}, errors.New("remote control is install-only and requires reinstalling the Agent")
	}
	if value.ReportInterval != nil {
		if err := value.ReportInterval.CheckValid(); err != nil {
			return Snapshot{}, fmt.Errorf("invalid report interval: %w", err)
		}
		result.ReportInterval = value.ReportInterval.AsDuration()
	}
	if err := validate(result); err != nil {
		return Snapshot{}, err
	}
	return result, nil
}

func validate(value Snapshot) error {
	if value.ReportInterval < minimumReportInterval || value.ReportInterval > maximumReportInterval {
		return fmt.Errorf("report interval must be between %s and %s", minimumReportInterval, maximumReportInterval)
	}
	if value.TrafficResetDay > 31 {
		return errors.New("traffic reset day must be between 0 and 31")
	}
	if value.DetailedGPU && !value.EnableGPU {
		return errors.New("detailed GPU reporting requires GPU reporting")
	}
	for name, values := range map[string][]string{
		"include_nics": value.IncludeNics, "exclude_nics": value.ExcludeNics, "include_mountpoints": value.IncludeMountpoints,
	} {
		if len(values) > 128 {
			return fmt.Errorf("%s contains more than 128 entries", name)
		}
		for _, item := range values {
			if len(item) > 512 {
				return fmt.Errorf("%s entry is too long", name)
			}
		}
	}
	return nil
}

func split(value, separator string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	return clean(strings.Split(value, separator))
}

func clean(values []string) []string {
	result := make([]string, 0, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			result = append(result, value)
		}
	}
	return result
}

func clone(value *Snapshot) *Snapshot {
	if value == nil {
		return nil
	}
	result := *value
	result.IncludeNics = append([]string(nil), value.IncludeNics...)
	result.ExcludeNics = append([]string(nil), value.ExcludeNics...)
	result.IncludeMountpoints = append([]string(nil), value.IncludeMountpoints...)
	return &result
}
