package clientcore

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/statelock"
	metricsv1 "github.com/r11234567/komari-proto/gen/go/komari/metrics/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

const (
	trafficSampleInterval = 30 * time.Second
	// Allow time for transport and clock skew at the panel's 48-hour cutoff.
	trafficSpoolWindow = 48*time.Hour - time.Minute
	trafficSpoolBytes  = 16 << 20
	trafficUploadLimit = 32
)

type trafficSpoolState struct {
	Stream       string    `json:"stream"`
	Sequence     uint64    `json:"sequence"`
	Acknowledged uint64    `json:"acknowledged,omitempty"`
	LastObserved time.Time `json:"last_observed"`
	Gap          time.Time `json:"gap,omitempty"`
	Enabled      bool      `json:"enabled"`
}

type pendingTrafficSample struct {
	sample *metricsv1.TrafficSample
	size   int
}

type trafficSpool struct {
	mu      sync.Mutex
	dir     string
	state   trafficSpoolState
	pending []pendingTrafficSample
	bytes   int
}

func openTrafficSpool(dir string) (*trafficSpool, func(), error) {
	release, err := statelock.Acquire(filepath.Join(dir, "writer.lock"))
	if err != nil {
		return nil, nil, err
	}
	spool := &trafficSpool{dir: dir}
	if err := spool.load(); err != nil {
		release()
		return nil, nil, err
	}
	return spool, release, nil
}

func (s *trafficSpool) load() error {
	if err := hostops.ReadJSON(filepath.Join(s.dir, "state.json"), &s.state, false); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if s.state.Stream == "" {
		s.state.Stream = uuid.NewString()
		if err := s.saveState(); err != nil {
			return err
		}
	}
	entries, err := os.ReadDir(s.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".sample") {
			continue
		}
		seq, err := strconv.ParseUint(strings.TrimSuffix(entry.Name(), ".sample"), 10, 64)
		if err != nil || seq == 0 || !entry.Type().IsRegular() || entry.Name() != sampleFilename(seq) {
			return errors.New("invalid traffic spool file")
		}
		if seq <= s.state.Acknowledged {
			if err := os.Remove(filepath.Join(s.dir, entry.Name())); err != nil {
				return err
			}
			continue
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.Size() > 16<<10 || info.Size() > int64(trafficSpoolBytes-s.bytes) {
			return errors.New("traffic spool exceeds its size budget")
		}
		data, err := os.ReadFile(filepath.Join(s.dir, entry.Name()))
		if err != nil {
			return err
		}
		var sample metricsv1.TrafficSample
		if err := proto.Unmarshal(data, &sample); err != nil || sample.Sequence != seq || sample.ObservedAt == nil || sample.ObservedAt.CheckValid() != nil {
			return errors.New("invalid persisted traffic sample")
		}
		s.pending = append(s.pending, pendingTrafficSample{sample: &sample, size: len(data)})
		s.bytes += len(data)
		if seq > s.state.Sequence {
			s.state.Sequence = seq
			s.state.LastObserved = sample.ObservedAt.AsTime()
			if sample.GapStartedAt != nil && sample.GapStartedAt.AsTime().Equal(s.state.Gap) {
				s.state.Gap = time.Time{}
			}
		}
	}
	return s.saveState()
}

func sampleFilename(seq uint64) string { return fmt.Sprintf("%020d.sample", seq) }

func (s *trafficSpool) saveState() error {
	return hostops.WriteJSON(filepath.Join(s.dir, "state.json"), s.state, 0600)
}

func (s *trafficSpool) add(sample *metricsv1.TrafficSample) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	observed := sample.ObservedAt.AsTime()
	if !observed.After(s.state.LastObserved) {
		return errors.New("traffic sampling time did not advance")
	}
	if s.state.Sequence >= 1<<63-1 {
		return errors.New("traffic sample sequence exhausted")
	}
	sample.Sequence = s.state.Sequence + 1
	if err := s.prune(observed, proto.Size(sample)+32); err != nil {
		return err
	}
	if !s.state.Gap.IsZero() && !s.state.Gap.After(observed) {
		sample.GapStartedAt = timestamppb.New(s.state.Gap)
	}
	data, err := proto.Marshal(sample)
	if err != nil {
		return err
	}
	if len(data) > 16<<10 {
		return errors.New("traffic sample exceeds its size budget")
	}
	if err := hostops.AtomicWrite(filepath.Join(s.dir, sampleFilename(sample.Sequence)), data, 0600); err != nil {
		return err
	}
	s.state.Sequence = sample.Sequence
	s.state.LastObserved = observed
	s.pending = append(s.pending, pendingTrafficSample{sample: sample, size: len(data)})
	s.bytes += len(data)
	if sample.GapStartedAt != nil {
		s.state.Gap = time.Time{}
		return s.saveState()
	}
	return nil
}

func (s *trafficSpool) noteGap(start time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.state.LastObserved.IsZero() && s.state.LastObserved.Before(start) {
		start = s.state.LastObserved
	}
	return s.noteGapLocked(start)
}

func (s *trafficSpool) noteGapLocked(start time.Time) error {
	if s.state.Gap.IsZero() || start.Before(s.state.Gap) {
		s.state.Gap = start
	}
	return s.saveState()
}

func (s *trafficSpool) prune(now time.Time, incomingBytes int) error {
	cutoff := now.Add(-trafficSpoolWindow)
	var count, bytes int
	for _, entry := range s.pending {
		if !entry.sample.ObservedAt.AsTime().Before(cutoff) && s.bytes-bytes+incomingBytes <= trafficSpoolBytes {
			break
		}
		count++
		bytes += entry.size
	}
	if count == 0 {
		return nil
	}
	if err := s.noteGapLocked(s.pending[0].sample.ObservedAt.AsTime()); err != nil {
		return err
	}
	return s.removePrefix(count)
}

func (s *trafficSpool) batch(now time.Time) ([]*metricsv1.TrafficSample, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.prune(now, 0); err != nil {
		return nil, err
	}
	var samples []*metricsv1.TrafficSample
	for _, entry := range s.pending[:min(trafficUploadLimit, len(s.pending))] {
		samples = append(samples, entry.sample)
	}
	return samples, nil
}

func (s *trafficSpool) acknowledge(samples []*metricsv1.TrafficSample, through uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	index := slices.IndexFunc(samples, func(sample *metricsv1.TrafficSample) bool { return sample.Sequence == through })
	if index < 0 {
		return errors.New("panel returned a traffic ACK outside the submitted batch")
	}
	previous := s.state
	s.state.Enabled = true
	s.state.Acknowledged = max(s.state.Acknowledged, through)
	if err := s.saveState(); err != nil {
		s.state = previous
		return err
	}
	var count int
	for _, entry := range s.pending {
		if entry.sample.Sequence > through {
			break
		}
		count++
	}
	return s.removePrefix(count)
}

func (s *trafficSpool) removePrefix(count int) error {
	for range count {
		entry := s.pending[0]
		if err := os.Remove(filepath.Join(s.dir, sampleFilename(entry.sample.Sequence))); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		s.bytes -= entry.size
		s.pending[0] = pendingTrafficSample{}
		s.pending = s.pending[1:]
	}
	return statelock.SyncDirectory(s.dir)
}
