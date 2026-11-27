package trafficwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/komari-monitor/komari-agent/core/hostops"
	"github.com/komari-monitor/komari-agent/core/statelock"
)

// Run starts the explicitly configured local pilot. The monitoring Agent does
// not start this command or share its privileges or credentials with it.
func Run(ctx context.Context, cfg Config) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.StateDir, 0o700); err != nil {
		return err
	}
	if err := privateDirectory(cfg.StateDir); err != nil {
		return err
	}
	release, err := statelock.Acquire(filepath.Join(cfg.StateDir, "collector.lock"))
	if err != nil {
		return err
	}
	defer release()
	if err := pruneArchive(cfg.StateDir, time.Now()); err != nil {
		return err
	}
	if cfg.UploadDir != "" {
		if err := pruneArchive(cfg.UploadDir, time.Now()); err != nil {
			return err
		}
	}
	if cfg.captureBackend() == "nfpcapd" {
		return runNFDump(ctx, cfg)
	}
	source, err := startEBPF(cfg)
	if err != nil {
		return err
	}
	defer source.Close()
	log.Printf("Traffic sampler ebpf attached to %s", cfg.Interface)
	return runSampler(ctx, cfg, source, nil, nil)
}

func runNFDump(ctx context.Context, cfg Config) error {
	if err := checkScratch(cfg.ScratchDir); err != nil {
		return err
	}
	releaseScratch, err := statelock.Acquire(filepath.Join(cfg.ScratchDir, "collector.lock"))
	if err != nil {
		return err
	}
	defer releaseScratch()
	scratch, err := os.OpenRoot(cfg.ScratchDir)
	if err != nil {
		return err
	}
	defer scratch.Close()
	dirs, err := os.ReadDir(cfg.ScratchDir)
	if err != nil {
		return err
	}
	for _, dir := range dirs {
		if dir.IsDir() && strings.HasPrefix(dir.Name(), "flow-run-") {
			if err := scratch.RemoveAll(dir.Name()); err != nil {
				return err
			}
		}
	}
	dir, err := os.MkdirTemp(cfg.ScratchDir, "flow-run-")
	if err != nil {
		return err
	}
	defer scratch.RemoveAll(filepath.Base(dir))
	if err := os.WriteFile(filepath.Join(dir, "empty.conf"), nil, 0o600); err != nil {
		return err
	}
	ctx, cancel := context.WithCancel(ctx)
	source, done, err := startNFDump(ctx, cfg, dir)
	if err != nil {
		cancel()
		return err
	}
	return runSampler(ctx, cfg, source, done, cancel)
}

func runSampler(ctx context.Context, cfg Config, source sampler, done <-chan error, cancel context.CancelFunc) error {
	waited := false
	if done != nil {
		defer func() {
			cancel()
			if !waited {
				<-done
			}
		}()
	}
	processor := newProcessor(source, cfg)
	defer processor.counters.close()
	processor.recoverHandoff()
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return processor.flush()
		case err := <-done:
			waited = true
			if ctx.Err() != nil {
				return processor.flush()
			}
			if err == nil {
				err = errors.New("collector stopped unexpectedly")
			}
			return errors.Join(fmt.Errorf("%s: %w", source.Name(), err), processor.flush())
		case <-ticker.C:
			if err := processor.tick(ctx, time.Now().UTC()); err != nil {
				return errors.Join(err, processor.flush())
			}
		}
	}
}

type processor struct {
	cfg          Config
	source       sampler
	engine       *engine
	counters     localCounters
	attribution  bool
	evidence     map[time.Time]evidence
	boundary     time.Time
	startedAt    time.Time
	hour         hourSummary
	eventID      string
	eventShift   time.Duration
	prunedAt     time.Time
	retryHandoff bool
}

func newProcessor(src sampler, cfg Config) *processor {
	legs := "both"
	if cfg.Xray != nil {
		legs = cfg.Xray.PublicLegs
	}
	attribution := cfg.Xray != nil || slices.ContainsFunc(cfg.Services, func(service ServiceConfig) bool {
		return service.PublicInterfaceOnly
	})
	return &processor{cfg: cfg, source: src, engine: newEngine(cfg.Interface, legs, src.Name(), cfg.Thresholds),
		attribution: attribution, evidence: make(map[time.Time]evidence)}
}

func (p *processor) tick(ctx context.Context, now time.Time) error {
	captureNow := now
	if clock, ok := p.source.(interface{ captureTime() (time.Time, error) }); ok {
		var err error
		captureNow, err = clock.captureTime()
		if err != nil {
			return err
		}
	}
	if p.startedAt.IsZero() {
		p.startedAt = captureNow
	}
	boundary := captureNow.Truncate(captureSlice)
	// Keep joins and detection on the sampler clock. Translate persisted
	// timestamps in whole slices to preserve UTC hourly boundaries.
	wallShift := now.Sub(captureNow).Round(captureSlice)
	if boundary.After(p.boundary) {
		last := p.boundary
		p.boundary = boundary
		stats := p.counters.read(ctx, p.cfg)
		if last.Add(captureSlice).Equal(boundary) {
			p.evidence[last] = stats
		}
		for stamp := range p.evidence {
			if stamp.Before(boundary.Add(-evidenceWindow)) {
				delete(p.evidence, stamp)
			}
		}
	}
	slices, err := p.source.Next()
	if err != nil {
		log.Printf("Traffic flow slice incomplete: %v", err)
	}
	for _, frame := range slices {
		stats, available := p.evidence[frame.Start]
		delete(p.evidence, frame.Start)
		if !available {
			stats.partial = p.attribution
			stats.servicePartial = len(p.cfg.Services) != 0
		}
		o := observation{sample: frame, evidence: stats}
		event, err := p.engine.add(o)
		if err != nil {
			return err
		}
		if event.ID != "" {
			if event.ID != p.eventID {
				p.eventID, p.eventShift = event.ID, wallShift
			}
			event.shift(p.eventShift)
			data, err := json.Marshal(event)
			if err != nil {
				return err
			}
			if len(data)+1 > maxSnapshotBytes {
				return errors.New("traffic snapshot exceeded the byte limit")
			}
			if err := p.saveRecord("event-"+event.ID+".json", append(data, '\n')); err != nil {
				return err
			}
		}
		o.Start, o.End = o.Start.Add(wallShift), o.End.Add(wallShift)
		if err := p.addHour(o, p.startedAt.Add(wallShift)); err != nil {
			return err
		}
	}
	if now.Sub(p.prunedAt) >= time.Minute {
		p.prunedAt = now
		if p.cfg.UploadDir != "" {
			if p.retryHandoff {
				p.recoverHandoff()
			}
			return errors.Join(pruneArchive(p.cfg.StateDir, now), pruneArchive(p.cfg.UploadDir, now))
		}
		return pruneArchive(p.cfg.StateDir, now)
	}
	return nil
}

type hourSummary struct {
	Hour        time.Time          `json:"hour_utc"`
	StartedAt   time.Time          `json:"started_at,omitzero"`
	Through     time.Time          `json:"through"`
	Observed    Traffic            `json:"observed"`
	Services    map[string]Traffic `json:"services"`
	Unexplained Traffic            `json:"unexplained"`
	Partial     bool               `json:"partial"`
}

func (p *processor) addHour(o observation, startedAt time.Time) error {
	hour := o.Start.Truncate(time.Hour)
	if !p.hour.Hour.Equal(hour) {
		if err := p.flush(); err != nil {
			return err
		}
		p.hour = hourSummary{Hour: hour, StartedAt: maxTime(o.Start, startedAt), Through: hour, Services: make(map[string]Traffic)}
		body, err := readBoundedFile(p.hourPath(), maxSnapshotBytes)
		if err == nil {
			if err := json.Unmarshal(body, &p.hour); err != nil || !p.hour.Hour.Equal(hour) || p.hour.Services == nil {
				return errors.New("invalid saved traffic hour")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if !o.End.After(p.hour.Through) {
		p.hour.Partial = true // UTC moved into an already published interval.
		return nil
	}
	p.hour.Partial = p.hour.Partial || !p.hour.Through.Equal(o.Start) || o.Partial || o.partial || o.servicePartial || o.Unknown != 0
	p.hour.Through = o.End
	p.hour.Observed = p.hour.Observed.add(o.totals())
	w := observationWindow{Services: make(map[string]Traffic)}
	w.add(o)
	p.hour.Unexplained = p.hour.Unexplained.add(w.unexplained(p.engine.legs))
	if p.cfg.Xray != nil {
		p.hour.Services["xray"] = p.hour.Services["xray"].add(o.xray.explained(p.engine.legs))
	}
	for name, count := range o.serviceTotals {
		p.hour.Services[name] = p.hour.Services[name].add(count)
	}
	if o.End.Equal(hour.Add(time.Hour)) {
		return p.flush()
	}
	return nil
}

func (p *processor) hourPath() string {
	return filepath.Join(p.cfg.StateDir, "hour-"+p.hour.Hour.Format("20060102T15")+".json")
}

func (p *processor) flush() error {
	if !p.hour.Through.After(maxTime(p.hour.Hour, p.hour.StartedAt)) {
		return nil
	}
	data, err := json.Marshal(p.hour)
	if err != nil {
		return err
	}
	return p.saveRecord(filepath.Base(p.hourPath()), append(data, '\n'))
}

func (p *processor) saveRecord(name string, body []byte) error {
	if err := hostops.AtomicWrite(filepath.Join(p.cfg.StateDir, name), body, 0o600); err != nil {
		return err
	}
	if p.cfg.UploadDir != "" {
		if err := hostops.AtomicWrite(filepath.Join(p.cfg.UploadDir, name), body, 0o640); err != nil {
			// The local archive succeeds independently of the handoff.
			p.retryHandoff = true
			log.Printf("Traffic evidence handoff unavailable: %v", err)
		}
	}
	return nil
}

func (p *processor) recoverHandoff() {
	if p.cfg.UploadDir == "" {
		return
	}
	p.retryHandoff = false
	files, err := os.ReadDir(p.cfg.StateDir)
	if err != nil {
		p.retryHandoff = true
		log.Printf("Could not list traffic evidence for handoff: %v", err)
		return
	}
	for _, file := range files {
		name := file.Name()
		if !file.Type().IsRegular() || !strings.HasSuffix(name, ".json") ||
			(!strings.HasPrefix(name, "hour-") && !strings.HasPrefix(name, "event-")) {
			continue
		}
		source, err := file.Info()
		if err != nil {
			p.retryHandoff = true
			continue
		}
		destination := filepath.Join(p.cfg.UploadDir, name)
		if published, err := os.Lstat(destination); err == nil && published.Mode().IsRegular() && !published.ModTime().Before(source.ModTime()) {
			continue
		}
		body, err := readBoundedFile(filepath.Join(p.cfg.StateDir, name), maxSnapshotBytes)
		if err == nil {
			err = hostops.AtomicWrite(destination, body, 0o640)
		}
		if err != nil {
			p.retryHandoff = true
			log.Printf("Could not restore traffic evidence handoff: %v", err)
		}
	}
}

func pruneArchive(dir string, now time.Time) error {
	files, err := os.ReadDir(dir)
	if err != nil {
		return err
	}
	type saved struct {
		path    string
		expires time.Time
	}
	var events []saved
	for _, file := range files {
		name := file.Name()
		if !file.Type().IsRegular() || !strings.HasSuffix(name, ".json") {
			continue
		}
		path := filepath.Join(dir, name)
		switch {
		case strings.HasPrefix(name, "hour-"):
			hour, err := time.Parse("20060102T15", strings.TrimSuffix(strings.TrimPrefix(name, "hour-"), ".json"))
			if err == nil && !hour.Add(baselineDays*24*time.Hour).After(now) {
				if err := os.Remove(path); err != nil {
					return err
				}
			}
		case strings.HasPrefix(name, "event-"):
			if _, err := uuid.Parse(strings.TrimSuffix(strings.TrimPrefix(name, "event-"), ".json")); err != nil {
				continue
			}
			var record snapshot
			body, err := readBoundedFile(path, maxSnapshotBytes)
			if err != nil || json.Unmarshal(body, &record) != nil || !record.ExpiresAt.After(now) {
				if err := os.Remove(path); err != nil {
					return err
				}
				continue
			}
			events = append(events, saved{path: path, expires: record.ExpiresAt})
		}
	}
	slices.SortFunc(events, func(a, b saved) int { return a.expires.Compare(b.expires) })
	const maxEvents = 288
	for _, item := range events[:max(0, len(events)-maxEvents)] {
		if err := os.Remove(item.path); err != nil {
			return err
		}
	}
	return nil
}
