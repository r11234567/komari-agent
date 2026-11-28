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

func Run(ctx context.Context, cfg Config) error {
	return RunWithReady(ctx, cfg, nil)
}

// RunWithReady reports when the kernel sampler has attached. The manual
// collector uses Run and does not need a readiness callback.
func RunWithReady(ctx context.Context, cfg Config, ready func()) error {
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
	if ready != nil {
		ready()
	}
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
	cfg              Config
	source           sampler
	engine           *engine
	counters         localCounters
	attribution      bool
	evidence         map[time.Time]evidence
	boundary         time.Time
	startedAt        time.Time
	hour             hourSummary
	eventID          string
	eventShift       time.Duration
	prunedAt         time.Time
	retryHandoff     bool
	publishedThrough time.Time
	readFailed       bool
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
		if len(slices) == 0 {
			p.readFailed = true
		}
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
	Coverage    *hourCoverage      `json:"coverage,omitempty"`
	Attributed  map[string]Traffic `json:"attributed_services,omitempty"`
}

type hourCoverage struct {
	Sampler        string    `json:"sampler"`
	Interface      string    `json:"interface"`
	ObservedSince  time.Time `json:"observed_since"`
	CoveredSeconds uint32    `json:"covered_seconds"`
	Sources        []string  `json:"sources,omitempty"`
	Issues         []string  `json:"issues,omitempty"`
	LatestIssues   []string  `json:"latest_issues,omitempty"`
	Unmatched      uint64    `json:"unmatched_ip_bytes,omitempty"`
	InvalidIP      uint64    `json:"invalid_ip_bytes,omitempty"`
	Scope          string    `json:"observation_scope"`
	LastScope      string    `json:"last_scope"`
}

func (p *processor) addHour(o observation, startedAt time.Time) error {
	hour := o.Start.Truncate(time.Hour)
	if !p.hour.Hour.Equal(hour) {
		if err := p.flush(); err != nil {
			return err
		}
		p.hour = hourSummary{Hour: hour, StartedAt: maxTime(o.Start, startedAt), Through: hour, Services: make(map[string]Traffic)}
		p.publishedThrough = time.Time{}
		body, err := readBoundedFile(p.hourPath(), maxSnapshotBytes)
		if err == nil {
			if err := json.Unmarshal(body, &p.hour); err != nil || !p.hour.Hour.Equal(hour) || p.hour.Services == nil {
				return errors.New("invalid saved traffic hour")
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	if o.Start.Before(p.hour.Through) {
		// A rollback can move a slice into a previously sealed interval.
		// Its bytes cannot be split safely across the overlap.
		if p.hour.Coverage != nil {
			p.hour.Coverage.Issues = appendIssue(p.hour.Coverage.Issues, "clock_overlap")
		}
		return nil
	}
	scope := "host_addresses"
	if s, ok := p.source.(interface{ observationScope() string }); ok {
		scope = s.observationScope()
	}
	if p.hour.Coverage == nil {
		p.hour.Coverage = &hourCoverage{Sampler: p.source.Name(), Interface: p.cfg.Interface, ObservedSince: o.Start, Scope: scope, LastScope: scope}
		if p.hour.Through.After(hour) {
			p.hour.Coverage.Issues = []string{"legacy_prefix"}
			p.hour.Coverage.Scope = "mixed"
		}
	}
	coverage := p.hour.Coverage
	coverage.LatestIssues = nil
	if p.readFailed {
		coverage.LatestIssues = append(coverage.LatestIssues, "read_error")
		p.readFailed = false
	}
	if coverage.Sampler != p.source.Name() || coverage.Interface != p.cfg.Interface || coverage.LastScope != scope {
		coverage.Sampler, coverage.Interface = p.source.Name(), p.cfg.Interface
		coverage.Scope, coverage.LastScope = "mixed", scope
		coverage.LatestIssues = append(coverage.LatestIssues, "collector_changed")
	}
	if !p.hour.Through.Equal(o.Start) {
		issue := "sample_gap"
		if p.hour.Through.Equal(hour) {
			issue = "started_mid_hour"
		}
		coverage.LatestIssues = append(coverage.LatestIssues, issue)
	}
	if o.Partial {
		coverage.LatestIssues = append(coverage.LatestIssues, "incomplete_slice")
	} else {
		coverage.CoveredSeconds += uint32(o.End.Sub(o.Start) / time.Second)
	}
	if o.partial || o.servicePartial {
		coverage.LatestIssues = append(coverage.LatestIssues, "attribution_unavailable")
	}
	if o.Unknown != 0 {
		coverage.Unmatched += o.Unknown
		issue := "unmatched_ip"
		if !o.UnknownIncluded {
			issue = "unmatched_excluded"
		}
		coverage.LatestIssues = append(coverage.LatestIssues, issue)
	}
	if o.InvalidIP != 0 {
		coverage.InvalidIP += o.InvalidIP
		coverage.LatestIssues = append(coverage.LatestIssues, "invalid_ip")
	}
	if o.PeerPartial {
		coverage.LatestIssues = append(coverage.LatestIssues, "peer_detail_limited")
	}
	for _, issue := range coverage.LatestIssues {
		coverage.Issues = appendIssue(coverage.Issues, issue)
		// Outside-address packets describe the capture scope. A multicast,
		// transit or other address is not by itself a missing host sample.
		p.hour.Partial = p.hour.Partial || issue == "sample_gap" || issue == "started_mid_hour" || issue == "incomplete_slice" || issue == "invalid_ip" || issue == "collector_changed"
	}
	coverage.Sources = p.attributionSources()
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
	return p.flush()
}

func appendIssue(issues []string, issue string) []string {
	if !slices.Contains(issues, issue) {
		return append(issues, issue)
	}
	return issues
}

func (p *processor) attributionSources() []string {
	var sources []string
	if p.cfg.Xray != nil {
		sources = append(sources, "xray")
	}
	for _, service := range p.cfg.Services {
		sources = appendIssue(sources, service.Group)
	}
	return sources
}

func (p *processor) hourPath() string {
	return filepath.Join(p.cfg.StateDir, "hour-"+p.hour.Hour.Format("20060102T15")+".json")
}

func (p *processor) flush() error {
	if !p.hour.Through.After(maxTime(p.hour.Hour, p.hour.StartedAt)) || p.hour.Through.Equal(p.publishedThrough) {
		return nil
	}
	data, err := json.Marshal(p.hour)
	if err != nil {
		return err
	}
	if err := p.saveRecord(filepath.Base(p.hourPath()), append(data, '\n')); err != nil {
		return err
	}
	p.publishedThrough = p.hour.Through
	return nil
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
