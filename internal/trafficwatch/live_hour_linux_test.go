package trafficwatch

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func TestLiveHourSurvivesRestartWithoutCountingOverlap(t *testing.T) {
	start := time.Now().UTC().Truncate(time.Hour)
	cfg := Config{StateDir: t.TempDir(), Interface: "eth0", Thresholds: defaultThresholds()}
	probe := &ebpfSampler{}
	makeSlice := func(offset time.Duration, bytes uint64) observation {
		return observation{sample: sample{
			Start: start.Add(offset), End: start.Add(offset + captureSlice), RXOverflow: bytes,
			Unknown: 1, UnknownIncluded: true,
		}}
	}
	read := func(p *processor) hourSummary {
		t.Helper()
		body, err := os.ReadFile(p.hourPath())
		if err != nil {
			t.Fatal(err)
		}
		var result hourSummary
		if err := json.Unmarshal(body, &result); err != nil {
			t.Fatal(err)
		}
		return result
	}
	p := newProcessor(probe, cfg)
	if err := p.addHour(makeSlice(0, 1000), start); err != nil {
		t.Fatal(err)
	}
	hour := read(p)
	if !hour.Through.Equal(start.Add(captureSlice)) || hour.Observed.RX != 1000 || hour.Partial ||
		hour.Coverage.CoveredSeconds != 30 || hour.Coverage.Unmatched != 1 || hour.Coverage.Scope != "interface_ip" {
		t.Fatalf("unexpected live hour %+v / %+v", hour, hour.Coverage)
	}

	p = newProcessor(probe, cfg)
	for _, sample := range []observation{makeSlice(0, 1000), makeSlice(15*time.Second, 777), makeSlice(90*time.Second, 2000)} {
		if err := p.addHour(sample, start); err != nil {
			t.Fatal(err)
		}
	}
	hour = read(p)
	if hour.Observed.RX != 3000 || hour.Coverage.CoveredSeconds != 60 || !hour.Partial ||
		!slices.Contains(hour.Coverage.Issues, "clock_overlap") || !slices.Contains(hour.Coverage.LatestIssues, "sample_gap") {
		t.Fatalf("overlap or gap was mishandled: %+v / %+v", hour, hour.Coverage)
	}
	if err := p.addHour(makeSlice(120*time.Second, 0), start); err != nil {
		t.Fatal(err)
	}
	hour = read(p)
	if !hour.Partial || slices.Contains(hour.Coverage.LatestIssues, "sample_gap") || hour.Coverage.CoveredSeconds != 90 {
		t.Fatalf("historical degradation was confused with current health: %+v", hour.Coverage)
	}
	root, err := os.OpenRoot(cfg.StateDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	upload, err := ReadUpload(root, filepath.Base(p.hourPath()), start.Add(-time.Hour), start.Add(3*time.Minute))
	if err != nil || upload.GetHour().GetCoverage().GetCoveredSeconds() != 90 || upload.GetHour().GetObserved().GetRxBytes() != 3000 {
		t.Fatalf("wrong handoff data: %v, %v", upload, err)
	}
}

func TestEBPFPeerMismatchCannotInflateObservedBytes(t *testing.T) {
	rx := map[netip.Addr]uint64{netip.MustParseAddr("192.0.2.100"): 300}
	frame := sample{RX: rx}
	applyEBPFTotals(&frame, 42, []ebpfTotals{{Bucket: 42, RX: 100, TX: 50, Unknown: 20, First: 1}})
	if frame.totals() != (Traffic{RX: 100, TX: 50}) || frame.Partial || !frame.PeerPartial || len(frame.RX) > 0 {
		t.Fatalf("peer detail overrode authoritative byte totals: %+v", frame)
	}
}
