package trafficwatch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

type fixtureCaptureClock struct {
	now    time.Time
	frames []sample
}

func (*fixtureCaptureClock) Name() string                      { return "ebpf" }
func (s *fixtureCaptureClock) captureTime() (time.Time, error) { return s.now, nil }
func (s *fixtureCaptureClock) Next() ([]sample, error) {
	frames := s.frames
	s.frames = nil
	return frames, nil
}

func TestProcessorJoinsByCaptureClockAfterWallClockJump(t *testing.T) {
	boundary := time.Date(2026, 11, 26, 9, 30, 0, 0, time.UTC)
	source := &fixtureCaptureClock{now: boundary}
	p := newProcessor(source, Config{StateDir: t.TempDir(), Thresholds: thresholds{Fast: 300}})
	p.attribution = true
	if err := p.tick(context.Background(), boundary); err != nil {
		t.Fatal(err)
	}
	source.now = boundary.Add(captureSlice)
	source.frames = []sample{{Start: boundary, End: source.now}}
	wallNow := source.now.Add(-time.Hour)
	if err := p.tick(context.Background(), wallNow); err != nil {
		t.Fatal(err)
	}
	if len(p.engine.ring) != 1 || p.engine.ring[0].partial || !p.engine.ring[0].Start.Equal(boundary) ||
		!p.hour.Through.Equal(wallNow) {
		t.Fatalf("clock jump broke the detector join or exposed stale UTC: %+v, %+v", p.engine.ring, p.hour)
	}
}

func TestServiceLifecycleAndPublicCredit(t *testing.T) {
	configured := []ServiceConfig{
		{Unit: "update.service", Group: "system_update", PublicInterfaceOnly: true},
		{Unit: "proxy.service", Group: "other_proxy"},
	}
	var c localCounters
	add := func(update counterValue, proxy uint64) evidence {
		t.Helper()
		result := evidence{services: make(map[string]Traffic), serviceTotals: make(map[string]Traffic)}
		c.addServices(&result, configured, map[string]counterValue{
			"update.service": update, "proxy.service": {instance: "proxy", n: Traffic{RX: proxy}},
		})
		return result
	}
	add(counterValue{}, 0)
	started := add(counterValue{instance: "first", n: Traffic{RX: 12}}, 9000)
	if started.partial || started.services["system_update"].RX != 12 || started.services["other_proxy"].RX != 0 ||
		started.serviceTotals["other_proxy"].RX != 9000 {
		t.Fatalf("normal start or local proxy accounting was misclassified: %+v", started)
	}
	if stopped := add(counterValue{}, 9000); stopped.partial {
		t.Fatalf("normal stop marked the slice incomplete: %+v", stopped)
	}
	if restarted := add(counterValue{instance: "next", n: Traffic{RX: 15}}, 9000); restarted.partial ||
		restarted.services["system_update"].RX != 15 {
		t.Fatalf("new invocation did not accrue from zero: %+v", restarted)
	}
	if rollback := add(counterValue{instance: "next", n: Traffic{RX: 5}}, 9000); !rollback.partial {
		t.Fatal("same invocation counter rollback did not mark a gap")
	}
}

func TestNFDumpKeepsLateHeavyPeerAtCapacity(t *testing.T) {
	local := netip.MustParseAddr("192.0.2.1")
	const times = "2026-11-26 09:30:06,2026-11-26 09:30:07,"
	var rows strings.Builder
	for i := range maxPeers {
		fmt.Fprintf(&rows, "%s198.51.%d.%d,192.0.2.1,1\n", times, i>>8, i&255)
	}
	fmt.Fprintf(&rows, "%s203.0.113.80,192.0.2.1,65536\n", times)
	stamp := time.Date(2026, 11, 26, 9, 30, 0, 0, time.UTC)
	frames, err := readFlows(strings.NewReader(rows.String()), stamp, map[netip.Addr]bool{local: true})
	frame := frames[stamp]
	if err != nil || frame.RX[netip.MustParseAddr("203.0.113.80")] != 65536 || frame.RXOverflow != 1 ||
		frame.totals().RX != maxPeers+65536 {
		t.Fatalf("nfdump lost the late heavy peer or miscounted overflow: %v, %d", err, frame.totals().RX)
	}
}

func TestNFDumpPreservesDirectionIPv6AndUnknown(t *testing.T) {
	local := map[netip.Addr]bool{netip.MustParseAddr("192.0.2.1"): true, netip.MustParseAddr("2001:db8::1"): true}
	const times = "2026-11-26 09:30:06.604,2026-11-26 09:30:07.604,"
	input := times + "2001:db8:abcd:ef00:1234:2345:3456:4567,2001:db8::1,1234567\n" +
		times + "192.0.2.1,203.0.113.8,999\n" + times + "192.0.2.2,192.0.2.3,100\n"
	start := time.Date(2026, 11, 26, 9, 30, 0, 0, time.UTC)
	frames, err := readFlows(strings.NewReader(input), start.Add(exportDelay), local)
	out := frames[start]
	if err != nil || out.totals() != (Traffic{RX: 1234567, TX: 999}) || out.Unknown != 100 {
		t.Fatalf("decoded %#v: %v", out, err)
	}
	if n := out.RX[netip.MustParseAddr("2001:db8:abcd:ef00:1234:2345:3456:4567")]; n != 1234567 {
		t.Fatal("lost full IPv6 address")
	}
}

func TestNFDumpIdleSliceStillCountsAsCovered(t *testing.T) {
	frames, err := readFlows(strings.NewReader("No matching flows\n"), time.Now(), nil)
	if err != nil || len(frames) != 0 {
		t.Fatalf("idle export decoded as %#v: %v", frames, err)
	}
}

func TestNFDumpVersionWithIdleFlowLossIsRejected(t *testing.T) {
	if checkCaptureVersion("nfpcapd: Version: 1.7.10-release options: lz4 ZSTD") == nil ||
		checkCaptureVersion("nfpcapd: Version: 1.7.5-release Options: NSEL-NEL") != nil {
		t.Fatal("version preflight did not isolate the reproduced 1.7.10 idle-flow defect")
	}
}

func TestNFDumpJoinsDelayedExportsByPacketTime(t *testing.T) {
	start := time.Date(2026, 11, 26, 9, 30, 0, 0, time.UTC)
	sampler := nfdumpSampler{pending: make(map[time.Time]sample)}
	remote := netip.MustParseAddr("192.0.2.2")
	for i := range 3 {
		stamp := start.Add(time.Duration(i) * captureSlice)
		got := sampler.accept(stamp, nil, false)
		if len(got) != 1 {
			t.Fatalf("unexpected initial observations: %+v", got)
		}
	}
	packetAt := start.Add(captureSlice + time.Second)
	record := "2026-11-26 09:30:31.000,2026-11-26 09:30:31.000,192.0.2.2,192.0.2.1,1234567\n"
	exportStart := start.Add(captureSlice + exportDelay)
	frames, err := readFlows(strings.NewReader(record), exportStart, map[netip.Addr]bool{netip.MustParseAddr("192.0.2.1"): true})
	if err != nil {
		t.Fatal(err)
	}
	got := sampler.accept(exportStart, frames, false)
	if len(got) != 1 || got[0].Partial || got[0].RX[remote] != 1234567 ||
		!got[0].Start.Equal(start.Add(captureSlice)) || !got[0].LastPacket.Equal(packetAt) {
		t.Fatalf("delayed flow matched the wrong accounting slice: %+v", got)
	}
}

func TestXrayPolicyRejectsUserStats(t *testing.T) {
	path := filepath.Join(t.TempDir(), "xray-policy.json")
	config := XrayConfig{PolicyFile: path}
	for _, user := range []string{"false", "true"} {
		body := `{"stats":{},"policy":{"system":{"statsInboundUplink":true,"statsInboundDownlink":true,"statsOutboundUplink":true,"statsOutboundDownlink":true},"levels":{"0":{"statsUserOnline":` + user + `}}}}`
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := config.checkPolicy(); (err != nil) != (user == "true") {
			t.Fatalf("statsUserOnline=%s: %v", user, err)
		}
	}
}

func TestPruneKeepsUnexpiredSnapshotAndIgnoresOtherFiles(t *testing.T) {
	dir := t.TempDir()
	now := time.Now().UTC()
	write := func(name string, expires time.Time) string {
		t.Helper()
		path := filepath.Join(dir, name)
		body, err := json.Marshal(snapshot{ExpiresAt: expires})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, body, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	expired := write("event-"+uuid.NewString()+".json", now)
	active := write("event-"+uuid.NewString()+".json", now.Add(time.Minute))
	other := write("event-unrelated.json", now)
	if err := pruneArchive(dir, now); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(expired); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expired snapshot was retained: %v", err)
	}
	for _, path := range []string{active, other} {
		if _, err := os.Stat(path); err != nil {
			t.Fatal(err)
		}
	}
}
