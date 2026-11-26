package trafficwatch

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
)

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
