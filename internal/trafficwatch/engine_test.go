package trafficwatch

import (
	"net/netip"
	"testing"
	"time"
)

func TestTrafficEngineKeepsCompletedBurstAndExplainsSplitProxy(t *testing.T) {
	start := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	e := newEngine("edge0", "inbound", "fixture", thresholds{Fast: 300, Slow: 1000, Sustained: 1500})
	remote := netip.MustParseAddr("2001:db8::2")
	add := func(rx, tx uint64, service evidence) snapshot {
		t.Helper()
		s := sample{Start: start, End: start.Add(captureSlice), RX: map[netip.Addr]uint64{remote: rx}, TX: map[netip.Addr]uint64{remote: tx}}
		start = s.End
		result, err := e.add(observation{sample: s, evidence: service})
		if err != nil {
			t.Fatal(err)
		}
		return result
	}
	for range 8 {
		if got := add(10, 1000, evidence{xray: proxyTraffic{InDown: 1000, OutDown: 1000}}); got.ID != "" {
			t.Fatalf("legitimate asymmetric traffic triggered: %+v", got)
		}
	}
	for range 4 {
		if got := add(900, 0, evidence{services: map[string]Traffic{"system_update": {RX: 900}}}); got.ID != "" {
			t.Fatalf("update triggered: %+v", got)
		}
	}
	// One slice arrived without a corresponding service sample. It must
	// expire from the detector window without erasing adjacent real evidence.
	add(0, 0, evidence{partial: true})
	add(0, 0, evidence{})
	add(0, 0, evidence{})
	burstStart := start
	add(900, 0, evidence{})
	got := add(0, 0, evidence{})
	if got.Reason != "fast_unexplained_ingress" || got.Sampler != "fixture" ||
		len(got.Sources) != 1 || got.Sources[0] != (peer{remote, 900}) ||
		!got.TriggeredAt.After(burstStart.Add(captureSlice)) || got.Complete {
		t.Fatalf("unexpected trigger: %+v", got)
	}
	for range int(followWindow / captureSlice) {
		next := add(0, 0, evidence{})
		if next.ID != got.ID {
			t.Fatalf("incident did not keep its identifier: %+v", next)
		}
		if next.End.Equal(got.TriggeredAt.Add(followWindow)) && !next.Complete {
			t.Fatal("incident was not finalized")
		}
	}
}

func TestTrafficEngineSustainedEgressKeepsOnlyCoveredHistory(t *testing.T) {
	start := time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC)
	e := newEngine("edge0", "both", "fixture", thresholds{Fast: 3000, Slow: 5000, Sustained: 1000})
	remote := netip.MustParseAddr("203.0.113.8")
	var got snapshot
	for range 60 {
		var err error
		got, err = e.add(observation{sample: sample{
			Start: start, End: start.Add(captureSlice), TX: map[netip.Addr]uint64{remote: 20},
		}})
		if err != nil {
			t.Fatal(err)
		}
		start = start.Add(captureSlice)
	}
	if got.Reason != "sustained_unexplained_egress" || got.End.Sub(got.Start) != evidenceWindow ||
		len(got.Destinations) != 1 || got.Destinations[0].Bytes != 600 {
		t.Fatalf("unexpected sustained evidence: %+v", got)
	}
}
