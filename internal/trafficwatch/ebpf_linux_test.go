package trafficwatch

import (
	"net/netip"
	"testing"
)

func TestEBPFPeerOverflowPreservesTriggerTotals(t *testing.T) {
	peer := netip.MustParseAddr("192.0.2.2")
	frame := sample{RX: map[netip.Addr]uint64{peer: 100}, TX: make(map[netip.Addr]uint64)}
	applyEBPFTotals(&frame, 42, []ebpfTotals{
		{Bucket: 42, RX: 120, First: 5, Last: 30},
		{Bucket: 42, RX: 80, TX: 15, First: 10, Last: 45},
		{Bucket: 10, RX: 123456, First: 1, Last: 2},
	})
	if got := frame.totals(); got != (Traffic{RX: 200, TX: 15}) || frame.Partial {
		t.Fatalf("overflow affected detector totals or coverage: %+v", frame)
	}
	if frame.RXOverflow != 100 || frame.TXOverflow != 15 || frame.FirstPacket.UnixNano() != 5 || frame.LastPacket.UnixNano() != 45 {
		t.Fatalf("incorrect overflow or time range: %+v", frame)
	}
	incident := incident{rx: make(map[netip.Addr]uint64), tx: make(map[netip.Addr]uint64)}
	incident.add(observation{sample: frame})
	if summary := incident.record(); !summary.Partial || summary.Other != (Traffic{RX: 100, TX: 15}) {
		t.Fatalf("snapshot did not flag missing peer details: %+v", summary)
	}
}
