package trafficwatch

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"time"
)

const (
	maxSnapshotBytes = 64 << 10
	snapshotTTL      = 72 * time.Hour
	topPeers         = 20
	captureSlice     = 30 * time.Second
	maxPeers         = 4096
)

type Traffic struct {
	RX uint64 `json:"rx_bytes"`
	TX uint64 `json:"tx_bytes"`
}

func (a Traffic) add(b Traffic) Traffic {
	return Traffic{RX: a.RX + b.RX, TX: a.TX + b.TX}
}

type peer struct {
	Address netip.Addr `json:"ip"`
	Bytes   uint64     `json:"bytes"`
}

// sample is a sealed observation at one network boundary. An alternative
// sampler can produce the same slices without using nfdump or subprocesses.
type sample struct {
	Start, End              time.Time
	FirstPacket, LastPacket time.Time
	RX, TX                  map[netip.Addr]uint64
	RXOverflow, TXOverflow  uint64
	Unknown                 uint64
	Partial                 bool
}

type sampler interface {
	Name() string
	Next() ([]sample, error)
}

func (s sample) totals() Traffic {
	return Traffic{RX: total(s.RX) + s.RXOverflow, TX: total(s.TX) + s.TXOverflow}
}

func total(peers map[netip.Addr]uint64) (sum uint64) {
	for _, n := range peers {
		sum += n
	}
	return sum
}

type snapshot struct {
	ID                 string    `json:"id"`
	Reason             string    `json:"reason"`
	Interface          string    `json:"interface"`
	Sampler            string    `json:"sampler"`
	TriggeredAt        time.Time `json:"triggered_at"`
	Start              time.Time `json:"start"`
	End                time.Time `json:"end"`
	ExpiresAt          time.Time `json:"expires_at"`
	FirstPacket        time.Time `json:"first_packet_at,omitzero"`
	LastPacket         time.Time `json:"last_packet_at,omitzero"`
	SpansSlices        bool      `json:"flows_span_slices"`
	Observed           Traffic   `json:"observed"`
	TriggerUnexplained Traffic   `json:"trigger_unexplained"`
	Unclassified       uint64    `json:"unclassified_bytes"`
	Partial            bool      `json:"partial"`
	Complete           bool      `json:"complete"`
	Sources            []peer    `json:"ingress_sources"`
	Destinations       []peer    `json:"egress_destinations"`
	Other              Traffic   `json:"other"`
}

type evidence struct {
	xray     proxyTraffic
	services map[string]Traffic
	partial  bool
}

type observation struct {
	sample
	evidence
}

func rankPeers(counts map[netip.Addr]uint64) ([]peer, uint64) {
	ranked := make([]peer, 0, len(counts))
	for addr, n := range counts {
		ranked = append(ranked, peer{Address: addr, Bytes: n})
	}
	slices.SortFunc(ranked, func(a, b peer) int {
		switch {
		case a.Bytes > b.Bytes:
			return -1
		case a.Bytes < b.Bytes:
			return 1
		default:
			return a.Address.Compare(b.Address)
		}
	})
	var other uint64
	if len(ranked) > topPeers {
		for _, entry := range ranked[topPeers:] {
			other += entry.Bytes
		}
		ranked = ranked[:topPeers]
	}
	return ranked, other
}

type observationWindow struct {
	First, Last time.Time
	Observed    Traffic
	Proxy       proxyTraffic
	Services    map[string]Traffic
	Covered     time.Duration
	Partial     bool
}

func (w *observationWindow) add(o observation) {
	if w.First.IsZero() {
		w.First = o.Start
	}
	w.Last = o.End
	w.Observed = w.Observed.add(o.totals())
	w.Proxy = w.Proxy.add(o.xray)
	for name, count := range o.services {
		w.Services[name] = w.Services[name].add(count)
	}
	w.Covered += o.End.Sub(o.Start)
	w.Partial = w.Partial || o.Partial || o.partial
}

func (w observationWindow) unexplained(legs string) Traffic {
	explained := w.Proxy.explained(legs)
	for _, count := range w.Services {
		explained = explained.add(count)
	}
	return Traffic{
		RX: w.Observed.RX - min(w.Observed.RX, explained.RX+explained.RX/5),
		TX: w.Observed.TX - min(w.Observed.TX, explained.TX+explained.TX/5),
	}
}

type proxyTraffic struct {
	InUp, InDown, OutUp, OutDown uint64
}

func (p proxyTraffic) add(q proxyTraffic) proxyTraffic {
	return proxyTraffic{p.InUp + q.InUp, p.InDown + q.InDown, p.OutUp + q.OutUp, p.OutDown + q.OutDown}
}

func (p proxyTraffic) explained(legs string) Traffic {
	up, down := min(p.InUp, p.OutUp), min(p.InDown, p.OutDown)
	switch legs {
	case "inbound":
		return Traffic{RX: up, TX: down}
	case "outbound":
		return Traffic{RX: down, TX: up}
	default:
		return Traffic{RX: up + down, TX: up + down}
	}
}

func selectDirection(o Traffic, threshold uint64) string {
	switch {
	case o.RX > threshold && o.TX > threshold:
		return "unexplained_bidirectional"
	case o.RX > threshold:
		return "unexplained_ingress"
	case o.TX > threshold:
		return "unexplained_egress"
	default:
		return ""
	}
}

func validateSample(s sample, last time.Time) error {
	if !s.Start.Before(s.End) || s.Start.Before(last) {
		return fmt.Errorf("invalid or overlapping observation: %s–%s", s.Start, s.End)
	}
	if s.End.Sub(s.Start) > time.Minute {
		return errors.New("observation slice exceeds one minute")
	}
	return nil
}
