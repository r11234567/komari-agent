package trafficwatch

import (
	"net/netip"
	"slices"
	"time"

	"github.com/google/uuid"
)

const (
	evidenceWindow = 15 * time.Minute
	followWindow   = 5 * time.Minute
	longWindow     = 30 * time.Minute
	baselineDays   = 7
)

type thresholds struct {
	Fast      uint64 `json:"fast_bytes"`
	Slow      uint64 `json:"slow_bytes"`
	Sustained uint64 `json:"sustained_bytes"`
}

type aggregate struct {
	End   time.Time
	Bytes Traffic
}

type incident struct {
	snapshot
	until time.Time
	rx    map[netip.Addr]uint64
	tx    map[netip.Addr]uint64
	extra Traffic
}

func (i *incident) add(o observation) {
	if i.Start.IsZero() {
		i.Start = o.Start
	}
	i.Partial = i.Partial || o.Partial || o.partial || o.Unknown != 0 ||
		(!i.End.IsZero() && !i.End.Equal(o.Start)) || o.RXOverflow != 0 || o.TXOverflow != 0
	i.End = o.End
	i.Complete = !o.End.Before(i.until)
	if !o.FirstPacket.IsZero() && (i.FirstPacket.IsZero() || o.FirstPacket.Before(i.FirstPacket)) {
		i.FirstPacket = o.FirstPacket
	}
	if o.LastPacket.After(i.LastPacket) {
		i.LastPacket = o.LastPacket
	}
	i.SpansSlices = i.SpansSlices || (!o.FirstPacket.IsZero() && o.FirstPacket.Before(o.Start)) || o.LastPacket.After(o.End)
	i.ExpiresAt = o.End.Add(snapshotTTL)
	i.Observed = i.Observed.add(o.totals())
	i.Unclassified += o.Unknown
	i.extra.RX += o.RXOverflow + mergePeers(i.rx, o.RX)
	i.extra.TX += o.TXOverflow + mergePeers(i.tx, o.TX)
}

func mergePeers(dst, src map[netip.Addr]uint64) (overflow uint64) {
	for addr, n := range src {
		if _, ok := dst[addr]; ok || len(dst) < maxPeers {
			dst[addr] += n
		} else {
			overflow += n
		}
	}
	return overflow
}

func (i *incident) record() snapshot {
	result := i.snapshot
	result.Sources, result.Other.RX = rankPeers(i.rx)
	result.Destinations, result.Other.TX = rankPeers(i.tx)
	result.Other = result.Other.add(i.extra)
	return result
}

type engine struct {
	iface, legs, backend string
	limits               thresholds
	ring                 []observation
	residual             []aggregate
	baseline             map[int][]aggregate
	active               *incident
	cooldownUntil        time.Time
	previousSlow         time.Time
	previousExcess       Traffic
	last                 time.Time
}

func newEngine(iface, legs, backend string, limits thresholds) *engine {
	return &engine{iface: iface, legs: legs, backend: backend, limits: limits,
		baseline: make(map[int][]aggregate)}
}

func (e *engine) window(start, end time.Time) observationWindow {
	w := observationWindow{Services: make(map[string]Traffic)}
	for _, o := range e.ring {
		if !o.Start.Before(start) && !o.End.After(end) {
			w.add(o)
		}
	}
	return w
}

func (e *engine) add(o observation) (snapshot, error) {
	if err := validateSample(o.sample, e.last); err != nil {
		return snapshot{}, err
	}
	e.last = o.End
	e.ring = append(e.ring, o)
	for !e.ring[0].End.After(o.End.Add(-evidenceWindow)) {
		e.ring[0] = observation{}
		e.ring = e.ring[1:]
	}
	fastStart := o.End.Add(-2 * time.Minute)
	fast := e.window(fastStart, o.End)
	unexplained := fast.unexplained(e.legs)
	var reason string
	if fast.Covered == 2*time.Minute && !fast.Partial {
		reason = selectDirection(unexplained, e.limits.Fast)
	}
	slow, sustained := e.checkBaseline(o.End)
	switch {
	case reason != "":
		reason = "fast_" + reason
	case slow.reason != "":
		fastStart, reason, unexplained = o.End.Add(-10*time.Minute), "slow_"+slow.reason, slow.unexplained
	case sustained.reason != "":
		fastStart, reason, unexplained = o.End.Add(-evidenceWindow), "sustained_"+sustained.reason, sustained.unexplained
	}
	if e.active != nil && o.End.After(e.active.until) {
		e.active = nil
	}
	if e.active != nil {
		e.active.add(o)
		return e.active.record(), nil
	}
	if reason == "" || o.End.Before(e.cooldownUntil) {
		return snapshot{}, nil
	}
	e.active = &incident{
		snapshot: snapshot{ID: uuid.NewString(), Reason: reason, Interface: e.iface, Sampler: e.backend,
			TriggeredAt: o.End, TriggerUnexplained: unexplained},
		until: o.End.Add(followWindow),
		rx:    make(map[netip.Addr]uint64),
		tx:    make(map[netip.Addr]uint64),
	}
	for _, previous := range e.ring {
		if !previous.Start.Before(fastStart) {
			e.active.add(previous)
		}
	}
	e.cooldownUntil = o.End.Add(evidenceWindow)
	return e.active.record(), nil
}

type trigger struct {
	reason      string
	unexplained Traffic
}

func (e *engine) checkBaseline(end time.Time) (slow, sustained trigger) {
	if !end.Equal(end.Truncate(5 * time.Minute)) {
		return slow, sustained
	}
	w := e.window(end.Add(-5*time.Minute), end)
	if w.Covered != 5*time.Minute || w.Partial {
		e.previousSlow, e.previousExcess = time.Time{}, Traffic{}
		e.residual = nil
		return slow, sustained
	}
	residual := w.unexplained(e.legs)
	e.residual = append(e.residual, aggregate{End: end, Bytes: residual})
	for !e.residual[0].End.After(end.Add(-longWindow)) {
		e.residual = e.residual[1:]
	}
	if len(e.residual) == int(longWindow/(5*time.Minute)) {
		var sum Traffic
		for _, part := range e.residual {
			sum = sum.add(part.Bytes)
		}
		sustained = trigger{selectDirection(sum, e.limits.Sustained), sum}
	}
	key := end.Hour()*12 + end.Minute()/5
	history := e.baseline[key]
	for len(history) > 0 && history[0].End.Before(end.AddDate(0, 0, -baselineDays)) {
		history = history[1:]
	}
	typical := baselineMedian(history)
	var excess Traffic
	floor := e.limits.Slow / 20
	if residual.RX > max(3*typical.RX, floor) {
		excess.RX = residual.RX
	}
	if residual.TX > max(3*typical.TX, floor) {
		excess.TX = residual.TX
	}
	if e.previousSlow.Equal(end.Add(-5 * time.Minute)) {
		var combined Traffic
		if e.previousExcess.RX != 0 && excess.RX != 0 {
			combined.RX = e.previousExcess.RX + excess.RX
		}
		if e.previousExcess.TX != 0 && excess.TX != 0 {
			combined.TX = e.previousExcess.TX + excess.TX
		}
		slow = trigger{selectDirection(combined, e.limits.Slow), combined}
	}
	if excess == (Traffic{}) && sustained.reason == "" && e.active == nil && !end.Before(e.cooldownUntil) {
		history = append(history, aggregate{End: end, Bytes: residual})
	}
	e.baseline[key] = history
	e.previousSlow, e.previousExcess = end, excess
	return slow, sustained
}

func baselineMedian(history []aggregate) Traffic {
	if len(history) == 0 {
		return Traffic{}
	}
	rx, tx := make([]uint64, len(history)), make([]uint64, len(history))
	for i, a := range history {
		rx[i], tx[i] = a.Bytes.RX, a.Bytes.TX
	}
	slices.Sort(rx)
	slices.Sort(tx)
	return Traffic{RX: rx[len(rx)/2], TX: tx[len(tx)/2]}
}
