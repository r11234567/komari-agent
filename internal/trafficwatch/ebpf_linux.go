package trafficwatch

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sys/unix"
)

//go:embed ebpf/capture_bpfel.o
var captureLittleEndian []byte

//go:embed ebpf/capture_bpfeb.o
var captureBigEndian []byte

const (
	ebpfBuckets = 32
	sealDelay   = time.Second
)

// These layouts are shared with ebpf/capture.c.
type ebpfPeer struct {
	Bucket    uint64
	Address   [16]byte
	Direction uint8
	_         [7]byte
}

type ebpfTotals struct {
	Bucket, RX, TX, Unknown, First, Last uint64
	InvalidIP                            uint64
}

type ebpfSampler struct {
	collection      *ebpf.Collection
	links           []link.Link
	offset          int64
	first, next     uint64
	peers, counters *ebpf.Map
}

func startEBPF(cfg Config) (*ebpfSampler, error) {
	iface, err := net.InterfaceByName(cfg.Interface)
	if err != nil {
		return nil, fmt.Errorf("resolve eBPF capture interface: %w", err)
	}
	if len(iface.HardwareAddr) != 6 {
		return nil, errors.New("eBPF capture requires an Ethernet interface")
	}
	object := captureLittleEndian
	if binary.NativeEndian.Uint16([]byte{1, 0}) != 1 {
		object = captureBigEndian
	}
	spec, err := ebpf.LoadCollectionSpecFromReader(bytes.NewReader(object))
	if err != nil {
		return nil, fmt.Errorf("read embedded eBPF sampler: %w", err)
	}
	collection, err := ebpf.NewCollection(spec)
	if err != nil {
		return nil, fmt.Errorf("load eBPF sampler (requires TCX and BPF privileges): %w", err)
	}
	s := &ebpfSampler{collection: collection, peers: collection.Maps["peer_bytes"], counters: collection.Maps["bucket_totals"]}
	if err := s.attach(iface.Index, cfg.LocalAddresses); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (s *ebpfSampler) attach(index int, addresses []netip.Addr) error {
	ns, err := bootNanos()
	if err != nil {
		return err
	}
	s.offset = time.Now().UnixNano() - ns
	if err := s.collection.Maps["offset_ns"].Put(uint32(0), uint64(s.offset)); err != nil {
		return fmt.Errorf("configure eBPF clock: %w", err)
	}
	for _, address := range addresses {
		if err := s.collection.Maps["local_addrs"].Put(address.As16(), uint8(1)); err != nil {
			return fmt.Errorf("configure eBPF address map: %w", err)
		}
	}
	for _, hook := range []struct {
		program string
		attach  ebpf.AttachType
	}{{"capture_ingress", ebpf.AttachTCXIngress}, {"capture_egress", ebpf.AttachTCXEgress}} {
		attached, err := link.AttachTCX(link.TCXOptions{
			Interface: index, Program: s.collection.Programs[hook.program], Attach: hook.attach, Anchor: link.Head(),
		})
		if err != nil {
			return fmt.Errorf("attach %s (requires Linux TCX support and network administration privilege): %w", hook.program, err)
		}
		s.links = append(s.links, attached)
	}
	ns, err = bootNanos()
	if err != nil {
		return err
	}
	s.first = uint64((ns + s.offset) / int64(captureSlice))
	s.next = s.first
	return nil
}

func bootNanos() (int64, error) {
	var clock unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &clock); err != nil {
		return 0, fmt.Errorf("read eBPF capture clock: %w", err)
	}
	return clock.Nano(), nil
}

func (s *ebpfSampler) Name() string { return "ebpf" }

func (s *ebpfSampler) observationScope() string { return "interface_ip" }

func (s *ebpfSampler) captureTime() (time.Time, error) {
	ns, err := bootNanos()
	if err != nil {
		return time.Time{}, err
	}
	return time.Unix(0, ns+s.offset).UTC(), nil
}

func (s *ebpfSampler) Close() {
	for _, attached := range s.links {
		_ = attached.Close()
	}
	s.collection.Close()
}

func (s *ebpfSampler) Next() ([]sample, error) {
	now, err := s.captureTime()
	if err != nil {
		return nil, err
	}
	end := uint64(now.Add(-sealDelay).UnixNano() / int64(captureSlice))
	if end <= s.next {
		return nil, nil
	}
	// The current bucket can already have reused one slot. Leave a second
	// slot for a read that straddles the next rotation.
	start := s.next
	if end-start > ebpfBuckets-2 {
		start = end - (ebpfBuckets - 2)
	}
	frames := make([]sample, end-start)
	for i := range frames {
		bucket := start + uint64(i)
		stamp := ebpfTimestamp(bucket * uint64(captureSlice))
		frames[i] = sample{Start: stamp, End: stamp.Add(captureSlice), RX: make(map[netip.Addr]uint64), TX: make(map[netip.Addr]uint64), Partial: bucket == s.first || (i == 0 && start != s.next), UnknownIncluded: true}
	}
	var key ebpfPeer
	var count uint64
	var consumed []ebpfPeer
	iter := s.peers.Iterate()
	for iter.Next(&key, &count) {
		if key.Bucket >= end {
			continue
		}
		consumed = append(consumed, key)
		if key.Bucket < start {
			continue
		}
		frame := &frames[key.Bucket-start]
		address := netip.AddrFrom16(key.Address).Unmap()
		switch key.Direction {
		case 1:
			frame.RX[address] = count
		case 2:
			frame.TX[address] = count
		}
	}
	var peerErr error
	if err := iter.Err(); err != nil {
		peerErr = fmt.Errorf("read eBPF peer map: %w", err)
		for i := range frames {
			frames[i].PeerPartial = true
		}
	}
	for i := range frames {
		bucket := start + uint64(i)
		var values []ebpfTotals
		if err := s.counters.Lookup(uint32(bucket%ebpfBuckets), &values); err != nil {
			return nil, fmt.Errorf("read eBPF traffic totals: %w", err)
		}
		applyEBPFTotals(&frames[i], bucket, values)
	}
	s.next = end
	for _, key := range consumed {
		if err := s.peers.Delete(key); err != nil && !errors.Is(err, ebpf.ErrKeyNotExist) {
			return frames, errors.Join(peerErr, fmt.Errorf("release sealed eBPF peers: %w", err))
		}
	}
	return frames, peerErr
}

func applyEBPFTotals(frame *sample, bucket uint64, values []ebpfTotals) {
	var rx, tx, first, last uint64
	for _, value := range values {
		if value.Bucket != bucket || value.First == 0 {
			continue
		}
		rx += value.RX
		tx += value.TX
		frame.Unknown += value.Unknown
		frame.InvalidIP += value.InvalidIP
		if first == 0 || value.First < first {
			first = value.First
		}
		last = max(last, value.Last)
	}
	if first != 0 {
		frame.FirstPacket = ebpfTimestamp(first)
		frame.LastPacket = ebpfTimestamp(last)
	}
	var rxMismatch, txMismatch bool
	frame.RXOverflow, rxMismatch = capEBPFPeers(frame.RX, rx)
	frame.TXOverflow, txMismatch = capEBPFPeers(frame.TX, tx)
	// Missing peer detail is kept in overflow. Accurate direction totals
	// must still be eligible to trigger a snapshot when the peer map fills.
	frame.PeerPartial = frame.PeerPartial || rxMismatch || txMismatch || frame.RXOverflow != 0 || frame.TXOverflow != 0
}

func capEBPFPeers(peers map[netip.Addr]uint64, observed uint64) (overflow uint64, partial bool) {
	before := total(peers)
	if before > observed {
		// A raced peer-map iteration cannot overrule the independent bucket
		// totals. Do not keep a misleading subset of peer counts.
		clear(peers)
		return observed, true
	}
	trimmed := trimPeers(peers, maxPeers)
	return observed - before + trimmed, false
}

func ebpfTimestamp(ns uint64) time.Time { return time.Unix(0, int64(ns)).UTC() }
