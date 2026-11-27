package trafficwatch

import (
	"container/heap"
	"net/netip"
)

// The priority follows weighted Space-Saving. Only measured bytes while a
// peer is retained are attributed to its address. Evicted bytes go to Other.
type peerTracker struct {
	index map[netip.Addr]*trackedPeer
	queue peerHeap
}

func (p *peerTracker) add(counts map[netip.Addr]uint64, addr netip.Addr, count uint64) (evicted uint64) {
	if count == 0 {
		return 0
	}
	if p.index == nil {
		p.index = make(map[netip.Addr]*trackedPeer)
	}
	if current := p.index[addr]; current != nil {
		counts[addr] += count
		current.weight += count
		heap.Fix(&p.queue, current.index)
		return 0
	}
	if len(p.queue) < maxPeers {
		current := &trackedPeer{address: addr, weight: count}
		p.index[addr], counts[addr] = current, count
		heap.Push(&p.queue, current)
		return 0
	}
	current := p.queue[0]
	evicted = counts[current.address]
	delete(counts, current.address)
	delete(p.index, current.address)
	current.address = addr
	current.weight += count
	p.index[addr], counts[addr] = current, count
	heap.Fix(&p.queue, 0)
	return evicted
}

type trackedPeer struct {
	address netip.Addr
	weight  uint64
	index   int
}

type peerHeap []*trackedPeer

func (h peerHeap) Len() int { return len(h) }
func (h peerHeap) Less(i, j int) bool {
	if h[i].weight == h[j].weight {
		return h[i].address.Compare(h[j].address) < 0
	}
	return h[i].weight < h[j].weight
}
func (h peerHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].index, h[j].index = i, j
}
func (h *peerHeap) Push(x any) {
	entry := x.(*trackedPeer)
	entry.index = len(*h)
	*h = append(*h, entry)
}
func (h *peerHeap) Pop() any {
	last := len(*h) - 1
	entry := (*h)[last]
	(*h)[last] = nil
	*h = (*h)[:last]
	return entry
}
