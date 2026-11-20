package kolomoq

import (
	"container/heap"
	"context"
	"errors"
	"os"
	"sync"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// errStalled means a peer stopped reading a data stream for RequestTimeout.
var errStalled = errors.New("kolomoq: data stream made no progress")

// gateTurns is how many turns RequestTimeout is divided in: one write holds
// the gate for at most RequestTimeout/gateTurns, then its stream queues again
// behind the others, so a peer that stops reading cannot hold up the other
// streams of the session.
const gateTurns = 100

// stalledTurn is the turn of a write whose last turn wrote nothing: a stream
// that flow control blocks holds the gate for 1 ms at a time.
const stalledTurn = time.Millisecond

// sendKey orders the waiting writes of one sendQueue as in draft section
// 5.1.2: subscriber priority, publisher priority, group in the writer's
// group order, subgroup, then arrival.
type sendKey struct {
	sub, pub uint8
	group    uint64
	order    GroupOrder
	subgroup uint64
	fill     bool // the write belongs to a subscription's fill
	seq      uint64
}

func (a sendKey) less(b sendKey) bool {
	switch {
	case a.sub != b.sub:
		return a.sub < b.sub
	case a.pub != b.pub:
		return a.pub < b.pub
	case a.group != b.group:
		return groupKey(a.group, a.order) < groupKey(b.group, b.order)
	case a.subgroup != b.subgroup:
		return a.subgroup < b.subgroup
	}
	return a.seq < b.seq
}

// fillFirst reports whether fill write f goes before live write l of the
// same subscription: in the same group the fill goes first (rule 4); in
// another group the group order decides, and the live write goes first when
// the fill has another order (rule 3).
func fillFirst(f, l sendKey) bool {
	switch {
	case f.sub != l.sub:
		return f.sub < l.sub
	case f.pub != l.pub:
		return f.pub < l.pub
	case f.group == l.group:
		return true
	case f.order != l.order:
		return false
	}
	return groupKey(f.group, f.order) < groupKey(l.group, l.order)
}

func groupKey(group uint64, order GroupOrder) uint64 {
	if order == OrderDescending {
		return ^group
	}
	return group
}

// sendQueue holds the waiting writes of one subscription, its fill included,
// or of one fetch. The gate orders writes within a queue by sendKey, and
// takes turns between queues of equal priority, since the draft orders
// groups only within one subscription.
type sendQueue struct {
	live, fill waitHeap
	served     uint64 // gate turn of the last grant, or of the first wait
	idx        int
	queued     bool
}

func (q *sendQueue) heap(fill bool) *waitHeap {
	if fill {
		return &q.fill
	}
	return &q.live
}

// best returns the heap holding the queue's most urgent write; the queue
// has one.
func (q *sendQueue) best() *waitHeap {
	switch {
	case len(q.fill) == 0:
		return &q.live
	case len(q.live) == 0 || fillFirst(q.fill[0].key, q.live[0].key):
		return &q.fill
	}
	return &q.live
}

// gate lets one data write of a session reach the transport at a time, in
// priority order, so the most urgent object is handed over first.
type gate struct {
	mu     sync.Mutex
	busy   bool
	seq    uint64
	turn   uint64
	queues queueHeap
}

type waiter struct {
	key     sendKey
	ch      chan struct{}
	granted bool
	idx     int
}

func (g *gate) acquire(ctx context.Context, q *sendQueue, key sendKey) error {
	g.mu.Lock()
	g.seq++
	key.seq = g.seq
	if !g.busy {
		g.busy = true
		g.turn++
		q.served = g.turn
		g.mu.Unlock()
		return nil
	}
	w := &waiter{key: key, ch: make(chan struct{})}
	heap.Push(q.heap(key.fill), w)
	g.update(q)
	g.mu.Unlock()
	select {
	case <-w.ch:
		return nil
	case <-ctx.Done():
		g.mu.Lock()
		if w.granted {
			g.mu.Unlock()
			g.release()
		} else {
			heap.Remove(q.heap(key.fill), w.idx)
			g.update(q)
			g.mu.Unlock()
		}
		return ctx.Err()
	}
}

func (g *gate) release() {
	g.mu.Lock()
	defer g.mu.Unlock()
	if len(g.queues) == 0 {
		g.busy = false
		return
	}
	q := g.queues[0]
	w := heap.Pop(q.best()).(*waiter)
	g.turn++
	q.served = g.turn
	g.update(q)
	w.granted = true
	close(w.ch)
}

// update puts q at its place among the queues after its writes changed.
func (g *gate) update(q *sendQueue) {
	empty := len(q.live) == 0 && len(q.fill) == 0
	switch {
	case empty && q.queued:
		heap.Remove(&g.queues, q.idx)
	case empty:
	case q.queued:
		heap.Fix(&g.queues, q.idx)
	default:
		if q.served == 0 {
			// A queue that never had a turn waits behind those that did.
			g.turn++
			q.served = g.turn
		}
		heap.Push(&g.queues, q)
	}
}

type waitHeap []*waiter

func (h waitHeap) Len() int           { return len(h) }
func (h waitHeap) Less(i, j int) bool { return h[i].key.less(h[j].key) }
func (h waitHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx, h[j].idx = i, j
}
func (h *waitHeap) Push(x any) {
	w := x.(*waiter)
	w.idx = len(*h)
	*h = append(*h, w)
}
func (h *waitHeap) Pop() any {
	old := *h
	w := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	return w
}

// queueHeap orders queues by the priorities of their most urgent write,
// then by the turn they were last served in, so queues of equal priority
// take turns.
type queueHeap []*sendQueue

func (h queueHeap) Len() int { return len(h) }
func (h queueHeap) Less(i, j int) bool {
	a, b := (*h[i].best())[0].key, (*h[j].best())[0].key
	switch {
	case a.sub != b.sub:
		return a.sub < b.sub
	case a.pub != b.pub:
		return a.pub < b.pub
	}
	return h[i].served < h[j].served
}
func (h queueHeap) Swap(i, j int) {
	h[i], h[j] = h[j], h[i]
	h[i].idx, h[j].idx = i, j
}
func (h *queueHeap) Push(x any) {
	q := x.(*sendQueue)
	q.idx, q.queued = len(*h), true
	*h = append(*h, q)
}
func (h *queueHeap) Pop() any {
	old := *h
	q := old[len(old)-1]
	old[len(old)-1] = nil
	*h = old[:len(old)-1]
	q.queued = false
	return q
}

// send writes b to st in turns of the gate, most urgent stream first, and
// returns how many bytes it wrote. A write that cannot finish within its
// turn (flow control) queues again, with a short turn while it makes no
// progress. deadline, if set, ends it with os.ErrDeadlineExceeded; no
// progress for RequestTimeout ends it with errStalled.
func (s *Session) send(ctx context.Context, q *sendQueue, key sendKey, st *kolotransport.SendStream, b []byte, deadline time.Time) (int, error) {
	full := s.cfg.RequestTimeout / gateTurns
	turnLen := full
	written := 0
	var stalled time.Time
	for len(b) > 0 {
		if err := s.gate.acquire(ctx, q, key); err != nil {
			return written, err
		}
		turn := time.Now().Add(turnLen)
		if !deadline.IsZero() && deadline.Before(turn) {
			turn = deadline
		}
		st.SetWriteDeadline(turn)
		n, err := st.Write(b)
		s.gate.release()
		s.sentBytes.Add(uint64(n))
		b = b[n:]
		written += n
		switch {
		case err == nil:
		case !errors.Is(err, os.ErrDeadlineExceeded), !deadline.IsZero() && !time.Now().Before(deadline):
			return written, err
		case n > 0:
			stalled, turnLen = time.Time{}, full
		case stalled.IsZero():
			stalled, turnLen = time.Now(), stalledTurn
		case time.Since(stalled) >= s.cfg.RequestTimeout:
			return written, errStalled
		}
	}
	st.SetWriteDeadline(time.Time{})
	return written, nil
}
