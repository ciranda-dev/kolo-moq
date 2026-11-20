package kolomoq

import (
	"context"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// queuedWaiters counts the writes waiting at g.
func queuedWaiters(g *gate) int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, q := range g.queues {
		n += len(q.live) + len(q.fill)
	}
	return n
}

// grantOrder queues every write while the gate is held, then releases it
// and returns the names in the order the writes got the gate.
func grantOrder(t *testing.T, writes []gateWrite) []string {
	t.Helper()
	var g gate
	var hold sendQueue
	ctx := context.Background()
	if err := g.acquire(ctx, &hold, sendKey{}); err != nil {
		t.Fatal(err)
	}
	order := make(chan string, len(writes))
	for i, w := range writes {
		go func() {
			if err := g.acquire(ctx, w.q, w.key); err != nil {
				t.Error(err)
				return
			}
			order <- w.name
			g.release()
		}()
		// Arrival order is part of the expected order.
		eventually(t, "the write to queue", func() bool { return queuedWaiters(&g) == i+1 })
	}
	g.release()
	var got []string
	for range writes {
		got = append(got, <-order)
	}
	return got
}

type gateWrite struct {
	name string
	q    *sendQueue
	key  sendKey
}

func TestGateOrder(t *testing.T) {
	var a, b, c sendQueue
	got := grantOrder(t, []gateWrite{
		{"a-sub1-pub1-g2-sg1", &a, sendKey{sub: 1, pub: 1, group: 2, subgroup: 1}},
		{"a-sub1-pub1-g2", &a, sendKey{sub: 1, pub: 1, group: 2}},
		{"a-sub1-pub1-g1", &a, sendKey{sub: 1, pub: 1, group: 1}},
		{"b-sub1-pub0", &b, sendKey{sub: 1, pub: 0, group: 9}},
		{"b-sub0", &b, sendKey{sub: 0, pub: 200, group: 9}},
		{"c-desc-older", &c, sendKey{sub: 2, group: 3, order: OrderDescending}},
		{"c-desc-newest", &c, sendKey{sub: 2, group: 10, order: OrderDescending}},
	})
	want := []string{"b-sub0", "b-sub1-pub0", "a-sub1-pub1-g1", "a-sub1-pub1-g2", "a-sub1-pub1-g2-sg1", "c-desc-newest", "c-desc-older"}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v", got)
	}
}

// Within one subscription the fill goes
// before live objects of its own group (draft section 5.1.2 rule 4), and
// after live objects of other groups when its group order differs (rule 3).
func TestGateFillOrder(t *testing.T) {
	cases := []struct {
		name   string
		writes func(q *sendQueue) []gateWrite
		want   []string
	}{
		{"same group, fill first", func(q *sendQueue) []gateWrite {
			return []gateWrite{
				{"live-g5", q, sendKey{sub: 128, pub: 128, group: 5}},
				{"fill-g5", q, sendKey{sub: 128, pub: 128, group: 5, fill: true}},
			}
		}, []string{"fill-g5", "live-g5"}},
		{"same group, other order, fill first", func(q *sendQueue) []gateWrite {
			return []gateWrite{
				{"live-g5", q, sendKey{sub: 128, pub: 128, group: 5}},
				{"fill-g5-desc", q, sendKey{sub: 128, pub: 128, group: 5, order: OrderDescending, fill: true}},
			}
		}, []string{"fill-g5-desc", "live-g5"}},
		{"other order, live first", func(q *sendQueue) []gateWrite {
			return []gateWrite{
				{"fill-g4-desc", q, sendKey{sub: 128, pub: 128, group: 4, order: OrderDescending, fill: true}},
				{"live-g6", q, sendKey{sub: 128, pub: 128, group: 6}},
				{"live-g5", q, sendKey{sub: 128, pub: 128, group: 5}},
			}
		}, []string{"live-g5", "live-g6", "fill-g4-desc"}},
		{"same order, group order", func(q *sendQueue) []gateWrite {
			return []gateWrite{
				{"live-g5", q, sendKey{sub: 128, pub: 128, group: 5}},
				{"fill-g4", q, sendKey{sub: 128, pub: 128, group: 4, fill: true}},
			}
		}, []string{"fill-g4", "live-g5"}},
		{"priority before the fill rules", func(q *sendQueue) []gateWrite {
			return []gateWrite{
				{"fill-g5-pub200", q, sendKey{sub: 128, pub: 200, group: 5, fill: true}},
				{"live-g5-pub1", q, sendKey{sub: 128, pub: 1, group: 5}},
			}
		}, []string{"live-g5-pub1", "fill-g5-pub200"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var q sendQueue
			if got := grantOrder(t, tc.writes(&q)); !slices.Equal(got, tc.want) {
				t.Fatalf("order %v, want %v", got, tc.want)
			}
		})
	}
}

// Subscriptions of equal priority share
// the gate even when one is at low group IDs and the other at a high one.
func TestGateFairAcrossSubscriptions(t *testing.T) {
	var g gate
	var qa, qb sendQueue
	var a, b atomic.Int64
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	var wg sync.WaitGroup
	worker := func(q *sendQueue, n *atomic.Int64, group func(i int) uint64) {
		defer wg.Done()
		for i := 0; ctx.Err() == nil; i++ {
			if err := g.acquire(ctx, q, sendKey{sub: 128, pub: 128, group: group(i)}); err != nil {
				return
			}
			time.Sleep(time.Millisecond) // a write turn on a saturated link
			g.release()
			n.Add(1)
		}
	}
	for range 3 {
		wg.Add(1)
		go worker(&qa, &a, func(i int) uint64 { return uint64(i / 10) })
	}
	wg.Add(1)
	go worker(&qb, &b, func(int) uint64 { return 1_000_000 })
	wg.Wait()
	// Turns alternate between the two subscriptions.
	if b.Load() < a.Load()/3 || a.Load() < b.Load()/3 {
		t.Fatalf("A wrote %d times, B %d times", a.Load(), b.Load())
	}
}

// Priorities still order writes across
// subscriptions, and group order still holds within one.
func TestGateTurnsKeepPriorities(t *testing.T) {
	var a, b, c sendQueue
	got := grantOrder(t, []gateWrite{
		{"a-g2", &a, sendKey{sub: 128, pub: 128, group: 2}},
		{"a-g1", &a, sendKey{sub: 128, pub: 128, group: 1}},
		{"b-g1000", &b, sendKey{sub: 128, pub: 128, group: 1000}},
		{"b-g999", &b, sendKey{sub: 128, pub: 128, group: 999}},
		{"c-urgent", &c, sendKey{sub: 1, pub: 128, group: 7}},
		{"c-pub-urgent", &c, sendKey{sub: 1, pub: 0, group: 8}},
		{"b-low", &b, sendKey{sub: 255, group: 0}},
	})
	// c first by priority; then a and b take turns, each in group order; the
	// lowest priority last.
	want := []string{"c-pub-urgent", "c-urgent", "a-g1", "b-g999", "a-g2", "b-g1000", "b-low"}
	if !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}

func TestGateCancel(t *testing.T) {
	var g gate
	var q sendQueue
	g.acquire(context.Background(), &q, sendKey{})
	ctx, cancel := context.WithCancel(context.Background())
	errc := make(chan error, 1)
	go func() { errc <- g.acquire(ctx, &q, sendKey{}) }()
	eventually(t, "the waiter to queue", func() bool { return queuedWaiters(&g) == 1 })
	cancel()
	if err := <-errc; err == nil {
		t.Fatal("acquired after cancel")
	}
	if len(g.queues) != 0 || q.queued {
		t.Fatal("canceled waiter left its queue in the gate")
	}
	g.release()
	if err := g.acquire(context.Background(), &q, sendKey{}); err != nil {
		t.Fatal(err)
	}
	if len(g.queues) != 0 || !g.busy {
		t.Fatal("gate state")
	}
}

func TestIDWindow(t *testing.T) {
	var w idWindow
	for _, seq := range []uint64{0, 1, 5, 70000, 70001, 3 << 20} {
		if !w.use(seq) {
			t.Fatalf("%d refused", seq)
		}
	}
	for _, seq := range []uint64{5, 70000, 3 << 20, 3<<20 - idWindowSize} {
		if w.use(seq) {
			t.Fatalf("%d accepted twice or too old", seq)
		}
	}
	if !w.use(3<<20 - 10) {
		t.Fatal("recent ID refused")
	}
	w2 := idWindow{}
	w2.use(100)
	w2.use(idWindowSize + 300)
	if !w2.use(idWindowSize+200) || w2.use(100) {
		t.Fatal("window slide")
	}
}
