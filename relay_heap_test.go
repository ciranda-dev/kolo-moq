package kolomoq

import (
	"fmt"
	"os"
	"runtime"
	"testing"
)

// heapNow returns the live heap plus goroutine stacks after a collection.
func heapNow() int64 {
	var ms runtime.MemStats
	for range 3 {
		runtime.GC()
	}
	runtime.ReadMemStats(&ms)
	return int64(ms.HeapAlloc + ms.StackInuse)
}

// TestMeasureRelayHeap prints what a relayed track and a session cost in memory; set KOLOMOQ_MEASURE=1 and run with -v.
// A track costs the difference between serving N tracks through a relay and serving them over a direct session:
// the extra is the relay's upstream subscription, its track and its downstream subscription.
func TestMeasureRelayHeap(t *testing.T) {
	if os.Getenv("KOLOMOQ_MEASURE") == "" {
		t.Skip("set KOLOMOQ_MEASURE=1")
	}
	const n = 500
	ns := Namespace{"measure"}
	payload := make([]byte, 1<<10)
	ctx := testCtx(t)
	// run subscribes to n tracks over the sessions that setup returns and reports the heap the subscriptions add.
	run := func(setup func(*Origin) *Session) int64 {
		origin := newOrigin(t)
		var tws []*TrackWriter
		for i := range n {
			tws = append(tws, mustTrack(t, origin, ns, fmt.Sprint("t", i), nil))
		}
		client := setup(origin)
		base := heapNow()
		subs := make([]*Subscription, n)
		for i := range n {
			var err error
			if subs[i], err = client.Subscribe(ctx, ns, fmt.Sprint("t", i), nil); err != nil {
				t.Fatal(err)
			}
		}
		for i := range n {
			mustWrite(t, mustGroup(t, tws[i]), payload)
		}
		for _, sub := range subs {
			readN(t, ctx, sub, 1)
		}
		used := heapNow() - base
		runtime.KeepAlive(subs)
		return used
	}
	direct := run(func(o *Origin) *Session {
		return newPair(t, nil, &Config{Origin: o}).client
	})
	relayed := run(func(o *Origin) *Session {
		r := newRelay(t, nil)
		pub, _ := joinRelay(t, r, &Config{Origin: o})
		if _, err := pub.PublishNamespace(ctx, ns); err != nil {
			t.Fatal(err)
		}
		peer, _ := joinRelay(t, r, nil)
		return peer
	})
	t.Logf("%s, %s, %d CPUs", runtime.Version(), runtime.GOARCH, runtime.NumCPU())
	t.Logf("direct: %d bytes per track, relayed: %d bytes per track, relay share: %d bytes per track", direct/n, relayed/n, (relayed-direct)/n)

	const sessions = 50
	r := newRelay(t, nil)
	base := heapNow()
	var peers []*Session
	for range sessions {
		peer, _ := joinRelay(t, r, nil)
		peers = append(peers, peer)
	}
	t.Logf("idle session, relay and client side together: %d bytes", (heapNow()-base)/sessions)
	runtime.KeepAlive(peers)
}
