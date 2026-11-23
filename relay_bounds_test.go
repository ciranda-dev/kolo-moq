package kolomoq

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// Many tracks that each carry an object larger than their share keep the relay within MaxCacheBytes, and the
// subscriber still gets every object.
func TestRelayCacheWithinBudgetOfLargeObjects(t *testing.T) {
	checkLeaks(t)
	const tracks, size = 20, 4 << 20
	r := newRelay(t, &RelayConfig{CacheBytes: 1 << 10, MaxCacheBytes: 200 * relayTrackOverhead})
	ns := Namespace{"large"}
	names := make([]string, tracks)
	for i := range names {
		names[i] = fmt.Sprint("t", i)
	}
	tws := relayedTracks(t, r, ns, names...)
	peer, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	subs := make([]*Subscription, tracks)
	for i := range subs {
		var err error
		if subs[i], err = peer.Subscribe(ctx, ns, names[i], nil); err != nil {
			t.Fatal(err)
		}
	}
	payload := make([]byte, size)
	for i, tw := range tws {
		mustWrite(t, mustGroup(t, tw), payload)
		if o := readN(t, ctx, subs[i], 1)[0]; len(o.Payload) != size {
			t.Fatalf("track %d: %d bytes", i, len(o.Payload))
		}
	}
	if held, cached := relayHeld(r), r.cached.Load(); held > r.cfg.MaxCacheBytes || cached != held {
		t.Fatalf("relay holds %d bytes, charges %d, budget %d", held, cached, r.cfg.MaxCacheBytes)
	}
}

// A session that opens tracks is held to MaxSessionCacheBytes, and another session is still admitted.
func TestRelaySessionCacheBytes(t *testing.T) {
	checkLeaks(t)
	const budget = 100 * relayTrackOverhead
	r := newRelay(t, &RelayConfig{CacheBytes: 1 << 10, MaxCacheBytes: budget})
	ns := Namespace{"lone"}
	names := make([]string, 12)
	for i := range names {
		names[i] = fmt.Sprint("t", i)
	}
	relayedTracks(t, r, ns, names...)
	ctx := testCtx(t)
	lone, _ := joinRelay(t, r, nil)
	opened := 0
	for _, n := range names[:11] {
		if _, err := lone.Subscribe(ctx, ns, n, nil); err != nil {
			if requestCode(err) != ReqExcessiveLoad {
				t.Fatal(err)
			}
			break
		}
		opened++
	}
	if want := int(r.cfg.MaxSessionCacheBytes / relayTrackOverhead); opened != want || opened != 10 {
		t.Fatalf("a lone session opened %d tracks, want %d, a tenth of the budget", opened, want)
	}
	other, _ := joinRelay(t, r, nil)
	if _, err := other.Subscribe(ctx, ns, names[11], nil); err != nil {
		t.Fatalf("a second session after the first reached its cap: %v", err)
	}
}

func TestRelaySessionCacheBytesConfig(t *testing.T) {
	const ov = relayTrackOverhead
	for _, tc := range []struct {
		cfg  RelayConfig
		want int64
		ok   bool
	}{
		{RelayConfig{}, (1 << 30) / 10, true},
		{RelayConfig{CacheBytes: 1 << 10, MaxCacheBytes: 100 * ov}, 10 * ov, true},
		{RelayConfig{CacheBytes: 256 << 20}, 256<<20 + ov, true},
		{RelayConfig{CacheBytes: 1 << 10, MaxCacheBytes: 100 * ov, MaxSessionCacheBytes: 100 * ov}, 100 * ov, true},
		{RelayConfig{CacheBytes: 1 << 10, MaxCacheBytes: 100 * ov, MaxSessionCacheBytes: 101 * ov}, 0, false},
		{RelayConfig{CacheBytes: 1 << 10, MaxSessionCacheBytes: ov}, 0, false},
	} {
		r, err := NewRelay(&tc.cfg)
		if tc.ok != (err == nil) || (tc.ok && r.cfg.MaxSessionCacheBytes != tc.want) {
			t.Errorf("%+v: %v", tc.cfg, err)
		}
		if !tc.ok && !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v: %v", tc.cfg, err)
		}
	}
}

// One subscription the application never reads fills its queue; the nine others of the session still get every
// object.
func TestSessionBufferedBytesHealthySubscriptions(t *testing.T) {
	checkLeaks(t)
	const healthy, rounds, size, budget = 9, 10, 30 << 10, 1 << 20
	origin := newOrigin(t)
	ns := Namespace{"hog"}
	hogTrack := mustTrack(t, origin, ns, "hog", nil)
	var tws []*TrackWriter
	for i := range healthy {
		tws = append(tws, mustTrack(t, origin, ns, fmt.Sprint("t", i), nil))
	}
	p := newPair(t, &Config{MaxObjectSize: 64 << 10, MaxBufferedBytes: budget, MaxSessionBufferedBytes: budget}, &Config{Origin: origin})
	ctx := testCtx(t)
	hog, err := p.client.Subscribe(ctx, ns, "hog", nil)
	if err != nil {
		t.Fatal(err)
	}
	subs := make([]*Subscription, healthy)
	for i := range subs {
		if subs[i], err = p.client.Subscribe(ctx, ns, fmt.Sprint("t", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	payload := make([]byte, size)
	for range budget/size + 4 {
		mustWrite(t, mustGroup(t, hogTrack), payload)
	}
	eventually(t, "the unread subscription to fill", func() bool { return hog.queuedBytes() > budget*9/10 })
	for range rounds {
		for i, tw := range tws {
			mustWrite(t, mustGroup(t, tw), payload)
			readN(t, ctx, subs[i], 1)
		}
	}
	for i, sub := range subs {
		if n := sub.Dropped(); n != 0 {
			t.Fatalf("healthy subscription %d dropped %d groups", i, n)
		}
	}
	if got := p.client.buffered.Load(); got > budget {
		t.Fatalf("session buffers %d bytes, budget %d", got, budget)
	}
}

// On the publishing side the subscriber that holds the most loses its oldest group, not the one that just queued.
func TestSessionShedsLargestPublisherQueue(t *testing.T) {
	o := newCobj(wire.Object{Payload: make([]byte, 1000)}, false)
	s := &Session{cfg: Config{MaxBufferedGroups: 8, MaxSessionBufferedBytes: 3 * o.size()}, pubs: map[*pubSub]struct{}{}}
	queue := func(p *pubSub, groups ...uint64) {
		for _, g := range groups {
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			st := &outStream{p: p, key: sgKey{group: g}, ctx: ctx, cancel: cancel, queue: []*cobj{o}}
			p.streams[st.key] = st
			p.addQueued(o.size())
		}
		s.pubs[p] = struct{}{}
	}
	big := &pubSub{s: s, dead: map[sgKey]struct{}{}, streams: map[sgKey]*outStream{}}
	small := &pubSub{s: s, dead: map[sgKey]struct{}{}, streams: map[sgKey]*outStream{}}
	queue(big, 1, 2, 3)
	queue(small, 4)
	s.shed()
	if big.queued != 2*o.size() || small.queued != o.size() || s.buffered.Load() != 3*o.size() {
		t.Fatalf("big %d, small %d, session %d", big.queued, small.queued, s.buffered.Load())
	}
	if _, ok := big.streams[sgKey{group: 1}]; ok || len(small.streams) != 1 || s.Stats().ResetGroups != 1 {
		t.Fatalf("oldest group of the largest queue kept, or the small queue lost a group")
	}
}
