package kolomoq

import (
	"context"
	"errors"
	"fmt"
	"testing"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// relayHeld returns what the relay's tracks cost: their fixed overhead and their cached bytes.
func relayHeld(r *Relay) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, rt := range r.tracks {
		n += relayTrackOverhead + trackBytes(rt.t)
	}
	return n
}

// openedHeld is relayHeld for the tracks that s opened.
func openedHeld(r *Relay, s *Session) int64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	var n int64
	for _, rt := range r.tracks {
		if rt.opener == s {
			n += relayTrackOverhead + trackBytes(rt.t)
		}
	}
	return n
}

func trackBytes(t *track) int64 {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.bytes
}

// relayedTracks publishes the tracks names under ns on a new publisher session of r.
func relayedTracks(t *testing.T, r *Relay, ns Namespace, names ...string) []*TrackWriter {
	t.Helper()
	o := newOrigin(t)
	var tws []*TrackWriter
	for _, n := range names {
		tws = append(tws, mustTrack(t, o, ns, n, nil))
	}
	pub, _ := joinRelay(t, r, &Config{Origin: o})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	return tws
}

// writeObjects writes n objects of size bytes, each in its own group, and reads them from sub.
func writeObjects(t *testing.T, tw *TrackWriter, sub *Subscription, n, size int) {
	t.Helper()
	payload := make([]byte, size)
	for range n {
		mustWrite(t, mustGroup(t, tw), payload)
	}
	readN(t, testCtx(t), sub, n)
}

// The relay holds more tracks than the removed caps of 1000 tracks and 100 per session when their bytes fit.
func TestRelayManyTracks(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	const publishers, subscribers, total = 2, 3, 1500
	var tws []*TrackWriter
	for p := range publishers {
		names := make([]string, total/publishers)
		for i := range names {
			names[i] = fmt.Sprint("t", i)
		}
		tws = append(tws, relayedTracks(t, r, Namespace{"many", fmt.Sprint(p)}, names...)...)
	}
	ctx := testCtx(t)
	subs := make([]*Subscription, total)
	for k := range subscribers {
		peer, _ := joinRelay(t, r, nil)
		for i := k; i < total; i += subscribers {
			var err error
			ns := Namespace{"many", fmt.Sprint(i / (total / publishers))}
			if subs[i], err = peer.Subscribe(ctx, ns, fmt.Sprint("t", i%(total/publishers)), nil); err != nil {
				t.Fatalf("track %d: %v", i, err)
			}
		}
	}
	for i, tw := range tws {
		mustWrite(t, mustGroup(t, tw), []byte(fmt.Sprint(i)))
	}
	for i, sub := range subs {
		if o := readN(t, ctx, sub, 1)[0]; string(o.Payload) != fmt.Sprint(i) {
			t.Fatalf("track %d got %q", i, o.Payload)
		}
	}
	if held, cached := relayHeld(r), r.cached.Load(); held != cached || cached > r.cfg.MaxCacheBytes {
		t.Fatalf("held %d, charged %d, budget %d", held, cached, r.cfg.MaxCacheBytes)
	}
}

// A SUBSCRIBE is refused when the cached bytes leave no room for a track, whatever the number of tracks, and the
// bytes return when a track ends.
func TestRelayRefusesByBytes(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, &RelayConfig{CacheBytes: 100 << 10, MaxCacheBytes: 6 * relayTrackOverhead, MaxSessionCacheBytes: 6 * relayTrackOverhead})
	ns := Namespace{"bytes"}
	tws := relayedTracks(t, r, ns, "t0", "t1", "t2")
	peer, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	var subs []*Subscription
	for i := range 2 {
		sub, err := peer.Subscribe(ctx, ns, fmt.Sprint("t", i), nil)
		if err != nil {
			t.Fatal(err)
		}
		writeObjects(t, tws[i], sub, 1, 80<<10)
		subs = append(subs, sub)
	}
	if _, err := peer.Subscribe(ctx, ns, "t2", nil); requestCode(err) != ReqExcessiveLoad {
		t.Fatalf("third track over the byte budget: %v", err)
	}
	subs[0].Close()
	eventually(t, "the bytes of the closed track", func() bool { return r.cached.Load() < 4*relayTrackOverhead })
	if _, err := peer.Subscribe(ctx, ns, "t2", nil); err != nil {
		t.Fatalf("after bytes were released: %v", err)
	}
}

// A cache that grows past the budget drops its oldest objects, so the relay stays within it.
func TestRelayEvictsToBudget(t *testing.T) {
	checkLeaks(t)
	const budget = 600 << 10
	r := newRelay(t, &RelayConfig{CacheBytes: 256 << 10, CacheGroups: 100, MaxCacheBytes: budget})
	ns := Namespace{"evict"}
	tws := relayedTracks(t, r, ns, "t0", "t1", "t2")
	peer, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	const size = 40 << 10
	subs := make([]*Subscription, len(tws))
	for i := range tws {
		var err error
		if subs[i], err = peer.Subscribe(ctx, ns, fmt.Sprint("t", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	for i, tw := range tws {
		writeObjects(t, tw, subs[i], 10, size)
	}
	var each int64
	r.mu.Lock()
	for _, rt := range r.tracks {
		each = max(each, trackBytes(rt.t))
	}
	r.mu.Unlock()
	held := relayHeld(r)
	if held > budget+size+objectOverhead {
		t.Fatalf("relay holds %d bytes, budget %d", held, budget)
	}
	if cached := r.cached.Load(); cached != held {
		t.Fatalf("charged %d bytes, held %d", cached, held)
	}
	if each < size {
		t.Fatalf("a track lost its newest object: %d bytes", each)
	}
}

// A session cannot open more tracks, or cache more, than its share of the budget; another session is still served.
func TestRelaySessionShare(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, &RelayConfig{CacheBytes: 1 << 20, CacheGroups: 100, MaxCacheBytes: 2560 << 10})
	ns := Namespace{"share"}
	names := []string{"g0", "g1", "h0", "h1", "h2"}
	for i := range 30 {
		names = append(names, fmt.Sprint("e", i))
	}
	tws := relayedTracks(t, r, ns, names...)
	ctx := testCtx(t)
	good, goodSide := joinRelay(t, r, nil)
	if _, err := good.Subscribe(ctx, ns, "g0", nil); err != nil {
		t.Fatal(err)
	}
	bad, badSide := joinRelay(t, r, nil)
	const size = 50 << 10
	for i := range 3 {
		sub, err := bad.Subscribe(ctx, ns, fmt.Sprint("h", i), nil)
		if err != nil {
			t.Fatal(err)
		}
		writeObjects(t, tws[2+i], sub, 8, size)
	}
	if share, held := r.share(2), openedHeld(r, badSide); held > share+size+objectOverhead {
		t.Fatalf("session holds %d bytes, share %d", held, share)
	}
	// Each further track costs at least its overhead, so the share allows 25 tracks in all.
	opened := 3
	for i := range 30 {
		_, err := bad.Subscribe(ctx, ns, fmt.Sprint("e", i), nil)
		if err != nil {
			if requestCode(err) != ReqExcessiveLoad {
				t.Fatal(err)
			}
			break
		}
		opened++
	}
	if want := int(r.share(2) / relayTrackOverhead); opened > want {
		t.Fatalf("session opened %d tracks, its share holds %d", opened, want)
	}
	if opened == 33 {
		t.Fatal("no track was refused")
	}
	if share, held := r.share(2), openedHeld(r, badSide); held > share {
		t.Fatalf("session holds %d bytes after opening tracks, share %d", held, share)
	}
	if _, err := good.Subscribe(ctx, ns, "g1", nil); err != nil {
		t.Fatalf("another session: %v", err)
	}
	if held := openedHeld(r, goodSide); held != 2*relayTrackOverhead {
		t.Fatalf("the other session holds %d bytes", held)
	}
}

func TestSessionBufferedBytesConfig(t *testing.T) {
	for _, tc := range []struct {
		cfg  Config
		want int64
		ok   bool
	}{
		{Config{}, 256 << 20, true},
		{Config{MaxBufferedBytes: 64 << 20}, 512 << 20, true},
		{Config{MaxBufferedBytes: 64 << 30}, 512 << 30, true},
		{Config{MaxSessionBufferedBytes: 32 << 20}, 32 << 20, true},
		{Config{MaxBufferedBytes: 64 << 20, MaxSessionBufferedBytes: 32 << 20}, 0, false},
		{Config{MaxSessionBufferedBytes: 65 << 30}, 65 << 30, true},
		{Config{MaxBufferedBytes: maxBudgetBytes}, maxBudgetBytes, true},
		{Config{MaxSessionBufferedBytes: maxBudgetBytes + 1}, 0, false},
	} {
		got, err := tc.cfg.resolve()
		if tc.ok != (err == nil) || (tc.ok && got.MaxSessionBufferedBytes != tc.want) {
			t.Errorf("%+v: %d, %v", tc.cfg, got.MaxSessionBufferedBytes, err)
		}
		if !tc.ok && !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v: %v", tc.cfg, err)
		}
	}
}

// The byte budgets have no fixed maximum: only one derived from int64, so their counters cannot overflow.
func TestByteBudgetsNoFixedMaximum(t *testing.T) {
	const big = 2 << 40
	cfg, err := (&Config{MaxBufferedBytes: big, MaxSessionBufferedBytes: big, MaxFetchBytes: big}).resolve()
	if err != nil || cfg.MaxBufferedBytes != big || cfg.MaxSessionBufferedBytes != big || cfg.MaxFetchBytes != big {
		t.Fatalf("session budgets of 2 TiB: %+v, %v", cfg, err)
	}
	r, err := NewRelay(&RelayConfig{CacheBytes: big, MaxCacheBytes: 4 * big})
	if err != nil || r.cfg.CacheBytes != big || r.cfg.MaxCacheBytes != 4*big {
		t.Fatalf("relay budgets of 2 and 8 TiB: %v", err)
	}
	if _, err := newOrigin(t).CreateTrack(Namespace{"big"}, "t", &TrackOptions{CacheBytes: big}); err != nil {
		t.Fatalf("a track cache of 2 TiB: %v", err)
	}
	for name, c := range map[string]Config{
		"MaxBufferedBytes":        {MaxBufferedBytes: maxBudgetBytes + 1},
		"MaxSessionBufferedBytes": {MaxSessionBufferedBytes: maxBudgetBytes + 1},
		"MaxFetchBytes":           {MaxFetchBytes: maxBudgetBytes + 1},
	} {
		if _, err := c.resolve(); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s past the int64 headroom: %v", name, err)
		}
	}
	for name, c := range map[string]RelayConfig{
		"CacheBytes":    {CacheBytes: maxBudgetBytes + 1},
		"MaxCacheBytes": {MaxCacheBytes: maxBudgetBytes + 1},
	} {
		if _, err := NewRelay(&c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s past the int64 headroom: %v", name, err)
		}
	}
}

// Subscriptions that are not read cannot hold more than the session's budget together, on the side that publishes.
func TestSessionBufferedBytesPublisher(t *testing.T) {
	checkLeaks(t)
	const tracks, budget = 8, 2 << 20
	origin := newOrigin(t)
	ns := Namespace{"sbuf"}
	var tws []*TrackWriter
	for i := range tracks {
		tws = append(tws, mustTrack(t, origin, ns, fmt.Sprint("t", i), nil))
	}
	cfg := &Config{Origin: origin, MaxObjectSize: 64 << 10, MaxBufferedBytes: 1 << 20, MaxSessionBufferedBytes: budget}
	r, s := connected(t, cfg)
	for i := range tracks {
		_, br := r.request(subscribeMsg(r.id(), ns, fmt.Sprint("t", i), nil))
		r.expect(br, wire.MsgSubscribeOK)
	}
	payload := make([]byte, 16<<10)
	var most int64
	for range 30 {
		for _, tw := range tws {
			gw := mustGroup(t, tw)
			for range 10 {
				mustWrite(t, gw, payload)
			}
		}
		var queued int64
		for _, tw := range tws {
			for _, ps := range pubSubsOf(tw) {
				ps.mu.Lock()
				queued += ps.queued
				ps.mu.Unlock()
			}
		}
		most = max(most, queued, s.buffered.Load())
	}
	if most > budget {
		t.Fatalf("subscriptions queued %d bytes, budget %d", most, budget)
	}
	if s.buffered.Load() > budget || s.Stats().ResetGroups == 0 {
		t.Fatalf("buffered %d, %d groups reset", s.buffered.Load(), s.Stats().ResetGroups)
	}
}

// The same on the side that subscribes.
func TestSessionBufferedBytesSubscriber(t *testing.T) {
	checkLeaks(t)
	const tracks, budget = 8, 2 << 20
	origin := newOrigin(t)
	ns := Namespace{"sbuf"}
	var tws []*TrackWriter
	for i := range tracks {
		tws = append(tws, mustTrack(t, origin, ns, fmt.Sprint("t", i), nil))
	}
	p := newPair(t, &Config{MaxObjectSize: 64 << 10, MaxBufferedBytes: 1 << 20, MaxBufferedGroups: 1000, MaxSessionBufferedBytes: budget}, &Config{Origin: origin})
	ctx := testCtx(t)
	var subs []*Subscription
	for i := range tracks {
		sub, err := p.client.Subscribe(ctx, ns, fmt.Sprint("t", i), nil)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}
	payload := make([]byte, 16<<10)
	for range 30 {
		for _, tw := range tws {
			gw := mustGroup(t, tw)
			for range 10 {
				mustWrite(t, gw, payload)
			}
		}
	}
	eventually(t, "drops", func() bool {
		var n uint64
		for _, sub := range subs {
			n += sub.Dropped()
		}
		return n > 0
	})
	var held int64
	for _, sub := range subs {
		sub.mu.Lock()
		held += sub.bytes
		sub.mu.Unlock()
	}
	if got := p.client.buffered.Load(); got != held || held > budget {
		t.Fatalf("session counts %d bytes, subscriptions hold %d, budget %d", got, held, budget)
	}
	for _, sub := range subs {
		sub.Close()
	}
	if got := p.client.buffered.Load(); got != 0 {
		t.Fatalf("%d bytes counted after every subscription closed", got)
	}
}

// A subgroup stream that ends with objects still queued returns them to the session's budget.
func TestStreamEndReleasesQueuedBytes(t *testing.T) {
	s := &Session{cfg: Config{MaxBufferedGroups: 4}}
	p := &pubSub{s: s, dead: map[sgKey]struct{}{}, streams: map[sgKey]*outStream{}, writers: 1}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	st := &outStream{p: p, key: sgKey{group: 1}, ctx: ctx, cancel: cancel}
	p.streams[st.key] = st
	for range 3 {
		o := newCobj(wire.Object{Payload: []byte("x")}, false)
		st.queue = append(st.queue, o)
		p.addQueued(o.size())
	}
	st.run()
	if p.queued != 0 || s.buffered.Load() != 0 {
		t.Fatalf("%d bytes queued, %d counted by the session", p.queued, s.buffered.Load())
	}
}
