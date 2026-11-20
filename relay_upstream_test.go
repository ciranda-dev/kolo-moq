package kolomoq

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"runtime"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

func mustTrack(t testing.TB, o *Origin, ns Namespace, name string, opts *TrackOptions) *TrackWriter {
	t.Helper()
	tw, err := o.CreateTrack(ns, name, opts)
	if err != nil {
		t.Fatal(err)
	}
	return tw
}

func mustGroup(t testing.TB, tw *TrackWriter) *GroupWriter {
	t.Helper()
	gw, err := tw.NewGroup()
	if err != nil {
		t.Fatal(err)
	}
	return gw
}

// rawPublisher connects a raw peer to r and announces ns; the raw side then
// answers the relay's requests by hand.
func rawPublisher(t *testing.T, r *Relay, ns Namespace) (*rawPeer, *Session) {
	t.Helper()
	rp, rs := rawRelayPeer(t, r)
	_, br := rp.request(&wire.Request{Type: wire.MsgPublishNamespace, RequestID: rp.id(), Namespace: ns, Params: &wire.MessageParams{}})
	rp.expect(br, wire.MsgRequestOK)
	return rp, rs
}

// rawRelayPeer connects a raw peer to r, with SETUP exchanged.
func rawRelayPeer(t *testing.T, r *Relay) (*rawPeer, *Session) {
	t.Helper()
	cc, sc, _ := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := make(chan sessionResult, 1)
	go func() {
		s, err := r.NewServer(ctx, sc)
		res <- sessionResult{s, err}
	}()
	rp := &rawPeer{t: t, conn: cc}
	rp.openControl(wire.Preface(), setupMsg(nil))
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	t.Cleanup(func() {
		cc.Close()
		sr.s.Close()
	})
	rp.readControl()
	return rp, sr.s
}

// subscribeAsync subscribes in the background and returns the result.
func subscribeAsync(ctx context.Context, s *Session, ns Namespace, name string) <-chan subResult {
	c := make(chan subResult, 1)
	go func() {
		sub, err := s.Subscribe(ctx, ns, name, nil)
		c <- subResult{sub, err}
	}()
	return c
}

type subResult struct {
	sub *Subscription
	err error
}

// answerSubscribe accepts the relay's SUBSCRIBE on the raw publisher.
func answerSubscribe(t *testing.T, rp *rawPeer, alias uint64) *kolotransport.Stream {
	t.Helper()
	s, _, m := rp.accept()
	if m.Type != wire.MsgSubscribe {
		t.Fatalf("request type 0x%x", m.Type)
	}
	write(t, s, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: alias, Params: &wire.MessageParams{}})
	return s
}

func subgroupStream(t *testing.T, rp *rawPeer, alias, group uint64) (w func(o *wire.Object), fin func()) {
	t.Helper()
	ds, err := rp.conn.OpenUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	var sw wire.SubgroupWriter
	hdr := (&wire.SubgroupHeader{Flags: wire.SubgroupTypeBit | wire.SubgroupDefaultPrio | wire.SubgroupProperties, TrackAlias: alias, Group: group}).Append(nil)
	first := true
	return func(o *wire.Object) {
			b := appendObject(&sw, nil, o)
			if first {
				b = append(hdr, b...)
				first = false
			}
			if _, err := ds.Write(b); err != nil {
				t.Error(err)
			}
		}, func() {
			if first {
				ds.Write(hdr)
			}
			ds.Close()
		}
}

func readCtx(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// The last subscriber gives up while the relay still opens the
// upstream subscription; the upstream subscription must then be closed.
func TestRelayLastSubscriberLeavesWhileOpening(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"leak"}
	origin := newOrigin(t)
	tw := mustTrack(t, origin, ns, "t", nil)
	hold := make(chan struct{})
	asked := make(chan struct{})
	var once sync.Once
	pub, _ := joinRelay(t, r, &Config{Origin: origin, Authorize: func(_ ed25519.PublicKey, kind RequestKind, _ Namespace, _ string) error {
		if kind == KindSubscribe {
			once.Do(func() { close(asked) })
			<-hold
		}
		return nil
	}})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	peer, _ := joinRelay(t, r, nil)
	res := subscribeAsync(testCtx(t), peer, ns, "t")
	<-asked
	r.mu.Lock()
	rt := r.tracks[trackKey(ns, "t")]
	r.mu.Unlock()
	if rt == nil {
		t.Fatal("relay holds no track while the upstream subscription opens")
	}
	peer.Close()
	<-res
	eventually(t, "relay track released", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.tracks) == 0
	})
	close(hold)
	<-rt.ready
	eventually(t, "upstream subscription closed", func() bool { return tw.Subscribers() == 0 })
	// The relay can still serve the track afterwards.
	peer2, _ := joinRelay(t, r, nil)
	sub, err := peer2.Subscribe(testCtx(t), ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	mustGroup(t, tw).WriteObject([]byte("after"))
	if o := readN(t, testCtx(t), sub, 1)[0]; string(o.Payload) != "after" {
		t.Fatalf("object %q", o.Payload)
	}
}

func settle() (goroutines int, heap uint64) {
	var ms runtime.MemStats
	prev := ^uint64(0)
	for range 50 {
		runtime.GC()
		debug.FreeOSMemory()
		runtime.ReadMemStats(&ms)
		goroutines = runtime.NumGoroutine()
		if ms.HeapAlloc >= prev {
			break
		}
		prev = ms.HeapAlloc
		time.Sleep(10 * time.Millisecond)
	}
	return goroutines, ms.HeapAlloc
}

// Stress: a subscriber that asks for many tracks and disconnects while the
// relay opens them leaves nothing behind once the publisher answers:
// goroutines and heap return to the baseline.
func TestRelayReleaseReturnsToBaseline(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, &RelayConfig{MaxTracks: 1000, MaxSessionTracks: 1000})
	ns := Namespace{"base"}
	origin := newOrigin(t)
	const tracks = 150
	payload := make([]byte, 64<<10)
	var tws []*TrackWriter
	for i := range tracks {
		tw := mustTrack(t, origin, ns, fmt.Sprint("t", i), nil)
		if _, err := mustGroup(t, tw).WriteObject(payload); err != nil {
			t.Fatal(err)
		}
		tws = append(tws, tw)
	}
	hold := make(chan struct{})
	var asked atomic.Int32
	pub, _ := joinRelay(t, r, &Config{Origin: origin, Authorize: func(_ ed25519.PublicKey, kind RequestKind, _ Namespace, _ string) error {
		if kind == KindSubscribe {
			asked.Add(1)
			<-hold
		}
		return nil
	}})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	peer, relaySide := joinRelay(t, r, nil)
	baseG, baseHeap := settle()

	var wg sync.WaitGroup
	ctx := testCtx(t)
	for i := range tracks {
		wg.Add(1)
		go func() {
			defer wg.Done()
			peer.Subscribe(ctx, ns, fmt.Sprint("t", i), nil)
		}()
	}
	eventually(t, "every upstream subscribe asked", func() bool { return int(asked.Load()) == tracks })
	r.mu.Lock()
	var rts []*relayTrack
	for _, rt := range r.tracks {
		rts = append(rts, rt)
	}
	r.mu.Unlock()
	if len(rts) != tracks {
		t.Fatalf("%d relay tracks", len(rts))
	}
	peer.Close()
	relaySide.Close()
	wg.Wait()
	eventually(t, "relay tracks released", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.tracks) == 0
	})
	close(hold)
	for _, rt := range rts {
		<-rt.ready
	}
	eventually(t, "upstream subscriptions closed", func() bool {
		for _, tw := range tws {
			if tw.Subscribers() != 0 {
				return false
			}
		}
		return true
	})
	var g int
	var heap uint64
	eventually(t, "goroutines back to the baseline", func() bool {
		g, heap = settle()
		return g <= baseG
	})
	if g > baseG {
		t.Fatalf("goroutines %d, baseline %d", g, baseG)
	}
	// Leaked upstream subscriptions would each hold the 64 KiB fill.
	if limit := baseHeap + 3<<20; heap > limit {
		t.Fatalf("heap %d KiB, baseline %d KiB", heap>>10, baseHeap>>10)
	}
}

// When the relay closes a publisher's session itself, the
// downstream subscribers get PUBLISH_DONE and the track leaves the relay.
func TestRelayClosesPublisherSession(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"closed"}
	origin := newOrigin(t)
	tw := mustTrack(t, origin, ns, "t", nil)
	pub, pubRelay := joinRelay(t, r, &Config{Origin: origin})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	peer, _ := joinRelay(t, r, nil)
	sub, err := peer.Subscribe(testCtx(t), ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 1, 2)
	readN(t, testCtx(t), sub, 2)
	pubRelay.Close()
	ctx := readCtx(t, 5*time.Second)
	var pd *PublishDoneError
	for {
		_, err = sub.ReadObject(ctx)
		if err != nil {
			break
		}
	}
	if !errors.As(err, &pd) || pd.Code != DoneInternalError {
		t.Fatalf("after the relay closed the publisher session: %v", err)
	}
	eventually(t, "track left the relay", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.tracks) == 0
	})
	if _, err := peer.Subscribe(testCtx(t), ns, "t", nil); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("subscribe after the publisher session closed: %v", err)
	}
}

// Draining: when the relay drains a publisher session with GOAWAY
// and the session closes cleanly, downstream subscribers still get
// PUBLISH_DONE.
func TestRelayDrainsPublisherSession(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"drain"}
	origin := newOrigin(t)
	mustTrack(t, origin, ns, "t", nil)
	pub, pubRelay := joinRelay(t, r, &Config{Origin: origin})
	pn, err := pub.PublishNamespace(testCtx(t), ns)
	if err != nil {
		t.Fatal(err)
	}
	peer, _ := joinRelay(t, r, nil)
	sub, err := peer.Subscribe(testCtx(t), ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Without the announcement no request of the publisher is open, so the drain ends cleanly with ErrClosed.
	pn.Close()
	eventually(t, "no request open", func() bool {
		pubRelay.mu.Lock()
		defer pubRelay.mu.Unlock()
		return pubRelay.active == 0
	})
	if err := pubRelay.GoAway(testCtx(t), 5*time.Second); err != nil {
		t.Fatal(err)
	}
	if err := pubRelay.Err(); !errors.Is(err, ErrClosed) {
		t.Fatalf("session error %v", err)
	}
	_, err = sub.ReadObject(readCtx(t, 5*time.Second))
	var pd *PublishDoneError
	if !errors.As(err, &pd) || pd.Code != DoneGoingAway {
		t.Fatalf("after the drain: %v", err)
	}
}

// Upstream failures reach downstream subscribers with the code
// the draft names, not as a clean end of track.
func TestRelayMapsUpstreamFailures(t *testing.T) {
	cases := []struct {
		name string
		do   func(t *testing.T, rp *rawPeer, st *kolotransport.Stream, alias uint64)
		want DoneCode
	}{
		{"malformed object", func(t *testing.T, rp *rawPeer, _ *kolotransport.Stream, alias uint64) {
			w, _ := subgroupStream(t, rp, alias, 0)
			w(&wire.Object{Properties: []wire.KV{{Type: 0x4000, Value: 1}}, Payload: []byte("x")})
		}, DoneMalformedTrack},
		{"object too large", func(t *testing.T, rp *rawPeer, _ *kolotransport.Stream, alias uint64) {
			w, _ := subgroupStream(t, rp, alias, 0)
			w(&wire.Object{Payload: make([]byte, 2048)})
		}, DoneInternalError},
		{"publisher reset the subscription", func(t *testing.T, rp *rawPeer, st *kolotransport.Stream, _ uint64) {
			st.CancelWrite(resetCancelled)
		}, DoneInternalError},
		{"status of the publisher", func(t *testing.T, rp *rawPeer, st *kolotransport.Stream, _ uint64) {
			write(t, st, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneExpired)})
		}, DoneExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			checkLeaks(t)
			r := newRelay(t, &RelayConfig{Session: Config{MaxObjectSize: 1024}})
			ns := Namespace{"fail"}
			rp, _ := rawPublisher(t, r, ns)
			peer, _ := joinRelay(t, r, nil)
			res := subscribeAsync(testCtx(t), peer, ns, "t")
			st := answerSubscribe(t, rp, 1)
			sr := <-res
			if sr.err != nil {
				t.Fatal(sr.err)
			}
			tc.do(t, rp, st, 1)
			_, err := sr.sub.ReadObject(readCtx(t, 5*time.Second))
			var pd *PublishDoneError
			if !errors.As(err, &pd) || pd.Code != tc.want {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
			eventually(t, "track left the relay", func() bool {
				r.mu.Lock()
				defer r.mu.Unlock()
				return len(r.tracks) == 0
			})
		})
	}
}

// A relay that finds a fetch malformed resets
// the downstream fetch stream with MALFORMED_TRACK.
func TestRelayFetchMalformedUpstream(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"fm"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	type fres struct {
		f   *Fetch
		err error
	}
	fc := make(chan fres, 1)
	go func() {
		f, err := peer.Fetch(ctx, ns, "t", nil)
		fc <- fres{f, err}
	}()
	st, _, m := rp.accept()
	if m.Type != wire.MsgFetch {
		t.Fatalf("request type 0x%x", m.Type)
	}
	write(t, st, wire.MsgFetchOK, &wire.FetchOK{End: wire.Location{Group: 0, Object: 1}, Params: &wire.MessageParams{}})
	// The data follows once the requester has its FETCH_OK: a reset of the
	// request stream would discard an unread answer.
	fr := <-fc
	if fr.err != nil {
		t.Fatal(fr.err)
	}
	ds, err := rp.conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var fw wire.FetchWriter
	b := wire.AppendVarint(wire.AppendVarint(nil, wire.StreamTypeFetch), m.RequestID)
	b = fw.Append(b, &wire.Object{Properties: []wire.KV{{Type: 0x4000, Value: 1}}, Payload: []byte("x")})
	ds.Write(b)
	_, err = fr.f.ReadObject(readCtx(t, 5*time.Second))
	if !errors.Is(err, ErrMalformedTrack) {
		t.Fatalf("fetch of a malformed track: %v", err)
	}
}

// Objects of a subgroup that a misbehaving upstream sends again
// with lower IDs never reach a live downstream stream.
func TestRelayUpstreamOutOfOrderIDs(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"ooo"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, peer, ns, "t")
	answerSubscribe(t, rp, 1)
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	a, _ := subgroupStream(t, rp, 1, 0)
	a(&wire.Object{ID: 5, Payload: []byte("5")})
	a(&wire.Object{ID: 6, Payload: []byte("6")})
	got := readN(t, ctx, sr.sub, 2)
	// A second stream for the same group and subgroup, with lower IDs, while
	// the first is still open.
	b, bfin := subgroupStream(t, rp, 1, 0)
	for _, id := range []uint64{1, 2, 3, 9} {
		b(&wire.Object{ID: id, Payload: []byte(fmt.Sprint(id))})
	}
	bfin()
	got = append(got, readN(t, ctx, sr.sub, 1)...)
	var ids []uint64
	for _, o := range got {
		ids = append(ids, o.ID)
	}
	if fmt.Sprint(ids) != "[5 6 9]" {
		t.Fatalf("IDs %v", ids)
	}
	// The downstream session survives and still delivers.
	c, _ := subgroupStream(t, rp, 1, 1)
	c(&wire.Object{Payload: []byte("next")})
	if o := readN(t, ctx, sr.sub, 1)[0]; string(o.Payload) != "next" || o.Group != 1 {
		t.Fatalf("object %+v", o)
	}
	if err := peer.Err(); err != nil {
		t.Fatalf("downstream session: %v", err)
	}
}

// The relay's sink keeps the order of events when the track
// becomes ready while new events arrive.
func TestRelaySinkKeepsOrderAtReady(t *testing.T) {
	r := newRelay(t, nil)
	rt := &relayTrack{r: r}
	k := &relaySink{rt: rt}
	var mu sync.Mutex
	var order []int
	record := func(i int) func(*track) {
		return func(*track) {
			mu.Lock()
			order = append(order, i)
			mu.Unlock()
		}
	}
	started := make(chan struct{})
	release := make(chan struct{})
	k.do(1, func(*track) {
		close(started)
		<-release
		record(1)(nil)
	})
	k.do(1, record(2))
	done := make(chan struct{})
	go func() {
		k.ready(&track{})
		close(done)
	}()
	<-started
	// ready is replaying the queue; a new event must wait its turn.
	late := make(chan struct{})
	go func() {
		k.do(1, record(3))
		close(late)
	}()
	<-late
	mu.Lock()
	early := len(order)
	mu.Unlock()
	if early != 0 {
		t.Fatalf("event ran before the queue was replayed: %v", order)
	}
	close(release)
	<-done
	k.do(1, record(4))
	mu.Lock()
	defer mu.Unlock()
	if fmt.Sprint(order) != "[1 2 3 4]" {
		t.Fatalf("order %v", order)
	}
}

// A SUBSCRIBE_OK the relay cannot re-encode within 65535 bytes
// is refused with an error, never cut. The upstream message fills the limit;
// the relay's answer to a later subscriber adds the Largest Object.
func TestRelayOversizedUpstreamProperties(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"big"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	res := subscribeAsync(ctx, peer, ns, "t")
	s, _, _ := rp.accept()
	ok := &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}, Properties: []wire.KV{{Type: 0x3803, Bytes: make([]byte, 60000)}}}
	for len(ok.Append(nil)) < wire.MaxMessageLen {
		ok.Properties[0].Bytes = append(ok.Properties[0].Bytes, 0)
	}
	if n := len(ok.Append(nil)); n != wire.MaxMessageLen {
		t.Fatalf("test message is %d bytes", n)
	}
	write(t, s, wire.MsgSubscribeOK, ok)
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	w, _ := subgroupStream(t, rp, 1, 0)
	w(&wire.Object{Payload: []byte("x")})
	readN(t, ctx, sr.sub, 1)
	// Now the track has a Largest Object, and the answer no longer fits.
	if _, err := peer.Subscribe(ctx, ns, "t", nil); requestCode(err) != ReqInternalError {
		t.Fatalf("subscribe: %v", err)
	}
	if err := peer.Err(); err != nil {
		t.Fatalf("session: %v", err)
	}
}

// Stress: with many subscribers reading live tracks, the relay closes the
// publisher's session itself; every reader ends with GOING_AWAY.
func TestRelayPublisherSessionClosedUnderLoad(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"load"}
	origin := newOrigin(t)
	const tracks, perTrack = 6, 4
	var tws []*TrackWriter
	for i := range tracks {
		tws = append(tws, mustTrack(t, origin, ns, fmt.Sprint("t", i), nil))
	}
	pub, pubRelay := joinRelay(t, r, &Config{Origin: origin})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var writers sync.WaitGroup
	for _, tw := range tws {
		writers.Add(1)
		go func() {
			defer writers.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				gw, err := tw.NewGroup()
				if err != nil {
					return
				}
				for range 5 {
					if _, err := gw.WriteObject([]byte("x")); err != nil {
						return
					}
					time.Sleep(time.Millisecond)
				}
			}
		}()
	}
	ctx := readCtx(t, 20*time.Second)
	var subs []*Subscription
	for i := range tracks {
		for range perTrack {
			peer, _ := joinRelay(t, r, nil)
			sub, err := peer.Subscribe(ctx, ns, fmt.Sprint("t", i), nil)
			if err != nil {
				t.Fatal(err)
			}
			subs = append(subs, sub)
		}
	}
	for _, sub := range subs {
		readN(t, ctx, sub, 1)
	}
	pubRelay.Close()
	var readers sync.WaitGroup
	for _, sub := range subs {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for {
				_, err := sub.ReadObject(ctx)
				if err == nil {
					continue
				}
				var pd *PublishDoneError
				if !errors.As(err, &pd) || pd.Code != DoneInternalError {
					t.Errorf("reader ended with %v", err)
				}
				return
			}
		}()
	}
	readers.Wait()
	close(stop)
	writers.Wait()
	eventually(t, "tracks left the relay", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.tracks) == 0
	})
}
