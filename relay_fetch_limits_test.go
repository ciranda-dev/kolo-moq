package kolomoq

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// One subscriber's FETCHes for a track the relay does not hold,
// forwarded and never read, do not stall the live track other subscribers
// get from the same publisher session.
func TestRelayForwardedFetchDoesNotStallOthers(t *testing.T) {
	for _, prio := range []uint8{0, 128} {
		t.Run(fmt.Sprint("priority ", prio), func(t *testing.T) {
			const rt = 2 * time.Second
			r := newRelay(t, &RelayConfig{Session: Config{RequestTimeout: rt}})
			ns := Namespace{"ff"}
			origin := newOrigin(t)
			live := mustTrack(t, origin, ns, "live", nil)
			big := mustTrack(t, origin, ns, "big", nil)
			gw := mustGroup(t, big)
			for range 7 {
				mustWrite(t, gw, make([]byte, 4<<20))
			}
			// The publisher accepts all three fetches; the relay's budget for the
			// subscriber's fetches (32 MiB) does not hold them.
			pub, _ := joinRelay(t, r, &Config{Origin: origin, RequestTimeout: rt, MaxFetchBytes: 128 << 20})
			if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
				t.Fatal(err)
			}
			good, _ := joinRelay(t, r, &Config{RequestTimeout: rt})
			ctx := testCtx(t)
			sub, err := good.Subscribe(ctx, ns, "live", nil)
			if err != nil {
				t.Fatal(err)
			}
			stop := make(chan struct{})
			var pw sync.WaitGroup
			pw.Add(1)
			go func() {
				defer pw.Done()
				for {
					g, err := live.NewGroup()
					if err != nil {
						return
					}
					g.WriteObject([]byte("x"))
					select {
					case <-stop:
						return
					case <-time.After(10 * time.Millisecond):
					}
				}
			}()
			defer func() { close(stop); pw.Wait() }()
			readN(t, ctx, sub, 5)
			bad, _ := joinRelay(t, r, &Config{RequestTimeout: rt})
			for range 3 {
				if _, err := bad.Fetch(ctx, ns, "big", &FetchOptions{RecentGroups: 1, Priority: prio}); err != nil {
					t.Fatal(err)
				}
			}
			time.Sleep(300 * time.Millisecond)
			var gap time.Duration
			last := time.Now()
			end := last.Add(3 * time.Second)
			for time.Now().Before(end) {
				rctx, cancel := context.WithDeadline(ctx, end)
				_, err := sub.ReadObject(rctx)
				cancel()
				if err != nil {
					break
				}
				gap = max(gap, time.Since(last))
				last = time.Now()
			}
			gap = max(gap, time.Since(last))
			if gap > 500*time.Millisecond {
				t.Fatalf("the live track stalled %v behind another subscriber's fetches", gap)
			}
		})
	}
}

// A forwarded fetch the subscriber reads too slowly is buffered
// within MaxFetchBytes and then reset, instead of slowing the publisher.
func TestRelayForwardedFetchBufferOverflow(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, &RelayConfig{Session: Config{MaxObjectSize: 64 << 10, MaxFetchBytes: 256 << 10}})
	ns := Namespace{"fb"}
	origin := newOrigin(t)
	tw := mustTrack(t, origin, ns, "t", nil)
	gw := mustGroup(t, tw)
	for range 40 {
		mustWrite(t, gw, make([]byte, 60<<10))
	}
	pub, _ := joinRelay(t, r, &Config{Origin: origin})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	peer, relaySide := joinRelay(t, r, nil)
	ctx := testCtx(t)
	f, err := peer.Fetch(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(500 * time.Millisecond)
	n := 0
	for {
		if _, err = f.ReadObject(readCtx(t, 5*time.Second)); err != nil {
			break
		}
		n++
	}
	if !errors.Is(err, ErrRequestCanceled) || n >= 40 {
		t.Fatalf("after %d objects: %v", n, err)
	}
	eventually(t, "the buffer to be released", func() bool {
		relaySide.mu.Lock()
		defer relaySide.mu.Unlock()
		return relaySide.fetchBytes == 0 && relaySide.forwarded == 0
	})
}

// One session has at most MaxSessionFetches fetches forwarded at
// once, so it cannot use up the publisher's requests.
func TestRelayForwardedFetchLimit(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, &RelayConfig{MaxSessionFetches: 2})
	ns := Namespace{"fl"}
	tw, _, _ := relayedPublisher(t, r, ns, "t")
	// Larger than the stream windows: an unread fetch stays forwarded.
	gw := mustGroup(t, tw)
	mustWrite(t, gw, make([]byte, 4<<20))
	mustWrite(t, gw, make([]byte, 4<<20))
	peer, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	var open []*Fetch
	for range 2 {
		f, err := peer.Fetch(ctx, ns, "t", nil)
		if err != nil {
			t.Fatal(err)
		}
		open = append(open, f)
	}
	if _, err := peer.Fetch(ctx, ns, "t", nil); requestCode(err) != ReqExcessiveLoad {
		t.Fatalf("third forwarded fetch: %v", err)
	}
	other, _ := joinRelay(t, r, nil)
	if _, err := other.Fetch(ctx, ns, "t", nil); err != nil {
		t.Fatalf("another session's fetch: %v", err)
	}
	open[0].Close()
	eventually(t, "a forwarded fetch slot", func() bool {
		f, err := peer.Fetch(ctx, ns, "t", nil)
		if err == nil {
			f.Close()
		}
		return err == nil
	})
}

// The relay asks the publisher with the lowest priority, not the
// subscriber's (draft section 5.1.3), so its live subscriptions go first.
func TestRelayForwardsFetchWithOwnPriority(t *testing.T) {
	r := newRelay(t, nil)
	ns := Namespace{"fp"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	go peer.Fetch(testCtx(t), ns, "t", &FetchOptions{RecentGroups: 1, Priority: 3})
	_, _, m := rp.accept()
	if m.Type != wire.MsgFetch {
		t.Fatalf("request type 0x%x", m.Type)
	}
	if !m.Params.Has(wire.ParamSubscriberPriority) || m.Params.SubscriberPriority != 255 {
		t.Fatalf("upstream FETCH priority %d (set %v), want 255", m.Params.SubscriberPriority, m.Params.Has(wire.ParamSubscriberPriority))
	}
}

// After a turn that wrote nothing, a stream the peer does not
// read holds the gate for a short turn only, so a less urgent live
// subscription of the session keeps a low latency.
func TestStalledStreamShortTurns(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"turns"}
	big := mustTrack(t, origin, ns, "big", nil)
	mustWrite(t, mustGroup(t, big), make([]byte, 8<<20))
	live := mustTrack(t, origin, ns, "live", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "live", &SubscribeOptions{Priority: 255})
	if err != nil {
		t.Fatal(err)
	}
	// Never read: its stream is stuck in flow control at the top priority.
	if _, err := p.client.Fetch(ctx, ns, "big", &FetchOptions{RecentGroups: 1, Priority: 0}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	var lat []time.Duration
	for range 100 {
		sent := time.Now()
		mustWrite(t, mustGroup(t, live), []byte("x"))
		if _, err := sub.ReadObject(readCtx(t, 5*time.Second)); err != nil {
			t.Fatal(err)
		}
		lat = append(lat, time.Since(sent))
		time.Sleep(5 * time.Millisecond)
	}
	slices.Sort(lat)
	// A full turn is RequestTimeout/100 = 100 ms; a short one 1 ms.
	if med := lat[len(lat)/2]; med > 20*time.Millisecond {
		t.Fatalf("median latency %v behind a stalled stream", med)
	}
}

// One session cannot open every track slot of the relay.
func TestRelaySessionTrackLimit(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, &RelayConfig{MaxTracks: 4, MaxSessionTracks: 3})
	ns := Namespace{"st"}
	origin := newOrigin(t)
	for i := range 5 {
		mustTrack(t, origin, ns, fmt.Sprint("t", i), nil)
	}
	pub, _ := joinRelay(t, r, &Config{Origin: origin})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	ctx := testCtx(t)
	bad, _ := joinRelay(t, r, nil)
	var subs []*Subscription
	for i := range 3 {
		sub, err := bad.Subscribe(ctx, ns, fmt.Sprint("t", i), nil)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}
	if _, err := bad.Subscribe(ctx, ns, "t3", nil); requestCode(err) != ReqExcessiveLoad {
		t.Fatalf("fourth track opened by one session: %v", err)
	}
	good, _ := joinRelay(t, r, nil)
	if _, err := good.Subscribe(ctx, ns, "t3", nil); err != nil {
		t.Fatalf("another session: %v", err)
	}
	// A track another session opened does not count.
	if _, err := bad.Subscribe(ctx, ns, "t3", nil); err != nil {
		t.Fatalf("joining a relayed track: %v", err)
	}
	subs[0].Close()
	eventually(t, "the session's track slot", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.tracks) == 3
	})
	if _, err := bad.Subscribe(ctx, ns, "t0", nil); err != nil {
		t.Fatalf("after a track left: %v", err)
	}
	cfg := newRelay(t, &RelayConfig{MaxTracks: 40}).cfg
	if cfg.MaxSessionTracks != 4 || cfg.MaxSessionFetches != 16 {
		t.Fatalf("defaults %d, %d", cfg.MaxSessionTracks, cfg.MaxSessionFetches)
	}
	if _, err := NewRelay(&RelayConfig{MaxTracks: 4, MaxSessionTracks: 5}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("MaxSessionTracks above MaxTracks: %v", err)
	}
}

// joinRelayAs connects a client session with identity id to the relay.
func joinRelayAs(t *testing.T, r *Relay, id *koloid.Identity, cfg *Config) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srvID, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", srvID, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	res := make(chan sessionResult, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			res <- sessionResult{nil, err}
			return
		}
		s, err := r.NewServer(ctx, c)
		res <- sessionResult{s, err}
	}()
	cc, err := kolosecure.Dial(ctx, l.Addr().String(), id, srvID.PublicKey(), &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	peer, err := NewClient(ctx, cc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	t.Cleanup(func() { peer.Close(); sr.s.Close() })
	return peer
}

// A publisher that moved to a new session (same key) and sent
// GOAWAY on the old one (draft section 7.6.1) gets the new subscriptions.
func TestRelayPublisherSwitchover(t *testing.T) {
	r := newRelay(t, nil)
	ns := Namespace{"sw"}
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	join := func() (*Session, *TrackWriter) {
		o := newOrigin(t)
		tw := mustTrack(t, o, ns, "u", nil)
		mustTrack(t, o, ns, "t", nil)
		s := joinRelayAs(t, r, id, &Config{Origin: o})
		if _, err := s.PublishNamespace(testCtx(t), ns); err != nil {
			t.Fatal(err)
		}
		return s, tw
	}
	oldS, _ := join()
	first, _ := joinRelay(t, r, nil)
	if _, err := first.Subscribe(testCtx(t), ns, "t", nil); err != nil {
		t.Fatal(err)
	}
	_, newTW := join()
	// The old session keeps its subscription open, so its drain lasts.
	go oldS.GoAway(context.Background(), 20*time.Second)
	peer, _ := joinRelay(t, r, nil)
	var sub *Subscription
	eventually(t, "a subscription after the GOAWAY", func() bool {
		var err error
		sub, err = peer.Subscribe(testCtx(t), ns, "u", nil)
		return err == nil && oldS.goneAway()
	})
	mustWrite(t, mustGroup(t, newTW), []byte("new"))
	o, err := sub.ReadObject(readCtx(t, 5*time.Second))
	if err != nil || string(o.Payload) != "new" {
		t.Fatalf("not served by the new session: %v", err)
	}
}

// The empty namespace, which would claim every track of the
// relay, cannot be announced.
func TestRelayRefusesEmptyNamespace(t *testing.T) {
	r := newRelay(t, nil)
	squat, _ := joinRelay(t, r, &Config{Origin: newOrigin(t)})
	if _, err := squat.PublishNamespace(testCtx(t), Namespace{}); requestCode(err) != ReqUnauthorized {
		t.Fatalf("empty namespace: %v", err)
	}
	other, _ := joinRelay(t, r, &Config{Origin: newOrigin(t)})
	if _, err := other.PublishNamespace(testCtx(t), Namespace{"live"}); err != nil {
		t.Fatalf("second publisher: %v", err)
	}
}

// The cached objects a session holds for its unread fetches are
// bounded by MaxFetchBytes; the bytes return once a fetch ends.
func TestFetchBudget(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"budget"}
	tw := mustTrack(t, origin, ns, "t", nil)
	gw := mustGroup(t, tw)
	for range 10 {
		mustWrite(t, gw, make([]byte, 100<<10))
	}
	p := newPair(t, nil, &Config{Origin: origin, MaxObjectSize: 1 << 20, MaxFetchBytes: 3 << 19})
	ctx := testCtx(t)
	f, err := p.client.Fetch(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.Fetch(ctx, ns, "t", nil); requestCode(err) != ReqExcessiveLoad {
		t.Fatalf("second fetch over the budget: %v", err)
	}
	f.Close()
	eventually(t, "the budget to be released", func() bool {
		p.server.mu.Lock()
		defer p.server.mu.Unlock()
		return p.server.fetchBytes == 0
	})
	f, err = p.client.Fetch(ctx, ns, "t", nil)
	if err != nil {
		t.Fatalf("fetch after the first ended: %v", err)
	}
	for i := range 10 {
		if _, err := f.ReadObject(ctx); err != nil {
			t.Fatalf("object %d: %v", i, err)
		}
	}
	f.Close()
}

// A fill that does not fit the session's fetch budget is skipped,
// and the subscription starts with live objects.
func TestFillOverBudgetSkipped(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"fillbudget"}
	tw := mustTrack(t, origin, ns, "t", nil)
	gw := mustGroup(t, tw)
	for range 10 {
		mustWrite(t, gw, make([]byte, 100<<10))
	}
	p := newPair(t, nil, &Config{Origin: origin, MaxObjectSize: 1 << 20, MaxFetchBytes: 3 << 19})
	ctx := testCtx(t)
	if _, err := p.client.Fetch(ctx, ns, "t", nil); err != nil {
		t.Fatal(err)
	}
	sub, err := p.client.Subscribe(ctx, ns, "t", &SubscribeOptions{Priority: DefaultPriority, Join: JoinCurrentGroup})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, gw, []byte("live"))
	o, err := sub.ReadObject(readCtx(t, 5*time.Second))
	if err != nil || o.ID != 10 {
		t.Fatalf("first object %d: %v", o.ID, err)
	}
}

// A stream reset before its header went out is not counted in
// PUBLISH_DONE, so the subscriber ends at once instead of after a timeout.
func TestPublishDoneCountsSentStreams(t *testing.T) {
	r := newRelay(t, nil)
	ns := Namespace{"count"}
	tw, pub, _ := relayedPublisher(t, r, ns, "t")
	peer, relaySide := joinRelay(t, r, &Config{RequestTimeout: 5 * time.Second})
	ctx := testCtx(t)
	sub, err := peer.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	// Hold the gate of the relay's session to the subscriber, so the
	// relay's stream for the next group waits before its header.
	var hold sendQueue
	if err := relaySide.gate.acquire(ctx, &hold, sendKey{}); err != nil {
		t.Fatal(err)
	}
	mustWrite(t, mustGroup(t, tw), []byte("x"))
	eventually(t, "the stream to wait for the gate", func() bool { return queuedWaiters(&relaySide.gate) == 1 })
	pub.Close()
	began := time.Now()
	_, err = sub.ReadObject(readCtx(t, 10*time.Second))
	relaySide.gate.release()
	var pd *PublishDoneError
	if !errors.As(err, &pd) {
		t.Fatalf("end: %v", err)
	}
	if d := time.Since(began); d > 2*time.Second {
		t.Fatalf("the subscription ended %v after the publisher left", d)
	}
}

// GOING_AWAY only follows a GOAWAY on the publisher's session
// (draft section 12.4); any other end of the session is INTERNAL_ERROR.
func TestRelayGoingAwayOnlyAfterGoAway(t *testing.T) {
	cases := []struct {
		name string
		end  func(t *testing.T, rp *rawPeer, relayPub *Session)
		want DoneCode
	}{
		{"protocol violation", func(t *testing.T, rp *rawPeer, _ *Session) {
			mustSend(t, rp.ctrl, msg(wire.MsgSubscribe, nil))
		}, DoneInternalError},
		{"connection closed", func(t *testing.T, rp *rawPeer, _ *Session) {
			rp.conn.Close()
		}, DoneInternalError},
		{"GOAWAY from the publisher", func(t *testing.T, rp *rawPeer, _ *Session) {
			mustSend(t, rp.ctrl, msg(wire.MsgGoAway, (&wire.GoAway{}).Append(nil)))
			time.Sleep(100 * time.Millisecond)
			rp.conn.Close()
		}, DoneGoingAway},
		{"GOAWAY from the relay", func(t *testing.T, _ *rawPeer, relayPub *Session) {
			go relayPub.GoAway(context.Background(), 50*time.Millisecond)
		}, DoneGoingAway},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := newRelay(t, nil)
			ns := Namespace{"ga"}
			rp, relayPub := rawPublisher(t, r, ns)
			peer, _ := joinRelay(t, r, nil)
			res := subscribeAsync(testCtx(t), peer, ns, "t")
			answerSubscribe(t, rp, 1)
			sr := <-res
			if sr.err != nil {
				t.Fatal(sr.err)
			}
			tc.end(t, rp, relayPub)
			_, err := sr.sub.ReadObject(readCtx(t, 10*time.Second))
			var pd *PublishDoneError
			if !errors.As(err, &pd) || pd.Code != tc.want {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}
}

// A goroutine is never started for a session that has ended, so none
// outlives Close.
func TestStartAfterEnd(t *testing.T) {
	p := newPair(t, nil, nil)
	p.client.Close()
	ran := make(chan struct{})
	if p.client.start(func() { close(ran) }) {
		t.Fatal("start ran a goroutine after the session ended")
	}
	select {
	case <-ran:
		t.Fatal("the function ran")
	case <-time.After(50 * time.Millisecond):
	}
}
