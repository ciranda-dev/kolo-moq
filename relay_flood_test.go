package kolomoq

import (
	"context"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// liveGap publishes a group every 10 ms on live and returns the largest gap
// sub sees over d while flood runs.
func liveGap(t *testing.T, live *TrackWriter, sub *Subscription, d time.Duration, flood func()) time.Duration {
	t.Helper()
	ctx := testCtx(t)
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
	flood()
	var gap time.Duration
	last := time.Now()
	end := last.Add(d)
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
	return max(gap, time.Since(last))
}

// floodSetup returns a relay with a publisher of a live track and of a big
// track (7 objects of 4 MiB) whose fetches the publisher always accepts,
// and a subscription to the live track.
func floodSetup(t *testing.T, rc *RelayConfig) (*Relay, *TrackWriter, *Subscription, Namespace) {
	t.Helper()
	r := newRelay(t, rc)
	ns := Namespace{"flood"}
	origin := newOrigin(t)
	live := mustTrack(t, origin, ns, "live", nil)
	gw := mustGroup(t, mustTrack(t, origin, ns, "big", nil))
	for range 7 {
		mustWrite(t, gw, make([]byte, 4<<20))
	}
	pub, _ := joinRelay(t, r, &Config{Origin: origin, RequestTimeout: rc.Session.RequestTimeout, MaxFetchBytes: 1 << 30})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	good, _ := joinRelay(t, r, &Config{RequestTimeout: rc.Session.RequestTimeout})
	sub, err := good.Subscribe(testCtx(t), ns, "live", nil)
	if err != nil {
		t.Fatal(err)
	}
	return r, live, sub, ns
}

// The largest live gaps the flood tests accept: with forwarded fetches at
// priority 255 the largest of 100 runs with -race were under 250 ms and
// 255 ms; at priority 128 they reached 800 ms.
const (
	floodBound     = 250 * time.Millisecond
	sustainedBound = 400 * time.Millisecond
)

// Four hostile sessions, each with the most fetches it may have
// forwarded, all unread, do not stall the live track.
func TestRelayForwardedFetchFlood(t *testing.T) {
	r, live, sub, ns := floodSetup(t, &RelayConfig{Session: Config{RequestTimeout: 2 * time.Second}})
	ctx := testCtx(t)
	var fwg sync.WaitGroup
	defer fwg.Wait()
	gap := liveGap(t, live, sub, 3*time.Second, func() {
		for range 4 {
			b, _ := joinRelay(t, r, &Config{RequestTimeout: 2 * time.Second})
			for range 17 {
				fwg.Add(1)
				go func() {
					defer fwg.Done()
					b.Fetch(ctx, ns, "big", &FetchOptions{RecentGroups: 1, Priority: 0})
				}()
			}
		}
		time.Sleep(300 * time.Millisecond)
	})
	if gap > floodBound {
		t.Fatalf("the live track stalled %v behind forwarded fetches", gap)
	}
}

// Hostile sessions that keep sending FETCHes and closing them do
// not stall the live track either.
func TestRelaySustainedFetchFlood(t *testing.T) {
	r, live, sub, ns := floodSetup(t, &RelayConfig{})
	fctx, fcancel := context.WithCancel(testCtx(t))
	var fwg sync.WaitGroup
	var issued atomic.Int64
	gap := liveGap(t, live, sub, 4*time.Second, func() {
		for range 4 {
			b, _ := joinRelay(t, r, nil)
			for range 16 {
				fwg.Add(1)
				go func() {
					defer fwg.Done()
					for fctx.Err() == nil {
						f, err := b.Fetch(fctx, ns, "big", &FetchOptions{RecentGroups: 1})
						issued.Add(1)
						if err != nil {
							time.Sleep(5 * time.Millisecond)
							continue
						}
						f.Close()
					}
				}()
			}
		}
	})
	fcancel()
	fwg.Wait()
	if gap > sustainedBound || issued.Load() < 64 {
		t.Fatalf("the live track stalled %v behind %d fetches", gap, issued.Load())
	}
}

// A GOAWAY on the upstream subscription's request stream, then
// the reset with GOING_AWAY that draft section 9.2 asks for, reaches the
// downstream subscribers as GOING_AWAY (section 12.4).
func TestRelayRequestGoAway(t *testing.T) {
	r := newRelay(t, nil)
	ns := Namespace{"rg"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	res := subscribeAsync(testCtx(t), peer, ns, "t")
	st := answerSubscribe(t, rp, 1)
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	write(t, st, wire.MsgGoAway, &wire.GoAway{Timeout: 10})
	time.Sleep(100 * time.Millisecond)
	st.CancelWrite(resetGoingAway)
	_, err := sr.sub.ReadObject(readCtx(t, 5*time.Second))
	var pd *PublishDoneError
	if !errors.As(err, &pd) || pd.Code != DoneGoingAway {
		t.Fatalf("after a request GOAWAY and a GOING_AWAY reset: %v", err)
	}
}

func fetchBytesOf(s *Session) int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.fetchBytes
}

// the fetch budget is released exactly, after fetches read in
// full, in part or not at all, and after fills.
func TestFetchBudgetReturnsToZero(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"bz"}
	tw := mustTrack(t, origin, ns, "t", nil)
	for range 4 {
		gw := mustGroup(t, tw)
		for range 8 {
			mustWrite(t, gw, make([]byte, 64<<10))
		}
	}
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	f, err := p.client.Fetch(ctx, ns, "t", &FetchOptions{RecentGroups: 4})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 32 {
		if _, err := f.ReadObject(ctx); err != nil {
			t.Fatalf("object %d: %v", i, err)
		}
	}
	if _, err := f.ReadObject(ctx); err == nil {
		t.Fatal("more objects than cached")
	}
	eventually(t, "the budget after a full read", func() bool { return fetchBytesOf(p.server) == 0 })
	for i := range 20 {
		f, err := p.client.Fetch(ctx, ns, "t", &FetchOptions{RecentGroups: 4})
		if err != nil {
			t.Fatal(err)
		}
		for range i % 7 {
			if _, err := f.ReadObject(ctx); err != nil {
				break
			}
		}
		f.Close()
		sub, err := p.client.Subscribe(ctx, ns, "t", &SubscribeOptions{Priority: DefaultPriority, Join: JoinCurrentGroup})
		if err == nil {
			if i%2 == 0 {
				sub.ReadObject(readCtx(t, 100*time.Millisecond))
			}
			sub.Close()
		}
	}
	eventually(t, "the budget back to zero", func() bool { return fetchBytesOf(p.server) == 0 })
	time.Sleep(100 * time.Millisecond)
	if n := fetchBytesOf(p.server); n != 0 {
		t.Fatalf("budget %d after every fetch ended", n)
	}
}

// announceAs announces ns with key id and a track "u" on a new
// session; keep, when not empty, is a second track.
func announceAs(t *testing.T, r *Relay, id *koloid.Identity, ns Namespace, keep string) (*Session, *TrackWriter) {
	t.Helper()
	o := newOrigin(t)
	tw := mustTrack(t, o, ns, "u", nil)
	if keep != "" {
		mustTrack(t, o, ns, keep, nil)
	}
	s := joinRelayAs(t, r, id, &Config{Origin: o})
	if _, err := s.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	return s, tw
}

// of two live announcements of one namespace by the same key (a
// reconnect whose old session is still up), the newest gets new
// subscriptions.
func TestRelayPublisherNewestWins(t *testing.T) {
	r := newRelay(t, nil)
	ns := Namespace{"newest"}
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	var tws []*TrackWriter
	for range 3 {
		_, tw := announceAs(t, r, id, ns, "")
		tws = append(tws, tw)
	}
	peer, _ := joinRelay(t, r, nil)
	sub, err := peer.Subscribe(testCtx(t), ns, "u", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, tw := range tws[:2] {
		if tw.Subscribers() != 0 {
			t.Fatalf("announcement %d got the subscription", i)
		}
	}
	mustWrite(t, mustGroup(t, tws[2]), []byte("n"))
	if _, err := sub.ReadObject(readCtx(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
}

// when the newest announcement's session sent GOAWAY, new
// subscriptions go to the older one.
func TestRelayGoAwaySkipsNewest(t *testing.T) {
	r := newRelay(t, nil)
	ns := Namespace{"skip"}
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	_, oldTW := announceAs(t, r, id, ns, "")
	newS, newTW := announceAs(t, r, id, ns, "keep")
	// A relayed track on the newest session keeps its drain going.
	keeper, _ := joinRelay(t, r, nil)
	if _, err := keeper.Subscribe(testCtx(t), ns, "keep", nil); err != nil {
		t.Fatal(err)
	}
	go newS.GoAway(context.Background(), 20*time.Second)
	eventually(t, "the GOAWAY", func() bool { return newS.goneAway() })
	time.Sleep(100 * time.Millisecond)
	peer, _ := joinRelay(t, r, nil)
	sub, err := peer.Subscribe(testCtx(t), ns, "u", nil)
	if err != nil {
		t.Fatalf("subscribe: %v", err)
	}
	if newTW.Subscribers() != 0 {
		t.Fatal("the session that sent GOAWAY got the subscription")
	}
	mustWrite(t, mustGroup(t, oldTW), []byte("old"))
	if _, err := sub.ReadObject(readCtx(t, 5*time.Second)); err != nil {
		t.Fatal(err)
	}
}

// a fill stream reset before its header went out is not counted
// in PUBLISH_DONE either.
func TestPublishDoneCountsSentFill(t *testing.T) {
	r := newRelay(t, nil)
	ns := Namespace{"fillcount"}
	rp, _ := rawPublisher(t, r, ns)
	first, _ := joinRelay(t, r, nil)
	res := subscribeAsync(testCtx(t), first, ns, "t")
	answerSubscribe(t, rp, 1)
	if sr := <-res; sr.err != nil {
		t.Fatal(sr.err)
	}
	w, _ := subgroupStream(t, rp, 1, 0)
	w(&wire.Object{Payload: []byte("cached")})
	eventually(t, "the object in the relay cache", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		for _, rt := range r.tracks {
			if rt.t != nil {
				if _, has := rt.t.status(); has {
					return true
				}
			}
		}
		return false
	})
	peer, relaySide := joinRelay(t, r, &Config{RequestTimeout: 5 * time.Second})
	// Hold the gate of the relay's session to peer: its fill stream waits
	// before its header.
	var hold sendQueue
	ctx := testCtx(t)
	if err := relaySide.gate.acquire(ctx, &hold, sendKey{}); err != nil {
		t.Fatal(err)
	}
	sub, err := peer.Subscribe(ctx, ns, "t", &SubscribeOptions{Priority: DefaultPriority, Join: JoinCurrentGroup})
	if err != nil {
		relaySide.gate.release()
		t.Fatal(err)
	}
	eventually(t, "the fill to wait for the gate", func() bool { return queuedWaiters(&relaySide.gate) == 1 })
	// A malformed object ends the track and resets the fill (section 12.1).
	w(&wire.Object{ID: 1, Properties: []wire.KV{{Type: 0x4000, Value: 1}}, Payload: []byte("x")})
	began := time.Now()
	_, err = sub.ReadObject(readCtx(t, 10*time.Second))
	relaySide.gate.release()
	var pd *PublishDoneError
	if !errors.As(err, &pd) || pd.Code != DoneMalformedTrack {
		t.Fatalf("end: %v", err)
	}
	if d := time.Since(began); d > 2*time.Second {
		t.Fatalf("the subscription ended %v after the track did", d)
	}
}

// a queue that never had a turn waits behind the queues of equal
// priority that had one, as in a round robin.
func TestGateNewQueueWaitsItsTurn(t *testing.T) {
	var g gate
	var a, b, c sendQueue
	ctx := context.Background()
	if err := g.acquire(ctx, &a, sendKey{sub: 7}); err != nil {
		t.Fatal(err)
	}
	order := make(chan string, 3)
	for i, w := range []struct {
		name string
		q    *sendQueue
	}{{"b", &b}, {"a", &a}, {"c", &c}} {
		go func() {
			if err := g.acquire(ctx, w.q, sendKey{sub: 7}); err != nil {
				t.Error(err)
				return
			}
			order <- w.name
			g.release()
		}()
		eventually(t, "the write to queue", func() bool { return queuedWaiters(&g) == i+1 })
	}
	g.release()
	got := []string{<-order, <-order, <-order}
	// a had its turn first, b and c queued in this order.
	if want := []string{"a", "b", "c"}; !slices.Equal(got, want) {
		t.Fatalf("order %v, want %v", got, want)
	}
}
