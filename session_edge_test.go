package kolomoq

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
	"weak"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// An object with a lower ID than one already queued on a live
// subgroup stream is not written; the subscriber's session stays open.
func TestSubscriberSurvivesOutOfOrderObjects(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"ooo"}
	tw := mustTrack(t, origin, ns, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := readCtx(t, 10*time.Second)
	sub, err := p.client.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	add := func(id uint64) {
		tw.t.add(newCobj(wire.Object{Group: 0, ID: id, Priority: tw.t.prio, Payload: []byte(fmt.Sprint(id))}, false))
	}
	add(5)
	add(3)
	add(6)
	add(5)
	got := readN(t, ctx, sub, 2)
	if string(got[0].Payload) != "5" || string(got[1].Payload) != "6" {
		t.Fatalf("objects %q %q", got[0].Payload, got[1].Payload)
	}
	if err := p.client.Err(); err != nil {
		t.Fatalf("subscriber session: %v", err)
	}
}

// IDs the cache trimmed are not accepted again.
func TestTrimmedIDsNotAcceptedAgain(t *testing.T) {
	tr, err := newTrack(Namespace{"a"}, "t", &TrackOptions{CacheGroups: 1, CacheBytes: 1 << 10}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	obj := func(id uint64) *cobj {
		return newCobj(wire.Object{Group: 0, ID: id, Payload: make([]byte, 100)}, id == 0)
	}
	for id := range 40 {
		tr.add(obj(uint64(id)))
	}
	g := tr.groups[0]
	n, bytes := len(g.objs), tr.bytes
	if n == 0 || n >= 40 {
		t.Fatalf("%d objects cached", n)
	}
	for _, id := range []uint64{0, 1, 10} {
		if !tr.add(obj(id)) {
			t.Fatalf("resent ID %d made the track malformed", id)
		}
	}
	if len(g.objs) != n || tr.bytes != bytes || g.ids[0] != nil {
		t.Fatalf("a trimmed ID came back: %d objects (was %d), %d bytes (was %d)", len(g.objs), n, tr.bytes, bytes)
	}
}

// Evicted groups and objects are not kept alive by the backing
// arrays of the cache.
func TestEvictedEntriesAreReleased(t *testing.T) {
	collected := func(w weak.Pointer[cobj]) bool {
		for range 5 {
			runtime.GC()
			if w.Value() == nil {
				return true
			}
		}
		return false
	}
	first := func(tr *track, group, id uint64) weak.Pointer[cobj] {
		o := newCobj(wire.Object{Group: group, ID: id, Payload: make([]byte, 100)}, id == 0)
		tr.add(o)
		return weak.Make(o)
	}
	t.Run("groups", func(t *testing.T) {
		tr, err := newTrack(Namespace{"a"}, "t", &TrackOptions{CacheGroups: 1}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		w := first(tr, 0, 0)
		first(tr, 1, 0)
		if len(tr.groups) != 1 {
			t.Fatalf("%d groups", len(tr.groups))
		}
		if !collected(w) {
			t.Fatal("the evicted group is still reachable")
		}
		runtime.KeepAlive(tr)
	})
	t.Run("objects", func(t *testing.T) {
		tr, err := newTrack(Namespace{"a"}, "t", &TrackOptions{CacheBytes: 1 << 10}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		w := first(tr, 0, 0)
		// Stop right after the first trim, before an append could move the
		// objects to a new backing array and hide the old one.
		for id := uint64(1); tr.groups[0].ids[0] != nil; id++ {
			if id > 100 {
				t.Fatal("nothing was trimmed")
			}
			first(tr, 0, id)
		}
		if !collected(w) {
			t.Fatal("the trimmed object is still reachable")
		}
		runtime.KeepAlive(tr)
	})
}

// Goroutines started by requests that race Close do not outlive it.
func TestCloseRacesRequests(t *testing.T) {
	origin := newOrigin(t)
	ns := Namespace{"race"}
	tw := mustTrack(t, origin, ns, "t", nil)
	writeGroups(t, tw, 2, 3)
	for i := range 25 {
		p := newPair(t, &Config{Origin: newOrigin(t)}, &Config{Origin: origin})
		ctx := testCtx(t)
		var wg sync.WaitGroup
		for range 6 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for ctx.Err() == nil {
					var err error
					switch i % 5 {
					case 0:
						var sub *Subscription
						if sub, err = p.client.Subscribe(ctx, ns, "t", &SubscribeOptions{Join: JoinCurrentGroup}); err == nil {
							sub.Update(ctx, SubscriptionUpdate{Priority: 1})
						}
					case 1:
						var f *Fetch
						if f, err = p.client.Fetch(ctx, ns, "t", nil); err == nil {
							f.ReadObject(ctx)
						}
					case 2:
						_, err = p.client.PublishNamespace(ctx, Namespace{"mine"})
					case 3:
						_, err = p.client.SubscribeNamespace(ctx, Namespace{"race"})
					default:
						_, err = p.client.TrackStatus(ctx, ns, "t")
					}
					if err != nil && p.client.Err() != nil {
						return
					}
				}
			}()
		}
		time.Sleep(time.Duration(i%7) * time.Millisecond)
		p.client.Close()
		p.server.Close()
		wg.Wait()
		for _, g := range strings.Split(stacks(), "\n\n") {
			if strings.Contains(g, "kolo-moq") && !strings.Contains(g, "testing.tRunner") && !strings.Contains(g, "TestCloseRacesRequests") {
				t.Fatalf("iteration %d: a goroutine outlived Close:\n%s", i, g)
			}
		}
	}
}

func stacks() string {
	buf := make([]byte, 1<<20)
	return string(buf[:runtime.Stack(buf, true)])
}

// A Fetch whose request stream the publisher resets before the
// data stream arrives ends with an error instead of waiting for the caller.
func TestFetchRequestResetBeforeData(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	fc := make(chan *Fetch, 1)
	go func() {
		f, err := s.Fetch(ctx, Namespace{"a"}, "t", nil)
		if err != nil {
			t.Error(err)
		}
		fc <- f
	}()
	st, _, _ := r.accept()
	write(t, st, wire.MsgFetchOK, &wire.FetchOK{End: wire.Location{Group: 0, Object: 1}, Params: &wire.MessageParams{}})
	f := <-fc
	st.CancelWrite(resetCancelled)
	_, err := f.ReadObject(readCtx(t, 5*time.Second))
	if !errors.Is(err, ErrRequestCanceled) {
		t.Fatalf("err %v", err)
	}
}

// A data stream that never arrives ends the Fetch after
// RequestTimeout.
func TestFetchDataStreamNeverArrives(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, &Config{RequestTimeout: time.Second})
	ctx := testCtx(t)
	fc := make(chan *Fetch, 1)
	go func() {
		f, err := s.Fetch(ctx, Namespace{"a"}, "t", nil)
		if err != nil {
			t.Error(err)
		}
		fc <- f
	}()
	st, _, _ := r.accept()
	write(t, st, wire.MsgFetchOK, &wire.FetchOK{End: wire.Location{Group: 0, Object: 1}, Params: &wire.MessageParams{}})
	f := <-fc
	start := time.Now()
	_, err := f.ReadObject(readCtx(t, 10*time.Second))
	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err %v", err)
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("took %v", d)
	}
}

// A data stream the peer does not read does not hold up the
// session's other streams.
func TestStalledStreamDoesNotBlockOthers(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"stall"}
	big := mustTrack(t, origin, ns, "big", nil)
	small := mustTrack(t, origin, ns, "small", nil)
	r, _ := connected(t, &Config{Origin: origin})
	for _, name := range []string{"big", "small"} {
		_, br := r.request(subscribeMsg(r.id(), ns, name, nil))
		r.expect(br, wire.MsgSubscribeOK)
	}
	ctx := testCtx(t)
	if _, err := mustGroup(t, big).WriteObject(make([]byte, 4<<20)); err != nil {
		t.Fatal(err)
	}
	// The big stream is open and unread: the session's write is stuck in
	// flow control.
	stalled, err := r.conn.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	if _, err := mustGroup(t, small).WriteObject([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	rs, err := r.conn.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	rs.SetReadDeadline(time.Now().Add(5 * time.Second))
	br := bufio.NewReader(rs)
	typ, err := wire.ReadVarint(br)
	if err != nil {
		t.Fatalf("small stream: %v", err)
	}
	h, err := wire.ReadSubgroupHeader(br, typ)
	if err != nil {
		t.Fatal(err)
	}
	o, err := (&wire.SubgroupReader{R: br, Header: h, MaxPayload: 1 << 20}).Next()
	if err != nil || string(o.Payload) != "ping" {
		t.Fatalf("object %+v: %v", o, err)
	}
	_ = stalled
}

// A fetch stream the peer stops reading is reset after
// RequestTimeout without progress.
func TestStalledFetchStreamIsReset(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"stall"}
	tw := mustTrack(t, origin, ns, "big", nil)
	if _, err := mustGroup(t, tw).WriteObject(make([]byte, 4<<20)); err != nil {
		t.Fatal(err)
	}
	r, _ := connected(t, &Config{Origin: origin, RequestTimeout: time.Second})
	_, br := r.request(&wire.Request{Type: wire.MsgFetch, RequestID: r.id(), Namespace: ns, Name: "big", Params: &wire.MessageParams{}})
	r.expect(br, wire.MsgFetchOK)
	rs, err := r.conn.AcceptUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(3 * time.Second)
	rs.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, err = io.Copy(io.Discard, rs)
	var te *kolotransport.Error
	if !errors.As(err, &te) || !errors.Is(te, kolotransport.ErrStreamReset) || te.Code != resetExcessiveLoad {
		t.Fatalf("read of the stalled stream: %v", err)
	}
}

// A GOAWAY on a request stream migrates that request only
// (draft section 9.2); a second one, or one with a URI from a client, is a
// protocol violation.
func TestGoAwayOnRequestStreams(t *testing.T) {
	origin := newOrigin(t)
	ns := Namespace{"ga"}
	tw := mustTrack(t, origin, ns, "t", nil)
	writeGroups(t, tw, 1, 2)
	reqs := map[string]func(r *rawPeer) (*kolotransport.Stream, *bufio.Reader){
		"fetch": func(r *rawPeer) (*kolotransport.Stream, *bufio.Reader) {
			st, br := r.request(&wire.Request{Type: wire.MsgFetch, RequestID: r.id(), Namespace: ns, Name: "t", Params: &wire.MessageParams{}})
			r.expect(br, wire.MsgFetchOK)
			return st, br
		},
		"subscribe": func(r *rawPeer) (*kolotransport.Stream, *bufio.Reader) {
			st, br := r.request(subscribeMsg(r.id(), ns, "t", nil))
			r.expect(br, wire.MsgSubscribeOK)
			return st, br
		},
		"publish namespace": func(r *rawPeer) (*kolotransport.Stream, *bufio.Reader) {
			st, br := r.request(&wire.Request{Type: wire.MsgPublishNamespace, RequestID: r.id(), Namespace: Namespace{"other"}, Params: &wire.MessageParams{}})
			r.expect(br, wire.MsgRequestOK)
			return st, br
		},
		"subscribe namespace": func(r *rawPeer) (*kolotransport.Stream, *bufio.Reader) {
			st, br := r.request(&wire.Request{Type: wire.MsgSubscribeNamespace, RequestID: r.id(), Namespace: Namespace{"x"}, Params: &wire.MessageParams{}})
			r.expect(br, wire.MsgRequestOK)
			return st, br
		},
	}
	for name, open := range reqs {
		t.Run(name+"/once", func(t *testing.T) {
			checkLeaks(t)
			r, s := connected(t, &Config{Origin: origin})
			st, _ := open(r)
			write(t, st, wire.MsgGoAway, &wire.GoAway{})
			// The session still answers.
			_, br := r.request(&wire.Request{Type: wire.MsgTrackStatus, RequestID: r.id(), Namespace: ns, Name: "t", Params: &wire.MessageParams{}})
			r.expect(br, wire.MsgRequestOK)
			if err := s.Err(); err != nil {
				t.Fatalf("session: %v", err)
			}
		})
		t.Run(name+"/twice", func(t *testing.T) {
			checkLeaks(t)
			r, _ := connected(t, &Config{Origin: origin})
			st, _ := open(r)
			write(t, st, wire.MsgGoAway, &wire.GoAway{})
			write(t, st, wire.MsgGoAway, &wire.GoAway{})
			if c := r.closedWith(); c != CodeProtocolViolation {
				t.Fatalf("closed with %v", c)
			}
		})
		t.Run(name+"/client URI", func(t *testing.T) {
			checkLeaks(t)
			r, _ := connected(t, &Config{Origin: origin})
			st, _ := open(r)
			write(t, st, wire.MsgGoAway, &wire.GoAway{URI: "moqt://elsewhere"})
			if c := r.closedWith(); c != CodeProtocolViolation {
				t.Fatalf("closed with %v", c)
			}
		})
	}
}

// REQUEST_UPDATE is not a new request in the sense of draft
// section 9.2, so a subscription can still be updated after a GOAWAY.
func TestUpdateAfterGoAway(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	subc := make(chan *Subscription, 1)
	go func() {
		sub, err := s.Subscribe(ctx, Namespace{"a"}, "t", nil)
		if err != nil {
			t.Error(err)
		}
		subc <- sub
	}()
	st, br, _ := r.accept()
	write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}})
	sub := <-subc
	write(t, r.ctrl, wire.MsgGoAway, &wire.GoAway{})
	<-s.GoingAway()
	errc := make(chan error, 1)
	go func() { errc <- sub.Update(ctx, SubscriptionUpdate{Priority: 3, Paused: true}) }()
	st.SetReadDeadline(time.Now().Add(5 * time.Second))
	r.expect(br, wire.MsgRequestUpdate)
	write(t, st, wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}})
	if err := <-errc; err != nil {
		t.Fatalf("update after GOAWAY: %v", err)
	}
	if _, err := s.Subscribe(ctx, Namespace{"a"}, "u", nil); !errors.Is(err, ErrGoingAway) {
		t.Fatalf("subscribe after GOAWAY: %v", err)
	}
}

// A fill stream that fails while SUBSCRIBE_OK is processed does
// not race with the subscription's alias (checked by -race; the window is a
// few instructions wide, so the test repeats).
func TestFailedFillDuringSubscribeOK(t *testing.T) {
	for i := range 60 {
		func() {
			r, s := serving(t, nil)
			ctx := testCtx(t)
			errc := make(chan error, 1)
			go func() {
				_, err := s.Subscribe(ctx, Namespace{"a"}, "t", &SubscribeOptions{Join: JoinCurrentGroup})
				errc <- err
			}()
			st, _, m := r.accept()
			ds, err := r.conn.OpenUniStream(ctx)
			if err != nil {
				t.Fatal(err)
			}
			var fw wire.FetchWriter
			b := wire.AppendVarint(wire.AppendVarint(nil, wire.StreamTypeFetch), m.RequestID)
			b = fw.Append(b, &wire.Object{Properties: []wire.KV{{Type: 0x4000, Value: 1}}, Payload: []byte("x")})
			// A large SUBSCRIBE_OK widens the window in which the subscription is
			// accepted but its alias not yet set.
			props := make([]wire.KV, 30000)
			for k := range props {
				props[k] = wire.KV{Type: 0x100, Value: uint64(k % 100)}
			}
			ok := msg(wire.MsgSubscribeOK, (&wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}, Properties: props}).Append(nil))
			var wg sync.WaitGroup
			wg.Add(2)
			go func() {
				defer wg.Done()
				time.Sleep(time.Duration(i%16) * 40 * time.Microsecond)
				ds.Write(b)
			}()
			go func() {
				defer wg.Done()
				st.Write(ok)
			}()
			wg.Wait()
			// Either the subscription was refused because the fill failed, or it
			// was accepted and ended with the error.
			if err := <-errc; err != nil && !errors.Is(err, ErrMalformedTrack) {
				t.Fatalf("subscribe: %v", err)
			}
		}()
	}
}

// Raising only MaxObjectSize does not fail on MaxBufferedBytes.
func TestMaxObjectSizeAlone(t *testing.T) {
	for _, size := range []int{1 << 10, 64 << 20, 1 << 30} {
		c, err := (&Config{MaxObjectSize: size}).resolve()
		if err != nil {
			t.Fatalf("MaxObjectSize %d: %v", size, err)
		}
		if c.MaxBufferedBytes < int64(size) {
			t.Fatalf("MaxBufferedBytes %d below MaxObjectSize %d", c.MaxBufferedBytes, size)
		}
	}
	if _, err := NewRelay(&RelayConfig{Session: Config{MaxObjectSize: 64 << 20}}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Config{MaxObjectSize: 64 << 20, MaxBufferedBytes: 1 << 20}).resolve(); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("MaxBufferedBytes below MaxObjectSize: %v", err)
	}
}

// A delivery timeout below a millisecond is rounded up, never
// turned into "no timeout".
func TestSubMillisecondTimeouts(t *testing.T) {
	tr, err := newTrack(Namespace{"a"}, "t", &TrackOptions{ObjectDeliveryTimeout: 500 * time.Microsecond, SubgroupDeliveryTimeout: 1500 * time.Microsecond}, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	got := map[uint64]uint64{}
	for _, kv := range tr.props {
		got[kv.Type] = kv.Value
	}
	if got[propObjectTimeout] != 1 || got[propSubgroupTimeout] != 2 {
		t.Fatalf("track properties %v", got)
	}
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	go s.Subscribe(ctx, Namespace{"a"}, "t", &SubscribeOptions{ObjectDeliveryTimeout: 100 * time.Microsecond, SubgroupDeliveryTimeout: 1500 * time.Microsecond})
	_, _, m := r.accept()
	if m.Params.ObjectTimeout != 1 || m.Params.SubgroupTimeout != 2 || !m.Params.Has(wire.ParamObjectTimeout) {
		t.Fatalf("SUBSCRIBE timeouts %d %d", m.Params.ObjectTimeout, m.Params.SubgroupTimeout)
	}
}

// Errors from request carry the package prefix and still wrap
// the caller's context error.
func TestRequestErrorsArePrefixed(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	_ = r
	ctx, cancel := context.WithCancel(testCtx(t))
	errc := make(chan error, 1)
	go func() {
		_, err := s.Subscribe(ctx, Namespace{"a"}, "t", nil)
		errc <- err
	}()
	r.accept()
	cancel()
	err := <-errc
	if !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), "kolomoq:") {
		t.Fatalf("err %q", err)
	}
	cctx, ccancel := context.WithCancel(testCtx(t))
	ccancel()
	if _, err := s.Subscribe(cctx, Namespace{"a"}, "t", nil); !errors.Is(err, context.Canceled) || !strings.HasPrefix(err.Error(), "kolomoq:") {
		t.Fatalf("err %q", err)
	}
}

// A second GoAway is refused with ErrGoingAway, and a GoAway
// that ends by timeout returns nil with the timeout as the session error.
func TestGoAwayResults(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	mustTrack(t, origin, Namespace{"a"}, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	if _, err := p.client.Subscribe(ctx, Namespace{"a"}, "t", nil); err != nil {
		t.Fatal(err)
	}
	first := make(chan error, 1)
	go func() { first <- p.server.GoAway(ctx, 300*time.Millisecond) }()
	eventually(t, "GOAWAY sent", func() bool {
		p.server.mu.Lock()
		defer p.server.mu.Unlock()
		return p.server.goawaySent
	})
	err := p.server.GoAway(ctx, time.Second)
	if !errors.Is(err, ErrGoingAway) || !strings.HasPrefix(err.Error(), "kolomoq:") {
		t.Fatalf("second GoAway: %v", err)
	}
	if err := <-first; err != nil {
		t.Fatalf("GoAway ended by timeout returned %v", err)
	}
	sessionErr(t, p.server.Err(), CodeGoAwayTimeout)
}

// Properties returns copies.
func TestPropertiesAreCopies(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"p"}
	tw := mustTrack(t, origin, ns, "t", &TrackOptions{Properties: []Property{{Type: 0x3801, Bytes: []byte("abc")}}})
	writeGroups(t, tw, 1, 1)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := p.client.Fetch(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	for name, props := range map[string]func() []Property{"subscription": sub.Properties, "fetch": f.Properties} {
		for i, ps := range props() {
			ps.Value, ps.Type = 99, 99
			if len(ps.Bytes) > 0 {
				ps.Bytes[0] = 'Z'
			}
			props()[i] = ps
		}
		for _, ps := range props() {
			if ps.Type == 99 || bytes.Contains(ps.Bytes, []byte("Z")) {
				t.Fatalf("%s: Properties returned its internal slice", name)
			}
		}
	}
}

// Close waits for every goroutine of the session, among them the
// one that reads a subscription's REQUEST_UPDATE messages.
func TestCloseWaitsForRequestUpdates(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"w"}
	mustTrack(t, origin, ns, "t", nil)
	hold := make(chan struct{})
	entered := make(chan struct{}, 1)
	cfg := &Config{Origin: origin, Authorize: func(_ ed25519.PublicKey, kind RequestKind, _ Namespace, _ string) error {
		if kind == KindFetch {
			entered <- struct{}{}
			<-hold
		}
		return nil
	}}
	r, s := connected(t, cfg)
	st, br := r.request(subscribeMsg(r.id(), ns, "t", nil))
	r.expect(br, wire.MsgSubscribeOK)
	upd := &wire.RequestUpdate{RequestID: r.id(), Params: &wire.MessageParams{Fill: &wire.MessageParams{}}}
	upd.Params.Set(wire.ParamFillParameters)
	write(t, st, wire.MsgRequestUpdate, upd)
	<-entered // the update is being authorized
	closed := make(chan struct{})
	go func() {
		s.Close()
		close(closed)
	}()
	select {
	case <-closed:
		t.Fatal("Close returned while a goroutine of the session was still running")
	case <-time.After(300 * time.Millisecond):
	}
	close(hold)
	select {
	case <-closed:
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return")
	}
}
