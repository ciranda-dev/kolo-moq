package kolomoq

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// acceptSubscribe returns the next SUBSCRIBE the relay sends the raw
// publisher, or nil when none comes within d.
func acceptSubscribe(t *testing.T, rp *rawPeer, d time.Duration) *kolotransport.Stream {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	st, err := rp.conn.AcceptStream(ctx)
	if err != nil {
		return nil
	}
	typ, body, err := wire.ReadMessage(bufio.NewReader(st), wire.MaxMessageLen)
	if err != nil {
		t.Fatal(err)
	}
	m, err := wire.ParseRequest(typ, body)
	if err != nil || m.Type != wire.MsgSubscribe {
		t.Fatalf("request 0x%x: %v", typ, err)
	}
	return st
}

// liveTracks returns the tracks the relay maps by name, those it counts
// against MaxCacheBytes, and the sessions that opened them.
func liveTracks(r *Relay) (mapped, counted, sessions int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, o := range r.openers {
		counted += o.tracks
	}
	return len(r.tracks), counted, len(r.openers)
}

func released(r *Relay) bool {
	m, c, s := liveTracks(r)
	return m == 0 && c == 0 && s == 0 && r.cached.Load() == 0
}

// reAnnounce subscribes v1 to track t of a raw publisher and returns the
// subscription with the publisher's request stream and data stream writer.
func reAnnounceStart(t *testing.T, r *Relay, rp *rawPeer, v1 *Session, ns Namespace) (*Subscription, *kolotransport.Stream, func(*wire.Object), func()) {
	t.Helper()
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, v1, ns, "t")
	req := answerSubscribe(t, rp, 1)
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	w, fin := subgroupStream(t, rp, 1, 0)
	w(&wire.Object{Payload: []byte("old")})
	if o := readN(t, ctx, sr.sub, 1)[0]; string(o.Payload) != "old" {
		t.Fatalf("object %+v", o)
	}
	return sr.sub, req, w, fin
}

// subscribeNew subscribes v2 to track t and checks that the relay opens a
// new upstream subscription for it, which delivers the new instance only.
func subscribeNew(t *testing.T, rp *rawPeer, v2 *Session, ns Namespace) (*Subscription, func(*wire.Object)) {
	t.Helper()
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, v2, ns, "t")
	st := acceptSubscribe(t, rp, 5*time.Second)
	if st == nil {
		sr := <-res
		if sr.err == nil {
			o, err := sr.sub.ReadObject(readCtx(t, 2*time.Second))
			t.Fatalf("the relay served the ended track: no upstream SUBSCRIBE; first read %+v, %v", o, err)
		}
		t.Fatalf("no upstream SUBSCRIBE: %v", sr.err)
	}
	write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 2, Params: &wire.MessageParams{}})
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	w, _ := subgroupStream(t, rp, 2, 0)
	w(&wire.Object{Payload: []byte("new")})
	if o := readN(t, ctx, sr.sub, 1)[0]; string(o.Payload) != "new" {
		t.Fatalf("the new subscriber got %+v", o)
	}
	return sr.sub, w
}

// endOld sends PUBLISH_DONE TRACK_ENDED for the old instance and checks
// that its subscriber gets the end while the new one keeps receiving.
func endOld(t *testing.T, req *kolotransport.Stream, fin func(), sub1, sub2 *Subscription, w2 func(*wire.Object)) {
	t.Helper()
	ctx := readCtx(t, 10*time.Second)
	write(t, req, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: 1})
	fin()
	for {
		o, err := sub1.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil || o.Status != StatusEndOfTrack {
			t.Fatalf("old subscriber: %+v, %v", o, err)
		}
	}
	w2(&wire.Object{ID: 1, Payload: []byte("new2")})
	if o := readN(t, ctx, sub2, 1)[0]; string(o.Payload) != "new2" {
		t.Fatalf("the new subscriber got %+v", o)
	}
}

// A publisher ends track t with End of Track and creates it again under the
// same name before its PUBLISH_DONE: a SUBSCRIBE that reaches the relay
// after the End of Track gets the new instance, never the ended one.
func TestRelayReAnnounceAfterEndOfTrack(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v1, _ := joinRelay(t, r, nil)
	v2, _ := joinRelay(t, r, nil)
	sub1, req, w, fin := reAnnounceStart(t, r, rp, v1, ns)
	w(&wire.Object{ID: 1, Status: uint64(StatusEndOfTrack)})
	if o := readN(t, readCtx(t, 10*time.Second), sub1, 1)[0]; o.Status != StatusEndOfTrack {
		t.Fatalf("object %+v", o)
	}
	sub2, w2 := subscribeNew(t, rp, v2, ns)
	endOld(t, req, fin, sub1, sub2, w2)
	sub2.Close()
	eventually(t, "the relay to release both instances", func() bool { return released(r) })
}

// PUBLISH_DONE takes the track out of the relay at once, while its last
// stream is still awaited.
func TestRelayReAnnounceAfterPublishDone(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v1, _ := joinRelay(t, r, nil)
	v2, _ := joinRelay(t, r, nil)
	sub1, req, _, fin := reAnnounceStart(t, r, rp, v1, ns)
	write(t, req, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: 2})
	eventually(t, "the ended track to leave the relay", func() bool { m, _, _ := liveTracks(r); return m == 0 })
	if _, c, _ := liveTracks(r); c != 1 {
		t.Fatalf("%d tracks counted, want the ended one", c)
	}
	sub2, w2 := subscribeNew(t, rp, v2, ns)
	fin()
	w, fin2 := subgroupStream(t, rp, 1, 1)
	w(&wire.Object{Payload: []byte("last")})
	fin2()
	ctx := readCtx(t, 10*time.Second)
	if o := readN(t, ctx, sub1, 1)[0]; string(o.Payload) != "last" {
		t.Fatalf("old subscriber got %+v", o)
	}
	if _, err := sub1.ReadObject(ctx); err != io.EOF {
		t.Fatalf("old subscriber: %v", err)
	}
	w2(&wire.Object{ID: 1, Payload: []byte("new2")})
	if o := readN(t, ctx, sub2, 1)[0]; string(o.Payload) != "new2" {
		t.Fatalf("the new subscriber got %+v", o)
	}
	sub2.Close()
	eventually(t, "the relay to release both instances", func() bool { return released(r) })
}

// A SUBSCRIBE that found the track just before its End of Track arrived is
// served the next instance, not refused and not bound to the ended one.
func TestRelaySubscribeRetriesEndedTrack(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v1, _ := joinRelay(t, r, nil)
	v2, _ := joinRelay(t, r, nil)
	_, _, _, _ = reAnnounceStart(t, r, rp, v1, ns)
	r.mu.Lock()
	rt := r.tracks[trackKey(ns, "t")]
	r.mu.Unlock()
	// Holding the track's lock stops the second SUBSCRIBE between acquire and
	// attach; the End of Track then lands as the relay's sink applies it.
	rt.t.mu.Lock()
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, v2, ns, "t")
	eventually(t, "the second SUBSCRIBE to find the track", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return rt.refs == 2
	})
	rt.retire()
	rt.t.final, rt.t.finalLoc = true, wire.Location{Object: 1}
	rt.t.mu.Unlock()
	st := acceptSubscribe(t, rp, 5*time.Second)
	if st == nil {
		sr := <-res
		t.Fatalf("no upstream SUBSCRIBE for the next instance: %v", sr.err)
	}
	write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 2, Params: &wire.MessageParams{}})
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	w, _ := subgroupStream(t, rp, 2, 0)
	w(&wire.Object{Payload: []byte("new")})
	if o := readN(t, ctx, sr.sub, 1)[0]; string(o.Payload) != "new" {
		t.Fatalf("object %+v", o)
	}
}

// A PUBLISH_DONE that follows SUBSCRIBE_OK at once retires the track while
// the relay still opens it: the subscriber that opened it gets the end, or
// the publisher's answer to a new SUBSCRIBE when the end came before it
// attached, never an internal error.
func TestRelayPublishDoneWhileOpening(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v, _ := joinRelay(t, r, nil)
	ctx := readCtx(t, 20*time.Second)
	for i := range 20 {
		name := fmt.Sprint("t", i)
		res := subscribeAsync(ctx, v, ns, name)
		st, _, m := rp.accept()
		if m.Type != wire.MsgSubscribe {
			t.Fatalf("request type 0x%x", m.Type)
		}
		alias := uint64(i + 1)
		b := msg(wire.MsgSubscribeOK, (&wire.SubscribeOK{TrackAlias: alias, Params: &wire.MessageParams{}}).Append(nil))
		b = append(b, msg(wire.MsgPublishDone, (&wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: 1}).Append(nil))...)
		mustSend(t, st, b)
		w, fin := subgroupStream(t, rp, alias, 0)
		w(&wire.Object{Payload: []byte(name)})
		fin()
		var sr subResult
		select {
		case sr = <-res:
		case <-time.After(time.Second):
			// The upstream subscription ended before the subscriber attached, so
			// the relay asks the publisher again, which no longer has the track.
			st := acceptSubscribe(t, rp, 5*time.Second)
			if st == nil {
				t.Fatalf("%s: no answer and no new upstream SUBSCRIBE", name)
			}
			write(t, st, wire.MsgRequestError, &wire.RequestError{Code: uint64(ReqDoesNotExist)})
			if sr = <-res; requestCode(sr.err) != ReqDoesNotExist {
				t.Fatalf("%s: %v", name, sr.err)
			}
			continue
		}
		if sr.err != nil {
			t.Fatalf("%s: %v", name, sr.err)
		}
		for {
			// The object may precede the subscriber's start; the end may not be an error.
			o, err := sr.sub.ReadObject(ctx)
			if err == io.EOF {
				break
			}
			if err != nil || string(o.Payload) != name {
				t.Fatalf("%s: %+v, %v", name, o, err)
			}
		}
	}
	eventually(t, "the relay to release every track", func() bool { return released(r) })
}

// The relay retires a track before it caches and forwards its End of Track:
// while retiring is held up, the subscriber gets no End of Track.
func TestRelayRetiresBeforeCachingEnd(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v1, _ := joinRelay(t, r, nil)
	sub1, req, w, fin := reAnnounceStart(t, r, rp, v1, ns)
	r.mu.Lock()
	w(&wire.Object{ID: 1, Status: uint64(StatusEndOfTrack)})
	o, err := sub1.ReadObject(readCtx(t, 300*time.Millisecond))
	r.mu.Unlock()
	if err == nil {
		t.Fatalf("End of Track forwarded before the track left the relay: %+v", o)
	}
	ctx := readCtx(t, 10*time.Second)
	if o := readN(t, ctx, sub1, 1)[0]; o.Status != StatusEndOfTrack {
		t.Fatalf("object %+v", o)
	}
	if m, _, _ := liveTracks(r); m != 0 {
		t.Fatal("the ended track is still mapped")
	}
	write(t, req, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: 1})
	fin()
	if _, err := sub1.ReadObject(ctx); err != io.EOF {
		t.Fatalf("subscriber: %v", err)
	}
	eventually(t, "the relay to release the track", func() bool { return released(r) })
}

// A track retired before the relay finished opening it still serves the
// subscriber that opened it.
func TestRelayRetiredWhileOpening(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v, _ := joinRelay(t, r, nil)
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, v, ns, "t")
	st, _, m := rp.accept()
	if m.Type != wire.MsgSubscribe {
		t.Fatalf("request type 0x%x", m.Type)
	}
	// Holding the lock keeps open from checking the track until it is retired.
	r.mu.Lock()
	write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}})
	delete(r.tracks, trackKey(ns, "t"))
	r.mu.Unlock()
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	write(t, st, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded)})
	if _, err := sr.sub.ReadObject(ctx); err != io.EOF {
		t.Fatalf("subscriber: %v", err)
	}
	eventually(t, "the relay to release the track", func() bool { return released(r) })
}

// The upstream subscription can end, and take its track out of the relay,
// before open has handed the track to the subscribers waiting for it: they
// get the track and its end, not INTERNAL_ERROR.
func TestRelayUpstreamEndsWhileOpening(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v, _ := joinRelay(t, r, nil)
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, v, ns, "t")
	st, _, m := rp.accept()
	if m.Type != wire.MsgSubscribe {
		t.Fatalf("request type 0x%x", m.Type)
	}
	// Holding the lock keeps open from its check; the removal is what the
	// end of the upstream subscription does (relaySink.done).
	r.mu.Lock()
	write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}})
	r.removeLocked(r.tracks[trackKey(ns, "t")])
	r.mu.Unlock()
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	write(t, st, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded)})
	if _, err := sr.sub.ReadObject(ctx); err != io.EOF {
		t.Fatalf("subscriber: %v", err)
	}
	eventually(t, "the relay to release the track", func() bool { return released(r) })
}

// A track whose End of Track is cached takes no new subscription.
func TestTrackAttachAfterEndOfTrack(t *testing.T) {
	tr, err := newTrack(Namespace{"a"}, "t", nil, 1<<10)
	if err != nil {
		t.Fatal(err)
	}
	if !tr.add(newCobj(wire.Object{Status: uint64(StatusEndOfTrack)}, false)) {
		t.Fatal("End of Track refused")
	}
	if _, _, ok := tr.attach(&pubSub{}); ok {
		t.Fatal("attached to a track after its End of Track")
	}
}

// An ended track still counts against MaxCacheBytes until its upstream
// subscription ends, so a publisher that never sends PUBLISH_DONE cannot
// make the relay hold more tracks than the budget allows.
func TestRelayEndedTrackCountsUntilDone(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, &RelayConfig{CacheBytes: 1 << 10, MaxCacheBytes: relayTrackOverhead + 1<<10})
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	v1, _ := joinRelay(t, r, nil)
	v2, _ := joinRelay(t, r, nil)
	sub1, req, w, fin := reAnnounceStart(t, r, rp, v1, ns)
	w(&wire.Object{ID: 1, Status: uint64(StatusEndOfTrack)})
	ctx := readCtx(t, 10*time.Second)
	readN(t, ctx, sub1, 1)
	if _, err := v2.Subscribe(ctx, ns, "t", nil); requestCode(err) != ReqExcessiveLoad {
		t.Fatalf("SUBSCRIBE over MaxCacheBytes: %v", err)
	}
	write(t, req, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: 1})
	fin()
	if _, err := sub1.ReadObject(ctx); err != io.EOF {
		t.Fatalf("old subscriber: %v", err)
	}
	eventually(t, "the ended track to be released", func() bool { return released(r) })
	sub2, _ := subscribeNew(t, rp, v2, ns)
	sub2.Close()
	eventually(t, "the relay to release the new instance", func() bool { return released(r) })
}

// TestRelayReAnnounceOrigin ends a track of a real Origin and creates it
// again under the same name, round after round: each new subscriber must
// receive the new instance and each old one its end.
func TestRelayReAnnounceOrigin(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	origin := newOrigin(t)
	pub, _ := joinRelay(t, r, &Config{Origin: origin})
	if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
		t.Fatal(err)
	}
	viewers := make([]*Session, 2)
	for i := range viewers {
		viewers[i], _ = joinRelay(t, r, nil)
	}
	ctx := testCtx(t)
	tw := mustTrack(t, origin, ns, "t", nil)
	cur, err := viewers[0].Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 16<<10)
	for round := range 100 {
		// Groups still in flight hold the old instance's PUBLISH_DONE behind its End of Track.
		for range 3 {
			gw := mustGroup(t, tw)
			for range 4 {
				mustWrite(t, gw, payload)
			}
		}
		if err := tw.Close(); err != nil {
			t.Fatal(err)
		}
		tw = mustTrack(t, origin, ns, "t", nil)
		var final Object
		for final.Status != StatusEndOfTrack {
			if final, err = cur.ReadObject(ctx); err != nil {
				t.Fatalf("round %d: old subscriber before End of Track: %v", round, err)
			}
		}
		next, err := viewers[(round+1)%2].Subscribe(ctx, ns, "t", nil)
		if err != nil {
			t.Fatalf("round %d: %v", round, err)
		}
		mustWrite(t, mustGroup(t, tw), []byte(fmt.Sprint(round)))
		rctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		o, err := next.ReadObject(rctx)
		cancel()
		if err != nil || string(o.Payload) != fmt.Sprint(round) {
			t.Fatalf("round %d: the new subscriber got %+v, %v (bound to the ended track)", round, o, err)
		}
		// Earlier groups travel on their own streams and can follow the End of Track.
		for {
			o, err := cur.ReadObject(ctx)
			if err == io.EOF {
				break
			}
			if err != nil || o.Group >= final.Group {
				t.Fatalf("round %d: old subscriber after End of Track: %+v, %v", round, o, err)
			}
		}
		cur = next
	}
	cur.Close()
	tw.Close()
	eventually(t, "the relay to release every instance", func() bool { return released(r) })
}

// TestRelayReAnnounceStress repeats the End of Track case 200 times with
// PUBLISH_DONE 0 to 2 ms after it, so the second SUBSCRIBE lands before,
// during and after the relay processes the end.
func TestRelayReAnnounceStress(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"re"}
	rp, _ := rawPublisher(t, r, ns)
	viewers := make([]*Session, 2)
	for i := range viewers {
		viewers[i], _ = joinRelay(t, r, nil)
	}
	ctx := testCtx(t)
	cur, req, w, fin := reAnnounceStart(t, r, rp, viewers[0], ns)
	for round := range 200 {
		w(&wire.Object{ID: 1, Status: uint64(StatusEndOfTrack)})
		ended := make(chan error, 1)
		go func(req *kolotransport.Stream, fin func()) {
			time.Sleep(time.Duration(round%5) * 500 * time.Microsecond)
			_, err := req.Write(msg(wire.MsgPublishDone, (&wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: 1}).Append(nil)))
			fin()
			ended <- err
		}(req, fin)
		if o := readN(t, ctx, cur, 1)[0]; o.Status != StatusEndOfTrack {
			t.Fatalf("round %d: object %+v", round, o)
		}
		alias := uint64(round + 2)
		res := subscribeAsync(ctx, viewers[(round+1)%2], ns, "t")
		st := acceptSubscribe(t, rp, 5*time.Second)
		if st == nil {
			sr := <-res
			t.Fatalf("round %d: no upstream SUBSCRIBE (bound to the ended track): %v", round, sr.err)
		}
		write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: alias, Params: &wire.MessageParams{}})
		sr := <-res
		if sr.err != nil {
			t.Fatalf("round %d: %v", round, sr.err)
		}
		if err := <-ended; err != nil {
			t.Fatal(err)
		}
		w, fin = subgroupStream(t, rp, alias, 0)
		w(&wire.Object{Payload: []byte(fmt.Sprint(round))})
		if o := readN(t, ctx, sr.sub, 1)[0]; string(o.Payload) != fmt.Sprint(round) {
			t.Fatalf("round %d: the new subscriber got %+v", round, o)
		}
		if _, err := cur.ReadObject(ctx); err != io.EOF {
			t.Fatalf("round %d: old subscriber: %v", round, err)
		}
		cur, req = sr.sub, st
	}
	cur.Close()
	eventually(t, "the relay to release every instance", func() bool { return released(r) })
}
