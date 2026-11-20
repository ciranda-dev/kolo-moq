package kolomoq

import (
	"crypto/ed25519"
	"errors"
	"testing"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

func TestNamespaceGoAwayRepeated(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	nsc := make(chan *NamespaceSubscription, 1)
	go func() {
		n, err := s.SubscribeNamespace(ctx, Namespace{"a"})
		if err != nil {
			t.Error(err)
		}
		nsc <- n
	}()
	st, _, _ := r.accept()
	write(t, st, wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}})
	n := <-nsc
	for range 2 {
		write(t, st, wire.MsgGoAway, &wire.GoAway{})
	}
	if _, err := n.Next(ctx); err == nil {
		t.Fatal("no error")
	}
	sessionErr(t, s.Err(), CodeProtocolViolation)
}

func TestFillNeedsFetchAuthorization(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"a"}, "t", nil)
	writeGroups(t, tw, 1, 2)
	cfg := &Config{Origin: origin, Authorize: func(_ ed25519.PublicKey, kind RequestKind, _ Namespace, _ string) error {
		if kind == KindFetch {
			return errors.New("no history")
		}
		return nil
	}}
	p := newPair(t, nil, cfg)
	ctx := testCtx(t)
	if _, err := p.client.Subscribe(ctx, Namespace{"a"}, "t", &SubscribeOptions{Priority: 1, Join: JoinCurrentGroup}); requestCode(err) != ReqUnauthorized {
		t.Fatalf("subscribe with fill: %v", err)
	}
	if _, err := p.client.Subscribe(ctx, Namespace{"a"}, "t", nil); err != nil {
		t.Fatalf("live subscribe: %v", err)
	}
}

func TestEmptyObjectsCountAgainstBuffer(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"e"}, "t", nil)
	const limit = 64 << 10
	p := newPair(t, &Config{MaxObjectSize: 1024, MaxBufferedBytes: limit}, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, Namespace{"e"}, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	gw := mustGroup(t, tw)
	for range 3000 {
		mustWrite(t, gw, nil)
	}
	eventually(t, "a drop", func() bool { return sub.Dropped() > 0 })
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.bytes > limit {
		t.Fatalf("%d bytes buffered", sub.bytes)
	}
}

func TestFailedSubscribeStopsFillStream(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	errc := make(chan error, 1)
	go func() {
		_, err := s.Subscribe(ctx, Namespace{"a"}, "t", &SubscribeOptions{Priority: 1, Join: JoinCurrentGroup})
		errc <- err
	}()
	st, _, m := r.accept()
	ds, err := r.conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var w wire.FetchWriter
	hdr := wire.AppendVarint(wire.AppendVarint(nil, wire.StreamTypeFetch), m.RequestID)
	mustSend(t, ds, w.Append(hdr, &wire.Object{Payload: []byte("x")}))
	write(t, st, wire.MsgRequestError, &wire.RequestError{Code: uint64(ReqDoesNotExist)})
	if err := <-errc; requestCode(err) != ReqDoesNotExist {
		t.Fatalf("subscribe: %v", err)
	}
	eventually(t, "STOP_SENDING on the fill stream", func() bool {
		_, err := ds.Write(w.Append(nil, &wire.Object{Payload: []byte("y")}))
		var te *kolotransport.Error
		return errors.As(err, &te)
	})
}

func TestOneFillAtATime(t *testing.T) {
	p := &pubSub{filling: true}
	p.startFill(&fillPlan{}) // a second fill returns before touching the track
}

func TestDeadSetBounded(t *testing.T) {
	p := &pubSub{s: &Session{cfg: Config{MaxBufferedGroups: 4}}, dead: map[sgKey]struct{}{}}
	for g := range uint64(100) {
		p.markDead(sgKey{group: g})
	}
	if len(p.dead) != 8 || len(p.deadFIFO) != 8 {
		t.Fatalf("%d dead, %d in FIFO", len(p.dead), len(p.deadFIFO))
	}
	if _, ok := p.dead[sgKey{group: 99}]; !ok {
		t.Fatal("newest dropped")
	}
}
