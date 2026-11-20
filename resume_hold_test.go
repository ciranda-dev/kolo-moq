package kolomoq

import (
	"context"
	"errors"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

// originWith returns an origin with one track under ns whose first object is payload.
func originWith(t *testing.T, ns Namespace, name, payload string) *Origin {
	t.Helper()
	o := newOrigin(t)
	tw := mustTrack(t, o, ns, name, nil)
	gw := mustGroup(t, tw)
	if _, err := gw.WriteObject([]byte(payload)); err != nil {
		t.Fatal(err)
	}
	return o
}

// firstObject subscribes to ns/name through the relay as a new peer and returns the first payload.
func (r *resumeRig) firstObject(t *testing.T, ns Namespace, name string) (string, error) {
	t.Helper()
	id, _ := koloid.Generate()
	c := r.dial(t, id, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	sub, err := c.Subscribe(ctx, ns, name, &SubscribeOptions{Join: JoinCurrentGroup})
	if err != nil {
		return "", err
	}
	o, err := sub.ReadObject(ctx)
	if err != nil {
		return "", err
	}
	return string(o.Payload), nil
}

// suspended announces the rig's namespace with origin, suspends the session and waits for the relay to see it end.
func (r *resumeRig) suspended(t *testing.T, origin *Origin) {
	t.Helper()
	s, err := r.publishWith(t, r.srvKey, origin)
	if err != nil {
		t.Fatal(err)
	}
	r.expect(t, true, 3*time.Second)
	old := <-r.sess
	s.Suspend()
	select {
	case <-old.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the relay's session never ended")
	}
}

// While a publisher's announcement is held, another peer cannot announce its namespace or one under it; the publisher
// comes back, takes the namespace over, and subscribers get its tracks.
func TestRelayHeldNamespaceRefusesOtherPeers(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, 10*time.Second)
	r.suspended(t, originWith(t, r.ns, "video", "owner"))
	for _, ns := range []Namespace{r.ns, {"room", "ana", "deeper"}} {
		id, _ := koloid.Generate()
		c := r.dial(t, id, newOrigin(t))
		_, err := c.PublishNamespace(testCtx(t), ns)
		if requestCode(err) != ReqUnauthorized {
			t.Fatalf("squatter announcing %v: %v, want UNAUTHORIZED", ns, err)
		}
	}
	r.none(t, 500*time.Millisecond)
	eventually(t, "the announcement to be held", func() bool { return r.held(t) == 1 })
	if _, err := r.publishWith(t, key, originWith(t, r.ns, "video", "owner")); err != nil {
		t.Fatalf("the owner came back: %v", err)
	}
	r.none(t, 500*time.Millisecond)
	if got, err := r.firstObject(t, r.ns, "video"); err != nil || got != "owner" {
		t.Fatalf("subscriber got %q, %v; want the owner's object", got, err)
	}
	if n := r.held(t); n != 0 {
		t.Fatalf("%d announcements still held after the takeover", n)
	}
}

// A wider announcement of another peer does not catch the tracks under a held namespace.
func TestRelayHeldNamespaceNotRoutedToWiderAnnouncement(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, 10*time.Second)
	r.suspended(t, originWith(t, r.ns, "video", "owner"))
	id, _ := koloid.Generate()
	evil := r.dial(t, id, originWith(t, r.ns, "video", "squatter"))
	if _, err := evil.PublishNamespace(testCtx(t), Namespace{"room"}); err != nil {
		t.Fatalf("a wider namespace is no takeover of the held one: %v", err)
	}
	if got, err := r.firstObject(t, r.ns, "video"); err == nil {
		t.Fatalf("a subscriber under the held namespace reached %q", got)
	} else if requestCode(err) != ReqDoesNotExist {
		t.Fatalf("subscribe: %v, want DOES_NOT_EXIST", err)
	}
	if _, err := r.publishWith(t, key, originWith(t, r.ns, "video", "owner")); err != nil {
		t.Fatal(err)
	}
	if got, err := r.firstObject(t, r.ns, "video"); err != nil || got != "owner" {
		t.Fatalf("after the takeover a subscriber got %q, %v; want the owner's object", got, err)
	}
}

// When Resume is over the namespace is free again.
func TestRelayHeldNamespaceFreeAfterResume(t *testing.T) {
	checkLeaks(t)
	r, _ := newResumeRig(t, time.Second)
	r.suspended(t, newOrigin(t))
	r.expect(t, false, 4*time.Second)
	id, _ := koloid.Generate()
	c := r.dial(t, id, newOrigin(t))
	if _, err := c.PublishNamespace(testCtx(t), r.ns); err != nil {
		t.Fatalf("announcing after the hold ended: %v", err)
	}
	if n := r.held(t); n != 0 {
		t.Fatalf("%d announcements still held", n)
	}
}

// A publisher that came back and then closes cleanly withdraws its namespace at once: the held announcement of its
// lost session does not keep it active.
func TestRelayCleanCloseAfterResumeWithdraws(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, 20*time.Second)
	r.suspended(t, newOrigin(t))
	s := r.publish(t, key)
	r.none(t, 500*time.Millisecond)
	if n := r.held(t); n != 0 {
		t.Fatalf("%d announcements held after the publisher came back", n)
	}
	<-r.sess
	s.Close()
	r.expect(t, false, 3*time.Second)
}

// Held announcements are counted in total and for each peer; one that does not fit is withdrawn with its session, as
// without Resume, and the ended sessions are not kept.
func TestRelayResumeCaps(t *testing.T) {
	checkLeaks(t)
	ctx := testCtx(t)
	relay := newRelay(t, &RelayConfig{Resume: 30 * time.Second, MaxResumeHeld: 3, MaxPeerResumeHeld: 2})
	watcher, _ := joinRelay(t, relay, nil)
	sub, err := watcher.SubscribeNamespace(ctx, Namespace{"cap"})
	if err != nil {
		t.Fatal(err)
	}
	events := make(chan NamespaceEvent, 32)
	go func() {
		for {
			ev, err := sub.Next(ctx)
			if err != nil {
				return
			}
			events <- ev
		}
	}()
	// waitEvent waits for an event of one of the names; the withdrawn announcement of a suspended peer is any of them.
	waitEvent := func(active bool, names ...string) {
		t.Helper()
		deadline := time.After(5 * time.Second)
		for {
			select {
			case ev := <-events:
				for _, n := range names {
					if ev.Active == active && ev.Namespace.key() == (Namespace{"cap", n}).key() {
						return
					}
				}
			case <-deadline:
				t.Fatalf("no event active=%v for %v", active, names)
			}
		}
	}
	heldCount := func() int {
		relay.mu.Lock()
		defer relay.mu.Unlock()
		return relay.held.Len()
	}
	// suspend announces the namespaces as a new peer and suspends it.
	suspend := func(names ...string) {
		t.Helper()
		peer, _ := joinRelay(t, relay, &Config{Origin: newOrigin(t)})
		for _, n := range names {
			if _, err := peer.PublishNamespace(ctx, Namespace{"cap", n}); err != nil {
				t.Fatal(err)
			}
			waitEvent(true, n)
		}
		peer.Suspend()
	}
	suspend("a1", "a2", "a3") // two fit for the peer; the third is withdrawn at once
	waitEvent(false, "a1", "a2", "a3")
	eventually(t, "two held", func() bool { return heldCount() == 2 })
	suspend("b1", "b2") // one more fits in total; the second is withdrawn
	waitEvent(false, "b1", "b2")
	eventually(t, "three held", func() bool { return heldCount() == 3 })
	suspend("c1") // full
	waitEvent(false, "c1")
	relay.mu.Lock()
	defer relay.mu.Unlock()
	if relay.held.Len() != 3 || len(relay.heldBy) != 2 {
		t.Fatalf("held %d for %d peers, want 3 for 2", relay.held.Len(), len(relay.heldBy))
	}
	for e := relay.held.Front(); e != nil; e = e.Next() {
		if a := e.Value.(*announcement); a.s != nil {
			t.Fatalf("the relay keeps the ended session of %v", a.ns)
		}
	}
}

func TestRelayResumeHeldRange(t *testing.T) {
	for _, c := range []RelayConfig{{MaxResumeHeld: -1}, {MaxResumeHeld: 2_000_000}, {MaxResumeHeld: 5, MaxPeerResumeHeld: 6}, {MaxPeerResumeHeld: -1}} {
		if _, err := NewRelay(&c); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%+v: %v", c, err)
		}
	}
	r := newRelay(t, &RelayConfig{MaxResumeHeld: 7})
	if r.cfg.MaxPeerResumeHeld != 7 {
		t.Fatalf("MaxPeerResumeHeld default %d, want MaxResumeHeld 7", r.cfg.MaxPeerResumeHeld)
	}
	r = newRelay(t, nil)
	if r.cfg.MaxResumeHeld != 10000 || r.cfg.MaxPeerResumeHeld != 1000 {
		t.Fatalf("defaults %d and %d", r.cfg.MaxResumeHeld, r.cfg.MaxPeerResumeHeld)
	}
}

// fakeConn is a Conn whose context ended with cause.
type fakeConn struct {
	Conn
	ctx context.Context
}

func (c fakeConn) Context() context.Context { return c.ctx }

// A peer's Suspend that the connection reports before the session has recorded it still counts as a lost connection.
func TestConnLostSeesSuspendBeforeTheSessionRecordsIt(t *testing.T) {
	ctx, cancel := context.WithCancelCause(context.Background())
	cancel(&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: uint64(CodeSuspend)})
	if s := (&Session{conn: fakeConn{ctx: ctx}}); !s.connLost(0) {
		t.Fatal("a suspend seen on the connection first was not taken as a lost connection")
	}
	ctx, cancel = context.WithCancelCause(context.Background())
	cancel(&kolotransport.Error{Err: kolotransport.ErrPeerClosed, Code: uint64(CodeNoError)})
	if s := (&Session{conn: fakeConn{ctx: ctx}}); s.connLost(0) {
		t.Fatal("a clean close seen on the connection first was taken as a lost connection")
	}
}
