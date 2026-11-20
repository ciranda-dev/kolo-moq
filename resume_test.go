package kolomoq

import (
	"context"
	"errors"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/netsim"
)

// resumeRig is a relay with a publisher whose connection goes through a link, and a watcher of the namespaces under
// "room" on a clean connection. Idle connections time out after 1 s, so a cut of 2 s kills the publisher's session.
type resumeRig struct {
	relay  *Relay
	link   *netsim.Link
	pubID  *koloid.Identity
	pubCfg *kolosecure.Config
	events chan NamespaceEvent
	ns     Namespace
	sess   chan *Session // the relay's sessions with the publisher, in order
	addr   string        // the relay's address, without the link
	srvKey []byte
}

func newResumeRig(t *testing.T, resume time.Duration) (*resumeRig, []byte) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	relay, err := NewRelay(&RelayConfig{Resume: resume})
	if err != nil {
		t.Fatal(err)
	}
	cfg := &kolosecure.Config{Transport: &kolotransport.Config{MaxIncomingStreams: 1000, MaxConnsPerIP: 32, IdleTimeout: time.Second, KeepAlivePeriod: 500 * time.Millisecond}}
	srvID, _ := koloid.Generate()
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", srvID, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	r := &resumeRig{relay: relay, events: make(chan NamespaceEvent, 16), ns: Namespace{"room", "ana"}, sess: make(chan *Session, 8)}
	r.pubID, _ = koloid.Generate()
	r.pubCfg = cfg
	r.addr, r.srvKey = l.Addr().String(), srvID.PublicKey()
	if r.link, err = netsim.New(l.Addr().String(), netsim.Profile{}, netsim.Profile{}); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.link.Close() })
	watcherID, _ := koloid.Generate()
	go func() {
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			s, err := relay.NewServer(ctx, c)
			if err != nil {
				continue
			}
			if string(c.RemotePublicKey()) == string(r.pubID.PublicKey()) {
				r.sess <- s
			}
		}
	}()
	wc, err := kolosecure.Dial(ctx, l.Addr().String(), watcherID, srvID.PublicKey(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	ws, err := NewClient(ctx, wc, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ws.Close() })
	sub, err := ws.SubscribeNamespace(ctx, Namespace{"room"})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			ev, err := sub.Next(ctx)
			if err != nil {
				return
			}
			r.events <- ev
		}
	}()
	return r, srvID.PublicKey()
}

// publish connects the publisher through the link and announces its namespace.
func (r *resumeRig) publish(t *testing.T, srvKey []byte) *Session {
	t.Helper()
	s, err := r.publishWith(t, srvKey, newOrigin(t))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// publishWith is publish with origin; it returns the announcement's error instead of failing on it.
func (r *resumeRig) publishWith(t *testing.T, srvKey []byte, origin *Origin) (*Session, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc, err := kolosecure.Dial(ctx, r.link.Addr(), r.pubID, srvKey, r.pubCfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewClient(context.Background(), cc, &Config{Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	_, err = s.PublishNamespace(ctx, r.ns)
	return s, err
}

// dial connects a new peer with identity id to the relay directly, without the link.
func (r *resumeRig) dial(t *testing.T, id *koloid.Identity, origin *Origin) *Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cc, err := kolosecure.Dial(ctx, r.addr, id, r.srvKey, r.pubCfg)
	if err != nil {
		t.Fatal(err)
	}
	s, err := NewClient(context.Background(), cc, &Config{Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// held returns how many announcements the relay holds, and checks that the held ones keep no session.
func (r *resumeRig) held(t *testing.T) int {
	t.Helper()
	r.relay.mu.Lock()
	defer r.relay.mu.Unlock()
	for a := range r.relay.announce {
		if (a.elem != nil) != (a.s == nil) {
			t.Fatalf("announcement %v: held %v, session kept %v", a.ns, a.elem != nil, a.s != nil)
		}
	}
	return r.relay.held.Len()
}

func (r *resumeRig) expect(t *testing.T, active bool, within time.Duration) {
	t.Helper()
	select {
	case ev := <-r.events:
		if ev.Active != active {
			t.Fatalf("event %v, want active=%v", ev, active)
		}
	case <-time.After(within):
		t.Fatalf("no active=%v event within %v", active, within)
	}
}

func (r *resumeRig) none(t *testing.T, d time.Duration) {
	t.Helper()
	select {
	case ev := <-r.events:
		t.Fatalf("unexpected event %v", ev)
	case <-time.After(d):
	}
}

// A publisher whose connection is lost and who comes back inside Resume is never seen to leave, and its older
// session, still running at the relay when the new one announces, is closed.
func TestRelayResumeKeepsNamespace(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, 5*time.Second)
	r.publish(t, key)
	r.expect(t, true, 3*time.Second)
	old := <-r.sess
	cutEnd := time.Now().Add(3 * time.Second)
	r.link.Cut(3 * time.Second)
	select {
	case <-old.Done():
	case <-time.After(8 * time.Second):
		t.Fatal("the relay's session with the publisher never timed out")
	}
	if !old.connLost(0) {
		t.Fatalf("session ended with %v, want a lost connection", old.Err())
	}
	r.none(t, 500*time.Millisecond)                       // lost, but held
	time.Sleep(time.Until(cutEnd) + 200*time.Millisecond) // the cut is over
	r.publish(t, key)
	r.none(t, 1500*time.Millisecond)
	if cur := <-r.sess; cur.Err() != nil {
		t.Fatalf("the new session ended: %v", cur.Err())
	}
}

// A new session of the same publisher replaces the old one while that still runs.
func TestRelayResumeReplacesLiveSession(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, 5*time.Second)
	r.publish(t, key)
	r.expect(t, true, 3*time.Second)
	old := <-r.sess
	r.publish(t, key)
	select {
	case <-old.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the older session of the publisher still runs")
	}
	if errors.Is(old.Err(), ErrClosed) == false {
		t.Fatalf("older session ended with %v", old.Err())
	}
	r.none(t, time.Second)
}

// A publisher that does not come back is seen to leave when Resume is over, not before.
func TestRelayResumeExpires(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, time.Second)
	r.publish(t, key)
	r.expect(t, true, 3*time.Second)
	old := <-r.sess
	r.link.Cut(time.Minute)
	<-old.Done()
	lostAt := time.Now()
	r.expect(t, false, 8*time.Second)
	if d := time.Since(lostAt); d < 800*time.Millisecond {
		t.Fatalf("left %v after the loss, Resume is 1s", d)
	}
}

// Without Resume the loss shows at once, and a session closed by its peer is never held.
func TestRelayWithoutResumeWithdraws(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, 0)
	s := r.publish(t, key)
	r.expect(t, true, 3*time.Second)
	<-r.sess
	s.Close()
	r.expect(t, false, 3*time.Second)
}

func TestRelayResumeRange(t *testing.T) {
	for _, d := range []time.Duration{time.Millisecond, 2 * time.Hour, -time.Second} {
		if _, err := NewRelay(&RelayConfig{Resume: d}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("Resume %v: %v", d, err)
		}
	}
}

// A publisher that suspends its session, as one does that found its path dead and goes to a new connection, is held like
// one whose connection was lost.
func TestRelayResumeAfterSuspend(t *testing.T) {
	checkLeaks(t)
	r, key := newResumeRig(t, 5*time.Second)
	s := r.publish(t, key)
	r.expect(t, true, 3*time.Second)
	old := <-r.sess
	s.Suspend()
	select {
	case <-old.Done():
	case <-time.After(3 * time.Second):
		t.Fatal("the relay's session never ended")
	}
	r.none(t, time.Second)
	r.publish(t, key)
	r.none(t, time.Second)
}
