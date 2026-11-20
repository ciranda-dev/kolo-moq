package secobj

import (
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"testing"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

// TestOpenersAreIndependent checks that each Opener of one Keyring opens an object once, whatever
// the others opened: a second watch of the same namespace reads the objects the first one read.
func TestOpenersAreIndependent(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	k.deliver(e, msgBytes(1, 1, ns, 1))
	obj := openObject(t, baseOf(1), 1, "a", 0, 0, "x")
	var ops []*Opener
	for range 3 {
		o, err := k.opener(ns, "a")
		if err != nil {
			t.Fatal(err)
		}
		ops = append(ops, o)
	}
	for i, o := range ops {
		if pt, _, err := o.Open(obj); err != nil || string(pt) != "x" {
			t.Fatalf("opener %d: %q %v", i, pt, err)
		}
	}
	for i, o := range ops {
		if _, _, err := o.Open(obj); err != ErrReplay {
			t.Fatalf("opener %d again: %v", i, err)
		}
	}
}

// TestConcurrentOpeners opens the same objects through several Openers at once while a new key arrives.
func TestConcurrentOpeners(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	k.deliver(e, msgBytes(1, 0, ns, 1))
	objs := make([]kolomoq.Object, 200)
	for i := range objs {
		objs[i] = openObject(t, baseOf(1), 0, "a", 0, uint64(i), "x")
	}
	var wg sync.WaitGroup
	opened := make([]int, 4)
	for w := range opened {
		o, err := k.opener(ns, "a")
		if err != nil {
			t.Fatal(err)
		}
		wg.Go(func() {
			for _, obj := range objs {
				if _, _, err := o.Open(obj); err == nil {
					opened[w]++
				}
				if _, _, err := o.Open(obj); err == nil {
					t.Error("an object opened twice through one Opener")
				}
			}
		})
	}
	wg.Go(func() { k.deliver(e, msgBytes(1, 1, ns, 2)) })
	wg.Wait()
	for w, n := range opened {
		if n != len(objs) {
			t.Errorf("opener %d opened %d of %d", w, n, len(objs))
		}
	}
}

// TestOpenerSession checks, for every protected track, data tracks included, that an Opener is
// made only for a session whose peer owns the namespace or is a listed relay.
func TestOpenerSession(t *testing.T) {
	alice, bob, relay, mallory := newNode(t), newNode(t), newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub, mallory.pub}); err != nil {
		t.Fatal(err)
	}
	k := newKeyring(t, KeyringConfig{Relays: []ed25519.PublicKey{relay.pub}})
	fromAlice, _ := link(t, alice, bob, nil)
	receive(t, k, fromAlice, bob.pub, ns)
	waitKID(t, k, ns, 1)
	fromRelay, _ := link(t, relay, bob, nil)
	fromMallory, _ := link(t, mallory, bob, nil)
	chat := seal(t, s, "chat", 0, 0, "raised hand")
	for name, sess := range map[string]*kolomoq.Session{"owner": fromAlice, "listed relay": fromRelay} {
		o, err := k.Opener(sess, ns, "chat")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if pt, _, err := o.Open(chat); err != nil || string(pt) != "raised hand" {
			t.Fatalf("%s: %q %v", name, pt, err)
		}
	}
	if o, err := k.Opener(fromMallory, ns, "chat"); err != ErrWrongSession || o != nil {
		t.Fatalf("another member's session: %v", err)
	}
	if _, err := k.Opener(nil, ns, "chat"); err != ErrWrongSession {
		t.Fatalf("nil session: %v", err)
	}
	if _, err := k.Opener(fromAlice, ns, string(make([]byte, 5000))); err != kolomoq.ErrInvalidName {
		t.Fatalf("long track name: %v", err)
	}
}

// TestOpenerKeepsReplayStateOnEviction checks that dropping a track's derived keys beyond the
// 1024 tracks of a namespace keeps what its Opener opened.
func TestOpenerKeepsReplayStateOnEviction(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	k.deliver(e, msgBytes(1, 1, ns, 1))
	o, err := k.opener(ns, "first")
	if err != nil {
		t.Fatal(err)
	}
	obj := openObject(t, baseOf(1), 1, "first", 0, 0, "x")
	if _, _, err := o.Open(obj); err != nil {
		t.Fatal(err)
	}
	for i := range maxTrackKeys {
		name := fmt.Sprintf("t%d", i)
		mustOpen(t, k, ns, name, openObject(t, baseOf(1), 1, name, 0, 0, "y"), "y")
	}
	k.mu.Lock()
	_, kept := e.tracks["first"]
	k.mu.Unlock()
	if kept {
		t.Fatal("the least recently used track kept its keys")
	}
	if _, _, err := o.Open(obj); err != ErrReplay {
		t.Fatalf("replay after eviction: %v", err)
	}
	if pt, _, err := o.Open(openObject(t, baseOf(1), 1, "first", 0, 1, "z")); err != nil || string(pt) != "z" {
		t.Fatalf("next object after eviction: %q %v", pt, err)
	}
}

// TestZeroValues checks that a Sender, Keyring or Opener not made by its constructor returns
// ErrInvalidConfig instead of panicking.
func TestZeroValues(t *testing.T) {
	var s Sender
	n := newNode(t)
	tw, err := n.origin.CreateTrack(testNS, "a", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()
	g, err := tw.NewGroup()
	if err != nil {
		t.Fatal(err)
	}
	_, _, sealErr := s.Seal("a", 0, 0, 48, []byte("x"), nil)
	_, writeErr := s.Write(g, "a", []byte("x"))
	var k Keyring
	_, openerErr := k.Opener(nil, testNS, "a")
	var o Opener
	_, _, openErr := o.Open(kolomoq.Object{})
	var nilOpener *Opener
	_, _, nilErr := nilOpener.Open(kolomoq.Object{})
	for name, err := range map[string]error{
		"Seal": sealErr, "Write": writeErr, "SetMembers": s.SetMembers(nil), "Rotate": s.Rotate(), "Close": s.Close(),
		"Receive": k.Receive(testCtx(t), nil, nil, testNS), "MayCarry": k.MayCarry(nil, testNS), "Opener": openerErr,
		"Open": openErr, "nil Open": nilErr,
	} {
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	k.Remove(testNS)
	k.Stats()
	s.KeyID()
	s.Members()
}

// TestWriteUsesTrackPriority checks that Write seals under the priority of the group's track,
// which is the priority receivers see and authenticate.
func TestWriteUsesTrackPriority(t *testing.T) {
	alice, bob := newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bobSide, _ := link(t, alice, bob, nil)
	k := newKeyring(t, KeyringConfig{})
	receive(t, k, bobSide, bob.pub, ns)
	waitKID(t, k, ns, 1)
	ctx := testCtx(t)
	for _, prio := range []uint8{0, 90, 255} {
		name := fmt.Sprintf("p%d", prio)
		tw, err := alice.origin.CreateTrack(ns, name, &kolomoq.TrackOptions{Priority: prio})
		if err != nil {
			t.Fatal(err)
		}
		defer tw.Close()
		sub, err := bobSide.Subscribe(ctx, ns, name, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer sub.Close()
		g, err := tw.NewGroup()
		if err != nil {
			t.Fatal(err)
		}
		if g.Priority() != prio {
			t.Fatalf("GroupWriter.Priority %d, want %d", g.Priority(), prio)
		}
		if _, err := s.Write(g, name, []byte("x")); err != nil {
			t.Fatal(err)
		}
		obj, err := sub.ReadObject(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if obj.Priority != prio {
			t.Fatalf("object priority %d, want %d", obj.Priority, prio)
		}
		o, err := k.Opener(bobSide, ns, name)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := o.Open(obj); err != nil {
			t.Fatalf("priority %d: %v", prio, err)
		}
	}
}

// TestSenderChanged checks that Changed is closed by every key change and by nothing else.
func TestSenderChanged(t *testing.T) {
	n, bob := newNode(t), newNode(t)
	s := newSender(t, n, nil)
	closed := func(c <-chan struct{}) bool {
		select {
		case <-c:
			return true
		default:
			return false
		}
	}
	c := s.Changed()
	if err := s.SetMembers(nil); err != nil || closed(c) {
		t.Fatalf("no change: %v, closed %v", err, closed(c))
	}
	seal(t, s, "a", 0, 0, "x")
	if closed(c) {
		t.Fatal("closed by a seal")
	}
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil || !closed(c) {
		t.Fatalf("join: %v, closed %v", err, closed(c))
	}
	c = s.Changed()
	if err := s.Rotate(); err != nil || !closed(c) {
		t.Fatalf("Rotate: %v, closed %v", err, closed(c))
	}
	c = s.Changed()
	seal(t, s, "a", 5, 0, "x")
	if _, _, err := s.Seal("a", 5, 0, 48, []byte("x"), nil); err != ErrObjectID || closed(c) {
		t.Fatalf("stale Seal: %v, closed %v", err, closed(c))
	}
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil || closed(c) {
		t.Fatalf("same members: %v, closed %v", err, closed(c))
	}
}
