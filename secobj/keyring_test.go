package secobj

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"reflect"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolomoq "github.com/ciranda-dev/kolo-moq"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

var testTransport = &kolotransport.Config{MaxIncomingStreams: 1000}

// node is one participant: an identity and the origin it publishes.
type node struct {
	id     *koloid.Identity
	pub    ed25519.PublicKey
	origin *kolomoq.Origin
}

func newNode(t testing.TB) *node {
	t.Helper()
	id, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	o, err := kolomoq.NewOrigin(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &node{id: id, pub: id.PublicKey(), origin: o}
}

func mediaNS(pub ed25519.PublicKey) kolomoq.Namespace {
	return kolomoq.Namespace{"room", hex.EncodeToString(pub)}
}

// ownerAuth is the meeting rule: a peer owns {room, hex(peer)}.
func ownerAuth(peer ed25519.PublicKey, ns kolomoq.Namespace) error {
	if slices.Equal(ns, mediaNS(peer)) {
		return nil
	}
	return errors.New("not the owner")
}

func testCtx(t testing.TB) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// link connects sub to pub over kolo-secure on 127.0.0.1 and returns sub's session (its peer
// is pub) and pub's session. The publisher side serves pub.origin with cfg.
func link(t testing.TB, pub, sub *node, cfg *kolomoq.Config) (subSide, pubSide *kolomoq.Session) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", pub.id, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	if cfg == nil {
		cfg = &kolomoq.Config{}
	}
	if cfg.Origin == nil {
		cfg.Origin = pub.origin
	}
	type res struct {
		s   *kolomoq.Session
		err error
	}
	srv := make(chan res, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			srv <- res{nil, err}
			return
		}
		s, err := kolomoq.NewServer(ctx, c, cfg)
		srv <- res{s, err}
	}()
	c, err := kolosecure.Dial(ctx, l.Addr().String(), sub.id, pub.pub, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := kolomoq.NewClient(ctx, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	r := <-srv
	if r.err != nil {
		t.Fatal(r.err)
	}
	t.Cleanup(func() {
		cs.Close()
		r.s.Close()
	})
	return cs, r.s
}

func newKeyring(t testing.TB, cfg KeyringConfig) *Keyring {
	t.Helper()
	if cfg.Authorize == nil {
		cfg.Authorize = ownerAuth
	}
	k, err := NewKeyring(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newSender(t testing.TB, n *node, cfg *SenderConfig) *Sender {
	t.Helper()
	s, err := NewSender(n.origin, mediaNS(n.pub), cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

// receive runs k.Receive in the background; the returned channel gets its result.
func receive(t testing.TB, k *Keyring, s *kolomoq.Session, self ed25519.PublicKey, ns kolomoq.Namespace) <-chan error {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	finished := make(chan struct{})
	go func() {
		done <- k.Receive(ctx, s, self, ns)
		close(finished)
	}()
	t.Cleanup(func() {
		cancel()
		<-finished
	})
	return done
}

// checkLeaks fails the test if goroutines started during it outlive it.
func checkLeaks(t testing.TB) {
	t.Helper()
	before := runtime.NumGoroutine()
	t.Cleanup(func() {
		deadline := time.Now().Add(10 * time.Second)
		for runtime.NumGoroutine() > before {
			if time.Now().After(deadline) {
				buf := make([]byte, 1<<20)
				t.Errorf("goroutines: %d before, %d after\n%s", before, runtime.NumGoroutine(), buf[:runtime.Stack(buf, true)])
				return
			}
			time.Sleep(10 * time.Millisecond)
		}
	})
}

func eventually(t testing.TB, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func (k *Keyring) currentKID(ns kolomoq.Namespace) (uint64, bool) {
	k.mu.Lock()
	defer k.mu.Unlock()
	e := k.senders[nsKey(ns)]
	if e == nil || e.cur == nil {
		return 0, false
	}
	return e.cur.kid, true
}

func waitKID(t testing.TB, k *Keyring, ns kolomoq.Namespace, kid uint64) {
	t.Helper()
	eventually(t, "key ID", func() bool {
		got, ok := k.currentKID(ns)
		return ok && got == kid
	})
}

func seal(t testing.TB, s *Sender, track string, group, object uint64, payload string) kolomoq.Object {
	t.Helper()
	ct, props, err := s.Seal(track, group, object, 48, []byte(payload), nil)
	if err != nil {
		t.Fatal(err)
	}
	return kolomoq.Object{Group: group, ID: object, Priority: 48, Properties: props, Payload: ct}
}

// openerKey names the one reader of a track that openAt keeps per Keyring.
type openerKey struct {
	k         *Keyring
	ns, track string
}

var testOpeners sync.Map // openerKey to *Opener

// openAt opens obj with the Opener that openAt keeps for k, ns and track, as one reader of the
// track would; it skips the session check, which the Opener tests cover.
func openAt(k *Keyring, ns kolomoq.Namespace, track string, obj kolomoq.Object) ([]byte, []kolomoq.Property, error) {
	key := openerKey{k, nsKey(ns), track}
	o, ok := testOpeners.Load(key)
	if !ok {
		op, err := k.opener(ns, track)
		if err != nil {
			return nil, nil, err
		}
		o, _ = testOpeners.LoadOrStore(key, op)
	}
	return o.(*Opener).Open(obj)
}

func mustOpen(t testing.TB, k *Keyring, ns kolomoq.Namespace, track string, obj kolomoq.Object, want string) {
	t.Helper()
	got, _, err := openAt(k, ns, track, obj)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if string(got) != want {
		t.Fatalf("opened %q, want %q", got, want)
	}
}

func requestCode(err error) kolomoq.RequestCode {
	var re *kolomoq.RequestError
	if errors.As(err, &re) {
		return re.Code
	}
	return 0xffff
}

func TestReceiveAndOpen(t *testing.T) {
	checkLeaks(t)
	alice, bob := newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bobSide, _ := link(t, alice, bob, nil)
	k := newKeyring(t, KeyringConfig{})
	receive(t, k, bobSide, bob.pub, ns)
	waitKID(t, k, ns, s.KeyID())
	mustOpen(t, k, ns, "audio", seal(t, s, "audio", 0, 0, "hello"), "hello")
	if st := k.Stats(); st != (KeyringStats{}) {
		t.Fatalf("stats %+v", st)
	}
}

func TestRemovedMemberRotation(t *testing.T) {
	checkLeaks(t)
	alice, bob, carol := newNode(t), newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub, carol.pub}); err != nil {
		t.Fatal(err)
	}
	bobSide, _ := link(t, alice, bob, nil)
	carolSide, _ := link(t, alice, carol, nil)
	kb, kc := newKeyring(t, KeyringConfig{}), newKeyring(t, KeyringConfig{})
	receive(t, kb, bobSide, bob.pub, ns)
	carolDone := receive(t, kc, carolSide, carol.pub, ns)
	first := s.KeyID()
	waitKID(t, kb, ns, first)
	waitKID(t, kc, ns, first)
	before := seal(t, s, "audio", 0, 0, "before")
	mustOpen(t, kc, ns, "audio", before, "before")

	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	if s.KeyID() == first {
		t.Fatal("removal did not rotate")
	}
	after := seal(t, s, "audio", 1, 0, "after")
	waitKID(t, kb, ns, s.KeyID())
	mustOpen(t, kb, ns, "audio", after, "after")
	select {
	case err := <-carolDone:
		if err != nil {
			t.Fatalf("removed member's Receive: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("removed member's key track was not closed")
	}
	if kid, _ := kc.currentKID(ns); kid != first {
		t.Fatalf("removed member holds key ID %d", kid)
	}
	if _, _, err := openAt(kc, ns, "audio", after); err != ErrNoKey {
		t.Fatalf("removed member opened a later object: %v", err)
	}
	if got := s.Members(); len(got) != 1 || !got[0].Equal(bob.pub) {
		t.Fatalf("members %x", got)
	}
}

func TestJoinerCannotOpenEarlier(t *testing.T) {
	checkLeaks(t)
	alice, bob, dave := newNode(t), newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	before := seal(t, s, "video", 0, 0, "before")
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub, dave.pub}); err != nil {
		t.Fatal(err)
	}
	daveSide, _ := link(t, alice, dave, nil)
	k := newKeyring(t, KeyringConfig{})
	receive(t, k, daveSide, dave.pub, ns)
	waitKID(t, k, ns, s.KeyID())
	if _, _, err := openAt(k, ns, "video", before); err != ErrKeyRetired {
		t.Fatalf("joiner opened an earlier object: %v", err)
	}
	mustOpen(t, k, ns, "video", seal(t, s, "video", 1, 0, "after"), "after")
}

// TestKeyBeforeObject checks that a rotation's key message is queued before the first object
// under the new Key ID, for a re-created track and for Rotate.
func TestKeyBeforeObject(t *testing.T) {
	checkLeaks(t)
	alice, bob := newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bobSide, _ := link(t, alice, bob, nil)
	k := newKeyring(t, KeyringConfig{})
	receive(t, k, bobSide, bob.pub, ns)
	ctx := testCtx(t)
	keyGroup := func() uint64 {
		st, err := bobSide.TrackStatus(ctx, KeyNamespace(ns), KeyTrack(bob.pub))
		if err != nil || !st.HasLargest {
			t.Fatalf("key track status %+v %v", st, err)
		}
		return st.Largest.Group
	}
	if g := keyGroup(); g != 0 {
		t.Fatalf("key group %d", g)
	}

	tw, err := alice.origin.CreateTrack(ns, "video", &kolomoq.TrackOptions{Priority: 68})
	if err != nil {
		t.Fatal(err)
	}
	g, _ := tw.NewGroup()
	if _, err := s.Write(g, "video", []byte("one")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	tw, err = alice.origin.CreateTrack(ns, "video", &kolomoq.TrackOptions{Priority: 68})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()
	sub, err := bobSide.Subscribe(ctx, ns, "video", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	g, _ = tw.NewGroup()
	if _, err := s.Write(g, "video", []byte("two")); err != nil {
		t.Fatal(err)
	}
	obj, err := sub.ReadObject(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if kg := keyGroup(); kg != 1 || s.KeyID() != 2 {
		t.Fatalf("re-created track: key group %d, key ID %d", kg, s.KeyID())
	}
	openWhenKeyed(t, k, ns, "video", obj, "two")

	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	if kg := keyGroup(); kg != 2 {
		t.Fatalf("after Rotate: key group %d", kg)
	}
}

// openWhenKeyed retries Open on every keyring change while the key is in flight.
func openWhenKeyed(t testing.TB, k *Keyring, ns kolomoq.Namespace, track string, obj kolomoq.Object, want string) {
	t.Helper()
	timeout := time.After(10 * time.Second)
	for {
		changed := k.Changed()
		got, _, err := openAt(k, ns, track, obj)
		if err == nil {
			if string(got) != want {
				t.Fatalf("opened %q", got)
			}
			return
		}
		if err != ErrNoKey {
			t.Fatalf("open: %v", err)
		}
		select {
		case <-changed:
		case <-timeout:
			t.Fatal("key never arrived")
		}
	}
}

func TestRedeliveredCurrentGroup(t *testing.T) {
	checkLeaks(t)
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
	k.mu.Lock()
	gen := k.senders[nsKey(ns)].cur
	k.mu.Unlock()
	changed := k.Changed()
	receive(t, k, bobSide, bob.pub, ns)
	eventually(t, "redelivered key message", func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		return k.senders[nsKey(ns)].windowCount == 2
	})
	k.mu.Lock()
	same := k.senders[nsKey(ns)].cur == gen
	k.mu.Unlock()
	if !same || k.Stats() != (KeyringStats{}) {
		t.Fatalf("redelivery changed the keys: same %v, stats %+v", same, k.Stats())
	}
	select {
	case <-changed:
		t.Fatal("redelivery signalled a change")
	default:
	}
}

func TestSenderRestart(t *testing.T) {
	checkLeaks(t)
	alice, bob := newNode(t), newNode(t)
	s1, err := NewSender(alice.origin, mediaNS(alice.pub), nil)
	if err != nil {
		t.Fatal(err)
	}
	ns := s1.Namespace()
	if err := s1.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bobSide, _ := link(t, alice, bob, nil)
	k := newKeyring(t, KeyringConfig{})
	done := receive(t, k, bobSide, bob.pub, ns)
	waitKID(t, k, ns, 1)
	old := seal(t, s1, "audio", 0, 0, "old")
	mustOpen(t, k, ns, "audio", old, "old")
	k.mu.Lock()
	oldGen := k.senders[nsKey(ns)].cur
	k.mu.Unlock()
	s1.Close()
	if err := <-done; err != nil {
		t.Fatalf("Receive after the sender closed: %v", err)
	}

	s2 := newSender(t, alice, nil)
	if s2.instance == s1.instance {
		t.Fatal("instance ID reused")
	}
	if err := s2.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	receive(t, k, bobSide, bob.pub, ns)
	eventually(t, "new instance", func() bool {
		k.mu.Lock()
		defer k.mu.Unlock()
		return k.senders[nsKey(ns)].instance == s2.instance
	})
	if oldGen.base != ([keySize]byte{}) {
		t.Fatal("replaced key not erased")
	}
	if _, _, err := openAt(k, ns, "audio", old); err != ErrAuthentication {
		t.Fatalf("old instance object: %v", err)
	}
	mustOpen(t, k, ns, "audio", seal(t, s2, "audio", 0, 0, "new"), "new")
}

func TestReceiveRefusals(t *testing.T) {
	checkLeaks(t)
	alice, bob, carol := newNode(t), newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	ctx := testCtx(t)
	k := newKeyring(t, KeyringConfig{})

	t.Run("relay session", func(t *testing.T) {
		relay := newNode(t)
		r, err := kolomoq.NewRelay(nil)
		if err != nil {
			t.Fatal(err)
		}
		bobRelay := relayLink(t, r, relay, bob)
		if err := k.Receive(ctx, bobRelay, bob.pub, ns); err != ErrUnauthorized {
			t.Fatalf("relay session: %v", err)
		}
		open := newKeyring(t, KeyringConfig{Authorize: func(ed25519.PublicKey, kolomoq.Namespace) error { return nil }})
		if err := open.Receive(ctx, bobRelay, bob.pub, ns); requestCode(err) != kolomoq.ReqUnauthorized {
			t.Fatalf("relay with an Authorize that allows all: %v", err)
		}
		if _, ok := open.currentKID(ns); ok {
			t.Fatal("key installed through a relay")
		}
	})

	t.Run("peer that does not own the namespace", func(t *testing.T) {
		forged, err := NewSender(carol.origin, ns, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer forged.Close()
		if err := forged.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
			t.Fatal(err)
		}
		bobCarol, _ := link(t, carol, bob, nil)
		if err := k.Receive(ctx, bobCarol, bob.pub, ns); err != ErrUnauthorized {
			t.Fatalf("carol giving alice's key: %v", err)
		}
		if _, ok := k.currentKID(ns); ok {
			t.Fatal("key installed")
		}
	})

	t.Run("message for another namespace", func(t *testing.T) {
		dave := newNode(t)
		tw, err := dave.origin.CreateTrack(KeyNamespace(mediaNS(dave.pub)), KeyTrack(bob.pub), &kolomoq.TrackOptions{Readers: []ed25519.PublicKey{bob.pub}})
		if err != nil {
			t.Fatal(err)
		}
		defer tw.Close()
		m := keyMessage{kid: 7, ns: ns, base: testBase}
		g, _ := tw.NewGroup()
		g.WriteObject(appendKeyMessage(nil, &m))
		g.WriteObject([]byte("not a key message"))
		bobDave, _ := link(t, dave, bob, nil)
		kd := newKeyring(t, KeyringConfig{})
		receive(t, kd, bobDave, bob.pub, mediaNS(dave.pub))
		eventually(t, "rejections", func() bool { return kd.Stats().Rejected == 2 })
		for _, n := range []kolomoq.Namespace{ns, mediaNS(dave.pub)} {
			if _, ok := kd.currentKID(n); ok {
				t.Fatalf("key installed for %v", n)
			}
		}
	})

	t.Run("not a member", func(t *testing.T) {
		carolSide, _ := link(t, alice, carol, nil)
		err := k.Receive(ctx, carolSide, carol.pub, ns)
		if requestCode(err) != kolomoq.ReqDoesNotExist {
			t.Fatalf("non-member: %v", err)
		}
		k.mu.Lock()
		n := len(k.senders)
		k.mu.Unlock()
		if n != 0 {
			t.Fatalf("%d sender states left after a failed Receive", n)
		}
	})

	t.Run("arguments", func(t *testing.T) {
		bobSide, _ := link(t, alice, bob, nil)
		for name, err := range map[string]error{
			"nil session":   k.Receive(ctx, nil, bob.pub, ns),
			"short self":    k.Receive(ctx, bobSide, bob.pub[:31], ns),
			"empty ns":      k.Receive(ctx, bobSide, bob.pub, nil),
			"key namespace": k.Receive(ctx, bobSide, bob.pub, KeyNamespace(ns)),
			"32 fields":     k.Receive(ctx, bobSide, bob.pub, slices.Repeat(kolomoq.Namespace{"a"}, 32)),
			"canceled":      k.Receive(canceled(), bobSide, bob.pub, ns),
		} {
			if err == nil {
				t.Errorf("%s accepted", name)
			}
		}
	})
}

func canceled() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}

// relayLink connects sub to a kolo-moq relay run by relay's identity.
func relayLink(t testing.TB, r *kolomoq.Relay, relay, sub *node) *kolomoq.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", relay.id, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := make(chan *kolomoq.Session, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			srv <- nil
			return
		}
		s, _ := r.NewServer(ctx, c)
		srv <- s
	}()
	c, err := kolosecure.Dial(ctx, l.Addr().String(), sub.id, relay.pub, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := kolomoq.NewClient(ctx, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	rs := <-srv
	if rs == nil {
		t.Fatal("relay session failed")
	}
	t.Cleanup(func() {
		cs.Close()
		rs.Close()
	})
	return cs
}

// TestKeyTrackIsolation uses a session with no Authorize hook: only the member reaches its key track.
func TestKeyTrackIsolation(t *testing.T) {
	checkLeaks(t)
	alice, bob, carol := newNode(t), newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub, carol.pub}); err != nil {
		t.Fatal(err)
	}
	media, err := alice.origin.CreateTrack(ns, "audio", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer media.Close()
	carolSide, _ := link(t, alice, carol, nil)
	ctx := testCtx(t)
	bobTrack := KeyTrack(bob.pub)
	for name, call := range map[string]func() error{
		"subscribe": func() error { _, err := carolSide.Subscribe(ctx, KeyNamespace(ns), bobTrack, nil); return err },
		"subscribe current group": func() error {
			_, err := carolSide.Subscribe(ctx, KeyNamespace(ns), bobTrack, &kolomoq.SubscribeOptions{Join: kolomoq.JoinCurrentGroup})
			return err
		},
		"fetch":        func() error { _, err := carolSide.Fetch(ctx, KeyNamespace(ns), bobTrack, nil); return err },
		"track status": func() error { _, err := carolSide.TrackStatus(ctx, KeyNamespace(ns), bobTrack); return err },
	} {
		if err := call(); requestCode(err) != kolomoq.ReqDoesNotExist {
			t.Errorf("%s of another member's key track: %v", name, err)
		}
	}
	if _, err := carolSide.TrackStatus(ctx, KeyNamespace(ns), KeyTrack(carol.pub)); err != nil {
		t.Fatalf("own key track: %v", err)
	}

	all, err := carolSide.SubscribeNamespace(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer all.Close()
	ev, err := all.Next(ctx)
	if err != nil || !slices.Equal(ev.Namespace, ns) {
		t.Fatalf("first namespace %v %v", ev.Namespace, err)
	}
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	defer cancel()
	if ev, err := all.Next(short); err == nil {
		t.Fatalf("empty prefix listed %v", ev.Namespace)
	}
	keys, err := carolSide.SubscribeNamespace(ctx, kolomoq.Namespace{kolomoq.KeyNamespaceField})
	if err == nil {
		defer keys.Close()
		short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
		defer cancel()
		if ev, err := keys.Next(short); err == nil {
			t.Fatalf("key prefix listed %v", ev.Namespace)
		}
	}
}

func TestMayCarry(t *testing.T) {
	alice, bob, relay := newNode(t), newNode(t), newNode(t)
	ns := mediaNS(alice.pub)
	k := newKeyring(t, KeyringConfig{Relays: []ed25519.PublicKey{relay.pub}})
	fromAlice, _ := link(t, alice, bob, nil)
	fromRelay, _ := link(t, relay, bob, nil)
	other := newNode(t)
	fromOther, _ := link(t, other, bob, nil)
	if err := k.MayCarry(fromAlice, ns); err != nil {
		t.Fatalf("owner: %v", err)
	}
	if err := k.MayCarry(fromRelay, ns); err != nil {
		t.Fatalf("listed relay: %v", err)
	}
	if err := k.MayCarry(fromOther, ns); err != ErrWrongSession {
		t.Fatalf("another member: %v", err)
	}
	if err := k.MayCarry(fromAlice, mediaNS(other.pub)); err != ErrWrongSession {
		t.Fatalf("owner of another namespace: %v", err)
	}
	if err := k.MayCarry(nil, ns); err != ErrWrongSession {
		t.Fatalf("nil session: %v", err)
	}
}

// fakeClock is a settable clock for the rate cap and Retain.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *fakeClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) add(d time.Duration) {
	c.mu.Lock()
	c.t = c.t.Add(d)
	c.mu.Unlock()
}

// localKeyring is a Keyring with a fake clock and one namespace joined without a session.
func localKeyring(t testing.TB, cfg KeyringConfig, ns kolomoq.Namespace) (*Keyring, *senderKeys, *fakeClock) {
	t.Helper()
	k := newKeyring(t, cfg)
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	k.now = clock.now
	e, err := k.join(ns, &receiver{cancel: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	return k, e, clock
}

func msgBytes(instance byte, kid uint64, ns kolomoq.Namespace, key byte) []byte {
	m := keyMessage{kid: kid, ns: ns}
	m.instance[0] = instance
	m.base[0], m.base[15] = key, key
	return appendKeyMessage(nil, &m)
}

// keyState returns the current and previous Key IDs, -1 when absent.
func keyState(k *Keyring, e *senderKeys) (cur, prev int64) {
	k.mu.Lock()
	defer k.mu.Unlock()
	cur, prev = -1, -1
	if e.cur != nil {
		cur = int64(e.cur.kid)
	}
	if e.prev != nil {
		prev = int64(e.prev.kid)
	}
	return
}

func TestKeyMessageOrdering(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	steps := []struct {
		name      string
		msg       []byte
		cur, prev int64
		rejected  uint64
		changed   bool
	}{
		{"first", msgBytes(1, 3, ns, 3), 3, -1, 0, true},
		{"lower Key ID ignored", msgBytes(1, 2, ns, 2), 3, -1, 0, false},
		{"same key again", msgBytes(1, 3, ns, 3), 3, -1, 0, false},
		{"same Key ID, other key", msgBytes(1, 3, ns, 9), 3, -1, 1, false},
		{"higher Key ID", msgBytes(1, 5, ns, 5), 5, 3, 1, true},
		{"between, out of order", msgBytes(1, 4, ns, 4), 5, 3, 1, false},
		{"previous Key ID again", msgBytes(1, 3, ns, 3), 5, 3, 1, false},
		{"next", msgBytes(1, 6, ns, 6), 6, 5, 1, true},
		{"new instance, lower Key ID", msgBytes(2, 0, ns, 7), 0, -1, 1, true},
		{"old instance again", msgBytes(1, 6, ns, 6), 6, -1, 1, true},
	}
	for _, st := range steps {
		k.mu.Lock()
		var gens []*generation
		for _, g := range []*generation{e.cur, e.prev} {
			if g != nil {
				gens = append(gens, g)
			}
		}
		k.mu.Unlock()
		changed := k.Changed()
		k.deliver(e, st.msg)
		cur, prev := keyState(k, e)
		if cur != st.cur || prev != st.prev || k.Stats().Rejected != st.rejected {
			t.Fatalf("%s: cur %d prev %d stats %+v", st.name, cur, prev, k.Stats())
		}
		select {
		case <-changed:
			if !st.changed {
				t.Fatalf("%s: signalled a change", st.name)
			}
		default:
			if st.changed {
				t.Fatalf("%s: no change signalled", st.name)
			}
		}
		k.mu.Lock()
		for _, g := range gens {
			if g != e.cur && g != e.prev && g.base != ([keySize]byte{}) {
				t.Fatalf("%s: dropped key not erased", st.name)
			}
		}
		k.mu.Unlock()
	}
}

func TestKeyMessageRate(t *testing.T) {
	ns, other := testNS, kolomoq.Namespace{"room", "other"}
	k, e, clock := localKeyring(t, KeyringConfig{MaxKeyRate: 3}, ns)
	e2, err := k.join(other, &receiver{cancel: func() {}})
	if err != nil {
		t.Fatal(err)
	}
	for kid := range uint64(3) {
		k.deliver(e, msgBytes(1, kid, ns, 1))
	}
	if cur, _ := keyState(k, e); cur != 2 || k.Stats().Dropped != 0 {
		t.Fatalf("within the cap: cur %d stats %+v", cur, k.Stats())
	}
	k.deliver(e, msgBytes(1, 3, ns, 1))
	clock.add(999 * time.Millisecond)
	k.deliver(e, msgBytes(1, 4, ns, 1))
	if cur, _ := keyState(k, e); cur != 2 || k.Stats().Dropped != 2 {
		t.Fatalf("over the cap: cur %d stats %+v", cur, k.Stats())
	}
	k.deliver(e2, msgBytes(1, 0, other, 1))
	if cur, _ := keyState(k, e2); cur != 0 {
		t.Fatal("another namespace was rate limited")
	}
	clock.add(time.Millisecond)
	k.deliver(e, msgBytes(1, 5, ns, 1))
	if cur, _ := keyState(k, e); cur != 5 || k.Stats().Dropped != 2 {
		t.Fatalf("next second: cur %d stats %+v", cur, k.Stats())
	}
	k.deliver(e, []byte("junk"))
	k.deliver(e, []byte("junk"))
	k.deliver(e, msgBytes(1, 6, ns, 1))
	if cur, _ := keyState(k, e); cur != 5 || k.Stats().Dropped != 3 || k.Stats().Rejected != 2 {
		t.Fatalf("rejected messages count against the cap: cur %d stats %+v", cur, k.Stats())
	}
}

func TestDeliverClearsMessage(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{MaxKeyRate: 2}, ns)
	for name, b := range map[string][]byte{
		"installed": msgBytes(1, 0, ns, 1),
		"rejected":  append(msgBytes(1, 1, ns, 1), 0),
		"dropped":   msgBytes(1, 2, ns, 1),
	} {
		k.deliver(e, b)
		if !bytes.Equal(b, make([]byte, len(b))) {
			t.Fatalf("%s message not cleared", name)
		}
	}
	k.Remove(ns)
	b := msgBytes(1, 3, ns, 1)
	k.deliver(e, b)
	if !bytes.Equal(b, make([]byte, len(b))) {
		t.Fatal("message after Remove not cleared")
	}
}

func TestMaxSenders(t *testing.T) {
	k := newKeyring(t, KeyringConfig{MaxSenders: 2})
	r := &receiver{cancel: func() {}}
	a, b, c := kolomoq.Namespace{"a"}, kolomoq.Namespace{"b"}, kolomoq.Namespace{"c"}
	ea, err := k.join(a, r)
	if err != nil {
		t.Fatal(err)
	}
	eb, err := k.join(b, r)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := k.join(c, r); err != ErrTooManySenders {
		t.Fatalf("third sender: %v", err)
	}
	k.deliver(ea, msgBytes(1, 0, a, 1))
	k.leave(eb, r)
	k.leave(ea, r)
	if _, err := k.join(c, r); err != nil {
		t.Fatalf("after a keyless sender left: %v", err)
	}
	if _, err := k.join(b, r); err != ErrTooManySenders {
		t.Fatalf("a keyed sender was dropped on leave: %v", err)
	}
	k.Remove(a)
	if _, err := k.join(b, r); err != nil {
		t.Fatalf("after Remove: %v", err)
	}
}

// openObject seals one object of testNS under base and kid.
func openObject(t testing.TB, base *[keySize]byte, kid uint64, track string, group, object uint64, payload string) kolomoq.Object {
	t.Helper()
	tk := newTestKey(t, base, kid, testNS, track)
	return sealObject(t, tk, group, object, 48, []byte(payload), nil)
}

func baseOf(key byte) *[keySize]byte {
	var b [keySize]byte
	b[0], b[15] = key, key
	return &b
}

func TestRetain(t *testing.T) {
	ns := testNS
	k, e, clock := localKeyring(t, KeyringConfig{Retain: time.Minute, RetainMax: 2 * time.Minute}, ns)
	k.deliver(e, msgBytes(1, 1, ns, 1))
	mustOpen(t, k, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 0, "x"), "x")
	k.deliver(e, msgBytes(1, 2, ns, 2))
	clock.add(30 * time.Second)
	mustOpen(t, k, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 1, "old"), "old")
	mustOpen(t, k, ns, "a", openObject(t, baseOf(2), 2, "a", 0, 0, "new"), "new")
	k.mu.Lock()
	prev := e.prev
	k.mu.Unlock()
	clock.add(time.Minute - 1)
	mustOpen(t, k, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 2, "late"), "late")
	mustOpen(t, k, ns, "a", openObject(t, baseOf(2), 2, "a", 0, 1, "new again"), "new again")
	clock.add(1)
	if _, _, err := openAt(k, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 3, "expired")); err != ErrKeyRetired {
		t.Fatalf("after Retain: %v", err)
	}
	if prev.base != ([keySize]byte{}) || len(prev.keys) != 0 {
		t.Fatal("expired key not erased")
	}
	if _, prev := keyState(k, e); prev != -1 {
		t.Fatal("expired key kept")
	}

	k2, e2, _ := localKeyring(t, KeyringConfig{Retain: 20 * time.Millisecond, RetainMax: time.Minute}, ns)
	k2.deliver(e2, msgBytes(1, 1, ns, 1))
	mustOpen(t, k2, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 0, "x"), "x")
	k2.deliver(e2, msgBytes(1, 2, ns, 2))
	k2.mu.Lock()
	prev = e2.prev
	tk := prev.keys["a"]
	k2.mu.Unlock()
	mustOpen(t, k2, ns, "a", openObject(t, baseOf(2), 2, "a", 0, 0, "y"), "y")
	eventually(t, "timer expiry", func() bool {
		_, p := keyState(k2, e2)
		return p == -1
	})
	if prev.base != ([keySize]byte{}) || tk.aead != nil || tk.salt != ([saltSize]byte{}) {
		t.Fatal("key erased by the timer still holds material")
	}
}

// TestRetainMax checks that a replaced key expires RetainMax after its successor arrived even if
// no object under the successor opens, as when a relay withholds the sender's new objects and a
// removed member forges objects under the old key.
func TestRetainMax(t *testing.T) {
	ns := testNS
	k, e, clock := localKeyring(t, KeyringConfig{Retain: 10 * time.Millisecond, RetainMax: time.Minute}, ns)
	k.deliver(e, msgBytes(1, 1, ns, 1))
	k.deliver(e, msgBytes(1, 2, ns, 2))
	clock.add(time.Minute - 1)
	mustOpen(t, k, ns, "a", openObject(t, baseOf(1), 1, "a", 100, 0, "in time"), "in time")
	clock.add(1)
	if _, _, err := openAt(k, ns, "a", openObject(t, baseOf(1), 1, "a", 101, 0, "forged")); err != ErrKeyRetired {
		t.Fatalf("old key after RetainMax: %v", err)
	}

	k2, e2, _ := localKeyring(t, KeyringConfig{Retain: 10 * time.Millisecond, RetainMax: 30 * time.Millisecond}, ns)
	k2.deliver(e2, msgBytes(1, 1, ns, 1))
	k2.deliver(e2, msgBytes(1, 2, ns, 2))
	k2.mu.Lock()
	prev := e2.prev
	k2.mu.Unlock()
	eventually(t, "RetainMax timer", func() bool {
		_, p := keyState(k2, e2)
		return p == -1
	})
	if prev.base != ([keySize]byte{}) {
		t.Fatal("key erased by the RetainMax timer still holds material")
	}
}

func TestOpenErrors(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	obj := openObject(t, baseOf(1), 1, "a", 0, 0, "x")
	if _, _, err := openAt(k, ns, "a", obj); err != ErrNoKey {
		t.Fatalf("no key yet: %v", err)
	}
	if _, _, err := openAt(k, kolomoq.Namespace{"other"}, "a", obj); err != ErrNoKey {
		t.Fatalf("unknown namespace: %v", err)
	}
	k.deliver(e, msgBytes(1, 1, ns, 1))
	mustOpen(t, k, ns, "a", obj, "x")
	cases := []struct {
		name  string
		track string
		obj   kolomoq.Object
		want  error
	}{
		{"replay", "a", obj, ErrReplay},
		{"newer Key ID", "a", openObject(t, baseOf(1), 2, "a", 0, 1, "x"), ErrNoKey},
		{"older Key ID", "a", openObject(t, baseOf(1), 0, "a", 0, 1, "x"), ErrKeyRetired},
		{"other track", "b", openObject(t, baseOf(1), 1, "a", 0, 1, "x"), ErrAuthentication},
		{"wrong key", "a", openObject(t, baseOf(9), 1, "a", 0, 1, "x"), ErrAuthentication},
		{"not protected", "a", kolomoq.Object{Payload: []byte("plain")}, ErrNotProtected},
		{"end of group", "a", kolomoq.Object{Status: kolomoq.StatusEndOfGroup, Properties: obj.Properties}, ErrNotProtected},
		{"bad track name", string(make([]byte, 5000)), openObject(t, baseOf(1), 1, "a", 0, 1, "x"), kolomoq.ErrInvalidName},
		{"Key ID at 0x02", "a", kolomoq.Object{Properties: []kolomoq.Property{{Type: propImmutable, Bytes: []byte{0x02, 1}}}, Payload: obj.Payload}, ErrMalformed},
		{"object 2^32", "a", kolomoq.Object{ID: 1 << 32, Properties: obj.Properties, Payload: obj.Payload}, ErrObjectID},
	}
	for _, c := range cases {
		_, _, err := openAt(k, ns, c.track, c.obj)
		if err != c.want {
			t.Errorf("%s: got %v, want %v", c.name, err, c.want)
		}
		noSecret(t, [][]byte{baseOf(1)[:]}, err)
	}
	mustOpen(t, k, ns, "a", openObject(t, baseOf(1), 1, "a", 200, 0, "far"), "far")
	if _, _, err := openAt(k, ns, "a", openObject(t, baseOf(1), 1, "a", 100, 0, "old")); err != ErrReplay {
		t.Fatalf("group outside the window: %v", err)
	}
}

func TestRemoveErases(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	var canceled bool
	k.mu.Lock()
	e.receivers[&receiver{cancel: func() { canceled = true }}] = struct{}{}
	k.mu.Unlock()
	k.deliver(e, msgBytes(1, 1, ns, 1))
	mustOpen(t, k, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 0, "x"), "x")
	k.deliver(e, msgBytes(1, 2, ns, 2))
	mustOpen(t, k, ns, "a", openObject(t, baseOf(2), 2, "a", 0, 0, "y"), "y")
	k.mu.Lock()
	cur, prev := e.cur, e.prev
	keys := []*trackKey{cur.keys["a"], prev.keys["a"]}
	k.mu.Unlock()
	k.Remove(ns)
	k.Remove(ns)
	for _, g := range []*generation{cur, prev} {
		if g.base != ([keySize]byte{}) || len(g.keys) != 0 {
			t.Fatal("Remove left a base key")
		}
	}
	for _, tk := range keys {
		if tk.aead != nil || tk.salt != ([saltSize]byte{}) {
			t.Fatal("Remove left a track key")
		}
	}
	if !canceled {
		t.Fatal("Remove did not end Receive")
	}
	if _, _, err := openAt(k, ns, "a", openObject(t, baseOf(2), 2, "a", 0, 1, "z")); err != ErrNoKey {
		t.Fatalf("after Remove: %v", err)
	}
}

func TestRemoveEndsReceive(t *testing.T) {
	checkLeaks(t)
	alice, bob := newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bobSide, _ := link(t, alice, bob, nil)
	k := newKeyring(t, KeyringConfig{})
	done := receive(t, k, bobSide, bob.pub, ns)
	waitKID(t, k, ns, 1)
	k.Remove(ns)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("Receive after Remove: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Receive did not end")
	}
	if _, ok := k.currentKID(ns); ok {
		t.Fatal("key left after Remove")
	}
}

func TestTrackKeyCache(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	k.deliver(e, msgBytes(1, 1, ns, 1))
	name := func(i int) string {
		return "t" + string(rune('a'+i%26)) + hex.EncodeToString([]byte{byte(i >> 8), byte(i)})
	}
	mustOpen(t, k, ns, name(0), openObject(t, baseOf(1), 1, name(0), 0, 0, "x"), "x")
	k.mu.Lock()
	first := e.cur.keys[name(0)]
	k.mu.Unlock()
	mustOpen(t, k, ns, name(1), openObject(t, baseOf(1), 1, name(1), 0, 0, "x"), "x")
	for i := 2; i <= maxTrackKeys; i++ {
		mustOpen(t, k, ns, name(i), openObject(t, baseOf(1), 1, name(i), 0, 0, "x"), "x")
		if i == 2 {
			mustOpen(t, k, ns, name(1), openObject(t, baseOf(1), 1, name(1), 0, 1, "x"), "x")
		}
	}
	k.mu.Lock()
	n, nk := len(e.tracks), len(e.cur.keys)
	_, kept := e.tracks[name(1)]
	_, dropped := e.tracks[name(0)]
	k.mu.Unlock()
	if n != maxTrackKeys || nk != maxTrackKeys || !kept || dropped {
		t.Fatalf("tracks %d keys %d, recently used kept %v, oldest kept %v", n, nk, kept, dropped)
	}
	if first.aead != nil {
		t.Fatal("dropped track key not erased")
	}
}

func TestKeyringConfig(t *testing.T) {
	auth := func(ed25519.PublicKey, kolomoq.Namespace) error { return nil }
	k := newKeyring(t, KeyringConfig{Authorize: auth})
	if k.retainMax != defaultRetain+400*time.Millisecond {
		t.Fatalf("default RetainMax %v", k.retainMax)
	}
	if k := newKeyring(t, KeyringConfig{Authorize: auth, Retain: time.Minute}); k.retainMax != time.Minute+400*time.Millisecond {
		t.Fatalf("RetainMax %v with Retain 1m", k.retainMax)
	}
	if k.retain != defaultRetain || k.maxSenders != 64 || k.maxKeyRate != 64 || k.replayGroups != 64 || k.replayObjects != 8192 {
		t.Fatalf("defaults %v %d %d %d %d", k.retain, k.maxSenders, k.maxKeyRate, k.replayGroups, k.replayObjects)
	}
	for name, cfg := range map[string]KeyringConfig{
		"nil Authorize":          {},
		"short relay":            {Authorize: auth, Relays: []ed25519.PublicKey{make([]byte, 31)}},
		"negative Retain":        {Authorize: auth, Retain: -1},
		"Retain over 1m":         {Authorize: auth, Retain: time.Minute + 1},
		"RetainMax below Retain": {Authorize: auth, Retain: time.Second, RetainMax: time.Second - 1},
		"RetainMax over 2m":      {Authorize: auth, RetainMax: 2*time.Minute + 1},
		"MaxSenders 1025":        {Authorize: auth, MaxSenders: 1025},
		"MaxSenders -1":          {Authorize: auth, MaxSenders: -1},
		"MaxKeyRate 1025":        {Authorize: auth, MaxKeyRate: 1025},
		"ReplayGroups -1":        {Authorize: auth, ReplayGroups: -1},
		"ReplayObjects big":      {Authorize: auth, ReplayObjects: 1_000_001},
	} {
		if _, err := NewKeyring(cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for name, cfg := range map[string]KeyringConfig{
		"bounds low":  {Authorize: auth, Retain: 1, RetainMax: 1, MaxSenders: 1, MaxKeyRate: 1, ReplayGroups: 1, ReplayObjects: 1},
		"bounds high": {Authorize: auth, Retain: time.Minute, RetainMax: 2 * time.Minute, MaxSenders: 1024, MaxKeyRate: 1024, ReplayGroups: 1_000_000, ReplayObjects: 1_000_000},
	} {
		if _, err := NewKeyring(cfg); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
	relay := make(ed25519.PublicKey, 32)
	cfg := KeyringConfig{Authorize: auth, Relays: []ed25519.PublicKey{relay}}
	k = newKeyring(t, cfg)
	relay[0] = 1
	if k.relays[0][0] != 0 {
		t.Fatal("Relays not copied")
	}
}

func TestKeyringRedaction(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{}, ns)
	k.deliver(e, msgBytes(1, 1, ns, 1))
	mustOpen(t, k, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 0, "x"), "x")
	k.mu.Lock()
	secret := slices.Clone(e.cur.base[:])
	tk := e.cur.keys["a"]
	salt := slices.Clone(tk.salt[:])
	k.mu.Unlock()
	_, _, err := openAt(k, ns, "a", openObject(t, baseOf(1), 1, "a", 0, 0, "x"))
	noSecret(t, [][]byte{secret, salt}, k, tk, struct{ K *Keyring }{k}, err, k.Stats(), reflect.ValueOf(k).Elem().Interface())
}

func TestConcurrentKeyring(t *testing.T) {
	ns := testNS
	k, e, _ := localKeyring(t, KeyringConfig{Retain: time.Minute}, ns)
	k.deliver(e, msgBytes(1, 0, ns, 1))
	var objs [4][200]kolomoq.Object
	for w := range objs {
		for i := range objs[w] {
			objs[w][i] = openObject(t, baseOf(1), 0, "a", uint64(w), uint64(i), "x")
		}
	}
	var wg sync.WaitGroup
	for w := range objs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, obj := range objs[w] {
				openAt(k, ns, "a", obj)
				k.Changed()
				k.Stats()
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for kid := range uint64(100) {
			k.deliver(e, msgBytes(1, kid, ns, byte(kid)))
		}
		k.Remove(ns)
	}()
	wg.Wait()
}
