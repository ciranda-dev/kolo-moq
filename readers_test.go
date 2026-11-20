package kolomoq

import (
	"context"
	"crypto/ed25519"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

var keyNS = Namespace{KeyNamespaceField, "room", "alice"}

// keyTrackPair returns two clients of one origin with no Authorize hook, and a key
// track only the first client may read.
func keyTrackPair(t *testing.T) (reader, other *pair, tw *TrackWriter, origin *Origin) {
	t.Helper()
	origin = newOrigin(t)
	reader = newPair(t, nil, &Config{Origin: origin})
	other = newPair(t, nil, &Config{Origin: origin})
	tw = mustTrack(t, origin, keyNS, "bob", &TrackOptions{Readers: []ed25519.PublicKey{reader.server.RemotePublicKey()}})
	writeGroups(t, tw, 2, 2)
	return
}

func TestReadersNilAuthorize(t *testing.T) {
	checkLeaks(t)
	reader, other, _, _ := keyTrackPair(t)
	ctx := testCtx(t)

	sub, err := reader.client.Subscribe(ctx, keyNS, "bob", &SubscribeOptions{Join: JoinCurrentGroup})
	if err != nil {
		t.Fatalf("reader subscribe: %v", err)
	}
	if got := readN(t, ctx, sub, 2); string(got[0].Payload) != "g1-o0" {
		t.Fatalf("reader got %q", got[0].Payload)
	}
	f, err := reader.client.Fetch(ctx, keyNS, "bob", nil)
	if err != nil {
		t.Fatalf("reader fetch: %v", err)
	}
	if o, err := f.ReadObject(ctx); err != nil || string(o.Payload) != "g1-o0" {
		t.Fatalf("reader fetch object %q %v", o.Payload, err)
	}
	if st, err := reader.client.TrackStatus(ctx, keyNS, "bob"); err != nil || !st.HasLargest {
		t.Fatalf("reader track status %+v %v", st, err)
	}

	for name, call := range map[string]func() error{
		"subscribe": func() error { _, err := other.client.Subscribe(ctx, keyNS, "bob", nil); return err },
		"subscribe current group": func() error {
			_, err := other.client.Subscribe(ctx, keyNS, "bob", &SubscribeOptions{Join: JoinCurrentGroup})
			return err
		},
		"fetch":        func() error { _, err := other.client.Fetch(ctx, keyNS, "bob", nil); return err },
		"track status": func() error { _, err := other.client.TrackStatus(ctx, keyNS, "bob"); return err },
		"missing track": func() error {
			_, err := other.client.TrackStatus(ctx, keyNS, "nobody")
			return err
		},
	} {
		if err := call(); requestCode(err) != ReqDoesNotExist {
			t.Errorf("%s by another peer: %v", name, err)
		}
	}
}

func TestReadersWithAuthorize(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	allow := func(ed25519.PublicKey, RequestKind, Namespace, string) error { return nil }
	deny := func(ed25519.PublicKey, RequestKind, Namespace, string) error { return errors.New("no") }
	allowed := newPair(t, nil, &Config{Origin: origin, Authorize: allow})
	denied := newPair(t, nil, &Config{Origin: origin, Authorize: deny})
	mustTrack(t, origin, keyNS, "bob", &TrackOptions{Readers: []ed25519.PublicKey{allowed.server.RemotePublicKey(), denied.server.RemotePublicKey()}})
	stranger := newPair(t, nil, &Config{Origin: origin, Authorize: allow})
	ctx := testCtx(t)
	if _, err := allowed.client.TrackStatus(ctx, keyNS, "bob"); err != nil {
		t.Fatalf("reader allowed by Authorize: %v", err)
	}
	if _, err := denied.client.TrackStatus(ctx, keyNS, "bob"); requestCode(err) != ReqUnauthorized {
		t.Fatalf("reader refused by Authorize: %v", err)
	}
	if _, err := stranger.client.TrackStatus(ctx, keyNS, "bob"); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("non-reader allowed by Authorize: %v", err)
	}
}

func TestReadersOptions(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	good := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for _, bad := range [][]ed25519.PublicKey{{nil}, {good[:31]}, {append(slices.Clone(good), 0)}, {good, {}}} {
		if _, err := origin.CreateTrack(Namespace{"n"}, "t", &TrackOptions{Readers: bad}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("readers %v: %v", bad, err)
		}
	}

	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	mustTrack(t, origin, Namespace{"none"}, "t", &TrackOptions{Readers: []ed25519.PublicKey{}})
	if _, err := p.client.TrackStatus(ctx, Namespace{"none"}, "t"); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("empty readers: %v", err)
	}
	mustTrack(t, origin, Namespace{"open"}, "t", &TrackOptions{})
	if _, err := p.client.TrackStatus(ctx, Namespace{"open"}, "t"); err != nil {
		t.Fatalf("nil readers: %v", err)
	}

	// Changing the caller's slice after CreateTrack changes nothing.
	readers := []ed25519.PublicKey{slices.Clone(p.server.RemotePublicKey())}
	mustTrack(t, origin, Namespace{"copy"}, "t", &TrackOptions{Readers: readers})
	clear(readers[0])
	if _, err := p.client.TrackStatus(ctx, Namespace{"copy"}, "t"); err != nil {
		t.Fatalf("readers copy: %v", err)
	}
}

// TestReadersThroughRelay checks that a relay, which subscribes to the
// publisher as its own peer, cannot read a track whose readers are others and
// so never forwards it.
func TestReadersThroughRelay(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	origin := newOrigin(t)
	ns := Namespace{"conf"}
	pub, _ := joinRelay(t, r, &Config{Origin: origin})
	member, _ := joinRelay(t, r, nil)
	otherKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	hidden := mustTrack(t, origin, ns, "hidden", &TrackOptions{Readers: []ed25519.PublicKey{otherKey}})
	shown := mustTrack(t, origin, ns, "shown", &TrackOptions{Readers: []ed25519.PublicKey{pub.RemotePublicKey()}})
	writeGroups(t, hidden, 1, 2)
	writeGroups(t, shown, 1, 2)
	ctx := testCtx(t)
	if _, err := pub.PublishNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	if _, err := member.Subscribe(ctx, ns, "hidden", nil); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("subscribe through relay: %v", err)
	}
	if _, err := member.Fetch(ctx, ns, "hidden", nil); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("fetch through relay: %v", err)
	}
	if _, err := member.TrackStatus(ctx, ns, "hidden"); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("track status through relay: %v", err)
	}
	// A track whose readers include the relay is served by it to everyone.
	sub, err := member.Subscribe(ctx, ns, "shown", &SubscribeOptions{Join: JoinCurrentGroup})
	if err != nil {
		t.Fatalf("relay as reader: %v", err)
	}
	readN(t, ctx, sub, 2)
}

func TestKeyNamespaceRefusedLocally(t *testing.T) {
	checkLeaks(t)
	p := newPair(t, nil, &Config{Origin: newOrigin(t)})
	ctx := testCtx(t)
	for _, ns := range []Namespace{{KeyNamespaceField}, keyNS} {
		if _, err := p.client.PublishNamespace(ctx, ns); !errors.Is(err, ErrInvalidName) {
			t.Errorf("PublishNamespace(%v): %v", ns, err)
		}
	}
	for _, ns := range []Namespace{{"room", KeyNamespaceField}, {"kolo-keys2"}} {
		pn, err := p.client.PublishNamespace(ctx, ns)
		if err != nil {
			t.Fatalf("PublishNamespace(%v): %v", ns, err)
		}
		pn.Close()
	}
}

// TestKeyNamespaceRefusedByPeers sends PUBLISH_NAMESPACE by hand, which the API
// refuses to send, to an origin session and to a relay session.
func TestKeyNamespaceRefusedByPeers(t *testing.T) {
	checkLeaks(t)
	for name, connect := range map[string]func() (*rawPeer, *Session){
		"origin": func() (*rawPeer, *Session) { return connected(t, &Config{Origin: newOrigin(t)}) },
		"relay":  func() (*rawPeer, *Session) { return rawRelayPeer(t, newRelay(t, nil)) },
	} {
		rp, s := connect()
		_, br := rp.request(&wire.Request{Type: wire.MsgPublishNamespace, RequestID: rp.id(), Namespace: keyNS, Params: &wire.MessageParams{}})
		rp.expectError(br, ReqUnauthorized)
		if n := len(s.PeerNamespaces()); n != 0 {
			t.Errorf("%s kept %d namespaces", name, n)
		}
	}
}

func TestRelayRefusesKeyNamespace(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	pub, _ := joinRelay(t, r, &Config{Origin: newOrigin(t)})
	member, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	for _, c := range []*Session{pub, member} {
		for _, ns := range []Namespace{{KeyNamespaceField}, keyNS} {
			if _, err := c.Subscribe(ctx, ns, "bob", nil); requestCode(err) != ReqUnauthorized {
				t.Errorf("subscribe %v: %v", ns, err)
			}
			if _, err := c.Fetch(ctx, ns, "bob", nil); requestCode(err) != ReqUnauthorized {
				t.Errorf("fetch %v: %v", ns, err)
			}
			if _, err := c.TrackStatus(ctx, ns, "bob"); requestCode(err) != ReqUnauthorized {
				t.Errorf("track status %v: %v", ns, err)
			}
			if _, err := c.SubscribeNamespace(ctx, ns); requestCode(err) != ReqUnauthorized {
				t.Errorf("subscribe namespace %v: %v", ns, err)
			}
		}
	}
	// Other namespaces still work.
	if _, err := pub.PublishNamespace(ctx, Namespace{"conf"}); err != nil {
		t.Fatal(err)
	}
	ns, err := member.SubscribeNamespace(ctx, Namespace{})
	if err != nil {
		t.Fatalf("empty prefix: %v", err)
	}
	if ev, err := ns.Next(ctx); err != nil || !slices.Equal(ev.Namespace, Namespace{"conf"}) {
		t.Fatalf("event %+v %v", ev, err)
	}
}

func TestNamespaceAnswersHideKeyNamespaces(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	mustTrack(t, origin, keyNS, "bob", nil)
	mustTrack(t, origin, Namespace{"pub", "a"}, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)

	all, err := p.client.SubscribeNamespace(ctx, Namespace{})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := all.Next(ctx)
	if err != nil || !slices.Equal(ev.Namespace, Namespace{"pub", "a"}) {
		t.Fatalf("initial event %+v %v", ev, err)
	}
	mustTrack(t, origin, Namespace{KeyNamespaceField, "room", "carol"}, "bob", nil)
	mustTrack(t, origin, Namespace{"pub", "b"}, "t", nil)
	if ev, err = all.Next(ctx); err != nil || !ev.Active || !slices.Equal(ev.Namespace, Namespace{"pub", "b"}) {
		t.Fatalf("live event %+v %v", ev, err)
	}
	all.Close()

	for _, prefix := range []Namespace{{KeyNamespaceField}, {KeyNamespaceField, "room"}} {
		q := newPair(t, nil, &Config{Origin: origin})
		ns, err := q.client.SubscribeNamespace(ctx, prefix)
		if err != nil {
			t.Fatalf("prefix %v: %v", prefix, err)
		}
		short, cancel := context.WithTimeout(ctx, 300*time.Millisecond)
		ev, err := ns.Next(short)
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("prefix %v listed %+v (%v)", prefix, ev, err)
		}
	}
}

// TestRemotePublicKeyIsACopy checks that writing to the returned key changes neither the session's
// peer identity nor what Readers checks.
func TestRemotePublicKeyIsACopy(t *testing.T) {
	checkLeaks(t)
	reader, _, _, _ := keyTrackPair(t)
	key := reader.server.RemotePublicKey()
	want := slices.Clone(key)
	clear(key)
	if !slices.Equal(reader.server.RemotePublicKey(), want) {
		t.Fatal("writing to the returned key changed the session's peer")
	}
	ctx := testCtx(t)
	sub, err := reader.client.Subscribe(ctx, keyNS, "bob", &SubscribeOptions{Join: JoinCurrentGroup})
	if err != nil {
		t.Fatalf("reader subscribe: %v", err)
	}
	defer sub.Close()
	readN(t, ctx, sub, 1)
}
