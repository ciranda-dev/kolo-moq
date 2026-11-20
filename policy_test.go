package kolomoq

import (
	"crypto/ed25519"
	"encoding/hex"
	"slices"
	"strings"
	"sync"
	"testing"
)

func testKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestRoomPolicy(t *testing.T) {
	room := Namespace{"conf", "r1"}
	alice, bob, carol := testKey(t), testKey(t), testKey(t)
	members := func(peer ed25519.PublicKey) bool { return peer.Equal(alice) || peer.Equal(bob) }
	p := RoomPolicy{Room: room, Member: members}
	own := func(k ed25519.PublicKey, rest ...string) Namespace {
		return append(append(Namespace{}, room...), append([]string{hex.EncodeToString(k)}, rest...)...)
	}
	reads := []RequestKind{KindSubscribe, KindFetch, KindTrackStatus, KindSubscribeNamespace}
	cases := []struct {
		name string
		p    RoomPolicy
		peer ed25519.PublicKey
		kind RequestKind
		ns   Namespace
		ok   bool
	}{
		{"publish own", p, alice, KindPublishNamespace, own(alice), true},
		{"publish own, not a member", p, carol, KindPublishNamespace, own(carol), true},
		{"publish another member's", p, alice, KindPublishNamespace, own(bob), false},
		{"publish a non-member's", p, alice, KindPublishNamespace, own(carol), false},
		{"publish the room", p, alice, KindPublishNamespace, room, false},
		{"publish under own namespace", p, alice, KindPublishNamespace, own(alice, "x"), false},
		{"publish upper-case hex", p, alice, KindPublishNamespace, append(slices.Clone(room), strings.ToUpper(hex.EncodeToString(alice))), false},
		{"publish outside the room", p, alice, KindPublishNamespace, Namespace{"other", hex.EncodeToString(alice)}, false},
		{"publish the key namespace", p, alice, KindPublishNamespace, Namespace{KeyNamespaceField, "conf", "r1", hex.EncodeToString(alice)}, false},
		{"publish the empty namespace", p, alice, KindPublishNamespace, Namespace{}, false},
		{"publish in a room that is a prefix", RoomPolicy{Room: room[:1], Member: members}, alice, KindPublishNamespace, own(alice), false},
		{"publish in the empty room", RoomPolicy{Member: members}, alice, KindPublishNamespace, Namespace{hex.EncodeToString(alice)}, true},
		{"publish short key", p, alice[:31], KindPublishNamespace, append(slices.Clone(room), hex.EncodeToString(alice[:31])), false},
		{"unknown kind", p, alice, 0, own(alice), false},
	}
	for _, k := range reads {
		cases = append(cases, []struct {
			name string
			p    RoomPolicy
			peer ed25519.PublicKey
			kind RequestKind
			ns   Namespace
			ok   bool
		}{
			{k.String() + " by a member", p, alice, k, own(bob), true},
			{k.String() + " of the room", p, bob, k, room, true},
			{k.String() + " by a non-member", p, carol, k, own(bob), false},
			{k.String() + " outside the room", p, alice, k, Namespace{"other"}, false},
			{k.String() + " of a prefix of the room", p, alice, k, room[:1], false},
			{k.String() + " of the empty prefix", p, alice, k, Namespace{}, false},
			{k.String() + " in the key namespace", p, alice, k, Namespace{KeyNamespaceField, "conf", "r1", hex.EncodeToString(bob)}, false},
			{k.String() + " with a nil Member", RoomPolicy{Room: room}, alice, k, own(bob), false},
			{k.String() + " in the empty room", RoomPolicy{Member: members}, alice, k, Namespace{"x"}, true},
			{k.String() + " with a short key", RoomPolicy{Room: room, Member: func(ed25519.PublicKey) bool { return true }}, alice[:31], k, own(bob), false},
		}...)
	}
	for _, c := range cases {
		if err := c.p.Authorize(c.peer, c.kind, c.ns, "t"); (err == nil) != c.ok {
			t.Errorf("%s: %v", c.name, err)
		} else if err != nil && !strings.HasPrefix(err.Error(), "kolomoq:") {
			t.Errorf("%s: error %q", c.name, err)
		}
	}
}

// memberSet is a Member function the test grows as clients connect.
type memberSet struct {
	mu   sync.Mutex
	keys []ed25519.PublicKey
}

func (m *memberSet) add(k ed25519.PublicKey) {
	m.mu.Lock()
	m.keys = append(m.keys, slices.Clone(k))
	m.mu.Unlock()
}

func (m *memberSet) has(k ed25519.PublicKey) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return slices.ContainsFunc(m.keys, func(x ed25519.PublicKey) bool { return x.Equal(k) })
}

func TestRelayRoomPolicy(t *testing.T) {
	checkLeaks(t)
	room := Namespace{"conf", "r1"}
	var members memberSet
	r := newRelay(t, &RelayConfig{Session: Config{Authorize: RoomPolicy{Room: room, Member: members.has}.Authorize}})
	origin := newOrigin(t)
	alice, aliceOnRelay := joinRelay(t, r, &Config{Origin: origin})
	bob, bobOnRelay := joinRelay(t, r, nil)
	outsider, _ := joinRelay(t, r, nil)
	members.add(aliceOnRelay.RemotePublicKey())
	members.add(bobOnRelay.RemotePublicKey())
	aliceNS := append(slices.Clone(room), hex.EncodeToString(aliceOnRelay.RemotePublicKey()))
	bobNS := append(slices.Clone(room), hex.EncodeToString(bobOnRelay.RemotePublicKey()))
	tw := mustTrack(t, origin, aliceNS, "audio", nil)
	writeGroups(t, tw, 2, 2)
	ctx := testCtx(t)

	if _, err := alice.PublishNamespace(ctx, bobNS); requestCode(err) != ReqUnauthorized {
		t.Fatalf("announce another member's namespace: %v", err)
	}
	if _, err := alice.PublishNamespace(ctx, room); requestCode(err) != ReqUnauthorized {
		t.Fatalf("announce the room: %v", err)
	}
	if _, err := alice.PublishNamespace(ctx, Namespace{"elsewhere"}); requestCode(err) != ReqUnauthorized {
		t.Fatalf("announce outside the room: %v", err)
	}
	if _, err := alice.PublishNamespace(ctx, aliceNS); err != nil {
		t.Fatalf("announce own namespace: %v", err)
	}
	if _, err := outsider.PublishNamespace(ctx, append(slices.Clone(room), hex.EncodeToString(bobOnRelay.RemotePublicKey()))); requestCode(err) != ReqUnauthorized {
		t.Fatalf("a non-member announces a member's namespace: %v", err)
	}

	sub, err := bob.Subscribe(ctx, aliceNS, "audio", &SubscribeOptions{Join: JoinCurrentGroup})
	if err != nil {
		t.Fatalf("member subscribe: %v", err)
	}
	readN(t, ctx, sub, 2)
	if _, err := bob.Fetch(ctx, aliceNS, "audio", nil); err != nil {
		t.Fatalf("member fetch: %v", err)
	}
	if _, err := bob.TrackStatus(ctx, aliceNS, "audio"); err != nil {
		t.Fatalf("member track status: %v", err)
	}
	if _, err := bob.SubscribeNamespace(ctx, room); err != nil {
		t.Fatalf("member subscribe namespace: %v", err)
	}

	if _, err := outsider.Subscribe(ctx, aliceNS, "audio", nil); requestCode(err) != ReqUnauthorized {
		t.Fatalf("non-member subscribe: %v", err)
	}
	if _, err := outsider.Fetch(ctx, aliceNS, "audio", nil); requestCode(err) != ReqUnauthorized {
		t.Fatalf("non-member fetch: %v", err)
	}
	if _, err := outsider.TrackStatus(ctx, aliceNS, "audio"); requestCode(err) != ReqUnauthorized {
		t.Fatalf("non-member track status: %v", err)
	}
	if _, err := outsider.SubscribeNamespace(ctx, room); requestCode(err) != ReqUnauthorized {
		t.Fatalf("non-member subscribe namespace: %v", err)
	}
	for name, err := range map[string]error{
		"subscribe":           func() error { _, err := bob.Subscribe(ctx, Namespace{"elsewhere"}, "t", nil); return err }(),
		"fetch":               func() error { _, err := bob.Fetch(ctx, Namespace{"elsewhere"}, "t", nil); return err }(),
		"track status":        func() error { _, err := bob.TrackStatus(ctx, Namespace{"elsewhere"}, "t"); return err }(),
		"subscribe namespace": func() error { _, err := bob.SubscribeNamespace(ctx, Namespace{}); return err }(),
	} {
		if requestCode(err) != ReqUnauthorized {
			t.Errorf("member %s outside the room: %v", name, err)
		}
	}
}
