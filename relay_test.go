package kolomoq

import (
	"context"
	"crypto/ed25519"
	"errors"
	"io"
	"slices"
	"sync"
	"testing"
	"time"
)

// joinRelay connects a client session with cfg to the relay.
func joinRelay(t *testing.T, r *Relay, cfg *Config) (peer, relaySide *Session) {
	t.Helper()
	cc, sc, _ := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	res := make(chan sessionResult, 1)
	go func() {
		s, err := r.NewServer(ctx, sc)
		res <- sessionResult{s, err}
	}()
	peer, err := NewClient(ctx, cc, cfg)
	if err != nil {
		t.Fatal(err)
	}
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	t.Cleanup(func() {
		peer.Close()
		sr.s.Close()
	})
	return peer, sr.s
}

func newRelay(t *testing.T, cfg *RelayConfig) *Relay {
	t.Helper()
	r, err := NewRelay(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// relayedPublisher connects a publisher with one track under ns to r.
func relayedPublisher(t *testing.T, r *Relay, ns Namespace, name string) (*TrackWriter, *Session, *PublishedNamespace) {
	t.Helper()
	origin := newOrigin(t)
	tw, err := origin.CreateTrack(ns, name, &TrackOptions{Priority: 9, Properties: []Property{{Type: 0x3803, Bytes: []byte("kept")}}})
	if err != nil {
		t.Fatal(err)
	}
	pub, _ := joinRelay(t, r, &Config{Origin: origin})
	pn, err := pub.PublishNamespace(testCtx(t), ns)
	if err != nil {
		t.Fatal(err)
	}
	return tw, pub, pn
}

func TestRelayFanOut(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"conf", "42"}
	tw, _, _ := relayedPublisher(t, r, ns, "video")
	ctx := testCtx(t)
	const n = 4
	var subs []*Subscription
	for range n {
		peer, _ := joinRelay(t, r, nil)
		sub, err := peer.Subscribe(ctx, ns, "video", nil)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}
	if got := len(pubSubsOf(tw)); got != 1 {
		t.Fatalf("%d upstream subscriptions", got)
	}
	writeGroups(t, tw, 3, 4)
	tw.Close()
	for _, sub := range subs {
		var got []Object
		for {
			o, err := sub.ReadObject(ctx)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, o)
		}
		if len(got) != 15 {
			t.Fatalf("%d objects", len(got))
		}
		for _, o := range got {
			if o.Priority != 9 {
				t.Fatalf("priority %+v", o)
			}
		}
		props := sub.Properties()
		if !slices.ContainsFunc(props, func(p Property) bool { return p.Type == 0x3803 && string(p.Bytes) == "kept" }) {
			t.Fatalf("track properties %+v", props)
		}
	}
	eventually(t, "relay cleanup", func() bool {
		r.mu.Lock()
		defer r.mu.Unlock()
		return len(r.tracks) == 0
	})
}

func TestRelayLateJoinAndCleanup(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"live"}
	tw, _, _ := relayedPublisher(t, r, ns, "cam")
	gw := writeGroups(t, tw, 2, 3)
	ctx := testCtx(t)
	first, _ := joinRelay(t, r, nil)
	sub1, err := first.Subscribe(ctx, ns, "cam", &SubscribeOptions{Priority: 1, Join: JoinCurrentGroup})
	if err != nil {
		t.Fatal(err)
	}
	readN(t, ctx, sub1, 3) // group 1 from the publisher's cache, via the relay
	mustWrite(t, gw, []byte("g1-o3"))
	readN(t, ctx, sub1, 1)
	late, _ := joinRelay(t, r, nil)
	sub2, err := late.Subscribe(ctx, ns, "cam", &SubscribeOptions{Priority: 1, Join: JoinCurrentGroup})
	if err != nil {
		t.Fatal(err)
	}
	got := readN(t, ctx, sub2, 4)
	var payloads []string
	for _, o := range got {
		payloads = append(payloads, string(o.Payload))
	}
	slices.Sort(payloads)
	if !slices.Equal(payloads, []string{"g1-o0", "g1-o1", "g1-o2", "g1-o3"}) {
		t.Fatalf("late joiner got %v", payloads)
	}
	if got := len(pubSubsOf(tw)); got != 1 {
		t.Fatalf("%d upstream subscriptions", got)
	}
	sub1.Close()
	sub2.Close()
	eventually(t, "upstream subscription to end", func() bool { return len(pubSubsOf(tw)) == 0 })
}

func TestRelayPublisherGone(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"gone"}
	tw, pub, _ := relayedPublisher(t, r, ns, "t")
	ctx := testCtx(t)
	peer, _ := joinRelay(t, r, nil)
	sub, err := peer.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 1, 2)
	readN(t, ctx, sub, 2)
	pub.Close()
	for {
		if _, err = sub.ReadObject(ctx); err != nil {
			break
		}
	}
	// The publisher left without GOAWAY, so the track did not end and the
	// relay reports an internal error (draft section 12.4).
	var pd *PublishDoneError
	if !errors.As(err, &pd) || pd.Code != DoneInternalError {
		t.Fatalf("after publisher left: %v", err)
	}
	if _, err := peer.Subscribe(ctx, ns, "t", nil); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("subscribe after publisher left: %v", err)
	}
}

func TestRelayPublishDoneCode(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"code"}
	tw, _, _ := relayedPublisher(t, r, ns, "t")
	ctx := testCtx(t)
	peer, _ := joinRelay(t, r, nil)
	sub, err := peer.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	tw.t.end(DoneUnauthorized)
	_, err = sub.ReadObject(ctx)
	var pd *PublishDoneError
	if !errors.As(err, &pd) || pd.Code != DoneUnauthorized {
		t.Fatalf("err %v", err)
	}
}

func TestRelayAuthorization(t *testing.T) {
	checkLeaks(t)
	var mu sync.Mutex
	var publisher ed25519.PublicKey
	r := newRelay(t, &RelayConfig{Session: Config{Authorize: func(peer ed25519.PublicKey, kind RequestKind, ns Namespace, track string) error {
		mu.Lock()
		defer mu.Unlock()
		if kind == KindPublishNamespace && publisher != nil && !publisher.Equal(peer) {
			return errors.New("not the publisher")
		}
		if kind == KindSubscribe && track == "secret" {
			return errors.New("no")
		}
		return nil
	}}})
	ctx := testCtx(t)
	origin := newOrigin(t)
	mustTrack(t, origin, Namespace{"a"}, "secret", nil)
	pub, relaySide := joinRelay(t, r, &Config{Origin: origin})
	mu.Lock()
	publisher = relaySide.RemotePublicKey()
	mu.Unlock()
	if _, err := pub.PublishNamespace(ctx, Namespace{"a"}); err != nil {
		t.Fatal(err)
	}
	other, _ := joinRelay(t, r, nil)
	if _, err := other.PublishNamespace(ctx, Namespace{"a"}); requestCode(err) != ReqUnauthorized {
		t.Fatalf("second publisher: %v", err)
	}
	if _, err := other.Subscribe(ctx, Namespace{"a"}, "secret", nil); requestCode(err) != ReqUnauthorized {
		t.Fatalf("subscribe: %v", err)
	}
	if _, err := other.Subscribe(ctx, Namespace{"b"}, "x", nil); requestCode(err) != ReqDoesNotExist {
		t.Fatalf("unknown namespace: %v", err)
	}
}

func TestRelayNamespaceTakeover(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ctx := testCtx(t)
	relayedPublisher(t, r, Namespace{"owned"}, "t")
	other, _ := joinRelay(t, r, nil)
	for _, ns := range []Namespace{{"owned"}, {"owned", "sub"}} {
		if _, err := other.PublishNamespace(ctx, ns); requestCode(err) != ReqUnauthorized {
			t.Fatalf("%v: %v", ns, err)
		}
	}
	if _, err := other.PublishNamespace(ctx, Namespace{"free"}); err != nil {
		t.Fatal(err)
	}
}

func TestRelayFetchAndStatus(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"f"}
	tw, _, _ := relayedPublisher(t, r, ns, "t")
	writeGroups(t, tw, 3, 2)
	ctx := testCtx(t)
	peer, _ := joinRelay(t, r, nil)
	fetchAll := func(opts *FetchOptions) []string {
		t.Helper()
		f, err := peer.Fetch(ctx, ns, "t", opts)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for {
			o, err := f.ReadObject(ctx)
			if err == io.EOF {
				return out
			}
			if err != nil {
				t.Fatal(err)
			}
			out = append(out, string(o.Payload))
		}
	}
	// Not relayed yet: forwarded to the publisher.
	if got := fetchAll(&FetchOptions{RecentGroups: 2, Priority: 1}); !slices.Equal(got, []string{"g1-o0", "g1-o1", "g2-o0", "g2-o1"}) {
		t.Fatalf("forwarded fetch %v", got)
	}
	st, err := peer.TrackStatus(ctx, ns, "t")
	if err != nil || st.Largest != (Location{2, 1}) {
		t.Fatalf("forwarded status %+v %v", st, err)
	}
	// Relayed: served from the relay's cache.
	sub, err := peer.Subscribe(ctx, ns, "t", &SubscribeOptions{Priority: 1, Join: JoinCurrentGroup})
	if err != nil {
		t.Fatal(err)
	}
	readN(t, ctx, sub, 2)
	if got := fetchAll(nil); !slices.Equal(got, []string{"g2-o0", "g2-o1"}) {
		t.Fatalf("cached fetch %v", got)
	}
	st, err = peer.TrackStatus(ctx, ns, "t")
	if err != nil || st.Largest != (Location{2, 1}) {
		t.Fatalf("cached status %+v %v", st, err)
	}
}

func TestRelayNamespaces(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ctx := testCtx(t)
	peer, _ := joinRelay(t, r, nil)
	_, _, pn1 := relayedPublisher(t, r, Namespace{"site", "a"}, "t")
	nsub, err := peer.SubscribeNamespace(ctx, Namespace{"site"})
	if err != nil {
		t.Fatal(err)
	}
	ev, err := nsub.Next(ctx)
	if err != nil || !ev.Active || !slices.Equal(ev.Namespace, Namespace{"site", "a"}) {
		t.Fatalf("%+v %v", ev, err)
	}
	relayedPublisher(t, r, Namespace{"site", "b"}, "t")
	if ev, err = nsub.Next(ctx); err != nil || !ev.Active || !slices.Equal(ev.Namespace, Namespace{"site", "b"}) {
		t.Fatalf("%+v %v", ev, err)
	}
	pn1.Close()
	if ev, err = nsub.Next(ctx); err != nil || ev.Active || !slices.Equal(ev.Namespace, Namespace{"site", "a"}) {
		t.Fatalf("%+v %v", ev, err)
	}
}

func TestRelayConfig(t *testing.T) {
	if _, err := NewRelay(&RelayConfig{Session: Config{Origin: newOrigin(t)}}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatal(err)
	}
	for _, cfg := range []RelayConfig{{MaxCacheBytes: -1}, {CacheBytes: 1 << 20, MaxCacheBytes: 1 << 20}, {MaxCacheBytes: 2 << 40}} {
		if _, err := NewRelay(&cfg); !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%+v: %v", cfg, err)
		}
	}
	if cfg := newRelay(t, nil).cfg; cfg.MaxCacheBytes != 1<<30 || cfg.MaxSessionFetches != 16 {
		t.Fatalf("defaults %d, %d", cfg.MaxCacheBytes, cfg.MaxSessionFetches)
	}
}
