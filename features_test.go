package kolomoq

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"
)

// writeGroups writes n groups of k objects, payload "g<i>-o<j>"; the last
// group stays open.
func writeGroups(t *testing.T, tw *TrackWriter, n, k int) *GroupWriter {
	t.Helper()
	var gw *GroupWriter
	for g := range n {
		var err error
		if gw, err = tw.NewGroup(); err != nil {
			t.Fatal(err)
		}
		for i := range k {
			if _, err := gw.WriteObject([]byte(fmt.Sprintf("g%d-o%d", g, i))); err != nil {
				t.Fatal(err)
			}
		}
	}
	return gw
}

func TestJoinCurrentGroup(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"live"}
	tw := mustTrack(t, origin, ns, "cam", nil)
	gw := writeGroups(t, tw, 3, 5) // group 2 is current, objects 0..4
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "cam", &SubscribeOptions{Priority: 10, Join: JoinCurrentGroup})
	if err != nil {
		t.Fatal(err)
	}
	if l, ok := sub.Largest(); !ok || l != (Location{2, 4}) {
		t.Fatalf("largest %v %v", l, ok)
	}
	mustWrite(t, gw, []byte("g2-o5"))
	got := readN(t, ctx, sub, 6)
	slices.SortFunc(got, func(a, b Object) int { return int(a.ID) - int(b.ID) })
	for i, o := range got {
		if o.Group != 2 || o.ID != uint64(i) || string(o.Payload) != fmt.Sprintf("g2-o%d", i) {
			t.Fatalf("object %d: %+v", i, o)
		}
	}
}

func TestJoinNextGroup(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"live"}, "cam", nil)
	gw := writeGroups(t, tw, 1, 2)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, Namespace{"live"}, "cam", &SubscribeOptions{Priority: DefaultPriority, Join: JoinNextGroup})
	if err != nil {
		t.Fatal(err)
	}
	mustWrite(t, gw, []byte("late"))
	writeGroups(t, tw, 1, 1)
	o := readN(t, ctx, sub, 1)[0]
	if o.Group != 1 {
		t.Fatalf("got %+v, want group 1", o)
	}
}

func TestFetch(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"vod"}
	tw := mustTrack(t, origin, ns, "t", &TrackOptions{Priority: 3, Properties: []Property{{Type: 0x3801, Bytes: []byte("x")}}})
	writeGroups(t, tw, 4, 3)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	readAll := func(f *Fetch) []string {
		t.Helper()
		var out []string
		for {
			o, err := f.ReadObject(ctx)
			if err == io.EOF {
				return out
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.Priority != 3 {
				t.Fatalf("priority %d", o.Priority)
			}
			out = append(out, string(o.Payload))
		}
	}
	for name, tc := range map[string]struct {
		opts *FetchOptions
		want []string
		end  Location
	}{
		"current group": {nil, []string{"g3-o0", "g3-o1", "g3-o2"}, Location{3, 2}},
		"two groups":    {&FetchOptions{RecentGroups: 2}, []string{"g2-o0", "g2-o1", "g2-o2", "g3-o0", "g3-o1", "g3-o2"}, Location{3, 2}},
		"range": {&FetchOptions{Start: Location{1, 1}, End: &Location{2, 0}},
			[]string{"g1-o1", "g1-o2", "g2-o0"}, Location{2, 0}},
		"descending": {&FetchOptions{Start: Location{1, 2}, End: &Location{3, 0}, GroupOrder: OrderDescending},
			[]string{"g3-o0", "g2-o0", "g2-o1", "g2-o2", "g1-o2"}, Location{3, 0}},
		"open end": {&FetchOptions{Start: Location{3, 1}}, []string{"g3-o1", "g3-o2"}, Location{3, 2}},
	} {
		t.Run(name, func(t *testing.T) {
			f, err := p.client.Fetch(ctx, ns, "t", tc.opts)
			if err != nil {
				t.Fatal(err)
			}
			if f.End() != tc.end {
				t.Fatalf("end %v", f.End())
			}
			if got := readAll(f); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
			if len(f.Properties()) == 0 {
				t.Fatal("no track properties")
			}
		})
	}
	if _, err := p.client.Fetch(ctx, ns, "t", &FetchOptions{Start: Location{9, 0}}); requestCode(err) != ReqInvalidRange {
		t.Fatalf("beyond largest: %v", err)
	}
	empty := mustTrack(t, origin, ns, "empty", nil)
	defer empty.Close()
	if _, err := p.client.Fetch(ctx, ns, "empty", nil); requestCode(err) != ReqInvalidRange {
		t.Fatalf("empty track: %v", err)
	}
}

func TestFetchEvictedGroups(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"c"}, "t", &TrackOptions{Priority: DefaultPriority, CacheGroups: 2})
	writeGroups(t, tw, 5, 2)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	f, err := p.client.Fetch(ctx, Namespace{"c"}, "t", &FetchOptions{Start: Location{0, 0}})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for {
		o, err := f.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(o.Payload))
	}
	if want := []string{"g3-o0", "g3-o1", "g4-o0", "g4-o1"}; !slices.Equal(got, want) {
		t.Fatalf("got %v", got)
	}
}

func TestTrackStatus(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"s"}, "t", &TrackOptions{Priority: 7, ObjectDeliveryTimeout: 250 * time.Millisecond})
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	st, err := p.client.TrackStatus(ctx, Namespace{"s"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if st.HasLargest {
		t.Fatal("largest before any object")
	}
	writeGroups(t, tw, 2, 3)
	st, err = p.client.TrackStatus(ctx, Namespace{"s"}, "t")
	if err != nil {
		t.Fatal(err)
	}
	if !st.HasLargest || st.Largest != (Location{1, 2}) {
		t.Fatalf("largest %+v", st)
	}
	props := map[uint64]uint64{}
	for _, pr := range st.Properties {
		props[pr.Type] = pr.Value
	}
	if props[propDefaultPriority] != 7 || props[propObjectTimeout] != 250 || props[propDefaultOrder] != 1 {
		t.Fatalf("properties %+v", st.Properties)
	}
}

func TestUpdatePauseResume(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"u"}, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, Namespace{"u"}, "t", &SubscribeOptions{Priority: 1, Paused: true})
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 1, 3)
	short, cancel := context.WithTimeout(ctx, 200*time.Millisecond)
	_, err = sub.ReadObject(short)
	cancel()
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("paused subscription delivered: %v", err)
	}
	if err := sub.Update(ctx, SubscriptionUpdate{Priority: 5}); err != nil {
		t.Fatal(err)
	}
	eventually(t, "priority update", func() bool {
		var ps *pubSub
		tw.t.mu.Lock()
		for k := range tw.t.subs {
			ps = k
		}
		tw.t.mu.Unlock()
		return ps != nil && ps.priority() == 5
	})
	writeGroups(t, tw, 1, 2)
	got := readN(t, ctx, sub, 3)
	slices.SortFunc(got, func(a, b Object) int { return int(a.Group*10+a.ID) - int(b.Group*10+b.ID) })
	// Group 0 ends while the subscription runs; group 1 follows.
	if got[0].Status != StatusEndOfGroup || got[1].Group != 1 || got[2].Group != 1 {
		t.Fatalf("got %+v", got)
	}
	if err := sub.Update(ctx, SubscriptionUpdate{Priority: 5, Paused: true}); err != nil {
		t.Fatal(err)
	}
}

func TestUnsubscribe(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"u"}, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, Namespace{"u"}, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 1, 1)
	readN(t, ctx, sub, 1)
	sub.Close()
	if _, err := sub.ReadObject(ctx); !errors.Is(err, ErrClosed) {
		t.Fatalf("after close: %v", err)
	}
	eventually(t, "publisher to drop the subscription", func() bool {
		tw.t.mu.Lock()
		defer tw.t.mu.Unlock()
		return len(tw.t.subs) == 0
	})
	writeGroups(t, tw, 1, 1)
	if p.server.Err() != nil || p.client.Err() != nil {
		t.Fatal(p.server.Err(), p.client.Err())
	}
}

func TestNamespaces(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	pub, err := p.client.PublishNamespace(ctx, Namespace{"mine", "a"})
	if err != nil {
		t.Fatal(err)
	}
	eventually(t, "peer namespace", func() bool { return len(p.server.PeerNamespaces()) == 1 })
	if got := p.server.PeerNamespaces()[0]; !slices.Equal(got, Namespace{"mine", "a"}) {
		t.Fatalf("peer namespace %v", got)
	}
	pub.Close()
	eventually(t, "withdrawal", func() bool { return len(p.server.PeerNamespaces()) == 0 })

	tw1 := mustTrack(t, origin, Namespace{"room", "1"}, "a", nil)
	mustTrack(t, origin, Namespace{"other"}, "a", nil)
	ns, err := p.client.SubscribeNamespace(ctx, Namespace{"room"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.SubscribeNamespace(ctx, Namespace{"room", "1"}); requestCode(err) != ReqPrefixOverlap {
		t.Fatalf("overlap: %v", err)
	}
	ev, err := ns.Next(ctx)
	if err != nil || !ev.Active || !slices.Equal(ev.Namespace, Namespace{"room", "1"}) {
		t.Fatalf("first event %+v %v", ev, err)
	}
	mustTrack(t, origin, Namespace{"room", "2"}, "a", nil)
	ev, err = ns.Next(ctx)
	if err != nil || !ev.Active || !slices.Equal(ev.Namespace, Namespace{"room", "2"}) {
		t.Fatalf("second event %+v %v", ev, err)
	}
	tw1.Close()
	ev, err = ns.Next(ctx)
	if err != nil || ev.Active || !slices.Equal(ev.Namespace, Namespace{"room", "1"}) {
		t.Fatalf("third event %+v %v", ev, err)
	}
	ns.Close()
}

func TestGoAway(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"g"}, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, Namespace{"g"}, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.server.GoAway(ctx, 10*time.Second) }()
	select {
	case <-p.client.GoingAway():
	case <-ctx.Done():
		t.Fatal("no GOAWAY")
	}
	if _, err := p.client.Subscribe(ctx, Namespace{"g"}, "t", nil); !errors.Is(err, ErrGoingAway) {
		t.Fatalf("new request after GOAWAY: %v", err)
	}
	// The old subscription keeps working while the client migrates.
	writeGroups(t, tw, 1, 1)
	readN(t, ctx, sub, 1)
	sub.Close()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	<-p.client.Done()
	var se *SessionError
	if !errors.As(p.client.Err(), &se) || se.Code != CodeNoError {
		t.Fatalf("client err %v", p.client.Err())
	}
}

func TestGoAwayTimeout(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	mustTrack(t, origin, Namespace{"g"}, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	if _, err := p.client.Subscribe(ctx, Namespace{"g"}, "t", nil); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if err := p.server.GoAway(ctx, 300*time.Millisecond); err != nil {
		t.Fatal(err)
	}
	if time.Since(start) < 300*time.Millisecond {
		t.Fatal("closed before the timeout")
	}
	<-p.client.Done()
	var se *SessionError
	if !errors.As(p.client.Err(), &se) || se.Code != CodeGoAwayTimeout || !se.Remote {
		t.Fatalf("client err %v", p.client.Err())
	}
}

func TestMultipleSubscribers(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"fan"}, "t", nil)
	ctx := testCtx(t)
	const n = 5
	var subs []*Subscription
	for range n {
		p := newPair(t, nil, &Config{Origin: origin})
		sub, err := p.client.Subscribe(ctx, Namespace{"fan"}, "t", nil)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}
	writeGroups(t, tw, 3, 10)
	for _, sub := range subs {
		// Groups 0 and 1 also carry End of Group.
		got := readN(t, ctx, sub, 32)
		count := map[uint64]int{}
		for _, o := range got {
			count[o.Group]++
		}
		if count[0] != 11 || count[1] != 11 || count[2] != 10 {
			t.Fatalf("per group %v", count)
		}
	}
}

func TestConcurrentPublishers(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	const tracks, groups, objs = 8, 5, 20
	var writers []*TrackWriter
	var subs []*Subscription
	for i := range tracks {
		tw, err := origin.CreateTrack(Namespace{"multi"}, fmt.Sprint(i), &TrackOptions{Priority: uint8(i)})
		if err != nil {
			t.Fatal(err)
		}
		writers = append(writers, tw)
		sub, err := p.client.Subscribe(ctx, Namespace{"multi"}, fmt.Sprint(i), nil)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}
	var wg sync.WaitGroup
	for _, tw := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range groups {
				gw, err := tw.NewGroup()
				if err != nil {
					t.Error(err)
					return
				}
				for range objs {
					if _, err := gw.WriteObject(make([]byte, 512)); err != nil {
						t.Error(err)
						return
					}
				}
			}
			tw.Close()
		}()
	}
	wg.Wait()
	for i, sub := range subs {
		n := 0
		for {
			o, err := sub.ReadObject(ctx)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.Priority != uint8(i) {
				t.Fatalf("track %d priority %d", i, o.Priority)
			}
			n++
		}
		// Each group ends with End of Group, the last with End of Track.
		if want := groups * (objs + 1); n != want {
			t.Fatalf("track %d: %d objects, want %d", i, n, want)
		}
	}
}

func TestReconnect(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"r"}, "t", nil)
	ctx := testCtx(t)
	p1 := newPair(t, nil, &Config{Origin: origin})
	sub1, err := p1.client.Subscribe(ctx, Namespace{"r"}, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 1, 1)
	readN(t, ctx, sub1, 1)
	p1.clientConn.CloseWithError(0, "")
	if _, err := sub1.ReadObject(ctx); err == nil {
		t.Fatal("old subscription still open")
	}
	eventually(t, "old state gone", func() bool {
		tw.t.mu.Lock()
		defer tw.t.mu.Unlock()
		return len(tw.t.subs) == 0
	})
	p2 := newPair(t, nil, &Config{Origin: origin})
	sub2, err := p2.client.Subscribe(ctx, Namespace{"r"}, "t", &SubscribeOptions{Priority: DefaultPriority, Join: JoinCurrentGroup})
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 1, 1)
	got := readN(t, ctx, sub2, 3)
	slices.SortFunc(got, func(a, b Object) int { return int(a.Group*10+a.ID) - int(b.Group*10+b.ID) })
	if string(got[0].Payload) != "g0-o0" || got[1].Status != StatusEndOfGroup || got[2].Group != 1 {
		t.Fatalf("got %+v", got)
	}
}
