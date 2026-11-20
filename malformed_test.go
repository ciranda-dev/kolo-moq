package kolomoq

import (
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// Tests of the malformed-track rules of draft section 12.1 that the cache
// of a relay checks, and of what a relay does about them.

func testTrack(t *testing.T, opts *TrackOptions) *track {
	t.Helper()
	tr, err := newTrack(Namespace{"m"}, "t", opts, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}

func obj(group, id uint64, subgroup uint64, prio uint8, payload string) *cobj {
	return newCobj(wire.Object{Group: group, Subgroup: subgroup, ID: id, Priority: prio, Payload: []byte(payload)}, false)
}

func endObj(group, id uint64, status uint64) *cobj {
	return newCobj(wire.Object{Group: group, ID: id, Priority: DefaultPriority, Status: status}, false)
}

// malformedTrack checks that the track ended with MALFORMED_TRACK.
func malformedTrack(t *testing.T, tr *track) {
	t.Helper()
	tr.mu.Lock()
	defer tr.mu.Unlock()
	if !tr.ended || tr.endCode != DoneMalformedTrack {
		t.Fatalf("track ended %v with %v, want MALFORMED_TRACK", tr.ended, tr.endCode)
	}
}

func TestMalformedTrackRules(t *testing.T) {
	cases := []struct {
		name string
		run  func(tr *track) bool // true when the track was found malformed
	}{
		{"1: another priority in a subgroup", func(tr *track) bool {
			tr.add(obj(0, 0, 3, 128, "a"))
			return !tr.add(obj(0, 1, 3, 64, "b"))
		}},
		{"1: the same priority in another subgroup is fine", func(tr *track) bool {
			tr.add(obj(0, 0, 3, 128, "a"))
			return !tr.add(obj(0, 1, 4, 64, "b"))
		}},
		{"2: object after the final object of a subgroup", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(obj(0, 1, 0, 128, "b"))
			tr.endSubgroup(0, 0, 1, false)
			return !tr.add(obj(0, 2, 0, 128, "c"))
		}},
		{"2: object after the end of another subgroup is fine", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.endSubgroup(0, 0, 0, false)
			return !tr.add(obj(0, 1, 1, 128, "b"))
		}},
		{"3: two streams of a subgroup end at different objects", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(obj(0, 1, 0, 128, "b"))
			tr.add(obj(0, 2, 0, 128, "c"))
			return tr.endSubgroup(0, 0, 2, false) && !tr.endSubgroup(0, 0, 1, false)
		}},
		{"3: a repeated end at the same object is fine", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			first := tr.endSubgroup(0, 0, 0, false)
			again := tr.endSubgroup(0, 0, 0, false)
			return !(first && again)
		}},
		{"3: a stream ends before an object already seen", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(obj(0, 5, 0, 128, "b"))
			return !tr.endSubgroup(0, 0, 3, false)
		}},
		{"4: object after End of Group status", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(endObj(0, 1, wire.StatusEndOfGroup))
			return !tr.add(obj(0, 2, 0, 128, "b"))
		}},
		{"4: object after the stream that ends the group", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(obj(0, 1, 0, 128, "b"))
			tr.endSubgroup(0, 0, 1, true)
			return !tr.add(obj(0, 2, 1, 128, "c"))
		}},
		{"4: two different ends of a group", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(endObj(0, 1, wire.StatusEndOfGroup))
			return !tr.endSubgroup(0, 0, 4, true)
		}},
		{"4: the stream that ends the group is not its last object", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(obj(0, 7, 1, 128, "b"))
			return !tr.endSubgroup(0, 0, 0, true)
		}},
		{"5: object after End of Track", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			tr.add(endObj(0, 1, wire.StatusEndOfTrack))
			return !tr.add(obj(1, 0, 0, 128, "b"))
		}},
		{"5: End of Track before an object already seen", func(tr *track) bool {
			tr.add(obj(2, 0, 0, 128, "a"))
			return !tr.add(endObj(1, 0, wire.StatusEndOfTrack))
		}},
		{"6: a repeat with another payload", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			return !tr.add(obj(0, 0, 0, 128, "b"))
		}},
		{"6: a repeat with another immutable property", func(tr *track) bool {
			with := func(v byte) *cobj {
				return newCobj(wire.Object{ID: 0, Priority: 128, Payload: []byte("a"), Properties: []wire.KV{{Type: wire.PropImmutable, Bytes: []byte{v}}}}, true)
			}
			tr.add(with(1))
			return !tr.add(with(2))
		}},
		{"6: a repeat with other mutable properties is fine", func(tr *track) bool {
			with := func(v uint64) *cobj {
				return newCobj(wire.Object{ID: 0, Priority: 128, Payload: []byte("a"), Properties: []wire.KV{{Type: 0x78, Value: v}}}, true)
			}
			tr.add(with(1))
			return !tr.add(with(2))
		}},
		{"6: a repeat with another subgroup", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			return !tr.add(obj(0, 0, 1, 128, "a"))
		}},
		{"7: a repeat with another delivery mode", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			d := obj(0, 0, 0, 128, "a")
			d.Datagram = true
			return !tr.add(d)
		}},
		{"an identical repeat is fine", func(tr *track) bool {
			tr.add(obj(0, 0, 0, 128, "a"))
			return !tr.add(obj(0, 0, 0, 128, "a"))
		}},
		{"a fill behind the live objects is fine", func(tr *track) bool {
			tr.add(obj(0, 5, 0, 128, "live"))
			tr.add(obj(0, 6, 0, 128, "live"))
			tr.endSubgroup(0, 0, 6, false)
			return !(tr.add(obj(0, 0, 0, 128, "fill")) && tr.add(obj(0, 4, 0, 128, "fill")))
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tr := testTrack(t, nil)
			bad := tc.run(tr)
			want := tc.name[1] == ':' && !strings.HasSuffix(tc.name, "is fine")

			if bad != want {
				t.Fatalf("malformed %v, want %v", bad, want)
			}
			if bad {
				malformedTrack(t, tr)
			} else if tr.ended {
				t.Fatal("track ended")
			}
		})
	}
}

// The object that makes a track malformed is not cached (section 12.1).
func TestMalformedObjectNotCached(t *testing.T) {
	tr := testTrack(t, nil)
	tr.add(obj(0, 0, 3, 128, "a"))
	bytes := tr.bytes
	if tr.add(obj(0, 1, 3, 1, "b")) {
		t.Fatal("accepted")
	}
	g := tr.groups[0]
	if g.ids[1] != nil || len(g.objs) != 1 || tr.bytes != bytes || tr.largest.Object != 0 {
		t.Fatalf("cached: %d objects, %d bytes (was %d), largest %+v", len(g.objs), tr.bytes, bytes, tr.largest)
	}
	// Once malformed, later objects are not cached either.
	tr.add(obj(0, 2, 3, 128, "c"))
	if g.ids[2] != nil {
		t.Fatal("object cached after the track ended")
	}
}

// What the checks remember about subgroups stays within the cache bounds.
func TestSubgroupStateBounded(t *testing.T) {
	tr := testTrack(t, &TrackOptions{CacheBytes: 4 << 10})
	for i := range uint64(2000) {
		if !tr.add(obj(0, i, i, 128, "x")) {
			t.Fatalf("object %d refused", i)
		}
	}
	g := tr.groups[0]
	if !g.noSub || g.sub != nil {
		t.Fatalf("subgroup state kept for a trimmed group: %d entries", len(g.sub))
	}
	if tr.bytes > 4<<10+objectOverhead+8 {
		t.Fatalf("cache holds %d bytes", tr.bytes)
	}
	// Before the first trim the entries count against the budget.
	tr = testTrack(t, &TrackOptions{CacheBytes: 1 << 20})
	for i := range uint64(100) {
		tr.add(obj(0, i, i, 128, ""))
	}
	if want := int64(100) * (objectOverhead + subShapeOverhead); tr.bytes != want {
		t.Fatalf("%d bytes, want %d", tr.bytes, want)
	}
}

// A relay that finds the track malformed ends its downstream subscriptions
// with PUBLISH_DONE MALFORMED_TRACK, cancels the upstream subscription and
// does not cache the object (section 12.1).
func TestRelayMalformedPriorityChange(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"mal"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, peer, ns, "t")
	up, upr, _ := rp.accept()
	_ = upr
	write(t, up, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}})
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	r.mu.Lock()
	var rt *relayTrack
	for _, x := range r.tracks {
		rt = x
	}
	r.mu.Unlock()
	a, _ := subgroupStream(t, rp, 1, 0)
	a(&wire.Object{ID: 0, Payload: []byte("a")})
	readN(t, ctx, sr.sub, 1)
	// The same subgroup, now with another priority in its header.
	ds, err := rp.conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := &wire.SubgroupHeader{Flags: wire.SubgroupTypeBit | wire.SubgroupProperties, TrackAlias: 1, Group: 0, Priority: 3}
	var w wire.SubgroupWriter
	ds.Write(appendObject(&w, h.Append(nil), &wire.Object{ID: 1, Payload: []byte("b")}))
	var pd *PublishDoneError
	_, err = sr.sub.ReadObject(ctx)
	if !errors.As(err, &pd) || pd.Code != DoneMalformedTrack {
		t.Fatalf("downstream: %v", err)
	}
	// The upstream subscription is canceled: the publisher's request stream ends.
	up.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := io.Copy(io.Discard, up); err == nil {
		t.Fatal("upstream request stream still open")
	}
	rt.t.mu.Lock()
	cached := rt.t.groups[0].ids[1]
	rt.t.mu.Unlock()
	if cached != nil {
		t.Fatal("the malformed object was cached")
	}
	r.mu.Lock()
	n := len(r.tracks)
	r.mu.Unlock()
	if n != 0 {
		t.Fatalf("relay still holds %d tracks", n)
	}
}

// A relay resets the fetch streams of a track it finds malformed with
// MALFORMED_TRACK (section 12.1).
func TestRelayResetsFetchOfMalformedTrack(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"mal"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	ctx := readCtx(t, 20*time.Second)
	res := subscribeAsync(ctx, peer, ns, "t")
	up, _, _ := rp.accept()
	write(t, up, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}})
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	a, _ := subgroupStream(t, rp, 1, 0)
	for i := range uint64(3) {
		a(&wire.Object{ID: i, Payload: make([]byte, 512<<10)})
	}
	readN(t, ctx, sr.sub, 3)
	// A raw requester fetches the cached objects and does not read them, so
	// the relay's write is blocked.
	rr, _ := rawRelayPeer(t, r)
	_, br := rr.request(&wire.Request{Type: wire.MsgFetch, RequestID: rr.id(), Namespace: ns, Name: "t", Params: &wire.MessageParams{}})
	rr.expect(br, wire.MsgFetchOK)
	rs, err := rr.conn.AcceptUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(200 * time.Millisecond)
	ds, err := rp.conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := &wire.SubgroupHeader{Flags: wire.SubgroupTypeBit | wire.SubgroupProperties, TrackAlias: 1, Group: 0, Priority: 3}
	var w wire.SubgroupWriter
	ds.Write(appendObject(&w, h.Append(nil), &wire.Object{ID: 3, Payload: []byte("b")}))
	rs.SetReadDeadline(time.Now().Add(10 * time.Second))
	_, err = io.Copy(io.Discard, rs)
	var te *kolotransport.Error
	if !errors.As(err, &te) || !errors.Is(te, kolotransport.ErrStreamReset) || te.Code != resetMalformedTrack {
		t.Fatalf("fetch stream: %v", err)
	}
}

// An upstream stream that ends in the middle of a subgroup another stream
// carried further makes the track malformed (item 3).
func TestRelayMalformedSubgroupEnds(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"mal"}
	rp, _ := rawPublisher(t, r, ns)
	peer, _ := joinRelay(t, r, nil)
	ctx := readCtx(t, 10*time.Second)
	res := subscribeAsync(ctx, peer, ns, "t")
	up, _, _ := rp.accept()
	write(t, up, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}})
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	a, afin := subgroupStream(t, rp, 1, 0)
	a(&wire.Object{ID: 0, Payload: []byte("a")})
	a(&wire.Object{ID: 1, Payload: []byte("b")})
	readN(t, ctx, sr.sub, 2)
	afin()
	// The second stream of the subgroup ends at another object.
	b, bfin := subgroupStream(t, rp, 1, 0)
	b(&wire.Object{ID: 0, Payload: []byte("a")})
	bfin()
	var pd *PublishDoneError
	_, err := sr.sub.ReadObject(ctx)
	if !errors.As(err, &pd) || pd.Code != DoneMalformedTrack {
		t.Fatalf("downstream: %v", err)
	}
}

// FuzzTrackCache feeds a cache objects and subgroup ends in any order: it
// must not panic, and what it holds must match what it accounts for.
func FuzzTrackCache(f *testing.F) {
	f.Add([]byte{0, 0, 0, 0, 128, 0, 0, 1, 0, 128, 1, 0, 1, 0, 0})
	f.Add([]byte{0, 1, 5, 2, 7, 0, 1, 3, 2, 7, 1, 1, 5, 2, 0, 2, 1, 0, 0, 0})
	f.Fuzz(func(t *testing.T, ops []byte) {
		tr, err := newTrack(Namespace{"f"}, "t", &TrackOptions{CacheGroups: 3, CacheBytes: 1 << 10}, 1<<20)
		if err != nil {
			t.Fatal(err)
		}
		for ; len(ops) >= 5; ops = ops[5:] {
			kind, group, id, sub, prio := ops[0]%4, uint64(ops[1]%6), uint64(ops[2]), uint64(ops[3]%4), ops[4]
			switch kind {
			case 0, 1:
				tr.add(obj(group, id, sub, prio%3, string(ops[:kind])))
			case 2:
				tr.endSubgroup(group, sub, id, prio%2 == 0)
			case 3:
				tr.add(endObj(group, id, []uint64{wire.StatusEndOfGroup, wire.StatusEndOfTrack}[prio%2]))
			}
		}
		tr.mu.Lock()
		defer tr.mu.Unlock()
		var total int64
		for _, g := range tr.groups {
			var n int64
			for _, o := range g.objs {
				n += o.size()
				if g.ids[o.ID] != o {
					t.Fatalf("object %d is not in the ID index", o.ID)
				}
			}
			n += int64(len(g.sub)) * subShapeOverhead
			if len(g.ids) != len(g.objs) || n != g.bytes || (g.noSub && g.sub != nil) {
				t.Fatalf("group %d: %d objects, %d IDs, %d bytes accounted for %d held", g.id, len(g.objs), len(g.ids), g.bytes, n)
			}
			total += g.bytes
		}
		if total != tr.bytes || len(tr.groups) > 3 {
			t.Fatalf("%d bytes accounted for %d held, %d groups", tr.bytes, total, len(tr.groups))
		}
		for i := 1; i < len(tr.groups); i++ {
			if tr.groups[i-1].id >= tr.groups[i].id {
				t.Fatal("groups out of order")
			}
		}
	})
}
