package kolomoq

import (
	"errors"
	"math"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// asked reports whether the publisher has a new group request pending, taking it.
func asked(tw *TrackWriter) bool {
	select {
	case <-tw.NewGroupRequests():
		return true
	default:
		return false
	}
}

// rawRequest sends a NEW_GROUP_REQUEST with value v without the subscriber's own rate limit.
func rawRequest(t *testing.T, sub *Subscription, v uint64) {
	t.Helper()
	prm := &wire.MessageParams{NewGroupRequest: v}
	prm.Set(wire.ParamNewGroupRequest)
	sub.updMu.Lock()
	defer sub.updMu.Unlock()
	if err := sub.update(testCtx(t), prm); err != nil {
		t.Fatal(err)
	}
}

func newGroupPair(t *testing.T, groups int) (*TrackWriter, *Subscription) {
	t.Helper()
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"ng"}, "v", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	sub, err := p.client.Subscribe(testCtx(t), Namespace{"ng"}, "v", nil)
	if err != nil {
		t.Fatal(err)
	}
	if groups > 0 {
		writeGroups(t, tw, groups, 1)
		readN(t, testCtx(t), sub, 2*groups-1)
	}
	return tw, sub
}

func TestRequestNewGroupSignalsThePublisher(t *testing.T) {
	checkLeaks(t)
	tw, sub := newGroupPair(t, 3)
	if err := sub.RequestNewGroup(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if !asked(tw) {
		t.Fatal("the publisher was not told")
	}
	// The request changed nothing else: the subscription still delivers.
	gw, err := tw.NewGroup()
	if err != nil {
		t.Fatal(err)
	}
	gw.WriteObject([]byte("key"))
	if o := readN(t, testCtx(t), sub, 1)[0]; o.Group < 2 {
		t.Fatalf("got group %d", o.Group)
	}
}

func TestRequestNewGroupBeforeAnyGroup(t *testing.T) {
	checkLeaks(t)
	tw, sub := newGroupPair(t, 0)
	if err := sub.RequestNewGroup(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if !asked(tw) {
		t.Fatal("a subscriber with no group asked and the publisher was not told")
	}
}

func TestNewGroupRequestNotAboveLargestIsIgnored(t *testing.T) {
	checkLeaks(t)
	tw, sub := newGroupPair(t, 3) // groups 0 to 2
	rawRequest(t, sub, 2)         // the subscriber saw group 1 only: group 2 exists
	if asked(tw) {
		t.Fatal("a request not above the largest group was signalled")
	}
	rawRequest(t, sub, 3) // above the largest group
	if !asked(tw) {
		t.Fatal("a request above the largest group was not signalled")
	}
	time.Sleep(NewGroupRequestInterval + 50*time.Millisecond)
	rawRequest(t, sub, 1)
	rawRequest(t, sub, 3)
	if !asked(tw) {
		t.Fatal("the ignored request used up the interval")
	}
}

func TestNewGroupRequestsCoalesceAndAreBounded(t *testing.T) {
	checkLeaks(t)
	tw, sub := newGroupPair(t, 1)
	for range 100 {
		rawRequest(t, sub, 0) // every one is answered
	}
	if !asked(tw) {
		t.Fatal("no signal")
	}
	if asked(tw) {
		t.Fatal("100 requests left more than one signal")
	}
	// Past the limit of the track they signal again, still one at a time.
	time.Sleep(NewGroupRequestInterval + 50*time.Millisecond)
	for range 100 {
		rawRequest(t, sub, 0)
	}
	if !asked(tw) || asked(tw) {
		t.Fatal("want exactly one signal")
	}
	// The largest value a varint holds is an ordinary request above every group: it signals once and breaks nothing.
	time.Sleep(NewGroupRequestInterval + 50*time.Millisecond)
	rawRequest(t, sub, 1<<62-1)
	if !asked(tw) || asked(tw) {
		t.Fatal("want exactly one signal for the largest value")
	}
}

func TestRequestNewGroupRateLimit(t *testing.T) {
	checkLeaks(t)
	tw, sub := newGroupPair(t, 1)
	if err := sub.RequestNewGroup(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if err := sub.RequestNewGroup(testCtx(t)); !errors.Is(err, ErrNewGroupTooSoon) {
		t.Fatalf("second request: %v", err)
	}
	if !asked(tw) || asked(tw) {
		t.Fatal("want exactly one signal")
	}
	time.Sleep(NewGroupRequestInterval)
	if err := sub.RequestNewGroup(testCtx(t)); err != nil {
		t.Fatal(err)
	}
	if !asked(tw) {
		t.Fatal("no signal after the interval")
	}
}

func TestRequestNewGroupThroughARelay(t *testing.T) {
	checkLeaks(t)
	r := newRelay(t, nil)
	ns := Namespace{"conf", "7"}
	tw, _, _ := relayedPublisher(t, r, ns, "video")
	peer, _ := joinRelay(t, r, nil)
	ctx := testCtx(t)
	sub, err := peer.Subscribe(ctx, ns, "video", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 2, 1)
	readN(t, ctx, sub, 3)
	if err := sub.RequestNewGroup(ctx); err != nil {
		t.Fatal(err)
	}
	eventually(t, "the publisher to be told through the relay", func() bool { return asked(tw) })
	// Many subscribers asking at once reach the publisher as one pending signal.
	var others []*Subscription
	for range 5 {
		p2, _ := joinRelay(t, r, nil)
		s2, err := p2.Subscribe(ctx, ns, "video", nil)
		if err != nil {
			t.Fatal(err)
		}
		others = append(others, s2)
	}
	time.Sleep(NewGroupRequestInterval + 50*time.Millisecond)
	for _, s := range others {
		s.RequestNewGroup(ctx)
	}
	eventually(t, "the publisher to be told by the others", func() bool { return asked(tw) })
	time.Sleep(200 * time.Millisecond)
	if asked(tw) {
		t.Fatal("five requests in one interval reached the publisher more than once")
	}
}

// Many subscriptions of one session to one track, each within its own rate, reach the publisher as one signal per
// interval: the limit is the track's.
func TestNewGroupRequestsAreLimitedPerTrack(t *testing.T) {
	checkLeaks(t)
	tw, first := newGroupPair(t, 1)
	subs := []*Subscription{first}
	for range 20 {
		sub, err := first.s.Subscribe(testCtx(t), Namespace{"ng"}, "v", nil)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}
	// A reader that drains the channel as fast as it fills counts every signal that gets through.
	var signals atomic.Int32
	done := make(chan struct{})
	t.Cleanup(func() { close(done) })
	go func() {
		for {
			select {
			case <-tw.NewGroupRequests():
				signals.Add(1)
			case <-done:
				return
			}
		}
	}()
	storm := func() {
		for range 3 {
			for _, sub := range subs {
				rawRequest(t, sub, 0)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	storm()
	if n := signals.Load(); n != 1 {
		t.Fatalf("63 requests from 21 subscriptions made %d signals, want 1", n)
	}
	time.Sleep(NewGroupRequestInterval)
	storm()
	if n := signals.Load(); n != 2 {
		t.Fatalf("%d signals after the interval, want 2", n)
	}
}

func TestNewGroupValue(t *testing.T) {
	for _, c := range []struct {
		max  uint64
		has  bool
		want uint64
	}{{0, false, 0}, {7, false, 0}, {0, true, 1}, {7, true, 8}, {1<<62 - 1, true, 1 << 62}, {math.MaxUint64 - 1, true, math.MaxUint64}, {math.MaxUint64, true, math.MaxUint64}} {
		if got := newGroupValue(c.max, c.has); got != c.want {
			t.Errorf("newGroupValue(%d, %v) = %d, want %d", c.max, c.has, got, c.want)
		}
	}
}
