package kolomoq

import (
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"slices"
	"sync"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// stalledSubscriber subscribes from a raw peer that never reads its data
// streams.
func stalledSubscriber(t *testing.T, cfg *Config, ns Namespace, name string, prm *wire.MessageParams) (*rawPeer, *Session) {
	t.Helper()
	r, s := connected(t, cfg)
	_, br := r.request(subscribeMsg(r.id(), ns, name, prm))
	r.expect(br, wire.MsgSubscribeOK)
	return r, s
}

func pubSubsOf(tw *TrackWriter) []*pubSub {
	tw.t.mu.Lock()
	defer tw.t.mu.Unlock()
	var out []*pubSub
	for p := range tw.t.subs {
		out = append(out, p)
	}
	return out
}

func TestSlowSubscriberDoesNotBlock(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"slow"}
	tw := mustTrack(t, origin, ns, "t", nil)
	const maxBytes = 1 << 20
	_, stalled := stalledSubscriber(t, &Config{Origin: origin, MaxBufferedGroups: 4, MaxBufferedBytes: maxBytes, MaxObjectSize: 64 << 10}, ns, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	fast, err := p.client.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	const groups, objs = 40, 10
	payload := make([]byte, 16<<10)
	var maxQueued int64
	start := time.Now()
	for range groups {
		gw := mustGroup(t, tw)
		for range objs {
			mustWrite(t, gw, payload)
		}
		for _, ps := range pubSubsOf(tw) {
			if ps.s != stalled {
				continue
			}
			ps.mu.Lock()
			maxQueued = max(maxQueued, ps.queued)
			ps.mu.Unlock()
		}
	}
	tw.Close()
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("writer blocked for %v", d)
	}
	n := 0
	for {
		_, err := fast.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		n++
	}
	if want := groups * (objs + 1); n != want {
		t.Fatalf("fast subscriber got %d objects, want %d", n, want)
	}
	if maxQueued > maxBytes {
		t.Fatalf("slow subscriber queued %d bytes", maxQueued)
	}
	if stalled.Stats().ResetGroups == 0 {
		t.Fatal("no group was reset for the slow subscriber")
	}
	t.Logf("slow subscriber: %d groups reset, at most %d bytes queued", stalled.Stats().ResetGroups, maxQueued)
}

func TestSubscriberBufferBounded(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"buf"}
	tw := mustTrack(t, origin, ns, "t", nil)
	p := newPair(t, &Config{MaxBufferedGroups: 2, MaxBufferedBytes: 64 << 20}, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	writeGroups(t, tw, 10, 3)
	tw.Close()
	eventually(t, "drops", func() bool { return sub.Dropped() >= 7 })
	sub.mu.Lock()
	if len(sub.groups) > 2 {
		t.Errorf("%d groups buffered", len(sub.groups))
	}
	sub.mu.Unlock()
	var groups []uint64
	for {
		o, err := sub.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(groups, o.Group) {
			groups = append(groups, o.Group)
		}
	}
	if len(groups) > 2 || !slices.Contains(groups, 9) {
		t.Fatalf("kept groups %v", groups)
	}
}

// readReset accepts n data streams and returns the reset codes seen.
func readResets(t *testing.T, r *rawPeer, n int) []uint64 {
	t.Helper()
	var codes []uint64
	for range n {
		rs, err := r.conn.AcceptUniStream(testCtx(t))
		if err != nil {
			t.Fatal(err)
		}
		_, err = io.Copy(io.Discard, rs)
		var te *kolotransport.Error
		if errors.As(err, &te) {
			codes = append(codes, te.Code)
		}
	}
	return codes
}

func TestSubgroupDeliveryTimeout(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"dt"}
	tw := mustTrack(t, origin, ns, "t", nil)
	prm := &wire.MessageParams{SubgroupTimeout: 100}
	prm.Set(wire.ParamSubgroupTimeout)
	r, s := stalledSubscriber(t, &Config{Origin: origin}, ns, "t", prm)
	gw := mustGroup(t, tw)
	big := make([]byte, 64<<10)
	for range 16 { // 1 MiB, beyond the stream's flow control window
		mustWrite(t, gw, big)
	}
	gw.Close()
	eventually(t, "expiry", func() bool { return s.Stats().ExpiredGroups == 1 })
	if codes := readResets(t, r, 1); !slices.Equal(codes, []uint64{resetDeliveryTimeout}) {
		t.Fatalf("reset codes %v", codes)
	}
}

func TestObjectDeliveryTimeout(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"ot"}
	tw := mustTrack(t, origin, ns, "t", &TrackOptions{Priority: DefaultPriority, ObjectDeliveryTimeout: 50 * time.Millisecond})
	r, s := stalledSubscriber(t, &Config{Origin: origin}, ns, "t", nil)
	gw := mustGroup(t, tw)
	big := make([]byte, 64<<10)
	for range 16 {
		mustWrite(t, gw, big)
	}
	eventually(t, "expiry", func() bool { return s.Stats().ExpiredGroups == 1 })
	if codes := readResets(t, r, 1); !slices.Equal(codes, []uint64{resetDeliveryTimeout}) {
		t.Fatalf("reset codes %v", codes)
	}
	// The expired subgroup is not reopened; the next group is sent.
	gw2 := mustGroup(t, tw)
	mustWrite(t, gw2, []byte("next"))
	rs, err := r.conn.AcceptUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	rs.SetReadDeadline(time.Now().Add(5 * time.Second))
	b := make([]byte, 64)
	n, _ := io.ReadAtLeast(rs, b, 3)
	h, err := wire.ReadSubgroupHeader(newByteReader(b[1:n]), uint64(b[0]))
	if err != nil || h.Group != 1 {
		t.Fatalf("next stream %+v %v", h, err)
	}
}

func TestConnectionLost(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"lost"}
	tw := mustTrack(t, origin, ns, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	f, err := p.client.Fetch(ctx, ns, "t", &FetchOptions{Start: Location{0, 0}, End: &Location{0, 0}})
	if requestCode(err) != ReqInvalidRange {
		t.Fatalf("fetch: %v %v", f, err)
	}
	writeGroups(t, tw, 2, 5)
	readN(t, ctx, sub, 3)
	p.serverConn.CloseWithError(0x77, "")
	for {
		if _, err = sub.ReadObject(ctx); err != nil {
			break
		}
	}
	var se *SessionError
	if !errors.As(err, &se) || se.Code != 0x77 || !se.Remote {
		t.Fatalf("subscription err %v", err)
	}
	if _, err := p.client.Subscribe(ctx, ns, "t", nil); !errors.As(err, &se) {
		t.Fatalf("subscribe after loss: %v", err)
	}
	// The writer keeps going and the dead subscription is gone.
	writeGroups(t, tw, 2, 5)
	eventually(t, "publisher cleanup", func() bool { return len(pubSubsOf(tw)) == 0 })
}

func TestLatency(t *testing.T) {
	if testing.Short() {
		t.Skip("latency measurement")
	}
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"lat"}
	tw := mustTrack(t, origin, ns, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	const n = 500
	var lat []time.Duration
	seen := make([]bool, n)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for len(lat) < n {
			o, err := sub.ReadObject(ctx)
			if err != nil {
				t.Error(err)
				return
			}
			if o.Status != StatusNormal {
				continue
			}
			// Groups travel on separate streams, so objects of two groups can swap.
			seq := binary.BigEndian.Uint64(o.Payload[8:])
			if seq >= n || seen[seq] {
				t.Errorf("object %d delivered twice or out of range", seq)
				return
			}
			seen[seq] = true
			sent := time.Unix(0, int64(binary.BigEndian.Uint64(o.Payload)))
			lat = append(lat, time.Since(sent))
		}
	}()
	var gw *GroupWriter
	payload := make([]byte, 1200)
	for i := range n {
		if i%30 == 0 {
			gw = mustGroup(t, tw)
		}
		binary.BigEndian.PutUint64(payload, uint64(time.Now().UnixNano()))
		binary.BigEndian.PutUint64(payload[8:], uint64(i))
		mustWrite(t, gw, payload)
		time.Sleep(time.Millisecond)
	}
	<-done
	if len(lat) != n {
		t.Fatalf("%d of %d objects arrived", len(lat), n)
	}
	slices.Sort(lat)
	// Not a benchmark: an object sent every millisecond over loopback must not wait a second.
	if lat[len(lat)-1] > time.Second || lat[0] < 0 {
		t.Fatalf("latency from %v to %v", lat[0], lat[len(lat)-1])
	}
	t.Logf("object publish to receive over loopback, %d objects of 1200 bytes: p50 %v, p90 %v, p99 %v, max %v",
		len(lat), lat[len(lat)/2], lat[len(lat)*9/10], lat[len(lat)*99/100], lat[len(lat)-1])
}

func TestLongRunning(t *testing.T) {
	if testing.Short() {
		t.Skip("long-running test")
	}
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"long"}
	tw := mustTrack(t, origin, ns, "t", &TrackOptions{Priority: DefaultPriority, CacheGroups: 4})
	ctx := testCtx(t)
	const subscribers = 3
	var subs []*Subscription
	for range subscribers {
		p := newPair(t, nil, &Config{Origin: origin})
		sub, err := p.client.Subscribe(ctx, ns, "t", nil)
		if err != nil {
			t.Fatal(err)
		}
		subs = append(subs, sub)
	}
	var wg sync.WaitGroup
	counts := make([]int, subscribers)
	for i, sub := range subs {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				_, err := sub.ReadObject(ctx)
				if err == io.EOF {
					return
				}
				if err != nil {
					t.Error(err)
					return
				}
				counts[i]++
			}
		}()
	}
	var ms runtime.MemStats
	var heap []uint64
	payload := make([]byte, 4096)
	written := 0
	end := time.Now().Add(8 * time.Second)
	for time.Now().Before(end) {
		gw := mustGroup(t, tw)
		for range 25 {
			mustWrite(t, gw, payload)
			written++
			time.Sleep(time.Millisecond)
		}
		written++ // End of Group
		runtime.ReadMemStats(&ms)
		heap = append(heap, ms.HeapInuse)
	}
	written-- // the last group ends with End of Track
	tw.Close()
	written++
	wg.Wait()
	for i, c := range counts {
		if c != written {
			t.Errorf("subscriber %d got %d of %d objects", i, c, written)
		}
	}
	t.Logf("%d objects to %d subscribers; heap in use first %d KiB, last %d KiB", written, subscribers, heap[0]>>10, heap[len(heap)-1]>>10)
	if heap[len(heap)-1] > 4*heap[len(heap)/4]+16<<20 {
		t.Errorf("heap grew from %d to %d", heap[len(heap)/4], heap[len(heap)-1])
	}
}

type byteReader struct{ b []byte }

func newByteReader(b []byte) *byteReader { return &byteReader{b} }

func (r *byteReader) Read(p []byte) (int, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	n := copy(p, r.b)
	r.b = r.b[n:]
	return n, nil
}

func (r *byteReader) ReadByte() (byte, error) {
	if len(r.b) == 0 {
		return 0, io.EOF
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}
