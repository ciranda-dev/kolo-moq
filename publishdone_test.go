package kolomoq

import (
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// doneSub subscribes through a raw publisher with the given delivery
// timeouts and returns the subscription and the request stream to end it on.
func doneSub(t *testing.T, opts *SubscribeOptions) (*rawPeer, *Subscription, func(count uint64)) {
	return doneSubTimeout(t, opts, 5*time.Second)
}

func doneSubTimeout(t *testing.T, opts *SubscribeOptions, requestTimeout time.Duration) (*rawPeer, *Subscription, func(count uint64)) {
	t.Helper()
	rp, s := serving(t, &Config{RequestTimeout: requestTimeout})
	res := make(chan subResult, 1)
	go func() {
		sub, err := s.Subscribe(testCtx(t), Namespace{"done"}, "t", opts)
		res <- subResult{sub, err}
	}()
	req := answerSubscribe(t, rp, 1)
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	return rp, sr.sub, func(count uint64) {
		// FIN after PUBLISH_DONE, as a kolo-moq publisher sends it.
		write(t, req, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: count})
		req.Close()
	}
}

func openStreams(sub *Subscription) int {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return len(sub.open)
}

// resetBeforeHeader opens a data stream and resets it before any byte.
func resetBeforeHeader(t *testing.T, rp *rawPeer) {
	t.Helper()
	ds, err := rp.conn.OpenUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	ds.CancelWrite(resetDeliveryTimeout)
}

func readPayload(t *testing.T, sub *Subscription, want string) {
	t.Helper()
	o, err := sub.ReadObject(readCtx(t, 5*time.Second))
	if err != nil || string(o.Payload) != want {
		t.Fatalf("object %q, %v; want %q", o.Payload, err, want)
	}
}

// endsWithin reads the end of sub and checks it came between lo and hi after since.
func endsWithin(t *testing.T, sub *Subscription, since time.Time, lo, hi time.Duration) {
	t.Helper()
	_, err := sub.ReadObject(readCtx(t, 10*time.Second))
	d := time.Since(since)
	if !errors.Is(err, io.EOF) {
		t.Fatalf("end: %v", err)
	}
	if d < lo || d > hi {
		t.Fatalf("ended %v after PUBLISH_DONE, want between %v and %v", d, lo, hi)
	}
}

// A stream counted in PUBLISH_DONE but reset before its header never
// arrives. Once no received stream is open, the subscription waits for it
// the larger delivery timeout (draft-22 section 9.9), not RequestTimeout.
func TestPublishDoneStreamResetBeforeHeader(t *testing.T) {
	rp, sub, done := doneSub(t, &SubscribeOptions{ObjectDeliveryTimeout: 200 * time.Millisecond, SubgroupDeliveryTimeout: time.Second})
	w, fin := subgroupStream(t, rp, 1, 0)
	w(&wire.Object{Payload: []byte("a")})
	fin()
	resetBeforeHeader(t, rp)
	readPayload(t, sub, "a")
	eventually(t, "the stream to close", func() bool { return openStreams(sub) == 0 })
	began := time.Now()
	done(2)
	endsWithin(t, sub, began, 900*time.Millisecond, 3*time.Second)
}

// The same when the last received stream closes after PUBLISH_DONE.
func TestPublishDoneLastStreamClosesLater(t *testing.T) {
	rp, sub, done := doneSub(t, &SubscribeOptions{ObjectDeliveryTimeout: 300 * time.Millisecond})
	w, fin := subgroupStream(t, rp, 1, 0)
	w(&wire.Object{Payload: []byte("a")})
	resetBeforeHeader(t, rp)
	readPayload(t, sub, "a")
	done(2)
	time.Sleep(100 * time.Millisecond)
	closed := time.Now()
	fin()
	endsWithin(t, sub, closed, 200*time.Millisecond, 3*time.Second)
}

// A stream that arrives within the wait is still delivered, and the count
// then ends the subscription at once.
func TestPublishDoneLateStreamWithinWait(t *testing.T) {
	for _, tc := range []struct {
		name  string
		opts  *SubscribeOptions
		delay time.Duration
	}{
		{"delivery timeout", &SubscribeOptions{ObjectDeliveryTimeout: time.Second}, 100 * time.Millisecond},
		{"no delivery timeout", nil, 600 * time.Millisecond},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rp, sub, done := doneSub(t, tc.opts)
			w, fin := subgroupStream(t, rp, 1, 0)
			w(&wire.Object{Payload: []byte("a")})
			fin()
			readPayload(t, sub, "a")
			eventually(t, "the stream to close", func() bool { return openStreams(sub) == 0 })
			done(2)
			time.Sleep(tc.delay)
			w, fin = subgroupStream(t, rp, 1, 1)
			w(&wire.Object{Payload: []byte("b")})
			fin()
			readPayload(t, sub, "b")
			endsWithin(t, sub, time.Now(), 0, time.Second)
			// The response reader ends with the subscription, not with the session.
			eventually(t, "the response reader to end", func() bool { return !inResponses(false) })
		})
	}
}

// An open stream keeps the longer wait: its objects still arrive after the
// delivery timeout.
func TestPublishDoneOpenStreamKeepsWait(t *testing.T) {
	rp, sub, done := doneSub(t, &SubscribeOptions{ObjectDeliveryTimeout: 200 * time.Millisecond})
	w, fin := subgroupStream(t, rp, 1, 0)
	w(&wire.Object{Payload: []byte("a")})
	readPayload(t, sub, "a")
	done(1)
	time.Sleep(600 * time.Millisecond)
	w(&wire.Object{ID: 1, Payload: []byte("b")})
	fin()
	readPayload(t, sub, "b")
	endsWithin(t, sub, time.Now(), 0, time.Second)
}

// Late streams never extend the wait past the one set at PUBLISH_DONE, so
// a publisher that trickles streams cannot keep the subscription alive.
func TestPublishDoneWaitBounded(t *testing.T) {
	rp, sub, done := doneSubTimeout(t, &SubscribeOptions{ObjectDeliveryTimeout: 600 * time.Millisecond}, time.Second)
	began := time.Now()
	done(100)
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		for g := uint64(0); g < 20; g++ {
			select {
			case <-stop:
				return
			case <-time.After(150 * time.Millisecond):
			}
			ds, err := rp.conn.OpenUniStream(testCtx(t))
			if err != nil {
				return
			}
			var sw wire.SubgroupWriter
			hdr := (&wire.SubgroupHeader{Flags: wire.SubgroupTypeBit | wire.SubgroupDefaultPrio | wire.SubgroupProperties, TrackAlias: 1, Group: g}).Append(nil)
			ds.Write(appendObject(&sw, hdr, &wire.Object{Payload: []byte("x")}))
			ds.Close()
		}
	}()
	for {
		if _, err := sub.ReadObject(readCtx(t, 10*time.Second)); err != nil {
			if !errors.Is(err, io.EOF) {
				t.Fatalf("end: %v", err)
			}
			break
		}
	}
	if d := time.Since(began); d > 2*time.Second {
		t.Fatalf("ended %v after PUBLISH_DONE, past RequestTimeout", d)
	}
}

// inResponses reports whether a goroutine runs readResponses, and reading whether one of them still
// reads its request stream.
func inResponses(reading bool) bool {
	buf := make([]byte, 1<<20)
	for _, g := range strings.Split(string(buf[:runtime.Stack(buf, true)]), "\n\n") {
		if strings.Contains(g, "(*Subscription).readResponses") && (!reading || strings.Contains(g, "(*reqStream).read")) {
			return true
		}
	}
	return false
}

// A subscription that has PUBLISH_DONE, sent with FIN as a kolo-moq publisher does, and still
// misses a stream ends with the session's error when its session ends, not after its wait.
func TestPublishDoneSessionEndEndsWait(t *testing.T) {
	rp, s := serving(t, &Config{RequestTimeout: 5 * time.Second})
	res := make(chan subResult, 1)
	go func() {
		sub, err := s.Subscribe(testCtx(t), Namespace{"done"}, "t", nil)
		res <- subResult{sub, err}
	}()
	req := answerSubscribe(t, rp, 1)
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	sub := sr.sub
	w, fin := subgroupStream(t, rp, 1, 0)
	w(&wire.Object{Payload: []byte("a")})
	fin()
	readPayload(t, sub, "a")
	eventually(t, "the stream to close", func() bool { return openStreams(sub) == 0 })
	write(t, req, wire.MsgPublishDone, &wire.PublishDone{Status: uint64(DoneTrackEnded), StreamCount: 2})
	req.Close()
	// The request stream's end has been read: the subscription now only waits for the missing stream.
	eventually(t, "the end of the request stream", func() bool { return !inResponses(true) })
	s.Close()
	if _, err := sub.ReadObject(readCtx(t, 10*time.Second)); !errors.Is(err, ErrClosed) {
		t.Fatalf("end after Session.Close: %v, want ErrClosed", err)
	}
}
