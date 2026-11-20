package kolomoq

import (
	"context"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// A peer that reads nothing leaves the session's write in flow control: Stats says how long the object has waited and
// that bytes were handed to the transport; when the peer reads, the queue empties and the delay returns to zero.
func TestStatsShowTheQueueOfASlowPeer(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"stats"}
	tw := mustTrack(t, origin, ns, "big", nil)
	r, sess := connected(t, &Config{Origin: origin})
	_, br := r.request(subscribeMsg(r.id(), ns, "big", nil))
	r.expect(br, wire.MsgSubscribeOK)
	if st := sess.Stats(); st.QueueDelay != 0 || st.QueuedBytes != 0 || st.SentBytes != 0 {
		t.Fatalf("idle: %+v", st)
	}
	if _, err := mustGroup(t, tw).WriteObject(make([]byte, 4<<20)); err != nil {
		t.Fatal(err)
	}
	stalled, err := r.conn.AcceptUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(300 * time.Millisecond)
	st := sess.Stats()
	if st.QueueDelay < 250*time.Millisecond || st.SentBytes == 0 || st.SentBytes >= 4<<20 {
		t.Fatalf("stalled: %+v", st)
	}
	go func() {
		buf := make([]byte, 64<<10)
		for {
			if _, err := stalled.Read(buf); err != nil {
				return
			}
		}
	}()
	eventually(t, "the queue to empty", func() bool {
		st := sess.Stats()
		return st.QueueDelay == 0 && st.QueuedBytes == 0 && st.SentBytes >= 4<<20
	})
}

// The session reports the transport's numbers of its kolo-secure connection on both ends.
func TestStatsCarryTheTransportNumbers(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"stats"}
	tw := mustTrack(t, origin, ns, "obj", nil)
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "obj", nil)
	if err != nil {
		t.Fatal(err)
	}
	const size = 512 << 10
	if _, err := mustGroup(t, tw).WriteObject(make([]byte, size)); err != nil {
		t.Fatal(err)
	}
	if _, err := sub.ReadObject(ctx); err != nil {
		t.Fatal(err)
	}
	for name, s := range map[string]*Session{"server": p.server, "client": p.client} {
		tr := s.Stats().Transport
		t.Logf("%s: %+v", name, tr)
		if tr.CongestionController != "reno" || tr.CongestionWindow == 0 || tr.SmoothedRTT <= 0 || tr.MinRTT <= 0 {
			t.Errorf("%s: %+v", name, tr)
		}
		if tr.MaxDatagramSize == 0 || tr.PacketsSent == 0 || tr.BytesSent == 0 {
			t.Errorf("%s: %+v", name, tr)
		}
	}
	if tr := p.server.Stats().Transport; tr.BytesSent < size {
		t.Errorf("the publisher's connection sent %d bytes for a %d byte object", tr.BytesSent, size)
	}
	if got, want := p.server.Stats().Transport.CongestionController, p.serverConn.Stats().CongestionController; got != want {
		t.Errorf("session says %q, connection %q", got, want)
	}
	p.server.Close()
	if tr := p.server.Stats().Transport; tr != (kolotransport.ConnStats{}) {
		t.Errorf("after Close: %+v", tr)
	}
}

// noStats hides the Stats method of the connection it wraps, as a Conn from another package may.
type noStats struct{ Conn }

func TestStatsTransportIsZeroWithoutAStatsMethod(t *testing.T) {
	checkLeaks(t)
	cc, sc, _ := connect(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	srv := make(chan *Session, 1)
	go func() {
		s, err := NewServer(ctx, noStats{sc}, nil)
		if err != nil {
			t.Error(err)
		}
		srv <- s
	}()
	client, err := NewClient(ctx, cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	server := <-srv
	if server == nil {
		t.FailNow()
	}
	t.Cleanup(func() { client.Close(); server.Close() })
	if tr := server.Stats().Transport; tr != (kolotransport.ConnStats{}) {
		t.Fatalf("a Conn without Stats gave %+v", tr)
	}
	if tr := client.Stats().Transport; tr.CongestionWindow == 0 {
		t.Fatalf("the client's kolo-secure Conn gave %+v", tr)
	}
}
