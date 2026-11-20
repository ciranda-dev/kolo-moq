package interop

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
	"github.com/floatdrop/moq-go/pkg/moqt"
	"github.com/floatdrop/moq-go/pkg/moqt/message"
	"github.com/floatdrop/moq-go/pkg/moqt/session"
	"github.com/floatdrop/moq-go/pkg/moqt/wire"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

var transport = &kolotransport.Config{MaxIncomingStreams: 1000}

func testCtx(t *testing.T) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	return ctx
}

// connect returns both ends of a kolo-secure connection on loopback.
func connect(t *testing.T) (dialed, accepted *kolosecure.Conn) {
	t.Helper()
	ctx := testCtx(t)
	srvID, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	cliID, err := koloid.Generate()
	if err != nil {
		t.Fatal(err)
	}
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", srvID, &kolosecure.Config{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	type acceptResult struct {
		conn *kolosecure.Conn
		err  error
	}
	acc := make(chan acceptResult, 1)
	go func() {
		c, err := l.Accept(ctx)
		acc <- acceptResult{c, err}
	}()
	dialed, err = kolosecure.Dial(ctx, l.Addr().String(), cliID, srvID.PublicKey(), &kolosecure.Config{Transport: transport})
	if err != nil {
		t.Fatal(err)
	}
	a := <-acc
	if a.err != nil {
		t.Fatal(a.err)
	}
	accepted = a.conn
	t.Cleanup(func() {
		dialed.Close()
		accepted.Close()
	})
	return dialed, accepted
}

// koloServerPeerClient starts a kolo-moq server and a peer client session.
func koloServerPeerClient(t *testing.T, cfg *kolomoq.Config) (*kolomoq.Session, *session.Session) {
	t.Helper()
	dialed, accepted := connect(t)
	ctx := testCtx(t)
	res := make(chan error, 1)
	var ks *kolomoq.Session
	go func() {
		var err error
		ks, err = kolomoq.NewServer(ctx, accepted, cfg)
		res <- err
	}()
	ps, err := session.Client(ctx, NewConn(dialed), session.WithImplementation("interop-peer"))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-res; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ps.Close(moqt.SessionNoError, "")
		ks.Close()
	})
	return ks, ps
}

// peerServerKoloClient starts a peer server session and a kolo-moq client.
func peerServerKoloClient(t *testing.T) (*session.Session, *kolomoq.Session) {
	t.Helper()
	dialed, accepted := connect(t)
	ctx := testCtx(t)
	res := make(chan error, 1)
	var ps *session.Session
	go func() {
		var err error
		ps, err = session.Server(ctx, NewConn(accepted), session.WithImplementation("interop-peer"))
		res <- err
	}()
	ks, err := kolomoq.NewClient(ctx, dialed, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := <-res; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ks.Close()
		ps.Close(moqt.SessionNoError, "")
	})
	return ps, ks
}

type peerObject struct {
	group, subgroup, object, status uint64
	props, payload                  []byte
}

// readPeerObjects reads n objects from the peer's subgroup streams.
func readPeerObjects(t *testing.T, ctx context.Context, ps *session.Session, n int) []peerObject {
	t.Helper()
	var mu sync.Mutex
	var out []peerObject
	done := make(chan struct{})
	var once sync.Once
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	go func() {
		for {
			ds, err := ps.AcceptDataStream(ctx)
			if err != nil {
				return
			}
			s, ok := ds.(*session.IncomingSubgroupStream)
			if !ok {
				continue
			}
			go func() {
				for {
					o, err := s.ReadDecoded()
					if err != nil {
						return
					}
					mu.Lock()
					out = append(out, peerObject{o.GroupID, o.SubgroupID, o.ObjectID, o.ObjectStatus, o.Properties, o.Payload})
					if len(out) == n {
						once.Do(func() { close(done) })
					}
					mu.Unlock()
				}
			}()
		}
	}()
	select {
	case <-done:
	case <-ctx.Done():
		mu.Lock()
		defer mu.Unlock()
		t.Fatalf("got %d of %d objects", len(out), n)
	}
	mu.Lock()
	defer mu.Unlock()
	res := slices.Clone(out)
	slices.SortFunc(res, func(a, b peerObject) int {
		if a.group != b.group {
			return int(a.group) - int(b.group)
		}
		return int(a.object) - int(b.object)
	})
	return res
}

func TestKoloPublisherPeerSubscriber(t *testing.T) {
	origin, _ := kolomoq.NewOrigin(nil)
	ns := kolomoq.Namespace{"interop", "room"}
	tw, err := origin.CreateTrack(ns, "video", &kolomoq.TrackOptions{Priority: 7, Properties: []kolomoq.Property{{Type: 0x3803, Bytes: []byte("track")}}})
	if err != nil {
		t.Fatal(err)
	}
	ks, ps := koloServerPeerClient(t, &kolomoq.Config{Origin: origin})
	ctx := testCtx(t)
	if got := ks.PeerImplementation(); got != "interop-peer" {
		t.Errorf("peer implementation %q", got)
	}
	sub, err := ps.Subscribe(ctx, &message.Subscribe{
		Namespace:  wire.Namespace("interop", "room"),
		Name:       []byte("video"),
		Parameters: message.Parameters{message.NextObjectFilter()},
	})
	if err != nil {
		t.Fatal(err)
	}
	for g := range 3 {
		gw, _ := tw.NewGroup()
		for i := range 4 {
			props := []kolomoq.Property{{Type: 0x78, Value: uint64(g*10 + i)}, {Type: 0x79, Bytes: []byte("p")}}
			gw.WriteObject([]byte(fmt.Sprintf("g%d-o%d", g, i)), props...)
		}
	}
	got := readPeerObjects(t, ctx, ps, 14) // groups 0 and 1 also carry End of Group
	var normal int
	for _, o := range got {
		if o.status != 0 {
			if o.status != 3 || o.object != 4 {
				t.Fatalf("status object %+v", o)
			}
			continue
		}
		normal++
		if want := fmt.Sprintf("g%d-o%d", o.group, o.object); string(o.payload) != want {
			t.Fatalf("payload %q, want %q", o.payload, want)
		}
		wantProps := []byte{0x78, byte(o.group*10 + o.object), 0x01, 0x01, 'p'}
		if !bytes.Equal(o.props, wantProps) {
			t.Fatalf("properties %x, want %x", o.props, wantProps)
		}
	}
	if normal != 12 {
		t.Fatalf("%d normal objects", normal)
	}
	if !bytes.Contains(sub.OK.TrackProperties, []byte("track")) {
		t.Fatalf("track properties %x", sub.OK.TrackProperties)
	}

	// Ending the track sends PUBLISH_DONE TRACK_ENDED.
	tw.Close()
	var done *message.PublishDone
	sub.Broker().Serve(ctx, func(m message.Message) bool {
		if d, ok := m.(*message.PublishDone); ok {
			done = d
			return false
		}
		return true
	})
	if done == nil || done.StatusCode != moqt.PublishDoneTrackEnded || done.StreamCount != 3 {
		t.Fatalf("PUBLISH_DONE %+v", done)
	}
}

func TestPeerPublisherKoloSubscriber(t *testing.T) {
	ps, ks := peerServerKoloClient(t)
	ctx := testCtx(t)
	type result struct {
		sub *kolomoq.Subscription
		err error
	}
	res := make(chan result, 1)
	go func() {
		sub, err := ks.Subscribe(ctx, kolomoq.Namespace{"peer"}, "audio", nil)
		res <- result{sub, err}
	}()
	req, err := ps.AcceptRequest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	m, ok := req.First.(*message.Subscribe)
	if !ok || string(m.Name) != "audio" {
		t.Fatalf("request %T %+v", req.First, req.First)
	}
	pub, err := req.AcceptSubscribe(nil)
	if err != nil {
		t.Fatal(err)
	}
	r := <-res
	if r.err != nil {
		t.Fatal(r.err)
	}
	props := wireProps(t, []kolomoq.Property{{Type: 0x78, Value: 42}, {Type: 0x3801, Bytes: []byte("meta")}})
	for g := range 3 {
		sg, err := pub.OpenSubgroup(message.SubgroupHeader{Properties: true, SubgroupIDMode: message.SubgroupIDImplicitZero, GroupID: uint64(g)})
		if err != nil {
			t.Fatal(err)
		}
		for i := range 3 {
			if err := sg.WriteObjectAt(uint64(i), &message.SubgroupObject{Properties: props, Payload: []byte(fmt.Sprintf("g%d-o%d", g, i))}); err != nil {
				t.Fatal(err)
			}
		}
		if err := sg.Close(); err != nil {
			t.Fatal(err)
		}
	}
	var got []kolomoq.Object
	for range 9 {
		o, err := r.sub.ReadObject(ctx)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, o)
	}
	slices.SortFunc(got, func(a, b kolomoq.Object) int { return int(a.Group*10+a.ID) - int(b.Group*10+b.ID) })
	for i, o := range got {
		if want := fmt.Sprintf("g%d-o%d", i/3, i%3); string(o.Payload) != want || o.Group != uint64(i/3) {
			t.Fatalf("object %+v, want %s", o, want)
		}
		if len(o.Properties) != 2 || o.Properties[0].Value != 42 || string(o.Properties[1].Bytes) != "meta" {
			t.Fatalf("properties %+v", o.Properties)
		}
	}
	if err := pub.Done(moqt.PublishDoneTrackEnded, ""); err != nil {
		t.Fatal(err)
	}
	if _, err := r.sub.ReadObject(ctx); err != io.EOF {
		t.Fatalf("after PUBLISH_DONE: %v", err)
	}
}

func wireProps(t *testing.T, ps []kolomoq.Property) []byte {
	t.Helper()
	var b []byte
	var prev uint64
	for _, p := range ps {
		b = appendVarint(b, p.Type-prev)
		prev = p.Type
		if p.Type%2 == 0 {
			b = appendVarint(b, p.Value)
		} else {
			b = appendVarint(b, uint64(len(p.Bytes)))
			b = append(b, p.Bytes...)
		}
	}
	return b
}

// appendVarint encodes values below 2^14, enough for the tests.
func appendVarint(b []byte, v uint64) []byte {
	if v < 1<<7 {
		return append(b, byte(v))
	}
	return append(b, byte(0x80|v>>8), byte(v))
}

func TestKoloUnsubscribeFromPeer(t *testing.T) {
	ps, ks := peerServerKoloClient(t)
	ctx := testCtx(t)
	res := make(chan *kolomoq.Subscription, 1)
	go func() {
		sub, err := ks.Subscribe(ctx, kolomoq.Namespace{"peer"}, "t", nil)
		if err != nil {
			t.Error(err)
		}
		res <- sub
	}()
	req, err := ps.AcceptRequest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := req.AcceptSubscribe(nil)
	if err != nil {
		t.Fatal(err)
	}
	sub := <-res
	sub.Close()
	// The publisher sees the subscriber cancel the request (draft section 6.4.2.3).
	select {
	case <-pub.Context().Done():
	case <-ctx.Done():
		t.Fatal("publisher did not see the cancellation")
	}
}

func TestPeerUnsubscribeFromKolo(t *testing.T) {
	origin, _ := kolomoq.NewOrigin(nil)
	tw, _ := origin.CreateTrack(kolomoq.Namespace{"k"}, "t", nil)
	_, ps := koloServerPeerClient(t, &kolomoq.Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := ps.Subscribe(ctx, &message.Subscribe{Namespace: wire.Namespace("k"), Name: []byte("t")})
	if err != nil {
		t.Fatal(err)
	}
	gw, _ := tw.NewGroup()
	gw.WriteObject([]byte("x"))
	readPeerObjects(t, ctx, ps, 1)
	sub.Close()
	deadline := time.Now().Add(10 * time.Second)
	for {
		gw.WriteObject([]byte("y"))
		if tw.Subscribers() == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("kolo-moq kept the subscription")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestErrors(t *testing.T) {
	t.Run("peer subscribes to a missing track", func(t *testing.T) {
		_, ps := koloServerPeerClient(t, &kolomoq.Config{Origin: mustOrigin(t)})
		_, err := ps.Subscribe(testCtx(t), &message.Subscribe{Namespace: wire.Namespace("none"), Name: []byte("x")})
		var rej *session.RequestRejectedError
		if !errors.As(err, &rej) || rej.Code != moqt.RequestDoesNotExist {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("peer is unauthorized", func(t *testing.T) {
		origin := mustOrigin(t)
		origin.CreateTrack(kolomoq.Namespace{"secret"}, "x", nil)
		_, ps := koloServerPeerClient(t, &kolomoq.Config{Origin: origin, Authorize: deny})
		_, err := ps.Subscribe(testCtx(t), &message.Subscribe{Namespace: wire.Namespace("secret"), Name: []byte("x")})
		var rej *session.RequestRejectedError
		if !errors.As(err, &rej) || rej.Code != moqt.RequestUnauthorized {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("peer refuses a kolo subscription", func(t *testing.T) {
		ps, ks := peerServerKoloClient(t)
		ctx := testCtx(t)
		errc := make(chan error, 1)
		go func() {
			_, err := ks.Subscribe(ctx, kolomoq.Namespace{"p"}, "t", nil)
			errc <- err
		}()
		req, err := ps.AcceptRequest(ctx)
		if err != nil {
			t.Fatal(err)
		}
		req.RejectError(moqt.RequestDoesNotExist, "no such track")
		var re *kolomoq.RequestError
		if err := <-errc; !errors.As(err, &re) || re.Code != kolomoq.ReqDoesNotExist || re.Reason != "no such track" {
			t.Fatalf("err %v", err)
		}
	})
	t.Run("peer asks for an unsupported request", func(t *testing.T) {
		_, ps := koloServerPeerClient(t, nil)
		_, err := ps.Publish(testCtx(t), &message.Publish{Namespace: wire.Namespace("p"), Name: []byte("t")})
		var rej *session.RequestRejectedError
		if !errors.As(err, &rej) || rej.Code != moqt.RequestNotSupported {
			t.Fatalf("err %v", err)
		}
	})
}

func deny(ed25519.PublicKey, kolomoq.RequestKind, kolomoq.Namespace, string) error {
	return errors.New("denied")
}

func mustOrigin(t *testing.T) *kolomoq.Origin {
	o, err := kolomoq.NewOrigin(nil)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestPeerFetchFromKolo(t *testing.T) {
	origin := mustOrigin(t)
	tw, _ := origin.CreateTrack(kolomoq.Namespace{"f"}, "t", nil)
	for g := range 3 {
		gw, _ := tw.NewGroup()
		for i := range 2 {
			gw.WriteObject([]byte(fmt.Sprintf("g%d-o%d", g, i)))
		}
	}
	_, ps := koloServerPeerClient(t, &kolomoq.Config{Origin: origin})
	ctx := testCtx(t)
	f, err := ps.Fetch(ctx, &message.Fetch{
		Namespace:  wire.Namespace("f"),
		Name:       []byte("t"),
		Parameters: message.Parameters{message.AbsoluteRangeFilter(message.Location{Group: 1, Object: 0}, 1)},
	})
	if err != nil {
		t.Fatal(err)
	}
	_ = f
	var got []string
	for {
		ds, err := ps.AcceptDataStream(ctx)
		if err != nil {
			t.Fatal(err)
		}
		fs, ok := ds.(*session.IncomingFetchStream)
		if !ok {
			continue
		}
		for {
			o, err := fs.ReadDecoded()
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if !o.IsEndOfRange() {
				got = append(got, string(o.Payload))
			}
		}
		break
	}
	if want := []string{"g1-o0", "g1-o1", "g2-o0", "g2-o1"}; !slices.Equal(got, want) {
		t.Fatalf("fetched %v", got)
	}
}

func TestPeerNamespaceAtKolo(t *testing.T) {
	ks, ps := koloServerPeerClient(t, nil)
	ctx := testCtx(t)
	ann, err := ps.PublishNamespace(ctx, &message.PublishNamespace{Namespace: wire.Namespace("rooms", "42")})
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(ks.PeerNamespaces()) == 1 })
	if got := ks.PeerNamespaces()[0]; !slices.Equal(got, kolomoq.Namespace{"rooms", "42"}) {
		t.Fatalf("namespace %v", got)
	}
	ann.Close()
	waitFor(t, func() bool { return len(ks.PeerNamespaces()) == 0 })
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("timed out")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPeerJoinsCurrentGroupAtKolo(t *testing.T) {
	origin := mustOrigin(t)
	tw, _ := origin.CreateTrack(kolomoq.Namespace{"j"}, "t", nil)
	gw, _ := tw.NewGroup()
	gw.WriteObject([]byte("g0-o0"))
	gw, _ = tw.NewGroup()
	for i := range 3 {
		gw.WriteObject([]byte(fmt.Sprintf("g1-o%d", i)))
	}
	_, ps := koloServerPeerClient(t, &kolomoq.Config{Origin: origin})
	ctx := testCtx(t)
	_, err := ps.Subscribe(ctx, &message.Subscribe{
		Namespace: wire.Namespace("j"),
		Name:      []byte("t"),
		Parameters: message.Parameters{
			message.NextObjectFilter(),
			message.FillParametersParam(message.Parameters{message.RelativeStartFilter(1)}),
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	ds, err := ps.AcceptDataStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	fs, ok := ds.(*session.IncomingFetchStream)
	if !ok {
		t.Fatalf("stream %T", ds)
	}
	var got []string
	for {
		o, err := fs.ReadDecoded()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, string(o.Payload))
	}
	if want := []string{"g1-o0", "g1-o1", "g1-o2"}; !slices.Equal(got, want) {
		t.Fatalf("fill %v", got)
	}
}

func TestKoloFetchFromPeer(t *testing.T) {
	ps, ks := peerServerKoloClient(t)
	ctx := testCtx(t)
	type result struct {
		objs []kolomoq.Object
		end  kolomoq.Location
		err  error
	}
	res := make(chan result, 1)
	go func() {
		f, err := ks.Fetch(ctx, kolomoq.Namespace{"p"}, "t", &kolomoq.FetchOptions{Start: kolomoq.Location{Group: 2}, End: &kolomoq.Location{Group: 3, Object: 1}})
		if err != nil {
			res <- result{err: err}
			return
		}
		var objs []kolomoq.Object
		for {
			o, err := f.ReadObject(ctx)
			if err == io.EOF {
				res <- result{objs: objs, end: f.End()}
				return
			}
			if err != nil {
				res <- result{err: err}
				return
			}
			objs = append(objs, o)
		}
	}()
	req, err := ps.AcceptRequest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := req.AcceptFetch(&message.FetchOK{EndLocation: message.Location{Group: 3, Object: 1}})
	if err != nil {
		t.Fatal(err)
	}
	fs, err := resp.OpenFetchStream()
	if err != nil {
		t.Fatal(err)
	}
	props := wireProps(t, []kolomoq.Property{{Type: 0x78, Value: 9}})
	for _, o := range []*message.FetchObject{
		{SerializationFlags: 0x1C | 0x20, GroupIDDelta: 2, ObjectIDDelta: 0, PublisherPriority: 5, Properties: props, ObjectPayload: []byte("a")},
		{SerializationFlags: 0x00, ObjectPayload: []byte("b")},
		{SerializationFlags: 0x0C, GroupIDDelta: 0, ObjectIDDelta: 0, ObjectPayload: []byte("c")},
		{SerializationFlags: 0x00, ObjectPayload: []byte("d")},
	} {
		if err := fs.WriteObject(o); err != nil {
			t.Fatal(err)
		}
	}
	fs.Close()
	r := <-res
	if r.err != nil {
		t.Fatal(r.err)
	}
	want := []kolomoq.Location{{Group: 2, Object: 0}, {Group: 2, Object: 1}, {Group: 3, Object: 0}, {Group: 3, Object: 1}}
	if len(r.objs) != len(want) || r.end != (kolomoq.Location{Group: 3, Object: 1}) {
		t.Fatalf("got %+v end %v", r.objs, r.end)
	}
	for i, o := range r.objs {
		if (kolomoq.Location{Group: o.Group, Object: o.ID}) != want[i] || o.Priority != 5 || string(o.Payload) != "abcd"[i:i+1] {
			t.Fatalf("object %d: %+v", i, o)
		}
	}
	if len(r.objs[0].Properties) != 1 || r.objs[0].Properties[0].Value != 9 {
		t.Fatalf("properties %+v", r.objs[0].Properties)
	}
}

func TestGoAway(t *testing.T) {
	t.Run("kolo server drains a peer client", func(t *testing.T) {
		origin := mustOrigin(t)
		origin.CreateTrack(kolomoq.Namespace{"g"}, "t", nil)
		ks, ps := koloServerPeerClient(t, &kolomoq.Config{Origin: origin})
		ctx := testCtx(t)
		sub, err := ps.Subscribe(ctx, &message.Subscribe{Namespace: wire.Namespace("g"), Name: []byte("t")})
		if err != nil {
			t.Fatal(err)
		}
		done := make(chan error, 1)
		go func() { done <- ks.GoAway(ctx, 10*time.Second) }()
		select {
		case <-ps.GoawayReceived():
		case <-ctx.Done():
			t.Fatal("peer saw no GOAWAY")
		}
		sub.Close()
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	})
	t.Run("peer server tells a kolo client to go", func(t *testing.T) {
		ps, ks := peerServerKoloClient(t)
		ctx := testCtx(t)
		if err := ps.SendGoaway(time.Second, ""); err != nil {
			t.Fatal(err)
		}
		select {
		case <-ks.GoingAway():
		case <-ctx.Done():
			t.Fatal("no GOAWAY")
		}
		if _, err := ks.Subscribe(ctx, kolomoq.Namespace{"x"}, "t", nil); !errors.Is(err, kolomoq.ErrGoingAway) {
			t.Fatalf("subscribe after GOAWAY: %v", err)
		}
	})
}

// relayPeer connects a peer client session to a kolo-moq relay.
func relayPeer(t *testing.T, r *kolomoq.Relay) *session.Session {
	t.Helper()
	dialed, accepted := connect(t)
	ctx := testCtx(t)
	res := make(chan error, 1)
	var rs *kolomoq.Session
	go func() {
		var err error
		rs, err = r.NewServer(ctx, accepted)
		res <- err
	}()
	ps, err := session.Client(ctx, NewConn(dialed))
	if err != nil {
		t.Fatal(err)
	}
	if err := <-res; err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ps.Close(moqt.SessionNoError, "")
		rs.Close()
	})
	return ps
}

func TestKoloRelayBetweenPeers(t *testing.T) {
	r, err := kolomoq.NewRelay(nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testCtx(t)
	pub := relayPeer(t, r)
	if _, err := pub.PublishNamespace(ctx, &message.PublishNamespace{Namespace: wire.Namespace("relay")}); err != nil {
		t.Fatal(err)
	}
	published := make(chan error, 1)
	start := make(chan struct{})
	go func() {
		req, err := pub.AcceptRequest(ctx)
		if err != nil {
			published <- err
			return
		}
		p, err := req.AcceptSubscribe(nil)
		if err != nil {
			published <- err
			return
		}
		<-start
		for g := range 2 {
			sg, err := p.OpenSubgroup(message.SubgroupHeader{SubgroupIDMode: message.SubgroupIDImplicitZero, GroupID: uint64(g)})
			if err != nil {
				published <- err
				return
			}
			for i := range 3 {
				sg.WriteObjectAt(uint64(i), &message.SubgroupObject{Payload: []byte(fmt.Sprintf("g%d-o%d", g, i))})
			}
			sg.Close()
		}
		published <- p.Done(moqt.PublishDoneTrackEnded, "")
	}()
	var subs []*session.Session
	for range 2 {
		s := relayPeer(t, r)
		if _, err := s.Subscribe(ctx, &message.Subscribe{Namespace: wire.Namespace("relay"), Name: []byte("t"), Parameters: message.Parameters{message.NextObjectFilter()}}); err != nil {
			t.Fatal(err)
		}
		subs = append(subs, s)
	}
	close(start)
	for _, s := range subs {
		got := readPeerObjects(t, ctx, s, 6)
		for i, o := range got {
			if want := fmt.Sprintf("g%d-o%d", i/3, i%3); string(o.payload) != want {
				t.Fatalf("object %d: %q, want %q", i, o.payload, want)
			}
		}
	}
	if err := <-published; err != nil {
		t.Fatal(err)
	}
}
