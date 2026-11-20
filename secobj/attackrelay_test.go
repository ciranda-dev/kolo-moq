package secobj

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

var roomNS = kolomoq.Namespace{"room"}

// roomTransport lets every participant on 127.0.0.1 reach the relay.
var roomTransport = &kolotransport.Config{MaxIncomingStreams: 1000, MaxConnsPerIP: 100}

// room is a real kolo-moq Relay on 127.0.0.1 with RoomPolicy for each of its rooms.
type room struct {
	t    testing.TB
	r    *kolomoq.Relay
	id   *node
	addr string

	mu       sync.Mutex
	members  map[string]bool
	sessions []*kolomoq.Session
}

func newRoom(t testing.TB, rooms ...kolomoq.Namespace) *room {
	t.Helper()
	if len(rooms) == 0 {
		rooms = []kolomoq.Namespace{roomNS}
	}
	rm := &room{t: t, id: newNode(t), members: map[string]bool{}}
	auth := func(peer ed25519.PublicKey, kind kolomoq.RequestKind, ns kolomoq.Namespace, track string) error {
		for _, n := range rooms {
			if ns.HasPrefix(n) {
				return kolomoq.RoomPolicy{Room: n, Member: rm.member}.Authorize(peer, kind, ns, track)
			}
		}
		return errors.New("outside every room")
	}
	r, err := kolomoq.NewRelay(&kolomoq.RelayConfig{
		Session:     kolomoq.Config{Authorize: auth, MaxBufferedGroups: 1000},
		CacheGroups: 16,
	})
	if err != nil {
		t.Fatal(err)
	}
	rm.r = r
	ctx, cancel := context.WithCancel(context.Background())
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", rm.id.id, &kolosecure.Config{Transport: roomTransport})
	if err != nil {
		t.Fatal(err)
	}
	rm.addr = l.Addr().String()
	var wg sync.WaitGroup
	wg.Go(func() {
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			wg.Go(func() {
				s, err := r.NewServer(ctx, c)
				if err != nil {
					return
				}
				rm.mu.Lock()
				rm.sessions = append(rm.sessions, s)
				rm.mu.Unlock()
			})
		}
	})
	t.Cleanup(func() {
		cancel()
		l.Close()
		wg.Wait()
		rm.mu.Lock()
		defer rm.mu.Unlock()
		for _, s := range rm.sessions {
			s.Close()
		}
	})
	return rm
}

func (rm *room) member(peer ed25519.PublicKey) bool {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	return rm.members[string(peer)]
}

func (rm *room) admit(ns ...*node) {
	rm.mu.Lock()
	defer rm.mu.Unlock()
	for _, n := range ns {
		rm.members[string(n.pub)] = true
	}
}

// sessionOf returns the relay's session with peer.
func (rm *room) sessionOf(peer ed25519.PublicKey) *kolomoq.Session {
	rm.t.Helper()
	var s *kolomoq.Session
	eventually(rm.t, "relay session", func() bool {
		rm.mu.Lock()
		defer rm.mu.Unlock()
		for _, x := range rm.sessions {
			if x.RemotePublicKey().Equal(peer) {
				s = x
				return true
			}
		}
		return false
	})
	return s
}

// join connects p to the relay, through a tap when tp is not nil, with p's origin served.
func (rm *room) join(p *node, cfg *kolomoq.Config, tp *tap) *kolomoq.Session {
	t := rm.t
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	addr := rm.addr
	if tp != nil {
		addr = tp.listen(rm, p)
	}
	c, err := kolosecure.Dial(ctx, addr, p.id, rm.id.pub, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	if tp != nil {
		tp.wait()
	}
	var c2 kolomoq.Config
	if cfg != nil {
		c2 = *cfg
	}
	c2.Origin = p.origin
	s, err := kolomoq.NewClient(ctx, c, &c2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

type trackRef struct {
	ns   string
	name string
}

func refOf(ns kolomoq.Namespace, name string) trackRef { return trackRef{nsKey(ns), name} }

// seen is a data object the tap saw; down means from the relay to the participant.
type seen struct {
	down  bool
	alias uint64
	fetch bool
	obj   wire.Object
	at    time.Time
}

type dirID struct {
	down bool
	id   uint64
}

// tap stands between one participant and the real Relay, as the relay's operator can: it holds
// the relay's identity toward the participant and the participant's toward the Relay, copies
// every stream and records every byte the Relay sends or receives for that participant. With a
// hook it re-encodes the objects the Relay sends; inject adds objects of its own.
type tap struct {
	t     testing.TB
	ctx   context.Context
	outer *kolosecure.Conn
	inner *kolosecure.Conn
	ready chan struct{}
	wg    sync.WaitGroup

	// hook, if set before join, replaces each object the Relay sends by what it returns.
	hook func(tr trackRef, o *wire.Object) []*wire.Object
	// trackProps, if set before join, are added to every SUBSCRIBE_OK the Relay sends.
	trackProps []wire.KV

	mu       sync.Mutex
	rec      []byte
	objects  []seen
	requests []*wire.Request
	reqDir   map[dirID]*wire.Request
	aliases  map[dirID]trackRef
	prios    map[dirID]uint8
	gate     chan struct{}
	nextReq  uint64
	injected atomic.Int64
}

func newTap(t testing.TB) *tap {
	return &tap{t: t, ready: make(chan struct{}), reqDir: map[dirID]*wire.Request{}, aliases: map[dirID]trackRef{}, prios: map[dirID]uint8{}, nextReq: 2*50000 + 1}
}

// listen accepts p's connection with the relay's identity and dials the Relay as p.
func (tp *tap) listen(rm *room, p *node) string {
	t := tp.t
	ctx, cancel := context.WithCancel(context.Background())
	tp.ctx = ctx
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", rm.id.id, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	tp.wg.Go(func() {
		defer close(tp.ready)
		out, err := l.Accept(ctx)
		if err != nil {
			return
		}
		in, err := kolosecure.Dial(ctx, rm.addr, p.id, rm.id.pub, &kolosecure.Config{Transport: testTransport})
		if err != nil {
			out.Close()
			return
		}
		tp.outer, tp.inner = out, in
		tp.wg.Go(func() { tp.acceptBidi(out, in, false) })
		tp.wg.Go(func() { tp.acceptBidi(in, out, true) })
		tp.wg.Go(func() { tp.acceptUni(out, in, false) })
		tp.wg.Go(func() { tp.acceptUni(in, out, true) })
	})
	t.Cleanup(func() {
		cancel()
		tp.release()
		l.Close()
		if tp.outer != nil {
			tp.outer.Close()
			tp.inner.Close()
		}
		tp.wg.Wait()
	})
	return l.Addr().String()
}

func (tp *tap) wait() {
	<-tp.ready
	if tp.outer == nil {
		tp.t.Fatal("tap did not connect")
	}
}

// acceptBidi forwards the request streams opened on from; down means from is the Relay.
func (tp *tap) acceptBidi(from, to *kolosecure.Conn, down bool) {
	for {
		src, err := from.AcceptStream(tp.ctx)
		if err != nil {
			return
		}
		tp.wg.Go(func() {
			dst, err := to.OpenStream(tp.ctx)
			if err != nil {
				src.CancelRead(0)
				src.CancelWrite(0)
				return
			}
			reqc := make(chan *wire.Request, 1)
			tp.wg.Go(func() { tp.copyMsg(src, dst, down, reqc, true) })
			tp.copyMsg(dst, src, !down, reqc, false)
		})
	}
}

type sendSide interface {
	io.Writer
	Close() error
	CancelWrite(code uint64) error
}

type recvSide interface {
	io.Reader
	CancelRead(code uint64) error
}

// copyMsg forwards one direction of a request stream, parsing its first message.
func (tp *tap) copyMsg(src recvSide, dst sendSide, down bool, reqc chan *wire.Request, request bool) {
	br := bufio.NewReader(&recReader{tp, src})
	typ, body, err := wire.ReadMessage(br, wire.MaxMessageLen)
	if err != nil {
		finish(src, dst, err)
		return
	}
	if request {
		m, perr := wire.ParseRequest(typ, body)
		if perr == nil {
			tp.mu.Lock()
			tp.requests = append(tp.requests, m)
			tp.reqDir[dirID{down, m.RequestID}] = m
			tp.mu.Unlock()
		}
		reqc <- m
	} else if typ == wire.MsgSubscribeOK {
		var req *wire.Request
		select {
		case req = <-reqc:
		case <-tp.ctx.Done():
		}
		if ok, perr := wire.ParseSubscribeOK(body); perr == nil && req != nil {
			tp.mu.Lock()
			for _, kv := range ok.Properties {
				if kv.Type == 0x0E {
					tp.prios[dirID{down, ok.TrackAlias}] = uint8(kv.Value)
				}
			}
			tp.aliases[dirID{down, ok.TrackAlias}] = refOf(req.Namespace, req.Name)
			props := tp.trackProps
			tp.mu.Unlock()
			if down && props != nil {
				ok.Properties = append(ok.Properties, props...)
				body = ok.Append(nil)
			}
		}
	}
	m, err := wire.AppendMessage(nil, typ, body)
	if err == nil {
		_, err = dst.Write(m)
	}
	if err != nil {
		finish(src, dst, err)
		return
	}
	finish(src, dst, pipe(dst, br))
}

func pipe(dst io.Writer, src io.Reader) error {
	_, err := io.Copy(dst, src)
	return err
}

// finish ends dst as src ended: FIN on a clean end, a reset with the same code otherwise.
func finish(src recvSide, dst sendSide, err error) {
	if err == nil || err == io.EOF {
		dst.Close()
		return
	}
	var te *kolotransport.Error
	code := uint64(0)
	if errors.As(err, &te) {
		code = te.Code
	}
	dst.CancelWrite(code)
	src.CancelRead(code)
}

// acceptUni forwards the unidirectional streams opened on from.
func (tp *tap) acceptUni(from, to *kolosecure.Conn, down bool) {
	for {
		src, err := from.AcceptUniStream(tp.ctx)
		if err != nil {
			return
		}
		tp.wg.Go(func() { tp.uni(src, to, down) })
	}
}

func (tp *tap) uni(src *kolotransport.ReceiveStream, to *kolosecure.Conn, down bool) {
	var r io.Reader = &recReader{tp, src}
	if down {
		r = &gateReader{tp, r}
	}
	br := bufio.NewReader(r)
	typ, err := wire.ReadVarint(br)
	if err != nil {
		src.CancelRead(0)
		return
	}
	tp.mu.Lock()
	hook := tp.hook
	tp.mu.Unlock()
	if down && hook != nil && wire.IsSubgroupType(typ) {
		tp.rewrite(src, br, typ, hook)
		return
	}
	dst, err := to.OpenUniStream(tp.ctx)
	if err != nil {
		src.CancelRead(0)
		return
	}
	if _, err := dst.Write(wire.AppendVarint(nil, typ)); err != nil {
		finish(src, dst, err)
		return
	}
	pr := bufio.NewReader(io.TeeReader(br, dst))
	switch {
	case wire.IsSubgroupType(typ):
		h, err := wire.ReadSubgroupHeader(pr, typ)
		if err != nil {
			finish(src, dst, err)
			return
		}
		tp.defaultPriority(down, h)
		sr := &wire.SubgroupReader{R: pr, Header: h, MaxPayload: 1 << 30}
		for {
			o, err := sr.Next()
			if err != nil {
				if err != io.EOF {
					err = pipe(io.Discard, pr)
				}
				finish(src, dst, err)
				return
			}
			tp.saw(seen{down: down, alias: h.TrackAlias, obj: *o})
		}
	case typ == wire.StreamTypeFetch:
		id, err := wire.ReadVarint(pr)
		if err != nil {
			finish(src, dst, err)
			return
		}
		fr := &wire.FetchReader{R: pr, MaxPayload: 1 << 30}
		for {
			fo, err := fr.Next()
			if err != nil {
				if err != io.EOF {
					err = pipe(io.Discard, pr)
				}
				finish(src, dst, err)
				return
			}
			if fo.EndOfRange == 0 {
				tp.saw(seen{down: down, alias: id, fetch: true, obj: fo.Object})
			}
		}
	default:
		finish(src, dst, pipe(io.Discard, pr))
	}
}

// rewrite decodes a subgroup stream from the Relay and emits what the hook returns for each object.
func (tp *tap) rewrite(src *kolotransport.ReceiveStream, br *bufio.Reader, typ uint64, hook func(trackRef, *wire.Object) []*wire.Object) {
	h, err := wire.ReadSubgroupHeader(br, typ)
	if err != nil {
		src.CancelRead(0)
		return
	}
	tr := tp.trackOf(true, h.TrackAlias)
	tp.defaultPriority(true, h)
	sr := &wire.SubgroupReader{R: br, Header: h, MaxPayload: 1 << 30}
	for {
		o, err := sr.Next()
		if err != nil {
			if err != io.EOF {
				src.CancelRead(0)
			}
			return
		}
		tp.saw(seen{down: true, alias: h.TrackAlias, obj: *o})
		for _, out := range hook(tr, o) {
			tp.emit(h.TrackAlias, out)
		}
	}
}

// defaultPriority fills in a header's priority from the track's default, as a subscriber does.
func (tp *tap) defaultPriority(down bool, h *wire.SubgroupHeader) {
	if h.Flags&wire.SubgroupDefaultPrio == 0 {
		return
	}
	tp.trackOf(down, h.TrackAlias)
	tp.mu.Lock()
	h.Priority = tp.prios[dirID{down, h.TrackAlias}]
	tp.mu.Unlock()
}

func (tp *tap) saw(s seen) {
	s.at = time.Now()
	tp.mu.Lock()
	tp.objects = append(tp.objects, s)
	tp.mu.Unlock()
}

// trackOf waits for the SUBSCRIBE_OK of alias, which the Relay sends before its objects; it runs
// on tap goroutines, so it gives up quietly.
func (tp *tap) trackOf(down bool, alias uint64) trackRef {
	for end := time.Now().Add(10 * time.Second); time.Now().Before(end); time.Sleep(time.Millisecond) {
		tp.mu.Lock()
		tr, ok := tp.aliases[dirID{down, alias}]
		tp.mu.Unlock()
		if ok {
			return tr
		}
	}
	return trackRef{}
}

// alias returns the Track Alias of the participant's latest subscription of ns and name.
func (tp *tap) alias(ns kolomoq.Namespace, name string) uint64 {
	want := refOf(ns, name)
	var alias uint64
	eventually(tp.t, "subscription alias", func() bool {
		tp.mu.Lock()
		defer tp.mu.Unlock()
		found := false
		for k, tr := range tp.aliases {
			if k.down && tr == want && (!found || k.id > alias) {
				alias, found = k.id, true
			}
		}
		return found
	})
	return alias
}

// seenObjects returns the normal objects of tr the tap saw: sent by the Relay (down) or received
// by it (up).
func (tp *tap) seenObjects(down bool, tr trackRef) []seen {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	var out []seen
	for _, s := range tp.objects {
		if s.down != down || s.obj.Status != wire.StatusNormal {
			continue
		}
		var ref trackRef
		if s.fetch {
			if m := tp.reqDir[dirID{!down, s.alias}]; m != nil {
				ref = refOf(m.Namespace, m.Name)
			}
		} else {
			ref = tp.aliases[dirID{down, s.alias}]
		}
		if ref == tr {
			out = append(out, s)
		}
	}
	return out
}

// emit sends objs, which share Group, Subgroup and Priority with increasing IDs, on a new
// subgroup stream with the given Track Alias.
func (tp *tap) emit(alias uint64, objs ...*wire.Object) {
	st, err := tp.outer.OpenUniStream(tp.ctx)
	if err != nil {
		return
	}
	h := wire.SubgroupHeader{
		Flags:      wire.SubgroupTypeBit | wire.SubgroupProperties | wire.SubgroupModeExplicit<<1,
		TrackAlias: alias, Group: objs[0].Group, Subgroup: objs[0].Subgroup, Priority: objs[0].Priority,
	}
	b := h.Append(nil)
	var w wire.SubgroupWriter
	for _, o := range objs {
		if b, err = w.Append(b, o); err != nil {
			panic(err)
		}
	}
	tp.injected.Add(int64(len(objs)))
	if _, err := st.Write(b); err != nil {
		st.CancelWrite(0)
		return
	}
	st.Close()
}

// ask sends a request to the participant as the relay and returns the first answer.
func (tp *tap) ask(m *wire.Request) (uint64, []byte, *bufio.Reader, *kolotransport.Stream) {
	tp.t.Helper()
	tp.mu.Lock()
	m.RequestID = tp.nextReq
	tp.nextReq += 2
	tp.mu.Unlock()
	st, err := tp.outer.OpenStream(tp.ctx)
	if err != nil {
		tp.t.Fatal(err)
	}
	b, err := wire.AppendMessage(nil, m.Type, m.Append(nil))
	if err != nil {
		tp.t.Fatal(err)
	}
	if _, err := st.Write(b); err != nil {
		tp.t.Fatal(err)
	}
	st.SetReadDeadline(time.Now().Add(10 * time.Second))
	br := bufio.NewReader(st)
	typ, body, err := wire.ReadMessage(br, wire.MaxMessageLen)
	if err != nil {
		tp.t.Fatalf("answer to 0x%x: %v", m.Type, err)
	}
	return typ, body, br, st
}

// hold stops the data the Relay sends to the participant; release lets it flow.
func (tp *tap) hold() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if tp.gate == nil {
		tp.gate = make(chan struct{})
	}
}

func (tp *tap) release() {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	if tp.gate != nil {
		close(tp.gate)
		tp.gate = nil
	}
}

func (tp *tap) recorded() []byte {
	tp.mu.Lock()
	defer tp.mu.Unlock()
	return slices.Clone(tp.rec)
}

type recReader struct {
	tp *tap
	r  io.Reader
}

func (r *recReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	r.tp.mu.Lock()
	r.tp.rec = append(r.tp.rec, p[:n]...)
	r.tp.mu.Unlock()
	return n, err
}

type gateReader struct {
	tp *tap
	r  io.Reader
}

func (g *gateReader) Read(p []byte) (int, error) {
	g.tp.mu.Lock()
	gate := g.tp.gate
	g.tp.mu.Unlock()
	if gate != nil {
		select {
		case <-gate:
		case <-g.tp.ctx.Done():
			return 0, g.tp.ctx.Err()
		}
	}
	return g.r.Read(p)
}

// udpPath is a byte relay for a pairwise kolo-secure connection: it copies datagrams it cannot
// read and drops them while held.
type udpPath struct {
	ln, up *net.UDPConn
	client atomic.Pointer[net.UDPAddr]
	held   atomic.Bool
}

func newUDPPath(t testing.TB, target string) *udpPath {
	t.Helper()
	loop := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)}
	ln, err := net.ListenUDP("udp4", loop)
	if err != nil {
		t.Fatal(err)
	}
	ta, err := net.ResolveUDPAddr("udp4", target)
	if err != nil {
		t.Fatal(err)
	}
	up, err := net.DialUDP("udp4", loop, ta)
	if err != nil {
		t.Fatal(err)
	}
	p := &udpPath{ln: ln, up: up}
	var wg sync.WaitGroup
	wg.Go(func() {
		b := make([]byte, 65536)
		for {
			n, from, err := ln.ReadFromUDP(b)
			if err != nil {
				return
			}
			p.client.Store(from)
			if !p.held.Load() {
				up.Write(b[:n])
			}
		}
	})
	wg.Go(func() {
		b := make([]byte, 65536)
		for {
			n, err := up.Read(b)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			if c := p.client.Load(); c != nil && !p.held.Load() {
				ln.WriteToUDP(b[:n], c)
			}
		}
	})
	t.Cleanup(func() {
		ln.Close()
		up.Close()
		wg.Wait()
	})
	return p
}

func (p *udpPath) addr() string { return p.ln.LocalAddr().String() }

// linkVia is link with sub dialing addr instead of pub's listener.
func linkVia(t testing.TB, pub, sub *node, via func(target string) string) *kolomoq.Session {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", pub.id, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	srv := make(chan *kolomoq.Session, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			srv <- nil
			return
		}
		s, _ := kolomoq.NewServer(ctx, c, &kolomoq.Config{Origin: pub.origin})
		srv <- s
	}()
	c, err := kolosecure.Dial(ctx, via(l.Addr().String()), sub.id, pub.pub, &kolosecure.Config{Transport: testTransport})
	if err != nil {
		t.Fatal(err)
	}
	cs, err := kolomoq.NewClient(ctx, c, nil)
	if err != nil {
		t.Fatal(err)
	}
	ss := <-srv
	if ss == nil {
		t.Fatal("pairwise server session failed")
	}
	t.Cleanup(func() {
		cs.Close()
		ss.Close()
	})
	return cs
}

// party is a participant of a room: a node with a Sender for its namespace, a Keyring and a
// session to the relay.
type party struct {
	*node
	ns     kolomoq.Namespace
	sender *Sender
	keys   *Keyring
	relay  *kolomoq.Session
	tap    *tap
	tracks map[string]*kolomoq.TrackWriter
	groups map[string]*kolomoq.GroupWriter
}

// newParty joins a new participant to rm, through tp when it is not nil.
func newParty(t testing.TB, rm *room, tp *tap, cfg *kolomoq.Config) *party {
	t.Helper()
	n := newNode(t)
	rm.admit(n)
	p := &party{node: n, ns: mediaNS(n.pub), tap: tp, tracks: map[string]*kolomoq.TrackWriter{}, groups: map[string]*kolomoq.GroupWriter{}}
	p.sender = newSender(t, n, nil)
	p.keys = newKeyring(t, KeyringConfig{Relays: []ed25519.PublicKey{rm.id.pub}})
	p.relay = rm.join(n, cfg, tp)
	if _, err := p.relay.PublishNamespace(testCtx(t), p.ns); err != nil {
		t.Fatal(err)
	}
	return p
}

func (p *party) track(t testing.TB, name string, prio uint8) *kolomoq.TrackWriter {
	t.Helper()
	tw, err := p.origin.CreateTrack(p.ns, name, &kolomoq.TrackOptions{Priority: prio, CacheGroups: 16})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { tw.Close() })
	p.tracks[name] = tw
	return tw
}

// write seals payload as the next object of track, in a new group when newGroup is set.
func (p *party) write(t testing.TB, name string, newGroup bool, payload []byte, private ...kolomoq.Property) kolomoq.Location {
	t.Helper()
	g := p.groups[name]
	if newGroup || g == nil {
		var err error
		if g, err = p.tracks[name].NewGroup(); err != nil {
			t.Fatal(err)
		}
		p.groups[name] = g
	}
	id, err := p.sender.Write(g, name, payload, private...)
	if err != nil {
		t.Fatal(err)
	}
	return kolomoq.Location{Group: g.ID(), Object: id}
}

// keysFrom delivers from's key to p over a direct pairwise session.
func (p *party) keysFrom(t testing.TB, from *party) <-chan error {
	t.Helper()
	side, _ := link(t, from.node, p.node, nil)
	return receive(t, p.keys, side, p.pub, from.ns)
}

// subscribe subscribes p to a track of from through the relay.
func (p *party) subscribe(t testing.TB, from *party, name string, opts *kolomoq.SubscribeOptions) *kolomoq.Subscription {
	t.Helper()
	sub, err := p.relay.Subscribe(testCtx(t), from.ns, name, opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close() })
	eventually(t, "relay subscription", func() bool { return from.tracks[name].Subscribers() > 0 })
	return sub
}

// nextNormal returns the next object of sub that has a payload, skipping End of Group objects.
func nextNormal(t testing.TB, sub *kolomoq.Subscription) kolomoq.Object {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	for {
		o, err := sub.ReadObject(ctx)
		if err != nil {
			t.Fatalf("read: %v", err)
		}
		if o.Status == kolomoq.StatusNormal {
			return o
		}
	}
}

// openAll reads n normal objects of sub and opens each; it returns the plaintexts opened and the
// errors of the others, counted by error.
func openAll(t testing.TB, k *Keyring, ns kolomoq.Namespace, track string, sub *kolomoq.Subscription, n int) (opened []string, errs map[error]int) {
	t.Helper()
	errs = map[error]int{}
	for range n {
		o := nextNormal(t, sub)
		pt, _, err := openAt(k, ns, track, o)
		if err != nil {
			errs[err]++
			continue
		}
		opened = append(opened, string(pt))
	}
	return opened, errs
}

func toWire(o kolomoq.Object) *wire.Object {
	w := &wire.Object{Group: o.Group, Subgroup: o.Subgroup, ID: o.ID, Priority: o.Priority, Status: uint64(o.Status), Payload: slices.Clone(o.Payload)}
	for _, p := range o.Properties {
		w.Properties = append(w.Properties, wire.KV{Type: p.Type, Value: p.Value, Bytes: slices.Clone(p.Bytes)})
	}
	return w
}

func fromWire(o *wire.Object) kolomoq.Object {
	k := kolomoq.Object{Group: o.Group, Subgroup: o.Subgroup, ID: o.ID, Priority: o.Priority, Status: kolomoq.ObjectStatus(o.Status), Payload: o.Payload}
	for _, p := range o.Properties {
		k.Properties = append(k.Properties, kolomoq.Property{Type: p.Type, Value: p.Value, Bytes: p.Bytes})
	}
	return k
}

func cloneWire(o *wire.Object) *wire.Object { return toWire(fromWire(o)) }

// keyIDProps is the visible property list of a protected object with Key ID kid.
func keyIDProps(kid uint64) []wire.KV {
	return []wire.KV{{Type: propImmutable, Bytes: wire.AppendVarint([]byte{PropertyKeyID}, kid)}}
}

func hexKey(pub ed25519.PublicKey) string { return hex.EncodeToString(pub) }
