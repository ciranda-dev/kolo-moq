package kolomoq

import (
	"bufio"
	"context"
	"errors"
	"io"
	"testing"
	"time"

	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// rawPeer speaks the wire format by hand, to send what a Session never
// would.
type rawPeer struct {
	t      *testing.T
	conn   *kolosecure.Conn
	ctrl   *kolotransport.SendStream
	nextID uint64
}

type sessionResult struct {
	s   *Session
	err error
}

// newRawClient connects a raw client to a server Session; the raw side
// sends preface and a SETUP message when preface is not nil.
func newRawClient(t *testing.T, cfg *Config, preface []byte) (*rawPeer, <-chan sessionResult) {
	t.Helper()
	cc, sc, _ := connect(t)
	res := closeWithTest(t, func(ctx context.Context) (*Session, error) { return NewServer(ctx, sc, cfg) })
	t.Cleanup(func() { cc.Close() })
	r := &rawPeer{t: t, conn: cc}
	if preface != nil {
		r.openControl(preface, setupMsg(nil))
	}
	return r, res
}

func setupMsg(opts []wire.KV) []byte {
	return msg(wire.MsgSetup, (&wire.Setup{Options: opts}).Append(nil))
}

func (r *rawPeer) openControl(parts ...[]byte) {
	r.t.Helper()
	ctx := testCtx(r.t)
	st, err := r.conn.OpenUniStream(ctx)
	if err != nil {
		r.t.Fatal(err)
	}
	for _, p := range parts {
		if _, err := st.Write(p); err != nil {
			r.t.Fatal(err)
		}
	}
	r.ctrl = st
}

// connected returns the server session after a correct handshake.
func connected(t *testing.T, cfg *Config) (*rawPeer, *Session) {
	t.Helper()
	r, res := newRawClient(t, cfg, wire.Preface())
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	r.readControl()
	return r, sr.s
}

// readControl reads the session's preface and SETUP.
func (r *rawPeer) readControl() {
	r.t.Helper()
	rs, err := r.conn.AcceptUniStream(testCtx(r.t))
	if err != nil {
		r.t.Fatal(err)
	}
	br := bufio.NewReader(rs)
	p := make([]byte, len(wire.Preface()))
	if _, err := io.ReadFull(br, p); err != nil || string(p) != string(wire.Preface()) {
		r.t.Fatalf("preface %q %v", p, err)
	}
	if typ, _, err := wire.ReadMessage(br, wire.MaxMessageLen); err != nil || typ != wire.MsgSetup {
		r.t.Fatalf("setup %x %v", typ, err)
	}
}

func (r *rawPeer) id() uint64 {
	id := r.nextID
	r.nextID += 2
	return id
}

// send opens a request stream and writes raw bytes on it.
func (r *rawPeer) send(b []byte) (*kolotransport.Stream, *bufio.Reader) {
	r.t.Helper()
	st, err := r.conn.OpenStream(testCtx(r.t))
	if err != nil {
		r.t.Fatal(err)
	}
	if _, err := st.Write(b); err != nil {
		r.t.Fatal(err)
	}
	return st, bufio.NewReader(st)
}

func (r *rawPeer) request(m *wire.Request) (*kolotransport.Stream, *bufio.Reader) {
	return r.send(msg(m.Type, m.Append(nil)))
}

// expect reads one message of type want from br.
func (r *rawPeer) expect(br *bufio.Reader, want uint64) []byte {
	r.t.Helper()
	typ, body, err := wire.ReadMessage(br, wire.MaxMessageLen)
	if err != nil {
		r.t.Fatalf("reading 0x%x: %v", want, err)
	}
	if typ != want {
		r.t.Fatalf("got message 0x%x, want 0x%x", typ, want)
	}
	return body
}

func (r *rawPeer) expectError(br *bufio.Reader, code RequestCode) {
	r.t.Helper()
	m, err := wire.ParseRequestError(r.expect(br, wire.MsgRequestError))
	if err != nil {
		r.t.Fatal(err)
	}
	if RequestCode(m.Code) != code {
		r.t.Fatalf("REQUEST_ERROR %v, want %v", RequestCode(m.Code), code)
	}
}

// closedWith waits for the connection to close and returns the code.
func (r *rawPeer) closedWith() SessionCode {
	r.t.Helper()
	select {
	case <-r.conn.Context().Done():
	case <-time.After(10 * time.Second):
		r.t.Fatal("connection still open")
	}
	var te *kolotransport.Error
	if !errors.As(context.Cause(r.conn.Context()), &te) {
		r.t.Fatalf("close cause %v", context.Cause(r.conn.Context()))
	}
	return SessionCode(te.Code)
}

func subscribeMsg(id uint64, ns Namespace, name string, prm *wire.MessageParams) *wire.Request {
	if prm == nil {
		prm = &wire.MessageParams{}
	}
	return &wire.Request{Type: wire.MsgSubscribe, RequestID: id, Namespace: ns, Name: name, Params: prm}
}

// closeWithTest starts a session in the background and closes it when the
// test ends, whether or not the test waited for it.
func closeWithTest(t *testing.T, start func(ctx context.Context) (*Session, error)) <-chan sessionResult {
	t.Helper()
	res := make(chan sessionResult, 1)
	done := make(chan struct{})
	var s *Session
	go func() {
		defer close(done)
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		var err error
		var made *Session
		made, err = start(ctx)
		s = made
		res <- sessionResult{made, err}
	}()
	t.Cleanup(func() {
		<-done
		if s != nil {
			s.Close()
		}
	})
	return res
}

// newRawServer connects a client Session to a raw server that sends
// preface and setup as given.
func newRawServer(t *testing.T, cfg *Config, preface, setup []byte) (*rawPeer, <-chan sessionResult) {
	t.Helper()
	cc, sc, _ := connect(t)
	res := closeWithTest(t, func(ctx context.Context) (*Session, error) { return NewClient(ctx, cc, cfg) })
	t.Cleanup(func() { sc.Close() })
	r := &rawPeer{t: t, conn: sc, nextID: 1}
	r.openControl(preface, setup)
	return r, res
}

// serving returns a client Session connected to a raw server.
func serving(t *testing.T, cfg *Config) (*rawPeer, *Session) {
	t.Helper()
	r, res := newRawServer(t, cfg, wire.Preface(), setupMsg(nil))
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	r.readControl()
	return r, sr.s
}

// accept reads the next request the session sends.
func (r *rawPeer) accept() (*kolotransport.Stream, *bufio.Reader, *wire.Request) {
	r.t.Helper()
	st, err := r.conn.AcceptStream(testCtx(r.t))
	if err != nil {
		r.t.Fatal(err)
	}
	br := bufio.NewReader(st)
	typ, body, err := wire.ReadMessage(br, wire.MaxMessageLen)
	if err != nil {
		r.t.Fatal(err)
	}
	m, err := wire.ParseRequest(typ, body)
	if err != nil {
		r.t.Fatal(err)
	}
	return st, br, m
}

func write(t *testing.T, w io.Writer, typ uint64, m appender) {
	t.Helper()
	if _, err := w.Write(msg(typ, m.Append(nil))); err != nil {
		t.Fatal(err)
	}
}
