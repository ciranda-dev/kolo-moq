// Package interop runs a second, independent draft-22 implementation over
// Kolo connections, to test kolo-moq against it.
package interop

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"sync"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"
	"github.com/floatdrop/moq-go/pkg/moqt/session"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

// preface is the varint length 7 and "moqt-22" each Kolo control stream
// starts with.
var preface = append([]byte{7}, "moqt-22"...)

// errNoDatagrams is returned for datagrams, which Kolo connections lack.
var errNoDatagrams = errors.New("interop: Kolo connections carry no datagrams")

// peekTimeout bounds the wait for the first bytes of the first stream the
// peer opens, which tell whether it carries the version preface.
const peekTimeout = 10 * time.Second

// probeInterval is how often a send stream checks for the peer's
// STOP_SENDING, which kolo-transport reports only to a write.
const probeInterval = 20 * time.Millisecond

// Conn adapts a Kolo connection to the peer implementation's transport:
// it adds the version preface to the first stream it opens (the control
// stream) and strips it from the first stream the peer opens.
type Conn struct {
	c kolomoq.Conn

	mu          sync.Mutex
	sentPreface bool
	gotPreface  bool
}

// NewConn wraps c.
func NewConn(c kolomoq.Conn) *Conn { return &Conn{c: c} }

// OpenUniStream opens a unidirectional stream, waiting while the peer's
// stream limit is reached.
func (a *Conn) OpenUniStream() (session.SendStream, error) {
	st, err := a.c.OpenUniStream(a.c.Context())
	if err != nil {
		return nil, err
	}
	s := newSend(st, st.CancelWrite, st.SetWriteDeadline, st.Close)
	a.mu.Lock()
	first := !a.sentPreface
	a.sentPreface = true
	a.mu.Unlock()
	if first {
		if _, err := s.Write(preface); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// AcceptUniStream accepts a unidirectional stream; the first one that
// starts with the preface loses it.
func (a *Conn) AcceptUniStream(ctx context.Context) (session.ReceiveStream, error) {
	rs, err := a.c.AcceptUniStream(ctx)
	if err != nil {
		return nil, err
	}
	r := &recv{br: bufio.NewReader(rs), cancel: rs.CancelRead}
	a.mu.Lock()
	need := !a.gotPreface
	a.mu.Unlock()
	if need {
		// A peer that opens a stream and sends nothing must not block the accept loop.
		rs.SetReadDeadline(time.Now().Add(peekTimeout))
		p, _ := r.br.Peek(len(preface))
		rs.SetReadDeadline(time.Time{})
		if bytes.Equal(p, preface) {
			r.br.Discard(len(preface))
			a.mu.Lock()
			a.gotPreface = true
			a.mu.Unlock()
		}
	}
	return r, nil
}

// OpenStream opens a bidirectional stream, waiting while the peer's stream
// limit is reached.
func (a *Conn) OpenStream() (session.Stream, error) {
	st, err := a.c.OpenStream(a.c.Context())
	if err != nil {
		return nil, err
	}
	return newBidi(st), nil
}

// AcceptStream accepts a bidirectional stream.
func (a *Conn) AcceptStream(ctx context.Context) (session.Stream, error) {
	st, err := a.c.AcceptStream(ctx)
	if err != nil {
		return nil, err
	}
	return newBidi(st), nil
}

// CloseWithError closes the connection.
func (a *Conn) CloseWithError(code uint64, reason string) error {
	if len(reason) > 256 {
		reason = reason[:256]
	}
	return a.c.CloseWithError(code, reason)
}

// Context is canceled when the connection ends.
func (a *Conn) Context() context.Context { return a.c.Context() }

// SendDatagram always fails: Kolo connections carry no datagrams.
func (a *Conn) SendDatagram([]byte) error { return errNoDatagrams }

// ReceiveDatagram waits for ctx: no datagram ever arrives.
func (a *Conn) ReceiveDatagram(ctx context.Context) ([]byte, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

type writer interface {
	Write([]byte) (int, error)
}

// send is the sending side of a stream. Its Context ends on Close,
// CancelWrite or a failed write, which is how a STOP_SENDING shows.
type send struct {
	w           writer
	cancelWrite func(uint64) error
	setDeadline func(time.Time) error
	close       func() error
	mu          sync.Mutex
	ctx         context.Context
	stop        context.CancelFunc
}

func newSend(w writer, cancelWrite func(uint64) error, setDeadline func(time.Time) error, closeFn func() error) *send {
	s := &send{w: w, cancelWrite: cancelWrite, setDeadline: setDeadline, close: closeFn}
	s.ctx, s.stop = context.WithCancel(context.Background())
	go s.probe()
	return s
}

func (s *send) probe() {
	t := time.NewTicker(probeInterval)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
		}
		if !s.mu.TryLock() {
			continue
		}
		_, err := s.w.Write(nil)
		s.mu.Unlock()
		if err != nil {
			s.stop()
			return
		}
	}
}

func (s *send) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	n, err := s.w.Write(p)
	if err != nil {
		s.stop()
	}
	return n, err
}

func (s *send) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stop()
	return s.close()
}

func (s *send) CancelWrite(code uint64) {
	s.cancelWrite(code)
	s.stop()
}

func (s *send) Context() context.Context { return s.ctx }

func (s *send) SetWriteDeadline(t time.Time) error { return s.setDeadline(t) }

type recv struct {
	br     *bufio.Reader
	cancel func(uint64) error
}

func (r *recv) Read(p []byte) (int, error) { return r.br.Read(p) }

func (r *recv) CancelRead(code uint64) { r.cancel(code) }

type bidi struct {
	*send
	*recv
}

func newBidi(st *kolotransport.Stream) *bidi {
	return &bidi{
		send: newSend(st, st.CancelWrite, st.SetWriteDeadline, st.Close),
		recv: &recv{br: bufio.NewReader(st), cancel: st.CancelRead},
	}
}
