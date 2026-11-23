package kolomoq

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// implementation is sent in the MOQT_IMPLEMENTATION setup option.
const implementation = "kolo-moq"

// Session is a MoQ Transport session over one Conn. It owns the Conn: it is
// the only caller of AcceptStream and AcceptUniStream and closes the Conn
// when the session ends. Its methods are safe for concurrent use.
type Session struct {
	conn   Conn
	cfg    Config
	client bool
	peer   ed25519.PublicKey
	ctx    context.Context
	cancel context.CancelFunc
	gate   gate

	ctrlMu sync.Mutex
	ctrl   *kolotransport.SendStream

	peerImpl string

	mu         sync.Mutex
	nextReqID  uint64
	ids        idWindow
	nextAlias  uint64
	aliases    map[uint64]*Subscription
	aliasWake  chan struct{}
	fetchByReq map[uint64]fetchTarget
	active     int
	pubSubs    int
	pubs       map[*pubSub]struct{}
	fetchBytes int64 // cached objects held for the peer's fetches and fills
	forwarded  int   // the peer's fetches a relay forwards
	peerNS     map[*peerNamespace]struct{}
	nsServes   map[*nsServe]struct{}
	goawaySent bool
	goawayRecv bool
	goingAway  chan struct{}
	err        error
	done       chan struct{}
	wg         sync.WaitGroup

	resetGroups   atomic.Uint64
	expiredGroups atomic.Uint64
	sentBytes     atomic.Uint64
	buffered      atomic.Int64 // payload bytes queued for MaxSessionBufferedBytes, in every subscription of both sides
}

// SessionStats counts what this side sent and the groups it stopped sending, and says how far behind its sending is.
type SessionStats struct {
	// SentBytes counts the bytes of data streams handed to the transport, which takes them as fast as the path lets
	// it: while QueueDelay is above zero, its change over time is the rate the path carries.
	SentBytes uint64
	// QueuedBytes is the payload waiting in subscribers' queues, not yet handed to the transport.
	QueuedBytes int64
	// QueueDelay is how long the oldest object still being sent or waiting has been held, across the subscribers of
	// this session. It is zero when nothing waits; it grows while the path carries less than is published.
	QueueDelay time.Duration
	// ResetGroups counts subgroup streams reset because a subscriber's queue exceeded MaxBufferedGroups, MaxBufferedBytes or MaxSessionBufferedBytes, or because the subscriber stopped reading the stream for RequestTimeout.
	ResetGroups uint64
	// ExpiredGroups counts subgroup streams reset with DELIVERY_TIMEOUT.
	ExpiredGroups uint64
	// Transport is the transport's statistics of the connection this session runs on: round-trip times, losses, the
	// congestion window, the congestion controller and the path (see kolotransport.ConnStats). It is the zero value
	// when the session's Conn has no Stats method, as a *kolorelay.Conn has none, and once the connection has ended.
	Transport kolotransport.ConnStats
}

// NewClient starts a session as the MoQT client, on a Conn this side
// dialed. It returns once both SETUP messages are exchanged.
func NewClient(ctx context.Context, conn Conn, cfg *Config) (*Session, error) {
	return newSession(ctx, conn, cfg, true)
}

// NewServer starts a session as the MoQT server, on a Conn this side
// accepted. It returns once both SETUP messages are exchanged.
func NewServer(ctx context.Context, conn Conn, cfg *Config) (*Session, error) {
	return newSession(ctx, conn, cfg, false)
}

func newSession(ctx context.Context, conn Conn, cfg *Config, client bool) (*Session, error) {
	c, err := cfg.resolve()
	if err != nil {
		return nil, err
	}
	s := &Session{
		conn:       conn,
		cfg:        c,
		client:     client,
		peer:       conn.RemotePublicKey(),
		aliases:    map[uint64]*Subscription{},
		aliasWake:  make(chan struct{}),
		fetchByReq: map[uint64]fetchTarget{},
		peerNS:     map[*peerNamespace]struct{}{},
		nsServes:   map[*nsServe]struct{}{},
		goingAway:  make(chan struct{}),
		done:       make(chan struct{}),
	}
	if !client {
		s.nextReqID = 1
	}
	s.ctx, s.cancel = context.WithCancel(context.Background())
	s.wg.Add(1)
	go s.watchConn()
	err = s.setup(ctx)
	if err == nil {
		err = s.Err()
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	s.wg.Add(2)
	go s.acceptRequests()
	go s.acceptData()
	return s, nil
}

func (s *Session) setup(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.SetupTimeout)
	defer cancel()
	stop := context.AfterFunc(ctx, func() {
		if ctx.Err() == context.DeadlineExceeded {
			s.fail(CodeControlMessageTimeout, ErrTimeout)
		} else {
			s.fail(CodeNoError, ctx.Err())
		}
	})
	defer stop()
	deadline, _ := ctx.Deadline()

	ctrl, err := s.conn.OpenUniStream(ctx)
	if err != nil {
		return s.setupErr(err)
	}
	s.ctrl = ctrl
	setup := &wire.Setup{Options: []wire.KV{{Type: wire.OptMoqtImplementation, Bytes: []byte(implementation)}}}
	msg, err := wire.AppendMessage(nil, wire.MsgSetup, setup.Append(nil))
	if err != nil {
		return s.setupErr(err)
	}
	b := append(wire.Preface(), msg...)
	ctrl.SetWriteDeadline(deadline)
	if _, err := ctrl.Write(b); err != nil {
		return s.setupErr(err)
	}
	ctrl.SetWriteDeadline(time.Time{})

	for {
		rs, err := s.conn.AcceptUniStream(ctx)
		if err != nil {
			return s.setupErr(err)
		}
		rs.SetReadDeadline(deadline)
		br := bufio.NewReader(rs)
		t, err := wire.ReadVarint(br)
		if err != nil {
			rs.CancelRead(resetInternalError)
			continue
		}
		if t == wire.StreamTypeFetch || t == wire.StreamTypePadding || wire.IsSubgroupType(t) {
			// Only control can come before our requests; drop the rest.
			rs.CancelRead(resetCancelled)
			continue
		}
		if err := s.readPreface(br, t); err != nil {
			return err
		}
		mt, body, err := wire.ReadMessage(br, s.cfg.MaxControlMessageSize)
		if err != nil {
			return s.setupErr(err)
		}
		if mt != wire.MsgSetup {
			return s.violation(CodeProtocolViolation)
		}
		m, err := wire.ParseSetup(body)
		if err != nil {
			return s.violation(sessionCode(err))
		}
		if err := s.applySetup(m); err != nil {
			return err
		}
		rs.SetReadDeadline(time.Time{})
		s.wg.Add(1)
		go s.readControl(rs, br)
		return nil
	}
}

func (s *Session) readPreface(br *bufio.Reader, n uint64) error {
	if n != wire.StreamTypePrefaceLength {
		s.fail(CodeProtocolViolation, ErrVersion)
		return s.Err()
	}
	var v [len(wire.PrefaceVersion)]byte
	if _, err := io.ReadFull(br, v[:]); err != nil {
		return s.setupErr(err)
	}
	if string(v[:]) != wire.PrefaceVersion {
		s.fail(CodeProtocolViolation, ErrVersion)
		return s.Err()
	}
	return nil
}

func (s *Session) applySetup(m *wire.Setup) error {
	seen := map[uint64]bool{}
	for _, o := range m.Options {
		if o.Type == wire.OptAuthToken {
			// Tokens may repeat; Kolo authorizes by peer key, so their values are unused.
			at, err := wire.TokenAliasType(o.Bytes)
			if err != nil {
				return s.violation(sessionCode(err))
			}
			if at == wire.TokenDelete || at == wire.TokenUseAlias {
				return s.violation(CodeProtocolViolation)
			}
			continue
		}
		if seen[o.Type] {
			continue
		}
		seen[o.Type] = true
		switch o.Type {
		case wire.OptPath:
			if s.client {
				return s.violation(CodeInvalidPath)
			}
		case wire.OptAuthority:
			if s.client {
				return s.violation(CodeInvalidAuthority)
			}
		case wire.OptMoqtImplementation:
			impl := string(o.Bytes)
			if len(impl) > wire.MaxReasonLen {
				impl = impl[:wire.MaxReasonLen]
			}
			s.peerImpl = sanitize(impl)
		}
	}
	return nil
}

func (s *Session) setupErr(err error) error {
	if e := s.Err(); e != nil {
		return e
	}
	var we *wire.Error
	if errors.As(err, &we) {
		return s.violation(SessionCode(we.Code))
	}
	if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(err, context.DeadlineExceeded) {
		s.fail(CodeControlMessageTimeout, ErrTimeout)
		return s.Err()
	}
	s.fail(CodeInternalError, err)
	return s.Err()
}

// violation closes the session with code and returns the session error.
func (s *Session) violation(code SessionCode) error {
	s.fail(code, ErrProtocol)
	return s.Err()
}

func (s *Session) readControl(rs *kolotransport.ReceiveStream, br *bufio.Reader) {
	defer s.wg.Done()
	for {
		t, body, err := wire.ReadMessage(br, s.cfg.MaxControlMessageSize)
		if err != nil {
			if s.connEnded(err) {
				return
			}
			var we *wire.Error
			if errors.As(err, &we) {
				s.fail(SessionCode(we.Code), ErrProtocol)
			} else {
				s.fail(CodeProtocolViolation, ErrProtocol)
			}
			return
		}
		if t != wire.MsgGoAway {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
		m, err := wire.ParseGoAway(body)
		if err != nil {
			s.fail(sessionCode(err), ErrProtocol)
			return
		}
		if !s.client && m.URI != "" {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
		s.mu.Lock()
		dup := s.goawayRecv
		if !dup {
			s.goawayRecv = true
			close(s.goingAway)
		}
		s.mu.Unlock()
		if dup {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
	}
}

func (s *Session) watchConn() {
	defer s.wg.Done()
	select {
	case <-s.conn.Context().Done():
		s.setErr(connError(context.Cause(s.conn.Context())))
	case <-s.ctx.Done():
	}
}

func connError(cause error) error {
	var te *kolotransport.Error
	if errors.As(cause, &te) && errors.Is(te, kolotransport.ErrPeerClosed) {
		return &SessionError{Code: SessionCode(te.Code), Remote: true}
	}
	return fmt.Errorf("kolomoq: connection ended: %w", cause)
}

// connEnded records the session's end if err shows the connection ended,
// and reports whether it did.
func (s *Session) connEnded(err error) bool {
	for _, e := range []error{kolotransport.ErrPeerClosed, kolotransport.ErrClosed, kolotransport.ErrTimeout,
		kolotransport.ErrTransport, kolotransport.ErrRefused, kolotransport.ErrHandshake} {
		if errors.Is(err, e) {
			s.setErr(connError(err))
			return true
		}
	}
	return s.ctx.Err() != nil
}

func (s *Session) setErr(err error) bool {
	s.mu.Lock()
	first := s.err == nil
	if first {
		s.err = err
		close(s.done)
	}
	s.mu.Unlock()
	if first {
		s.cancel()
	}
	return first
}

// fail ends the session with code; sentinel is what Err wraps.
func (s *Session) fail(code SessionCode, sentinel error) {
	var err error
	if code == CodeNoError && sentinel != nil {
		err = sentinel
	} else {
		err = &SessionError{Code: code, err: sentinel}
	}
	if s.setErr(err) {
		s.conn.CloseWithError(uint64(code), "")
	}
}

// start runs f in a goroutine that Close waits for. It reports false, and
// does not run f, once the session has ended: the check and the Add happen
// under one lock, so no goroutine is added to a WaitGroup that Close is
// already waiting on.
func (s *Session) start(f func()) bool {
	s.mu.Lock()
	if s.err != nil {
		s.mu.Unlock()
		return false
	}
	s.wg.Add(1)
	s.mu.Unlock()
	go func() {
		defer s.wg.Done()
		f()
	}()
	return true
}

// reserveFetch counts n bytes held for the peer's fetches against
// MaxFetchBytes; false means they do not fit.
func (s *Session) reserveFetch(n int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetchBytes+n > s.cfg.MaxFetchBytes {
		return false
	}
	s.fetchBytes += n
	return true
}

func (s *Session) releaseFetch(n int64) {
	s.mu.Lock()
	s.fetchBytes -= n
	s.mu.Unlock()
}

// goneAway reports whether this side sent or received GOAWAY.
func (s *Session) goneAway() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goawaySent || s.goawayRecv
}

// goawayReceived reports whether the peer sent GOAWAY, after which this side
// sends no new request (draft section 9.2).
func (s *Session) goawayReceived() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.goawayRecv
}

// Close ends the session with NO_ERROR and waits for its goroutines.
// Calls in progress return ErrClosed.
func (s *Session) Close() error {
	s.fail(CodeNoError, ErrClosed)
	s.wg.Wait()
	return nil
}

// Suspend ends the session and closes its connection with CodeSuspend, to tell a Relay with Resume that this peer means to
// come back: the relay keeps the peer's announcements as it does for a lost connection. Close, which ends with
// CodeNoError, withdraws them at once.
func (s *Session) Suspend() error {
	s.fail(CodeSuspend, ErrClosed)
	s.wg.Wait()
	return nil
}

// Done is closed when the session has ended.
func (s *Session) Done() <-chan struct{} { return s.done }

// connLost reports whether the session ended, within wait, because its connection timed out or failed, or because the peer
// suspended it.
func (s *Session) connLost(wait time.Duration) bool {
	if s.Err() == nil && s.conn.Context().Err() == nil {
		t := time.NewTimer(wait)
		select {
		case <-s.done:
		case <-s.conn.Context().Done():
		case <-t.C:
		}
		t.Stop()
	}
	err := s.Err()
	if cx := s.conn.Context(); err == nil && cx.Err() != nil {
		err = connError(context.Cause(cx)) // the connection ended first; the session records it a moment later
	}
	var se *SessionError
	if errors.As(err, &se) && se.Remote && se.Code == CodeSuspend {
		return true
	}
	return errors.Is(err, kolotransport.ErrTimeout) || errors.Is(err, kolotransport.ErrTransport)
}

// Err returns why the session ended, or nil while it runs: ErrClosed after
// Close, a *SessionError for a termination code, or a wrapped kolo-transport
// error when the connection failed.
func (s *Session) Err() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

// RemotePublicKey returns a copy of the peer's kolo-id public key.
func (s *Session) RemotePublicKey() ed25519.PublicKey { return slices.Clone(s.peer) }

// PeerImplementation returns the peer's MOQT_IMPLEMENTATION, cut to 1024
// bytes, then with bytes outside printable ASCII escaped.
func (s *Session) PeerImplementation() string { return s.peerImpl }

// Stats returns counters of groups this side stopped sending, how far behind its sending is, and the transport's numbers of the connection.
func (s *Session) Stats() SessionStats {
	st := SessionStats{ResetGroups: s.resetGroups.Load(), ExpiredGroups: s.expiredGroups.Load(), SentBytes: s.sentBytes.Load()}
	if c, ok := s.conn.(interface {
		Stats() kolotransport.ConnStats
	}); ok {
		st.Transport = c.Stats()
	}
	s.mu.Lock()
	pubs := make([]*pubSub, 0, len(s.pubs))
	for p := range s.pubs {
		pubs = append(pubs, p)
	}
	s.mu.Unlock()
	now := time.Now()
	for _, p := range pubs {
		q, d := p.backlog(now)
		st.QueuedBytes += q
		st.QueueDelay = max(st.QueueDelay, d)
	}
	return st
}

func (s *Session) addPub(p *pubSub) {
	s.mu.Lock()
	if s.pubs == nil {
		s.pubs = map[*pubSub]struct{}{}
	}
	s.pubs[p] = struct{}{}
	s.mu.Unlock()
}

func (s *Session) delPub(p *pubSub) {
	s.mu.Lock()
	delete(s.pubs, p)
	s.mu.Unlock()
}

// buffer is a subscription of either side that queues payload for its session.
type buffer interface {
	queuedBytes() int64
	dropOldest() bool
}

// shed drops the oldest group of the subscription that holds the most while the session is over MaxSessionBufferedBytes,
// so a subscription nobody reads cannot make the healthy ones lose their objects.
func (s *Session) shed() {
	for s.buffered.Load() > s.cfg.MaxSessionBufferedBytes {
		s.mu.Lock()
		bufs := make([]buffer, 0, len(s.aliases)+len(s.pubs))
		for _, sub := range s.aliases {
			bufs = append(bufs, sub)
		}
		for p := range s.pubs {
			bufs = append(bufs, p)
		}
		s.mu.Unlock()
		var most buffer
		var mostBytes int64
		for _, b := range bufs {
			if n := b.queuedBytes(); n > mostBytes {
				most, mostBytes = b, n
			}
		}
		if most == nil || !most.dropOldest() {
			return
		}
	}
}

// GoingAway is closed when the peer sent GOAWAY: open a new session and
// move the subscriptions there.
func (s *Session) GoingAway() <-chan struct{} { return s.goingAway }

// GoAway sends GOAWAY, refuses new requests with GOING_AWAY, and closes the
// session with NO_ERROR once the peer has no request open, or with
// GOAWAY_TIMEOUT after timeout (at least 1ms). It returns nil once it has
// closed the session either way; Err tells which. A second call returns
// ErrGoingAway, and a session that had already ended returns its error.
func (s *Session) GoAway(ctx context.Context, timeout time.Duration) error {
	if timeout < time.Millisecond {
		return fmt.Errorf("%w: GoAway timeout below 1ms", ErrInvalidConfig)
	}
	s.mu.Lock()
	if s.err != nil {
		err := s.err
		s.mu.Unlock()
		return err
	}
	if s.goawaySent {
		s.mu.Unlock()
		return fmt.Errorf("%w: GOAWAY already sent", ErrGoingAway)
	}
	s.goawaySent = true
	s.mu.Unlock()
	m := &wire.GoAway{Timeout: uint64(timeout / time.Millisecond)}
	if err := s.writeControl(wire.MsgGoAway, m.Append(nil)); err != nil {
		return err
	}
	t := time.NewTimer(timeout)
	defer t.Stop()
	tick := time.NewTicker(timeout / 100)
	defer tick.Stop()
	for {
		s.mu.Lock()
		idle := s.active == 0 && s.err == nil
		s.mu.Unlock()
		if idle {
			s.fail(CodeNoError, ErrClosed)
			s.wg.Wait()
			return nil
		}
		select {
		case <-tick.C:
		case <-t.C:
			s.fail(CodeGoAwayTimeout, ErrTimeout)
			s.wg.Wait()
			return nil
		case <-s.done:
			return s.Err()
		case <-ctx.Done():
			return fmt.Errorf("kolomoq: GoAway: %w", ctx.Err())
		}
	}
}

func (s *Session) writeControl(t uint64, body []byte) error {
	msg, err := wire.AppendMessage(nil, t, body)
	if err != nil {
		return err
	}
	s.ctrlMu.Lock()
	defer s.ctrlMu.Unlock()
	if _, err := s.ctrl.Write(msg); err != nil {
		if e := s.Err(); e != nil {
			return e
		}
		return err
	}
	return nil
}

// acceptRequests serves the bidirectional request streams the peer opens.
func (s *Session) acceptRequests() {
	defer s.wg.Done()
	for {
		st, err := s.conn.AcceptStream(s.ctx)
		if err != nil {
			return
		}
		s.mu.Lock()
		full := s.active >= s.cfg.MaxRequests
		if !full {
			s.active++
		}
		s.mu.Unlock()
		if full {
			st.CancelRead(resetExcessiveLoad)
			st.CancelWrite(resetExcessiveLoad)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveRequest(st)
			s.mu.Lock()
			s.active--
			s.mu.Unlock()
		}()
	}
}

// acceptData dispatches the unidirectional streams the peer opens.
func (s *Session) acceptData() {
	defer s.wg.Done()
	for {
		rs, err := s.conn.AcceptUniStream(s.ctx)
		if err != nil {
			return
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.readDataStream(rs)
		}()
	}
}

// useRequestID records a request ID from the peer, closing the session
// with INVALID_REQUEST_ID on a wrong parity or a repeat.
func (s *Session) useRequestID(id uint64) bool {
	wantOdd := s.client
	s.mu.Lock()
	ok := (id%2 == 1) == wantOdd && s.ids.use(id>>1)
	s.mu.Unlock()
	if !ok {
		s.fail(CodeInvalidRequestID, ErrProtocol)
	}
	return ok
}

// newRequestID returns the ID of a new request; after a GOAWAY from the peer
// no new request is sent (draft section 9.2).
func (s *Session) newRequestID() (uint64, error) { return s.nextRequestID(false) }

// newUpdateID returns the ID of a REQUEST_UPDATE, which is not a new request
// in the sense of section 9.2 and stays allowed after a GOAWAY.
func (s *Session) newUpdateID() (uint64, error) { return s.nextRequestID(true) }

func (s *Session) nextRequestID(update bool) (uint64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return 0, s.err
	}
	if s.goawayRecv && !update {
		return 0, ErrGoingAway
	}
	id := s.nextReqID
	s.nextReqID += 2
	return id, nil
}

// idWindow remembers the last idWindowSize request sequence numbers; older
// ones count as repeats. The transport caps open streams at 1000, far
// below the window.
type idWindow struct {
	base uint64
	bits [idWindowSize / 64]uint64
}

const idWindowSize = 1 << 16

func (w *idWindow) use(seq uint64) bool {
	if seq < w.base {
		return false
	}
	if seq >= w.base+idWindowSize {
		newBase := seq - idWindowSize + 1
		if newBase-w.base >= idWindowSize {
			w.bits = [idWindowSize / 64]uint64{}
		} else {
			for i := w.base; i < newBase; {
				if i%64 == 0 && newBase-i >= 64 {
					w.bits[(i%idWindowSize)/64] = 0
					i += 64
					continue
				}
				w.bits[(i%idWindowSize)/64] &^= 1 << (i % 64)
				i++
			}
		}
		w.base = newBase
	}
	i := seq % idWindowSize
	if w.bits[i/64]&(1<<(i%64)) != 0 {
		return false
	}
	w.bits[i/64] |= 1 << (i % 64)
	return true
}

// reqStream is a bidirectional request stream.
type reqStream struct {
	st  *kolotransport.Stream
	br  *bufio.Reader
	wmu sync.Mutex
}

func newReqStream(st *kolotransport.Stream) *reqStream {
	return &reqStream{st: st, br: bufio.NewReader(st)}
}

type appender interface{ Append([]byte) []byte }

func (r *reqStream) write(t uint64, m appender) error {
	b, err := wire.AppendMessage(nil, t, m.Append(nil))
	if err != nil {
		return err
	}
	r.wmu.Lock()
	defer r.wmu.Unlock()
	_, err = r.st.Write(b)
	return err
}

// writeFin writes a final message and closes the send side.
func (r *reqStream) writeFin(t uint64, m appender) error {
	b, err := wire.AppendMessage(nil, t, m.Append(nil))
	if err != nil {
		return err
	}
	r.wmu.Lock()
	defer r.wmu.Unlock()
	if _, err := r.st.Write(b); err != nil {
		return err
	}
	return r.st.Close()
}

func (r *reqStream) read(max int) (uint64, []byte, error) { return wire.ReadMessage(r.br, max) }

func (r *reqStream) cancel(code uint64) {
	r.st.CancelRead(code)
	r.st.CancelWrite(code)
}

// stopped reports whether the peer sent STOP_SENDING for our side, by a
// zero-length write; it skips the check while a message is being written.
func (r *reqStream) stopped() bool {
	if !r.wmu.TryLock() {
		return false
	}
	defer r.wmu.Unlock()
	_, err := r.st.Write(nil)
	return err != nil
}

// streamCode returns the reset code of a stream error, if it is one.
func streamCode(err error) (uint64, bool) {
	var te *kolotransport.Error
	if errors.As(err, &te) && errors.Is(te, kolotransport.ErrStreamReset) {
		return te.Code, true
	}
	return 0, false
}

// readFirst reads the first message of a request stream within the
// request timeout.
func (s *Session) readFirst(r *reqStream) (uint64, []byte, error) {
	r.st.SetReadDeadline(time.Now().Add(s.cfg.RequestTimeout))
	defer r.st.SetReadDeadline(time.Time{})
	return r.read(s.cfg.MaxControlMessageSize)
}

// interruptOnDone sets a read deadline in the past once ctx is done. The
// returned stop clears the deadline and guarantees it is not set later.
func interruptOnDone(ctx context.Context, setDeadline func(time.Time) error) (stop func()) {
	var mu sync.Mutex
	stopped := false
	unregister := context.AfterFunc(ctx, func() {
		mu.Lock()
		defer mu.Unlock()
		if !stopped {
			setDeadline(time.Now())
		}
	})
	return func() {
		unregister()
		mu.Lock()
		stopped = true
		mu.Unlock()
		setDeadline(time.Time{})
	}
}

// requestGoAway checks a GOAWAY on a request stream (draft section 9.2): a
// client sends no URI and a stream carries one GOAWAY. It closes the session
// and reports false when the message breaks either rule; seen counts the
// GOAWAYs of the stream.
func (s *Session) requestGoAway(body []byte, seen *int) bool {
	m, err := wire.ParseGoAway(body)
	if err != nil {
		s.fail(sessionCode(err), ErrProtocol)
		return false
	}
	if (!s.client && m.URI != "") || *seen > 0 {
		s.fail(CodeProtocolViolation, ErrProtocol)
		return false
	}
	*seen++
	return true
}

// protocolErr closes the session for a decoding error from the peer.
func (s *Session) protocolErr(err error) {
	var we *wire.Error
	if errors.As(err, &we) {
		s.fail(SessionCode(we.Code), ErrProtocol)
	}
}
