package kolomoq

import (
	"container/list"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// RelayConfig sets a Relay. A zero field takes its default.
type RelayConfig struct {
	// Session configures every session of the relay; its Origin must be nil.
	// Its Authorize hook decides PUBLISH_NAMESPACE from publishers and every
	// request from subscribers.
	Session Config
	// MaxCacheBytes caps the memory of all relayed tracks together: their cached bytes, counted as for CacheBytes, and 50 KiB for each track itself (measured, see docs/limits.md).
	// A SUBSCRIBE that would open a track beyond the budget or the session's share is refused with EXCESSIVE_LOAD; a cache that grows past either drops its oldest objects, the newest included, so a late joiner or a FETCH finds less while live subscribers still get every object.
	// There is no cap on the number of tracks. Default 1 GiB, at least CacheBytes plus 50 KiB.
	MaxCacheBytes int64
	// MaxSessionCacheBytes caps what the tracks one session opened may hold of MaxCacheBytes, so one session cannot take it all. Its share is MaxCacheBytes divided by the sessions with tracks open, but at least what one track can hold (CacheBytes plus 50 KiB) and at most this.
	// Default a tenth of MaxCacheBytes, or CacheBytes plus 50 KiB if larger, from CacheBytes plus 50 KiB to MaxCacheBytes.
	MaxSessionCacheBytes int64
	// MaxSessionFetches caps the FETCHes of one session the relay forwards to publishers at once; more are refused with EXCESSIVE_LOAD. Default 16, from 1 to 1000000.
	MaxSessionFetches int
	// CacheGroups and CacheBytes bound the cache of each relayed track, as in TrackOptions. Defaults 16 groups and 32 MiB.
	CacheGroups int
	CacheBytes  int64
	// Resume lets a publisher come back after its connection is lost. When a session ends because the connection
	// failed or the peer called Suspend, not because a side closed it, its announcements are held, so subscribers do
	// not see the publisher leave. While held, no other peer may announce the namespace or one under it, and no
	// request under it goes to another peer. A new session of the same peer that announces the namespace takes over
	// and closes the older one if it still runs. A hold ends when Resume is over or the session closes cleanly. Zero,
	// the default, withdraws the announcements with the session. From 1s to 1h.
	Resume time.Duration
	// MaxResumeHeld caps the announcements held at once for sessions that ended. A session whose announcements do not
	// fit loses them with the session, as without Resume, so a flood of short sessions cannot push out the holds of
	// others. Default 10000, ten times the default MaxRequests, from 1 to 1000000. It counts only with Resume.
	MaxResumeHeld int
	// MaxPeerResumeHeld caps the announcements held for one peer key, so one key cannot fill MaxResumeHeld. Default
	// the Session's MaxRequests, the most announcements one session can have, or MaxResumeHeld if that is lower;
	// from 1 to MaxResumeHeld. It counts only with Resume.
	MaxPeerResumeHeld int
}

// Relay forwards tracks from publishers to many subscribers. Publishers
// announce namespaces with PUBLISH_NAMESPACE; a SUBSCRIBE for a track under
// such a namespace opens one upstream subscription to the publisher, shared
// by every subscriber of the track and cached for FETCH and late joiners.
// The upstream subscription ends when the last subscriber leaves; when the
// publisher ends the track or goes away, subscribers get PUBLISH_DONE.
type Relay struct {
	cfg RelayConfig

	mu       sync.Mutex
	announce map[*announcement]struct{}
	seq      uint64
	tracks   map[string]*relayTrack // the current instance of each track
	openers  map[*Session]*opener   // sessions with relayed tracks, ended ones included
	cached   atomic.Int64           // bytes charged to MaxCacheBytes
	nOpeners atomic.Int64           // len(openers), for the lock-free share
	watchers map[*nsWatcher]struct{}
	held     *list.List     // announcements kept for ended sessions, oldest first
	heldBy   map[string]int // held announcements per peer key
}

// announcement is a namespace a publisher announced. While it is held for Resume, s is nil: the ended Session is not
// kept. Fields after seq are guarded by Relay.mu.
type announcement struct {
	s    *Session
	peer ed25519.PublicKey
	ns   Namespace
	seq  uint64

	elem  *list.Element // in Relay.held while held
	timer *time.Timer   // ends the hold
	gone  bool          // released
}

// relayTrackOverhead is the heap one relayed track costs beyond its cached objects: its upstream and downstream
// subscriptions and their goroutines, 50,000 bytes measured by TestMeasureRelayHeap.
const relayTrackOverhead = 50 << 10

// opener is what the SUBSCRIBEs of one session opened.
type opener struct {
	tracks int          // relayed tracks still counted; guarded by Relay.mu
	bytes  atomic.Int64 // their charge against MaxCacheBytes
}

// cacheAcct charges one relayed track to the relay's budget and to the session that opened it.
type cacheAcct struct {
	r *Relay
	o *opener

	mu   sync.Mutex
	held int64
	done bool // released: later charges are ignored
}

// charge adds delta to the track's charge and returns how many bytes the relay or the session is now over its budget.
func (a *cacheAcct) charge(delta int64) int64 {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.done {
		return 0
	}
	a.held += delta
	total, mine := a.r.cached.Add(delta), a.o.bytes.Add(delta)
	return max(total-a.r.cfg.MaxCacheBytes, mine-a.r.share(int(a.r.nOpeners.Load())), 0)
}

func (a *cacheAcct) release() {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.done = true
	a.r.cached.Add(-a.held)
	a.o.bytes.Add(-a.held)
	a.held = 0
}

// share returns the bytes of MaxCacheBytes one of n sessions may use. Callers pass the nOpeners atomic, so admission and eviction agree.
func (r *Relay) share(n int) int64 {
	return min(r.cfg.MaxSessionCacheBytes, max(r.cfg.MaxCacheBytes/int64(max(n, 1)), r.cfg.CacheBytes+relayTrackOverhead))
}

// relayTrack is a track relayed from one publisher session.
type relayTrack struct {
	r      *Relay
	key    string
	opener *Session
	ready  chan struct{}
	err    error

	forwarding atomic.Bool // a new group request is on its way upstream

	// Guarded by r.mu.
	refs    int
	counted bool
	acct    *cacheAcct
	t       *track
	up      *Subscription
}

// NewRelay returns a Relay with no sessions.
func NewRelay(cfg *RelayConfig) (*Relay, error) {
	var c RelayConfig
	if cfg != nil {
		c = *cfg
	}
	if c.Session.Origin != nil {
		return nil, fmt.Errorf("%w: a relay session has no Origin", ErrInvalidConfig)
	}
	var err error
	if c.Session, err = c.Session.resolve(); err != nil {
		return nil, err
	}
	if err := (limit[int]{"MaxSessionFetches", 16, 1, 1_000_000}).apply(&c.MaxSessionFetches); err != nil {
		return nil, err
	}
	if err := (limit[int]{"CacheGroups", 16, 1, 1_000_000}).apply(&c.CacheGroups); err != nil {
		return nil, err
	}
	if err := (limit[int64]{"CacheBytes", 32 << 20, 1 << 10, maxBudgetBytes}).apply(&c.CacheBytes); err != nil {
		return nil, err
	}
	if err := (limit[int64]{"MaxCacheBytes", max(1<<30, c.CacheBytes+relayTrackOverhead), c.CacheBytes + relayTrackOverhead, maxBudgetBytes}).apply(&c.MaxCacheBytes); err != nil {
		return nil, err
	}
	if err := (limit[int64]{"MaxSessionCacheBytes", max(c.MaxCacheBytes/10, c.CacheBytes+relayTrackOverhead), c.CacheBytes + relayTrackOverhead, c.MaxCacheBytes}).apply(&c.MaxSessionCacheBytes); err != nil {
		return nil, err
	}
	if c.Resume != 0 && (c.Resume < time.Second || c.Resume > time.Hour) {
		return nil, fmt.Errorf("%w: Resume %v out of range [1s, 1h]", ErrInvalidConfig, c.Resume)
	}
	if err := (limit[int]{"MaxResumeHeld", 10_000, 1, 1_000_000}).apply(&c.MaxResumeHeld); err != nil {
		return nil, err
	}
	if err := (limit[int]{"MaxPeerResumeHeld", min(c.Session.MaxRequests, c.MaxResumeHeld), 1, c.MaxResumeHeld}).apply(&c.MaxPeerResumeHeld); err != nil {
		return nil, err
	}
	return &Relay{
		cfg:      c,
		announce: map[*announcement]struct{}{},
		tracks:   map[string]*relayTrack{},
		openers:  map[*Session]*opener{},
		watchers: map[*nsWatcher]struct{}{},
		held:     list.New(),
		heldBy:   map[string]int{},
	}, nil
}

// NewServer starts a relay session as the MoQT server on a Conn this side
// accepted, as the package-level NewServer.
func (r *Relay) NewServer(ctx context.Context, conn Conn) (*Session, error) {
	return newSession(ctx, conn, r.sessionConfig(), false)
}

// NewClient starts a relay session as the MoQT client on a Conn this side
// dialed, as the package-level NewClient.
func (r *Relay) NewClient(ctx context.Context, conn Conn) (*Session, error) {
	return newSession(ctx, conn, r.sessionConfig(), true)
}

func (r *Relay) sessionConfig() *Config {
	c := r.cfg.Session
	c.src = r
	return &c
}

// errUpstream asks the session to forward a FETCH or TRACK_STATUS for a
// track the relay does not hold to publisher s.
type errUpstream struct {
	s *Session
	r *Relay
}

func (errUpstream) Error() string { return "kolomoq: forward upstream" }

// reserved reports whether a still stands for its publisher: its session runs, or Resume keeps it for one that ended.
func (r *Relay) reserved(a *announcement) bool {
	return a.s == nil || r.cfg.Resume > 0 || a.s.ctx.Err() == nil
}

// usable reports whether requests can go to a's session. A session that received GOAWAY takes no new request (draft
// section 9.2), so a publisher that moved to a new session is reached there (section 7.6.1).
func (a *announcement) usable() bool {
	return a.s != nil && a.s.ctx.Err() == nil && !a.s.goawayReceived()
}

// publisher returns the session that announced the longest namespace prefix of ns, other than the asking session, the
// newest announcement on a tie. When that announcement cannot serve, because it is held for a publisher that is away
// or its session received GOAWAY, only a session of the same peer takes the request: a namespace is reserved for its
// publisher, so a wider announcement of another peer does not catch the tracks under it.
func (r *Relay) publisher(asker *Session, ns Namespace) *Session {
	pick := func(ok func(*announcement) bool) *announcement {
		var best *announcement
		for a := range r.announce {
			if a.s == asker || !ns.HasPrefix(a.ns) || !ok(a) {
				continue
			}
			if best == nil || len(a.ns) > len(best.ns) || (len(a.ns) == len(best.ns) && a.seq > best.seq) {
				best = a
			}
		}
		return best
	}
	best := pick(r.reserved)
	switch {
	case best == nil:
		return nil
	case best.usable():
		return best.s
	}
	if alt := pick(func(a *announcement) bool { return a.usable() && a.peer.Equal(best.peer) }); alt != nil {
		return alt.s
	}
	return nil
}

func (*Relay) servesKeys() bool { return false }

func (r *Relay) acquire(ctx context.Context, s *Session, kind RequestKind, ns Namespace, name string) (*track, error) {
	key := trackKey(ns, name)
	r.mu.Lock()
	rt := r.tracks[key]
	if rt == nil {
		pub := r.publisher(s, ns)
		switch {
		case pub == nil:
			r.mu.Unlock()
			return nil, &RequestError{Code: ReqDoesNotExist}
		case kind != KindSubscribe:
			r.mu.Unlock()
			return nil, errUpstream{pub, r}
		case !r.admit(s):
			r.mu.Unlock()
			return nil, &RequestError{Code: ReqExcessiveLoad}
		}
		o := r.openers[s]
		if o == nil {
			o = &opener{}
			r.openers[s] = o
			r.nOpeners.Add(1)
		}
		o.tracks++
		rt = &relayTrack{r: r, key: key, opener: s, ready: make(chan struct{}), counted: true, acct: &cacheAcct{r: r, o: o}}
		rt.acct.charge(relayTrackOverhead)
		r.tracks[key] = rt
		go rt.open(pub, ns, name)
	}
	rt.refs++
	r.mu.Unlock()
	select {
	case <-rt.ready:
	case <-ctx.Done():
		r.releaseRT(rt)
		return nil, ctx.Err()
	}
	if rt.err != nil {
		r.releaseRT(rt)
		return nil, rt.err
	}
	return rt.t, nil
}

// admit reports whether the relay's budget and the share of s have room for one more track. Called with r.mu held.
func (r *Relay) admit(s *Session) bool {
	if r.cached.Load()+relayTrackOverhead > r.cfg.MaxCacheBytes {
		return false
	}
	o := r.openers[s]
	return o == nil || o.bytes.Load()+relayTrackOverhead <= r.share(int(r.nOpeners.Load()))
}

// open subscribes upstream; the relay joins at the current group so late
// subscribers can fill from its cache.
func (rt *relayTrack) open(pub *Session, ns Namespace, name string) {
	defer close(rt.ready)
	ctx, cancel := context.WithTimeout(pub.ctx, pub.cfg.RequestTimeout)
	defer cancel()
	sink := &relaySink{rt: rt, pub: pub}
	up, err := pub.subscribe(ctx, ns, name, &SubscribeOptions{Priority: DefaultPriority, Join: JoinCurrentGroup}, sink)
	if err != nil {
		var re *RequestError
		if !errors.As(err, &re) {
			re = &RequestError{Code: ReqInternalError}
			if errors.Is(err, ErrTimeout) || errors.Is(err, context.DeadlineExceeded) {
				re.Code = ReqTimeout
			}
		}
		sink.discard()
		rt.fail(re)
		return
	}
	t, err := relayedTrack(ns, name, up, rt.r.cfg)
	if err != nil {
		rt.drop(sink, up, &RequestError{Code: ReqInternalError})
		return
	}
	t.relay, t.acct = rt, rt.acct
	rt.r.mu.Lock()
	if rt.refs == 0 {
		// Every subscriber gave up while the upstream subscription opened:
		// nobody will release it, so close it here. A track retired, or whose
		// upstream subscription already ended, still serves the subscribers
		// that found it; they release it.
		rt.r.mu.Unlock()
		rt.drop(sink, up, &RequestError{Code: ReqInternalError})
		return
	}
	rt.t, rt.up = t, up
	rt.r.mu.Unlock()
	sink.ready(t)
	// The upstream fills the current group; serve it to subscribers only
	// once it is cached (draft section 7.6).
	if _, ok := up.Largest(); ok {
		select {
		case <-up.fillDone:
		case <-ctx.Done():
		}
	}
}

// forwardNewGroup passes a subscriber's request for a new group to the publisher on the upstream subscription,
// off the caller's goroutine and one at a time; the upstream subscription limits how often one goes out.
func (rt *relayTrack) forwardNewGroup() {
	rt.r.mu.Lock()
	up := rt.up
	rt.r.mu.Unlock()
	if up == nil || !rt.forwarding.CompareAndSwap(false, true) {
		return
	}
	if !up.s.start(func() {
		defer rt.forwarding.Store(false)
		up.RequestNewGroup(up.s.ctx)
	}) {
		rt.forwarding.Store(false)
	}
}

func (rt *relayTrack) fail(err error) {
	rt.err = err
	rt.detach()
}

// drop closes an upstream subscription no subscriber is waiting for.
func (rt *relayTrack) drop(sink *relaySink, up *Subscription, err error) {
	sink.discard()
	up.Close()
	rt.fail(err)
}

// malformed cancels the upstream subscription of a track the cache found
// malformed; the track already ended with MALFORMED_TRACK.
func (rt *relayTrack) malformed() {
	rt.detach()
	rt.r.mu.Lock()
	up := rt.up
	rt.r.mu.Unlock()
	if up != nil {
		up.fail(ErrMalformedTrack)
	}
}

// detach removes the track from the relay, so the next SUBSCRIBE opens a
// new upstream subscription.
func (rt *relayTrack) detach() {
	rt.r.mu.Lock()
	rt.r.removeLocked(rt)
	rt.r.mu.Unlock()
}

// retire takes a track the publisher ended out of the relay, so the next
// SUBSCRIBE opens the instance the publisher has now; its subscribers keep
// it, and it counts against the limits, until its upstream subscription ends.
func (rt *relayTrack) retire() {
	rt.r.mu.Lock()
	if rt.r.tracks[rt.key] == rt {
		delete(rt.r.tracks, rt.key)
	}
	rt.r.mu.Unlock()
}

// removeLocked takes rt out of the relay and out of the counts. Called with
// r.mu held.
func (r *Relay) removeLocked(rt *relayTrack) {
	if r.tracks[rt.key] == rt {
		delete(r.tracks, rt.key)
	}
	if !rt.counted {
		return
	}
	rt.counted = false
	rt.acct.release()
	o := r.openers[rt.opener]
	if o.tracks--; o.tracks == 0 {
		delete(r.openers, rt.opener)
		r.nOpeners.Add(-1)
	}
}

// relayedTrack builds the relay's copy of an upstream track, keeping every
// track property the publisher sent.
func relayedTrack(ns Namespace, name string, up *Subscription, cfg RelayConfig) (*track, error) {
	t, err := newTrack(ns, name, &TrackOptions{Priority: DefaultPriority, CacheGroups: cfg.CacheGroups, CacheBytes: cfg.CacheBytes}, cfg.Session.MaxObjectSize)
	if err != nil {
		return nil, err
	}
	t.props = toKVs(up.props)
	t.prio, t.order, t.objTimeout, t.sgTimeout = up.trackPrio, OrderAscending, up.pubObj, up.pubSg
	for _, kv := range t.props {
		if kv.Type == propDefaultOrder {
			t.order = GroupOrder(kv.Value)
		}
	}
	if l, ok := up.Largest(); ok {
		t.largest, t.hasLargest = wire.Location(l), true
	}
	return t, nil
}

func (r *Relay) release(t *track) {
	if t.relay != nil {
		r.releaseRT(t.relay)
	}
}

// releaseRT drops one reference; the last one ends the upstream
// subscription.
func (r *Relay) releaseRT(rt *relayTrack) {
	r.mu.Lock()
	rt.refs--
	last := rt.refs == 0
	if last {
		r.removeLocked(rt)
	}
	up := rt.up
	r.mu.Unlock()
	if last && up != nil {
		up.Close()
	}
}

// relaySink feeds upstream objects into the relay's track. Events that
// arrive before SUBSCRIBE_OK is processed wait in pending, within
// MaxBufferedBytes.
type relaySink struct {
	rt  *relayTrack
	pub *Session

	mu      sync.Mutex
	t       *track
	dead    bool
	pending []func(*track)
	held    int64
}

// ready replays the events that waited for the track. New events keep
// queueing behind them until the queue is empty, so the order of the
// upstream is kept.
func (k *relaySink) ready(t *track) {
	for {
		k.mu.Lock()
		pending := k.pending
		if len(pending) == 0 {
			k.t = t
			k.mu.Unlock()
			return
		}
		k.pending, k.held = nil, 0
		k.mu.Unlock()
		for _, f := range pending {
			f(t)
		}
	}
}

// discard drops pending events after the upstream subscription failed.
func (k *relaySink) discard() {
	k.mu.Lock()
	k.dead, k.pending, k.held = true, nil, 0
	k.mu.Unlock()
}

func (k *relaySink) do(cost int64, f func(*track)) {
	k.mu.Lock()
	t := k.t
	if t == nil {
		if k.dead || k.held+cost > k.rt.r.cfg.Session.MaxBufferedBytes {
			k.mu.Unlock()
			return
		}
		k.held += cost
		k.pending = append(k.pending, f)
	}
	k.mu.Unlock()
	if t != nil {
		f(t)
	}
}

func (k *relaySink) object(o *wire.Object, first bool) {
	c := newCobj(*o, first)
	k.do(c.size(), func(t *track) {
		if c.Status == wire.StatusEndOfTrack {
			// Retire before the end is cached: a SUBSCRIBE that sees it opens the next instance.
			k.rt.retire()
		}
		if len(c.Payload) <= t.maxObject && !t.add(c) {
			k.rt.malformed()
		}
	})
}

func (k *relaySink) endSubgroup(group, subgroup, last uint64, endOfGroup, reset bool) {
	k.do(objectOverhead, func(t *track) {
		if reset {
			t.resetSubgroup(group, subgroup)
		} else if !t.endSubgroup(group, subgroup, last, endOfGroup) {
			k.rt.malformed()
		}
	})
}

// publishDone retires the track as soon as PUBLISH_DONE arrives, before the
// streams it still announces.
func (k *relaySink) publishDone() { k.rt.retire() }

// doneCode is the PUBLISH_DONE status a relay gives its subscribers when the
// upstream subscription ended with err: the publisher's own status, a
// malformed track (draft section 12.1), GOING_AWAY once a GOAWAY was sent or
// received on the publisher's session or on the subscription's request stream
// (section 12.4), or an internal error.
func (k *relaySink) doneCode(err error, goaway bool) DoneCode {
	var pd *PublishDoneError
	switch {
	case errors.As(err, &pd):
		return pd.Code
	case errors.Is(err, io.EOF):
		return DoneTrackEnded
	case errors.Is(err, ErrMalformedTrack):
		return DoneMalformedTrack
	case goaway || k.pub.goneAway():
		return DoneGoingAway
	}
	return DoneInternalError
}

// done ends the relayed track with the status the upstream subscription
// ended with. When the relay gave the subscription up itself, the track has
// no subscriber left and has already left the relay.
func (k *relaySink) done(err error, goaway bool) {
	code := k.doneCode(err, goaway)
	k.rt.detach()
	k.do(0, func(t *track) { t.end(code) })
}

func (r *Relay) watchNamespaces(prefix Namespace, fn func(Namespace, bool)) ([]Namespace, func()) {
	w := &nsWatcher{prefix: prefix, fn: fn}
	r.mu.Lock()
	defer r.mu.Unlock()
	seen := map[string]bool{}
	var initial []Namespace
	for a := range r.announce {
		if k := a.ns.key(); !seen[k] && a.ns.HasPrefix(prefix) {
			seen[k] = true
			initial = append(initial, a.ns)
		}
	}
	r.watchers[w] = struct{}{}
	return initial, func() {
		r.mu.Lock()
		delete(r.watchers, w)
		r.mu.Unlock()
	}
}

func (r *Relay) announced(ns Namespace) int {
	n := 0
	k := ns.key()
	for a := range r.announce {
		if a.ns.key() == k {
			n++
		}
	}
	return n
}

func (r *Relay) notify(ns Namespace, active bool) {
	for w := range r.watchers {
		if ns.HasPrefix(w.prefix) {
			w.fn(ns, active)
		}
	}
}

// publishNamespace records an announcement. Another peer may not announce a namespace equal to or under one already
// announced, held ones included, so it cannot take over that publisher's tracks; the empty namespace, which would take
// every track of the relay, is refused. A peer that announces a namespace again takes over its own held announcement of
// it, and closes its older session that still runs, whatever another peer announced in the meantime.
func (r *Relay) publishNamespace(s *Session, ns Namespace) (func(), error) {
	if len(ns) == 0 {
		return nil, &RequestError{Code: ReqUnauthorized}
	}
	r.mu.Lock()
	var older []*Session
	var ended []*announcement
	key := ns.key()
	if r.cfg.Resume > 0 {
		for a := range r.announce {
			if a.s == s || !a.peer.Equal(s.peer) || a.ns.key() != key {
				continue
			}
			switch {
			case a.s == nil || a.s.ctx.Err() != nil:
				ended = append(ended, a)
			case !slices.Contains(older, a.s):
				older = append(older, a.s)
			}
		}
	}
	if len(ended) == 0 && len(older) == 0 {
		for a := range r.announce {
			if ns.HasPrefix(a.ns) && !a.peer.Equal(s.peer) && r.reserved(a) {
				r.mu.Unlock()
				return nil, &RequestError{Code: ReqUnauthorized}
			}
		}
	}
	r.seq++
	a := &announcement{s: s, peer: s.peer, ns: ns, seq: r.seq}
	first := r.announced(ns) == 0
	r.announce[a] = struct{}{}
	for _, e := range ended {
		r.dropLocked(e)
	}
	if first {
		r.notify(ns, true)
	}
	r.mu.Unlock()
	for _, o := range older {
		o.fail(CodeNoError, ErrClosed)
	}
	return func() {
		if r.cfg.Resume > 0 && s.connLost(connEndWait) && r.hold(a) {
			return
		}
		r.withdraw(a)
	}, nil
}

// hold keeps a, whose session ended with its connection lost, for Resume, without the ended session; false means the
// caps leave no room and the caller withdraws it.
func (r *Relay) hold(a *announcement) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a.gone {
		return true
	}
	pk := string(a.peer)
	if r.held.Len() >= r.cfg.MaxResumeHeld || r.heldBy[pk] >= r.cfg.MaxPeerResumeHeld {
		return false
	}
	a.s = nil
	a.elem = r.held.PushBack(a)
	r.heldBy[pk]++
	a.timer = time.AfterFunc(r.cfg.Resume, func() { r.withdraw(a) })
	return true
}

// withdraw removes a and tells the namespace watchers when no announcement of its namespace is left.
func (r *Relay) withdraw(a *announcement) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if a.gone {
		return
	}
	r.dropLocked(a)
	if r.announced(a.ns) == 0 {
		r.notify(a.ns, false)
	}
}

// dropLocked removes a from the relay and ends its hold. Called with r.mu held.
func (r *Relay) dropLocked(a *announcement) {
	a.gone = true
	delete(r.announce, a)
	if a.elem == nil {
		return
	}
	r.held.Remove(a.elem)
	pk := string(a.peer)
	if r.heldBy[pk]--; r.heldBy[pk] == 0 {
		delete(r.heldBy, pk)
	}
	a.timer.Stop()
}

// connEndWait is how long a withdrawn announcement waits to learn whether its session's connection was lost: the request
// stream fails a moment before the connection records why.
const connEndWait = 250 * time.Millisecond

// errFetchBuffer means a forwarded fetch outgrew MaxFetchBytes.
var errFetchBuffer = errors.New("kolomoq: forwarded fetch over MaxFetchBytes")

// forwardFetch answers a FETCH for a track the relay does not hold with a
// FETCH to the publisher, passing its objects through. The publisher's
// session is shared, so the relay reads the answer at once into a buffer
// within MaxFetchBytes and resets the fetch when the subscriber falls further
// behind. It asks with the lowest priority, not the subscriber's (section
// 5.1.3). One session forwards at most max fetches.
func (s *Session) forwardFetch(r *reqStream, m *wire.Request, pub *Session, max int) {
	s.mu.Lock()
	full := s.forwarded >= max
	if !full {
		s.forwarded++
	}
	s.mu.Unlock()
	if full {
		s.reject(r, ReqExcessiveLoad, "too many forwarded fetches")
		return
	}
	defer func() {
		s.mu.Lock()
		s.forwarded--
		s.mu.Unlock()
	}()
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	stopPub := context.AfterFunc(pub.ctx, cancel)
	defer stopPub()
	id, err := pub.newRequestID()
	if err != nil {
		s.reject(r, ReqInternalError, "")
		return
	}
	prm := &wire.MessageParams{}
	for _, t := range []uint64{wire.ParamLocationFilter, wire.ParamGroupOrder} {
		if m.Params.Has(t) {
			prm.Set(t)
		}
	}
	prm.Filter, prm.GroupOrder = m.Params.Filter, m.Params.GroupOrder
	// The lowest priority: the relay's live subscriptions on the shared
	// publisher session go first (section 5.1.3 leaves the value to the relay).
	prm.Set(wire.ParamSubscriberPriority)
	prm.SubscriberPriority = 255
	upCtx, upCancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	f, err := pub.fetch(upCtx, id, m.Namespace, m.Name, prm, nil)
	upCancel()
	if err != nil {
		var re *RequestError
		if errors.As(err, &re) {
			s.reject(r, re.Code, "")
		} else {
			s.reject(r, ReqInternalError, "")
		}
		return
	}
	in := &fetchBuffer{s: s, wake: make(chan struct{}, 1), stop: cancel}
	pulled := make(chan struct{})
	go func() {
		defer close(pulled)
		in.pull(ctx, f)
	}()
	defer func() {
		cancel()
		f.Close()
		<-pulled
		in.drop()
	}()
	props := f.rawProps
	if m.Params.Has(wire.ParamIncludeProperties) && m.Params.IncludeProperties == 0 {
		props = nil
	}
	if err := r.write(wire.MsgFetchOK, &wire.FetchOK{EndOfTrack: f.eot, End: wire.Location(f.end), Params: &wire.MessageParams{}, Properties: props}); err != nil {
		s.writeFailed(r, err)
		return
	}
	order := OrderAscending
	if f.desc {
		order = OrderDescending
	}
	prio := uint8(DefaultPriority)
	if m.Params.Has(wire.ParamSubscriberPriority) {
		prio = m.Params.SubscriberPriority
	}
	st, err := s.conn.OpenUniStream(ctx)
	if err != nil {
		r.cancel(resetCancelled)
		return
	}
	stop := context.AfterFunc(ctx, func() { st.CancelWrite(resetCancelled) })
	defer stop()
	readDone := make(chan struct{})
	defer func() {
		r.st.CancelRead(resetCancelled)
		<-readDone
	}()
	go func() {
		defer close(readDone)
		// The requester resets the request to cancel it.
		if _, _, err := r.read(s.cfg.MaxControlMessageSize); err != io.EOF {
			cancel()
		}
	}()
	buf := wire.AppendVarint(wire.AppendVarint(nil, wire.StreamTypeFetch), m.RequestID)
	w := wire.FetchWriter{Descending: f.desc}
	fail := func(err error, sending bool) {
		code, req := resetCode(ctx, err), uint64(resetCancelled)
		switch {
		case in.overflowed():
			code = resetExcessiveLoad
		case errors.Is(err, ErrMalformedTrack):
			// A relay that finds a track malformed resets the fetch (draft section 12.1).
			code, req = resetMalformedTrack, resetMalformedTrack
		case !sending:
			code = resetUnknownStatus
		}
		st.CancelWrite(code)
		r.cancel(req)
	}
	var q sendQueue
	key := sendKey{sub: prio, order: order}
	for {
		fo, err := in.next(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(err, false)
			return
		}
		key.group = fo.Group
		if fo.EndOfRange != 0 {
			buf = w.AppendEndOfRange(buf, fo.EndOfRange, wire.Location{Group: fo.Group, Object: fo.ID})
		} else {
			buf = w.Append(buf, &fo.Object)
			key.pub, key.subgroup = fo.Priority, fo.Subgroup
		}
		if _, err := s.send(ctx, &q, key, st, buf, time.Time{}); err != nil {
			fail(err, true)
			return
		}
		buf = buf[:0]
	}
	if len(buf) > 0 {
		if _, err := s.send(ctx, &q, key, st, buf, time.Time{}); err != nil {
			fail(err, true)
			return
		}
	}
	st.Close()
	r.wmu.Lock()
	r.st.Close()
	r.wmu.Unlock()
}

// fetchBuffer holds the entries of a forwarded fetch the subscriber has not
// taken yet, counted against the subscriber session's MaxFetchBytes.
type fetchBuffer struct {
	s    *Session
	wake chan struct{}
	stop context.CancelFunc // ends the forwarding at an overflow

	mu    sync.Mutex
	queue []*wire.FetchObject
	bytes int64
	err   error // io.EOF, the upstream's error, or errFetchBuffer
}

// pull reads the upstream fetch until it ends or outgrows the budget.
func (b *fetchBuffer) pull(ctx context.Context, f *Fetch) {
	for {
		fo, err := f.next(ctx)
		var n int64
		if err == nil {
			n = objectSize(&fo.Object)
			if !b.s.reserveFetch(n) {
				err = errFetchBuffer
			}
		}
		b.mu.Lock()
		if err != nil {
			b.err = err
		} else {
			b.queue = append(b.queue, fo)
			b.bytes += n
		}
		b.mu.Unlock()
		select {
		case b.wake <- struct{}{}:
		default:
		}
		if errors.Is(err, errFetchBuffer) {
			// Stop the upstream stream at once: unread data would hold the
			// publisher's connection window.
			f.Close()
			b.stop()
		}
		if err != nil {
			return
		}
	}
}

func (b *fetchBuffer) overflowed() bool {
	b.mu.Lock()
	defer b.mu.Unlock()
	return errors.Is(b.err, errFetchBuffer)
}

// next returns the oldest buffered entry; an overflow ends the fetch at once,
// any other end once the buffer is empty.
func (b *fetchBuffer) next(ctx context.Context) (*wire.FetchObject, error) {
	for {
		b.mu.Lock()
		switch {
		case errors.Is(b.err, errFetchBuffer):
			b.mu.Unlock()
			return nil, b.err
		case len(b.queue) > 0:
			fo := b.queue[0]
			b.queue[0] = nil
			b.queue = b.queue[1:]
			n := objectSize(&fo.Object)
			b.bytes -= n
			b.mu.Unlock()
			b.s.releaseFetch(n)
			return fo, nil
		case b.err != nil:
			b.mu.Unlock()
			return nil, b.err
		}
		b.mu.Unlock()
		select {
		case <-b.wake:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// drop releases what is still buffered; pull has returned.
func (b *fetchBuffer) drop() {
	b.mu.Lock()
	n := b.bytes
	b.queue, b.bytes = nil, 0
	b.mu.Unlock()
	b.s.releaseFetch(n)
}

// forwardTrackStatus answers a TRACK_STATUS for a track the relay does not
// hold by asking the publisher.
func (s *Session) forwardTrackStatus(r *reqStream, m *wire.Request, pub *Session) {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.RequestTimeout)
	defer cancel()
	st, err := pub.TrackStatus(ctx, m.Namespace, m.Name)
	if err != nil {
		var re *RequestError
		if errors.As(err, &re) {
			s.reject(r, re.Code, "")
		} else {
			s.reject(r, ReqInternalError, "")
		}
		return
	}
	props := toKVs(st.Properties)
	if m.Params.Has(wire.ParamIncludeProperties) && m.Params.IncludeProperties == 0 {
		props = nil
	}
	if err := r.writeFin(wire.MsgRequestOK, &wire.RequestOK{Params: largestParam(wire.Location(st.Largest), st.HasLargest), Properties: props}); err != nil {
		s.writeFailed(r, err)
		return
	}
	r.st.CancelRead(resetCancelled)
}
