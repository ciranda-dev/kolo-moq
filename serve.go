package kolomoq

import (
	"context"
	"errors"
	"io"
	"math"
	"os"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// emptySource answers a session without an Origin.
type emptySource struct{}

func (emptySource) acquire(context.Context, *Session, RequestKind, Namespace, string) (*track, error) {
	return nil, &RequestError{Code: ReqDoesNotExist}
}
func (emptySource) release(*track) {}
func (emptySource) watchNamespaces(Namespace, func(Namespace, bool)) ([]Namespace, func()) {
	return nil, func() {}
}
func (emptySource) publishNamespace(*Session, Namespace) (func(), error) { return func() {}, nil }
func (emptySource) servesKeys() bool                                     { return false }

func (s *Session) source() source {
	if s.cfg.src == nil {
		return emptySource{}
	}
	return s.cfg.src
}

// reject answers a request with REQUEST_ERROR and ends the stream.
func (s *Session) reject(r *reqStream, code RequestCode, reason string) {
	r.writeFin(wire.MsgRequestError, &wire.RequestError{Code: uint64(code), Reason: reason})
	r.st.CancelRead(resetCancelled)
}

func requestKind(t uint64) RequestKind {
	switch t {
	case wire.MsgSubscribe:
		return KindSubscribe
	case wire.MsgFetch:
		return KindFetch
	case wire.MsgTrackStatus:
		return KindTrackStatus
	case wire.MsgPublishNamespace:
		return KindPublishNamespace
	case wire.MsgSubscribeNamespace:
		return KindSubscribeNamespace
	}
	return 0
}

// checkTokens closes the session for token aliases: this side announces a
// token cache of 0 bytes (draft section 9.1.3), so it holds no alias.
func (s *Session) checkTokens(p *wire.MessageParams) bool {
	if p == nil {
		return true
	}
	for _, tok := range p.AuthTokens {
		at, err := wire.TokenAliasType(tok)
		switch {
		case err != nil:
			s.protocolErr(err)
			return false
		case at == wire.TokenRegister:
			s.fail(CodeAuthTokenCacheOverflow, ErrProtocol)
			return false
		case at == wire.TokenDelete || at == wire.TokenUseAlias:
			s.fail(CodeUnknownAuthTokenAlias, ErrProtocol)
			return false
		}
	}
	return true
}

func hasRangeFilter(p *wire.MessageParams) bool {
	if p == nil {
		return false
	}
	for _, f := range p.RangeFilters {
		if len(f.Bytes) > 0 {
			return true
		}
	}
	return hasRangeFilter(p.Fill)
}

// reserved reports a namespace the draft makes answer DOES_NOT_EXIST
// (sections 2.4.3 and 6.5).
func reserved(ns Namespace) bool {
	return len(ns) > 0 && (ns[0] == "." || ns[0] == ".session")
}

// keyNamespace reports a namespace under KeyNamespaceField.
func keyNamespace(ns Namespace) bool {
	return len(ns) > 0 && ns[0] == KeyNamespaceField
}

func (s *Session) serveRequest(st *kolotransport.Stream) {
	r := newReqStream(st)
	t, body, err := s.readFirst(r)
	if err != nil {
		var we *wire.Error
		if errors.As(err, &we) {
			s.fail(SessionCode(we.Code), ErrProtocol)
		}
		r.cancel(resetCancelled)
		return
	}
	if !wire.IsRequest(t) {
		s.fail(CodeProtocolViolation, ErrProtocol)
		return
	}
	m, err := wire.ParseRequest(t, body)
	if err != nil {
		s.protocolErr(err)
		return
	}
	if !s.useRequestID(m.RequestID) || !s.checkTokens(m.Params) {
		return
	}
	kind := requestKind(t)
	if kind == 0 {
		s.reject(r, ReqNotSupported, "not supported")
		return
	}
	s.mu.Lock()
	goingAway := s.goawaySent
	s.mu.Unlock()
	ns := Namespace(m.Namespace)
	trackReq := kind == KindSubscribe || kind == KindFetch || kind == KindTrackStatus
	switch {
	case goingAway:
		s.reject(r, ReqGoingAway, "going away")
		return
	case s.cfg.checkName(ns, m.Name, trackReq) != nil:
		s.reject(r, ReqNotSupported, "name exceeds the configured limits")
		return
	case reserved(ns):
		s.reject(r, ReqDoesNotExist, "reserved namespace")
		return
	case keyNamespace(ns) && (kind == KindPublishNamespace || !s.source().servesKeys()):
		s.reject(r, ReqUnauthorized, "reserved namespace")
		return
	case hasRangeFilter(m.Params):
		s.reject(r, ReqInvalidFilter, "range filters are not supported")
		return
	}
	if !s.allowed(kind, ns, m.Name) || (kind == KindSubscribe && m.Params.Has(wire.ParamFillParameters) && !s.allowed(KindFetch, ns, m.Name)) {
		s.reject(r, ReqUnauthorized, "unauthorized")
		return
	}
	switch kind {
	case KindSubscribe:
		s.serveSubscribe(r, m)
	case KindFetch:
		s.serveFetch(r, m)
	case KindTrackStatus:
		s.serveTrackStatus(r, m)
	case KindPublishNamespace:
		s.servePublishNamespace(r, ns)
	case KindSubscribeNamespace:
		s.serveSubscribeNamespace(r, ns)
	}
}

// allowed asks the Authorize hook; a fill of cached objects is a FETCH.
func (s *Session) allowed(kind RequestKind, ns Namespace, track string) bool {
	return s.cfg.Authorize == nil || s.cfg.Authorize(s.peer, kind, ns, track) == nil
}

// acquireTrack resolves a track within the request timeout, answering the
// request on failure.
func (s *Session) acquireTrack(r *reqStream, kind RequestKind, m *wire.Request) *track {
	ctx, cancel := context.WithTimeout(s.ctx, s.cfg.RequestTimeout)
	defer cancel()
	t, err := s.source().acquire(ctx, s, kind, Namespace(m.Namespace), m.Name)
	if err == nil {
		return t
	}
	var re *RequestError
	var up errUpstream
	switch {
	case errors.As(err, &up) && kind == KindFetch:
		s.forwardFetch(r, m, up.s, up.r.cfg.MaxSessionFetches)
	case errors.As(err, &up):
		s.forwardTrackStatus(r, m, up.s)
	case errors.As(err, &re):
		s.reject(r, re.Code, "")
	case ctx.Err() == context.DeadlineExceeded:
		s.reject(r, ReqTimeout, "")
	default:
		s.reject(r, ReqInternalError, "")
	}
	return nil
}

func includeProps(p *wire.MessageParams, t *track) []wire.KV {
	if p.Has(wire.ParamIncludeProperties) && p.IncludeProperties == 0 {
		return nil
	}
	return t.props
}

func largestParam(l wire.Location, has bool) *wire.MessageParams {
	p := &wire.MessageParams{}
	if has {
		p.Set(wire.ParamLargestObject)
		p.Largest = l
	}
	return p
}

func ms(v uint64) time.Duration {
	if v > uint64(math.MaxInt64/int64(time.Millisecond)) {
		return math.MaxInt64
	}
	return time.Duration(v) * time.Millisecond
}

func minTimeout(a, b time.Duration) time.Duration {
	switch {
	case a == 0:
		return b
	case b == 0:
		return a
	}
	return min(a, b)
}

func (s *Session) serveSubscribe(r *reqStream, m *wire.Request) {
	s.mu.Lock()
	full := s.pubSubs >= s.cfg.MaxSubscriptions
	if !full {
		s.pubSubs++
	}
	s.mu.Unlock()
	if full {
		s.reject(r, ReqExcessiveLoad, "too many subscriptions")
		return
	}
	defer func() {
		s.mu.Lock()
		s.pubSubs--
		s.mu.Unlock()
	}()
	t := s.acquireTrack(r, KindSubscribe, m)
	if t == nil {
		return
	}
	p := newPubSub(s, t, r, m)
	largest, has, ok := t.attach(p)
	if !ok && t.relay != nil {
		// A relayed track retires before its end is cached, so this finds the next instance.
		p.cancel()
		s.source().release(t)
		if t = s.acquireTrack(r, KindSubscribe, m); t == nil {
			return
		}
		p = newPubSub(s, t, r, m)
		largest, has, ok = t.attach(p)
	}
	defer s.source().release(t)
	defer p.cancel()
	s.addPub(p)
	defer s.delPub(p)
	if !ok {
		s.reject(r, ReqDoesNotExist, "track ended")
		return
	}
	defer t.detach(p)
	p.mu.Lock()
	p.setFilter(m.Params, largest, has)
	p.mu.Unlock()
	s.mu.Lock()
	p.alias = s.nextAlias
	s.nextAlias++
	s.mu.Unlock()
	okMsg := &wire.SubscribeOK{TrackAlias: p.alias, Params: largestParam(largest, has), Properties: includeProps(m.Params, t)}
	if err := r.write(wire.MsgSubscribeOK, okMsg); err != nil {
		if errors.Is(err, wire.ErrMessageTooLong) {
			s.reject(r, ReqInternalError, "")
			return
		}
		p.cancel()
		p.wait()
		return
	}
	close(p.ready)
	if m.Params.Has(wire.ParamFillParameters) {
		p.mu.Lock()
		plan := p.planFill(m.RequestID, m.Params.Fill, largest, has)
		p.mu.Unlock()
		p.startFill(plan)
	}
	if !s.start(p.readUpdates) {
		close(p.upDone)
		p.cancel()
	}
	p.wait()
}

type sgKey struct{ group, subgroup uint64 }

// pubSub is one subscription this side serves.
type pubSub struct {
	s      *Session
	t      *track
	r      *reqStream
	reqID  uint64
	alias  uint64
	order  GroupOrder
	prio   atomic.Uint32
	ready  chan struct{}
	ctx    context.Context
	cancel context.CancelFunc
	endCh  chan struct{}
	upDone chan struct{}
	q      sendQueue // guarded by the session's gate

	mu         sync.Mutex
	forward    bool
	start      wire.Location
	end        wire.Location
	hasEnd     bool
	objTimeout time.Duration
	sgTimeout  time.Duration
	streams    map[sgKey]*outStream
	dead       map[sgKey]struct{}
	deadFIFO   []sgKey
	queued     int64
	opened     uint64
	writers    int
	ended      bool
	filling    bool
	fillCancel context.CancelCauseFunc
	endCode    DoneCode
	drained    chan struct{}
}

func newPubSub(s *Session, t *track, r *reqStream, m *wire.Request) *pubSub {
	p := &pubSub{
		s: s, t: t, r: r, reqID: m.RequestID, order: t.order,
		ready: make(chan struct{}), endCh: make(chan struct{}), upDone: make(chan struct{}),
		forward: true, streams: map[sgKey]*outStream{}, dead: map[sgKey]struct{}{},
		drained: make(chan struct{}),
	}
	p.ctx, p.cancel = context.WithCancel(s.ctx)
	prm := m.Params
	p.prio.Store(DefaultPriority)
	if prm.Has(wire.ParamSubscriberPriority) {
		p.prio.Store(uint32(prm.SubscriberPriority))
	}
	if prm.Has(wire.ParamGroupOrder) {
		p.order = GroupOrder(prm.GroupOrder)
	}
	if prm.Has(wire.ParamForward) {
		p.forward = prm.Forward == 1
	}
	p.objTimeout = ms(prm.ObjectTimeout)
	p.sgTimeout = ms(prm.SubgroupTimeout)
	return p
}

// setFilter applies a subscription's Location Filter (draft section 9.20.9).
func (p *pubSub) setFilter(prm *wire.MessageParams, largest wire.Location, has bool) {
	if !prm.Has(wire.ParamLocationFilter) {
		return
	}
	f := prm.Filter
	p.hasEnd = false
	switch f.Type {
	case wire.FilterNone:
		p.start = wire.Location{}
	case wire.FilterRelativeStart:
		p.start = wire.Location{Group: relativeGroup(largest, has, f.StartGroup)}
	case wire.FilterAbsoluteStart:
		p.start = wire.Location{Group: f.StartGroup, Object: f.StartObject}
	case wire.FilterGroupEnd:
		p.start = wire.Location{Group: f.StartGroup, Object: f.StartObject}
		p.end, p.hasEnd = wire.Location{Group: f.EndGroup, Object: math.MaxUint64}, true
	case wire.FilterAbsoluteRange:
		p.start = wire.Location{Group: f.StartGroup, Object: f.StartObject}
		p.end, p.hasEnd = wire.Location{Group: f.EndGroup, Object: f.EndObject}, true
	case wire.FilterNextObject:
		p.start = nextObject(largest, has)
	}
}

// relativeGroup returns Largest Object.Group + 1 - n, clamped.
func relativeGroup(largest wire.Location, has bool, n uint64) uint64 {
	next := uint64(0)
	if has {
		next = largest.Group
		if next != math.MaxUint64 {
			next++
		}
	}
	if n > next {
		return 0
	}
	return next - n
}

func nextObject(largest wire.Location, has bool) wire.Location {
	if !has {
		return wire.Location{}
	}
	if largest.Object == math.MaxUint64 {
		return wire.Location{Group: largest.Group + 1}
	}
	return wire.Location{Group: largest.Group, Object: largest.Object + 1}
}

// fetchRange evaluates a Location Filter with the FETCH rules; ok is false
// when the range is empty or starts after Largest Object.
func fetchRange(f *wire.LocationFilter, largest wire.Location, has bool) (start, end wire.Location, ok bool) {
	if !has {
		return start, end, false
	}
	end = largest
	if f != nil {
		switch f.Type {
		case wire.FilterRelativeStart:
			start = wire.Location{Group: relativeGroup(largest, has, f.StartGroup)}
		case wire.FilterAbsoluteStart:
			start = wire.Location{Group: f.StartGroup, Object: f.StartObject}
		case wire.FilterGroupEnd, wire.FilterAbsoluteRange:
			start = wire.Location{Group: f.StartGroup, Object: f.StartObject}
			e := wire.Location{Group: f.EndGroup, Object: math.MaxUint64}
			if f.Type == wire.FilterAbsoluteRange {
				e.Object = f.EndObject
			}
			if e.Less(end) {
				end = e
			}
		case wire.FilterNextObject:
			return start, end, false
		}
	}
	if largest.Less(start) || end.Less(start) {
		return start, end, false
	}
	return start, end, true
}

func (p *pubSub) priority() uint8 { return uint8(p.prio.Load()) }

// backlog returns the payload queued for this subscriber and how long its oldest unsent object has been held.
func (p *pubSub) backlog(now time.Time) (bytes int64, oldest time.Duration) {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, st := range p.streams {
		at := st.sending
		if at.IsZero() && len(st.queue) > 0 {
			at = st.queue[0].at
		}
		if !at.IsZero() {
			oldest = max(oldest, now.Sub(at))
		}
	}
	return p.queued, oldest
}

// offer queues o for this subscriber; it never blocks. Called with the
// track locked.
func (p *pubSub) offer(o *cobj) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended || p.ctx.Err() != nil {
		return
	}
	key := sgKey{o.Group, o.Subgroup}
	loc := wire.Location{Group: o.Group, Object: o.ID}
	if !p.forward {
		if st := p.streams[key]; st != nil {
			st.kill(resetCancelled)
		}
		return
	}
	if loc.Less(p.start) || (p.hasEnd && p.end.Less(loc)) {
		return
	}
	if _, dead := p.dead[key]; dead {
		return
	}
	st := p.streams[key]
	if st == nil {
		if p.r.stopped() {
			p.cancel()
			return
		}
		if st = p.newStream(key, o); st == nil {
			return
		}
	} else if o.ID <= st.last {
		// A subgroup stream carries increasing IDs; an object that arrives late
		// (a repeat or an older one) cannot join it.
		return
	}
	st.last = o.ID
	st.queue = append(st.queue, o)
	p.queued += o.size()
	st.signal()
	p.enforceLimits()
}

// enforceLimits resets the oldest groups while the queue is over its
// bounds, so a slow subscriber holds bounded memory. Every open subgroup
// stream counts toward MaxBufferedGroups.
func (p *pubSub) enforceLimits() {
	for p.queued > p.s.cfg.MaxBufferedBytes || len(p.streams) > p.s.cfg.MaxBufferedGroups {
		oldest, found := uint64(0), false
		for k := range p.streams {
			if !found || k.group < oldest {
				oldest, found = k.group, true
			}
		}
		if !found {
			return
		}
		for k, st := range p.streams {
			if k.group == oldest {
				st.kill(resetExcessiveLoad)
			}
		}
		p.s.resetGroups.Add(1)
	}
}

// markDead keeps a subgroup from being reopened; the set holds the most
// recent 2*MaxBufferedGroups subgroups.
func (p *pubSub) markDead(key sgKey) {
	if _, ok := p.dead[key]; ok {
		return
	}
	p.dead[key] = struct{}{}
	p.deadFIFO = append(p.deadFIFO, key)
	if len(p.deadFIFO) > 2*p.s.cfg.MaxBufferedGroups {
		delete(p.dead, p.deadFIFO[0])
		p.deadFIFO = p.deadFIFO[1:]
	}
}

func (p *pubSub) newStream(key sgKey, o *cobj) *outStream {
	pubObj, pubSg := p.t.objTimeout, p.t.sgTimeout
	pubObj, pubSg = objectTimeouts(o.Properties, pubObj, pubSg)
	st := &outStream{
		p: p, key: key, prio: o.Priority, first: o.first,
		objTimeout: minTimeout(pubObj, p.objTimeout),
		sgTimeout:  minTimeout(pubSg, p.sgTimeout),
		wake:       make(chan struct{}, 1),
	}
	st.ctx, st.cancel = context.WithCancel(p.ctx)
	if !p.s.start(st.run) {
		st.cancel()
		return nil
	}
	p.streams[key] = st
	p.writers++
	return st
}

// objectTimeouts applies the delivery timeouts an object's properties carry,
// also inside Immutable Properties, which processors must search (draft
// section 10.7).
func objectTimeouts(kvs []wire.KV, obj, sg time.Duration) (time.Duration, time.Duration) {
	apply := func(kvs []wire.KV) {
		for _, kv := range kvs {
			switch kv.Type {
			case propObjectTimeout:
				obj = ms(kv.Value)
			case propSubgroupTimeout:
				sg = ms(kv.Value)
			}
		}
	}
	apply(kvs)
	for _, kv := range kvs {
		if kv.Type != wire.PropImmutable {
			continue
		}
		if inner, err := wire.ParseKVs(kv.Bytes); err == nil {
			apply(inner)
		}
	}
	return obj, sg
}

// endSubgroup marks a subgroup complete (its stream ends with FIN once
// sent) or reset. Called with the track locked.
func (p *pubSub) endSubgroup(group, subgroup uint64, reset bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	st := p.streams[sgKey{group, subgroup}]
	if st == nil {
		return
	}
	if reset {
		st.kill(resetCancelled)
		return
	}
	st.finish()
}

// trackEnded schedules PUBLISH_DONE: complete subgroups are sent first,
// the others reset. Called with the track locked.
func (p *pubSub) trackEnded(code DoneCode, reset bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if reset && p.fillCancel != nil {
		p.fillCancel(ErrMalformedTrack)
	}
	p.endLocked(code, reset)
}

func (p *pubSub) endLocked(code DoneCode, resetAll bool) {
	if p.ended {
		return
	}
	p.ended, p.endCode = true, code
	for _, st := range p.streams {
		if resetAll || !st.finished {
			st.kill(resetCancelled)
		}
	}
	if p.writers == 0 {
		close(p.drained)
	}
	close(p.endCh)
}

func (p *pubSub) writerDone() {
	p.writers--
	if p.writers == 0 && p.ended {
		close(p.drained)
	}
}

// wait runs until the subscription ends, then sends PUBLISH_DONE or
// cancels the request.
func (p *pubSub) wait() {
	probe := time.NewTicker(p.s.cfg.RequestTimeout)
	defer probe.Stop()
	for {
		select {
		case <-p.endCh:
			p.sendDone()
			return
		case <-p.ctx.Done():
			p.mu.Lock()
			p.endLocked(DoneInternalError, true)
			p.mu.Unlock()
			if p.s.ctx.Err() == nil {
				p.r.cancel(resetCancelled)
			}
			return
		case <-probe.C:
			if p.r.stopped() {
				p.cancel()
			}
		}
	}
}

func (p *pubSub) sendDone() {
	select {
	case <-p.drained:
	case <-p.ctx.Done():
		p.r.cancel(resetCancelled)
		return
	}
	p.mu.Lock()
	m := &wire.PublishDone{Status: uint64(p.endCode), StreamCount: p.opened}
	p.mu.Unlock()
	if err := p.r.writeFin(wire.MsgPublishDone, m); err != nil {
		p.r.cancel(resetCancelled)
		return
	}
	t := time.NewTimer(p.s.cfg.RequestTimeout)
	defer t.Stop()
	select {
	case <-p.upDone:
	case <-t.C:
	case <-p.ctx.Done():
	}
	p.r.st.CancelRead(resetCancelled)
}

// readUpdates applies the subscriber's REQUEST_UPDATE messages.
func (p *pubSub) readUpdates() {
	defer close(p.upDone)
	s := p.s
	goaways := 0
	for {
		t, body, err := p.r.read(s.cfg.MaxControlMessageSize)
		if err != nil {
			if err != io.EOF {
				s.protocolErr(err)
				p.cancel()
			}
			return
		}
		switch t {
		case wire.MsgGoAway:
			if !s.requestGoAway(body, &goaways) {
				return
			}
			continue
		case wire.MsgRequestUpdate:
		default:
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
		m, err := wire.ParseRequestUpdate(body)
		if err != nil {
			s.protocolErr(err)
			return
		}
		if !s.useRequestID(m.RequestID) || !s.checkTokens(m.Params) {
			return
		}
		if m.Params.Types()&^wire.UpdateSubscription != 0 {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
		refuse := ReqInternalError
		switch {
		case hasRangeFilter(m.Params):
			refuse = ReqInvalidFilter
		case m.Params.Has(wire.ParamFillParameters) && !s.allowed(KindFetch, p.t.ns, p.t.name):
			refuse = ReqUnauthorized
		}
		if refuse != ReqInternalError {
			p.r.write(wire.MsgRequestError, &wire.RequestError{Code: uint64(refuse)})
			p.mu.Lock()
			p.endLocked(DoneUpdateFailed, true)
			p.mu.Unlock()
			return
		}
		largest, has := p.t.status()
		if m.Params.Has(wire.ParamNewGroupRequest) {
			p.newGroupRequest(m.Params.NewGroupRequest, largest, has)
		}
		p.startFill(p.applyUpdate(m, largest, has))
		if err := p.r.write(wire.MsgRequestOK, &wire.RequestOK{Params: largestParam(largest, has)}); err != nil {
			p.cancel()
			return
		}
	}
}

// newGroupRequest handles a subscriber's NEW_GROUP_REQUEST with value v: a request whose value is not above the
// track's largest group is ignored, and the track limits how often the rest reach the publisher.
func (p *pubSub) newGroupRequest(v uint64, largest wire.Location, has bool) {
	if has && v != 0 && v <= largest.Group {
		return
	}
	p.t.requestNewGroup()
}

func (p *pubSub) applyUpdate(m *wire.RequestUpdate, largest wire.Location, has bool) *fillPlan {
	prm := m.Params
	if prm.Has(wire.ParamSubscriberPriority) {
		p.prio.Store(uint32(prm.SubscriberPriority))
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if prm.Has(wire.ParamObjectTimeout) {
		p.objTimeout = ms(prm.ObjectTimeout)
	}
	if prm.Has(wire.ParamSubgroupTimeout) {
		p.sgTimeout = ms(prm.SubgroupTimeout)
	}
	if prm.Has(wire.ParamForward) {
		p.forward = prm.Forward == 1
		if !p.forward {
			for _, st := range p.streams {
				st.kill(resetCancelled)
			}
		}
	}
	p.setFilter(prm, largest, has)
	if prm.Has(wire.ParamFillParameters) {
		return p.planFill(m.RequestID, prm.Fill, largest, has)
	}
	return nil
}

type fillPlan struct {
	reqID      uint64
	start, end wire.Location
	order      GroupOrder
	prio       func() uint8
}

// planFill evaluates a fill range (draft section 3.4); nil means no fill
// stream. Called with p.mu held.
func (p *pubSub) planFill(reqID uint64, fill *wire.MessageParams, largest wire.Location, has bool) *fillPlan {
	if !p.forward || p.ended {
		return nil
	}
	var f *wire.LocationFilter
	if fill != nil && fill.Has(wire.ParamLocationFilter) {
		f = &fill.Filter
	} else if p.hasFilter() {
		f = &wire.LocationFilter{Type: wire.FilterAbsoluteStart, StartGroup: p.start.Group, StartObject: p.start.Object}
		if p.hasEnd {
			f.Type, f.EndGroup, f.EndObject = wire.FilterAbsoluteRange, p.end.Group, p.end.Object
		}
	}
	start, end, ok := fetchRange(f, largest, has)
	if !ok {
		return nil
	}
	plan := &fillPlan{reqID: reqID, start: start, end: end, order: p.order, prio: p.priority}
	if fill != nil && fill.Has(wire.ParamGroupOrder) {
		plan.order = GroupOrder(fill.GroupOrder)
	}
	if fill != nil && fill.Has(wire.ParamSubscriberPriority) {
		v := fill.SubscriberPriority
		plan.prio = func() uint8 { return v }
	}
	return plan
}

// startFill opens the fill fetch stream of plan.
func (p *pubSub) startFill(plan *fillPlan) {
	if plan == nil {
		return
	}
	p.mu.Lock()
	busy := p.filling
	p.filling = true
	p.mu.Unlock()
	if busy {
		// One fill at a time per subscription bounds what updates can start.
		return
	}
	entries := p.t.snapshot(plan.start, plan.end, plan.order)
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ended || !p.s.reserveFetch(heldBytes(entries)) {
		// A fill over MaxFetchBytes is skipped like one asked for while another runs.
		p.filling = false
		return
	}
	ctx, cancel := context.WithCancelCause(p.ctx)
	started := p.s.start(func() {
		defer cancel(nil)
		opened := func() {
			p.mu.Lock()
			p.opened++
			p.mu.Unlock()
		}
		p.s.writeFetch(ctx, &p.q, true, plan.reqID, entries, plan.order, plan.prio, opened)
		p.s.releaseFetch(heldBytes(entries))
		p.mu.Lock()
		p.fillCancel = nil
		p.filling = false
		p.writerDone()
		p.mu.Unlock()
	})
	if !started {
		cancel(nil)
		p.s.releaseFetch(heldBytes(entries))
		p.filling = false
		return
	}
	p.writers++
	p.fillCancel = cancel
}

func (p *pubSub) hasFilter() bool { return p.start != (wire.Location{}) || p.hasEnd }

// writeFetch sends entries on a new fetch stream and ends it with FIN; a
// canceled ctx or a failed write resets it. opened runs once the stream
// header is written. Sent entries are released from MaxFetchBytes and
// cleared, so the cache can free them.
func (s *Session) writeFetch(ctx context.Context, q *sendQueue, fill bool, reqID uint64, entries []fetchEntry, order GroupOrder, prio func() uint8, opened func()) error {
	st, err := s.conn.OpenUniStream(ctx)
	if err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, func() { st.CancelWrite(resetCode(ctx, nil)) })
	defer stop()
	if err := s.writeEntries(ctx, q, fill, st, reqID, entries, order, prio, opened); err != nil {
		st.CancelWrite(resetCode(ctx, err))
		return err
	}
	return st.Close()
}

func (s *Session) writeEntries(ctx context.Context, q *sendQueue, fill bool, st *kolotransport.SendStream, reqID uint64, entries []fetchEntry, order GroupOrder, prio func() uint8, opened func()) error {
	buf := wire.AppendVarint(nil, wire.StreamTypeFetch)
	buf = wire.AppendVarint(buf, reqID)
	counted := false
	w := wire.FetchWriter{Descending: order == OrderDescending}
	key := sendKey{order: order, fill: fill}
	flush := func() error {
		key.sub = prio()
		n, err := s.send(ctx, q, key, st, buf, time.Time{})
		if !counted && n > 0 {
			counted = true
			opened()
		}
		buf = buf[:0]
		return err
	}
	for i, e := range entries {
		if e.obj == nil {
			buf = w.AppendEndOfRange(buf, wire.EndOfUnknownRange, e.loc)
			continue
		}
		buf = w.Append(buf, &e.obj.Object)
		key.pub, key.group, key.subgroup = e.obj.Priority, e.obj.Group, e.obj.Subgroup
		if err := flush(); err != nil {
			return err
		}
		s.releaseFetch(e.obj.size())
		entries[i] = fetchEntry{}
	}
	if len(buf) > 0 {
		return flush()
	}
	return nil
}

// heldBytes is what the objects of entries count against MaxFetchBytes.
func heldBytes(entries []fetchEntry) int64 {
	var n int64
	for _, e := range entries {
		if e.obj != nil {
			n += e.obj.size()
		}
	}
	return n
}

// resetCode is the stream reset code for a fetch stream that ended with err
// while ctx was canceled or not.
func resetCode(ctx context.Context, err error) uint64 {
	switch {
	case errors.Is(context.Cause(ctx), ErrMalformedTrack):
		return resetMalformedTrack
	case errors.Is(err, errStalled):
		return resetExcessiveLoad
	}
	return resetCancelled
}

// writeFailed handles an error writing a response: a message the draft's
// length field cannot hold is answered with INTERNAL_ERROR, any other error
// cancels the request.
func (s *Session) writeFailed(r *reqStream, err error) {
	if errors.Is(err, wire.ErrMessageTooLong) {
		s.reject(r, ReqInternalError, "")
		return
	}
	r.cancel(resetCancelled)
}

// outStream sends one subgroup to one subscriber.
type outStream struct {
	p          *pubSub
	key        sgKey
	prio       uint8
	first      bool
	objTimeout time.Duration
	sgTimeout  time.Duration
	ctx        context.Context
	cancel     context.CancelFunc
	wake       chan struct{}

	// Guarded by p.mu.
	last      uint64 // ID of the newest queued object
	queue     []*cobj
	finished  bool
	completed bool
	dead      bool
	stream    *kolotransport.SendStream
	timer     *time.Timer
	sending   time.Time // when the object being sent arrived; zero when none
}

func (st *outStream) signal() {
	select {
	case st.wake <- struct{}{}:
	default:
	}
}

// finish marks the subgroup complete and starts SUBGROUP_DELIVERY_TIMEOUT.
// Called with p.mu held.
func (st *outStream) finish() {
	if st.finished || st.dead {
		return
	}
	st.finished = true
	if st.sgTimeout > 0 {
		st.timer = time.AfterFunc(st.sgTimeout, func() {
			st.p.mu.Lock()
			defer st.p.mu.Unlock()
			if !st.completed && !st.dead {
				st.kill(resetDeliveryTimeout)
				st.p.s.expiredGroups.Add(1)
			}
		})
	}
	st.signal()
}

// kill resets the stream with code and drops its queue. Called with p.mu
// held.
func (st *outStream) kill(code uint64) {
	if st.dead {
		return
	}
	p := st.p
	st.dead = true
	for _, o := range st.queue {
		p.queued -= o.size()
	}
	st.queue = nil
	if p.streams[st.key] == st {
		delete(p.streams, st.key)
	}
	p.markDead(st.key)
	if st.stream != nil && !st.completed {
		st.stream.CancelWrite(code)
	}
	if st.timer != nil {
		st.timer.Stop()
	}
	st.cancel()
}

// next returns the next object to send, or fin when the subgroup is
// complete and sent, or stop when the stream is dead.
func (st *outStream) next() (o *cobj, fin, stop bool) {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	st.sending = time.Time{}
	for {
		switch {
		case st.dead:
			return nil, false, true
		case len(st.queue) > 0:
			o = st.queue[0]
			st.queue[0] = nil
			st.queue = st.queue[1:]
			p.queued -= o.size()
			st.sending = o.at
			return o, false, false
		case st.finished:
			st.completed = true
			if st.timer != nil {
				st.timer.Stop()
			}
			return nil, true, false
		}
		p.mu.Unlock()
		select {
		case <-st.wake:
		case <-st.ctx.Done():
		}
		p.mu.Lock()
		if st.ctx.Err() != nil && !st.dead {
			st.kill(resetCancelled)
		}
	}
}

func (st *outStream) run() {
	p, s := st.p, st.p.s
	defer func() {
		p.mu.Lock()
		if !st.dead {
			st.dead = true
			if p.streams[st.key] == st {
				delete(p.streams, st.key)
			}
			p.markDead(st.key)
			if st.stream != nil && !st.completed {
				st.stream.CancelWrite(resetInternalError)
			}
		}
		st.cancel()
		p.writerDone()
		p.mu.Unlock()
	}()
	select {
	case <-p.ready:
	case <-st.ctx.Done():
		return
	}
	var stream *kolotransport.SendStream
	var w wire.SubgroupWriter
	var buf []byte
	counted := false
	for {
		o, fin, stop := st.next()
		if stop {
			return
		}
		if fin {
			if stream != nil {
				stream.Close()
			}
			return
		}
		if st.objTimeout > 0 && time.Since(o.at) > st.objTimeout {
			st.expire()
			return
		}
		if stream == nil {
			ss, err := s.conn.OpenUniStream(st.ctx)
			if err != nil {
				return
			}
			p.mu.Lock()
			if st.dead {
				p.mu.Unlock()
				ss.CancelWrite(resetCancelled)
				return
			}
			st.stream = ss
			p.mu.Unlock()
			stream = ss
			buf = st.header().Append(buf)
		}
		var werr error
		if buf, werr = w.Append(buf, &o.Object); werr != nil {
			// offer keeps the IDs increasing, so this is unreachable; reset rather than send a broken delta.
			st.reset(resetInternalError)
			return
		}
		key := sendKey{sub: p.priority(), pub: st.prio, group: st.key.group, order: p.order, subgroup: st.key.subgroup}
		var deadline time.Time
		if st.objTimeout > 0 {
			deadline = o.at.Add(st.objTimeout)
		}
		n, err := s.send(st.ctx, &p.q, key, stream, buf, deadline)
		buf = buf[:0]
		if !counted && n > 0 {
			// PUBLISH_DONE counts a stream once its header is out (draft section
			// 9.9). A write cut inside the header needs a nearly closed window;
			// the subscriber's timeout covers that.
			counted = true
			p.mu.Lock()
			p.opened++
			p.mu.Unlock()
		}
		if err != nil {
			switch {
			case errors.Is(err, os.ErrDeadlineExceeded):
				st.expire()
			case errors.Is(err, errStalled):
				st.reset(resetExcessiveLoad)
				s.resetGroups.Add(1)
			}
			return
		}
	}
}

// reset kills the stream with code, unless it is already dead.
func (st *outStream) reset(code uint64) {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	st.kill(code)
}

func (st *outStream) expire() {
	p := st.p
	p.mu.Lock()
	defer p.mu.Unlock()
	if !st.dead {
		st.kill(resetDeliveryTimeout)
		p.s.expiredGroups.Add(1)
	}
}

func (st *outStream) header() *wire.SubgroupHeader {
	h := &wire.SubgroupHeader{
		Flags:      wire.SubgroupTypeBit | wire.SubgroupProperties,
		TrackAlias: st.p.alias,
		Group:      st.key.group,
		Subgroup:   st.key.subgroup,
		Priority:   st.prio,
	}
	if st.key.subgroup != 0 {
		h.Flags |= wire.SubgroupModeExplicit << 1
	}
	if st.prio == st.p.t.prio {
		h.Flags |= wire.SubgroupDefaultPrio
	}
	if st.first {
		h.Flags |= wire.SubgroupFirstObject
	}
	return h
}

func (s *Session) serveFetch(r *reqStream, m *wire.Request) {
	t := s.acquireTrack(r, KindFetch, m)
	if t == nil {
		return
	}
	defer s.source().release(t)
	largest, has := t.status()
	var f *wire.LocationFilter
	if m.Params.Has(wire.ParamLocationFilter) {
		f = &m.Params.Filter
	}
	start, end, ok := fetchRange(f, largest, has)
	if !ok {
		s.reject(r, ReqInvalidRange, "")
		return
	}
	order := OrderAscending
	if m.Params.Has(wire.ParamGroupOrder) {
		order = GroupOrder(m.Params.GroupOrder)
	}
	var prio atomic.Uint32
	prio.Store(DefaultPriority)
	if m.Params.Has(wire.ParamSubscriberPriority) {
		prio.Store(uint32(m.Params.SubscriberPriority))
	}
	entries := t.snapshot(start, end, order)
	if !s.reserveFetch(heldBytes(entries)) {
		s.reject(r, ReqExcessiveLoad, "fetch exceeds the session's fetch budget")
		return
	}
	defer func() { s.releaseFetch(heldBytes(entries)) }()
	t.mu.Lock()
	eot := t.final && end == t.largest
	t.mu.Unlock()
	okMsg := &wire.FetchOK{EndOfTrack: eot, End: end, Params: &wire.MessageParams{}, Properties: includeProps(m.Params, t)}
	if err := r.write(wire.MsgFetchOK, okMsg); err != nil {
		s.writeFailed(r, err)
		return
	}
	ctx, cancelCause := context.WithCancelCause(s.ctx)
	cancel := func() { cancelCause(nil) }
	defer cancel()
	// A malformed track resets its fetch streams (draft section 12.1).
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		select {
		case <-t.malformedCh:
			cancelCause(ErrMalformedTrack)
		case <-ctx.Done():
		}
	}()
	defer func() {
		cancel()
		<-watched
	}()
	upDone := make(chan struct{})
	go func() {
		defer close(upDone)
		s.readFetchUpdates(r, &prio, cancel)
	}()
	var q sendQueue
	err := s.writeFetch(ctx, &q, false, m.RequestID, entries, order, func() uint8 { return uint8(prio.Load()) }, func() {})
	if err != nil {
		r.cancel(resetCancelled)
		<-upDone
		return
	}
	r.wmu.Lock()
	r.st.Close()
	r.wmu.Unlock()
	timer := time.NewTimer(s.cfg.RequestTimeout)
	defer timer.Stop()
	select {
	case <-upDone:
	case <-timer.C:
	case <-ctx.Done():
	}
	r.st.CancelRead(resetCancelled)
	<-upDone
}

func (s *Session) readFetchUpdates(r *reqStream, prio *atomic.Uint32, cancel context.CancelFunc) {
	goaways := 0
	for {
		t, body, err := r.read(s.cfg.MaxControlMessageSize)
		if err != nil {
			if err != io.EOF {
				s.protocolErr(err)
				cancel()
			}
			return
		}
		if t == wire.MsgGoAway {
			if !s.requestGoAway(body, &goaways) {
				return
			}
			continue
		}
		if t != wire.MsgRequestUpdate {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
		m, err := wire.ParseRequestUpdate(body)
		if err != nil {
			s.protocolErr(err)
			return
		}
		if !s.useRequestID(m.RequestID) || !s.checkTokens(m.Params) {
			return
		}
		if m.Params.Types()&^wire.UpdateFetch != 0 {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
		if m.Params.Has(wire.ParamSubscriberPriority) {
			prio.Store(uint32(m.Params.SubscriberPriority))
		}
		if err := r.write(wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}}); err != nil {
			cancel()
			return
		}
	}
}

func (s *Session) serveTrackStatus(r *reqStream, m *wire.Request) {
	t := s.acquireTrack(r, KindTrackStatus, m)
	if t == nil {
		return
	}
	defer s.source().release(t)
	largest, has := t.status()
	if err := r.writeFin(wire.MsgRequestOK, &wire.RequestOK{Params: largestParam(largest, has), Properties: includeProps(m.Params, t)}); err != nil {
		s.writeFailed(r, err)
		return
	}
	r.st.CancelRead(resetCancelled)
}

// peerNamespace is a namespace the peer published to this side.
type peerNamespace struct{ ns Namespace }

// PeerNamespaces returns the namespaces the peer has published to this
// side with PUBLISH_NAMESPACE and not withdrawn.
func (s *Session) PeerNamespaces() []Namespace {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Namespace, 0, len(s.peerNS))
	for p := range s.peerNS {
		out = append(out, p.ns)
	}
	return out
}

func (s *Session) servePublishNamespace(r *reqStream, ns Namespace) {
	withdraw, err := s.source().publishNamespace(s, ns)
	if err != nil {
		var re *RequestError
		code := ReqInternalError
		if errors.As(err, &re) {
			code = re.Code
		}
		s.reject(r, code, "")
		return
	}
	defer withdraw()
	pn := &peerNamespace{ns: ns}
	s.mu.Lock()
	s.peerNS[pn] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.peerNS, pn)
		s.mu.Unlock()
	}()
	if err := r.write(wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}}); err != nil {
		r.cancel(resetCancelled)
		return
	}
	if !s.readNamespaceUpdates(r, wire.UpdatePublishNS) {
		r.cancel(resetCancelled)
		return
	}
	s.waitStopped(r)
}

// readNamespaceUpdates answers REQUEST_UPDATE on a namespace request until
// the requester ends its side; false means the request was canceled.
func (s *Session) readNamespaceUpdates(r *reqStream, allowed wire.ParamSet) bool {
	goaways := 0
	for {
		t, body, err := r.read(s.cfg.MaxControlMessageSize)
		if err == io.EOF {
			return true
		}
		if err != nil {
			s.protocolErr(err)
			return false
		}
		if t == wire.MsgGoAway {
			if !s.requestGoAway(body, &goaways) {
				return false
			}
			continue
		}
		if t != wire.MsgRequestUpdate {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return false
		}
		m, err := wire.ParseRequestUpdate(body)
		if err != nil {
			s.protocolErr(err)
			return false
		}
		if !s.useRequestID(m.RequestID) || !s.checkTokens(m.Params) {
			return false
		}
		if m.Params.Types()&^allowed != 0 {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return false
		}
		if m.Params.Has(wire.ParamNamespacePrefix) {
			// Moving a namespace subscription is not supported: refuse and
			// close the stream (draft section 9.5.1).
			r.writeFin(wire.MsgRequestError, &wire.RequestError{Code: uint64(ReqNotSupported)})
			return false
		}
		if err := r.write(wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}}); err != nil {
			return false
		}
	}
}

// waitStopped waits, after the requester's FIN, for its STOP_SENDING or
// the end of the session, checking every RequestTimeout.
func (s *Session) waitStopped(r *reqStream) {
	t := time.NewTicker(s.cfg.RequestTimeout)
	defer t.Stop()
	for {
		select {
		case <-s.ctx.Done():
			return
		case <-t.C:
			if r.stopped() {
				r.st.CancelWrite(resetCancelled)
				return
			}
		}
	}
}

// nsServe is a SUBSCRIBE_NAMESPACE this side serves.
type nsServe struct {
	prefix  Namespace
	mu      sync.Mutex
	events  []nsEvent
	over    bool
	wake    chan struct{}
	maxSize int
}

type nsEvent struct {
	ns     Namespace
	active bool
}

func (n *nsServe) push(ns Namespace, active bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	if len(n.events) >= n.maxSize {
		n.over = true
	} else {
		n.events = append(n.events, nsEvent{ns, active})
	}
	select {
	case n.wake <- struct{}{}:
	default:
	}
}

func (s *Session) serveSubscribeNamespace(r *reqStream, prefix Namespace) {
	n := &nsServe{prefix: prefix, wake: make(chan struct{}, 1), maxSize: s.cfg.MaxNamespaces}
	s.mu.Lock()
	overlap := false
	for o := range s.nsServes {
		if o.prefix.HasPrefix(prefix) || prefix.HasPrefix(o.prefix) {
			overlap = true
		}
	}
	if !overlap {
		s.nsServes[n] = struct{}{}
	}
	s.mu.Unlock()
	if overlap {
		s.reject(r, ReqPrefixOverlap, "")
		return
	}
	defer func() {
		s.mu.Lock()
		delete(s.nsServes, n)
		s.mu.Unlock()
	}()
	initial, stopWatch := s.source().watchNamespaces(prefix, func(ns Namespace, active bool) {
		if !keyNamespace(ns) {
			n.push(ns, active)
		}
	})
	defer stopWatch()
	initial = slices.DeleteFunc(initial, keyNamespace)
	if len(initial) > s.cfg.MaxNamespaces {
		s.reject(r, ReqNamespaceTooLarge, "")
		return
	}
	if err := r.write(wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}}); err != nil {
		r.cancel(resetCancelled)
		return
	}
	ctx, cancel := context.WithCancel(s.ctx)
	defer cancel()
	readDone := make(chan struct{})
	defer func() { <-readDone }()
	go func() {
		defer close(readDone)
		if !s.readNamespaceUpdates(r, wire.UpdateNamespace) {
			cancel()
		}
	}()
	probe := time.NewTicker(s.cfg.RequestTimeout)
	defer probe.Stop()
	announced := map[string]bool{}
	send := func(ev nsEvent) error {
		k := ev.ns.key()
		if announced[k] == ev.active {
			return nil
		}
		if ev.active && len(announced) >= s.cfg.MaxNamespaces {
			return ErrTooManyNamespaces
		}
		if ev.active {
			announced[k] = true
		} else {
			delete(announced, k)
		}
		t := uint64(wire.MsgNamespaceDone)
		if ev.active {
			t = wire.MsgNamespace
		}
		return r.write(t, nsSuffix(ev.ns[len(prefix):]))
	}
	for _, ns := range initial {
		if err := send(nsEvent{ns, true}); err != nil {
			r.cancel(resetCancelled)
			return
		}
	}
	for {
		select {
		case <-ctx.Done():
			r.cancel(resetCancelled)
			return
		case <-probe.C:
			if r.stopped() {
				r.cancel(resetCancelled)
				return
			}
			continue
		case <-n.wake:
		}
		n.mu.Lock()
		evs, over := n.events, n.over
		n.events = nil
		n.mu.Unlock()
		if over {
			r.cancel(resetExcessiveLoad)
			return
		}
		for _, ev := range evs {
			if err := send(ev); err != nil {
				r.cancel(resetExcessiveLoad)
				return
			}
		}
	}
}

type nsSuffix Namespace

func (n nsSuffix) Append(b []byte) []byte { return wire.AppendNamespace(b, n) }
