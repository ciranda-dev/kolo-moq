package kolomoq

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"sync"
	"sync/atomic"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// Join is where a subscription starts.
type Join int

// Join points (draft section 3.5).
const (
	// JoinNextObject delivers objects published from now on.
	JoinNextObject Join = iota
	// JoinCurrentGroup also delivers the current group's earlier objects
	// from the publisher's cache, on a fill fetch stream.
	JoinCurrentGroup
	// JoinNextGroup starts at the next group.
	JoinNextGroup
)

// SubscribeOptions sets a subscription. A nil *SubscribeOptions takes every
// default; in a non-nil one, Priority is used as is.
type SubscribeOptions struct {
	// Priority is the subscriber priority, 0 (most urgent) to 255; nil options give DefaultPriority.
	Priority uint8
	// GroupOrder overrides the publisher's group order.
	GroupOrder GroupOrder
	// Join is where the subscription starts.
	Join Join
	// Paused subscribes without receiving objects until Update resumes.
	Paused bool
	// SubgroupDeliveryTimeout and ObjectDeliveryTimeout ask the publisher to drop late groups; the smaller of its and these values applies. Zero means none.
	SubgroupDeliveryTimeout time.Duration
	ObjectDeliveryTimeout   time.Duration
}

// queued is an object waiting for ReadObject, with the memory it holds.
type queued struct {
	Object
	size int64
}

// sink receives a subscription's objects; the default queues them for
// ReadObject, a relay forwards them.
type sink interface {
	object(o *wire.Object, first bool)
	// endSubgroup reports the end of a subgroup stream: last is the ID of its final object, endOfGroup says that object ends the group.
	endSubgroup(group, subgroup, last uint64, endOfGroup, reset bool)
	// publishDone reports PUBLISH_DONE, which can precede the last streams.
	publishDone()
	// done reports the end of the subscription; goaway says a GOAWAY came on its request stream.
	done(err error, goaway bool)
}

// Subscription receives the objects of one track. ReadObject is safe for
// concurrent use with the other methods.
type Subscription struct {
	s         *Session
	r         *reqStream
	reqID     uint64
	ns        Namespace
	name      string
	alias     uint64
	props     []Property
	trackPrio uint8
	pubObj    time.Duration
	pubSg     time.Duration
	subObj    time.Duration
	subSg     time.Duration
	relay     sink
	updMu     sync.Mutex
	lastNG    time.Time // when RequestNewGroup last sent, guarded by updMu
	fillDone  chan struct{}
	fillOnce  sync.Once
	done      atomic.Bool
	goaway    atomic.Bool // a GOAWAY came on the request stream

	// mu is taken before Session.mu, never after.

	mu        sync.Mutex
	largest   wire.Location
	hasLarges bool
	maxGroup  uint64 // the largest group ID of an object received
	hasGroup  bool
	queue     []queued
	bytes     int64
	groups    map[uint64]int
	dropSet   map[uint64]struct{}
	dropFIFO  []uint64
	dropped   uint64
	open      map[*kolotransport.ReceiveStream]uint64
	received  uint64
	doneMsg   *wire.PublishDone
	doneTimer *time.Timer
	doneBy    time.Time
	finished  bool
	ended     chan struct{} // closed when finished is set
	err       error
	changed   chan struct{}
	updates   []chan error
}

// Subscribe asks the peer for a track and returns once the peer accepted
// (SUBSCRIBE_OK) or refused (*RequestError).
func (s *Session) Subscribe(ctx context.Context, ns Namespace, track string, opts *SubscribeOptions) (*Subscription, error) {
	return s.subscribe(ctx, ns, track, opts, nil)
}

func (s *Session) subscribe(ctx context.Context, ns Namespace, track string, opts *SubscribeOptions, relay sink) (*Subscription, error) {
	if err := s.cfg.checkName(ns, track, true); err != nil {
		return nil, err
	}
	o := SubscribeOptions{Priority: DefaultPriority}
	if opts != nil {
		o = *opts
	}
	if o.GroupOrder > OrderDescending || o.Join > JoinNextGroup || o.SubgroupDeliveryTimeout < 0 || o.ObjectDeliveryTimeout < 0 {
		return nil, fmt.Errorf("%w: invalid subscribe options", ErrInvalidConfig)
	}
	id, err := s.newRequestID()
	if err != nil {
		return nil, err
	}
	prm := &wire.MessageParams{SubscriberPriority: o.Priority}
	prm.Set(wire.ParamSubscriberPriority)
	if o.GroupOrder != OrderDefault {
		prm.Set(wire.ParamGroupOrder)
		prm.GroupOrder = uint8(o.GroupOrder)
	}
	if o.Paused {
		prm.Set(wire.ParamForward)
	}
	if o.ObjectDeliveryTimeout > 0 {
		prm.Set(wire.ParamObjectTimeout)
		prm.ObjectTimeout = toMS(o.ObjectDeliveryTimeout)
	}
	if o.SubgroupDeliveryTimeout > 0 {
		prm.Set(wire.ParamSubgroupTimeout)
		prm.SubgroupTimeout = toMS(o.SubgroupDeliveryTimeout)
	}
	prm.Set(wire.ParamLocationFilter)
	prm.Filter.Type = wire.FilterNextObject
	if o.Join == JoinNextGroup {
		prm.Filter = wire.LocationFilter{Type: wire.FilterRelativeStart}
	}
	if o.Join == JoinCurrentGroup {
		fill := &wire.MessageParams{GroupOrder: uint8(OrderAscending), Filter: wire.LocationFilter{Type: wire.FilterRelativeStart, StartGroup: 1}}
		fill.Set(wire.ParamGroupOrder)
		fill.Set(wire.ParamLocationFilter)
		prm.Set(wire.ParamFillParameters)
		prm.Fill = fill
	}
	sub := &Subscription{
		s: s, reqID: id, ns: ns, name: track, relay: relay,
		subObj: o.ObjectDeliveryTimeout, subSg: o.SubgroupDeliveryTimeout,
		groups: map[uint64]int{}, dropSet: map[uint64]struct{}{},
		open: map[*kolotransport.ReceiveStream]uint64{}, changed: make(chan struct{}), ended: make(chan struct{}),
	}
	if o.Join == JoinCurrentGroup {
		sub.fillDone = make(chan struct{})
		s.mu.Lock()
		s.fetchByReq[id] = sub
		s.mu.Unlock()
	}
	r, t, body, err := s.request(ctx, &wire.Request{Type: wire.MsgSubscribe, RequestID: id, Namespace: ns, Name: track, Params: prm}, false)
	if err != nil {
		sub.fail(err)
		return nil, err
	}
	sub.mu.Lock()
	sub.r = r
	sub.mu.Unlock()
	if t != wire.MsgSubscribeOK {
		err := s.refused(r, t, body)
		sub.fail(err)
		return nil, err
	}
	m, err := wire.ParseSubscribeOK(body)
	if err == nil {
		err = checkTrackProperties(m.Properties)
	}
	if err != nil {
		s.protocolErr(err)
		sub.fail(s.errOr(err))
		return nil, s.errOr(err)
	}
	if mandatory(m.Properties) {
		sub.fail(ErrUnsupportedProperty)
		return nil, ErrUnsupportedProperty
	}
	// A failing fill stream can finish the subscription at any time, so the
	// fields it reads are set under the lock.
	sub.mu.Lock()
	sub.alias = m.TrackAlias
	sub.props = fromKVs(m.Properties)
	sub.trackPrio = DefaultPriority
	for _, kv := range m.Properties {
		switch kv.Type {
		case propDefaultPriority:
			sub.trackPrio = uint8(kv.Value)
		case propObjectTimeout:
			sub.pubObj = ms(kv.Value)
		case propSubgroupTimeout:
			sub.pubSg = ms(kv.Value)
		}
	}
	if m.Params.Has(wire.ParamLargestObject) {
		sub.largest, sub.hasLarges = m.Params.Largest, true
	}
	if sub.finished {
		// The fill stream already failed.
		err := sub.err
		sub.mu.Unlock()
		r.cancel(resetCancelled)
		return nil, err
	}
	sub.mu.Unlock()
	s.mu.Lock()
	if old := s.aliases[sub.alias]; old != nil && !old.isDone() && (old.name != track || old.ns.key() != ns.key()) {
		s.mu.Unlock()
		s.fail(CodeDuplicateTrackAlias, ErrProtocol)
		return nil, s.Err()
	}
	s.aliases[sub.alias] = sub
	s.wakeAliases()
	s.mu.Unlock()
	if !s.start(sub.readResponses) {
		err := s.errOr(ErrClosed)
		sub.fail(err)
		return nil, err
	}
	return sub, nil
}

// toMS converts a delivery timeout to milliseconds, rounding up so that a
// positive timeout never becomes 0, which means none.
func toMS(d time.Duration) uint64 {
	n := uint64(d / time.Millisecond)
	if d%time.Millisecond != 0 {
		n++
	}
	return n
}

// wrapErr gives an error from the transport or a context the package prefix.
func wrapErr(what string, err error) error {
	return fmt.Errorf("kolomoq: %s: %w", what, err)
}

// canceledErr is the error for a request stream the peer reset or ended early.
func canceledErr(err error) error {
	code, ok := streamCode(err)
	switch {
	case ok && code == resetMalformedTrack:
		return fmt.Errorf("%w (code %d): %w", ErrRequestCanceled, code, ErrMalformedTrack)
	case ok:
		return fmt.Errorf("%w (code %d)", ErrRequestCanceled, code)
	}
	return ErrRequestCanceled
}

// request opens a request stream, sends m and reads the first response
// within ctx and RequestTimeout.
func (s *Session) request(ctx context.Context, m *wire.Request, fin bool) (*reqStream, uint64, []byte, error) {
	ctx, cancel := context.WithTimeout(ctx, s.cfg.RequestTimeout)
	defer cancel()
	st, err := s.conn.OpenStream(ctx)
	if err != nil {
		return nil, 0, nil, s.errOr(wrapErr("open request stream", err))
	}
	r := newReqStream(st)
	stop := interruptOnDone(ctx, st.SetReadDeadline)
	defer stop()
	write := r.write
	if fin {
		write = r.writeFin
	}
	if err := write(m.Type, m); err != nil {
		r.cancel(resetCancelled)
		if errors.Is(err, wire.ErrMessageTooLong) {
			return nil, 0, nil, err
		}
		return nil, 0, nil, s.errOr(wrapErr("write request", err))
	}
	t, body, err := r.read(s.cfg.MaxControlMessageSize)
	if err != nil {
		r.cancel(resetCancelled)
		if s.connEnded(err) {
			return nil, 0, nil, s.Err()
		}
		if errors.Is(err, os.ErrDeadlineExceeded) {
			if ctx.Err() == context.DeadlineExceeded {
				return nil, 0, nil, s.errOr(ErrTimeout)
			}
			return nil, 0, nil, s.errOr(wrapErr("request", ctx.Err()))
		}
		s.protocolErr(err)
		if _, ok := streamCode(err); ok || err == io.EOF {
			return nil, 0, nil, s.errOr(canceledErr(err))
		}
		return nil, 0, nil, s.errOr(wrapErr("read response", err))
	}
	return r, t, body, nil
}

// errOr returns the session's error if it ended, else err.
func (s *Session) errOr(err error) error {
	if e := s.Err(); e != nil {
		return e
	}
	return err
}

// refused handles a first response that is not the expected OK.
func (s *Session) refused(r *reqStream, t uint64, body []byte) error {
	if t != wire.MsgRequestError {
		s.fail(CodeProtocolViolation, ErrProtocol)
		return s.Err()
	}
	m, err := wire.ParseRequestError(body)
	if err != nil {
		s.protocolErr(err)
		return s.Err()
	}
	r.cancel(resetCancelled)
	return requestErrorFromWire(m)
}

func mandatory(kvs []wire.KV) bool {
	for _, kv := range kvs {
		if kv.Type >= 0x4000 && kv.Type <= 0x7FFF {
			return true
		}
	}
	return false
}

// checkTrackProperties validates the track properties the draft defines.
func checkTrackProperties(kvs []wire.KV) error {
	for _, kv := range kvs {
		bad := false
		switch kv.Type {
		case propDefaultPriority:
			bad = kv.Value > 255
		case propDefaultOrder:
			bad = kv.Value != 1 && kv.Value != 2
		case propDynamicGroups:
			bad = kv.Value > 1
		}
		if bad {
			return &wire.Error{Code: uint64(CodeProtocolViolation), Msg: "track property out of range"}
		}
	}
	return nil
}

func (s *Session) wakeAliases() {
	close(s.aliasWake)
	s.aliasWake = make(chan struct{})
}

func (sub *Subscription) unregister() {
	s := sub.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetchByReq[sub.reqID] == fetchTarget(sub) {
		delete(s.fetchByReq, sub.reqID)
	}
	if s.aliases[sub.alias] == sub {
		delete(s.aliases, sub.alias)
	}
}

func (sub *Subscription) isDone() bool { return sub.done.Load() }

// readResponses reads the publisher's messages after SUBSCRIBE_OK.
func (sub *Subscription) readResponses() {
	s := sub.s
	goaways := 0
	for {
		t, body, err := sub.r.read(s.cfg.MaxControlMessageSize)
		if err != nil {
			sub.mu.Lock()
			gotDone := sub.doneMsg != nil
			sub.mu.Unlock()
			switch {
			case gotDone && err == io.EOF:
				// Only late streams remain; the end of the session ends their wait too.
				select {
				case <-s.done:
					sub.finish(s.Err())
				case <-sub.ended:
				}
			case s.connEnded(err):
				sub.finish(s.Err())
			default:
				s.protocolErr(err)
				sub.finish(s.errOr(canceledErr(err)))
			}
			return
		}
		switch t {
		case wire.MsgPublishDone:
			m, err := wire.ParsePublishDone(body)
			if err != nil {
				s.protocolErr(err)
				return
			}
			if !sub.publishDone(m) {
				s.fail(CodeProtocolViolation, ErrProtocol)
				return
			}
			if sub.relay != nil {
				sub.relay.publishDone()
			}
		case wire.MsgRequestOK, wire.MsgRequestError:
			var uerr error
			if t == wire.MsgRequestOK {
				m, err := wire.ParseRequestOK(body)
				if err == nil && (len(m.Properties) > 0 || m.Params.Types()&^wire.Params(wire.ParamExpires, wire.ParamLargestObject) != 0) {
					err = &wire.Error{Code: uint64(CodeProtocolViolation), Msg: "properties in REQUEST_OK"}
				}
				if err != nil {
					s.protocolErr(err)
					return
				}
				if m.Params.Has(wire.ParamLargestObject) {
					sub.setLargest(m.Params.Largest)
				}
			} else {
				m, err := wire.ParseRequestError(body)
				if err != nil {
					s.protocolErr(err)
					return
				}
				uerr = requestErrorFromWire(m)
			}
			sub.mu.Lock()
			if len(sub.updates) == 0 {
				sub.mu.Unlock()
				s.fail(CodeProtocolViolation, ErrProtocol)
				return
			}
			ch := sub.updates[0]
			sub.updates = sub.updates[1:]
			sub.mu.Unlock()
			ch <- uerr
		case wire.MsgPublishStateNotify:
			m, err := wire.ParsePublishStateNotify(body)
			if err != nil {
				s.protocolErr(err)
				return
			}
			if m.Has(wire.ParamLargestObject) {
				sub.setLargest(m.Largest)
			}
		case wire.MsgGoAway:
			if !s.requestGoAway(body, &goaways) {
				return
			}
			sub.goaway.Store(true)
		default:
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
	}
}

func (sub *Subscription) setLargest(l wire.Location) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if !sub.hasLarges || sub.largest.Less(l) {
		sub.largest, sub.hasLarges = l, true
	}
}

// publishDone records PUBLISH_DONE; late streams are awaited until the
// stream count is reached or the larger of RequestTimeout and the delivery
// timeouts passes.
func (sub *Subscription) publishDone(m *wire.PublishDone) bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.doneMsg != nil {
		return false
	}
	sub.doneMsg = m
	if sub.received >= m.StreamCount && len(sub.open) == 0 {
		sub.finishLocked(sub.doneErr())
		return true
	}
	wait := max(sub.s.cfg.RequestTimeout, sub.deliveryTimeout())
	sub.doneBy = time.Now().Add(wait)
	sub.doneTimer = time.AfterFunc(wait, func() { sub.finish(sub.doneErr()) })
	sub.awaitUnseenLocked()
	return true
}

// deliveryTimeout is the larger of the delivery timeouts in effect, 0 if none.
func (sub *Subscription) deliveryTimeout() time.Duration {
	return max(minTimeout(sub.pubObj, sub.subObj), minTimeout(sub.pubSg, sub.subSg))
}

// awaitUnseenLocked shortens the wait after PUBLISH_DONE once no received
// stream is open: the missing streams were reset before their header or
// are late, and section 9.9 asks to wait the larger delivery timeout for them.
func (sub *Subscription) awaitUnseenLocked() {
	d := sub.deliveryTimeout()
	if d == 0 || len(sub.open) > 0 {
		return
	}
	if by := time.Now().Add(d); by.Before(sub.doneBy) {
		sub.doneBy = by
		sub.doneTimer.Reset(d)
	}
}

func (sub *Subscription) doneErr() error {
	if DoneCode(sub.doneMsg.Status) == DoneTrackEnded {
		return io.EOF
	}
	return &PublishDoneError{Code: DoneCode(sub.doneMsg.Status), Reason: sanitize(sub.doneMsg.Reason)}
}

func (sub *Subscription) finish(err error) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	sub.finishLocked(err)
}

func (sub *Subscription) finishLocked(err error) {
	if sub.finished {
		return
	}
	sub.finished, sub.err = true, err
	close(sub.ended)
	if sub.doneTimer != nil {
		sub.doneTimer.Stop()
	}
	for rs := range sub.open {
		rs.CancelRead(resetCancelled)
	}
	for _, ch := range sub.updates {
		ch <- err
	}
	sub.updates = nil
	sub.notify()
	sub.done.Store(true)
	if sub.relay != nil {
		// The relay must hear of the end even when the session is over, and then
		// Close no longer waits for it.
		goaway := sub.goaway.Load()
		if !sub.s.start(func() { sub.relay.done(err, goaway) }) {
			go sub.relay.done(err, goaway)
		}
	}
	sub.unregister()
}

func (sub *Subscription) notify() {
	close(sub.changed)
	sub.changed = make(chan struct{})
}

// ReadObject returns the next object, in arrival order. After the
// publisher ends the track it returns io.EOF; after another PUBLISH_DONE, a
// *PublishDoneError; after Close, ErrClosed.
func (sub *Subscription) ReadObject(ctx context.Context) (Object, error) {
	for {
		sub.mu.Lock()
		if len(sub.queue) > 0 {
			q := sub.queue[0]
			sub.queue[0] = queued{}
			sub.queue = sub.queue[1:]
			sub.addBytes(-q.size)
			o := q.Object
			if sub.groups[o.Group]--; sub.groups[o.Group] == 0 {
				delete(sub.groups, o.Group)
			}
			sub.mu.Unlock()
			return o, nil
		}
		if sub.finished {
			err := sub.err
			sub.mu.Unlock()
			return Object{}, err
		}
		ch := sub.changed
		sub.mu.Unlock()
		select {
		case <-ch:
		case <-ctx.Done():
			return Object{}, ctx.Err()
		}
	}
}

// Dropped returns how many groups this side dropped because the reader fell
// more than MaxBufferedGroups or MaxBufferedBytes behind.
func (sub *Subscription) Dropped() uint64 {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.dropped
}

// Largest returns the Largest Object the publisher last reported.
func (sub *Subscription) Largest() (Location, bool) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return Location(sub.largest), sub.hasLarges
}

// Properties returns a copy of the track properties from SUBSCRIBE_OK.
func (sub *Subscription) Properties() []Property {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return cloneProperties(sub.props)
}

// SubscriptionUpdate is the new state Update asks for.
type SubscriptionUpdate struct {
	Priority uint8
	Paused   bool
}

// Update changes the subscriber priority and pauses or resumes delivery,
// waiting for the publisher's answer. A refused update ends the
// subscription.
func (sub *Subscription) Update(ctx context.Context, u SubscriptionUpdate) error {
	prm := &wire.MessageParams{SubscriberPriority: u.Priority, Forward: 1}
	prm.Set(wire.ParamSubscriberPriority)
	prm.Set(wire.ParamForward)
	if u.Paused {
		prm.Forward = 0
	}
	sub.updMu.Lock()
	defer sub.updMu.Unlock()
	return sub.update(ctx, prm)
}

// NewGroupRequestInterval is the least time between two requests for a new group on one subscription, and the
// most often a publisher signals one for one track, whatever the number of subscriptions.
const NewGroupRequestInterval = time.Second

// RequestNewGroup asks the publisher to start a new group, so a subscriber that lost a group or just joined
// does not wait for the next one: for a video track the publisher sends a key frame. The publisher ignores
// the request when a newer group exists. At most one request goes out every NewGroupRequestInterval; a sooner
// call returns ErrNewGroupTooSoon and sends nothing. A refused update ends the subscription, as with Update.
func (sub *Subscription) RequestNewGroup(ctx context.Context) error {
	sub.updMu.Lock()
	defer sub.updMu.Unlock()
	if !sub.lastNG.IsZero() && time.Since(sub.lastNG) < NewGroupRequestInterval {
		return ErrNewGroupTooSoon
	}
	sub.lastNG = time.Now()
	sub.mu.Lock()
	v := newGroupValue(sub.maxGroup, sub.hasGroup)
	sub.mu.Unlock()
	prm := &wire.MessageParams{NewGroupRequest: v}
	prm.Set(wire.ParamNewGroupRequest)
	return sub.update(ctx, prm)
}

// newGroupValue is the NEW_GROUP_REQUEST value for a subscription whose largest group ID received is largest: 0 while
// no group arrived, else largest plus one, saturating, because 0 would mean no group yet.
func newGroupValue(largest uint64, has bool) uint64 {
	if !has {
		return 0
	}
	if largest == math.MaxUint64 {
		return largest
	}
	return largest + 1
}

// update sends a REQUEST_UPDATE with prm and waits for the publisher's answer; the caller holds updMu.
func (sub *Subscription) update(ctx context.Context, prm *wire.MessageParams) error {
	s := sub.s
	id, err := s.newUpdateID()
	if err != nil {
		return err
	}
	ch := make(chan error, 1)
	sub.mu.Lock()
	if sub.finished {
		err := sub.err
		sub.mu.Unlock()
		return err
	}
	sub.updates = append(sub.updates, ch)
	sub.mu.Unlock()
	if err := sub.r.write(wire.MsgRequestUpdate, &wire.RequestUpdate{RequestID: id, Params: prm}); err != nil {
		sub.Close()
		return s.errOr(err)
	}
	t := time.NewTimer(s.cfg.RequestTimeout)
	defer t.Stop()
	select {
	case err := <-ch:
		return err
	case <-t.C:
		sub.Close()
		return ErrTimeout
	case <-ctx.Done():
		sub.Close()
		return wrapErr("update", ctx.Err())
	}
}

// Close unsubscribes; queued objects are dropped and ReadObject returns
// ErrClosed.
func (sub *Subscription) Close() error {
	sub.mu.Lock()
	sub.addBytes(-sub.bytes)
	sub.queue = nil
	clear(sub.groups)
	sub.finishLocked(ErrClosed)
	sub.mu.Unlock()
	sub.r.cancel(resetCancelled)
	return nil
}

func (sub *Subscription) addStream(rs *kolotransport.ReceiveStream, group uint64) bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.finished {
		return false
	}
	sub.received++
	sub.open[rs] = group
	return true
}

func (sub *Subscription) removeStream(rs *kolotransport.ReceiveStream) {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	delete(sub.open, rs)
	if sub.doneMsg == nil || sub.finished {
		return
	}
	if sub.received >= sub.doneMsg.StreamCount && len(sub.open) == 0 {
		sub.finishLocked(sub.doneErr())
		return
	}
	sub.awaitUnseenLocked()
}

// push queues an object for ReadObject, dropping the oldest groups when
// the reader is too far behind.
func (sub *Subscription) push(o *wire.Object, first bool) {
	if sub.isDone() {
		return
	}
	sub.mu.Lock()
	if !sub.hasGroup || o.Group > sub.maxGroup {
		sub.maxGroup, sub.hasGroup = o.Group, true
	}
	sub.mu.Unlock()
	if sub.relay != nil {
		sub.relay.object(o, first)
		return
	}
	sub.enqueue(o)
	sub.s.shed()
}

func (sub *Subscription) enqueue(o *wire.Object) {
	cfg := &sub.s.cfg
	sub.mu.Lock()
	defer sub.mu.Unlock()
	if sub.finished {
		return
	}
	if _, drop := sub.dropSet[o.Group]; drop {
		return
	}
	n := objectSize(o)
	sub.queue = append(sub.queue, queued{objectFromWire(o), n})
	sub.addBytes(n)
	sub.groups[o.Group]++
	for (len(sub.groups) > cfg.MaxBufferedGroups || sub.bytes > cfg.MaxBufferedBytes) && sub.dropOldestLocked() {
	}
	sub.notify()
}

func (sub *Subscription) queuedBytes() int64 {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.bytes
}

func (sub *Subscription) dropOldest() bool {
	sub.mu.Lock()
	defer sub.mu.Unlock()
	return sub.dropOldestLocked()
}

// dropOldestLocked drops the oldest queued group and reports whether there was one.
func (sub *Subscription) dropOldestLocked() bool {
	if len(sub.groups) == 0 {
		return false
	}
	oldest := uint64(math.MaxUint64)
	for g := range sub.groups {
		oldest = min(oldest, g)
	}
	sub.dropGroup(oldest)
	return true
}

// addBytes counts n more bytes (or fewer, if negative) queued for this subscription and for its session. Called with sub.mu held.
func (sub *Subscription) addBytes(n int64) {
	sub.bytes += n
	sub.s.buffered.Add(n)
}

func (sub *Subscription) dropGroup(g uint64) {
	kept := sub.queue[:0]
	for _, o := range sub.queue {
		if o.Group == g {
			sub.addBytes(-o.size)
			continue
		}
		kept = append(kept, o)
	}
	clear(sub.queue[len(kept):])
	sub.queue = kept
	delete(sub.groups, g)
	for rs, sg := range sub.open {
		if sg == g {
			rs.CancelRead(resetCancelled)
		}
	}
	sub.dropped++
	sub.dropSet[g] = struct{}{}
	sub.dropFIFO = append(sub.dropFIFO, g)
	if len(sub.dropFIFO) > sub.s.cfg.MaxBufferedGroups {
		delete(sub.dropSet, sub.dropFIFO[0])
		sub.dropFIFO = sub.dropFIFO[1:]
	}
}

// fail ends the subscription after a malformed track or an object too
// large, cancelling the request (draft section 12.1).
func (sub *Subscription) fail(err error) {
	sub.mu.Lock()
	sub.finishLocked(err)
	r := sub.r
	sub.mu.Unlock()
	if r != nil {
		r.cancel(resetCancelled)
	}
}

// fetchTarget receives a fetch stream: a *Fetch, or a *Subscription's fill.
type fetchTarget interface {
	fetchStream(rs *kolotransport.ReceiveStream, br *bufio.Reader)
}

func (sub *Subscription) fetchStream(rs *kolotransport.ReceiveStream, br *bufio.Reader) {
	s := sub.s
	defer sub.fillOnce.Do(func() { close(sub.fillDone) })
	if !sub.addStream(rs, math.MaxUint64) {
		rs.CancelRead(resetCancelled)
		return
	}
	defer sub.removeStream(rs)
	fr := &wire.FetchReader{R: br, MaxPayload: uint64(s.cfg.MaxObjectSize)}
	for {
		fo, err := fr.Next()
		if err != nil {
			if err != io.EOF {
				s.dataErr(rs, sub, err)
			}
			return
		}
		if fo.EndOfRange != 0 {
			continue
		}
		sub.mu.Lock()
		sub.open[rs] = fo.Group
		sub.mu.Unlock()
		sub.push(&fo.Object, false)
	}
}

// dataErr handles an error reading a data stream of sub.
func (s *Session) dataErr(rs *kolotransport.ReceiveStream, sub *Subscription, err error) {
	var we *wire.Error
	switch {
	case errors.As(err, &we):
		s.fail(SessionCode(we.Code), ErrProtocol)
	case errors.Is(err, wire.ErrTooLarge):
		rs.CancelRead(resetExcessiveLoad)
		if sub != nil {
			sub.fail(ErrObjectTooLarge)
		}
	case errors.Is(err, wire.ErrMalformedTrack):
		rs.CancelRead(resetMalformedTrack)
		if sub != nil {
			sub.fail(ErrMalformedTrack)
		}
	}
}

// readDataStream dispatches one unidirectional stream from the peer.
func (s *Session) readDataStream(rs *kolotransport.ReceiveStream) {
	br := bufio.NewReader(rs)
	rs.SetReadDeadline(time.Now().Add(s.cfg.RequestTimeout))
	t, err := wire.ReadVarint(br)
	if err != nil {
		rs.CancelRead(resetCancelled)
		return
	}
	switch {
	case wire.IsSubgroupType(t):
		h, err := wire.ReadSubgroupHeader(br, t)
		if err != nil {
			s.protocolErr(err)
			rs.CancelRead(resetCancelled)
			return
		}
		sub := s.waitAlias(h.TrackAlias)
		rs.SetReadDeadline(time.Time{})
		if sub == nil {
			rs.CancelRead(resetCancelled)
			return
		}
		s.readSubgroup(rs, br, h, sub)
	case t == wire.StreamTypeFetch:
		id, err := wire.ReadVarint(br)
		rs.SetReadDeadline(time.Time{})
		if err != nil {
			rs.CancelRead(resetCancelled)
			return
		}
		s.mu.Lock()
		target := s.fetchByReq[id]
		s.mu.Unlock()
		if target == nil {
			rs.CancelRead(resetCancelled)
			return
		}
		target.fetchStream(rs, br)
	case t == wire.StreamTypePadding:
		rs.SetReadDeadline(time.Time{})
		io.Copy(io.Discard, br)
	default:
		s.fail(CodeProtocolViolation, ErrProtocol)
	}
}

// waitAlias returns the subscription of a Track Alias, waiting up to
// RequestTimeout for its SUBSCRIBE_OK (draft section 3.1.3.1).
func (s *Session) waitAlias(alias uint64) *Subscription {
	t := time.NewTimer(s.cfg.RequestTimeout)
	defer t.Stop()
	for {
		s.mu.Lock()
		sub, wake := s.aliases[alias], s.aliasWake
		s.mu.Unlock()
		if sub != nil {
			return sub
		}
		select {
		case <-wake:
		case <-t.C:
			return nil
		case <-s.ctx.Done():
			return nil
		}
	}
}

func (s *Session) readSubgroup(rs *kolotransport.ReceiveStream, br *bufio.Reader, h *wire.SubgroupHeader, sub *Subscription) {
	if !sub.addStream(rs, h.Group) {
		rs.CancelRead(resetCancelled)
		return
	}
	defer sub.removeStream(rs)
	if h.Flags&wire.SubgroupDefaultPrio != 0 {
		h.Priority = sub.trackPrio
	}
	sr := &wire.SubgroupReader{R: br, Header: h, MaxPayload: uint64(s.cfg.MaxObjectSize)}
	first := true
	var last uint64
	for {
		o, err := sr.Next()
		if err == io.EOF {
			if !first && sub.relay != nil {
				sub.relay.endSubgroup(h.Group, h.Subgroup, last, h.Flags&wire.SubgroupEndOfGroup != 0, false)
			}
			return
		}
		if err != nil {
			s.dataErr(rs, sub, err)
			if !first && sub.relay != nil {
				sub.relay.endSubgroup(h.Group, h.Subgroup, last, false, true)
			}
			return
		}
		last = o.ID
		if first && h.Mode() == wire.SubgroupModeFirstID {
			h.Subgroup, o.Subgroup = o.ID, o.ID
		}
		sub.push(o, first && h.Flags&wire.SubgroupFirstObject != 0)
		first = false
	}
}
