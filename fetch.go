package kolomoq

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// FetchOptions selects the objects a Fetch asks for. A nil *FetchOptions
// fetches the current group; in a non-nil one, Priority is used as is.
type FetchOptions struct {
	// RecentGroups, when above zero, fetches the newest RecentGroups groups up to the Largest Object; 1 is the current group.
	RecentGroups uint64
	// Start is the first location of an absolute range, used when RecentGroups is zero.
	Start Location
	// End is the last location of the range, inclusive; nil means up to the Largest Object.
	End *Location
	// Priority is the subscriber priority, 0 (most urgent) to 255.
	Priority uint8
	// GroupOrder is the order groups are sent in. Default OrderAscending.
	GroupOrder GroupOrder
}

// Fetch receives the cached objects of a track that a FETCH asked for.
type Fetch struct {
	s     *Session
	r     *reqStream
	reqID uint64
	desc  bool
	end   Location
	eot   bool
	props []Property

	rawProps []wire.KV
	got      chan struct{}
	once     sync.Once

	mu     sync.Mutex
	rs     *kolotransport.ReceiveStream
	fr     *wire.FetchReader
	closed bool
	err    error // why no data stream will arrive
	timer  *time.Timer
}

// Fetch asks the peer for cached objects and returns once the peer accepted
// (FETCH_OK) or refused (*RequestError, INVALID_RANGE when nothing is
// cached in the range).
func (s *Session) Fetch(ctx context.Context, ns Namespace, track string, opts *FetchOptions) (*Fetch, error) {
	if err := s.cfg.checkName(ns, track, true); err != nil {
		return nil, err
	}
	o := FetchOptions{Priority: DefaultPriority, RecentGroups: 1}
	if opts != nil {
		o = *opts
	}
	if o.GroupOrder > OrderDescending || (o.End != nil && o.End.Less(o.Start)) {
		return nil, fmt.Errorf("%w: invalid fetch options", ErrInvalidConfig)
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
	prm.Set(wire.ParamLocationFilter)
	switch {
	case o.RecentGroups > 0:
		prm.Filter = wire.LocationFilter{Type: wire.FilterRelativeStart, StartGroup: o.RecentGroups}
	case o.End == nil:
		prm.Filter = wire.LocationFilter{Type: wire.FilterAbsoluteStart, StartGroup: o.Start.Group, StartObject: o.Start.Object}
	default:
		prm.Filter = wire.LocationFilter{Type: wire.FilterAbsoluteRange, StartGroup: o.Start.Group, StartObject: o.Start.Object,
			EndGroup: o.End.Group, EndObject: o.End.Object}
	}
	var start *wire.Location
	if o.RecentGroups == 0 {
		start = (*wire.Location)(&o.Start)
	}
	return s.fetch(ctx, id, ns, track, prm, start)
}

// fetch sends a FETCH; start, when known, is checked against FETCH_OK.
func (s *Session) fetch(ctx context.Context, id uint64, ns Namespace, track string, prm *wire.MessageParams, start *wire.Location) (*Fetch, error) {
	desc := prm.Has(wire.ParamGroupOrder) && prm.GroupOrder == uint8(OrderDescending)
	f := &Fetch{s: s, reqID: id, desc: desc, got: make(chan struct{})}
	s.mu.Lock()
	s.fetchByReq[id] = f
	s.mu.Unlock()
	r, t, body, err := s.request(ctx, &wire.Request{Type: wire.MsgFetch, RequestID: id, Namespace: ns, Name: track, Params: prm}, true)
	if err != nil {
		f.Close()
		return nil, err
	}
	f.r = r
	if t != wire.MsgFetchOK {
		err := s.refused(r, t, body)
		f.Close()
		return nil, err
	}
	m, err := wire.ParseFetchOK(body)
	if err == nil {
		err = checkTrackProperties(m.Properties)
	}
	if err == nil && start != nil && m.End.Less(*start) {
		err = &wire.Error{Code: uint64(CodeProtocolViolation), Msg: "FETCH_OK End Location before the start"}
	}
	if err != nil {
		f.Close()
		s.protocolErr(err)
		return nil, s.errOr(err)
	}
	if mandatory(m.Properties) {
		f.Close()
		return nil, ErrUnsupportedProperty
	}
	f.end, f.eot, f.props, f.rawProps = Location(m.End), m.EndOfTrack, fromKVs(m.Properties), m.Properties
	f.mu.Lock()
	if f.rs == nil && !f.closed && f.err == nil {
		// The data stream has to arrive within RequestTimeout of FETCH_OK.
		f.timer = time.AfterFunc(s.cfg.RequestTimeout, func() { f.noStream(s.errOr(ErrTimeout)) })
	}
	f.mu.Unlock()
	if !s.start(f.readResponses) {
		f.Close()
		return nil, s.errOr(ErrClosed)
	}
	return f, nil
}

// End returns the last location the fetch covers, from FETCH_OK.
func (f *Fetch) End() Location { return f.end }

// EndOfTrack reports whether End is the last object of the track.
func (f *Fetch) EndOfTrack() bool { return f.eot }

// Properties returns a copy of the track properties from FETCH_OK.
func (f *Fetch) Properties() []Property { return cloneProperties(f.props) }

func (f *Fetch) fetchStream(rs *kolotransport.ReceiveStream, br *bufio.Reader) {
	f.mu.Lock()
	dup := f.rs != nil || f.closed || f.err != nil
	if !dup {
		f.rs = rs
		f.fr = &wire.FetchReader{R: br, Descending: f.desc, MaxPayload: uint64(f.s.cfg.MaxObjectSize)}
		if f.timer != nil {
			f.timer.Stop()
		}
	}
	f.mu.Unlock()
	if dup {
		rs.CancelRead(resetCancelled)
		return
	}
	f.once.Do(func() { close(f.got) })
	f.unregister()
}

// noStream records that no data stream will come, and wakes the reader.
func (f *Fetch) noStream(err error) {
	f.mu.Lock()
	first := f.rs == nil && !f.closed && f.err == nil
	if first {
		f.err = err
	}
	f.mu.Unlock()
	if !first {
		return
	}
	f.once.Do(func() { close(f.got) })
	f.r.cancel(resetCancelled)
	f.unregister()
}

func (f *Fetch) unregister() {
	s := f.s
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.fetchByReq[f.reqID] == fetchTarget(f) {
		delete(s.fetchByReq, f.reqID)
	}
}

// ReadObject returns the next object; io.EOF after the last one. Calls must
// not overlap.
func (f *Fetch) ReadObject(ctx context.Context) (Object, error) {
	for {
		fo, err := f.next(ctx)
		if err != nil {
			return Object{}, err
		}
		if fo.EndOfRange == 0 {
			return objectFromWire(&fo.Object), nil
		}
	}
}

// next returns the next entry of the fetch stream, End of Range markers
// included.
func (f *Fetch) next(ctx context.Context) (*wire.FetchObject, error) {
	select {
	case <-f.got:
	case <-f.s.done:
		return nil, f.s.Err()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	f.mu.Lock()
	closed, rs, fr, ferr := f.closed, f.rs, f.fr, f.err
	f.mu.Unlock()
	if closed {
		return nil, ErrClosed
	}
	if fr == nil {
		return nil, ferr
	}
	stop := interruptOnDone(ctx, rs.SetReadDeadline)
	defer stop()
	fo, err := fr.Next()
	if err != nil {
		if ctx.Err() != nil {
			f.Close()
			return nil, wrapErr("fetch", ctx.Err())
		}
		if err != io.EOF {
			f.s.dataErr(rs, nil, err)
			f.Close()
			err = f.s.errOr(fetchError(err))
		}
		return nil, err
	}
	return fo, nil
}

// fetchError maps an error from a fetch data stream to the package's.
func fetchError(err error) error {
	switch code, isReset := streamCode(err); {
	case errors.Is(err, wire.ErrMalformedTrack), isReset && code == resetMalformedTrack:
		return ErrMalformedTrack
	case errors.Is(err, wire.ErrTooLarge):
		return ErrObjectTooLarge
	case isReset:
		return canceledErr(err)
	}
	var we *wire.Error
	if errors.As(err, &we) {
		return fmt.Errorf("%w: %s", ErrProtocol, we.Msg)
	}
	return wrapErr("fetch stream", err)
}

// Close cancels the fetch.
func (f *Fetch) Close() error {
	f.mu.Lock()
	f.closed = true
	rs := f.rs
	if f.timer != nil {
		f.timer.Stop()
	}
	f.mu.Unlock()
	f.once.Do(func() { close(f.got) })
	if rs != nil {
		rs.CancelRead(resetCancelled)
	}
	if f.r != nil {
		f.r.cancel(resetCancelled)
	}
	f.unregister()
	return nil
}

// readResponses drains the request stream after FETCH_OK.
func (f *Fetch) readResponses() {
	s := f.s
	goaways := 0
	for {
		t, body, err := f.r.read(s.cfg.MaxControlMessageSize)
		if err != nil {
			if err != io.EOF {
				s.protocolErr(err)
				// Without a data stream yet, none will come; one that arrived keeps its own fate.
				f.noStream(canceledErr(err))
			}
			return
		}
		// This side sends no REQUEST_UPDATE for a fetch, so only a GOAWAY may follow FETCH_OK.
		if t != wire.MsgGoAway {
			s.fail(CodeProtocolViolation, ErrProtocol)
			return
		}
		if !s.requestGoAway(body, &goaways) {
			return
		}
	}
}

// TrackStatus is the publisher's view of a track (TRACK_STATUS_OK).
type TrackStatus struct {
	Largest    Location
	HasLargest bool
	Properties []Property
}

// TrackStatus asks the peer for the Largest Object and properties of a
// track without subscribing.
func (s *Session) TrackStatus(ctx context.Context, ns Namespace, track string) (*TrackStatus, error) {
	if err := s.cfg.checkName(ns, track, true); err != nil {
		return nil, err
	}
	id, err := s.newRequestID()
	if err != nil {
		return nil, err
	}
	r, t, body, err := s.request(ctx, &wire.Request{Type: wire.MsgTrackStatus, RequestID: id, Namespace: ns, Name: track, Params: &wire.MessageParams{}}, true)
	if err != nil {
		return nil, err
	}
	if t != wire.MsgRequestOK {
		return nil, s.refused(r, t, body)
	}
	m, err := wire.ParseRequestOK(body)
	if err == nil {
		err = checkTrackProperties(m.Properties)
	}
	if err != nil {
		s.protocolErr(err)
		return nil, s.errOr(err)
	}
	r.st.CancelRead(resetCancelled)
	st := &TrackStatus{Properties: fromKVs(m.Properties)}
	if m.Params.Has(wire.ParamLargestObject) {
		st.Largest, st.HasLargest = Location(m.Params.Largest), true
	}
	return st, nil
}
