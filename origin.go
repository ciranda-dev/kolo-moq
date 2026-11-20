package kolomoq

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"fmt"
	"slices"
	"sort"
	"sync"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// Track properties kolo-moq sets itself (draft section 10).
const (
	propObjectTimeout   = 0x02
	propSubgroupTimeout = 0x06
	propDefaultPriority = 0x0E
	propDefaultOrder    = 0x22
	propDynamicGroups   = 0x30
)

// source answers SUBSCRIBE, FETCH, TRACK_STATUS and namespace requests: an
// Origin, or a Relay.
type source interface {
	acquire(ctx context.Context, s *Session, kind RequestKind, ns Namespace, name string) (*track, error)
	release(t *track)
	watchNamespaces(prefix Namespace, fn func(ns Namespace, active bool)) (initial []Namespace, cancel func())
	publishNamespace(s *Session, ns Namespace) (cancel func(), err error)
	// servesKeys reports whether the source answers requests under KeyNamespaceField.
	servesKeys() bool
}

// OriginConfig sets the limits of an Origin. A zero field takes its default.
type OriginConfig struct {
	// MaxTracks caps the open tracks. Default 1000, from 1 to 1000000.
	MaxTracks int
	// MaxObjectSize caps an object payload, in bytes. Default 16 MiB, from 1 KiB to 1 GiB.
	MaxObjectSize int
}

// Origin holds the tracks one side publishes. Many sessions can serve the
// same Origin: each subscriber gets its own queue, so a slow one never
// blocks the writer or the others. Its methods are safe for concurrent use.
type Origin struct {
	maxTracks int
	maxObject int

	mu       sync.Mutex
	tracks   map[string]*track
	nsCount  map[string]int
	watchers map[*nsWatcher]struct{}
}

type nsWatcher struct {
	prefix Namespace
	fn     func(Namespace, bool)
}

// NewOrigin returns an empty Origin.
func NewOrigin(cfg *OriginConfig) (*Origin, error) {
	var c OriginConfig
	if cfg != nil {
		c = *cfg
	}
	if err := (limit[int]{"MaxTracks", 1000, 1, 1_000_000}).apply(&c.MaxTracks); err != nil {
		return nil, err
	}
	if err := (limit[int]{"MaxObjectSize", 16 << 20, 1 << 10, 1 << 30}).apply(&c.MaxObjectSize); err != nil {
		return nil, err
	}
	return &Origin{
		maxTracks: c.MaxTracks,
		maxObject: c.MaxObjectSize,
		tracks:    map[string]*track{},
		nsCount:   map[string]int{},
		watchers:  map[*nsWatcher]struct{}{},
	}, nil
}

// TrackOptions sets how a track is published. A nil *TrackOptions takes
// every default; in a non-nil one, Priority is used as is.
type TrackOptions struct {
	// Priority is the publisher priority, 0 (most urgent) to 255; nil options give DefaultPriority.
	Priority uint8
	// GroupOrder is the publisher's preferred group order. Default OrderAscending.
	GroupOrder GroupOrder
	// SubgroupDeliveryTimeout resets a group's stream that is not fully sent this long after the group ended. Zero means none; millisecond precision, rounded up.
	SubgroupDeliveryTimeout time.Duration
	// ObjectDeliveryTimeout resets a group's stream when an object waited this long to be sent. Zero means none; millisecond precision, rounded up.
	ObjectDeliveryTimeout time.Duration
	// CacheGroups caps the newest groups kept for FETCH and late joiners. Default 16, from 1 to 1000000.
	CacheGroups int
	// CacheBytes caps the payload bytes kept, in bytes. Default 32 MiB, from 1 KiB to 64 GiB.
	CacheBytes int64
	// Properties are extra track properties sent to subscribers; types 0x02, 0x06, 0x0E and 0x22 are set from the fields above.
	Properties []Property
	// Readers, if non-nil, are the only peers that may SUBSCRIBE to, FETCH or ask TRACK_STATUS of the track, whatever Config.Authorize decides; others get DOES_NOT_EXIST, also through a relay. An empty non-nil slice admits nobody. Each key must be 32 bytes.
	Readers []ed25519.PublicKey
}

// CreateTrack adds a track to the origin and returns its writer.
func (o *Origin) CreateTrack(ns Namespace, name string, opts *TrackOptions) (*TrackWriter, error) {
	t, err := newTrack(ns, name, opts, o.maxObject)
	if err != nil {
		return nil, err
	}
	nsKey := ns.key()
	o.mu.Lock()
	defer o.mu.Unlock()
	if _, ok := o.tracks[t.key]; ok {
		return nil, ErrTrackExists
	}
	if len(o.tracks) >= o.maxTracks {
		return nil, ErrTooManyTracks
	}
	o.tracks[t.key] = t
	o.nsCount[nsKey]++
	if o.nsCount[nsKey] == 1 {
		o.notify(ns, true)
	}
	return &TrackWriter{t: t, o: o}, nil
}

func (o *Origin) notify(ns Namespace, active bool) {
	for w := range o.watchers {
		if ns.HasPrefix(w.prefix) {
			w.fn(ns, active)
		}
	}
}

func (o *Origin) remove(t *track) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.tracks[t.key] != t {
		return
	}
	delete(o.tracks, t.key)
	nsKey := t.ns.key()
	o.nsCount[nsKey]--
	if o.nsCount[nsKey] == 0 {
		delete(o.nsCount, nsKey)
		o.notify(t.ns, false)
	}
}

func (o *Origin) acquire(_ context.Context, s *Session, _ RequestKind, ns Namespace, name string) (*track, error) {
	o.mu.Lock()
	t := o.tracks[trackKey(ns, name)]
	o.mu.Unlock()
	if t == nil || !t.readable(s.peer) {
		return nil, &RequestError{Code: ReqDoesNotExist}
	}
	return t, nil
}

func (*Origin) servesKeys() bool { return true }

func (o *Origin) release(*track) {}

func (o *Origin) watchNamespaces(prefix Namespace, fn func(Namespace, bool)) ([]Namespace, func()) {
	w := &nsWatcher{prefix: prefix, fn: fn}
	o.mu.Lock()
	defer o.mu.Unlock()
	seen := map[string]bool{}
	var initial []Namespace
	for _, t := range o.tracks {
		k := t.ns.key()
		if !seen[k] && t.ns.HasPrefix(prefix) {
			seen[k] = true
			initial = append(initial, t.ns)
		}
	}
	o.watchers[w] = struct{}{}
	return initial, func() {
		o.mu.Lock()
		delete(o.watchers, w)
		o.mu.Unlock()
	}
}

func (o *Origin) publishNamespace(*Session, Namespace) (func(), error) { return func() {}, nil }

func trackKey(ns Namespace, name string) string { return ns.key() + name }

// TrackWriter publishes the groups of one track. Its methods are safe for
// concurrent use.
type TrackWriter struct {
	t *track
	o *Origin

	mu     sync.Mutex
	group  *GroupWriter
	next   uint64
	closed bool
}

// GroupWriter writes the objects of one group, numbered from 0.
type GroupWriter struct {
	w      *TrackWriter
	id     uint64
	next   uint64
	closed bool
}

// NewGroup ends the open group, if any, and starts the next one; group IDs
// start at 0 and increase by one.
func (w *TrackWriter) NewGroup() (*GroupWriter, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return nil, ErrClosed
	}
	if w.group != nil {
		w.endGroup(wire.StatusEndOfGroup)
	}
	w.group = &GroupWriter{w: w, id: w.next}
	w.next++
	return w.group, nil
}

func (w *TrackWriter) endGroup(status uint64) {
	g := w.group
	w.t.add(newCobj(wire.Object{Group: g.id, ID: g.next, Priority: w.t.prio, Status: status}, false))
	w.t.endSubgroup(g.id, 0, g.next, true)
	g.closed = true
	w.group = nil
}

// Close ends the track: the open group ends with an End of Track object,
// subscribers get PUBLISH_DONE TRACK_ENDED once their queues are sent, and
// the track leaves the origin.
func (w *TrackWriter) Close() error {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		return ErrClosed
	}
	w.closed = true
	if w.group != nil {
		w.endGroup(wire.StatusEndOfTrack)
	} else {
		w.t.add(newCobj(wire.Object{Group: w.next, Priority: w.t.prio, Status: wire.StatusEndOfTrack}, false))
		w.t.endSubgroup(w.next, 0, 0, true)
	}
	w.mu.Unlock()
	w.t.end(DoneTrackEnded)
	w.o.remove(w.t)
	return nil
}

// NewGroupRequests returns a channel that receives when a subscriber asks for a new group with RequestNewGroup
// and no newer group exists. The application then calls NewGroup and writes a group that a late subscriber can
// start from: for video, one that begins with a key frame. Requests merge while one is pending, and the track
// signals at most once every NewGroupRequestInterval, however many subscriptions ask.
func (w *TrackWriter) NewGroupRequests() <-chan struct{} { return w.t.newGroup }

// Subscribers returns the number of subscriptions the track has now, over
// all sessions.
func (w *TrackWriter) Subscribers() int {
	w.t.mu.Lock()
	defer w.t.mu.Unlock()
	return len(w.t.subs)
}

// ID returns the group ID.
func (g *GroupWriter) ID() uint64 { return g.id }

// Priority returns the publisher priority of the group's track.
func (g *GroupWriter) Priority() uint8 { return g.w.t.prio }

// WriteObject publishes the next object of the group and returns its ID.
// The payload and properties are copied.
func (g *GroupWriter) WriteObject(payload []byte, props ...Property) (uint64, error) {
	kvs, err := g.w.checkObject(payload, props)
	if err != nil {
		return 0, err
	}
	g.w.mu.Lock()
	defer g.w.mu.Unlock()
	if g.closed {
		return 0, ErrClosed
	}
	return g.put(payload, kvs), nil
}

// WriteObjectFunc publishes the next object of the group with the payload and properties that build returns for its Object ID, holding the group for the whole call.
// If build or the checks of its result fail, no ID is used. build must not call methods of this track's writers.
func (g *GroupWriter) WriteObjectFunc(build func(id uint64) ([]byte, []Property, error)) (uint64, error) {
	g.w.mu.Lock()
	defer g.w.mu.Unlock()
	if g.closed {
		return 0, ErrClosed
	}
	payload, props, err := build(g.next)
	if err != nil {
		return 0, err
	}
	kvs, err := g.w.checkObject(payload, props)
	if err != nil {
		return 0, err
	}
	return g.put(payload, kvs), nil
}

// checkObject validates an object and returns its properties as wire values.
func (w *TrackWriter) checkObject(payload []byte, props []Property) ([]wire.KV, error) {
	if len(payload) > w.t.maxObject {
		return nil, ErrObjectTooLarge
	}
	if err := checkProperties(props); err != nil {
		return nil, err
	}
	kvs := toKVs(props)
	if wire.KVsLen(kvs) > wire.MaxMessageLen {
		return nil, ErrInvalidProperty
	}
	if err := wire.CheckObjectProperties(kvs); err != nil {
		return nil, ErrInvalidProperty
	}
	return kvs, nil
}

// put adds the next object; the caller holds the track writer's lock.
func (g *GroupWriter) put(payload []byte, kvs []wire.KV) uint64 {
	id := g.next
	g.next++
	data := slices.Clone(payload)
	if data == nil {
		data = []byte{}
	}
	g.w.t.add(newCobj(wire.Object{Group: g.id, ID: id, Priority: g.w.t.prio, Properties: kvs, Payload: data}, id == 0))
	return id
}

// Close ends the group with an End of Group object.
func (g *GroupWriter) Close() error {
	w := g.w
	w.mu.Lock()
	defer w.mu.Unlock()
	if g.closed {
		return ErrClosed
	}
	w.endGroup(wire.StatusEndOfGroup)
	return nil
}

// cobj is a published object with the time it was published.
type cobj struct {
	wire.Object
	at    time.Time
	first bool
	sz    int64
}

func newCobj(o wire.Object, first bool) *cobj {
	return &cobj{Object: o, at: time.Now(), first: first, sz: objectSize(&o)}
}

func (o *cobj) size() int64 { return o.sz }

// Memory an object and each of its properties cost beyond their bytes, so
// empty objects and properties count against the queue and cache limits.
const (
	objectOverhead   = 64
	propertyOverhead = 48
)

func objectSize(o *wire.Object) int64 {
	n := int64(len(o.Payload)) + objectOverhead
	for _, kv := range o.Properties {
		n += propertyOverhead + int64(len(kv.Bytes))
	}
	return n
}

type cgroup struct {
	id      uint64
	objs    []*cobj
	ids     map[uint64]*cobj
	maxID   uint64
	endID   uint64 // ID of the final object of the group, if hasEnd
	hasEnd  bool
	trimmed bool
	floor   uint64 // IDs below it were trimmed and are not taken again
	bytes   int64

	// What the rules of draft section 12.1 need per subgroup; dropped when the
	// group is trimmed, so it stays within the cache bounds.
	sub   map[uint64]*subShape
	noSub bool
}

// subShape is what a track has shown of one subgroup.
type subShape struct {
	prio     uint8
	maxID    uint64
	final    uint64
	hasFinal bool
}

// subShapeOverhead is the memory a subgroup entry costs beyond the objects.
const subShapeOverhead = 48

// track is one published track: its cache and its subscriptions.
type track struct {
	ns         Namespace
	name       string
	key        string
	prio       uint8
	order      GroupOrder
	objTimeout time.Duration
	sgTimeout  time.Duration
	props      []wire.KV
	maxGroups  int
	maxBytes   int64
	maxObject  int
	relay      *relayTrack
	newGroup   chan struct{} // signals a subscriber's request for a new group; cap 1
	ngMu       sync.Mutex
	lastNG     time.Time // when the track last signalled a new group request
	readers    []ed25519.PublicKey
	restricted bool

	mu          sync.Mutex
	groups      []*cgroup
	bytes       int64
	largest     wire.Location
	hasLargest  bool
	subs        map[*pubSub]struct{}
	ended       bool
	endCode     DoneCode
	final       bool // End of Track was seen
	finalLoc    wire.Location
	malformedCh chan struct{}
}

func newTrack(ns Namespace, name string, opts *TrackOptions, maxObject int) (*track, error) {
	cfg := Config{MaxNamespaceFields: wire.MaxNamespaceFields, MaxNameLength: wire.MaxFullNameLen}
	if err := cfg.checkName(ns, name, true); err != nil {
		return nil, err
	}
	o := TrackOptions{Priority: DefaultPriority}
	if opts != nil {
		o = *opts
	}
	if o.GroupOrder == OrderDefault {
		o.GroupOrder = OrderAscending
	}
	if o.GroupOrder > OrderDescending || o.SubgroupDeliveryTimeout < 0 || o.ObjectDeliveryTimeout < 0 {
		return nil, fmt.Errorf("%w: invalid track options", ErrInvalidConfig)
	}
	if err := (limit[int]{"CacheGroups", 16, 1, 1_000_000}).apply(&o.CacheGroups); err != nil {
		return nil, err
	}
	if err := (limit[int64]{"CacheBytes", 32 << 20, 1 << 10, 64 << 30}).apply(&o.CacheBytes); err != nil {
		return nil, err
	}
	if err := checkProperties(o.Properties); err != nil {
		return nil, err
	}
	props := []wire.KV{
		{Type: propDefaultPriority, Value: uint64(o.Priority)},
		{Type: propDefaultOrder, Value: uint64(o.GroupOrder)},
	}
	if o.ObjectDeliveryTimeout > 0 {
		props = append(props, wire.KV{Type: propObjectTimeout, Value: toMS(o.ObjectDeliveryTimeout)})
	}
	if o.SubgroupDeliveryTimeout > 0 {
		props = append(props, wire.KV{Type: propSubgroupTimeout, Value: toMS(o.SubgroupDeliveryTimeout)})
	}
	for _, p := range o.Properties {
		switch p.Type {
		case propObjectTimeout, propSubgroupTimeout, propDefaultPriority, propDefaultOrder:
			return nil, ErrInvalidProperty
		}
	}
	props = append(props, toKVs(o.Properties)...)
	for _, k := range o.Readers {
		if len(k) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: reader key is not %d bytes", ErrInvalidConfig, ed25519.PublicKeySize)
		}
	}
	// SUBSCRIBE_OK, FETCH_OK and REQUEST_OK must stay within 65535 bytes.
	if wire.KVsLen(props) > wire.MaxMessageLen-64 {
		return nil, ErrInvalidProperty
	}
	return &track{
		ns: slices.Clone(ns), name: name, key: trackKey(ns, name),
		prio: o.Priority, order: o.GroupOrder,
		objTimeout: o.ObjectDeliveryTimeout, sgTimeout: o.SubgroupDeliveryTimeout,
		props: props, maxGroups: o.CacheGroups, maxBytes: o.CacheBytes, maxObject: maxObject,
		subs: map[*pubSub]struct{}{}, malformedCh: make(chan struct{}), newGroup: make(chan struct{}, 1),
		readers: cloneKeys(o.Readers), restricted: o.Readers != nil,
	}, nil
}

func cloneKeys(keys []ed25519.PublicKey) []ed25519.PublicKey {
	out := make([]ed25519.PublicKey, len(keys))
	for i, k := range keys {
		out[i] = slices.Clone(k)
	}
	return out
}

// readable reports whether peer may read the track.
func (t *track) readable(peer ed25519.PublicKey) bool {
	return !t.restricted || slices.ContainsFunc(t.readers, func(k ed25519.PublicKey) bool { return k.Equal(peer) })
}

func (t *track) groupIndex(id uint64) (int, bool) {
	i := sort.Search(len(t.groups), func(i int) bool { return t.groups[i].id >= id })
	return i, i < len(t.groups) && t.groups[i].id == id
}

// add caches o and offers it to every subscription; a repeated object is
// dropped. An object that makes the track malformed (draft sections 7.1
// and 12.1) is not cached, the track ends with MALFORMED_TRACK and add
// returns false.
func (t *track) add(o *cobj) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended {
		return true
	}
	i, ok := t.groupIndex(o.Group)
	var g *cgroup
	if ok {
		g = t.groups[i]
	}
	if malformed(t, g, o) {
		t.endLocked(DoneMalformedTrack, true)
		return false
	}
	if g == nil {
		g = &cgroup{id: o.Group, ids: map[uint64]*cobj{}}
		t.groups = slices.Insert(t.groups, i, g)
	}
	if g.ids[o.ID] != nil || o.ID < g.floor {
		return true
	}
	g.ids[o.ID] = o
	g.objs = append(g.objs, o)
	g.maxID = max(g.maxID, o.ID)
	if o.Status == wire.StatusEndOfGroup {
		g.endID, g.hasEnd = o.ID, true
	}
	n := o.size()
	if !g.noSub {
		if g.sub == nil {
			g.sub = map[uint64]*subShape{}
		}
		s := g.sub[o.Subgroup]
		if s == nil {
			s = &subShape{prio: o.Priority}
			g.sub[o.Subgroup] = s
			n += subShapeOverhead
		}
		s.maxID = max(s.maxID, o.ID)
	}
	g.bytes += n
	t.bytes += n
	loc := wire.Location{Group: o.Group, Object: o.ID}
	if !t.hasLargest || t.largest.Less(loc) {
		t.largest, t.hasLargest = loc, true
	}
	if o.Status == wire.StatusEndOfTrack {
		t.final, t.finalLoc = true, loc
	}
	t.evict()
	for sub := range t.subs {
		sub.offer(o)
	}
	return true
}

// malformed applies the rules of draft section 12.1 that a cache can check,
// with the state it keeps: a repeated object that differs (items 6 and 7),
// another priority in a subgroup (1), objects beyond the end of a subgroup,
// group or track (2, 4 and 5).
func malformed(t *track, g *cgroup, o *cobj) bool {
	loc := wire.Location{Group: o.Group, Object: o.ID}
	if t.final && t.finalLoc.Less(loc) {
		return true
	}
	if o.Status == wire.StatusEndOfTrack && t.hasLargest && loc.Less(t.largest) {
		return true
	}
	if g == nil {
		return false
	}
	if old := g.ids[o.ID]; old != nil {
		return old.Subgroup != o.Subgroup || old.Priority != o.Priority || old.Status != o.Status ||
			old.Datagram != o.Datagram || !bytes.Equal(old.Payload, o.Payload) || !bytes.Equal(immutable(old.Properties), immutable(o.Properties))
	}
	if g.hasEnd && o.ID > g.endID {
		return true
	}
	if s := g.sub[o.Subgroup]; s != nil && (s.prio != o.Priority || (s.hasFinal && o.ID > s.final)) {
		return true
	}
	return o.Status == wire.StatusEndOfGroup && len(g.objs) > 0 && g.maxID > o.ID
}

// immutable returns the Immutable Properties value of an object, which a
// repeat of the object must not change (draft section 10.7).
func immutable(kvs []wire.KV) []byte {
	for _, kv := range kvs {
		if kv.Type == wire.PropImmutable {
			return kv.Bytes
		}
	}
	return nil
}

func (t *track) evict() {
	for len(t.groups) > 1 && (len(t.groups) > t.maxGroups || t.bytes > t.maxBytes) {
		t.bytes -= t.groups[0].bytes
		t.groups[0] = nil
		t.groups = t.groups[1:]
	}
	if len(t.groups) == 1 {
		g := t.groups[0]
		for t.bytes > t.maxBytes && len(g.objs) > 1 {
			if !g.noSub {
				// Without the early objects the subgroup rules cannot be checked
				// any more; stop tracking them rather than hold them without bound.
				n := int64(len(g.sub)) * subShapeOverhead
				g.sub, g.noSub = nil, true
				g.bytes -= n
				t.bytes -= n
			}
			o := g.objs[0]
			n := o.size()
			delete(g.ids, o.ID)
			g.floor = max(g.floor, o.ID+1)
			g.objs[0] = nil
			g.objs = g.objs[1:]
			g.bytes -= n
			t.bytes -= n
			g.trimmed = true
		}
	}
}

// endSubgroup records that the stream of a subgroup ended with FIN after
// object last, and delivers the end to the subscriptions. endOfGroup says
// the stream carried the final object of its group. It returns false, after
// ending the track, when the end makes the track malformed (section 12.1,
// items 2 to 4).
func (t *track) endSubgroup(group, subgroup, last uint64, endOfGroup bool) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if !t.ended {
		if i, ok := t.groupIndex(group); ok {
			g := t.groups[i]
			bad := false
			if s := g.sub[subgroup]; s != nil {
				bad = (s.hasFinal && s.final != last) || s.maxID > last
				s.final, s.hasFinal = last, true
			}
			if endOfGroup {
				bad = bad || (g.hasEnd && g.endID != last) || g.maxID > last
				g.endID, g.hasEnd = last, true
			}
			if bad {
				t.endLocked(DoneMalformedTrack, true)
				return false
			}
		}
	}
	for sub := range t.subs {
		sub.endSubgroup(group, subgroup, false)
	}
	return true
}

func (t *track) resetSubgroup(group, subgroup uint64) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for sub := range t.subs {
		sub.endSubgroup(group, subgroup, true)
	}
}

// end stops the track: each subscription gets PUBLISH_DONE with code once
// its streams are closed.
func (t *track) end(code DoneCode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.endLocked(code, code == DoneMalformedTrack)
}

// endLocked ends the track; with reset, open streams and fetches are reset
// instead of completed.
func (t *track) endLocked(code DoneCode, reset bool) {
	if t.ended {
		return
	}
	t.ended, t.endCode = true, code
	if reset {
		close(t.malformedCh)
	}
	for sub := range t.subs {
		sub.trackEnded(code, reset)
	}
}

// attach registers sub and returns the Largest Object; a track that ended or
// cached its End of Track takes no new subscription.
func (t *track) attach(sub *pubSub) (wire.Location, bool, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.ended || t.final {
		return t.largest, t.hasLargest, false
	}
	t.subs[sub] = struct{}{}
	return t.largest, t.hasLargest, true
}

func (t *track) detach(sub *pubSub) int {
	t.mu.Lock()
	defer t.mu.Unlock()
	delete(t.subs, sub)
	return len(t.subs)
}

// requestNewGroup tells the publisher of the track that a subscriber wants a new group: a relayed track passes the
// request upstream, any other signals its TrackWriter, merging with a signal not yet taken. A request within
// NewGroupRequestInterval of the last one is dropped: the group that answered that one reaches every subscriber.
func (t *track) requestNewGroup() {
	t.ngMu.Lock()
	soon := !t.lastNG.IsZero() && time.Since(t.lastNG) < NewGroupRequestInterval
	if !soon {
		t.lastNG = time.Now()
	}
	t.ngMu.Unlock()
	if soon {
		return
	}
	if t.relay != nil {
		t.relay.forwardNewGroup()
		return
	}
	select {
	case t.newGroup <- struct{}{}:
	default:
	}
}

func (t *track) status() (wire.Location, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	return t.largest, t.hasLargest
}

// fetchEntry is one entry of a fetch stream: an object, or an End of
// Unknown Range marker at loc.
type fetchEntry struct {
	obj *cobj
	loc wire.Location
}

// snapshot returns the cached normal objects from start to end in the
// given group order, with End of Unknown Range markers where the cache no
// longer holds objects.
func (t *track) snapshot(start, end wire.Location, order GroupOrder) []fetchEntry {
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []fetchEntry
	for _, g := range t.groups {
		if g.id < start.Group || g.id > end.Group {
			continue
		}
		objs := slices.Clone(g.objs)
		slices.SortFunc(objs, func(a, b *cobj) int { return cmpU64(a.ID, b.ID) })
		var entries []fetchEntry
		if g.trimmed && len(objs) > 0 && objs[0].ID > 0 {
			loc := wire.Location{Group: g.id, Object: objs[0].ID - 1}
			if !loc.Less(start) && !end.Less(loc) {
				entries = append(entries, fetchEntry{loc: loc})
			}
		}
		for _, o := range objs {
			loc := wire.Location{Group: o.Group, Object: o.ID}
			if loc.Less(start) || end.Less(loc) || o.Status != wire.StatusNormal {
				continue
			}
			entries = append(entries, fetchEntry{obj: o})
		}
		if order == OrderDescending {
			out = append(entries, out...)
		} else {
			out = append(out, entries...)
		}
	}
	if len(t.groups) > 0 && start.Group < t.groups[0].id && end.Group >= t.groups[0].id {
		marker := fetchEntry{loc: wire.Location{Group: t.groups[0].id - 1, Object: ^uint64(0)}}
		if order == OrderDescending {
			out = append(out, marker)
		} else {
			out = append([]fetchEntry{marker}, out...)
		}
	}
	return out
}

func cmpU64(a, b uint64) int {
	switch {
	case a < b:
		return -1
	case a > b:
		return 1
	}
	return 0
}
