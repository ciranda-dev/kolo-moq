package wire

import (
	"bytes"
	"errors"
	"io"
	"math"
)

// Subgroup header flags (section 11.3.1).
const (
	SubgroupProperties  = 0x01
	SubgroupModeMask    = 0x06
	SubgroupEndOfGroup  = 0x08
	SubgroupTypeBit     = 0x10
	SubgroupDefaultPrio = 0x20
	SubgroupFirstObject = 0x40

	SubgroupModeZero     = 0
	SubgroupModeFirstID  = 1
	SubgroupModeExplicit = 2
)

// Object Status values (section 11.1.1).
const (
	StatusNormal     = 0x0
	StatusEndOfGroup = 0x3
	StatusEndOfTrack = 0x4
)

// Fetch Serialization Flags (section 11.4.1).
const (
	FetchModeMask     = 0x03
	FetchObjectDelta  = 0x04
	FetchGroupDelta   = 0x08
	FetchPriority     = 0x10
	FetchProperties   = 0x20
	FetchDatagram     = 0x40
	EndOfNonExistent  = 0x8C
	EndOfUnknownRange = 0x10C
	EndOfTimedOut     = 0x20C
)

// Properties that make a track malformed when misused on an object.
const (
	PropImmutable        = 0x0B
	PropPriorGroupGap    = 0x3C
	PropPriorObjectGap   = 0x3E
	mandatoryTrackPropLo = 0x4000
	mandatoryTrackPropHi = 0x7FFF
)

var (
	// ErrTooLarge means an object payload exceeds the configured limit.
	ErrTooLarge = errors.New("kolomoq: object larger than the configured limit")
	// ErrMalformedTrack means an object breaks a rule of section 12.1.
	ErrMalformedTrack = errors.New("kolomoq: malformed track")
	// ErrIDNotIncreasing means a subgroup writer was given an object ID that
	// does not exceed the previous one.
	ErrIDNotIncreasing = errors.New("kolomoq: object ID does not increase within a subgroup")
)

// IsSubgroupType reports whether a stream type is a SUBGROUP_HEADER.
func IsSubgroupType(t uint64) bool { return t < 0x80 && t&SubgroupTypeBit != 0 }

// SubgroupHeader is a SUBGROUP_HEADER (section 11.3.1).
type SubgroupHeader struct {
	Flags      uint64
	TrackAlias uint64
	Group      uint64
	Subgroup   uint64
	Priority   uint8
}

// Mode returns the SUBGROUP_ID_MODE field.
func (h *SubgroupHeader) Mode() uint64 { return (h.Flags & SubgroupModeMask) >> 1 }

// Append appends the header with its type.
func (h *SubgroupHeader) Append(b []byte) []byte {
	b = AppendVarint(b, h.Flags)
	b = AppendVarint(b, h.TrackAlias)
	b = AppendVarint(b, h.Group)
	if h.Mode() == SubgroupModeExplicit {
		b = AppendVarint(b, h.Subgroup)
	}
	if h.Flags&SubgroupDefaultPrio == 0 {
		b = append(b, h.Priority)
	}
	return b
}

// ReadSubgroupHeader reads the header after its type t.
func ReadSubgroupHeader(r ByteReader, t uint64) (*SubgroupHeader, error) {
	if !IsSubgroupType(t) || (t&SubgroupModeMask)>>1 == 3 {
		return nil, violation("invalid subgroup header type")
	}
	h := &SubgroupHeader{Flags: t}
	var err error
	if h.TrackAlias, err = readStreamVarint(r); err != nil {
		return nil, err
	}
	if h.Group, err = readStreamVarint(r); err != nil {
		return nil, err
	}
	if h.Mode() == SubgroupModeExplicit {
		if h.Subgroup, err = readStreamVarint(r); err != nil {
			return nil, err
		}
	}
	if t&SubgroupDefaultPrio == 0 {
		if h.Priority, err = r.ReadByte(); err != nil {
			return nil, streamErr(err)
		}
	}
	return h, nil
}

// Object is one object read from or written to a data stream.
type Object struct {
	Group      uint64
	Subgroup   uint64
	ID         uint64
	Priority   uint8
	Status     uint64
	Properties []KV
	Payload    []byte
	// Datagram is set on a fetch object that was first sent as a datagram.
	Datagram bool
}

// SubgroupWriter encodes the objects of one subgroup stream.
type SubgroupWriter struct {
	started bool
	prev    uint64
}

// Append appends o and refuses an ID that does not increase. Properties are
// always written, since the header announces them.
func (w *SubgroupWriter) Append(b []byte, o *Object) ([]byte, error) {
	delta := o.ID
	if w.started {
		if o.ID <= w.prev {
			return b, ErrIDNotIncreasing
		}
		delta = o.ID - w.prev - 1
	}
	w.started, w.prev = true, o.ID
	b = AppendVarint(b, delta)
	props := AppendKVs(nil, o.Properties)
	b = AppendVarint(b, uint64(len(props)))
	b = append(b, props...)
	b = AppendVarint(b, uint64(len(o.Payload)))
	if len(o.Payload) == 0 {
		b = AppendVarint(b, o.Status)
	}
	return append(b, o.Payload...), nil
}

// SubgroupReader decodes the objects of one subgroup stream.
type SubgroupReader struct {
	R          ByteReader
	Header     *SubgroupHeader
	MaxPayload uint64
	started    bool
	prev       uint64
}

// Next reads the next object; io.EOF means the stream ended cleanly.
func (s *SubgroupReader) Next() (*Object, error) {
	delta, err := ReadVarint(s.R)
	if err == io.EOF {
		return nil, io.EOF
	}
	if err != nil {
		return nil, streamErr(err)
	}
	id := delta
	if s.started {
		if addOverflows(s.prev, delta) || s.prev+delta == math.MaxUint64 {
			return nil, violation("object ID overflows")
		}
		id = s.prev + delta + 1
	}
	s.started, s.prev = true, id
	o := &Object{Group: s.Header.Group, Subgroup: s.Header.Subgroup, ID: id, Priority: s.Header.Priority}
	if s.Header.Flags&SubgroupProperties != 0 {
		if o.Properties, err = readObjectProperties(s.R); err != nil {
			return nil, err
		}
	}
	n, err := readStreamVarint(s.R)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		if o.Status, err = readStreamVarint(s.R); err != nil {
			return nil, err
		}
		switch o.Status {
		case StatusNormal, StatusEndOfGroup, StatusEndOfTrack:
		default:
			return nil, violation("unknown object status")
		}
		if o.Status != StatusNormal && len(o.Properties) > 0 {
			return nil, violation("properties on an object that is not normal")
		}
		return o, nil
	}
	if n > s.MaxPayload {
		return nil, ErrTooLarge
	}
	if o.Payload, err = readPayload(s.R, n); err != nil {
		return nil, err
	}
	return o, nil
}

func readObjectProperties(r ByteReader) ([]KV, error) {
	n, err := readStreamVarint(r)
	if err != nil {
		return nil, err
	}
	if n == 0 {
		return nil, nil
	}
	if n > MaxMessageLen {
		return nil, violation("object properties too long")
	}
	p := make([]byte, n)
	if _, err := io.ReadFull(r, p); err != nil {
		return nil, streamErr(err)
	}
	kvs, err := ParseKVs(p)
	if err != nil {
		return nil, err
	}
	return kvs, CheckObjectProperties(kvs)
}

// CheckObjectProperties applies the malformed-track rules of sections
// 3.7, 10.7, 10.8 and 10.9 that need no other object.
func CheckObjectProperties(kvs []KV) error {
	var imm, gg, og int
	for _, kv := range kvs {
		switch {
		case kv.Type >= mandatoryTrackPropLo && kv.Type <= mandatoryTrackPropHi:
			return ErrMalformedTrack
		case kv.Type == PropImmutable:
			imm++
			inner, err := ParseKVs(kv.Bytes)
			if err != nil {
				return ErrMalformedTrack
			}
			for _, in := range inner {
				if in.Type == PropImmutable {
					return ErrMalformedTrack
				}
			}
		case kv.Type == PropPriorGroupGap:
			gg++
		case kv.Type == PropPriorObjectGap:
			og++
		}
	}
	if imm > 1 || gg > 1 || og > 1 {
		return ErrMalformedTrack
	}
	return nil
}

// FetchObject is one entry of a fetch stream: an object, or an End of
// Range marker when EndOfRange is set.
type FetchObject struct {
	Object
	EndOfRange uint64
}

// FetchWriter encodes the objects of one fetch stream.
type FetchWriter struct {
	Descending bool
	started    bool // an object or End of Range was written
	haveObject bool // an actual object was written
	prev       Object
}

// Append appends o, choosing the shortest flags.
func (w *FetchWriter) Append(b []byte, o *Object) []byte {
	var flags, gd, od uint64
	next := w.prev.ID != math.MaxUint64 && o.ID == w.prev.ID+1
	switch {
	case !w.started:
		flags |= FetchGroupDelta | FetchObjectDelta
		gd, od = o.Group, o.ID
	case o.Group != w.prev.Group:
		flags |= FetchGroupDelta
		if w.Descending {
			gd = w.prev.Group - o.Group - 1
		} else {
			gd = o.Group - w.prev.Group - 1
		}
		if !next {
			flags |= FetchObjectDelta
			od = o.ID
		}
	case !next:
		flags |= FetchObjectDelta
		od = o.ID - w.prev.ID
	}
	mode := uint64(3)
	switch {
	case o.Subgroup == 0:
		mode = 0
	case w.haveObject && o.Subgroup == w.prev.Subgroup:
		mode = 1
	case w.haveObject && w.prev.Subgroup != math.MaxUint64 && o.Subgroup == w.prev.Subgroup+1:
		mode = 2
	}
	flags |= mode
	if !w.haveObject || o.Priority != w.prev.Priority {
		flags |= FetchPriority
	}
	if len(o.Properties) > 0 {
		flags |= FetchProperties
	}
	b = AppendVarint(b, flags)
	if flags&FetchGroupDelta != 0 {
		b = AppendVarint(b, gd)
	}
	if mode == 3 {
		b = AppendVarint(b, o.Subgroup)
	}
	if flags&FetchObjectDelta != 0 {
		b = AppendVarint(b, od)
	}
	if flags&FetchPriority != 0 {
		b = append(b, o.Priority)
	}
	if flags&FetchProperties != 0 {
		props := AppendKVs(nil, o.Properties)
		b = AppendVarint(b, uint64(len(props)))
		b = append(b, props...)
	}
	b = AppendVarint(b, uint64(len(o.Payload)))
	b = append(b, o.Payload...)
	w.started, w.haveObject, w.prev = true, true, *o
	return b
}

// AppendEndOfRange appends an End of Range marker of kind at l; the next
// object is encoded relative to l.
func (w *FetchWriter) AppendEndOfRange(b []byte, kind uint64, l Location) []byte {
	b = AppendVarint(b, kind)
	b = AppendVarint(b, l.Group)
	b = AppendVarint(b, l.Object)
	w.started = true
	w.prev.Group, w.prev.ID = l.Group, l.Object
	return b
}

// FetchReader decodes the objects of one fetch stream.
type FetchReader struct {
	R          ByteReader
	Descending bool
	MaxPayload uint64
	started    bool // an object or End of Range was read
	haveObject bool // an actual object was read
	prev       Object
}

// Next reads the next entry; io.EOF means the stream ended cleanly.
func (f *FetchReader) Next() (*FetchObject, error) {
	flags, err := ReadVarint(f.R)
	if err == io.EOF {
		return nil, io.EOF
	}
	if err != nil {
		return nil, streamErr(err)
	}
	if flags >= 128 {
		switch flags {
		case EndOfNonExistent, EndOfUnknownRange, EndOfTimedOut:
		default:
			return nil, violation("invalid fetch serialization flags")
		}
		g, err := readStreamVarint(f.R)
		if err != nil {
			return nil, err
		}
		o, err := readStreamVarint(f.R)
		if err != nil {
			return nil, err
		}
		f.started = true
		f.prev.Group, f.prev.ID = g, o
		return &FetchObject{Object: Object{Group: g, ID: o}, EndOfRange: flags}, nil
	}
	if !f.started && flags&(FetchGroupDelta|FetchObjectDelta) != FetchGroupDelta|FetchObjectDelta {
		return nil, violation("first fetch object without absolute IDs")
	}
	datagram := flags&FetchDatagram != 0
	mode := flags & FetchModeMask
	if !f.haveObject && ((!datagram && (mode == 1 || mode == 2)) || flags&FetchPriority == 0) {
		return nil, violation("fetch object refers to a prior object that does not exist")
	}
	o := Object{}
	var gd uint64
	if flags&FetchGroupDelta != 0 {
		if gd, err = readStreamVarint(f.R); err != nil {
			return nil, err
		}
	}
	switch {
	case !f.started:
		o.Group = gd
	case flags&FetchGroupDelta == 0:
		o.Group = f.prev.Group
	case f.Descending:
		if gd >= f.prev.Group {
			return nil, violation("fetch group ID underflows")
		}
		o.Group = f.prev.Group - gd - 1
	default:
		if addOverflows(f.prev.Group, gd) || f.prev.Group+gd == math.MaxUint64 {
			return nil, violation("fetch group ID overflows")
		}
		o.Group = f.prev.Group + gd + 1
	}
	if !datagram {
		switch mode {
		case 0:
		case 1:
			o.Subgroup = f.prev.Subgroup
		case 2:
			if f.prev.Subgroup == math.MaxUint64 {
				return nil, violation("subgroup ID overflows")
			}
			o.Subgroup = f.prev.Subgroup + 1
		case 3:
			if o.Subgroup, err = readStreamVarint(f.R); err != nil {
				return nil, err
			}
		}
	}
	var od uint64
	hasOD := flags&FetchObjectDelta != 0
	if hasOD {
		if od, err = readStreamVarint(f.R); err != nil {
			return nil, err
		}
	}
	switch {
	case !f.started || (flags&FetchGroupDelta != 0 && hasOD):
		o.ID = od
	case hasOD:
		if addOverflows(f.prev.ID, od) {
			return nil, violation("fetch object ID overflows")
		}
		o.ID = f.prev.ID + od
	default:
		if f.prev.ID == math.MaxUint64 {
			return nil, violation("fetch object ID overflows")
		}
		o.ID = f.prev.ID + 1
	}
	o.Datagram = datagram
	o.Priority = f.prev.Priority
	if flags&FetchPriority != 0 {
		if o.Priority, err = f.R.ReadByte(); err != nil {
			return nil, streamErr(err)
		}
	}
	if flags&FetchProperties != 0 {
		if o.Properties, err = readObjectProperties(f.R); err != nil {
			return nil, err
		}
	}
	n, err := readStreamVarint(f.R)
	if err != nil {
		return nil, err
	}
	if n > f.MaxPayload {
		return nil, ErrTooLarge
	}
	if n > 0 {
		if o.Payload, err = readPayload(f.R, n); err != nil {
			return nil, err
		}
	}
	f.started, f.haveObject, f.prev = true, true, o
	return &FetchObject{Object: o}, nil
}

// payloadChunk bounds the memory a payload holds before its bytes arrive,
// so a peer announcing large objects it never sends cannot reserve memory.
const payloadChunk = 64 << 10

func readPayload(r io.Reader, n uint64) ([]byte, error) {
	if n <= payloadChunk {
		p := make([]byte, n)
		if _, err := io.ReadFull(r, p); err != nil {
			return nil, streamErr(err)
		}
		return p, nil
	}
	var b bytes.Buffer
	b.Grow(payloadChunk)
	if _, err := io.CopyN(&b, r, int64(n)); err != nil {
		return nil, streamErr(err)
	}
	return b.Bytes(), nil
}

// readStreamVarint reads a varint inside a structure, where a clean end of
// stream is a truncation.
func readStreamVarint(r ByteReader) (uint64, error) {
	v, err := ReadVarint(r)
	if err != nil {
		return 0, streamErr(err)
	}
	return v, nil
}

// streamErr maps a stream that ends inside a structure to a protocol
// violation (section 11.3) and passes other errors through.
func streamErr(err error) error {
	if err == io.EOF || err == io.ErrUnexpectedEOF {
		return violation("stream ended inside an object")
	}
	return err
}
