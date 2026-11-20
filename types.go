package kolomoq

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"slices"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// Conn is an authenticated Kolo connection; *kolosecure.Conn and
// *kolorelay.Conn satisfy it. A Session owns its Conn: it is the only
// caller of AcceptStream and AcceptUniStream, and closes the Conn when the
// session ends.
type Conn interface {
	RemotePublicKey() ed25519.PublicKey
	OpenStream(ctx context.Context) (*kolotransport.Stream, error)
	AcceptStream(ctx context.Context) (*kolotransport.Stream, error)
	OpenUniStream(ctx context.Context) (*kolotransport.SendStream, error)
	AcceptUniStream(ctx context.Context) (*kolotransport.ReceiveStream, error)
	Context() context.Context
	Close() error
	CloseWithError(code uint64, msg string) error
}

// Namespace is a Track Namespace: 0 to 32 non-empty fields.
type Namespace []string

// HasPrefix reports whether p is a prefix of n, field by field.
func (n Namespace) HasPrefix(p Namespace) bool {
	return len(p) <= len(n) && slices.Equal(n[:len(p)], p)
}

func (n Namespace) key() string { return string(wire.AppendNamespace(nil, n)) }

// Location is a Group and Object pair.
type Location struct {
	Group, Object uint64
}

// Less reports whether l comes before m.
func (l Location) Less(m Location) bool { return wire.Location(l).Less(wire.Location(m)) }

// Property is an object or track property: an even Type carries Value, an
// odd Type carries Bytes (at most 65535 of them).
type Property struct {
	Type  uint64
	Value uint64
	Bytes []byte
}

// ObjectStatus tells a normal object from an end marker.
type ObjectStatus uint64

// Object statuses (draft section 11.1.1).
const (
	StatusNormal     ObjectStatus = wire.StatusNormal
	StatusEndOfGroup ObjectStatus = wire.StatusEndOfGroup
	StatusEndOfTrack ObjectStatus = wire.StatusEndOfTrack
)

// Object is one object of a track.
type Object struct {
	Group      uint64
	Subgroup   uint64
	ID         uint64
	Priority   uint8
	Status     ObjectStatus
	Properties []Property
	Payload    []byte
}

// GroupOrder is the order groups of a track are sent in.
type GroupOrder uint8

// Group orders; OrderDefault means the publisher's preference.
const (
	OrderDefault    GroupOrder = 0
	OrderAscending  GroupOrder = 1
	OrderDescending GroupOrder = 2
)

// DefaultPriority is the draft's default publisher and subscriber
// priority. Lower numbers are more urgent.
const DefaultPriority = 128

// RequestKind is the kind of request the Authorize hook decides on.
type RequestKind int

// Request kinds.
const (
	KindSubscribe RequestKind = iota + 1
	KindFetch
	KindTrackStatus
	KindPublishNamespace
	KindSubscribeNamespace
)

// String returns the draft message name of the kind.
func (k RequestKind) String() string {
	switch k {
	case KindSubscribe:
		return "SUBSCRIBE"
	case KindFetch:
		return "FETCH"
	case KindTrackStatus:
		return "TRACK_STATUS"
	case KindPublishNamespace:
		return "PUBLISH_NAMESPACE"
	case KindSubscribeNamespace:
		return "SUBSCRIBE_NAMESPACE"
	}
	return "unknown"
}

func toKVs(ps []Property) []wire.KV {
	if len(ps) == 0 {
		return nil
	}
	out := make([]wire.KV, len(ps))
	for i, p := range ps {
		out[i] = wire.KV{Type: p.Type, Value: p.Value, Bytes: bytes.Clone(p.Bytes)}
	}
	return out
}

// cloneProperties returns a deep copy of ps.
func cloneProperties(ps []Property) []Property {
	if len(ps) == 0 {
		return nil
	}
	out := make([]Property, len(ps))
	for i, p := range ps {
		out[i] = Property{Type: p.Type, Value: p.Value, Bytes: bytes.Clone(p.Bytes)}
	}
	return out
}

func fromKVs(kvs []wire.KV) []Property {
	if len(kvs) == 0 {
		return nil
	}
	out := make([]Property, len(kvs))
	for i, kv := range kvs {
		out[i] = Property{Type: kv.Type, Value: kv.Value, Bytes: bytes.Clone(kv.Bytes)}
	}
	return out
}

func checkProperties(ps []Property) error {
	for _, p := range ps {
		if p.Type%2 == 0 && p.Bytes != nil {
			return ErrInvalidProperty
		}
		if p.Type%2 == 1 && (p.Value != 0 || len(p.Bytes) > wire.MaxKVBytes) {
			return ErrInvalidProperty
		}
	}
	return nil
}

func objectFromWire(o *wire.Object) Object {
	return Object{
		Group: o.Group, Subgroup: o.Subgroup, ID: o.ID, Priority: o.Priority,
		Status: ObjectStatus(o.Status), Properties: fromKVs(o.Properties), Payload: o.Payload,
	}
}
