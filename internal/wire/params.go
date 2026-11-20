package wire

import "slices"

// Message Parameter types (section 16.7).
const (
	ParamObjectTimeout      = 0x02
	ParamAuthToken          = 0x03
	ParamRendezvousTimeout  = 0x04
	ParamSubgroupTimeout    = 0x06
	ParamExpires            = 0x08
	ParamLargestObject      = 0x09
	ParamFillTimeout        = 0x0A
	ParamForward            = 0x10
	ParamSubscriberPriority = 0x20
	ParamLocationFilter     = 0x21
	ParamGroupOrder         = 0x22
	ParamFillParameters     = 0x23
	ParamSubgroupFilter     = 0x25
	ParamObjectIDFilter     = 0x26
	ParamPriorityFilter     = 0x27
	ParamObjectPropFilter   = 0x28
	ParamTrackPropFilter    = 0x29
	ParamNewGroupRequest    = 0x32
	ParamNamespacePrefix    = 0x34
	ParamIncludeProperties  = 0x35
)

var paramTypes = []uint64{
	ParamObjectTimeout, ParamAuthToken, ParamRendezvousTimeout, ParamSubgroupTimeout,
	ParamExpires, ParamLargestObject, ParamFillTimeout, ParamForward,
	ParamSubscriberPriority, ParamLocationFilter, ParamGroupOrder, ParamFillParameters,
	ParamSubgroupFilter, ParamObjectIDFilter, ParamPriorityFilter, ParamObjectPropFilter,
	ParamTrackPropFilter, ParamNewGroupRequest, ParamNamespacePrefix, ParamIncludeProperties,
}

func paramBit(t uint64) uint64 {
	i := slices.Index(paramTypes, t)
	if i < 0 {
		return 0
	}
	return 1 << i
}

// ParamSet is a set of parameter types.
type ParamSet uint64

// Params builds a ParamSet.
func Params(types ...uint64) ParamSet {
	var s ParamSet
	for _, t := range types {
		s |= ParamSet(paramBit(t))
	}
	return s
}

var rangeFilters = Params(ParamSubgroupFilter, ParamObjectIDFilter, ParamPriorityFilter, ParamObjectPropFilter)

// Parameter sets each message allows (section 9).
var (
	AllowSubscribe = Params(ParamObjectTimeout, ParamAuthToken, ParamRendezvousTimeout,
		ParamSubgroupTimeout, ParamForward, ParamSubscriberPriority, ParamLocationFilter,
		ParamGroupOrder, ParamFillParameters, ParamNewGroupRequest, ParamIncludeProperties) | rangeFilters
	AllowSubscribeOK = Params(ParamExpires, ParamLargestObject)
	AllowPublish     = Params(ParamObjectTimeout, ParamAuthToken, ParamSubgroupTimeout, ParamExpires,
		ParamLargestObject, ParamForward, ParamSubscriberPriority, ParamLocationFilter, ParamGroupOrder)
	AllowRequestOK     = Params(ParamExpires, ParamLargestObject)
	AllowFetch         = Params(ParamAuthToken, ParamFillTimeout, ParamSubscriberPriority, ParamLocationFilter, ParamGroupOrder, ParamIncludeProperties) | rangeFilters
	AllowTrackStatus   = Params(ParamAuthToken, ParamIncludeProperties)
	AllowNamespace     = Params(ParamAuthToken)
	AllowSubscribeTrks = Params(ParamAuthToken, ParamForward, ParamGroupOrder, ParamTrackPropFilter, ParamIncludeProperties) | rangeFilters
	AllowStateNotify   = Params(ParamLargestObject, ParamForward, ParamLocationFilter)
	AllowFill          = Params(ParamFillTimeout, ParamSubscriberPriority, ParamLocationFilter, ParamGroupOrder) | rangeFilters
	// AllowUpdate is the union over request types; the session narrows it.
	AllowUpdate = Params(ParamObjectTimeout, ParamAuthToken, ParamSubgroupTimeout, ParamForward,
		ParamSubscriberPriority, ParamLocationFilter, ParamFillParameters, ParamNewGroupRequest,
		ParamNamespacePrefix, ParamTrackPropFilter) | rangeFilters
	UpdateSubscription = Params(ParamObjectTimeout, ParamAuthToken, ParamSubgroupTimeout, ParamForward,
		ParamSubscriberPriority, ParamLocationFilter, ParamFillParameters, ParamNewGroupRequest) | rangeFilters
	UpdateFetch     = Params(ParamAuthToken, ParamSubscriberPriority)
	UpdateNamespace = Params(ParamAuthToken, ParamNamespacePrefix)
	UpdatePublishNS = Params(ParamAuthToken)
)

// Location Filter types (section 9.20.9).
const (
	FilterNone          = 0x00
	FilterRelativeStart = 0x01
	FilterAbsoluteStart = 0x02
	FilterGroupEnd      = 0x03
	FilterAbsoluteRange = 0x04
	FilterNextObject    = 0x05
)

// LocationFilter is a LOCATION_FILTER value; EndGroup is absolute.
type LocationFilter struct {
	Type        uint64
	StartGroup  uint64
	StartObject uint64
	EndGroup    uint64
	EndObject   uint64
}

// RawParam is a length-prefixed parameter kept as bytes.
type RawParam struct {
	Type  uint64
	Bytes []byte
}

// MessageParams holds the parameters of one message; Has reports which
// were present.
type MessageParams struct {
	set ParamSet

	ObjectTimeout      uint64
	SubgroupTimeout    uint64
	RendezvousTimeout  uint64
	Expires            uint64
	FillTimeout        uint64
	NewGroupRequest    uint64
	Largest            Location
	Forward            uint8
	SubscriberPriority uint8
	GroupOrder         uint8
	IncludeProperties  uint8
	Filter             LocationFilter
	Fill               *MessageParams
	NamespacePrefix    []string
	AuthTokens         [][]byte
	RangeFilters       []RawParam
}

// Has reports whether parameter type t was present.
func (p *MessageParams) Has(t uint64) bool { return p.set&ParamSet(paramBit(t)) != 0 }

// Set marks parameter type t as present.
func (p *MessageParams) Set(t uint64) { p.set |= ParamSet(paramBit(t)) }

// Types returns the set of parameter types present.
func (p *MessageParams) Types() ParamSet { return p.set }

// AppendParams appends the parameter count and the parameters.
func AppendParams(b []byte, p *MessageParams) []byte {
	if p == nil {
		return AppendVarint(b, 0)
	}
	n := 0
	for _, t := range paramTypes {
		if !p.Has(t) {
			continue
		}
		switch t {
		case ParamAuthToken:
			n += len(p.AuthTokens)
		case ParamSubgroupFilter, ParamObjectIDFilter, ParamPriorityFilter, ParamObjectPropFilter, ParamTrackPropFilter:
			for _, f := range p.RangeFilters {
				if f.Type == t {
					n++
				}
			}
		default:
			n++
		}
	}
	b = AppendVarint(b, uint64(n))
	var prev uint64
	put := func(t uint64) {
		b = AppendVarint(b, t-prev)
		prev = t
	}
	for _, t := range paramTypes {
		if !p.Has(t) {
			continue
		}
		switch t {
		case ParamObjectTimeout, ParamSubgroupTimeout, ParamRendezvousTimeout, ParamExpires, ParamFillTimeout, ParamNewGroupRequest:
			put(t)
			b = AppendVarint(b, p.varint(t))
		case ParamLargestObject:
			put(t)
			b = appendLocation(b, p.Largest)
		case ParamForward, ParamSubscriberPriority, ParamGroupOrder, ParamIncludeProperties:
			put(t)
			b = append(b, p.byteValue(t))
		case ParamLocationFilter:
			put(t)
			b = appendFilter(b, p.Filter)
		case ParamFillParameters:
			put(t)
			inner := AppendParams(nil, p.Fill)
			b = AppendVarint(b, uint64(len(inner)))
			b = append(b, inner...)
		case ParamNamespacePrefix:
			put(t)
			b = AppendNamespace(b, p.NamespacePrefix)
		case ParamAuthToken:
			for _, tok := range p.AuthTokens {
				put(t)
				b = AppendVarint(b, uint64(len(tok)))
				b = append(b, tok...)
			}
		default:
			for _, f := range p.RangeFilters {
				if f.Type == t {
					put(t)
					b = AppendVarint(b, uint64(len(f.Bytes)))
					b = append(b, f.Bytes...)
				}
			}
		}
	}
	return b
}

func (p *MessageParams) varint(t uint64) uint64 {
	switch t {
	case ParamObjectTimeout:
		return p.ObjectTimeout
	case ParamSubgroupTimeout:
		return p.SubgroupTimeout
	case ParamRendezvousTimeout:
		return p.RendezvousTimeout
	case ParamExpires:
		return p.Expires
	case ParamFillTimeout:
		return p.FillTimeout
	}
	return p.NewGroupRequest
}

func (p *MessageParams) setVarint(t, v uint64) {
	switch t {
	case ParamObjectTimeout:
		p.ObjectTimeout = v
	case ParamSubgroupTimeout:
		p.SubgroupTimeout = v
	case ParamRendezvousTimeout:
		p.RendezvousTimeout = v
	case ParamExpires:
		p.Expires = v
	case ParamFillTimeout:
		p.FillTimeout = v
	default:
		p.NewGroupRequest = v
	}
}

func (p *MessageParams) byteValue(t uint64) byte {
	switch t {
	case ParamForward:
		return p.Forward
	case ParamSubscriberPriority:
		return p.SubscriberPriority
	case ParamGroupOrder:
		return p.GroupOrder
	}
	return p.IncludeProperties
}

// ReadParams reads a parameter count and the parameters, closing the
// session (PROTOCOL_VIOLATION) on an unknown, misplaced or repeated type.
func ReadParams(r *Reader, allowed ParamSet) (*MessageParams, error) {
	return readParams(r, allowed, true)
}

func readParams(r *Reader, allowed ParamSet, fillAllowed bool) (*MessageParams, error) {
	count, err := r.Varint()
	if err != nil {
		return nil, err
	}
	p := &MessageParams{}
	var prev uint64
	for range count {
		d, err := r.Varint()
		if err != nil {
			return nil, err
		}
		if addOverflows(prev, d) {
			return nil, violation("parameter type overflows")
		}
		t := prev + d
		prev = t
		bit := ParamSet(paramBit(t))
		if bit == 0 {
			return nil, violation("unknown message parameter")
		}
		if allowed&bit == 0 || (t == ParamFillParameters && !fillAllowed) {
			return nil, violation("parameter not allowed in this message")
		}
		repeatable := t == ParamAuthToken || rangeFilters&bit != 0 || t == ParamTrackPropFilter
		if p.set&bit != 0 && !repeatable {
			return nil, violation("repeated message parameter")
		}
		p.set |= bit
		switch t {
		case ParamObjectTimeout, ParamSubgroupTimeout, ParamRendezvousTimeout, ParamExpires, ParamFillTimeout, ParamNewGroupRequest:
			v, err := r.Varint()
			if err != nil {
				return nil, err
			}
			p.setVarint(t, v)
		case ParamLargestObject:
			if p.Largest, err = readLocation(r); err != nil {
				return nil, err
			}
		case ParamForward, ParamIncludeProperties:
			v, err := r.Byte()
			if err != nil {
				return nil, err
			}
			if v > 1 {
				return nil, violation("boolean parameter out of range")
			}
			if t == ParamForward {
				p.Forward = v
			} else {
				p.IncludeProperties = v
			}
		case ParamSubscriberPriority:
			if p.SubscriberPriority, err = r.Byte(); err != nil {
				return nil, err
			}
		case ParamGroupOrder:
			v, err := r.Byte()
			if err != nil {
				return nil, err
			}
			if v != 1 && v != 2 {
				return nil, violation("group order out of range")
			}
			p.GroupOrder = v
		case ParamLocationFilter:
			if p.Filter, err = readFilter(r); err != nil {
				return nil, err
			}
		case ParamFillParameters:
			body, err := r.LenBytes(MaxMessageLen, "fill parameters")
			if err != nil {
				return nil, err
			}
			ir := NewReader(body)
			if p.Fill, err = readParams(ir, AllowFill, false); err != nil {
				return nil, err
			}
			if err := ir.End(); err != nil {
				return nil, err
			}
		case ParamNamespacePrefix:
			if p.NamespacePrefix, err = ReadNamespace(r); err != nil {
				return nil, err
			}
		case ParamAuthToken:
			tok, err := r.LenBytes(MaxMessageLen, "authorization token")
			if err != nil {
				return nil, err
			}
			p.AuthTokens = append(p.AuthTokens, slices.Clone(tok))
		default:
			body, err := r.LenBytes(MaxMessageLen, "range filter")
			if err != nil {
				return nil, err
			}
			p.RangeFilters = append(p.RangeFilters, RawParam{Type: t, Bytes: slices.Clone(body)})
		}
	}
	return p, nil
}

func appendFilter(b []byte, f LocationFilter) []byte {
	b = AppendVarint(b, f.Type)
	switch f.Type {
	case FilterRelativeStart:
		b = AppendVarint(b, f.StartGroup)
	case FilterAbsoluteStart:
		b = appendLocation(b, Location{f.StartGroup, f.StartObject})
	case FilterGroupEnd, FilterAbsoluteRange:
		b = appendLocation(b, Location{f.StartGroup, f.StartObject})
		b = AppendVarint(b, f.EndGroup-f.StartGroup)
		if f.Type == FilterAbsoluteRange {
			b = AppendVarint(b, f.EndObject)
		}
	}
	return b
}

func readFilter(r *Reader) (LocationFilter, error) {
	var f LocationFilter
	var err error
	if f.Type, err = r.Varint(); err != nil {
		return f, err
	}
	switch f.Type {
	case FilterNone, FilterNextObject:
	case FilterRelativeStart:
		f.StartGroup, err = r.Varint()
	case FilterAbsoluteStart, FilterGroupEnd, FilterAbsoluteRange:
		var l Location
		if l, err = readLocation(r); err != nil {
			return f, err
		}
		f.StartGroup, f.StartObject = l.Group, l.Object
		if f.Type == FilterAbsoluteStart {
			break
		}
		var d uint64
		if d, err = r.Varint(); err != nil {
			return f, err
		}
		if addOverflows(f.StartGroup, d) {
			return f, violation("filter end group overflows")
		}
		f.EndGroup = f.StartGroup + d
		if f.Type == FilterAbsoluteRange {
			f.EndObject, err = r.Varint()
		}
	default:
		return f, violation("unknown location filter type")
	}
	return f, err
}

// Authorization token alias types (section 8.9).
const (
	TokenDelete   = 0x0
	TokenRegister = 0x1
	TokenUseAlias = 0x2
	TokenUseValue = 0x3
)

// TokenAliasType checks the Token structure and returns its Alias Type.
// A token that does not decode is a KEY_VALUE_FORMATTING_ERROR.
func TokenAliasType(tok []byte) (uint64, error) {
	bad := &Error{Code: CodeKeyValueFormatting, Msg: "malformed authorization token"}
	r := NewReader(tok)
	at, err := r.Varint()
	if err != nil {
		return 0, bad
	}
	switch at {
	case TokenDelete, TokenUseAlias:
		if _, err := r.Varint(); err != nil {
			return 0, bad
		}
	case TokenRegister:
		if _, err := r.Varint(); err != nil {
			return 0, bad
		}
		fallthrough
	case TokenUseValue:
		if _, err := r.Varint(); err != nil {
			return 0, bad
		}
		r.Rest()
	default:
		return 0, bad
	}
	if r.Len() != 0 {
		return 0, bad
	}
	return at, nil
}
