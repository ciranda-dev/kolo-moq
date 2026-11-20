package wire

import (
	"encoding/binary"
	"errors"
	"io"
)

// Control message types (section 9, Table 5).
const (
	MsgSetup              = 0x2F00
	MsgGoAway             = 0x10
	MsgSubscribe          = 0x03
	MsgSubscribeOK        = 0x04
	MsgPublishStateNotify = 0x22
	MsgPublish            = 0x1D
	MsgPublishDone        = 0x0B
	MsgFetch              = 0x16
	MsgFetchOK            = 0x18
	MsgTrackStatus        = 0x0D
	MsgPublishNamespace   = 0x06
	MsgSubscribeNamespace = 0x50
	MsgSubscribeTracks    = 0x51
	MsgNamespace          = 0x08
	MsgNamespaceDone      = 0x0E
	MsgPublishSkipped     = 0x0F
	MsgRequestUpdate      = 0x02
	MsgRequestOK          = 0x07
	MsgRequestError       = 0x05
)

// Setup Options (section 16.4).
const (
	OptPath                 = 0x01
	OptAuthToken            = 0x03
	OptMaxAuthTokenCache    = 0x04
	OptAuthority            = 0x05
	OptMaxFilterRanges      = 0x06
	OptMoqtImplementation   = 0x07
	OptMaxRequestUpdates    = 0x08
	RequestErrorRedirect    = 0x34
	PrefaceVersion          = "moqt-22"
	StreamTypeFetch         = 0x05
	StreamTypePadding       = 0x132B3E28
	StreamTypePrefaceLength = uint64(len(PrefaceVersion))
)

// Preface is the version preface each control stream starts with.
func Preface() []byte {
	return append(AppendVarint(nil, StreamTypePrefaceLength), PrefaceVersion...)
}

// ErrMessageTooLong means a control message body does not fit the 16-bit
// Message Length (section 9).
var ErrMessageTooLong = errors.New("kolomoq: control message longer than 65535 bytes")

// AppendMessage appends a framed control message; a body longer than
// MaxMessageLen is refused.
func AppendMessage(b []byte, typ uint64, body []byte) ([]byte, error) {
	if len(body) > MaxMessageLen {
		return b, ErrMessageTooLong
	}
	b = AppendVarint(b, typ)
	b = binary.BigEndian.AppendUint16(b, uint16(len(body)))
	return append(b, body...), nil
}

// ReadMessage reads one framed control message whose body is at most max
// bytes. io.EOF means the stream ended cleanly before a message.
func ReadMessage(r ByteReader, max int) (uint64, []byte, error) {
	t, err := ReadVarint(r)
	if err != nil {
		return 0, nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return 0, nil, unexpected(err)
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n > max {
		return 0, nil, &Error{Code: CodeInternalError, Msg: "control message larger than the configured limit"}
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, unexpected(err)
	}
	return t, body, nil
}

// Setup is SETUP (section 9.1).
type Setup struct {
	Options []KV
}

// Append appends the body.
func (m *Setup) Append(b []byte) []byte { return AppendKVs(b, m.Options) }

// ParseSetup parses a SETUP body.
func ParseSetup(p []byte) (*Setup, error) {
	kvs, err := ParseKVs(p)
	if err != nil {
		return nil, err
	}
	return &Setup{Options: kvs}, nil
}

// GoAway is GOAWAY (section 9.2).
type GoAway struct {
	URI     string
	Timeout uint64
}

// Append appends the body.
func (m *GoAway) Append(b []byte) []byte {
	b = AppendVarint(b, uint64(len(m.URI)))
	b = append(b, m.URI...)
	return AppendVarint(b, m.Timeout)
}

// ParseGoAway parses a GOAWAY body.
func ParseGoAway(p []byte) (*GoAway, error) {
	r := NewReader(p)
	uri, err := r.LenBytes(MaxGoAwayURI, "GOAWAY URI")
	if err != nil {
		return nil, err
	}
	m := &GoAway{URI: string(uri)}
	if m.Timeout, err = r.Varint(); err != nil {
		return nil, err
	}
	return m, r.End()
}

// Request is a request message that names a track or a namespace:
// SUBSCRIBE, FETCH, TRACK_STATUS, PUBLISH, PUBLISH_NAMESPACE,
// SUBSCRIBE_NAMESPACE and SUBSCRIBE_TRACKS.
type Request struct {
	Type      uint64
	RequestID uint64
	Namespace []string
	Name      string
	// TrackAlias and Properties are used by PUBLISH only.
	TrackAlias uint64
	Params     *MessageParams
	Properties []KV
}

func hasName(t uint64) bool {
	switch t {
	case MsgSubscribe, MsgFetch, MsgTrackStatus, MsgPublish:
		return true
	}
	return false
}

func allowedParams(t uint64) ParamSet {
	switch t {
	case MsgSubscribe:
		return AllowSubscribe
	case MsgFetch:
		return AllowFetch
	case MsgTrackStatus:
		return AllowTrackStatus
	case MsgPublish:
		return AllowPublish
	case MsgSubscribeTracks:
		return AllowSubscribeTrks
	}
	return AllowNamespace
}

// IsRequest reports whether t may start a request stream.
func IsRequest(t uint64) bool {
	switch t {
	case MsgSubscribe, MsgFetch, MsgTrackStatus, MsgPublish, MsgPublishNamespace, MsgSubscribeNamespace, MsgSubscribeTracks:
		return true
	}
	return false
}

// Append appends the body.
func (m *Request) Append(b []byte) []byte {
	b = AppendVarint(b, m.RequestID)
	b = AppendNamespace(b, m.Namespace)
	if hasName(m.Type) {
		b = appendName(b, m.Name)
	}
	if m.Type == MsgPublish {
		b = AppendVarint(b, m.TrackAlias)
	}
	b = AppendParams(b, m.Params)
	if m.Type == MsgPublish {
		b = AppendKVs(b, m.Properties)
	}
	return b
}

// ParseRequest parses the body of request message type t.
func ParseRequest(t uint64, p []byte) (*Request, error) {
	r := NewReader(p)
	m := &Request{Type: t}
	var err error
	if m.RequestID, err = r.Varint(); err != nil {
		return nil, err
	}
	if hasName(t) {
		m.Namespace, m.Name, err = readFullName(r)
	} else {
		m.Namespace, err = ReadNamespace(r)
	}
	if err != nil {
		return nil, err
	}
	if t == MsgPublish {
		if m.TrackAlias, err = r.Varint(); err != nil {
			return nil, err
		}
	}
	if m.Params, err = ReadParams(r, allowedParams(t)); err != nil {
		return nil, err
	}
	if t == MsgPublish {
		if m.Properties, err = ParseKVs(r.Rest()); err != nil {
			return nil, err
		}
	}
	return m, r.End()
}

// SubscribeOK is SUBSCRIBE_OK (section 9.7).
type SubscribeOK struct {
	TrackAlias uint64
	Params     *MessageParams
	Properties []KV
}

// Append appends the body.
func (m *SubscribeOK) Append(b []byte) []byte {
	b = AppendVarint(b, m.TrackAlias)
	b = AppendParams(b, m.Params)
	return AppendKVs(b, m.Properties)
}

// ParseSubscribeOK parses a SUBSCRIBE_OK body.
func ParseSubscribeOK(p []byte) (*SubscribeOK, error) {
	r := NewReader(p)
	m := &SubscribeOK{}
	var err error
	if m.TrackAlias, err = r.Varint(); err != nil {
		return nil, err
	}
	if m.Params, err = ReadParams(r, AllowSubscribeOK); err != nil {
		return nil, err
	}
	m.Properties, err = ParseKVs(r.Rest())
	return m, err
}

// RequestOK is REQUEST_OK (section 9.3).
type RequestOK struct {
	Params     *MessageParams
	Properties []KV
}

// Append appends the body.
func (m *RequestOK) Append(b []byte) []byte {
	b = AppendParams(b, m.Params)
	return AppendKVs(b, m.Properties)
}

// ParseRequestOK parses a REQUEST_OK body.
func ParseRequestOK(p []byte) (*RequestOK, error) {
	r := NewReader(p)
	m := &RequestOK{}
	var err error
	if m.Params, err = ReadParams(r, AllowRequestOK); err != nil {
		return nil, err
	}
	m.Properties, err = ParseKVs(r.Rest())
	return m, err
}

// Redirect is the Redirect structure of REQUEST_ERROR (section 9.4.1).
type Redirect struct {
	URI       string
	Namespace []string
	Name      string
}

// RequestError is REQUEST_ERROR (section 9.4.2).
type RequestError struct {
	Code          uint64
	RetryInterval uint64
	Reason        string
	Redirect      *Redirect
}

// Append appends the body.
func (m *RequestError) Append(b []byte) []byte {
	b = AppendVarint(b, m.Code)
	b = AppendVarint(b, m.RetryInterval)
	b = appendReason(b, m.Reason)
	if m.Code == RequestErrorRedirect {
		rd := m.Redirect
		if rd == nil {
			rd = &Redirect{}
		}
		b = AppendVarint(b, uint64(len(rd.URI)))
		b = append(b, rd.URI...)
		b = AppendNamespace(b, rd.Namespace)
		b = appendName(b, rd.Name)
	}
	return b
}

// ParseRequestError parses a REQUEST_ERROR body.
func ParseRequestError(p []byte) (*RequestError, error) {
	r := NewReader(p)
	m := &RequestError{}
	var err error
	if m.Code, err = r.Varint(); err != nil {
		return nil, err
	}
	if m.RetryInterval, err = r.Varint(); err != nil {
		return nil, err
	}
	if m.Reason, err = readReason(r); err != nil {
		return nil, err
	}
	if m.Code == RequestErrorRedirect {
		uri, err := r.LenBytes(MaxGoAwayURI, "redirect URI")
		if err != nil {
			return nil, err
		}
		rd := &Redirect{URI: string(uri)}
		if rd.Namespace, rd.Name, err = readFullName(r); err != nil {
			return nil, err
		}
		m.Redirect = rd
	}
	return m, r.End()
}

// RequestUpdate is REQUEST_UPDATE (section 9.5).
type RequestUpdate struct {
	RequestID uint64
	Params    *MessageParams
}

// Append appends the body.
func (m *RequestUpdate) Append(b []byte) []byte {
	b = AppendVarint(b, m.RequestID)
	return AppendParams(b, m.Params)
}

// ParseRequestUpdate parses a REQUEST_UPDATE body.
func ParseRequestUpdate(p []byte) (*RequestUpdate, error) {
	r := NewReader(p)
	m := &RequestUpdate{}
	var err error
	if m.RequestID, err = r.Varint(); err != nil {
		return nil, err
	}
	if m.Params, err = ReadParams(r, AllowUpdate); err != nil {
		return nil, err
	}
	return m, r.End()
}

// PublishDone is PUBLISH_DONE (section 9.9).
type PublishDone struct {
	Status      uint64
	StreamCount uint64
	Reason      string
}

// Append appends the body.
func (m *PublishDone) Append(b []byte) []byte {
	b = AppendVarint(b, m.Status)
	b = AppendVarint(b, m.StreamCount)
	return appendReason(b, m.Reason)
}

// ParsePublishDone parses a PUBLISH_DONE body.
func ParsePublishDone(p []byte) (*PublishDone, error) {
	r := NewReader(p)
	m := &PublishDone{}
	var err error
	if m.Status, err = r.Varint(); err != nil {
		return nil, err
	}
	if m.StreamCount, err = r.Varint(); err != nil {
		return nil, err
	}
	if m.Reason, err = readReason(r); err != nil {
		return nil, err
	}
	return m, r.End()
}

// ParsePublishStateNotify parses a PUBLISH_STATE_NOTIFY body.
func ParsePublishStateNotify(p []byte) (*MessageParams, error) {
	r := NewReader(p)
	m, err := ReadParams(r, AllowStateNotify)
	if err != nil {
		return nil, err
	}
	return m, r.End()
}

// FetchOK is FETCH_OK (section 9.12).
type FetchOK struct {
	EndOfTrack bool
	End        Location
	Params     *MessageParams
	Properties []KV
}

// Append appends the body.
func (m *FetchOK) Append(b []byte) []byte {
	eot := byte(0)
	if m.EndOfTrack {
		eot = 1
	}
	b = append(b, eot)
	b = appendLocation(b, m.End)
	b = AppendParams(b, m.Params)
	return AppendKVs(b, m.Properties)
}

// ParseFetchOK parses a FETCH_OK body.
func ParseFetchOK(p []byte) (*FetchOK, error) {
	r := NewReader(p)
	m := &FetchOK{}
	eot, err := r.Byte()
	if err != nil {
		return nil, err
	}
	if eot > 1 {
		return nil, violation("End Of Track out of range")
	}
	m.EndOfTrack = eot == 1
	if m.End, err = readLocation(r); err != nil {
		return nil, err
	}
	if m.Params, err = ReadParams(r, 0); err != nil {
		return nil, err
	}
	m.Properties, err = ParseKVs(r.Rest())
	return m, err
}

// ParseNamespaceSuffix parses NAMESPACE or NAMESPACE_DONE.
func ParseNamespaceSuffix(p []byte) ([]string, error) {
	r := NewReader(p)
	ns, err := ReadNamespace(r)
	if err != nil {
		return nil, err
	}
	return ns, r.End()
}

// ParsePublishSkipped parses PUBLISH_SKIPPED.
func ParsePublishSkipped(p []byte) ([]string, string, error) {
	r := NewReader(p)
	ns, name, err := readFullName(r)
	if err != nil {
		return nil, "", err
	}
	return ns, name, r.End()
}
