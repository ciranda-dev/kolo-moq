package kolomoq

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

var (
	// ErrInvalidConfig means a Config, OriginConfig or TrackOptions field is out of range.
	ErrInvalidConfig = errors.New("kolomoq: invalid config")
	// ErrInvalidName means a namespace or track name breaks the draft or configured limits.
	ErrInvalidName = errors.New("kolomoq: invalid namespace or track name")
	// ErrInvalidProperty means a property's Type parity does not match its value, or its bytes are too long.
	ErrInvalidProperty = errors.New("kolomoq: invalid property")
	// ErrClosed means this side closed the session, subscription, fetch, track or group.
	ErrClosed = errors.New("kolomoq: closed")
	// ErrGoingAway means a GOAWAY was received, so no new request is sent, or this side already sent one, so GoAway is not repeated.
	ErrGoingAway = errors.New("kolomoq: session is going away")
	// ErrVersion means the peer's control stream did not start with the moqt-22 preface.
	ErrVersion = errors.New("kolomoq: peer speaks another MoQ Transport version")
	// ErrProtocol means the peer broke the draft; the session is closed.
	ErrProtocol = errors.New("kolomoq: protocol violation")
	// ErrTimeout means the setup or a request took longer than its configured timeout.
	ErrTimeout = errors.New("kolomoq: timeout")
	// ErrNewGroupTooSoon means RequestNewGroup was called less than NewGroupRequestInterval after the last request on the subscription.
	ErrNewGroupTooSoon = errors.New("kolomoq: new group requested too soon")
	// ErrTrackExists means the origin already has a track with this name.
	ErrTrackExists = errors.New("kolomoq: track exists")
	// ErrTooManyTracks means the origin holds the MaxTracks tracks it is capped at.
	ErrTooManyTracks = errors.New("kolomoq: too many tracks")
	// ErrObjectTooLarge means an object is larger than MaxObjectSize.
	ErrObjectTooLarge = errors.New("kolomoq: object too large")
	// ErrMalformedTrack means the publisher sent objects that break the draft's track rules.
	ErrMalformedTrack = errors.New("kolomoq: malformed track")
	// ErrTooManyNamespaces means a namespace subscription announced more than MaxNamespaces namespaces.
	ErrTooManyNamespaces = errors.New("kolomoq: too many namespaces")
	// ErrRequestCanceled means the peer reset a request stream; the error wraps the stream code.
	ErrRequestCanceled = errors.New("kolomoq: request canceled by peer")
	// ErrUnsupportedProperty means a track carries a mandatory track property (types 0x4000 to 0x7FFF) this side does not understand.
	ErrUnsupportedProperty = errors.New("kolomoq: unsupported mandatory track property")
)

// SessionCode is a session termination code (draft section 12.2).
type SessionCode uint64

// Session termination codes.
const (
	CodeNoError                 SessionCode = 0x0
	CodeInternalError           SessionCode = 0x1
	CodeUnauthorized            SessionCode = 0x2
	CodeProtocolViolation       SessionCode = 0x3
	CodeInvalidRequestID        SessionCode = 0x4
	CodeDuplicateTrackAlias     SessionCode = 0x5
	CodeKeyValueFormatting      SessionCode = 0x6
	CodeInvalidPath             SessionCode = 0x8
	CodeMalformedPath           SessionCode = 0x9
	CodeGoAwayTimeout           SessionCode = 0x10
	CodeControlMessageTimeout   SessionCode = 0x11
	CodeDataStreamTimeout       SessionCode = 0x12
	CodeAuthTokenCacheOverflow  SessionCode = 0x13
	CodeDuplicateAuthTokenAlias SessionCode = 0x14
	CodeMalformedAuthToken      SessionCode = 0x16
	CodeUnknownAuthTokenAlias   SessionCode = 0x17
	CodeExpiredAuthToken        SessionCode = 0x18
	CodeInvalidAuthority        SessionCode = 0x19
	CodeMalformedAuthority      SessionCode = 0x1A
	CodeTooManyRequestUpdates   SessionCode = 0x1B
	// CodeSuspend is kolo-moq's own code, outside the draft's: Suspend closes a session with it.
	CodeSuspend SessionCode = 0x100
)

var sessionCodeNames = map[SessionCode]string{
	CodeNoError: "NO_ERROR", CodeInternalError: "INTERNAL_ERROR", CodeUnauthorized: "UNAUTHORIZED",
	CodeProtocolViolation: "PROTOCOL_VIOLATION", CodeInvalidRequestID: "INVALID_REQUEST_ID",
	CodeDuplicateTrackAlias: "DUPLICATE_TRACK_ALIAS", CodeKeyValueFormatting: "KEY_VALUE_FORMATTING_ERROR",
	CodeInvalidPath: "INVALID_PATH", CodeMalformedPath: "MALFORMED_PATH", CodeGoAwayTimeout: "GOAWAY_TIMEOUT",
	CodeControlMessageTimeout: "CONTROL_MESSAGE_TIMEOUT", CodeDataStreamTimeout: "DATA_STREAM_TIMEOUT",
	CodeAuthTokenCacheOverflow: "AUTH_TOKEN_CACHE_OVERFLOW", CodeDuplicateAuthTokenAlias: "DUPLICATE_AUTH_TOKEN_ALIAS",
	CodeMalformedAuthToken: "MALFORMED_AUTH_TOKEN", CodeUnknownAuthTokenAlias: "UNKNOWN_AUTH_TOKEN_ALIAS",
	CodeExpiredAuthToken: "EXPIRED_AUTH_TOKEN", CodeInvalidAuthority: "INVALID_AUTHORITY",
	CodeMalformedAuthority: "MALFORMED_AUTHORITY", CodeTooManyRequestUpdates: "TOO_MANY_REQUEST_UPDATES",
	CodeSuspend: "SUSPEND",
}

// String returns the draft name of the code, or its hex value if unknown.
func (c SessionCode) String() string { return codeName(sessionCodeNames, c) }

// RequestCode is a REQUEST_ERROR code (draft section 12.3).
type RequestCode uint64

// REQUEST_ERROR codes.
const (
	ReqInternalError        RequestCode = 0x0
	ReqUnauthorized         RequestCode = 0x1
	ReqTimeout              RequestCode = 0x2
	ReqNotSupported         RequestCode = 0x3
	ReqMalformedAuthToken   RequestCode = 0x4
	ReqExpiredAuthToken     RequestCode = 0x5
	ReqGoingAway            RequestCode = 0x6
	ReqExcessiveLoad        RequestCode = 0x9
	ReqDoesNotExist         RequestCode = 0x10
	ReqInvalidRange         RequestCode = 0x11
	ReqMalformedTrack       RequestCode = 0x12
	ReqUninterested         RequestCode = 0x20
	ReqPrefixOverlap        RequestCode = 0x30
	ReqNamespaceTooLarge    RequestCode = 0x31
	ReqUnsupportedExtension RequestCode = 0x33
	ReqRedirect             RequestCode = 0x34
	ReqConflictingFilters   RequestCode = 0x35
	ReqInvalidFilter        RequestCode = 0x36
)

var requestCodeNames = map[RequestCode]string{
	ReqInternalError: "INTERNAL_ERROR", ReqUnauthorized: "UNAUTHORIZED", ReqTimeout: "TIMEOUT",
	ReqNotSupported: "NOT_SUPPORTED", ReqMalformedAuthToken: "MALFORMED_AUTH_TOKEN",
	ReqExpiredAuthToken: "EXPIRED_AUTH_TOKEN", ReqGoingAway: "GOING_AWAY", ReqExcessiveLoad: "EXCESSIVE_LOAD",
	ReqDoesNotExist: "DOES_NOT_EXIST", ReqInvalidRange: "INVALID_RANGE", ReqMalformedTrack: "MALFORMED_TRACK",
	ReqUninterested: "UNINTERESTED", ReqPrefixOverlap: "PREFIX_OVERLAP", ReqNamespaceTooLarge: "NAMESPACE_TOO_LARGE",
	ReqUnsupportedExtension: "UNSUPPORTED_EXTENSION", ReqRedirect: "REDIRECT",
	ReqConflictingFilters: "CONFLICTING_FILTERS", ReqInvalidFilter: "INVALID_FILTER",
}

// String returns the draft name of the code, or its hex value if unknown.
func (c RequestCode) String() string { return codeName(requestCodeNames, c) }

// DoneCode is a PUBLISH_DONE status code (draft section 12.4).
type DoneCode uint64

// PUBLISH_DONE status codes.
const (
	DoneInternalError  DoneCode = 0x0
	DoneUnauthorized   DoneCode = 0x1
	DoneTrackEnded     DoneCode = 0x2
	DoneGoingAway      DoneCode = 0x4
	DoneTooFarBehind   DoneCode = 0x5
	DoneExpired        DoneCode = 0x6
	DoneUpdateFailed   DoneCode = 0x8
	DoneExcessiveLoad  DoneCode = 0x9
	DoneMalformedTrack DoneCode = 0x12
)

var doneCodeNames = map[DoneCode]string{
	DoneInternalError: "INTERNAL_ERROR", DoneUnauthorized: "UNAUTHORIZED", DoneTrackEnded: "TRACK_ENDED",
	DoneGoingAway: "GOING_AWAY", DoneTooFarBehind: "TOO_FAR_BEHIND", DoneExpired: "EXPIRED",
	DoneUpdateFailed: "UPDATE_FAILED", DoneExcessiveLoad: "EXCESSIVE_LOAD", DoneMalformedTrack: "MALFORMED_TRACK",
}

// String returns the draft name of the code, or its hex value if unknown.
func (c DoneCode) String() string { return codeName(doneCodeNames, c) }

// Stream reset codes (draft section 12.5).
const (
	resetInternalError   = 0x0
	resetCancelled       = 0x1
	resetDeliveryTimeout = 0x2
	resetSessionClosed   = 0x3
	resetGoingAway       = 0x4
	resetUnknownStatus   = 0x6
	resetExcessiveLoad   = 0x9
	resetMalformedTrack  = 0x12
)

func codeName[C ~uint64](names map[C]string, c C) string {
	if n, ok := names[c]; ok {
		return n
	}
	return "0x" + strconv.FormatUint(uint64(c), 16)
}

// SessionError means the session ended with a MoQT termination code.
// Remote reports whether the peer chose the code.
type SessionError struct {
	Code   SessionCode
	Remote bool
	err    error
}

// Error says who closed the session and with which code.
func (e *SessionError) Error() string {
	who := "locally"
	if e.Remote {
		who = "by peer"
	}
	return fmt.Sprintf("kolomoq: session closed %s with %v", who, e.Code)
}

// Unwrap returns the sentinel behind a local close (ErrProtocol, ErrVersion, ErrTimeout), if any.
func (e *SessionError) Unwrap() error { return e.err }

// RequestError is a REQUEST_ERROR from the peer. Reason is the peer's text
// (at most 1024 bytes on the wire) with bytes outside printable ASCII
// escaped; it is not part of Error().
type RequestError struct {
	Code RequestCode
	// Retry reports whether the peer allows a retry, after RetryAfter.
	Retry      bool
	RetryAfter time.Duration
	Reason     string
}

// Error names the refusal code and leaves out the peer text.
func (e *RequestError) Error() string { return "kolomoq: request refused with " + e.Code.String() }

// PublishDoneError means the publisher ended a subscription with a status
// other than TRACK_ENDED. Reason is sanitized peer text, as in RequestError.
type PublishDoneError struct {
	Code   DoneCode
	Reason string
}

// Error names the status code and leaves out the peer text.
func (e *PublishDoneError) Error() string {
	return "kolomoq: subscription ended with " + e.Code.String()
}

// sanitize escapes bytes outside printable ASCII (draft section 15.9).
func sanitize(s string) string {
	q := strconv.QuoteToASCII(s)
	return q[1 : len(q)-1]
}

func requestErrorFromWire(m *wire.RequestError) *RequestError {
	e := &RequestError{Code: RequestCode(m.Code), Reason: sanitize(m.Reason)}
	if m.RetryInterval > 0 {
		e.Retry = true
		ms := min(m.RetryInterval-1, uint64(1<<62)/uint64(time.Millisecond))
		e.RetryAfter = time.Duration(ms) * time.Millisecond
	}
	return e
}

// sessionCode returns the termination code for a decoding error.
func sessionCode(err error) SessionCode {
	var we *wire.Error
	if errors.As(err, &we) {
		return SessionCode(we.Code)
	}
	return CodeProtocolViolation
}
