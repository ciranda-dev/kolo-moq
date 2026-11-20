package wire

import "math"

// Session termination codes (section 12.2) the decoders report.
const (
	CodeInternalError      = 0x1
	CodeProtocolViolation  = 0x3
	CodeKeyValueFormatting = 0x6
)

// Error is a decoding failure; Code is the session termination code the
// draft requires for it.
type Error struct {
	Code uint64
	Msg  string
}

// Error returns the failure message.
func (e *Error) Error() string { return "kolomoq: " + e.Msg }

func violation(msg string) error { return &Error{Code: CodeProtocolViolation, Msg: msg} }

var errShort = violation("truncated message")

// Reader parses a message body held in memory.
type Reader struct {
	b []byte
}

// NewReader returns a Reader over b.
func NewReader(b []byte) *Reader { return &Reader{b: b} }

// Len returns the number of unread bytes.
func (r *Reader) Len() int { return len(r.b) }

// Varint reads a varint.
func (r *Reader) Varint() (uint64, error) {
	if len(r.b) == 0 {
		return 0, errShort
	}
	n := varintSize(r.b[0])
	if len(r.b) < n {
		return 0, errShort
	}
	v := varintValue(r.b[:n])
	r.b = r.b[n:]
	return v, nil
}

// Byte reads one byte.
func (r *Reader) Byte() (byte, error) {
	if len(r.b) == 0 {
		return 0, errShort
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c, nil
}

// Bytes returns the next n bytes without copying them.
func (r *Reader) Bytes(n uint64) ([]byte, error) {
	if n > uint64(len(r.b)) {
		return nil, errShort
	}
	p := r.b[:n:n]
	r.b = r.b[n:]
	return p, nil
}

// Rest returns the unread bytes.
func (r *Reader) Rest() []byte {
	p := r.b
	r.b = nil
	return p
}

// LenBytes reads a varint length and that many bytes, at most max.
func (r *Reader) LenBytes(max uint64, what string) ([]byte, error) {
	n, err := r.Varint()
	if err != nil {
		return nil, err
	}
	if n > max {
		return nil, violation(what + " too long")
	}
	return r.Bytes(n)
}

// End reports an error if bytes are left.
func (r *Reader) End() error {
	if len(r.b) != 0 {
		return violation("message length does not match its body")
	}
	return nil
}

func addOverflows(a, b uint64) bool { return b > math.MaxUint64-a }
