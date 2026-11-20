// Package wire encodes and decodes the messages and data streams of MoQ
// Transport draft-ietf-moq-transport-22.
package wire

import (
	"encoding/binary"
	"io"
	"math/bits"
)

// VarintLen returns the length of the shortest encoding of v.
func VarintLen(v uint64) int {
	switch {
	case v < 1<<7:
		return 1
	case v < 1<<14:
		return 2
	case v < 1<<21:
		return 3
	case v < 1<<28:
		return 4
	case v < 1<<35:
		return 5
	case v < 1<<42:
		return 6
	case v < 1<<49:
		return 7
	case v < 1<<56:
		return 8
	}
	return 9
}

// AppendVarint appends the shortest encoding of v (section 8.1).
func AppendVarint(b []byte, v uint64) []byte {
	n := VarintLen(v)
	if n == 9 {
		b = append(b, 0xff)
		return binary.BigEndian.AppendUint64(b, v)
	}
	start := len(b)
	for i := n - 1; i >= 0; i-- {
		b = append(b, byte(v>>(8*i)))
	}
	b[start] |= byte(0xff << (9 - n))
	return b
}

// varintSize returns the encoded length announced by the first byte.
func varintSize(first byte) int {
	ones := bits.LeadingZeros8(^first)
	if ones == 8 {
		return 9
	}
	return ones + 1
}

func varintValue(p []byte) uint64 {
	n := len(p)
	if n == 9 {
		return binary.BigEndian.Uint64(p[1:])
	}
	v := uint64(p[0] & (0xff >> n))
	for _, c := range p[1:] {
		v = v<<8 | uint64(c)
	}
	return v
}

// ByteReader is the reader data and control streams are parsed from.
type ByteReader interface {
	io.Reader
	io.ByteReader
}

// ReadVarint reads one varint from r. A stream that ends inside the
// varint returns io.ErrUnexpectedEOF; one that ends before it, io.EOF.
func ReadVarint(r ByteReader) (uint64, error) {
	first, err := r.ReadByte()
	if err != nil {
		return 0, err
	}
	n := varintSize(first)
	var buf [9]byte
	buf[0] = first
	if n > 1 {
		if _, err := io.ReadFull(r, buf[1:n]); err != nil {
			return 0, unexpected(err)
		}
	}
	return varintValue(buf[:n]), nil
}

func unexpected(err error) error {
	if err == io.EOF {
		return io.ErrUnexpectedEOF
	}
	return err
}
