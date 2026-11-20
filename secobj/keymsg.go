package secobj

import (
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

const (
	keyMessageFormat = 1
	instanceSize     = 16
	// keyTrackLen is the length of a key track name: the hex of an Ed25519 public key.
	keyTrackLen = 2 * ed25519.PublicKeySize
)

// KeyNamespace returns the namespace of the key tracks of the media namespace ns.
func KeyNamespace(ns kolomoq.Namespace) kolomoq.Namespace {
	return append(kolomoq.Namespace{kolomoq.KeyNamespaceField}, ns...)
}

// KeyTrack returns the name of the key track for member: the lowercase hex of its public key.
func KeyTrack(member ed25519.PublicKey) string { return hex.EncodeToString(member) }

// checkKeyNamespace applies the media namespace limits of the profile: 1 to 31 non-empty
// fields, a first field other than the reserved one, and a key full track name within 4096 bytes.
func checkKeyNamespace(ns kolomoq.Namespace) error {
	if len(ns) == 0 || len(ns) > maxFields || ns[0] == kolomoq.KeyNamespaceField {
		return kolomoq.ErrInvalidName
	}
	n := len(kolomoq.KeyNamespaceField) + keyTrackLen
	for _, f := range ns {
		if f == "" {
			return kolomoq.ErrInvalidName
		}
		n += len(f)
	}
	if n > maxNameLen {
		return kolomoq.ErrInvalidName
	}
	return nil
}

// keyMessage gives one sender's base key for one media namespace.
type keyMessage struct {
	instance [instanceSize]byte
	kid      uint64
	ns       kolomoq.Namespace
	base     [keySize]byte
}

// Format prints no key material.
func (keyMessage) Format(f fmt.State, _ rune) { io.WriteString(f, "secobj.keyMessage{redacted}") }

func (m *keyMessage) erase() { clear(m.base[:]) }

// appendKeyMessage appends the canonical encoding of m.
func appendKeyMessage(b []byte, m *keyMessage) []byte {
	b = append(b, keyMessageFormat)
	b = binary.BigEndian.AppendUint16(b, uint16(AES128GCMSHA256))
	b = append(b, m.instance[:]...)
	b = wire.AppendVarint(b, m.kid)
	b = wire.AppendNamespace(b, m.ns)
	b = wire.AppendVarint(b, keySize)
	return append(b, m.base[:]...)
}

// parseKeyMessage accepts only the canonical encoding. Every failure is ErrKeyMessage, so no
// error carries message bytes.
func parseKeyMessage(b []byte) (keyMessage, error) {
	var m keyMessage
	if len(b) < 3+instanceSize || b[0] != keyMessageFormat || binary.BigEndian.Uint16(b[1:3]) != uint16(AES128GCMSHA256) {
		return m, ErrKeyMessage
	}
	copy(m.instance[:], b[3:])
	b = b[3+instanceSize:]
	kid, b, ok := readVarint(b)
	if !ok {
		return m, ErrKeyMessage
	}
	count, b, ok := readVarint(b)
	if !ok || count == 0 || count > maxFields {
		return m, ErrKeyMessage
	}
	ns := make(kolomoq.Namespace, count)
	room := maxNameLen - len(kolomoq.KeyNamespaceField) - keyTrackLen
	for i := range ns {
		var l uint64
		l, b, ok = readVarint(b)
		if !ok || l == 0 || l > uint64(room) || l > uint64(len(b)) {
			return m, ErrKeyMessage
		}
		room -= int(l)
		ns[i], b = string(b[:l]), b[l:]
	}
	if ns[0] == kolomoq.KeyNamespaceField {
		return m, ErrKeyMessage
	}
	l, b, ok := readVarint(b)
	if !ok || l != keySize || len(b) != keySize {
		return m, ErrKeyMessage
	}
	m.kid, m.ns = kid, ns
	copy(m.base[:], b)
	return m, nil
}
