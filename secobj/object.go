package secobj

import (
	"cmp"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"math/bits"
	"slices"
	"sync"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

const (
	propImmutable = 0x0B
	propPadding   = 0x32
	maxObjectID   = 1<<32 - 1
	// maxPayload is the largest object payload a kolo-moq receiver accepts (Config.MaxObjectSize).
	maxPayload = 1 << 30
	// maxImmSize is the Key ID type byte plus the longest vi64.
	maxImmSize = 1 + 9
	aadSize    = 8 + 4 + 1 + maxImmSize
	// maxFields leaves one field for the key namespace prefix.
	maxFields  = 31
	maxNameLen = wire.MaxFullNameLen
)

// trackKey seals and opens the objects of one track under one Key ID.
type trackKey struct {
	mu     sync.Mutex
	aead   cipher.AEAD // nil once erased
	salt   [saltSize]byte
	kid    uint64
	imm    [maxImmSize]byte
	immLen int
	sealed bool
	last   kolomoq.Location
	// nonce and aad are scratch buffers under mu; locals would escape through the AEAD interface.
	nonce [saltSize]byte
	aad   [aadSize]byte
}

// checkName applies the profile's media namespace limits.
func checkName(ns kolomoq.Namespace, track string) error {
	if len(ns) == 0 || len(ns) > maxFields || ns[0] == kolomoq.KeyNamespaceField {
		return kolomoq.ErrInvalidName
	}
	n := len(track)
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

func newTrackKey(base *[keySize]byte, kid uint64, ns kolomoq.Namespace, track string) (*trackKey, error) {
	if err := checkName(ns, track); err != nil {
		return nil, err
	}
	ftn := appendFullTrackName(nil, ns, track)
	key, salt, err := deriveKeySalt(base[:], profileInfo(keyLabel, ftn, kid), profileInfo(saltLabel, ftn, kid))
	if err != nil {
		return nil, err
	}
	aead, err := newAEAD(&key)
	clear(key[:])
	if err != nil {
		clear(salt[:])
		return nil, err
	}
	k := &trackKey{aead: aead, salt: salt, kid: kid}
	k.immLen = len(wire.AppendVarint(append(k.imm[:0], PropertyKeyID), kid))
	return k, nil
}

// Format prints no key material.
func (k *trackKey) Format(f fmt.State, _ rune) { io.WriteString(f, "secobj.trackKey{redacted}") }

// erase overwrites the salt and drops the cipher; Go keeps no guarantee about copies.
func (k *trackKey) erase() {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.aead = nil
	clear(k.salt[:])
	clear(k.nonce[:])
	clear(k.aad[:])
}

// seal returns the protected payload and the single Immutable Properties property of an object.
// The payload and the property bytes share one allocation.
func (k *trackKey) seal(group, object uint64, priority uint8, payload []byte, private []kolomoq.Property) ([]byte, []kolomoq.Property, error) {
	if object > maxObjectID {
		return nil, nil, ErrObjectID
	}
	private, listLen, err := checkPrivate(private)
	if err != nil {
		return nil, nil, err
	}
	// listLen <= maxPayload, and the sum must not overflow a 32-bit int.
	if len(payload) > maxPayload-listLen {
		return nil, nil, kolomoq.ErrObjectTooLarge
	}
	ptLen := wire.VarintLen(uint64(len(payload))) + len(payload)
	if listLen > 0 {
		ptLen += 2 + wire.VarintLen(uint64(listLen)) + listLen
	}
	if ptLen+tagSize > maxPayload {
		return nil, nil, kolomoq.ErrObjectTooLarge
	}
	buf := make([]byte, 0, ptLen+tagSize+maxImmSize)
	buf = wire.AppendVarint(buf, uint64(len(payload)))
	buf = append(buf, payload...)
	if listLen > 0 {
		buf = append(buf, 0, PropertyEncryptedList)
		buf = wire.AppendVarint(buf, uint64(listLen))
		buf = appendList(buf, private)
	}
	ct, imm, err := k.sealPlaintext(buf, group, uint32(object), priority)
	if err != nil {
		return nil, nil, err
	}
	return ct, []kolomoq.Property{{Type: propImmutable, Bytes: imm}}, nil
}

// sealPlaintext encrypts pt in place. Spare capacity in pt for the tag and the Key ID bytes
// avoids further allocations.
func (k *trackKey) sealPlaintext(pt []byte, group uint64, object uint32, priority uint8) (ct, imm []byte, err error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.aead == nil {
		return nil, nil, ErrKeyRetired
	}
	loc := kolomoq.Location{Group: group, Object: uint64(object)}
	if k.sealed && !k.last.Less(loc) {
		return nil, nil, ErrObjectID
	}
	immBytes := k.imm[:k.immLen]
	makeNonce(&k.nonce, &k.salt, group, object)
	aad := appendAAD(k.aad[:0], group, object, priority, immBytes)
	ct = k.aead.Seal(pt[:0], k.nonce[:], pt, aad)
	imm = append(ct[len(ct):], immBytes...)
	k.sealed, k.last = true, loc
	return ct[:len(ct):len(ct)], imm[:len(imm):len(imm)], nil
}

// open authenticates and decrypts obj. The payload and the property bytes share one new buffer.
func (k *trackKey) open(obj kolomoq.Object) ([]byte, []kolomoq.Property, error) {
	if obj.Status != kolomoq.StatusNormal {
		return nil, nil, ErrNotProtected
	}
	kid, imm, err := keyID(obj.Properties)
	if err != nil {
		return nil, nil, err
	}
	if kid != k.kid {
		return nil, nil, ErrNoKey
	}
	if obj.ID > maxObjectID {
		return nil, nil, ErrObjectID
	}
	// The shortest plaintext is one length byte.
	if len(obj.Payload) < 1+tagSize {
		return nil, nil, ErrAuthentication
	}
	if len(obj.Payload) > maxPayload {
		return nil, nil, ErrMalformed
	}
	buf := make([]byte, 0, len(obj.Payload)-tagSize)
	pt, err := k.openPayload(buf, obj.Group, uint32(obj.ID), obj.Priority, imm, obj.Payload)
	if err != nil {
		return nil, nil, err
	}
	payload, props, err := parsePlaintext(pt)
	if err != nil {
		clear(buf[:cap(buf)])
		return nil, nil, err
	}
	return payload, props, nil
}

func (k *trackKey) openPayload(dst []byte, group uint64, object uint32, priority uint8, imm, ct []byte) ([]byte, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if k.aead == nil {
		return nil, ErrKeyRetired
	}
	makeNonce(&k.nonce, &k.salt, group, object)
	aad := appendAAD(k.aad[:0], group, object, priority, imm)
	pt, err := k.aead.Open(dst, k.nonce[:], ct, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return pt, nil
}

// keyID returns the Key ID of an object and the Immutable Properties bytes that carry it.
// The bytes must be exactly PropertyKeyID followed by a minimal vi64.
func keyID(props []kolomoq.Property) (uint64, []byte, error) {
	var imm []byte
	n := 0
	for _, p := range props {
		if p.Type == propImmutable {
			imm = p.Bytes
			n++
		}
	}
	switch {
	case n == 0:
		return 0, nil, ErrNotProtected
	case n > 1:
		return 0, nil, ErrMalformed
	case len(imm) < 2 || imm[0] != PropertyKeyID:
		return 0, nil, ErrMalformed
	}
	kid, rest, ok := readVarint(imm[1:])
	if !ok || len(rest) != 0 {
		return 0, nil, ErrMalformed
	}
	return kid, imm, nil
}

// checkPrivate validates the properties to encrypt and returns them in ascending type order
// with the encoded list length.
func checkPrivate(ps []kolomoq.Property) ([]kolomoq.Property, int, error) {
	if len(ps) == 0 {
		return nil, 0, nil
	}
	if !slices.IsSortedFunc(ps, func(a, b kolomoq.Property) int { return cmp.Compare(a.Type, b.Type) }) {
		ps = slices.Clone(ps)
		slices.SortFunc(ps, func(a, b kolomoq.Property) int { return cmp.Compare(a.Type, b.Type) })
	}
	n := 0
	var prev uint64
	for i, p := range ps {
		switch {
		case i > 0 && p.Type == prev,
			p.Type == PropertyEncryptedList, p.Type == propImmutable, p.Type == propPadding,
			p.Type%2 == 0 && p.Bytes != nil,
			p.Type%2 == 1 && (p.Value != 0 || len(p.Bytes) > wire.MaxKVBytes):
			return nil, 0, kolomoq.ErrInvalidProperty
		}
		n += wire.VarintLen(p.Type - prev)
		if p.Type%2 == 0 {
			n += wire.VarintLen(p.Value)
		} else {
			n += wire.VarintLen(uint64(len(p.Bytes))) + len(p.Bytes)
		}
		if n > maxPayload {
			return nil, 0, kolomoq.ErrObjectTooLarge
		}
		prev = p.Type
	}
	return ps, n, nil
}

// appendList appends sorted properties as draft-22 Key-Value-Pairs.
func appendList(b []byte, ps []kolomoq.Property) []byte {
	var prev uint64
	for _, p := range ps {
		b = wire.AppendVarint(b, p.Type-prev)
		prev = p.Type
		if p.Type%2 == 0 {
			b = wire.AppendVarint(b, p.Value)
			continue
		}
		b = wire.AppendVarint(b, uint64(len(p.Bytes)))
		b = append(b, p.Bytes...)
	}
	return b
}

// parsePlaintext splits a decrypted plaintext into payload and private properties.
// Only the encoding seal produces is accepted.
func parsePlaintext(pt []byte) ([]byte, []kolomoq.Property, error) {
	n, rest, ok := readVarint(pt)
	if !ok || n > uint64(len(rest)) {
		return nil, nil, ErrMalformed
	}
	payload, rest := rest[:n:n], rest[n:]
	if len(rest) == 0 {
		return payload, nil, nil
	}
	if len(rest) < 2 || rest[0] != 0 || rest[1] != PropertyEncryptedList {
		return nil, nil, ErrMalformed
	}
	n, list, ok := readVarint(rest[2:])
	if !ok || n == 0 || n != uint64(len(list)) {
		return nil, nil, ErrMalformed
	}
	count, err := parseList(list, nil)
	if err != nil {
		return nil, nil, err
	}
	props := make([]kolomoq.Property, count)
	if _, err := parseList(list, props); err != nil {
		return nil, nil, err
	}
	return payload, props, nil
}

// parseList validates a Key-Value-Pair list with strictly ascending types, fills out if it is
// not nil, and returns the count.
func parseList(b []byte, out []kolomoq.Property) (int, error) {
	var prev uint64
	i := 0
	for len(b) > 0 {
		d, rest, ok := readVarint(b)
		if !ok || (i > 0 && d == 0) {
			return 0, ErrMalformed
		}
		t, carry := bits.Add64(prev, d, 0)
		if carry != 0 || t == PropertyEncryptedList || t == propImmutable || t == propPadding {
			return 0, ErrMalformed
		}
		prev = t
		p := kolomoq.Property{Type: t}
		if t%2 == 0 {
			p.Value, rest, ok = readVarint(rest)
			if !ok {
				return 0, ErrMalformed
			}
		} else {
			var l uint64
			l, rest, ok = readVarint(rest)
			if !ok || l > wire.MaxKVBytes || l > uint64(len(rest)) {
				return 0, ErrMalformed
			}
			p.Bytes, rest = rest[:l:l], rest[l:]
		}
		if out != nil {
			out[i] = p
		}
		b = rest
		i++
	}
	return i, nil
}

// readVarint reads a draft-22 vi64 (section 8.1) and refuses a longer form than needed.
func readVarint(b []byte) (uint64, []byte, bool) {
	if len(b) == 0 {
		return 0, nil, false
	}
	n := bits.LeadingZeros8(^b[0]) + 1
	if n == 9 {
		if len(b) < 9 {
			return 0, nil, false
		}
		v := binary.BigEndian.Uint64(b[1:9])
		return v, b[9:], wire.VarintLen(v) == 9
	}
	if len(b) < n {
		return 0, nil, false
	}
	v := uint64(b[0] & (0xff >> n))
	for _, c := range b[1:n] {
		v = v<<8 | uint64(c)
	}
	return v, b[n:], wire.VarintLen(v) == n
}
