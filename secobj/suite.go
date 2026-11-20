package secobj

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/sha256"
	"encoding/binary"
	"errors"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// Suite is an SFrame cipher suite identifier (RFC 9605 section 8.1).
type Suite uint16

// AES128GCMSHA256 is AES_128_GCM_SHA256_128, the only suite of the profile.
const AES128GCMSHA256 Suite = 0x0004

// Property types of the profile.
const (
	// PropertyKeyID is the type of the Key ID property inside Immutable Properties.
	PropertyKeyID = 0x78
	// PropertyEncryptedList is the type that marks the Encrypted Properties List inside the plaintext.
	PropertyEncryptedList = 0x0A
)

const (
	keySize   = 16 // Nk
	saltSize  = 12 // Nn
	tagSize   = 16 // Nt
	keyLabel  = "MOQ 1.0 Secure Objects Secret key "
	saltLabel = "MOQ 1.0 Secret salt "
)

var errDerive = errors.New("kolomoq: secobj: key derivation failed")

// extractSecret is HKDF-Extract with SHA-256 and an empty salt.
func extractSecret(base []byte) ([]byte, error) {
	secret, err := hkdf.Extract(sha256.New, base, nil)
	if err != nil {
		return nil, errDerive
	}
	return secret, nil
}

// expandKeySalt is HKDF-Expand of the key and the salt with their info strings.
func expandKeySalt(secret []byte, keyInfo, saltInfo string) (key [keySize]byte, salt [saltSize]byte, err error) {
	k, err := hkdf.Expand(sha256.New, secret, keyInfo, keySize)
	if err != nil {
		return key, salt, errDerive
	}
	copy(key[:], k)
	clear(k)
	s, err := hkdf.Expand(sha256.New, secret, saltInfo, saltSize)
	if err != nil {
		clear(key[:])
		return key, salt, errDerive
	}
	copy(salt[:], s)
	clear(s)
	return key, salt, nil
}

// deriveKeySalt is the key schedule of RFC 9605 section 4.4.2 with the info strings given.
func deriveKeySalt(base []byte, keyInfo, saltInfo string) ([keySize]byte, [saltSize]byte, error) {
	secret, err := extractSecret(base)
	if err != nil {
		return [keySize]byte{}, [saltSize]byte{}, err
	}
	defer clear(secret)
	return expandKeySalt(secret, keyInfo, saltInfo)
}

// profileInfo returns label + full track name + be16(suite) + be64(kid) (Secure Objects 3.7).
func profileInfo(label string, ftn []byte, kid uint64) string {
	b := make([]byte, 0, len(label)+len(ftn)+2+8)
	b = append(b, label...)
	b = append(b, ftn...)
	b = binary.BigEndian.AppendUint16(b, uint16(AES128GCMSHA256))
	b = binary.BigEndian.AppendUint64(b, kid)
	return string(b)
}

// appendFullTrackName appends the namespace and track name in draft-22 encoding (Secure Objects 3.3.1).
func appendFullTrackName(b []byte, ns kolomoq.Namespace, track string) []byte {
	b = wire.AppendNamespace(b, ns)
	b = wire.AppendVarint(b, uint64(len(track)))
	return append(b, track...)
}

// makeNonce sets nonce to salt XOR (be64(group) || be32(object)) (Secure Objects 3.6).
func makeNonce(nonce, salt *[saltSize]byte, group uint64, object uint32) {
	var ctr [saltSize]byte
	binary.BigEndian.PutUint64(ctr[:8], group)
	binary.BigEndian.PutUint32(ctr[8:], object)
	for i := range nonce {
		nonce[i] = salt[i] ^ ctr[i]
	}
}

// appendAAD appends be64(group) || be32(object) || priority || imm (Secure Objects 3.5).
func appendAAD(b []byte, group uint64, object uint32, priority uint8, imm []byte) []byte {
	b = binary.BigEndian.AppendUint64(b, group)
	b = binary.BigEndian.AppendUint32(b, object)
	b = append(b, priority)
	return append(b, imm...)
}

func newAEAD(key *[keySize]byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, errDerive
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errDerive
	}
	return aead, nil
}
