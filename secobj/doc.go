// Package secobj protects MoQ objects end to end through relays with the
// Kolo profile of MoQ Secure Objects (draft-ietf-moq-secure-objects-01).
//
// One cipher suite is used: AES_128_GCM_SHA256_128 (0x0004). The key and
// salt of a track come from HKDF-SHA256 over a 16-byte base key, the Key ID
// and the serialized full track name. The nonce is the salt XOR the 64-bit
// Group ID and 32-bit Object ID, so an Object ID is below 2^32. The AAD is
// the Group ID, the Object ID, the publisher priority and the Immutable
// Properties bytes.
//
// A protected object carries one visible property: Immutable Properties
// (0x0B) holding one Key ID property of type PropertyKeyID (0x78). Its
// payload is the AEAD output of the payload length, the payload and, when
// there are private properties, the marker 00 0A, a length and the
// properties. Every encoding is draft-ietf-moq-transport-22's, so objects
// do not interoperate with other Secure Objects implementations.
//
// Relays still see namespaces, track names, Group and Object IDs, priority,
// Key IDs, sizes and timing, object status and track properties. Status and
// track properties are not authenticated. Go's AES-GCM is constant time only
// in its assembly for amd64 and arm64 CPUs with AES instructions, ppc64x and
// s390x; on 386, arm, riscv64, loong64, mips, wasm, and amd64 or arm64 CPUs
// without AES instructions, it is generic code that is not constant time.
//
// A Sender gives its key for one media namespace to each member over a key
// track that only that member may read; a Keyring receives keys only from the
// peer that KeyringConfig.Authorize names as the namespace owner; each reader
// of a track opens objects through its own Opener, which keeps its own replay
// window.
//
// Keys are never written to disk. Base keys and salts are overwritten when
// replaced, removed or closed; AES key schedules and key messages in key track
// caches and transport buffers are only released, and Go does not guarantee
// that no copy remains.
//
// Experimental: the API may change before v1.0.0.
package secobj
