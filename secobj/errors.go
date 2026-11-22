package secobj

import "errors"

var (
	// ErrNoKey means no key is held for the object's Key ID.
	ErrNoKey = errors.New("kolomoq: secobj: no key for this key ID")
	// ErrKeyRetired means the object's key was erased.
	ErrKeyRetired = errors.New("kolomoq: secobj: key retired")
	// ErrAuthentication means the object failed AEAD authentication.
	ErrAuthentication = errors.New("kolomoq: secobj: authentication failed")
	// ErrMalformed means a Key ID property or a decrypted plaintext breaks the profile's encoding.
	ErrMalformed = errors.New("kolomoq: secobj: malformed object")
	// ErrNotProtected means the object carries no Immutable Properties, so it was not sealed.
	ErrNotProtected = errors.New("kolomoq: secobj: object not protected")
	// ErrReplay means the object was opened before or falls outside the replay window.
	ErrReplay = errors.New("kolomoq: secobj: replayed object")
	// ErrWrongSession means a session that neither owns a protected namespace nor is a listed relay carries it.
	ErrWrongSession = errors.New("kolomoq: secobj: session may not carry this namespace")
	// ErrObjectID means an Object ID of 2^32 or more, or a (Group ID, Object ID) not after the last one sealed under the key.
	ErrObjectID = errors.New("kolomoq: secobj: object ID not allowed")
	// ErrKeyMessage means a key message breaks the profile's encoding.
	ErrKeyMessage = errors.New("kolomoq: secobj: malformed key message")
	// ErrUnauthorized means a key message came from a peer that may not give keys for its namespace.
	ErrUnauthorized = errors.New("kolomoq: secobj: unauthorized key message")
	// ErrInvalidConfig means a configuration field is out of range.
	ErrInvalidConfig = errors.New("kolomoq: secobj: invalid config")
	// ErrTooManySenders means a Keyring already holds keys for the MaxSenders namespaces it is capped at.
	ErrTooManySenders = errors.New("kolomoq: secobj: too many senders")
)
