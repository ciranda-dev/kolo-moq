package kolomoq

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
)

// KeyNamespaceField is the reserved first namespace field of key tracks: PublishNamespace refuses it, namespace answers never list it, and a Relay refuses every request under it.
const KeyNamespaceField = "kolo-keys"

var errRoomPolicy = errors.New("kolomoq: request refused by the room policy")

// RoomPolicy authorizes requests for a relay serving rooms: a peer publishes only Room+{hex(peer)} and, if Member allows it, reads under Room. Everything else is refused. A nil Member admits no reader.
type RoomPolicy struct {
	Room   Namespace
	Member func(peer ed25519.PublicKey) bool
}

// Authorize decides one request as Config.Authorize does; a peer's field is the lowercase hex of its 32-byte key.
func (p RoomPolicy) Authorize(peer ed25519.PublicKey, kind RequestKind, ns Namespace, track string) error {
	if len(peer) != ed25519.PublicKeySize || !ns.HasPrefix(p.Room) {
		return errRoomPolicy
	}
	switch kind {
	case KindPublishNamespace:
		if len(ns) == len(p.Room)+1 && ns[len(p.Room)] == hex.EncodeToString(peer) {
			return nil
		}
	case KindSubscribe, KindFetch, KindTrackStatus, KindSubscribeNamespace:
		if p.Member != nil && p.Member(peer) {
			return nil
		}
	}
	return errRoomPolicy
}
