package secobj

import (
	"cmp"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

const (
	// defaultMaxTracks matches kolo-media's CatalogLimits MaxTracks.
	defaultMaxTracks = 1024
	// maxUnits is the usage limit of one track key: 2^24.5 full TLS records for a 2^-57
	// margin (RFC 9846 section 5.5), rounded down.
	maxUnits = 1 << 24
	// unitSize is the plaintext of one full TLS record.
	unitSize = 1 << 14
)

// SenderConfig sets a Sender. A zero field takes its default.
type SenderConfig struct {
	// MaxTracks caps the tracks sealed under one key; one more rotates. Default 1024, from 1 to 1000000.
	MaxTracks int
}

// Sender holds one sender's key for one media namespace and gives it to each member on the
// member's key track. Make one with NewSender. Its methods are safe for concurrent use; it prints
// redacted with fmt.
type Sender struct {
	origin    *kolomoq.Origin
	ns, keyNS kolomoq.Namespace
	maxTracks int
	maxUnits  uint64
	instance  [instanceSize]byte

	mu     sync.Mutex
	closed bool
	// key is an atomic.Pointer, which fmt prints as an address, so a copied Sender prints no key.
	key     atomic.Pointer[senderKey]
	kid     uint64
	nextKID uint64
	tracks  map[string]*sealState
	members map[string]*member
	changed chan struct{}
}

// senderKey holds a Sender's key material.
type senderKey struct {
	base [keySize]byte
	// next and msg hold a rotation's new key and key message; both are cleared after use.
	next [keySize]byte
	msg  []byte
}

type sealState struct {
	key   *trackKey
	units uint64
}

type member struct {
	pub ed25519.PublicKey
	w   *kolomoq.TrackWriter
}

// NewSender returns a Sender for the media namespace ns with a random instance ID and a
// random key of Key ID 0, and no members. Its key tracks are published on origin.
func NewSender(origin *kolomoq.Origin, ns kolomoq.Namespace, cfg *SenderConfig) (*Sender, error) {
	if origin == nil {
		return nil, fmt.Errorf("%w: nil origin", ErrInvalidConfig)
	}
	if err := checkKeyNamespace(ns); err != nil {
		return nil, err
	}
	var c SenderConfig
	if cfg != nil {
		c = *cfg
	}
	if c.MaxTracks == 0 {
		c.MaxTracks = defaultMaxTracks
	}
	if c.MaxTracks < 1 || c.MaxTracks > 1_000_000 {
		return nil, fmt.Errorf("%w: MaxTracks %d out of range [1, 1000000]", ErrInvalidConfig, c.MaxTracks)
	}
	s := &Sender{
		origin:    origin,
		ns:        slices.Clone(ns),
		keyNS:     KeyNamespace(ns),
		maxTracks: c.MaxTracks,
		maxUnits:  maxUnits,
		nextKID:   1,
		tracks:    map[string]*sealState{},
		members:   map[string]*member{},
		changed:   make(chan struct{}),
	}
	s.key.Store(&senderKey{})
	rand.Read(s.instance[:])
	rand.Read(s.key.Load().base[:])
	return s, nil
}

// Format prints no key material.
func (s *Sender) Format(f fmt.State, _ rune) { io.WriteString(f, "secobj.Sender{redacted}") }

// Namespace returns the media namespace.
func (s *Sender) Namespace() kolomoq.Namespace { return slices.Clone(s.ns) }

// usableLocked returns ErrInvalidConfig for a Sender not made by NewSender and kolomoq.ErrClosed
// after Close.
func (s *Sender) usableLocked() error {
	switch {
	case s.origin == nil:
		return fmt.Errorf("%w: Sender not made by NewSender", ErrInvalidConfig)
	case s.closed:
		return kolomoq.ErrClosed
	}
	return nil
}

// Changed returns a channel that is closed the next time the key changes.
func (s *Sender) Changed() <-chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.changed
}

// KeyID returns the Key ID of the current key.
func (s *Sender) KeyID() uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.kid
}

// Members returns the members that receive the key, in ascending order.
func (s *Sender) Members() []ed25519.PublicKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]ed25519.PublicKey, 0, len(s.members))
	for _, m := range s.members {
		out = append(out, slices.Clone(m.pub))
	}
	slices.SortFunc(out, func(a, b ed25519.PublicKey) int { return cmp.Compare(string(a), string(b)) })
	return out
}

// SetMembers sets who receives the key. When the set changes, the Sender rotates: the new key
// goes to every member's key track before it is used, and a removed member's track is closed.
// On error the members and the key do not change.
func (s *Sender) SetMembers(members []ed25519.PublicKey) error {
	want := make(map[string]ed25519.PublicKey, len(members))
	for _, m := range members {
		if len(m) != ed25519.PublicKeySize {
			return fmt.Errorf("%w: member key of %d bytes", ErrInvalidConfig, len(m))
		}
		want[KeyTrack(m)] = slices.Clone(m)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return err
	}
	changed := len(want) != len(s.members)
	next := make(map[string]*member, len(want))
	var added []*member
	for name, pub := range want {
		if m := s.members[name]; m != nil {
			next[name] = m
			continue
		}
		changed = true
		w, err := s.origin.CreateTrack(s.keyNS, name, &kolomoq.TrackOptions{Priority: 0, CacheGroups: 1, Readers: []ed25519.PublicKey{pub}})
		if err != nil {
			closeMembers(added)
			return err
		}
		m := &member{pub: pub, w: w}
		next[name], added = m, append(added, m)
	}
	if !changed {
		return nil
	}
	if err := s.rotateLocked(next); err != nil {
		closeMembers(added)
		return err
	}
	for name, m := range s.members {
		if next[name] == nil {
			m.w.Close()
		}
	}
	s.members = next
	return nil
}

func closeMembers(ms []*member) {
	for _, m := range ms {
		m.w.Close()
	}
}

// Rotate draws a new key, gives it to every member, then makes it current.
func (s *Sender) Rotate() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return err
	}
	return s.rotateLocked(s.members)
}

// rotateLocked writes the next key to every member before it replaces the current one, so
// key messages are queued before the first object sealed under the new Key ID. On error the
// current key stays and the Key ID drawn is not reused.
func (s *Sender) rotateLocked(members map[string]*member) error {
	key := s.key.Load()
	defer clear(key.next[:])
	rand.Read(key.next[:])
	kid := s.nextKID
	s.nextKID++
	m := keyMessage{instance: s.instance, kid: kid, ns: s.ns, base: key.next}
	defer m.erase()
	key.msg = appendKeyMessage(key.msg[:0], &m)
	defer clear(key.msg)
	for _, mb := range members {
		g, err := mb.w.NewGroup()
		if err != nil {
			return err
		}
		if _, err := g.WriteObject(key.msg); err != nil {
			return err
		}
	}
	for _, st := range s.tracks {
		st.key.erase()
	}
	clear(s.tracks)
	key.base, s.kid = key.next, kid
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}

// Seal protects one object of track under the current key and returns its payload and
// properties. A (group, object) not after the last one sealed for the track is refused.
// The Sender rotates first when the track is one more than MaxTracks or its key reached the
// usage limit.
func (s *Sender) Seal(track string, group, object uint64, priority uint8, payload []byte, private []kolomoq.Property) ([]byte, []kolomoq.Property, error) {
	return s.seal(track, group, object, priority, payload, private, false)
}

// Write seals the next object of g, a group of track, under the track's priority inside
// GroupWriter.WriteObjectFunc and publishes it. Objects of one track must be written in increasing
// (Group ID, Object ID) order: one that is not means the track was re-created, so the Sender
// rotates before sealing, and a rotation per object soon goes over the receivers' MaxKeyRate.
func (s *Sender) Write(g *kolomoq.GroupWriter, track string, payload []byte, private ...kolomoq.Property) (uint64, error) {
	group, priority := g.ID(), g.Priority()
	return g.WriteObjectFunc(func(id uint64) ([]byte, []kolomoq.Property, error) {
		return s.seal(track, group, id, priority, payload, private, true)
	})
}

func (s *Sender) seal(track string, group, object uint64, priority uint8, payload []byte, private []kolomoq.Property, rotateStale bool) ([]byte, []kolomoq.Property, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return nil, nil, err
	}
	if err := checkName(s.ns, track); err != nil {
		return nil, nil, err
	}
	units, err := sealUnits(payload, private)
	if err != nil {
		return nil, nil, err
	}
	st, err := s.trackLocked(track, units)
	if err != nil {
		return nil, nil, err
	}
	ct, props, err := st.key.seal(group, object, priority, payload, private)
	if err == ErrObjectID && rotateStale && object <= maxObjectID {
		if err := s.rotateLocked(s.members); err != nil {
			return nil, nil, err
		}
		if st, err = s.trackLocked(track, units); err != nil {
			return nil, nil, err
		}
		ct, props, err = st.key.seal(group, object, priority, payload, private)
	}
	if err != nil {
		return nil, nil, err
	}
	st.units += units
	return ct, props, nil
}

// trackLocked returns the seal state of track with room for units, rotating at the track
// cap and at the usage limit.
func (s *Sender) trackLocked(track string, units uint64) (*sealState, error) {
	if units > s.maxUnits {
		return nil, kolomoq.ErrObjectTooLarge
	}
	st := s.tracks[track]
	if st != nil && st.units+units <= s.maxUnits {
		return st, nil
	}
	if st != nil || len(s.tracks) >= s.maxTracks {
		if err := s.rotateLocked(s.members); err != nil {
			return nil, err
		}
	}
	k, err := newTrackKey(&s.key.Load().base, s.kid, s.ns, track)
	if err != nil {
		return nil, err
	}
	st = &sealState{key: k}
	s.tracks[track] = st
	return st, nil
}

// sealUnits returns the plaintext length of an object (length prefix, payload and private
// list) in units of unitSize, rounded up.
func sealUnits(payload []byte, private []kolomoq.Property) (uint64, error) {
	_, listLen, err := checkPrivate(private)
	if err != nil {
		return 0, err
	}
	if len(payload) > maxPayload-listLen {
		return 0, kolomoq.ErrObjectTooLarge
	}
	n := wire.VarintLen(uint64(len(payload))) + len(payload)
	if listLen > 0 {
		n += 2 + wire.VarintLen(uint64(listLen)) + listLen
	}
	return uint64(n+unitSize-1) / unitSize, nil
}

// Close closes the key tracks and erases the keys. Later calls fail with kolomoq.ErrClosed.
func (s *Sender) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.usableLocked(); err != nil {
		return err
	}
	s.closed = true
	for _, m := range s.members {
		m.w.Close()
	}
	s.members = nil
	for _, st := range s.tracks {
		st.key.erase()
	}
	s.tracks = nil
	clear(s.key.Load().base[:])
	return nil
}
