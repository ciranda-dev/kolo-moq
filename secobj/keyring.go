package secobj

import (
	"context"
	"crypto/ed25519"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"time"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

const (
	// defaultRetain is kolo-media's playout MaxDelay plus MaxBehind: later objects are dropped anyway.
	defaultRetain = 450 * time.Millisecond
	// defaultHold is kolo-media's playout MaxDelay, how long it holds an object whose key is in
	// flight: objects under a new key may trail its key message by that much.
	defaultHold = 400 * time.Millisecond
	// defaultMaxSenders and defaultMaxKeyRate follow kolo-swarm's MaxPeers of 64, each peer
	// changing at most once per second (its RetryMin).
	defaultMaxSenders = 64
	defaultMaxKeyRate = 64
	// maxTrackKeys caps the tracks with derived keys per namespace.
	maxTrackKeys = 1024
)

// KeyringConfig sets a Keyring. A zero field takes its default.
type KeyringConfig struct {
	// Authorize reports whether peer owns ns and may give its key. Required.
	Authorize func(peer ed25519.PublicKey, ns kolomoq.Namespace) error
	// Relays are the relay identities a protected watch may use besides a namespace's owner.
	Relays []ed25519.PublicKey
	// Retain is how long a replaced key still opens objects after the first object under its successor. Default 450ms, at most 1m.
	Retain time.Duration
	// RetainMax is how long a replaced key opens objects at most after its successor arrived, even if no object under the successor opens. Default Retain plus 400ms, from Retain to 2m.
	RetainMax time.Duration
	// MaxSenders caps the namespaces with keys. Default 64, from 1 to 1024.
	MaxSenders int
	// MaxKeyRate caps key messages per namespace per second; more are dropped. Default 64, from 1 to 1024.
	MaxKeyRate int
	// ReplayGroups and ReplayObjects bound the replay window per track. Defaults 64 and 8192, from 1 to 1000000.
	ReplayGroups  int
	ReplayObjects int
}

// KeyringStats counts the key messages a Keyring did not install.
type KeyringStats struct {
	// Rejected counts malformed key messages, ones naming another namespace and ones that change the key of a Key ID.
	Rejected uint64
	// Dropped counts key messages over MaxKeyRate.
	Dropped uint64
}

// Keyring holds the keys of the senders a participant receives, per media namespace: the
// current key and the one it replaced. Objects are opened through an Opener per reader, each with
// its own replay window. Make one with NewKeyring. Its methods are safe for concurrent use; it
// prints redacted with fmt.
type Keyring struct {
	authorize     func(ed25519.PublicKey, kolomoq.Namespace) error
	relays        []ed25519.PublicKey
	retain        time.Duration
	retainMax     time.Duration
	maxSenders    int
	maxKeyRate    int
	replayGroups  int
	replayObjects int
	now           func() time.Time

	mu      sync.Mutex
	senders map[string]*senderKeys
	changed chan struct{}
	stats   KeyringStats
	epochs  uint64
}

// senderKeys is the state of one media namespace.
type senderKeys struct {
	ns       kolomoq.Namespace
	instance [instanceSize]byte
	// epoch changes with the instance ID, so Openers reset their replay windows.
	epoch       uint64
	cur, prev   *generation
	tracks      map[string]uint64 // tracks with derived keys, by last use
	tick        uint64
	windowStart time.Time
	windowCount int
	receivers   map[*receiver]struct{}
	removed     bool
}

type receiver struct{ cancel context.CancelFunc }

// generation is one base key with its derived track keys.
type generation struct {
	kid     uint64
	base    [keySize]byte
	keys    map[string]*trackKey
	expires time.Time
	timer   *time.Timer
	// retaining is set once an object under the successor opened and Retain started.
	retaining bool
}

// NewKeyring returns an empty Keyring.
func NewKeyring(cfg KeyringConfig) (*Keyring, error) {
	if cfg.Authorize == nil {
		return nil, fmt.Errorf("%w: nil Authorize", ErrInvalidConfig)
	}
	for _, r := range cfg.Relays {
		if len(r) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("%w: relay key of %d bytes", ErrInvalidConfig, len(r))
		}
	}
	if cfg.Retain == 0 {
		cfg.Retain = defaultRetain
	}
	if cfg.Retain < 0 || cfg.Retain > time.Minute {
		return nil, fmt.Errorf("%w: Retain %v out of range (0, 1m0s]", ErrInvalidConfig, cfg.Retain)
	}
	if cfg.RetainMax == 0 {
		cfg.RetainMax = cfg.Retain + defaultHold
	}
	if cfg.RetainMax < cfg.Retain || cfg.RetainMax > 2*time.Minute {
		return nil, fmt.Errorf("%w: RetainMax %v out of range [%v, 2m0s]", ErrInvalidConfig, cfg.RetainMax, cfg.Retain)
	}
	for _, l := range []struct {
		name          string
		v             *int
		def, min, max int
	}{
		{"MaxSenders", &cfg.MaxSenders, defaultMaxSenders, 1, 1024},
		{"MaxKeyRate", &cfg.MaxKeyRate, defaultMaxKeyRate, 1, 1024},
		{"ReplayGroups", &cfg.ReplayGroups, defaultReplayGroups, 1, 1_000_000},
		{"ReplayObjects", &cfg.ReplayObjects, defaultReplayObjects, 1, 1_000_000},
	} {
		if *l.v == 0 {
			*l.v = l.def
		}
		if *l.v < l.min || *l.v > l.max {
			return nil, fmt.Errorf("%w: %s %d out of range [%d, %d]", ErrInvalidConfig, l.name, *l.v, l.min, l.max)
		}
	}
	relays := make([]ed25519.PublicKey, len(cfg.Relays))
	for i, r := range cfg.Relays {
		relays[i] = slices.Clone(r)
	}
	return &Keyring{
		authorize:     cfg.Authorize,
		relays:        relays,
		retain:        cfg.Retain,
		retainMax:     cfg.RetainMax,
		maxSenders:    cfg.MaxSenders,
		maxKeyRate:    cfg.MaxKeyRate,
		replayGroups:  cfg.ReplayGroups,
		replayObjects: cfg.ReplayObjects,
		now:           time.Now,
		senders:       map[string]*senderKeys{},
		changed:       make(chan struct{}),
	}, nil
}

// Format prints no key material.
func (k *Keyring) Format(f fmt.State, _ rune) { io.WriteString(f, "secobj.Keyring{redacted}") }

var errZeroKeyring = fmt.Errorf("%w: Keyring not made by NewKeyring", ErrInvalidConfig)

func nsKey(ns kolomoq.Namespace) string { return string(wire.AppendNamespace(nil, ns)) }

// Receive installs the keys that the peer of s gives for ns on the key track of self, until
// ctx ends, s ends, the peer ends the track (nil) or Remove(ns) is called. The peer is
// s.RemotePublicKey(); Receive fails with ErrUnauthorized unless Authorize says it owns ns.
// Until the peer makes self a member, the subscription is refused and Receive returns that
// error. Key messages that break the rules are counted in Stats and skipped.
func (k *Keyring) Receive(ctx context.Context, s *kolomoq.Session, self ed25519.PublicKey, ns kolomoq.Namespace) error {
	if k.authorize == nil {
		return errZeroKeyring
	}
	if s == nil || len(self) != ed25519.PublicKeySize {
		return fmt.Errorf("%w: nil session or self key of %d bytes", ErrInvalidConfig, len(self))
	}
	if err := checkKeyNamespace(ns); err != nil {
		return err
	}
	if k.authorize(s.RemotePublicKey(), ns) != nil {
		return ErrUnauthorized
	}
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	r := &receiver{cancel: cancel}
	e, err := k.join(ns, r)
	if err != nil {
		return err
	}
	defer k.leave(e, r)
	sub, err := s.Subscribe(ctx, KeyNamespace(ns), KeyTrack(self), &kolomoq.SubscribeOptions{Priority: 0, Join: kolomoq.JoinCurrentGroup})
	if err != nil {
		return err
	}
	defer sub.Close()
	for {
		obj, err := sub.ReadObject(ctx)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		if obj.Status == kolomoq.StatusNormal {
			k.deliver(e, obj.Payload)
		}
	}
}

// join registers a receiver of ns, creating its state within MaxSenders.
func (k *Keyring) join(ns kolomoq.Namespace, r *receiver) (*senderKeys, error) {
	key := nsKey(ns)
	k.mu.Lock()
	defer k.mu.Unlock()
	e := k.senders[key]
	if e == nil {
		if len(k.senders) >= k.maxSenders {
			return nil, ErrTooManySenders
		}
		e = &senderKeys{ns: slices.Clone(ns), tracks: map[string]uint64{}, receivers: map[*receiver]struct{}{}}
		k.senders[key] = e
	}
	e.receivers[r] = struct{}{}
	return e, nil
}

// leave unregisters r and drops the state of ns if it holds no key and no receiver.
func (k *Keyring) leave(e *senderKeys, r *receiver) {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(e.receivers, r)
	if !e.removed && e.cur == nil && len(e.receivers) == 0 {
		delete(k.senders, nsKey(e.ns))
	}
}

// deliver applies the rate cap, then parses and installs one key message, and clears payload.
func (k *Keyring) deliver(e *senderKeys, payload []byte) {
	defer clear(payload)
	k.mu.Lock()
	defer k.mu.Unlock()
	if e.removed {
		return
	}
	now := k.now()
	if now.Before(e.windowStart) || now.Sub(e.windowStart) >= time.Second {
		e.windowStart, e.windowCount = now, 0
	}
	if e.windowCount >= k.maxKeyRate {
		k.stats.Dropped++
		return
	}
	e.windowCount++
	m, err := parseKeyMessage(payload)
	defer m.erase()
	if err != nil || !slices.Equal(m.ns, e.ns) {
		k.stats.Rejected++
		return
	}
	k.install(e, &m)
}

// install applies the ordering rules: a new instance ID replaces every key, a higher Key ID
// becomes current, a lower one is ignored, and an equal one with another key is rejected.
func (k *Keyring) install(e *senderKeys, m *keyMessage) {
	switch {
	case e.cur == nil || m.instance != e.instance:
		e.eraseKeys()
		k.epochs++
		e.instance, e.epoch = m.instance, k.epochs
	case m.kid < e.cur.kid:
		return
	case m.kid == e.cur.kid:
		if subtle.ConstantTimeCompare(m.base[:], e.cur.base[:]) != 1 {
			k.stats.Rejected++
		}
		return
	default:
		if e.prev != nil {
			e.prev.erase()
		}
		p := e.cur
		p.expires = k.now().Add(k.retainMax)
		p.timer = time.AfterFunc(k.retainMax, func() { k.expire(e, p) })
		e.prev = p
	}
	e.cur = &generation{kid: m.kid, base: m.base, keys: map[string]*trackKey{}}
	close(k.changed)
	k.changed = make(chan struct{})
}

func (g *generation) erase() {
	if g.timer != nil {
		g.timer.Stop()
	}
	clear(g.base[:])
	for _, tk := range g.keys {
		tk.erase()
	}
	clear(g.keys)
}

func (e *senderKeys) eraseKeys() {
	for _, g := range []*generation{e.cur, e.prev} {
		if g != nil {
			g.erase()
		}
	}
	e.cur, e.prev = nil, nil
}

// Opener opens the objects of one track of a protected namespace for one reader, such as one
// subscription, with the reader's own replay window: each Opener opens an object at most once,
// whatever other Openers of the same Keyring opened. Its methods are safe for concurrent use.
type Opener struct {
	k      *Keyring
	key    string
	track  string
	epoch  uint64
	replay *replayWindow
}

// Opener returns an Opener for track under ns read on s. It fails with ErrWrongSession unless
// MayCarry(s, ns) is nil, so a member cannot serve another member's namespace on its own session.
func (k *Keyring) Opener(s *kolomoq.Session, ns kolomoq.Namespace, track string) (*Opener, error) {
	if err := k.MayCarry(s, ns); err != nil {
		return nil, err
	}
	return k.opener(ns, track)
}

func (k *Keyring) opener(ns kolomoq.Namespace, track string) (*Opener, error) {
	if err := checkName(ns, track); err != nil {
		return nil, err
	}
	return &Opener{k: k, key: nsKey(ns), track: track, replay: newReplayWindow(k.replayGroups, k.replayObjects)}, nil
}

// Open authenticates and decrypts an object with its sender's key and records it in the replay
// window. It fails with ErrNoKey for a Key ID newer than the keys held, ErrKeyRetired for an older
// one, and ErrReplay for an object this Opener opened before or one outside its window.
func (o *Opener) Open(obj kolomoq.Object) ([]byte, []kolomoq.Property, error) {
	if o == nil || o.k == nil {
		return nil, nil, fmt.Errorf("%w: Opener not made by Keyring.Opener", ErrInvalidConfig)
	}
	if obj.Status != kolomoq.StatusNormal {
		return nil, nil, ErrNotProtected
	}
	kid, _, err := keyID(obj.Properties)
	if err != nil {
		return nil, nil, err
	}
	k := o.k
	k.mu.Lock()
	defer k.mu.Unlock()
	e := k.senders[o.key]
	if e == nil || e.cur == nil || kid > e.cur.kid {
		return nil, nil, ErrNoKey
	}
	g := e.cur
	if kid != g.kid {
		if e.prev == nil || kid != e.prev.kid {
			return nil, nil, ErrKeyRetired
		}
		g = e.prev
		if !k.now().Before(g.expires) {
			g.erase()
			e.prev = nil
			return nil, nil, ErrKeyRetired
		}
	}
	if o.epoch != e.epoch {
		o.replay.reset()
		o.epoch = e.epoch
	}
	e.touch(o.track)
	tk := g.keys[o.track]
	if tk == nil {
		if tk, err = newTrackKey(&g.base, g.kid, e.ns, o.track); err != nil {
			return nil, nil, err
		}
		g.keys[o.track] = tk
	}
	payload, props, err := tk.open(obj)
	if err != nil {
		return nil, nil, err
	}
	if err := o.replay.check(kid, obj.Group, uint32(obj.ID)); err != nil {
		return nil, nil, err
	}
	if p := e.prev; g == e.cur && p != nil && !p.retaining {
		p.retaining = true
		if end := k.now().Add(k.retain); end.Before(p.expires) {
			p.expires = end
			p.timer.Reset(k.retain)
		}
	}
	return payload, props, nil
}

// touch marks a track's derived keys as used, dropping those of the least recently used track
// beyond maxTrackKeys.
func (e *senderKeys) touch(name string) {
	if _, ok := e.tracks[name]; !ok && len(e.tracks) >= maxTrackKeys {
		e.evict()
	}
	e.tick++
	e.tracks[name] = e.tick
}

func (e *senderKeys) evict() {
	var oldest string
	var used uint64
	first := true
	for name, u := range e.tracks {
		if first || u < used {
			oldest, used, first = name, u, false
		}
	}
	delete(e.tracks, oldest)
	for _, g := range []*generation{e.cur, e.prev} {
		if g != nil && g.keys[oldest] != nil {
			g.keys[oldest].erase()
			delete(g.keys, oldest)
		}
	}
}

func (k *Keyring) expire(e *senderKeys, g *generation) {
	k.mu.Lock()
	defer k.mu.Unlock()
	if e.prev == g {
		g.erase()
		e.prev = nil
	}
}

// MayCarry reports whether s may carry the protected namespace ns: its peer owns ns or is a
// listed relay. Otherwise it returns ErrWrongSession.
func (k *Keyring) MayCarry(s *kolomoq.Session, ns kolomoq.Namespace) error {
	if k.authorize == nil {
		return errZeroKeyring
	}
	if s == nil {
		return ErrWrongSession
	}
	peer := s.RemotePublicKey()
	if k.authorize(peer, ns) == nil {
		return nil
	}
	for _, r := range k.relays {
		if r.Equal(peer) {
			return nil
		}
	}
	return ErrWrongSession
}

// Changed returns a channel that is closed the next time a key is installed.
func (k *Keyring) Changed() <-chan struct{} {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.changed
}

// Remove erases the keys of ns and ends its Receive calls.
func (k *Keyring) Remove(ns kolomoq.Namespace) {
	key := nsKey(ns)
	k.mu.Lock()
	defer k.mu.Unlock()
	e := k.senders[key]
	if e == nil {
		return
	}
	delete(k.senders, key)
	e.removed = true
	e.eraseKeys()
	clear(e.tracks)
	for r := range e.receivers {
		r.cancel()
	}
}

// Stats returns the key message counters.
func (k *Keyring) Stats() KeyringStats {
	k.mu.Lock()
	defer k.mu.Unlock()
	return k.stats
}
