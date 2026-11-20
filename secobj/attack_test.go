// A relay can still drop, delay, reorder and withhold objects and analyse traffic (sizes, timing, names, IDs); a member who controls the relay can impersonate any other member, as objects carry no per-object signatures.

package secobj

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

var bigBuffers = &kolomoq.Config{MaxBufferedGroups: 1000}

// keyedPair is alice publishing to the room relay and bob subscribed to her audio through it,
// with alice's key delivered to bob on their pairwise session.
func keyedPair(t *testing.T, aliceTap, bobTap *tap) (rm *room, alice, bob *party, sub *kolomoq.Subscription) {
	t.Helper()
	rm = newRoom(t)
	alice = newParty(t, rm, aliceTap, bigBuffers)
	bob = newParty(t, rm, bobTap, bigBuffers)
	if err := alice.sender.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bob.keysFrom(t, alice)
	waitKID(t, bob.keys, alice.ns, alice.sender.KeyID())
	alice.track(t, "audio", 48)
	sub = bob.subscribe(t, alice, "audio", nil)
	return rm, alice, bob, sub
}

// profileKeys derives a track key and salt with the formulas of the secobj profile, independently of
// the package code.
func profileKeys(t testing.TB, base [keySize]byte, ns kolomoq.Namespace, track string, kid uint64) (key, salt []byte) {
	t.Helper()
	secret, err := hkdf.Extract(sha256.New, base[:], nil)
	if err != nil {
		t.Fatal(err)
	}
	ftn := wire.AppendVarint(nil, uint64(len(ns)))
	for _, f := range ns {
		ftn = append(wire.AppendVarint(ftn, uint64(len(f))), f...)
	}
	ftn = append(wire.AppendVarint(ftn, uint64(len(track))), track...)
	suffix := binary.BigEndian.AppendUint64(binary.BigEndian.AppendUint16(slices.Clone(ftn), 0x0004), kid)
	if key, err = hkdf.Expand(sha256.New, secret, "MOQ 1.0 Secure Objects Secret key "+string(suffix), 16); err != nil {
		t.Fatal(err)
	}
	if salt, err = hkdf.Expand(sha256.New, secret, "MOQ 1.0 Secret salt "+string(suffix), 12); err != nil {
		t.Fatal(err)
	}
	return key, salt
}

// profileOpen decrypts an object exactly as the secobj profile specifies, with no package code.
func profileOpen(t testing.TB, key, salt []byte, o *wire.Object) []byte {
	t.Helper()
	nonce := slices.Clone(salt)
	ctr := binary.BigEndian.AppendUint32(binary.BigEndian.AppendUint64(nil, o.Group), uint32(o.ID))
	for i := range ctr {
		nonce[i] ^= ctr[i]
	}
	if len(o.Properties) != 1 || o.Properties[0].Type != 0x0B {
		t.Fatalf("visible properties %+v", o.Properties)
	}
	aad := append(slices.Clone(ctr), o.Priority)
	aad = append(aad, o.Properties[0].Bytes...)
	block, err := aes.NewCipher(key)
	if err != nil {
		t.Fatal(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		t.Fatal(err)
	}
	pt, err := gcm.Open(nil, nonce, o.Payload, aad)
	if err != nil {
		t.Fatalf("object %d/%d does not open with the profile formulas: %v", o.Group, o.ID, err)
	}
	return pt
}

func randomHex(t testing.TB) string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}

func senderBase(s *Sender) [keySize]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.key.Load().base
}

// TestRelayObservation records every byte a real Relay sends and receives for a publisher and a
// subscriber and checks what it sees: names, IDs, priority, Key ID, sizes and timing, and no
// plaintext, no private property, no key and no key track. It also checks that the Relay
// forwards priority, the 0x0B bytes and payloads unchanged on a subscription and on FETCH.
func TestRelayObservation(t *testing.T) {
	ta, tb := newTap(t), newTap(t)
	_, alice, bob, sub := keyedPair(t, ta, tb)
	marker := randomHex(t)
	private := kolomoq.Property{Type: 0x21, Bytes: []byte("private " + marker)}
	type sent struct {
		loc kolomoq.Location
		pt  string
	}
	var all []sent
	for g := range 3 {
		for o := range 3 {
			pt := fmt.Sprintf("voice %d %d %s", g, o, marker)
			all = append(all, sent{alice.write(t, "audio", o == 0, []byte(pt), private), pt})
		}
	}
	want := map[kolomoq.Location]string{}
	for _, s := range all {
		want[s.loc] = s.pt
	}
	for range all {
		o := nextNormal(t, sub)
		pt, props, err := openAt(bob.keys, alice.ns, "audio", o)
		if err != nil {
			t.Fatal(err)
		}
		if string(pt) != want[kolomoq.Location{Group: o.Group, Object: o.ID}] || len(props) != 1 || !bytes.Equal(props[0].Bytes, private.Bytes) {
			t.Fatalf("opened %q %+v at %d/%d", pt, props, o.Group, o.ID)
		}
	}
	ctx := testCtx(t)
	f, err := bob.relay.Fetch(ctx, alice.ns, "audio", &kolomoq.FetchOptions{RecentGroups: 3})
	if err != nil {
		t.Fatal(err)
	}
	fetched := 0
	for {
		o, err := f.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if o.Status != kolomoq.StatusNormal {
			continue
		}
		fetched++
		if _, _, err := openAt(bob.keys, alice.ns, "audio", o); err != ErrReplay {
			t.Fatalf("fetched duplicate of %d/%d: %v", o.Group, o.ID, err)
		}
	}
	if fetched != len(all) {
		t.Fatalf("fetched %d objects", fetched)
	}

	audio := refOf(alice.ns, "audio")
	up := ta.seenObjects(false, audio)
	down := tb.seenObjects(true, audio)
	if len(up) != len(all) || len(down) != 2*len(all) {
		t.Fatalf("relay received %d and sent %d objects", len(up), len(down))
	}
	base := senderBase(alice.sender)
	key, salt := profileKeys(t, base, alice.ns, "audio", 1)
	imm := wire.AppendVarint([]byte{PropertyKeyID}, 1)
	sentBy := map[kolomoq.Location]wire.Object{}
	for _, s := range up {
		o := s.obj
		loc := kolomoq.Location{Group: o.Group, Object: o.ID}
		pt := want[loc]
		ptLen := wire.VarintLen(uint64(len(pt))) + len(pt) + 2 + 1 + 2 + len(private.Bytes)
		// Exactly what the relay learns of each object.
		if o.Priority != 48 || len(o.Properties) != 1 || o.Properties[0].Type != 0x0B || !bytes.Equal(o.Properties[0].Bytes, imm) || len(o.Payload) != ptLen+tagSize {
			t.Fatalf("relay saw %d/%d priority %d properties %+v and %d payload bytes", o.Group, o.ID, o.Priority, o.Properties, len(o.Payload))
		}
		got, props, err := parsePlaintext(profileOpen(t, key, salt, &o))
		if err != nil || string(got) != pt || len(props) != 1 {
			t.Fatalf("profile decryption of %d/%d: %q %v", o.Group, o.ID, got, err)
		}
		sentBy[loc] = o
	}
	for _, s := range down {
		o := s.obj
		orig, ok := sentBy[kolomoq.Location{Group: o.Group, Object: o.ID}]
		if !ok || o.Priority != orig.Priority || !slices.EqualFunc(o.Properties, orig.Properties, kvEqual) || !bytes.Equal(o.Payload, orig.Payload) {
			t.Fatalf("relay changed %d/%d (fetch %v)", o.Group, o.ID, s.fetch)
		}
	}
	for _, s := range up {
		if s.at.IsZero() {
			t.Fatal("no arrival time")
		}
	}

	names := map[string]bool{}
	for _, tp := range []*tap{ta, tb} {
		tp.mu.Lock()
		for _, m := range tp.requests {
			if !kolomoq.Namespace(m.Namespace).HasPrefix(roomNS) {
				t.Errorf("request 0x%x outside the room: %q", m.Type, m.Namespace)
			}
			names[fmt.Sprintf("%x %s %s", m.Type, kolomoq.Namespace(m.Namespace)[1:], m.Name)] = true
		}
		tp.mu.Unlock()
	}
	allowed := map[string]bool{
		fmt.Sprintf("%x [%s] ", wire.MsgPublishNamespace, hexKey(alice.pub)): true,
		fmt.Sprintf("%x [%s] ", wire.MsgPublishNamespace, hexKey(bob.pub)):   true,
		fmt.Sprintf("%x [%s] audio", wire.MsgSubscribe, hexKey(alice.pub)):   true,
		fmt.Sprintf("%x [%s] audio", wire.MsgFetch, hexKey(alice.pub)):       true,
	}
	for n := range names {
		if !allowed[n] {
			t.Errorf("relay saw request %s", n)
		}
	}
	for n := range allowed {
		if !names[n] {
			t.Errorf("relay did not see request %s", n)
		}
	}

	rec := append(ta.recorded(), tb.recorded()...)
	for _, s := range up {
		if !bytes.Contains(rec, s.obj.Payload) {
			t.Fatal("recording misses a ciphertext")
		}
	}
	secrets := map[string][]byte{"base key": base[:], "track key": key, "salt": salt, "marker": []byte(marker), "key namespace field": []byte(kolomoq.KeyNamespaceField)}
	for _, s := range all {
		secrets["plaintext "+s.pt] = []byte(s.pt)
	}
	bob.keys.mu.Lock()
	secrets["receiver key"] = slices.Clone(bob.keys.senders[nsKey(alice.ns)].cur.base[:])
	bob.keys.mu.Unlock()
	for name, b := range secrets {
		if bytes.Contains(rec, b) {
			t.Errorf("relay handled the %s", name)
		}
	}
}

func kvEqual(a, b wire.KV) bool {
	return a.Type == b.Type && a.Value == b.Value && bytes.Equal(a.Bytes, b.Bytes)
}

// objectKey identifies an object by every field a relay can change.
func objectKey(o kolomoq.Object) string {
	var b []byte
	b = fmt.Appendf(b, "%d/%d/%d/%d|", o.Group, o.ID, o.Priority, o.Status)
	for _, p := range o.Properties {
		b = fmt.Appendf(b, "%x=%d:%x;", p.Type, p.Value, p.Bytes)
	}
	return string(fmt.Appendf(b, "|%x", o.Payload))
}

// expectKeyID is the error Open gives an object whose 0x0B value is imm, with Key ID 1 current
// and no previous key.
func expectKeyID(imm []byte) error {
	if len(imm) < 2 || imm[0] != PropertyKeyID {
		return ErrMalformed
	}
	kid, rest, ok := readVarint(imm[1:])
	switch {
	case !ok || len(rest) != 0:
		return ErrMalformed
	case kid > 1:
		return ErrNoKey
	case kid < 1:
		return ErrKeyRetired
	}
	return ErrAuthentication
}

// TestRelayTampering lets the relay deliver, next to an honest object, a copy with each bit of
// the payload and of the Key ID property flipped, every Group ID, Object ID and priority bit
// flipped, the Key ID replaced, the protection stripped and the payload cut or extended. Only
// the honest object opens.
func TestRelayTampering(t *testing.T) {
	type variant struct {
		o    *wire.Object
		want error
	}
	var variants []variant
	var mu sync.Mutex
	tb := newTap(t)
	tb.hook = func(tr trackRef, o *wire.Object) []*wire.Object {
		mu.Lock()
		defer mu.Unlock()
		if o.Status != wire.StatusNormal || variants != nil {
			return []*wire.Object{o}
		}
		seen := map[string]bool{objectKey(fromWire(o)): true}
		add := func(want error, change func(v *wire.Object)) {
			v := cloneWire(o)
			change(v)
			if wire.CheckObjectProperties(v.Properties) != nil {
				// kolo-moq ends the subscription as a malformed track; TestRelayMalformedKeyID.
				return
			}
			if k := objectKey(fromWire(v)); !seen[k] {
				seen[k] = true
				variants = append(variants, variant{v, want})
			}
		}
		for i := range len(o.Payload) * 8 {
			add(ErrAuthentication, func(v *wire.Object) { v.Payload[i/8] ^= 1 << (i % 8) })
		}
		for n := range len(o.Payload) {
			add(ErrAuthentication, func(v *wire.Object) { v.Payload = v.Payload[:n] })
		}
		add(ErrAuthentication, func(v *wire.Object) { v.Payload = append(v.Payload, 0) })
		imm := o.Properties[0].Bytes
		for i := range len(imm) * 8 {
			m := slices.Clone(imm)
			m[i/8] ^= 1 << (i % 8)
			add(expectKeyID(m), func(v *wire.Object) { v.Properties[0].Bytes = m })
		}
		for b := range 64 {
			add(ErrAuthentication, func(v *wire.Object) { v.Group ^= 1 << b })
		}
		for b := range 32 {
			add(ErrAuthentication, func(v *wire.Object) { v.ID ^= 1 << b })
		}
		add(ErrObjectID, func(v *wire.Object) { v.ID = 1 << 32 })
		add(ErrObjectID, func(v *wire.Object) { v.ID = 1<<62 + 7 })
		for b := range 8 {
			add(ErrAuthentication, func(v *wire.Object) { v.Priority ^= 1 << b })
		}
		for _, p := range [][]byte{
			{PropertyKeyID, 2},
			{PropertyKeyID, 0},
			{PropertyKeyID, 0x80, 0x01},
			{0x02, 0x01},
			{PropertyKeyID, 0x01, 0x02, 0x05},
			{},
			wire.AppendVarint([]byte{PropertyKeyID}, 1<<64-1),
		} {
			add(expectKeyID(p), func(v *wire.Object) { v.Properties[0].Bytes = p })
		}
		add(ErrNotProtected, func(v *wire.Object) { v.Properties = nil })
		add(ErrNotProtected, func(v *wire.Object) { v.Properties[0].Type = 0x0D })
		add(ErrNotProtected, func(v *wire.Object) { v.Properties, v.Payload = nil, []byte("hello") })
		add(ErrAuthentication, func(v *wire.Object) { v.Payload = []byte("hello, not sealed but long enough") })
		out := []*wire.Object{o}
		for _, v := range variants {
			out = append(out, v.o)
		}
		return out
	}
	_, alice, bob, sub := keyedPair(t, nil, tb)
	alice.write(t, "audio", true, []byte("hello"))
	eventually(t, "variants", func() bool {
		mu.Lock()
		defer mu.Unlock()
		return variants != nil
	})
	mu.Lock()
	want := map[string]error{}
	for _, v := range variants {
		want[objectKey(fromWire(v.o))] = v.want
	}
	mu.Unlock()
	opened := 0
	counts := map[error]int{}
	for range len(want) + 1 {
		o := nextNormal(t, sub)
		pt, _, err := openAt(bob.keys, alice.ns, "audio", o)
		if err == nil {
			opened++
			if string(pt) != "hello" {
				t.Fatalf("opened %q", pt)
			}
			continue
		}
		counts[err]++
		w, ok := want[objectKey(o)]
		if !ok {
			t.Fatalf("unknown object %d/%d failed with %v", o.Group, o.ID, err)
		}
		if err != w {
			t.Errorf("variant %s: got %v, want %v", objectKey(o), err, w)
		}
	}
	if opened != 1 {
		t.Fatalf("%d objects opened", opened)
	}
	t.Logf("%d tampered objects refused: %v", len(want), counts)
}

// TestRelayMalformedKeyID shows that a Key ID property the relay makes unparsable, or a second
// one, never reaches Open: kolo-moq ends the subscription as a malformed track.
func TestRelayMalformedKeyID(t *testing.T) {
	tb := newTap(t)
	_, alice, bob, sub := keyedPair(t, nil, tb)
	for name, props := range map[string][]wire.KV{
		"odd type":         {{Type: 0x0B, Bytes: []byte{PropertyKeyID + 1, 0x01}}},
		"truncated varint": {{Type: 0x0B, Bytes: []byte{PropertyKeyID, 0x81}}},
		"nested 0x0B":      {{Type: 0x0B, Bytes: []byte{0x0B, 0x01, 0x00}}},
	} {
		alias := tb.alias(alice.ns, "audio")
		tb.emit(alias, &wire.Object{Group: 9, ID: 0, Priority: 48, Properties: props, Payload: make([]byte, 40)})
		ctx := testCtx(t)
		for {
			o, err := sub.ReadObject(ctx)
			if err != nil {
				if !errors.Is(err, kolomoq.ErrMalformedTrack) {
					t.Fatalf("%s: %v", name, err)
				}
				break
			}
			t.Fatalf("%s: delivered %d/%d", name, o.Group, o.ID)
		}
		sub = bob.subscribe(t, alice, "audio", nil)
	}
	alice.write(t, "audio", true, []byte("after"))
	mustOpen(t, bob.keys, alice.ns, "audio", nextNormal(t, sub), "after")
}

// stageHook returns a tap hook that runs the current stage, or forwards objects unchanged.
func stageHook(stage *atomic.Pointer[func(*wire.Object) []*wire.Object]) func(trackRef, *wire.Object) []*wire.Object {
	return func(_ trackRef, o *wire.Object) []*wire.Object {
		if f := stage.Load(); f != nil && o.Status == wire.StatusNormal {
			return (*f)(o)
		}
		return []*wire.Object{o}
	}
}

func setStage(stage *atomic.Pointer[func(*wire.Object) []*wire.Object], f func(*wire.Object) []*wire.Object) {
	if f == nil {
		stage.Store(nil)
		return
	}
	stage.Store(&f)
}

// TestRelayReplayReorderDrop replays objects in the same and in another group, late within the
// window and beyond it, through FETCH and after the key that sealed them retired; it also
// reorders and drops objects.
func TestRelayReplayReorderDrop(t *testing.T) {
	var stage atomic.Pointer[func(*wire.Object) []*wire.Object]
	tb := newTap(t)
	// Every stage change waits until the tap has passed each object written so far: groups travel on
	// separate streams, so a late stream would otherwise meet the next stage.
	var hooked atomic.Int64
	inner := stageHook(&stage)
	tb.hook = func(r trackRef, o *wire.Object) []*wire.Object {
		out := inner(r, o)
		if o.Status == wire.StatusNormal {
			hooked.Add(1)
		}
		return out
	}
	rm := newRoom(t)
	alice := newParty(t, rm, nil, bigBuffers)
	written := 0
	write := func(first bool, payload []byte) {
		alice.write(t, "audio", first, payload)
		written++
	}
	settle := func() {
		eventually(t, "the tap to pass every object written", func() bool { return hooked.Load() == int64(written) })
	}
	bob := newParty(t, rm, tb, bigBuffers)
	bob.keys = newKeyring(t, KeyringConfig{Retain: 50 * time.Millisecond})
	if err := alice.sender.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bob.keysFrom(t, alice)
	waitKID(t, bob.keys, alice.ns, 1)
	alice.track(t, "audio", 48)
	sub := bob.subscribe(t, alice, "audio", nil)
	open := func(n int) ([]string, map[error]int) { return openAll(t, bob.keys, alice.ns, "audio", sub, n) }
	alias := tb.alias(alice.ns, "audio")

	var mu sync.Mutex
	withheld := map[uint64]*wire.Object{}
	setStage(&stage, func(o *wire.Object) []*wire.Object {
		mu.Lock()
		defer mu.Unlock()
		switch o.ID {
		case 0:
			moved := cloneWire(o)
			moved.Group = 5
			return []*wire.Object{o, cloneWire(o), moved}
		case 1, 3:
			withheld[o.ID] = cloneWire(o)
			return nil
		}
		return []*wire.Object{o}
	})
	for i := range 4 {
		write(i == 0, fmt.Appendf(nil, "g0 o%d", i))
	}
	opened, errs := open(4)
	if !slices.Equal(sortedStrings(opened), []string{"g0 o0", "g0 o2"}) || errs[ErrReplay] != 1 || errs[ErrAuthentication] != 1 {
		t.Fatalf("group 0: opened %q, errors %v", opened, errs)
	}

	settle()
	setStage(&stage, nil)
	for g := 1; g <= 3; g++ {
		write(true, fmt.Appendf(nil, "g%d", g))
	}
	if opened, errs := open(3); len(opened) != 3 || len(errs) != 0 {
		t.Fatalf("groups 1 to 3: %q %v", opened, errs)
	}
	tb.emit(alias, withheld[1])
	if opened, errs := open(1); !slices.Equal(opened, []string{"g0 o1"}) {
		t.Fatalf("late object within the window: %q %v", opened, errs)
	}
	// One group at a time: a burst reordered by more than ReplayGroups would be refused.
	for g := 4; g <= 70; g++ {
		write(true, fmt.Appendf(nil, "g%d", g))
		if opened, errs := open(1); len(opened) != 1 {
			t.Fatalf("group %d: %v", g, errs)
		}
	}
	tb.emit(alias, withheld[3])
	if _, errs := open(1); errs[ErrReplay] != 1 {
		t.Fatalf("unseen object 64 groups behind: %v", errs)
	}

	ctx := testCtx(t)
	f, err := bob.relay.Fetch(ctx, alice.ns, "audio", &kolomoq.FetchOptions{RecentGroups: 3})
	if err != nil {
		t.Fatal(err)
	}
	dups := 0
	for {
		o, err := f.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		if o.Status != kolomoq.StatusNormal {
			continue
		}
		dups++
		if _, _, err := openAt(bob.keys, alice.ns, "audio", o); err != ErrReplay {
			t.Fatalf("fetched duplicate %d/%d: %v", o.Group, o.ID, err)
		}
	}
	if dups != 3 {
		t.Fatalf("%d fetched duplicates", dups)
	}

	var held []*wire.Object
	settle()
	setStage(&stage, func(o *wire.Object) []*wire.Object {
		mu.Lock()
		defer mu.Unlock()
		held = append(held, o)
		if len(held) < 10 {
			return nil
		}
		out := slices.Clone(held)
		slices.Reverse(out)
		return out
	})
	var want []string
	for g := 71; g <= 80; g++ {
		want = append(want, fmt.Sprintf("g%d", g))
		write(true, []byte(want[len(want)-1]))
	}
	if opened, errs := open(10); !slices.Equal(sortedStrings(opened), sortedStrings(want)) || len(errs) != 0 {
		t.Fatalf("reordered groups: %q %v", opened, errs)
	}

	dropped := map[uint64]*wire.Object{}
	settle()
	setStage(&stage, func(o *wire.Object) []*wire.Object {
		if o.Group%2 == 1 {
			mu.Lock()
			dropped[o.Group] = cloneWire(o)
			mu.Unlock()
			return nil
		}
		return []*wire.Object{o}
	})
	for g := 81; g <= 90; g++ {
		write(true, fmt.Appendf(nil, "g%d", g))
	}
	if opened, errs := open(5); len(opened) != 5 || len(errs) != 0 {
		t.Fatalf("with odd groups dropped: %q %v", opened, errs)
	}

	settle()
	setStage(&stage, func(o *wire.Object) []*wire.Object {
		if o.ID == 1 {
			mu.Lock()
			dropped[o.Group] = cloneWire(o)
			mu.Unlock()
			return nil
		}
		return []*wire.Object{o}
	})
	if err := alice.sender.Rotate(); err != nil {
		t.Fatal(err)
	}
	write(true, []byte("g91"))
	write(false, []byte("g91 o1"))
	openWhenKeyed(t, bob.keys, alice.ns, "audio", nextNormal(t, sub), "g91")
	bob.keys.mu.Lock()
	e := bob.keys.senders[nsKey(alice.ns)]
	bob.keys.mu.Unlock()
	eventually(t, "retired key erased by its timer", func() bool { _, prev := keyState(bob.keys, e); return prev == -1 })
	mu.Lock()
	old := dropped[89]
	mu.Unlock()
	tb.emit(alias, old)
	if _, errs := open(1); errs[ErrKeyRetired] != 1 {
		t.Fatalf("unseen object of the retired key: %v", errs)
	}

	// Retain counts on the keyring's clock even before the erasing timer fires.
	clock := &fakeClock{t: time.Now()}
	bob.keys.mu.Lock()
	bob.keys.retain, bob.keys.now = time.Minute, clock.now
	bob.keys.mu.Unlock()
	settle()
	setStage(&stage, nil)
	if err := alice.sender.Rotate(); err != nil {
		t.Fatal(err)
	}
	write(true, []byte("g92"))
	openWhenKeyed(t, bob.keys, alice.ns, "audio", nextNormal(t, sub), "g92")
	clock.add(2 * time.Minute)
	mu.Lock()
	old = dropped[91]
	mu.Unlock()
	tb.emit(alias, old)
	if _, errs := open(1); errs[ErrKeyRetired] != 1 {
		t.Fatalf("unseen object of a key past Retain: %v", errs)
	}
}

func sortedStrings(s []string) []string {
	s = slices.Clone(s)
	slices.Sort(s)
	return s
}

// TestRelaySwaps moves an authentic object to another track of its sender, to another sender's
// track and to the same sender's track in another room.
func TestRelaySwaps(t *testing.T) {
	room2 := kolomoq.Namespace{"room2"}
	rm := newRoom(t, roomNS, room2)
	tb := newTap(t)
	alice := newParty(t, rm, nil, nil)
	dave := newParty(t, rm, nil, nil)
	bob := newParty(t, rm, tb, nil)
	bob.keys = newKeyring(t, KeyringConfig{Authorize: func(peer ed25519.PublicKey, ns kolomoq.Namespace) error {
		if slices.Equal(ns, mediaNS(peer)) || slices.Equal(ns, kolomoq.Namespace{"room2", hexKey(peer)}) {
			return nil
		}
		return errors.New("not the owner")
	}})
	ctx := testCtx(t)
	other := &party{node: alice.node, ns: kolomoq.Namespace{"room2", hexKey(alice.pub)}, tracks: map[string]*kolomoq.TrackWriter{}, groups: map[string]*kolomoq.GroupWriter{}}
	var err error
	if other.sender, err = NewSender(alice.origin, other.ns, nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { other.sender.Close() })
	if _, err := alice.relay.PublishNamespace(ctx, other.ns); err != nil {
		t.Fatal(err)
	}
	for _, p := range []*party{alice, dave, other} {
		if err := p.sender.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
			t.Fatal(err)
		}
		bob.keysFrom(t, p)
		waitKID(t, bob.keys, p.ns, 1)
		p.track(t, "audio", 48)
	}
	alice.track(t, "video", 48)
	subs := map[string]*kolomoq.Subscription{
		"alice audio": bob.subscribe(t, alice, "audio", nil),
		"alice video": bob.subscribe(t, alice, "video", nil),
		"dave audio":  bob.subscribe(t, dave, "audio", nil),
		"room2 audio": bob.subscribe(t, other, "audio", nil),
	}
	alice.write(t, "audio", true, []byte("alice speaking"))
	mustOpen(t, bob.keys, alice.ns, "audio", nextNormal(t, subs["alice audio"]), "alice speaking")
	got := tb.seenObjects(true, refOf(alice.ns, "audio"))
	if len(got) != 1 {
		t.Fatalf("%d objects seen", len(got))
	}
	for name, to := range map[string]struct {
		p     *party
		track string
	}{
		"alice video": {alice, "video"},
		"dave audio":  {dave, "audio"},
		"room2 audio": {other, "audio"},
	} {
		tb.emit(tb.alias(to.p.ns, to.track), cloneWire(&got[0].obj))
		o := nextNormal(t, subs[name])
		if _, _, err := openAt(bob.keys, to.p.ns, to.track, o); err != ErrAuthentication {
			t.Errorf("moved to %s: %v", name, err)
		}
	}
}

// TestRelayForgedFlood injects 100,000 objects with a valid-looking header and the current Key
// ID: none opens, each is counted, and the track keeps working.
func TestRelayForgedFlood(t *testing.T) {
	const groups, perGroup = 100, 1000
	tb := newTap(t)
	_, alice, bob, sub := keyedPair(t, nil, tb)
	alice.write(t, "audio", true, []byte("before"))
	mustOpen(t, bob.keys, alice.ns, "audio", nextNormal(t, sub), "before")
	alias := tb.alias(alice.ns, "audio")
	go func() {
		payload := make([]byte, 32)
		for g := range groups {
			objs := make([]*wire.Object, perGroup)
			for i := range objs {
				rand.Read(payload)
				objs[i] = &wire.Object{Group: 1000 + uint64(g), ID: uint64(i), Priority: 48, Properties: keyIDProps(1), Payload: slices.Clone(payload)}
			}
			tb.emit(alias, objs...)
		}
	}()
	refused := 0
	for range groups * perGroup {
		o := nextNormal(t, sub)
		if _, _, err := openAt(bob.keys, alice.ns, "audio", o); err != ErrAuthentication {
			t.Fatalf("forged %d/%d: %v", o.Group, o.ID, err)
		}
		refused++
	}
	if refused != groups*perGroup || sub.Dropped() != 0 || tb.injected.Load() != groups*perGroup {
		t.Fatalf("refused %d, dropped groups %d, injected %d", refused, sub.Dropped(), tb.injected.Load())
	}
	alice.write(t, "audio", true, []byte("after"))
	mustOpen(t, bob.keys, alice.ns, "audio", nextNormal(t, sub), "after")
}

// TestRelayDowngrade strips the protection, serves unprotected objects and a false End of Track,
// and adds visible and track properties: a receiver with keys refuses or ignores all of it.
func TestRelayDowngrade(t *testing.T) {
	var stage atomic.Pointer[func(*wire.Object) []*wire.Object]
	tb := newTap(t)
	tb.hook = stageHook(&stage)
	tb.trackProps = []wire.KV{{Type: 0x10, Value: 999}}
	_, alice, bob, sub := keyedPair(t, nil, tb)
	if !slices.ContainsFunc(sub.Properties(), func(p kolomoq.Property) bool { return p.Type == 0x10 && p.Value == 999 }) {
		t.Fatalf("track properties %+v", sub.Properties())
	}
	stamp := kolomoq.Property{Type: 0x10, Value: 1234}

	setStage(&stage, func(o *wire.Object) []*wire.Object {
		strip := cloneWire(o)
		strip.Properties = nil
		plain := &wire.Object{Group: o.Group, ID: o.ID + 1, Priority: o.Priority, Payload: []byte("unprotected audio")}
		return []*wire.Object{strip, plain}
	})
	alice.write(t, "audio", true, []byte("protected"), stamp)
	for range 2 {
		o := nextNormal(t, sub)
		if pt, _, err := openAt(bob.keys, alice.ns, "audio", o); err != ErrNotProtected || pt != nil {
			t.Fatalf("unprotected object: %q %v", pt, err)
		}
	}

	setStage(&stage, func(o *wire.Object) []*wire.Object {
		v := cloneWire(o)
		v.Properties = append(v.Properties, wire.KV{Type: 0x02, Value: 1}, wire.KV{Type: 0x10, Value: 999})
		return []*wire.Object{v}
	})
	alice.write(t, "audio", true, []byte("voice"), stamp)
	o := nextNormal(t, sub)
	if len(o.Properties) != 3 {
		t.Fatalf("visible properties %+v", o.Properties)
	}
	pt, props, err := openAt(bob.keys, alice.ns, "audio", o)
	if err != nil || string(pt) != "voice" || len(props) != 1 || props[0].Type != stamp.Type || props[0].Value != stamp.Value {
		t.Fatalf("with relay properties: %q %+v %v", pt, props, err)
	}

	setStage(&stage, nil)
	tb.emit(tb.alias(alice.ns, "audio"), &wire.Object{Group: 50, ID: 0, Priority: 48, Status: wire.StatusEndOfTrack})
	ctx := testCtx(t)
	for {
		o, err := sub.ReadObject(ctx)
		if err != nil {
			t.Fatal(err)
		}
		if o.Status == kolomoq.StatusEndOfTrack {
			if _, _, err := openAt(bob.keys, alice.ns, "audio", o); err != ErrNotProtected {
				t.Fatalf("End of Track: %v", err)
			}
			break
		}
	}
	if kid, ok := bob.keys.currentKID(alice.ns); !ok || kid != 1 {
		t.Fatalf("keys changed: %d %v", kid, ok)
	}
}

// TestRelaySubstitution serves another sender's catalog, a stale and a forged catalog, a
// catalog relabelled as newer, pre-join catalogs to a joiner, and a key track of its own.
func TestRelaySubstitution(t *testing.T) {
	t.Run("catalog", func(t *testing.T) {
		var stage atomic.Pointer[func(*wire.Object) []*wire.Object]
		tb, tc := newTap(t), newTap(t)
		tc.hook = stageHook(&stage)
		rm := newRoom(t)
		alice := newParty(t, rm, nil, nil)
		dave := newParty(t, rm, nil, nil)
		bob := newParty(t, rm, tb, nil)
		for _, p := range []*party{alice, dave} {
			if err := p.sender.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
				t.Fatal(err)
			}
			bob.keysFrom(t, p)
			waitKID(t, bob.keys, p.ns, 1)
			p.track(t, "catalog", 28)
		}
		subA, subD := bob.subscribe(t, alice, "catalog", nil), bob.subscribe(t, dave, "catalog", nil)
		alice.write(t, "catalog", true, []byte("alice v0"))
		alice.write(t, "catalog", true, []byte("alice v1"))
		dave.write(t, "catalog", true, []byte("dave v0"))
		if opened, errs := openAll(t, bob.keys, alice.ns, "catalog", subA, 2); !slices.Equal(sortedStrings(opened), []string{"alice v0", "alice v1"}) {
			t.Fatalf("catalogs %q %v", opened, errs)
		}
		mustOpen(t, bob.keys, dave.ns, "catalog", nextNormal(t, subD), "dave v0")
		aliasA := tb.alias(alice.ns, "catalog")
		daveCat := tb.seenObjects(true, refOf(dave.ns, "catalog"))[0].obj
		aliceCat := tb.seenObjects(true, refOf(alice.ns, "catalog"))
		forged := &wire.Object{Group: 2, ID: 0, Priority: 28, Properties: keyIDProps(1), Payload: make([]byte, 64)}
		for name, c := range map[string]struct {
			o    wire.Object
			want error
		}{
			"other sender's": {daveCat, ErrAuthentication},
			"stale":          {aliceCat[0].obj, ErrReplay},
			"forged":         {*forged, ErrAuthentication},
		} {
			tb.emit(aliasA, cloneWire(&c.o))
			if _, _, err := openAt(bob.keys, alice.ns, "catalog", nextNormal(t, subA)); err != c.want {
				t.Errorf("%s catalog: %v, want %v", name, err, c.want)
			}
		}

		carol := newParty(t, rm, tc, nil)
		if err := alice.sender.SetMembers([]ed25519.PublicKey{bob.pub, carol.pub}); err != nil {
			t.Fatal(err)
		}
		carol.keysFrom(t, alice)
		waitKID(t, carol.keys, alice.ns, 2)
		ctx := testCtx(t)
		f, err := carol.relay.Fetch(ctx, alice.ns, "catalog", &kolomoq.FetchOptions{RecentGroups: 2})
		if err != nil {
			t.Fatal(err)
		}
		for n := 0; n < 2; {
			o, err := f.ReadObject(ctx)
			if err != nil {
				t.Fatal(err)
			}
			if o.Status != kolomoq.StatusNormal {
				continue
			}
			n++
			if _, _, err := openAt(carol.keys, alice.ns, "catalog", o); err != ErrKeyRetired {
				t.Fatalf("pre-join catalog %d: %v", o.Group, err)
			}
		}
		subC := carol.subscribe(t, alice, "catalog", nil)
		var mu sync.Mutex
		var v2 *wire.Object
		setStage(&stage, func(o *wire.Object) []*wire.Object {
			mu.Lock()
			defer mu.Unlock()
			if o.Group == 2 {
				v2 = cloneWire(o)
				return []*wire.Object{o}
			}
			relabelled := cloneWire(v2)
			relabelled.Group = o.Group
			return []*wire.Object{relabelled}
		})
		alice.write(t, "catalog", true, []byte("alice v2"))
		o := nextNormal(t, subC)
		mustOpen(t, carol.keys, alice.ns, "catalog", o, "alice v2")
		if o.Group != 2 {
			t.Fatalf("catalog group %d", o.Group)
		}
		alice.write(t, "catalog", true, []byte("alice v3"))
		if _, _, err := openAt(carol.keys, alice.ns, "catalog", nextNormal(t, subC)); err != ErrAuthentication {
			t.Fatalf("stale catalog relabelled as newer: %v", err)
		}
	})

	t.Run("key track", func(t *testing.T) {
		rm := newRoom(t)
		alice := newParty(t, rm, nil, nil)
		bob := newParty(t, rm, nil, nil)
		evil := &node{id: rm.id.id, pub: rm.id.pub}
		var err error
		if evil.origin, err = kolomoq.NewOrigin(nil); err != nil {
			t.Fatal(err)
		}
		tw, err := evil.origin.CreateTrack(KeyNamespace(alice.ns), KeyTrack(bob.pub), &kolomoq.TrackOptions{Readers: []ed25519.PublicKey{bob.pub}})
		if err != nil {
			t.Fatal(err)
		}
		defer tw.Close()
		m := keyMessage{kid: 9, ns: alice.ns}
		rand.Read(m.instance[:])
		rand.Read(m.base[:])
		g, _ := tw.NewGroup()
		if _, err := g.WriteObject(appendKeyMessage(nil, &m)); err != nil {
			t.Fatal(err)
		}
		fromRelay, _ := link(t, evil, bob.node, nil)
		short, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		if err := bob.keys.Receive(short, fromRelay, bob.pub, alice.ns); err != ErrUnauthorized {
			t.Fatalf("key track served by the relay: %v", err)
		}
		if _, ok := bob.keys.currentKID(alice.ns); ok || bob.keys.Stats() != (KeyringStats{}) {
			t.Fatal("relay key installed or counted")
		}

		// A member gives, on its own pairwise session, a key it says is alice's.
		dave := newNode(t)
		dw, err := dave.origin.CreateTrack(KeyNamespace(mediaNS(dave.pub)), KeyTrack(bob.pub), &kolomoq.TrackOptions{Readers: []ed25519.PublicKey{bob.pub}})
		if err != nil {
			t.Fatal(err)
		}
		defer dw.Close()
		dg, _ := dw.NewGroup()
		if _, err := dg.WriteObject(appendKeyMessage(nil, &m)); err != nil {
			t.Fatal(err)
		}
		fromDave, _ := link(t, dave, bob.node, nil)
		receive(t, bob.keys, fromDave, bob.pub, mediaNS(dave.pub))
		eventually(t, "rejected key message", func() bool { return bob.keys.Stats().Rejected == 1 })
		for _, ns := range []kolomoq.Namespace{alice.ns, mediaNS(dave.pub)} {
			if _, ok := bob.keys.currentKID(ns); ok {
				t.Fatalf("key installed for %q", ns)
			}
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if c, err := kolosecure.Dial(ctx, rm.addr, bob.id, alice.pub, &kolosecure.Config{Transport: testTransport}); err == nil {
			c.Close()
			t.Fatal("the relay passed as alice on a pairwise connection")
		}
	})
}

// TestRelayAsksForKeyTracks has the relay ask alice's session for key tracks with SUBSCRIBE, a
// fill, a delivery timeout, FETCH, TRACK_STATUS and SUBSCRIBE_NAMESPACE: alice's session has no
// Authorize hook and still refuses. A member asking the relay for a key track is refused too.
func TestRelayAsksForKeyTracks(t *testing.T) {
	ta := newTap(t)
	rm := newRoom(t)
	alice := newParty(t, rm, ta, nil)
	bob := newParty(t, rm, nil, nil)
	if err := alice.sender.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	alice.track(t, "audio", 48)
	keyNS := KeyNamespace(alice.ns)
	params := func(set func(p *wire.MessageParams)) *wire.MessageParams {
		p := &wire.MessageParams{}
		p.Set(wire.ParamLocationFilter)
		p.Filter.Type = wire.FilterNextObject
		if set != nil {
			set(p)
		}
		return p
	}
	fill := func(p *wire.MessageParams) {
		f := &wire.MessageParams{GroupOrder: 1, Filter: wire.LocationFilter{Type: wire.FilterRelativeStart, StartGroup: 1}}
		f.Set(wire.ParamGroupOrder)
		f.Set(wire.ParamLocationFilter)
		p.Set(wire.ParamFillParameters)
		p.Fill = f
	}
	timeout := func(p *wire.MessageParams) {
		p.Set(wire.ParamObjectTimeout)
		p.ObjectTimeout = 1
	}
	fetch := &wire.MessageParams{Filter: wire.LocationFilter{Type: wire.FilterRelativeStart, StartGroup: 1}}
	fetch.Set(wire.ParamLocationFilter)

	typ, _, _, st := ta.ask(&wire.Request{Type: wire.MsgSubscribe, Namespace: alice.ns, Name: "audio", Params: params(nil)})
	if typ != wire.MsgSubscribeOK {
		t.Fatalf("media subscription answered 0x%x", typ)
	}
	st.CancelWrite(0)
	st.CancelRead(0)
	for _, member := range []ed25519.PublicKey{bob.pub, rm.id.pub} {
		for name, m := range map[string]*wire.Request{
			"subscribe":            {Type: wire.MsgSubscribe, Params: params(nil)},
			"subscribe with fill":  {Type: wire.MsgSubscribe, Params: params(fill)},
			"subscribe, timeout 1": {Type: wire.MsgSubscribe, Params: params(timeout)},
			"fetch":                {Type: wire.MsgFetch, Params: fetch},
			"track status":         {Type: wire.MsgTrackStatus, Params: &wire.MessageParams{}},
		} {
			m.Namespace, m.Name = keyNS, KeyTrack(member)
			typ, body, _, st := ta.ask(m)
			e, err := wire.ParseRequestError(body)
			if typ != wire.MsgRequestError || err != nil || kolomoq.RequestCode(e.Code) != kolomoq.ReqDoesNotExist {
				t.Errorf("relay %s of the key track of %s: answered 0x%x %+v", name, KeyTrack(member)[:8], typ, e)
			}
			st.CancelRead(0)
		}
	}
	for _, prefix := range []kolomoq.Namespace{nil, {kolomoq.KeyNamespaceField}, roomNS} {
		typ, body, br, st := ta.ask(&wire.Request{Type: wire.MsgSubscribeNamespace, Namespace: prefix, Params: &wire.MessageParams{}})
		// The previous prefix's cancellation may still be in flight.
		for end := time.Now().Add(5 * time.Second); typ == wire.MsgRequestError && time.Now().Before(end); {
			if e, err := wire.ParseRequestError(body); err != nil || kolomoq.RequestCode(e.Code) != kolomoq.ReqPrefixOverlap {
				break
			}
			st.CancelRead(0)
			time.Sleep(20 * time.Millisecond)
			typ, body, br, st = ta.ask(&wire.Request{Type: wire.MsgSubscribeNamespace, Namespace: prefix, Params: &wire.MessageParams{}})
		}
		if typ != wire.MsgRequestOK {
			t.Fatalf("namespace prefix %q answered 0x%x", prefix, typ)
		}
		st.SetReadDeadline(time.Now().Add(300 * time.Millisecond))
		for {
			typ, body, err := wire.ReadMessage(br, wire.MaxMessageLen)
			if err != nil {
				break
			}
			suffix, _ := wire.ParseNamespaceSuffix(body)
			full := append(slices.Clone(prefix), suffix...)
			if typ != wire.MsgNamespace || !slices.Equal(full, alice.ns) {
				t.Errorf("prefix %q listed 0x%x %q", prefix, typ, full)
			}
		}
		st.CancelWrite(0)
		st.CancelRead(0)
	}

	ctx := testCtx(t)
	for name, call := range map[string]func() error{
		"subscribe": func() error {
			_, err := bob.relay.Subscribe(ctx, keyNS, KeyTrack(bob.pub), &kolomoq.SubscribeOptions{Join: kolomoq.JoinCurrentGroup, ObjectDeliveryTimeout: time.Millisecond})
			return err
		},
		"fetch":        func() error { _, err := bob.relay.Fetch(ctx, keyNS, KeyTrack(bob.pub), nil); return err },
		"track status": func() error { _, err := bob.relay.TrackStatus(ctx, keyNS, KeyTrack(bob.pub)); return err },
	} {
		if err := call(); requestCode(err) != kolomoq.ReqUnauthorized {
			t.Errorf("member asking the relay, %s: %v", name, err)
		}
	}

	// A relay with no Authorize at all refuses the key namespace too.
	open, err := kolomoq.NewRelay(nil)
	if err != nil {
		t.Fatal(err)
	}
	relayNode := newNode(t)
	fromOpen := relayLink(t, open, relayNode, bob.node)
	if _, err := fromOpen.Subscribe(ctx, keyNS, KeyTrack(bob.pub), nil); requestCode(err) != kolomoq.ReqUnauthorized {
		t.Errorf("relay with no Authorize: %v", err)
	}
}

// TestRelayNamespaceOwnership checks RoomPolicy against a member announcing another member's
// namespace, before and while the owner is present, and a member serving it directly.
func TestRelayNamespaceOwnership(t *testing.T) {
	rm := newRoom(t)
	mallory := newParty(t, rm, nil, nil)
	aliceNode := newNode(t)
	rm.admit(aliceNode)
	ctx := testCtx(t)
	victim := mediaNS(aliceNode.pub)
	refuse := func(name string, ns kolomoq.Namespace) {
		t.Helper()
		if _, err := mallory.relay.PublishNamespace(ctx, ns); requestCode(err) != kolomoq.ReqUnauthorized {
			t.Errorf("%s: %v", name, err)
		}
	}
	refuse("victim absent", victim)
	alice := &party{node: aliceNode, ns: victim, tracks: map[string]*kolomoq.TrackWriter{}, groups: map[string]*kolomoq.GroupWriter{}}
	alice.sender = newSender(t, aliceNode, nil)
	alice.relay = rm.join(aliceNode, nil, nil)
	if _, err := alice.relay.PublishNamespace(ctx, victim); err != nil {
		t.Fatal(err)
	}
	refuse("victim present", victim)
	refuse("longer", append(slices.Clone(victim), "x"))
	refuse("room only", roomNS)
	refuse("outside the room", kolomoq.Namespace{"elsewhere", hexKey(mallory.pub)})
	refuse("uppercase hex", kolomoq.Namespace{"room", fmt.Sprintf("%X", aliceNode.pub)})
	other := newNode(t)
	rm.admit(other)
	if _, err := rm.join(other, nil, nil).PublishNamespace(ctx, victim); requestCode(err) != kolomoq.ReqUnauthorized {
		t.Errorf("another relay announcing the victim's namespace: %v", err)
	}

	eve := newNode(t)
	eveSession := rm.join(eve, nil, nil)
	if _, err := eveSession.Subscribe(ctx, victim, "audio", nil); requestCode(err) != kolomoq.ReqUnauthorized {
		t.Errorf("non-member subscription: %v", err)
	}

	bob := newParty(t, rm, nil, nil)
	if err := alice.sender.SetMembers([]ed25519.PublicKey{bob.pub, mallory.pub}); err != nil {
		t.Fatal(err)
	}
	bob.keysFrom(t, alice)
	mallory.keysFrom(t, alice)
	waitKID(t, bob.keys, victim, 1)
	waitKID(t, mallory.keys, victim, 1)
	alice.track(t, "audio", 48)
	sub := bob.subscribe(t, alice, "audio", nil)
	alice.write(t, "audio", true, []byte("real alice"))
	mustOpen(t, bob.keys, victim, "audio", nextNormal(t, sub), "real alice")

	mallory.keys.mu.Lock()
	stolen := mallory.keys.senders[nsKey(victim)].cur.base
	mallory.keys.mu.Unlock()
	fk, err := newTrackKey(&stolen, 1, victim, "audio")
	if err != nil {
		t.Fatal(err)
	}
	forged := sealObject(t, fk, 7, 0, 48, []byte("forged alice"), nil)
	direct, _ := link(t, mallory.node, bob.node, nil)
	if err := bob.keys.MayCarry(direct, victim); err != ErrWrongSession {
		t.Fatalf("member serving the victim's namespace directly: %v", err)
	}
	if err := bob.keys.MayCarry(bob.relay, victim); err != nil {
		t.Fatalf("listed relay: %v", err)
	}
	fromAlice, _ := link(t, alice.node, bob.node, nil)
	if err := bob.keys.MayCarry(fromAlice, victim); err != nil {
		t.Fatalf("owner: %v", err)
	}
	// Without MayCarry the forgery would authenticate: every member holds every sender's key.
	pt, _, err := openAt(bob.keys, victim, "audio", forged)
	if err != nil || string(pt) != "forged alice" {
		t.Fatalf("member forgery: %q %v", pt, err)
	}
}

// TestKeyDeliveryWithheld holds the datagrams of the pairwise path, as a byte relay can, while
// alice rotates: bob gets ErrNoKey for the new key's objects until the key arrives, and nothing
// for a key that never arrives.
func TestKeyDeliveryWithheld(t *testing.T) {
	rm := newRoom(t)
	alice := newParty(t, rm, nil, nil)
	bob := newParty(t, rm, nil, nil)
	if err := alice.sender.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	var path *udpPath
	side := linkVia(t, alice.node, bob.node, func(target string) string {
		path = newUDPPath(t, target)
		return path.addr()
	})
	receive(t, bob.keys, side, bob.pub, alice.ns)
	alice.track(t, "audio", 48)
	sub := bob.subscribe(t, alice, "audio", nil)
	alice.write(t, "audio", true, []byte("one"))
	openWhenKeyed(t, bob.keys, alice.ns, "audio", nextNormal(t, sub), "one")

	refusedFor := func(o kolomoq.Object, d time.Duration) {
		t.Helper()
		for end := time.Now().Add(d); time.Now().Before(end); time.Sleep(20 * time.Millisecond) {
			if _, _, err := openAt(bob.keys, alice.ns, "audio", o); err != ErrNoKey {
				t.Fatalf("object of a withheld key: %v", err)
			}
		}
	}
	path.held.Store(true)
	carol := newNode(t)
	if err := alice.sender.SetMembers([]ed25519.PublicKey{bob.pub, carol.pub}); err != nil {
		t.Fatal(err)
	}
	alice.write(t, "audio", true, []byte("two"))
	two := nextNormal(t, sub)
	refusedFor(two, time.Second)
	if kid, _ := bob.keys.currentKID(alice.ns); kid != 1 {
		t.Fatalf("key ID %d while withheld", kid)
	}
	path.held.Store(false)
	start := time.Now()
	openWhenKeyed(t, bob.keys, alice.ns, "audio", two, "two")
	t.Logf("key arrived %v after the path was released", time.Since(start))

	path.held.Store(true)
	if err := alice.sender.Rotate(); err != nil {
		t.Fatal(err)
	}
	alice.write(t, "audio", true, []byte("three"))
	refusedFor(nextNormal(t, sub), 1500*time.Millisecond)
}

// TestKeyIDAndKeyTrackTimeouts checks that Key IDs of every size pass a real Relay to a stalled
// subscriber without expiring, while a real OBJECT_DELIVERY_TIMEOUT inside 0x0B does expire. A key
// subscription with a 1 ms object delivery timeout still gets the current key, which comes in the
// fill, and the next one, and a relay asking with that timeout is refused like any other request.
func TestKeyIDAndKeyTrackTimeouts(t *testing.T) {
	t.Run("relay", func(t *testing.T) {
		tb := newTap(t)
		rm := newRoom(t)
		alice := newParty(t, rm, nil, nil)
		bob := newParty(t, rm, tb, bigBuffers)
		relaySide := rm.sessionOf(bob.pub)
		control := alice.track(t, "control", 68)
		alice.track(t, "kids", 68)
		bob.subscribe(t, alice, "control", nil)
		sub := bob.subscribe(t, alice, "kids", nil)
		big := make([]byte, 64<<10)
		tb.hold()
		// The 0x0B timeout applies on every hop, so on a starved machine alice's own hop can expire
		// the group before the relay holds it; the relay then sees a reset subgroup, not an expiry.
		// Each attempt sends a new group and waits for one of the two outcomes, not for a time budget.
		for attempt := uint64(1); relaySide.Stats().ExpiredGroups == 0; attempt++ {
			if attempt > 5 {
				t.Fatalf("alice's hop expired the group %d times", attempt-1)
			}
			g, _ := control.NewGroup()
			if _, err := g.WriteObject(big, kolomoq.Property{Type: 0x0B, Bytes: wire.AppendKVs(nil, []wire.KV{{Type: 0x02, Value: 1000}})}); err != nil {
				t.Fatal(err)
			}
			for range 15 {
				g.WriteObject(big)
			}
			for deadline := time.Now().Add(30 * time.Second); relaySide.Stats().ExpiredGroups == 0 && alice.relay.Stats().ExpiredGroups < attempt; time.Sleep(2 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("no expiry: relay %+v, alice %+v", relaySide.Stats(), alice.relay.Stats())
				}
			}
		}

		ids := []uint64{0, 1, 2, 127, 128, 300, 1<<62 - 1}
		for _, kid := range ids {
			if kid > 0 {
				alice.sender.mu.Lock()
				alice.sender.nextKID = kid
				alice.sender.mu.Unlock()
				if err := alice.sender.Rotate(); err != nil {
					t.Fatal(err)
				}
			}
			for i := range 16 {
				alice.write(t, "kids", i == 0, big)
			}
		}
		time.Sleep(500 * time.Millisecond)
		if st := relaySide.Stats(); st.ExpiredGroups != 1 || st.ResetGroups != 0 {
			t.Fatalf("relay stats with Key IDs %v: %+v", ids, st)
		}
		tb.release()
		got := map[string]int{}
		for range 16 * len(ids) {
			o := nextNormal(t, sub)
			if len(o.Properties) != 1 || o.Properties[0].Type != 0x0B || len(o.Payload) < len(big) {
				t.Fatalf("object %d/%d arrived as %+v", o.Group, o.ID, o.Properties)
			}
			got[string(o.Properties[0].Bytes)]++
		}
		for _, kid := range ids {
			if n := got[string(wire.AppendVarint([]byte{PropertyKeyID}, kid))]; n != 16 {
				t.Errorf("Key ID %d: %d objects", kid, n)
			}
		}
	})

	t.Run("key track", func(t *testing.T) {
		alice, bob, relay := newNode(t), newNode(t), newNode(t)
		s := newSender(t, alice, nil)
		ns := s.Namespace()
		if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
			t.Fatal(err)
		}
		bobSide, _ := link(t, alice, bob, nil)
		relaySide, _ := link(t, alice, relay, nil)
		time.Sleep(100 * time.Millisecond)
		ctx := testCtx(t)
		opts := &kolomoq.SubscribeOptions{Join: kolomoq.JoinCurrentGroup, ObjectDeliveryTimeout: time.Millisecond}
		if _, err := relaySide.Subscribe(ctx, KeyNamespace(ns), KeyTrack(relay.pub), opts); requestCode(err) != kolomoq.ReqDoesNotExist {
			t.Fatalf("relay with a timeout: %v", err)
		}
		if _, err := relaySide.Subscribe(ctx, KeyNamespace(ns), KeyTrack(bob.pub), opts); requestCode(err) != kolomoq.ReqDoesNotExist {
			t.Fatalf("relay asking for bob's key with a timeout: %v", err)
		}
		k := newKeyring(t, KeyringConfig{})
		e, err := k.join(ns, &receiver{cancel: func() {}})
		if err != nil {
			t.Fatal(err)
		}
		for want := uint64(1); want <= 2; want++ {
			sub, err := bobSide.Subscribe(ctx, KeyNamespace(ns), KeyTrack(bob.pub), opts)
			if err != nil {
				t.Fatal(err)
			}
			o := nextNormal(t, sub)
			sub.Close()
			k.deliver(e, slices.Clone(o.Payload))
			if kid, _ := k.currentKID(ns); kid != want {
				t.Fatalf("key ID %d, want %d", kid, want)
			}
			if err := s.Rotate(); err != nil {
				t.Fatal(err)
			}
			time.Sleep(50 * time.Millisecond)
		}
	})
}

// TestKeyMessageFlood floods bob's key track from the owner of a namespace: bob installs
// MaxKeyRate messages a second and drops and counts the rest. A relay session delivers none.
func TestKeyMessageFlood(t *testing.T) {
	const n = 1000
	flooder, bob := newNode(t), newNode(t)
	ns := mediaNS(flooder.pub)
	tw, err := flooder.origin.CreateTrack(KeyNamespace(ns), KeyTrack(bob.pub), &kolomoq.TrackOptions{CacheGroups: 1, Readers: []ed25519.PublicKey{bob.pub}})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()
	g, _ := tw.NewGroup()
	m := keyMessage{ns: ns}
	rand.Read(m.instance[:])
	for kid := uint64(1); kid <= n; kid++ {
		m.kid = kid
		rand.Read(m.base[:])
		if _, err := g.WriteObject(appendKeyMessage(nil, &m)); err != nil {
			t.Fatal(err)
		}
	}
	k := newKeyring(t, KeyringConfig{})
	clock := &fakeClock{t: time.Unix(1_800_000_000, 0)}
	k.now = clock.now
	side, _ := link(t, flooder, bob, nil)
	receive(t, k, side, bob.pub, ns)
	eventually(t, "flood processed", func() bool { return k.Stats().Dropped == n-defaultMaxKeyRate })
	if kid, _ := k.currentKID(ns); kid != defaultMaxKeyRate || k.Stats().Rejected != 0 {
		t.Fatalf("key ID %d, stats %+v", kid, k.Stats())
	}
	clock.add(time.Second)
	m.kid = n + 1
	if _, err := g.WriteObject(appendKeyMessage(nil, &m)); err != nil {
		t.Fatal(err)
	}
	waitKID(t, k, ns, n+1)

	rm := newRoom(t)
	rm.admit(bob)
	fromRelay := rm.join(bob, nil, nil)
	before := k.Stats()
	if err := k.Receive(testCtx(t), fromRelay, bob.pub, ns); err != ErrUnauthorized || k.Stats() != before {
		t.Fatalf("relay session: %v %+v", err, k.Stats())
	}
}

// TestRelayGroupCall runs calls of 3 and 5 through an honest relay with RoomPolicy and pairwise
// key sessions: everyone reads everyone, a joiner reads nothing sealed before it joined (relay
// cache included), and a member removed by every sender reads nothing sealed after, although the
// relay keeps forwarding to it.
func TestRelayGroupCall(t *testing.T) {
	for _, n := range []int{3, 5} {
		t.Run(fmt.Sprint(n), func(t *testing.T) { groupCall(t, n) })
	}
}

func groupCall(t *testing.T, n int) {
	rm := newRoom(t)
	ps := make([]*party, n)
	for i := range ps {
		ps[i] = newParty(t, rm, nil, bigBuffers)
		ps[i].track(t, "audio", 48)
	}
	subs := map[[2]int]*kolomoq.Subscription{}
	connect := func(i, j int) {
		ps[j].keysFrom(t, ps[i])
		subs[[2]int{i, j}] = ps[j].subscribe(t, ps[i], "audio", nil)
	}
	setMembers := func(i int, in []int) {
		var keys []ed25519.PublicKey
		for _, j := range in {
			if j != i {
				keys = append(keys, ps[j].pub)
			}
		}
		if err := ps[i].sender.SetMembers(keys); err != nil {
			t.Fatal(err)
		}
	}
	round := func(r int, senders, readers []int) {
		t.Helper()
		for _, i := range senders {
			ps[i].write(t, "audio", true, fmt.Appendf(nil, "round %d from %d", r, i))
		}
		for _, j := range readers {
			for _, i := range senders {
				if i != j {
					openWhenKeyed(t, ps[j].keys, ps[i].ns, "audio", nextNormal(t, subs[[2]int{i, j}]), fmt.Sprintf("round %d from %d", r, i))
				}
			}
		}
	}
	members := make([]int, n-1)
	for i := range members {
		members[i] = i
	}
	for _, i := range members {
		setMembers(i, members)
		for _, j := range members {
			if i != j {
				connect(i, j)
			}
		}
	}
	round(0, members, members)

	joiner := n - 1
	before := map[int]uint64{}
	for _, i := range members {
		before[i] = ps[i].sender.KeyID()
	}
	all := append(slices.Clone(members), joiner)
	for _, i := range all {
		setMembers(i, all)
	}
	for _, i := range members {
		if ps[i].sender.KeyID() == before[i] {
			t.Fatalf("sender %d did not rotate on join", i)
		}
		connect(i, joiner)
		connect(joiner, i)
		waitKID(t, ps[joiner].keys, ps[i].ns, ps[i].sender.KeyID())
		ctx := testCtx(t)
		f, err := ps[joiner].relay.Fetch(ctx, ps[i].ns, "audio", &kolomoq.FetchOptions{RecentGroups: 4})
		if err != nil {
			t.Fatal(err)
		}
		cached := 0
		for {
			o, err := f.ReadObject(ctx)
			if err == io.EOF {
				break
			}
			if err != nil {
				t.Fatal(err)
			}
			if o.Status != kolomoq.StatusNormal {
				continue
			}
			cached++
			if _, _, err := openAt(ps[joiner].keys, ps[i].ns, "audio", o); err != ErrKeyRetired {
				t.Fatalf("joiner opened cached %d/%d of %d: %v", o.Group, o.ID, i, err)
			}
		}
		if cached == 0 {
			t.Fatalf("no cached group of %d", i)
		}
	}
	round(1, all, all)

	removed := 1
	var stay []int
	for _, i := range all {
		if i != removed {
			stay = append(stay, i)
		}
	}
	for _, i := range stay {
		before[i] = ps[i].sender.KeyID()
		setMembers(i, stay)
		if ps[i].sender.KeyID() == before[i] {
			t.Fatalf("sender %d did not rotate on leave", i)
		}
	}
	round(2, stay, stay)
	for _, i := range stay {
		o := nextNormal(t, subs[[2]int{i, removed}])
		if _, _, err := openAt(ps[removed].keys, ps[i].ns, "audio", o); err != ErrNoKey {
			t.Fatalf("removed member and %d's object after the rotation: %v", i, err)
		}
	}
}
