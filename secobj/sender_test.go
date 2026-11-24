package secobj

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"errors"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

func TestNewSender(t *testing.T) {
	n := newNode(t)
	ns := mediaNS(n.pub)
	for name, c := range map[string]struct {
		origin *kolomoq.Origin
		ns     kolomoq.Namespace
		cfg    *SenderConfig
		want   error
	}{
		"nil origin":         {nil, ns, nil, ErrInvalidConfig},
		"empty namespace":    {n.origin, nil, nil, kolomoq.ErrInvalidName},
		"32 fields":          {n.origin, slices.Repeat(kolomoq.Namespace{"a"}, 32), nil, kolomoq.ErrInvalidName},
		"key namespace":      {n.origin, KeyNamespace(ns), nil, kolomoq.ErrInvalidName},
		"empty field":        {n.origin, kolomoq.Namespace{"room", ""}, nil, kolomoq.ErrInvalidName},
		"key name over 4096": {n.origin, kolomoq.Namespace{strings.Repeat("a", 4096-9-64+1)}, nil, kolomoq.ErrInvalidName},
		"MaxTracks -1":       {n.origin, ns, &SenderConfig{MaxTracks: -1}, ErrInvalidConfig},
		"MaxTracks too high": {n.origin, ns, &SenderConfig{MaxTracks: 1_000_001}, ErrInvalidConfig},
	} {
		if _, err := NewSender(c.origin, c.ns, c.cfg); !errors.Is(err, c.want) {
			t.Errorf("%s: %v", name, err)
		}
	}
	for _, cfg := range []*SenderConfig{{MaxTracks: 1}, {MaxTracks: 1_000_000}} {
		if _, err := NewSender(n.origin, ns, cfg); err != nil {
			t.Fatal(err)
		}
	}
	s := newSender(t, n, nil)
	if s.maxTracks != 1024 || s.maxUnits != 1<<24 || s.KeyID() != 0 || len(s.Members()) != 0 {
		t.Fatalf("defaults: tracks %d units %d kid %d", s.maxTracks, s.maxUnits, s.KeyID())
	}
	got := s.Namespace()
	got[0] = "x"
	if s.Namespace()[0] != "room" {
		t.Fatal("Namespace shares the Sender's slice")
	}
}

func TestSenderRandomKeys(t *testing.T) {
	n := newNode(t)
	a, b := newSender(t, n, nil), newSender(t, n, nil)
	if a.instance == b.instance || a.key.Load().base == b.key.Load().base || a.instance == ([instanceSize]byte{}) || a.key.Load().base == ([keySize]byte{}) {
		t.Fatal("instance IDs or keys are not random")
	}
	instance, base := a.instance, a.key.Load().base
	if err := a.Rotate(); err != nil {
		t.Fatal(err)
	}
	if a.KeyID() != 1 || a.key.Load().base == base || a.instance != instance {
		t.Fatalf("rotation: kid %d, key changed %v, instance kept %v", a.KeyID(), a.key.Load().base != base, a.instance == instance)
	}
}

func TestSealOrder(t *testing.T) {
	s := newSender(t, newNode(t), nil)
	seal(t, s, "audio", 5, 5, "x")
	for name, loc := range map[string][2]uint64{
		"repeated":         {5, 5},
		"earlier object":   {5, 4},
		"earlier group":    {4, 9},
		"object 2^32":      {6, 1 << 32},
		"object 2^64 - 1":  {7, 1<<64 - 1},
		"group 0 object 0": {0, 0},
	} {
		if _, _, err := s.Seal("audio", loc[0], loc[1], 48, []byte("x"), nil); err != ErrObjectID {
			t.Errorf("%s: %v", name, err)
		}
	}
	if s.KeyID() != 0 {
		t.Fatal("Seal rotated on a refused ID")
	}
	seal(t, s, "audio", 5, 6, "x")
	seal(t, s, "video", 0, 0, "x")
	if _, _, err := s.Seal(strings.Repeat("a", 5000), 0, 0, 48, nil, nil); err != kolomoq.ErrInvalidName {
		t.Fatalf("long track name: %v", err)
	}
	if _, _, err := s.Seal("audio", 9, 0, 48, nil, []kolomoq.Property{{Type: PropertyEncryptedList}}); err != kolomoq.ErrInvalidProperty {
		t.Fatalf("bad private property: %v", err)
	}
}

func TestWriteRecreatedTrack(t *testing.T) {
	n := newNode(t)
	s := newSender(t, n, nil)
	ns := s.Namespace()
	create := func() *kolomoq.TrackWriter {
		tw, err := n.origin.CreateTrack(ns, "video", &kolomoq.TrackOptions{Priority: 68})
		if err != nil {
			t.Fatal(err)
		}
		return tw
	}
	tw := create()
	for range 2 {
		g, _ := tw.NewGroup()
		for range 2 {
			if _, err := s.Write(g, "video", []byte("frame")); err != nil {
				t.Fatal(err)
			}
		}
	}
	if s.KeyID() != 0 {
		t.Fatal("rotated without a re-created track")
	}
	tw.Close()
	tw = create()
	defer tw.Close()
	g, _ := tw.NewGroup()
	if id, err := s.Write(g, "video", []byte("frame")); err != nil || id != 0 {
		t.Fatalf("write %d %v", id, err)
	}
	if s.KeyID() != 1 {
		t.Fatalf("re-created track: key ID %d", s.KeyID())
	}
	if _, err := s.Write(g, "video", []byte("frame")); err != nil || s.KeyID() != 1 {
		t.Fatalf("next object: %v, key ID %d", err, s.KeyID())
	}
	g.Close()
	if _, err := s.Write(g, "video", []byte("frame")); err != kolomoq.ErrClosed {
		t.Fatalf("closed group: %v", err)
	}
	if s.KeyID() != 1 {
		t.Fatal("rotated for a closed group")
	}
}

func TestSenderManyMembers(t *testing.T) {
	s := newSender(t, newNode(t), nil)
	members := make([]ed25519.PublicKey, 1100)
	for i := range members {
		members[i] = make(ed25519.PublicKey, ed25519.PublicKeySize)
		binary.BigEndian.PutUint32(members[i], uint32(i))
	}
	if err := s.SetMembers(members); err != nil {
		t.Fatalf("1100 members: %v", err)
	}
}

func TestMaxTracksRotates(t *testing.T) {
	s := newSender(t, newNode(t), &SenderConfig{MaxTracks: 2})
	seal(t, s, "a", 0, 0, "x")
	seal(t, s, "b", 0, 0, "x")
	seal(t, s, "a", 0, 1, "x")
	if s.KeyID() != 0 {
		t.Fatal("rotated within MaxTracks")
	}
	seal(t, s, "c", 0, 0, "x")
	if s.KeyID() != 1 || len(s.tracks) != 1 {
		t.Fatalf("MaxTracks + 1: key ID %d, %d tracks", s.KeyID(), len(s.tracks))
	}
	seal(t, s, "a", 0, 0, "x")
	if s.KeyID() != 1 {
		t.Fatal("a track under the new key rotated again")
	}
}

// TestUsageLimit lowers the limit to 4 units: a unit is 16384 bytes of plaintext, which counts
// the length prefix, the payload and the private list, never the tag.
func TestUsageLimit(t *testing.T) {
	s := newSender(t, newNode(t), nil)
	s.maxUnits = 4
	obj := uint64(0)
	write := func(payload int, private []kolomoq.Property) {
		t.Helper()
		if _, _, err := s.Seal("a", 0, obj, 48, make([]byte, payload), private); err != nil {
			t.Fatal(err)
		}
		obj++
	}
	for range 4 {
		write(16382, nil) // 2 + 16382 bytes: one unit
	}
	if s.KeyID() != 0 {
		t.Fatalf("rotated at %d units", 4)
	}
	write(16382, nil)
	if s.KeyID() != 1 {
		t.Fatal("no rotation past the usage limit")
	}
	write(16382, nil)
	write(16382, nil)
	write(16383, nil) // 16385 bytes: two units, 5 in all
	if s.KeyID() != 2 {
		t.Fatalf("length prefix not counted: key ID %d", s.KeyID())
	}
	write(16382, nil)
	// 2 + 16374 + 2 + 1 + 5 = 16384 bytes with the list: one unit, 4 in all.
	list := []kolomoq.Property{{Type: 0x0D, Bytes: []byte{1, 2, 3}}}
	write(16374, list)
	if s.KeyID() != 2 {
		t.Fatal("list counted wrong")
	}
	write(16382, nil)
	write(16382, nil)
	write(16382, nil)
	if s.KeyID() != 3 {
		t.Fatalf("key ID %d", s.KeyID())
	}
	write(16375, list) // two units only with the list
	if s.KeyID() != 4 {
		t.Fatalf("list not counted: key ID %d", s.KeyID())
	}
	if _, _, err := s.Seal("a", 0, obj, 48, make([]byte, 5*unitSize), nil); err != kolomoq.ErrObjectTooLarge {
		t.Fatalf("object over the whole limit: %v", err)
	}
	if units, err := sealUnits(make([]byte, maxPayload), nil); err != nil || units != 1<<16+1 {
		t.Fatalf("largest payload: %d units, %v", units, err)
	}
	if _, err := sealUnits(make([]byte, maxPayload+1), nil); err != kolomoq.ErrObjectTooLarge {
		t.Fatalf("payload over the maximum: %v", err)
	}
}

func TestSetMembers(t *testing.T) {
	n, bob, carol := newNode(t), newNode(t), newNode(t)
	s := newSender(t, n, nil)
	ns := s.Namespace()
	if err := s.SetMembers(nil); err != nil || s.KeyID() != 0 {
		t.Fatalf("same empty set: %v, key ID %d", err, s.KeyID())
	}
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub, carol.pub, bob.pub}); err != nil || s.KeyID() != 1 {
		t.Fatalf("add: %v, key ID %d", err, s.KeyID())
	}
	if err := s.SetMembers([]ed25519.PublicKey{carol.pub, bob.pub}); err != nil || s.KeyID() != 1 {
		t.Fatalf("same set: %v, key ID %d", err, s.KeyID())
	}
	want := []ed25519.PublicKey{bob.pub, carol.pub}
	slices.SortFunc(want, func(a, b ed25519.PublicKey) int { return bytes.Compare(a, b) })
	if got := s.Members(); !slices.EqualFunc(got, want, func(a, b ed25519.PublicKey) bool { return a.Equal(b) }) {
		t.Fatalf("members %x", got)
	}
	if _, err := n.origin.CreateTrack(KeyNamespace(ns), KeyTrack(bob.pub), nil); err != kolomoq.ErrTrackExists {
		t.Fatalf("bob's key track missing: %v", err)
	}
	if err := s.SetMembers([]ed25519.PublicKey{carol.pub}); err != nil || s.KeyID() != 2 {
		t.Fatalf("remove: %v, key ID %d", err, s.KeyID())
	}
	tw, err := n.origin.CreateTrack(KeyNamespace(ns), KeyTrack(bob.pub), nil)
	if err != nil {
		t.Fatalf("removed member's key track still open: %v", err)
	}
	tw.Close()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil || s.KeyID() != 3 {
		t.Fatalf("swap: %v, key ID %d", err, s.KeyID())
	}
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub, make([]byte, 31)}); !errors.Is(err, ErrInvalidConfig) || s.KeyID() != 3 {
		t.Fatalf("short key: %v, key ID %d", err, s.KeyID())
	}
	if got := s.Members(); len(got) != 1 || !got[0].Equal(bob.pub) {
		t.Fatal("members changed on error")
	}
}

func TestSetMembersFailure(t *testing.T) {
	bob, carol := newNode(t), newNode(t)
	t.Run("key message over MaxObjectSize", func(t *testing.T) {
		origin, err := kolomoq.NewOrigin(&kolomoq.OriginConfig{MaxObjectSize: 1024})
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewSender(origin, kolomoq.Namespace{"room", strings.Repeat("a", 1000)}, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		base := s.key.Load().base
		err = s.SetMembers([]ed25519.PublicKey{bob.pub})
		if err != kolomoq.ErrObjectTooLarge {
			t.Fatalf("got %v", err)
		}
		if s.KeyID() != 0 || len(s.Members()) != 0 || s.key.Load().base != base {
			t.Fatal("state changed on error")
		}
		if s.key.Load().next != ([keySize]byte{}) || !bytes.Equal(s.key.Load().msg, make([]byte, len(s.key.Load().msg))) || len(s.key.Load().msg) == 0 {
			t.Fatal("rotation scratch not cleared")
		}
		tw, err := origin.CreateTrack(KeyNamespace(s.ns), KeyTrack(bob.pub), nil)
		if err != nil {
			t.Fatalf("new member's track left open: %v", err)
		}
		tw.Close()
		if err := s.Rotate(); err != nil || s.KeyID() != 2 {
			t.Fatalf("Key ID of the failed rotation reused: %v, %d", err, s.KeyID())
		}
	})
	t.Run("origin full", func(t *testing.T) {
		origin, err := kolomoq.NewOrigin(&kolomoq.OriginConfig{MaxTracks: 1})
		if err != nil {
			t.Fatal(err)
		}
		s, err := NewSender(origin, testNS, nil)
		if err != nil {
			t.Fatal(err)
		}
		defer s.Close()
		if err := s.SetMembers([]ed25519.PublicKey{bob.pub, carol.pub}); err != kolomoq.ErrTooManyTracks {
			t.Fatalf("got %v", err)
		}
		if s.KeyID() != 0 || len(s.Members()) != 0 {
			t.Fatal("state changed on error")
		}
		if err := s.SetMembers([]ed25519.PublicKey{carol.pub}); err != nil {
			t.Fatalf("created track left open: %v", err)
		}
	})
}

func trackKeys(s *Sender) []*trackKey {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*trackKey
	for _, st := range s.tracks {
		out = append(out, st.key)
	}
	return out
}

func erased(tk *trackKey) bool {
	tk.mu.Lock()
	defer tk.mu.Unlock()
	return tk.aead == nil && tk.salt == [saltSize]byte{}
}

func TestSenderErasure(t *testing.T) {
	n, bob := newNode(t), newNode(t)
	s := newSender(t, n, nil)
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	seal(t, s, "a", 0, 0, "x")
	seal(t, s, "b", 0, 0, "x")
	old := trackKeys(s)
	if err := s.Rotate(); err != nil {
		t.Fatal(err)
	}
	for _, tk := range old {
		if !erased(tk) {
			t.Fatal("rotation left a track key")
		}
	}
	if s.key.Load().next != ([keySize]byte{}) || len(s.key.Load().msg) == 0 || !bytes.Equal(s.key.Load().msg, make([]byte, len(s.key.Load().msg))) {
		t.Fatal("rotation scratch not cleared")
	}

	seal(t, s, "a", 1, 0, "x")
	old = trackKeys(s)
	tw, err := n.origin.CreateTrack(s.ns, "v", nil)
	if err != nil {
		t.Fatal(err)
	}
	g, _ := tw.NewGroup()
	if _, err := s.Write(g, "v", []byte("x")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	tw, _ = n.origin.CreateTrack(s.ns, "v", nil)
	g, _ = tw.NewGroup()
	if _, err := s.Write(g, "v", []byte("x")); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	for _, tk := range old {
		if !erased(tk) {
			t.Fatal("automatic rotation left a track key")
		}
	}

	old = trackKeys(s)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	for _, tk := range old {
		if !erased(tk) {
			t.Fatal("Close left a track key")
		}
	}
	if s.key.Load().base != ([keySize]byte{}) || s.tracks != nil || s.members != nil {
		t.Fatal("Close left key state")
	}
	if tw, err := n.origin.CreateTrack(KeyNamespace(s.ns), KeyTrack(bob.pub), nil); err != nil {
		t.Fatalf("Close left a key track open: %v", err)
	} else {
		tw.Close()
	}
}

func TestSenderClosed(t *testing.T) {
	n := newNode(t)
	s, err := NewSender(n.origin, testNS, nil)
	if err != nil {
		t.Fatal(err)
	}
	tw, _ := n.origin.CreateTrack(testNS, "a", nil)
	defer tw.Close()
	g, _ := tw.NewGroup()
	s.Close()
	_, _, sealErr := s.Seal("a", 0, 0, 48, nil, nil)
	_, writeErr := s.Write(g, "a", nil)
	for name, err := range map[string]error{
		"Seal":       sealErr,
		"Write":      writeErr,
		"Rotate":     s.Rotate(),
		"SetMembers": s.SetMembers(nil),
		"Close":      s.Close(),
	} {
		if err != kolomoq.ErrClosed {
			t.Errorf("%s after Close: %v", name, err)
		}
	}
}

func TestSenderRedaction(t *testing.T) {
	n, bob := newNode(t), newNode(t)
	s := newSender(t, n, nil)
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	seal(t, s, "a", 0, 0, "x")
	s.mu.Lock()
	secrets := [][]byte{slices.Clone(s.key.Load().base[:]), slices.Clone(s.tracks["a"].key.salt[:])}
	m := keyMessage{instance: s.instance, kid: s.kid, ns: s.ns, base: s.key.Load().base}
	s.mu.Unlock()
	secrets = append(secrets, appendKeyMessage(nil, &m))
	var errs []error
	_, _, err := s.Seal("a", 0, 0, 48, nil, nil)
	errs = append(errs, err)
	_, _, err = s.Seal("a", 1, 1<<32, 48, nil, nil)
	errs = append(errs, err, s.SetMembers([]ed25519.PublicKey{make([]byte, 3)}))
	_, err = NewSender(n.origin, nil, nil)
	errs = append(errs, err)
	_, err = NewSender(n.origin, testNS, &SenderConfig{MaxTracks: -1})
	errs = append(errs, err)
	// A copy of the Sender, which vet's copylocks check would flag if written as *s.
	values := []any{s, struct{ S *Sender }{s}, []*Sender{s}, m, &m, reflect.ValueOf(s).Elem().Interface()}
	for _, err := range errs {
		if err == nil {
			t.Fatal("expected an error")
		}
		values = append(values, err)
	}
	noSecret(t, secrets, values...)
}

// TestConcurrentWrite writes from many goroutines into one group while the Sender rotates, and
// the member opens every object: no sealed ID is paired with another written ID.
func TestConcurrentWrite(t *testing.T) {
	checkLeaks(t)
	alice, bob := newNode(t), newNode(t)
	s := newSender(t, alice, nil)
	ns := s.Namespace()
	if err := s.SetMembers([]ed25519.PublicKey{bob.pub}); err != nil {
		t.Fatal(err)
	}
	bobSide, _ := link(t, alice, bob, nil)
	k := newKeyring(t, KeyringConfig{Retain: time.Minute})
	receive(t, k, bobSide, bob.pub, ns)
	waitKID(t, k, ns, 1)
	ctx := testCtx(t)
	tw, err := alice.origin.CreateTrack(ns, "data", &kolomoq.TrackOptions{Priority: 7, CacheGroups: 4})
	if err != nil {
		t.Fatal(err)
	}
	defer tw.Close()
	sub, err := bobSide.Subscribe(ctx, ns, "data", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	g, _ := tw.NewGroup()
	const writers, each = 8, 40
	var wg sync.WaitGroup
	errs := make(chan error, writers*each+1)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range each {
				if _, err := s.Write(g, "data", []byte{byte(w), byte(i)}); err != nil {
					errs <- err
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		time.Sleep(time.Millisecond)
		if err := s.Rotate(); err != nil {
			errs <- err
		}
		s.KeyID()
		s.Members()
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	seen := map[[2]byte]bool{}
	for range writers * each {
		obj, err := sub.ReadObject(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var got []byte
		for {
			changed := k.Changed()
			got, _, err = openAt(k, ns, "data", obj)
			if err != ErrNoKey {
				break
			}
			<-changed
		}
		if err != nil {
			t.Fatalf("object %d: %v", obj.ID, err)
		}
		seen[[2]byte(got)] = true
	}
	if len(seen) != writers*each {
		t.Fatalf("%d distinct objects", len(seen))
	}
}

func TestConcurrentSender(t *testing.T) {
	n, bob, carol := newNode(t), newNode(t), newNode(t)
	s := newSender(t, n, &SenderConfig{MaxTracks: 3})
	var wg sync.WaitGroup
	for w := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 100 {
				s.Seal(string(rune('a'+(w+i)%5)), uint64(w), uint64(i), 48, []byte("x"), nil)
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range 20 {
			if i%2 == 0 {
				s.SetMembers([]ed25519.PublicKey{bob.pub})
			} else {
				s.SetMembers([]ed25519.PublicKey{bob.pub, carol.pub})
			}
			s.Rotate()
			s.Members()
			s.KeyID()
		}
	}()
	wg.Wait()
	s.Close()
}
