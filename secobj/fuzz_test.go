package secobj

import (
	"bytes"
	"encoding/hex"
	"testing"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

// FuzzOpen opens arbitrary objects, and arbitrary plaintexts sealed under a valid key. Only the
// canonical encoding of a payload and its private properties may open.
func FuzzOpen(f *testing.F) {
	k, err := newTrackKey(&testBase, 0, testNS, testTrack)
	if err != nil {
		f.Fatal(err)
	}
	ct, props, err := k.seal(7, 1, 68, []byte("seed frame"), []kolomoq.Property{{Type: 0x08, Value: 48000}, {Type: 0x0D, Bytes: []byte{1, 2}}})
	if err != nil {
		f.Fatal(err)
	}
	f.Add(ct, props[0].Bytes, uint64(7), uint64(1), uint8(68), []byte{0x00})
	for _, s := range []string{"", "00", "0501020304", "01aa000a020805", "01aa000a0408050006", "01aa000a020d00",
		"01aa000a03088005", "01aa000a023200", "80", "ff", "01aa000a8002080500"} {
		pt, _ := hex.DecodeString(s)
		f.Add([]byte{}, []byte{PropertyKeyID, 0}, uint64(0), uint64(0), uint8(0), pt)
	}
	f.Add(bytes.Repeat([]byte{0xff}, 40), []byte{PropertyKeyID, 0x80, 0x80}, uint64(1<<64-1), uint64(1<<32), uint8(255), []byte{})
	f.Fuzz(func(t *testing.T, payload, imm []byte, group, object uint64, priority uint8, pt []byte) {
		obj := kolomoq.Object{Group: group, ID: object, Priority: priority, Payload: payload,
			Properties: []kolomoq.Property{{Type: 0x02, Value: 1}, {Type: propImmutable, Bytes: imm}}}
		seed := bytes.Equal(payload, ct) && bytes.Equal(imm, props[0].Bytes) && group == 7 && object == 1 && priority == 68
		if _, _, err := k.open(obj); err == nil {
			if !seed {
				t.Fatal("forged object opened")
			}
		} else if err != ErrNotProtected && err != ErrMalformed && err != ErrNoKey && err != ErrObjectID && err != ErrAuthentication {
			t.Fatalf("unexpected error %v", err)
		}

		fresh, err := newTrackKey(&testBase, 0, testNS, testTrack)
		if err != nil {
			t.Fatal(err)
		}
		sealed, immBytes, err := fresh.sealPlaintext(bytes.Clone(pt), group, uint32(object), priority)
		if err != nil {
			t.Fatal(err)
		}
		obj = kolomoq.Object{Group: group, ID: uint64(uint32(object)), Priority: priority, Payload: sealed,
			Properties: []kolomoq.Property{{Type: propImmutable, Bytes: immBytes}}}
		gotPayload, gotPrivate, err := fresh.open(obj)
		if err != nil {
			if err != ErrMalformed && !(len(pt) == 0 && err == ErrAuthentication) {
				t.Fatalf("plaintext %x: %v", pt, err)
			}
			return
		}
		again, err := newTrackKey(&testBase, 0, testNS, testTrack)
		if err != nil {
			t.Fatal(err)
		}
		resealed, _, err := again.seal(group, uint64(uint32(object)), priority, gotPayload, gotPrivate)
		if err != nil {
			t.Fatalf("plaintext %x: reseal: %v", pt, err)
		}
		if !bytes.Equal(resealed, sealed) {
			t.Fatalf("plaintext %x opened but is not canonical", pt)
		}
	})
}
