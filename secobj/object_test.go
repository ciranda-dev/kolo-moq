package secobj

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"

	kolomoq "github.com/ciranda-dev/kolo-moq"
	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

var (
	testBase  = [keySize]byte{0x0f, 0x1e, 0x2d, 0x3c, 0x4b, 0x5a, 0x69, 0x78, 0x87, 0x96, 0xa5, 0xb4, 0xc3, 0xd2, 0xe1, 0xf0}
	testNS    = kolomoq.Namespace{"room", strings.Repeat("ab", 32)}
	testTrack = "video"
)

func newTestKey(t testing.TB, base *[keySize]byte, kid uint64, ns kolomoq.Namespace, track string) *trackKey {
	t.Helper()
	k, err := newTrackKey(base, kid, ns, track)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sealObject(t testing.TB, k *trackKey, group, object uint64, priority uint8, payload []byte, private []kolomoq.Property) kolomoq.Object {
	t.Helper()
	ct, props, err := k.seal(group, object, priority, payload, private)
	if err != nil {
		t.Fatal(err)
	}
	return kolomoq.Object{Group: group, ID: object, Priority: priority, Properties: props, Payload: ct}
}

func cloneObject(o kolomoq.Object) kolomoq.Object {
	o.Payload = bytes.Clone(o.Payload)
	ps := make([]kolomoq.Property, len(o.Properties))
	for i, p := range o.Properties {
		ps[i] = kolomoq.Property{Type: p.Type, Value: p.Value, Bytes: bytes.Clone(p.Bytes)}
	}
	o.Properties = ps
	return o
}

// wantErr fails unless err is exactly the sentinel, so no error carries object bytes.
func wantErr(t testing.TB, name string, err, want error) {
	t.Helper()
	if err != want {
		t.Errorf("%s: got %v, want %v", name, err, want)
	}
}

func TestProfileVectors(t *testing.T) {
	for _, v := range vectors(t, "kolo-") {
		t.Run(v["vector"], func(t *testing.T) {
			ns, track, kid := v.namespace(t), v.get(t, "track"), v.uint(t, "kid")
			g, o, p := v.uint(t, "group"), v.uint(t, "object"), uint8(v.uint(t, "priority"))
			payload, private := v.bytes(t, "payload"), v.private(t)

			ftn := appendFullTrackName(nil, ns, track)
			eq(t, "ftn", ftn, v.bytes(t, "ftn"))
			secret, err := extractSecret(v.bytes(t, "base_key"))
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "secret", secret, v.bytes(t, "secret"))
			key, salt, err := expandKeySalt(secret, profileInfo(keyLabel, ftn, kid), profileInfo(saltLabel, ftn, kid))
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "key", key[:], v.bytes(t, "key"))
			eq(t, "salt", salt[:], v.bytes(t, "salt"))
			var nonce [saltSize]byte
			makeNonce(&nonce, &salt, g, uint32(o))
			eq(t, "nonce", nonce[:], v.bytes(t, "nonce"))
			eq(t, "aad", appendAAD(nil, g, uint32(o), p, v.bytes(t, "immutable")), v.bytes(t, "aad"))

			k := newTestKey(t, v.base(t), kid, ns, track)
			eq(t, "track key salt", k.salt[:], salt[:])
			obj := sealObject(t, k, g, o, p, payload, private)
			eq(t, "ciphertext", obj.Payload, v.bytes(t, "ciphertext"))
			if len(obj.Properties) != 1 || obj.Properties[0].Type != propImmutable {
				t.Fatalf("visible properties %+v", obj.Properties)
			}
			eq(t, "immutable", obj.Properties[0].Bytes, v.bytes(t, "immutable"))

			aead, err := newAEAD(&key)
			if err != nil {
				t.Fatal(err)
			}
			pt, err := aead.Open(nil, nonce[:], obj.Payload, v.bytes(t, "aad"))
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "plaintext", pt, v.bytes(t, "plaintext"))

			// kolo-moq's own parser reads the Key ID at 0x78 and accepts the property.
			kvs, err := wire.ParseKVs(obj.Properties[0].Bytes)
			if err != nil || len(kvs) != 1 || kvs[0].Type != PropertyKeyID || kvs[0].Value != kid {
				t.Fatalf("wire.ParseKVs: %+v %v", kvs, err)
			}
			if err := wire.CheckObjectProperties([]wire.KV{{Type: propImmutable, Bytes: obj.Properties[0].Bytes}}); err != nil {
				t.Fatal(err)
			}

			// Relays may add visible properties; they are ignored.
			obj.Properties = append(obj.Properties, kolomoq.Property{Type: 0x02, Value: 5}, kolomoq.Property{Type: 0x10, Value: 1})
			gotPayload, gotPrivate, err := k.open(obj)
			if err != nil {
				t.Fatal(err)
			}
			eq(t, "payload", gotPayload, payload)
			if !propsEqual(gotPrivate, private) {
				t.Fatalf("private %+v, want %+v", gotPrivate, private)
			}

			// Unsorted input gives the same object.
			if len(private) > 1 {
				rev := slices.Clone(private)
				slices.Reverse(rev)
				before := slices.Clone(rev)
				again := sealObject(t, newTestKey(t, v.base(t), kid, ns, track), g, o, p, payload, rev)
				eq(t, "ciphertext from unsorted properties", again.Payload, v.bytes(t, "ciphertext"))
				if !reflect.DeepEqual(rev, before) {
					t.Fatal("seal reordered the caller's properties")
				}
			}
		})
	}
}

func propsEqual(a, b []kolomoq.Property) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i].Type != b[i].Type || a[i].Value != b[i].Value || !bytes.Equal(a[i].Bytes, b[i].Bytes) {
			return false
		}
	}
	return true
}

func TestSealOpenRoundTrip(t *testing.T) {
	big := bytes.Repeat([]byte{0x5a}, wire.MaxKVBytes)
	cases := []struct {
		payload []byte
		private []kolomoq.Property
	}{
		{nil, nil},
		{[]byte{}, nil},
		{[]byte{1}, nil},
		{bytes.Repeat([]byte{7}, 127), nil},
		{bytes.Repeat([]byte{7}, 128), nil},
		{bytes.Repeat([]byte{9}, 100000), []kolomoq.Property{{Type: 0x10, Value: 1<<64 - 1}}},
		{nil, []kolomoq.Property{{Type: 0, Value: 0}}},
		{[]byte("x"), []kolomoq.Property{{Type: 0x0D, Bytes: nil}, {Type: 0x0F, Bytes: big}}},
		{[]byte("y"), []kolomoq.Property{{Type: 1<<64 - 1, Bytes: []byte{1}}}},
		{[]byte("z"), []kolomoq.Property{{Type: 0x08, Value: 48000}, {Type: 0x10, Value: 960}, {Type: PropertyKeyID, Value: 3}}},
	}
	k := newTestKey(t, &testBase, 5, testNS, testTrack)
	for i, c := range cases {
		obj := sealObject(t, k, 9, uint64(i), 68, c.payload, c.private)
		if want := wire.VarintLen(uint64(len(c.payload))) + len(c.payload) + tagSize; len(c.private) == 0 && len(obj.Payload) != want {
			t.Errorf("case %d: %d bytes, want %d", i, len(obj.Payload), want)
		}
		payload, private, err := k.open(obj)
		if err != nil {
			t.Fatalf("case %d: %v", i, err)
		}
		if !bytes.Equal(payload, c.payload) || !propsEqual(private, c.private) {
			t.Fatalf("case %d: got %x %+v", i, payload, private)
		}
		// The returned slices may not grow into each other.
		if len(payload) > 0 && cap(payload) != len(payload) {
			t.Fatalf("case %d: payload cap %d", i, cap(payload))
		}
	}
}

func TestOpenHostile(t *testing.T) {
	k := newTestKey(t, &testBase, 1, testNS, testTrack)
	good := sealObject(t, k, 40, 3, 68, []byte("authentic frame bytes"), []kolomoq.Property{{Type: 0x10, Value: 1234}})
	mod := func(f func(o *kolomoq.Object)) kolomoq.Object {
		o := cloneObject(good)
		f(&o)
		return o
	}
	imm := func(b string) []kolomoq.Property {
		raw, err := hex.DecodeString(b)
		if err != nil {
			t.Fatal(err)
		}
		return []kolomoq.Property{{Type: propImmutable, Bytes: raw}}
	}
	cases := []struct {
		name string
		obj  kolomoq.Object
		want error
	}{
		{"end of group status", mod(func(o *kolomoq.Object) { o.Status = kolomoq.StatusEndOfGroup }), ErrNotProtected},
		{"end of track status", mod(func(o *kolomoq.Object) { o.Status = kolomoq.StatusEndOfTrack; o.Payload = nil }), ErrNotProtected},
		{"no properties", mod(func(o *kolomoq.Object) { o.Properties = nil }), ErrNotProtected},
		{"no immutable properties", mod(func(o *kolomoq.Object) { o.Properties = []kolomoq.Property{{Type: 0x02, Value: 1}} }), ErrNotProtected},
		{"key id at top level", mod(func(o *kolomoq.Object) { o.Properties = []kolomoq.Property{{Type: PropertyKeyID, Value: 1}} }), ErrNotProtected},
		{"two immutable properties", mod(func(o *kolomoq.Object) { o.Properties = append(o.Properties, o.Properties[0]) }), ErrMalformed},
		{"empty immutable properties", mod(func(o *kolomoq.Object) { o.Properties = imm("") }), ErrMalformed},
		{"key id at type 0x02", mod(func(o *kolomoq.Object) { o.Properties = imm("0201") }), ErrMalformed},
		{"two key ids", mod(func(o *kolomoq.Object) { o.Properties = imm("78010001") }), ErrMalformed},
		{"key id and another property", mod(func(o *kolomoq.Object) { o.Properties = imm("78010205") }), ErrMalformed},
		{"key id not minimal", mod(func(o *kolomoq.Object) { o.Properties = imm("788001") }), ErrMalformed},
		{"key id type not minimal", mod(func(o *kolomoq.Object) { o.Properties = imm("807801") }), ErrMalformed},
		{"key id truncated", mod(func(o *kolomoq.Object) { o.Properties = imm("78") }), ErrMalformed},
		{"key id varint truncated", mod(func(o *kolomoq.Object) { o.Properties = imm("7880") }), ErrMalformed},
		{"key id with odd type length", mod(func(o *kolomoq.Object) { o.Properties = imm("790101") }), ErrMalformed},
		{"unknown key id", mod(func(o *kolomoq.Object) { o.Properties = imm("7802") }), ErrNoKey},
		{"older key id", mod(func(o *kolomoq.Object) { o.Properties = imm("7800") }), ErrNoKey},
		{"object id 2^32", mod(func(o *kolomoq.Object) { o.ID = 1 << 32 }), ErrObjectID},
		{"object id 2^32+3 aliasing object 3", mod(func(o *kolomoq.Object) { o.ID = 1<<32 + 3 }), ErrObjectID},
		{"object id 2^64-1", mod(func(o *kolomoq.Object) { o.ID = 1<<64 - 1 }), ErrObjectID},
		{"empty payload", mod(func(o *kolomoq.Object) { o.Payload = nil }), ErrAuthentication},
		{"payload shorter than the tag", mod(func(o *kolomoq.Object) { o.Payload = o.Payload[:tagSize-1] }), ErrAuthentication},
		{"payload exactly the tag", mod(func(o *kolomoq.Object) { o.Payload = o.Payload[len(o.Payload)-tagSize:] }), ErrAuthentication},
		{"payload truncated by one", mod(func(o *kolomoq.Object) { o.Payload = o.Payload[:len(o.Payload)-1] }), ErrAuthentication},
		{"tag truncated", mod(func(o *kolomoq.Object) { o.Payload = o.Payload[:len(o.Payload)-tagSize/2] }), ErrAuthentication},
		{"payload extended", mod(func(o *kolomoq.Object) { o.Payload = append(o.Payload, 0) }), ErrAuthentication},
		{"payload prefixed", mod(func(o *kolomoq.Object) { o.Payload = append([]byte{0}, o.Payload...) }), ErrAuthentication},
		{"group changed", mod(func(o *kolomoq.Object) { o.Group++ }), ErrAuthentication},
		{"object changed", mod(func(o *kolomoq.Object) { o.ID-- }), ErrAuthentication},
		{"priority changed", mod(func(o *kolomoq.Object) { o.Priority = 0 }), ErrAuthentication},
		{"subgroup changed", mod(func(o *kolomoq.Object) { o.Subgroup = 9 }), nil},
		{"visible properties added", mod(func(o *kolomoq.Object) {
			o.Properties = append([]kolomoq.Property{{Type: 0x02, Value: 1}, {Type: 0x10, Value: 99}}, o.Properties...)
		}), nil},
	}
	for _, c := range cases {
		payload, private, err := k.open(c.obj)
		wantErr(t, c.name, err, c.want)
		if c.want != nil && (payload != nil || private != nil) {
			t.Errorf("%s: returned data with an error", c.name)
		}
	}

	ct := good.Payload
	for i := range len(ct) * 8 {
		o := cloneObject(good)
		o.Payload[i/8] ^= 1 << (i % 8)
		_, _, err := k.open(o)
		wantErr(t, fmt.Sprintf("payload bit %d", i), err, ErrAuthentication)
	}
	for i := range 64 {
		o := cloneObject(good)
		o.Group ^= 1 << i
		_, _, err := k.open(o)
		wantErr(t, fmt.Sprintf("group bit %d", i), err, ErrAuthentication)
	}
	for i := range 32 {
		o := cloneObject(good)
		o.ID ^= 1 << i
		_, _, err := k.open(o)
		wantErr(t, fmt.Sprintf("object bit %d", i), err, ErrAuthentication)
	}
	for i := range 8 {
		o := cloneObject(good)
		o.Priority ^= 1 << i
		_, _, err := k.open(o)
		wantErr(t, fmt.Sprintf("priority bit %d", i), err, ErrAuthentication)
	}
	immBytes := good.Properties[0].Bytes
	for i := range len(immBytes) * 8 {
		o := cloneObject(good)
		o.Properties[0].Bytes[i/8] ^= 1 << (i % 8)
		if _, _, err := k.open(o); err != ErrMalformed && err != ErrNoKey {
			t.Errorf("immutable bit %d: %v", i, err)
		}
	}
	if _, _, err := k.open(good); err != nil {
		t.Fatalf("original no longer opens: %v", err)
	}
}

func TestOpenWrongKey(t *testing.T) {
	k := newTestKey(t, &testBase, 1, testNS, testTrack)
	obj := sealObject(t, k, 2, 0, 68, []byte("frame"), nil)
	other := testBase
	other[0] ^= 1
	for _, c := range []struct {
		name string
		k    *trackKey
	}{
		{"other base key", newTestKey(t, &other, 1, testNS, testTrack)},
		{"other track", newTestKey(t, &testBase, 1, testNS, "audio")},
		{"other namespace", newTestKey(t, &testBase, 1, kolomoq.Namespace{"room", strings.Repeat("cd", 32)}, testTrack)},
		{"other namespace split", newTestKey(t, &testBase, 1, kolomoq.Namespace{"roo", "m" + strings.Repeat("ab", 32)}, testTrack)},
	} {
		_, _, err := c.k.open(obj)
		wantErr(t, c.name, err, ErrAuthentication)
	}

	// Key generation mismatch: the next generation's key does not open KID 1, and
	// relabeling the object as KID 2 fails authentication.
	next := newTestKey(t, &testBase, 2, testNS, testTrack)
	_, _, err := next.open(obj)
	wantErr(t, "next generation key", err, ErrNoKey)
	relabeled := cloneObject(obj)
	relabeled.Properties[0].Bytes = []byte{PropertyKeyID, 2}
	_, _, err = next.open(relabeled)
	wantErr(t, "relabeled key id", err, ErrAuthentication)
	nextBase := newTestKey(t, &other, 2, testNS, testTrack)
	_, _, err = nextBase.open(relabeled)
	wantErr(t, "relabeled key id, new base key", err, ErrAuthentication)
}

func TestOpenMalformedPlaintext(t *testing.T) {
	k := newTestKey(t, &testBase, 0, testNS, testTrack)
	longValue := wire.AppendVarint([]byte{0x0d}, wire.MaxKVBytes+1)
	longValue = append(longValue, make([]byte, wire.MaxKVBytes+1)...)
	longPT := append([]byte{0x01, 0xaa, 0x00, PropertyEncryptedList}, wire.AppendVarint(nil, uint64(len(longValue)))...)
	longPT = append(longPT, longValue...)
	// Type 2^64-1 with an empty value, then a delta of 1.
	overflowList := append(wire.AppendVarint(nil, 1<<64-1), 0x00, 0x01, 0x00)
	overflow := append([]byte{0x01, 0xaa, 0x00, PropertyEncryptedList}, wire.AppendVarint(nil, uint64(len(overflowList)))...)
	overflow = append(overflow, overflowList...)
	cases := []struct {
		name string
		pt   string
		raw  []byte
		want error
	}{
		{"empty plaintext", "", nil, ErrAuthentication},
		{"length above the remainder", "0501020304", nil, ErrMalformed},
		{"truncated length", "80", nil, ErrMalformed},
		{"length not minimal", "8001aa", nil, ErrMalformed},
		{"one trailing byte", "01aa00", nil, ErrMalformed},
		{"marker 00 0b", "01aa000b020805", nil, ErrMalformed},
		{"marker 0a 00", "01aa0a00020805", nil, ErrMalformed},
		{"marker 0a", "01aa0a020805", nil, ErrMalformed},
		{"list length above", "01aa000a030805", nil, ErrMalformed},
		{"list length below", "01aa000a010805", nil, ErrMalformed},
		{"trailing bytes after list", "01aa000a02080500", nil, ErrMalformed},
		{"empty list", "01aa000a00", nil, ErrMalformed},
		{"list length truncated", "01aa000a", nil, ErrMalformed},
		{"list length not minimal", "01aa000a80020805", nil, ErrMalformed},
		{"nested encrypted list", "01aa000a020a05", nil, ErrMalformed},
		{"nested immutable properties", "01aa000a020b00", nil, ErrMalformed},
		{"padding", "01aa000a023200", nil, ErrMalformed},
		{"padding after a property", "01aa000a040805" + "2a00", nil, ErrMalformed},
		{"duplicate property", "01aa000a0408050006", nil, ErrMalformed},
		{"delta not minimal", "01aa000a03800805", nil, ErrMalformed},
		{"value not minimal", "01aa000a03088005", nil, ErrMalformed},
		{"value truncated", "01aa000a020880", nil, ErrMalformed},
		{"odd length above the remainder", "01aa000a030d0501", nil, ErrMalformed},
		{"odd length truncated", "01aa000a020d80", nil, ErrMalformed},
		{"odd value over 65535 bytes", "", longPT, ErrMalformed},
		{"type overflows", "", overflow, ErrMalformed},
		{"empty payload", "00", nil, nil},
		{"one property", "01aa000a020805", nil, nil},
		{"empty odd property", "01aa000a020d00", nil, nil},
		{"type 0 first", "01aa000a020005", nil, nil},
	}
	for i, c := range cases {
		pt := c.raw
		if pt == nil {
			var err error
			if pt, err = hex.DecodeString(c.pt); err != nil {
				t.Fatal(err)
			}
		}
		ct, imm, err := k.sealPlaintext(bytes.Clone(pt), 1, uint32(i), 9)
		if err != nil {
			t.Fatal(err)
		}
		obj := kolomoq.Object{Group: 1, ID: uint64(i), Priority: 9, Payload: ct,
			Properties: []kolomoq.Property{{Type: propImmutable, Bytes: imm}}}
		payload, private, err := k.open(obj)
		wantErr(t, c.name, err, c.want)
		if c.want != nil && (payload != nil || private != nil) {
			t.Errorf("%s: returned data with an error", c.name)
		}
	}
}

func TestSealRefuses(t *testing.T) {
	k := newTestKey(t, &testBase, 0, testNS, testTrack)
	try := func(name string, group, object uint64, private []kolomoq.Property, want error) {
		t.Helper()
		_, _, err := k.seal(group, object, 1, []byte("p"), private)
		wantErr(t, name, err, want)
	}
	try("object id 2^32", 0, 1<<32, nil, ErrObjectID)
	try("encrypted list type", 0, 0, []kolomoq.Property{{Type: PropertyEncryptedList, Value: 1}}, kolomoq.ErrInvalidProperty)
	try("immutable type", 0, 0, []kolomoq.Property{{Type: propImmutable, Bytes: []byte{1}}}, kolomoq.ErrInvalidProperty)
	try("padding type", 0, 0, []kolomoq.Property{{Type: propPadding, Value: 0}}, kolomoq.ErrInvalidProperty)
	try("duplicate type", 0, 0, []kolomoq.Property{{Type: 8, Value: 1}, {Type: 8, Value: 2}}, kolomoq.ErrInvalidProperty)
	try("even type with bytes", 0, 0, []kolomoq.Property{{Type: 8, Bytes: []byte{}}}, kolomoq.ErrInvalidProperty)
	try("odd type with value", 0, 0, []kolomoq.Property{{Type: 9, Value: 1}}, kolomoq.ErrInvalidProperty)
	try("odd type too long", 0, 0, []kolomoq.Property{{Type: 9, Bytes: make([]byte, wire.MaxKVBytes+1)}}, kolomoq.ErrInvalidProperty)

	// Refused calls do not move the high-water mark.
	try("first", 5, 2, nil, nil)
	try("repeated", 5, 2, nil, ErrObjectID)
	try("lower object", 5, 1, nil, ErrObjectID)
	try("lower group", 4, 9, nil, ErrObjectID)
	try("next object", 5, 3, nil, nil)
	try("skipped objects", 5, 10, nil, nil)
	try("next group", 6, 0, nil, nil)
	try("group 0 again", 0, 0, nil, ErrObjectID)
	try("last object id", 6, 1<<32-1, nil, nil)
	try("after the last object id", 6, 1<<32, nil, ErrObjectID)
	try("max group", 1<<64-1, 0, nil, nil)
	try("max group, max object", 1<<64-1, 1<<32-1, nil, nil)
	try("nothing after the last nonce", 1<<64-1, 1<<32-1, nil, ErrObjectID)

	// One untouched buffer: the limits are checked before anything is copied.
	big := make([]byte, maxPayload+1)
	k2 := newTestKey(t, &testBase, 0, testNS, testTrack)
	if _, _, err := k2.seal(0, 0, 0, big, nil); err != kolomoq.ErrObjectTooLarge {
		t.Errorf("payload over the limit: %v", err)
	}
	if _, _, err := k2.seal(0, 0, 0, big[:maxPayload-tagSize-4], nil); err != kolomoq.ErrObjectTooLarge {
		t.Errorf("ciphertext over the limit: %v", err)
	}
	if _, _, err := k2.open(kolomoq.Object{Properties: []kolomoq.Property{{Type: propImmutable, Bytes: []byte{PropertyKeyID, 0}}},
		Payload: big}); err != ErrMalformed {
		t.Errorf("open over the limit: %v", err)
	}
}

func TestTrackNames(t *testing.T) {
	long := strings.Repeat("n", maxNameLen-4)
	fields := make(kolomoq.Namespace, maxFields)
	for i := range fields {
		fields[i] = "f"
	}
	for _, c := range []struct {
		name  string
		ns    kolomoq.Namespace
		track string
		ok    bool
	}{
		{"empty namespace", nil, "a", false},
		{"31 fields", fields, "a", true},
		{"32 fields", append(slices.Clone(fields), "f"), "a", false},
		{"empty field", kolomoq.Namespace{"room", ""}, "a", false},
		{"key namespace field first", kolomoq.Namespace{kolomoq.KeyNamespaceField, "x"}, "a", false},
		{"key namespace field later", kolomoq.Namespace{"x", kolomoq.KeyNamespaceField}, "a", true},
		{"4096 bytes", kolomoq.Namespace{"room"}, long, true},
		{"4097 bytes", kolomoq.Namespace{"room"}, long + "n", false},
		{"empty track name", kolomoq.Namespace{"room"}, "", true},
	} {
		_, err := newTrackKey(&testBase, 0, c.ns, c.track)
		if (err == nil) != c.ok || (err != nil && err != kolomoq.ErrInvalidName) {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}

func TestEraseAndRedaction(t *testing.T) {
	k := newTestKey(t, &testBase, 3, testNS, testTrack)
	obj := sealObject(t, k, 0, 0, 0, []byte("x"), nil)
	salt := hex.EncodeToString(k.salt[:])
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%d", "%q"} {
		if s := fmt.Sprintf(verb, k); s != "secobj.trackKey{redacted}" {
			t.Errorf("%s printed %q", verb, s)
		} else if strings.Contains(strings.ToLower(s), salt) {
			t.Errorf("%s printed the salt", verb)
		}
	}
	k.erase()
	if k.salt != [saltSize]byte{} || k.aead != nil {
		t.Fatal("key material left after erase")
	}
	_, _, err := k.open(obj)
	wantErr(t, "open after erase", err, ErrKeyRetired)
	_, _, err = k.seal(1, 0, 0, []byte("x"), nil)
	wantErr(t, "seal after erase", err, ErrKeyRetired)
}

func TestAllocations(t *testing.T) {
	k := newTestKey(t, &testBase, 0, testNS, testTrack)
	payload := make([]byte, 1200)
	private := []kolomoq.Property{{Type: 0x08, Value: 90000}, {Type: 0x10, Value: 5}}
	var id uint64
	var obj kolomoq.Object
	if n := testing.AllocsPerRun(100, func() {
		ct, props, err := k.seal(0, id, 1, payload, private)
		if err != nil {
			t.Fatal(err)
		}
		obj = kolomoq.Object{ID: id, Priority: 1, Properties: props, Payload: ct}
		id++
	}); n != 2 {
		t.Errorf("seal: %v allocations, want 2", n)
	}
	if n := testing.AllocsPerRun(100, func() {
		if _, _, err := k.open(obj); err != nil {
			t.Fatal(err)
		}
	}); n != 2 {
		t.Errorf("open with private properties: %v allocations, want 2", n)
	}
	plain := sealObject(t, k, 1, 0, 1, payload, nil)
	if n := testing.AllocsPerRun(100, func() {
		if _, _, err := k.open(plain); err != nil {
			t.Fatal(err)
		}
	}); n != 1 {
		t.Errorf("open: %v allocations, want 1", n)
	}
	bad := cloneObject(plain)
	bad.Payload[0] ^= 1
	if n := testing.AllocsPerRun(100, func() { _, _, _ = k.open(bad) }); n != 1 {
		t.Errorf("failed open: %v allocations, want 1", n)
	}
}

func TestConcurrentSealOpen(t *testing.T) {
	k := newTestKey(t, &testBase, 0, testNS, testTrack)
	const workers, each = 8, 200
	objs := make(chan kolomoq.Object, workers*each)
	var wg sync.WaitGroup
	var mu sync.Mutex
	next := uint64(0)
	for range workers {
		wg.Go(func() {
			for range each {
				mu.Lock()
				id := next
				next++
				obj := sealObject(t, k, 0, id, 2, []byte{byte(id)}, nil)
				mu.Unlock()
				objs <- obj
			}
		})
	}
	for range workers {
		wg.Go(func() {
			for range each {
				obj := <-objs
				payload, _, err := k.open(obj)
				if err != nil || len(payload) != 1 || payload[0] != byte(obj.ID) {
					t.Errorf("object %d: %x %v", obj.ID, payload, err)
				}
			}
		})
	}
	wg.Wait()
}

func TestNeverPanics(t *testing.T) {
	k := newTestKey(t, &testBase, 0, testNS, testTrack)
	sentinels := []error{ErrNotProtected, ErrMalformed, ErrNoKey, ErrObjectID, ErrAuthentication}
	seed := uint64(1)
	rnd := func() uint64 {
		seed ^= seed << 13
		seed ^= seed >> 7
		seed ^= seed << 17
		return seed
	}
	for i := range 20000 {
		payload := make([]byte, rnd()%64)
		for j := range payload {
			payload[j] = byte(rnd())
		}
		imm := []byte{PropertyKeyID, 0}
		if i%3 == 0 {
			imm = payload[:min(len(payload), int(rnd()%12))]
		}
		obj := kolomoq.Object{Group: rnd(), ID: rnd() % (1 << 33), Priority: uint8(rnd()),
			Properties: []kolomoq.Property{{Type: propImmutable, Bytes: imm}}, Payload: payload}
		_, _, err := k.open(obj)
		if !slices.ContainsFunc(sentinels, func(s error) bool { return err == s }) {
			t.Fatalf("input %d: %v", i, err)
		}
	}
}

func BenchmarkSeal(b *testing.B) {
	for _, n := range []int{100, 1024, 100 * 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			k := newTestKey(b, &testBase, 0, testNS, testTrack)
			payload := make([]byte, n)
			b.SetBytes(int64(n))
			var id uint64
			for b.Loop() {
				if _, _, err := k.seal(0, id, 1, payload, nil); err != nil {
					b.Fatal(err)
				}
				id++
			}
		})
	}
}

func BenchmarkOpen(b *testing.B) {
	for _, n := range []int{100, 1024, 100 * 1024} {
		b.Run(fmt.Sprint(n), func(b *testing.B) {
			k := newTestKey(b, &testBase, 0, testNS, testTrack)
			obj := sealObject(b, k, 0, 0, 1, make([]byte, n), nil)
			b.SetBytes(int64(n))
			for b.Loop() {
				if _, _, err := k.open(obj); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkTrackKey(b *testing.B) {
	for b.Loop() {
		if _, err := newTrackKey(&testBase, 7, testNS, testTrack); err != nil {
			b.Fatal(err)
		}
	}
}
