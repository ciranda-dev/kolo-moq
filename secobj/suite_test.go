package secobj

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

type vector map[string]string

var (
	vectorsOnce sync.Once
	vectorsAll  []vector
	vectorsErr  error
)

// vectors returns the records of testdata/vectors.txt whose name starts with prefix.
func vectors(t testing.TB, prefix string) []vector {
	t.Helper()
	vectorsOnce.Do(func() {
		f, err := os.Open("testdata/vectors.txt")
		if err != nil {
			vectorsErr = err
			return
		}
		defer f.Close()
		cur := vector{}
		sc := bufio.NewScanner(f)
		sc.Buffer(nil, 1<<20)
		for sc.Scan() {
			line := sc.Text()
			switch {
			case strings.HasPrefix(line, "#"):
			case line == "":
				if len(cur) > 0 {
					vectorsAll = append(vectorsAll, cur)
					cur = vector{}
				}
			default:
				k, v, ok := strings.Cut(line, ": ")
				if !ok {
					k, v = strings.TrimSuffix(line, ":"), ""
				}
				cur[k] = v
			}
		}
		if len(cur) > 0 {
			vectorsAll = append(vectorsAll, cur)
		}
		vectorsErr = sc.Err()
	})
	if vectorsErr != nil {
		t.Fatal(vectorsErr)
	}
	var out []vector
	for _, v := range vectorsAll {
		if strings.HasPrefix(v["vector"], prefix) {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		t.Fatalf("no vector %q", prefix)
	}
	return out
}

func (v vector) get(t testing.TB, k string) string {
	t.Helper()
	s, ok := v[k]
	if !ok {
		t.Fatalf("%s: no field %q", v["vector"], k)
	}
	return s
}

func (v vector) bytes(t testing.TB, k string) []byte {
	t.Helper()
	b, err := hex.DecodeString(v.get(t, k))
	if err != nil {
		t.Fatalf("%s: %s: %v", v["vector"], k, err)
	}
	return b
}

func (v vector) uint(t testing.TB, k string) uint64 {
	t.Helper()
	n, err := strconv.ParseUint(v.get(t, k), 10, 64)
	if err != nil {
		t.Fatalf("%s: %s: %v", v["vector"], k, err)
	}
	return n
}

func (v vector) base(t testing.TB) *[keySize]byte {
	t.Helper()
	var b [keySize]byte
	if copy(b[:], v.bytes(t, "base_key")) != keySize {
		t.Fatalf("%s: base key length", v["vector"])
	}
	return &b
}

func (v vector) namespace(t testing.TB) kolomoq.Namespace {
	t.Helper()
	return strings.Fields(v.get(t, "namespace"))
}

func (v vector) private(t testing.TB) []kolomoq.Property {
	t.Helper()
	var ps []kolomoq.Property
	for _, f := range strings.Fields(v.get(t, "private")) {
		ty, val, _ := strings.Cut(f, "=")
		typ, err := strconv.ParseUint(strings.TrimPrefix(ty, "0x"), 16, 64)
		if err != nil {
			t.Fatal(err)
		}
		p := kolomoq.Property{Type: typ}
		if typ%2 == 0 {
			p.Value, err = strconv.ParseUint(val, 10, 64)
		} else {
			p.Bytes, err = hex.DecodeString(val)
		}
		if err != nil {
			t.Fatal(err)
		}
		ps = append(ps, p)
	}
	return ps
}

func eq(t testing.TB, name string, got, want []byte) {
	t.Helper()
	if !bytes.Equal(got, want) {
		t.Errorf("%s:\n got %x\nwant %x", name, got, want)
	}
}

func TestRFC9605SuiteAES128GCM(t *testing.T) {
	v := vectors(t, "rfc9605-c3-0004")[0]
	kid, ctr := v.uint(t, "kid"), v.uint(t, "ctr")
	suite := binary.BigEndian.AppendUint16(nil, uint16(AES128GCMSHA256))
	keyInfo := string(append(binary.BigEndian.AppendUint64([]byte("SFrame 1.0 Secret key "), kid), suite...))
	saltInfo := string(append(binary.BigEndian.AppendUint64([]byte("SFrame 1.0 Secret salt "), kid), suite...))
	eq(t, "key label", []byte(keyInfo), v.bytes(t, "key_label"))
	eq(t, "salt label", []byte(saltInfo), v.bytes(t, "salt_label"))

	secret, err := extractSecret(v.bytes(t, "base_key"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "secret", secret, v.bytes(t, "secret"))
	key, salt, err := deriveKeySalt(v.bytes(t, "base_key"), keyInfo, saltInfo)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "key", key[:], v.bytes(t, "key"))
	eq(t, "salt", salt[:], v.bytes(t, "salt"))

	// The SFrame 96-bit counter is group*2^32 + object in the shared nonce helper.
	var nonce [saltSize]byte
	makeNonce(&nonce, &salt, ctr>>32, uint32(ctr))
	eq(t, "nonce", nonce[:], v.bytes(t, "nonce"))

	hdr := v.bytes(t, "header")
	aad := append(bytes.Clone(hdr), v.bytes(t, "metadata")...)
	eq(t, "aad", aad, v.bytes(t, "aad"))
	aead, err := newAEAD(&key)
	if err != nil {
		t.Fatal(err)
	}
	ct := append(bytes.Clone(hdr), aead.Seal(nil, nonce[:], v.bytes(t, "plaintext"), aad)...)
	eq(t, "ciphertext", ct, v.bytes(t, "ciphertext"))
	pt, err := aead.Open(nil, nonce[:], ct[len(hdr):], aad)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "decrypt", pt, v.bytes(t, "plaintext"))
}

func TestSecureObjectsFullTrackName(t *testing.T) {
	for _, v := range vectors(t, "secobj01-b1-") {
		eq(t, v["vector"], appendFullTrackName(nil, v.namespace(t), v.get(t, "track")), v.bytes(t, "ftn"))
	}
}

func TestSecureObjectsKeyDerivation(t *testing.T) {
	v := vectors(t, "secobj01-b2-4")[0]
	ftn := appendFullTrackName(nil, v.namespace(t), v.get(t, "track"))
	eq(t, "ftn", ftn, v.bytes(t, "ftn"))
	kid := v.uint(t, "kid")
	keyInfo, saltInfo := profileInfo(keyLabel, ftn, kid), profileInfo(saltLabel, ftn, kid)
	eq(t, "key label", []byte(keyInfo), v.bytes(t, "key_label"))
	eq(t, "salt label", []byte(saltInfo), v.bytes(t, "salt_label"))
	secret, err := extractSecret(v.bytes(t, "base_key"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "secret", secret, v.bytes(t, "secret"))
	key, salt, err := expandKeySalt(secret, keyInfo, saltInfo)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "key", key[:], v.bytes(t, "key"))
	eq(t, "salt", salt[:], v.bytes(t, "salt"))

	k, err := newTrackKey(v.base(t), kid, v.namespace(t), v.get(t, "track"))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "track key salt", k.salt[:], v.bytes(t, "salt"))
}

func TestSecureObjectsNonceAndAAD(t *testing.T) {
	for _, v := range vectors(t, "secobj01-b3-") {
		g, o, p := v.uint(t, "group"), uint32(v.uint(t, "object")), uint8(v.uint(t, "priority"))
		var zero, ctr, nonce, salt [saltSize]byte
		copy(salt[:], v.bytes(t, "salt"))
		makeNonce(&ctr, &zero, g, o)
		eq(t, v["vector"]+" ctr", ctr[:], v.bytes(t, "ctr"))
		makeNonce(&nonce, &salt, g, o)
		eq(t, v["vector"]+" nonce", nonce[:], v.bytes(t, "nonce"))
		eq(t, v["vector"]+" aad", appendAAD(nil, g, o, p, v.bytes(t, "immutable")), v.bytes(t, "aad"))
	}
}

func TestSecureObjectsFullEncryption(t *testing.T) {
	v := vectors(t, "secobj01-b4-4")[0]
	ftn := appendFullTrackName(nil, v.namespace(t), v.get(t, "track"))
	kid := v.uint(t, "kid")
	key, salt, err := deriveKeySalt(v.bytes(t, "base_key"), profileInfo(keyLabel, ftn, kid), profileInfo(saltLabel, ftn, kid))
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "key", key[:], v.bytes(t, "key"))
	eq(t, "salt", salt[:], v.bytes(t, "salt"))
	g, o, p := v.uint(t, "group"), uint32(v.uint(t, "object")), uint8(v.uint(t, "priority"))
	var nonce [saltSize]byte
	makeNonce(&nonce, &salt, g, o)
	eq(t, "nonce", nonce[:], v.bytes(t, "nonce"))
	aad := appendAAD(nil, g, o, p, v.bytes(t, "immutable"))
	eq(t, "aad", aad, v.bytes(t, "aad"))
	aead, err := newAEAD(&key)
	if err != nil {
		t.Fatal(err)
	}
	ct := aead.Seal(nil, nonce[:], v.bytes(t, "plaintext"), aad)
	eq(t, "ciphertext", ct, v.bytes(t, "ciphertext"))
	pt, err := aead.Open(nil, nonce[:], ct, aad)
	if err != nil {
		t.Fatal(err)
	}
	eq(t, "decrypt", pt, v.bytes(t, "plaintext"))
	for i := range len(aad) * 8 {
		bad := bytes.Clone(aad)
		bad[i/8] ^= 1 << (i % 8)
		if _, err := aead.Open(nil, nonce[:], ct, bad); err == nil {
			t.Fatalf("aad bit %d flipped: opened", i)
		}
	}
}

func TestVarint(t *testing.T) {
	// draft-ietf-moq-transport-22 section 8.1, Table 4; 0x8025 is a longer form, refused here.
	for _, c := range []struct {
		hex string
		v   uint64
		ok  bool
	}{
		{"25", 37, true},
		{"8025", 37, false},
		{"bbbd", 15293, true},
		{"ed7f3e7d", 226442877, true},
		{"faa1a0e403d8", 2893212287960, true},
		{"fc8998abc66bc0", 151288809941952, true},
		{"fefa318fa8e3ca11", 70423237261249041, true},
		{"ffffffffffffffffff", 1<<64 - 1, true},
		{"c00000", 0, false},
		{"ff00ffffffffffffff", 1<<56 - 1, false},
		{"", 0, false},
		{"bb", 0, false},
		{"ffffffffffffffff", 0, false},
	} {
		b, _ := hex.DecodeString(c.hex)
		v, rest, ok := readVarint(b)
		if ok != c.ok || (ok && (v != c.v || len(rest) != 0)) {
			t.Errorf("%s: got %d %x %v, want %d %v", c.hex, v, rest, ok, c.v, c.ok)
		}
		if c.ok {
			if _, rest, _ := readVarint(append(b, 0xaa)); !bytes.Equal(rest, []byte{0xaa}) {
				t.Errorf("%s: rest %x", c.hex, rest)
			}
		}
	}
	for _, v := range []uint64{0, 127, 128, 1<<14 - 1, 1 << 14, 1<<21 - 1, 1 << 21, 1<<28 - 1, 1 << 28,
		1<<35 - 1, 1 << 35, 1<<42 - 1, 1 << 42, 1<<49 - 1, 1 << 49, 1<<56 - 1, 1 << 56, 1<<64 - 1} {
		enc := appendList(nil, []kolomoq.Property{{Type: 0, Value: v}})[1:]
		got, rest, ok := readVarint(enc)
		if !ok || got != v || len(rest) != 0 {
			t.Errorf("round trip %d: %d %v", v, got, ok)
		}
		if _, _, ok := readVarint(enc[:len(enc)-1]); ok {
			t.Errorf("truncated %d accepted", v)
		}
	}
}
