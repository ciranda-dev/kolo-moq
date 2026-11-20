package secobj

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"fmt"
	"slices"
	"strings"
	"testing"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

func testKeyMessage() keyMessage {
	m := keyMessage{kid: 300, ns: kolomoq.Namespace{"room", "ab"}, base: testBase}
	for i := range m.instance {
		m.instance[i] = byte(i)
	}
	return m
}

func mustHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// noSecret fails if any formatting of the values shows a secret, raw or in hex.
func noSecret(t testing.TB, secrets [][]byte, values ...any) {
	t.Helper()
	for _, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%x", "%X", "%q", "%d"} {
			out := fmt.Sprintf(verb, v)
			for _, s := range secrets {
				if len(s) == 0 {
					continue
				}
				decimal := strings.Trim(fmt.Sprint(s), "[]")
				if strings.Contains(out, string(s)) || strings.Contains(strings.ToLower(out), hex.EncodeToString(s)) || strings.Contains(out, decimal) {
					t.Fatalf("%s of %T shows secret bytes: %s", verb, v, out)
				}
			}
		}
	}
}

func TestKeyMessageCanonicalEncoding(t *testing.T) {
	m := testKeyMessage()
	want := mustHex(t, "01 0004 000102030405060708090a0b0c0d0e0f 812c 02 04726f6f6d 026162 10 0f1e2d3c4b5a69788796a5b4c3d2e1f0")
	got := appendKeyMessage(nil, &m)
	eq(t, "encoding", got, want)
	back, err := parseKeyMessage(want)
	if err != nil {
		t.Fatal(err)
	}
	if back.instance != m.instance || back.kid != m.kid || !slices.Equal(back.ns, m.ns) || back.base != m.base {
		t.Fatal("round trip changed the message")
	}
	for _, kid := range []uint64{0, 127, 128, 16383, 16384, 1<<64 - 1} {
		m.kid = kid
		b := appendKeyMessage(nil, &m)
		back, err := parseKeyMessage(b)
		if err != nil || back.kid != kid {
			t.Fatalf("kid %d: %v", kid, err)
		}
	}
}

func TestKeyMessageHostile(t *testing.T) {
	m := testKeyMessage()
	valid := appendKeyMessage(nil, &m)
	head := valid[:19] // format, suite, instance
	tail := valid[len(valid)-17:]
	nsField := func(fields ...string) []byte {
		b := []byte{byte(len(fields))}
		for _, f := range fields {
			b = append(b, appendVarintTest(uint64(len(f)))...)
			b = append(b, f...)
		}
		return b
	}
	join := func(parts ...[]byte) []byte { return bytes.Join(parts, nil) }
	kid := []byte{0x81, 0x2c}
	ns := nsField("room", "ab")
	maxField := strings.Repeat("a", maxNameLen-len(kolomoq.KeyNamespaceField)-keyTrackLen)
	cases := map[string][]byte{
		"empty":                   {},
		"format 0":                join([]byte{0}, valid[1:]),
		"format 2":                join([]byte{2}, valid[1:]),
		"suite 5":                 join([]byte{1, 0, 5}, valid[3:]),
		"missing instance":        valid[:3],
		"short instance":          valid[:18],
		"missing key ID":          head,
		"non-minimal key ID":      join(head, []byte{0xc0, 0x01, 0x2c}, ns, tail),
		"truncated key ID":        join(head, []byte{0x81}),
		"no namespace":            join(head, kid),
		"empty namespace":         join(head, kid, []byte{0}, tail),
		"non-minimal count":       join(head, kid, []byte{0x80, 0x02}, ns[1:], tail),
		"32 fields":               join(head, kid, nsField(slices.Repeat([]string{"a"}, 32)...), tail),
		"huge count":              join(head, kid, []byte{0xbf, 0xff}, ns[1:], tail),
		"empty field":             join(head, kid, nsField("room", ""), tail),
		"non-minimal field":       join(head, kid, []byte{2, 0x80, 0x04}, []byte("room"), []byte{2}, []byte("ab"), tail),
		"field past end":          join(head, kid, []byte{2, 4}, []byte("ro")),
		"key namespace first":     join(head, kid, nsField(kolomoq.KeyNamespaceField, "ab"), tail),
		"key name over 4096":      join(head, kid, nsField(maxField+"a"), tail),
		"key name over 4096 b":    join(head, kid, nsField(maxField[1:], "ab"), tail),
		"key length 15":           join(head, kid, ns, []byte{15}, testBase[:15]),
		"key length 17":           join(head, kid, ns, []byte{17}, testBase[:], []byte{0}),
		"key length 16, 15 bytes": join(head, kid, ns, []byte{16}, testBase[:15]),
		"non-minimal key length":  join(head, kid, ns, []byte{0x80, 0x10}, testBase[:]),
		"missing key":             join(head, kid, ns),
		"trailing byte":           join(valid, []byte{0}),
	}
	for name, b := range cases {
		got, err := parseKeyMessage(b)
		if err != ErrKeyMessage {
			t.Errorf("%s: got %v, want ErrKeyMessage", name, err)
		}
		if got.base != ([keySize]byte{}) {
			t.Errorf("%s: key copied out of a refused message", name)
		}
		noSecret(t, [][]byte{testBase[:], b}, err)
	}
	for i := range valid {
		if _, err := parseKeyMessage(valid[:i]); err != ErrKeyMessage {
			t.Fatalf("truncated to %d bytes: %v", i, err)
		}
	}
	if _, err := parseKeyMessage(join(head, kid, nsField(maxField), tail)); err != nil {
		t.Fatalf("key name of exactly 4096 bytes: %v", err)
	}
	if _, err := parseKeyMessage(join(head, kid, nsField(slices.Repeat([]string{"a"}, 31)...), tail)); err != nil {
		t.Fatalf("31 fields: %v", err)
	}
}

func appendVarintTest(v uint64) []byte {
	switch {
	case v < 1<<7:
		return []byte{byte(v)}
	case v < 1<<14:
		return []byte{0x80 | byte(v>>8), byte(v)}
	}
	panic("test varint too large")
}

// TestKeyMessageEveryByte flips every bit of a valid message: each result is refused or is the
// canonical encoding of what it parses to.
func TestKeyMessageEveryByte(t *testing.T) {
	m := testKeyMessage()
	valid := appendKeyMessage(nil, &m)
	for i := range valid {
		for bit := range 8 {
			b := bytes.Clone(valid)
			b[i] ^= 1 << bit
			got, err := parseKeyMessage(b)
			if err != nil {
				continue
			}
			if again := appendKeyMessage(nil, &got); !bytes.Equal(again, b) {
				t.Fatalf("byte %d bit %d: accepted a non-canonical message", i, bit)
			}
		}
	}
}

func TestKeyNamespaceAndTrack(t *testing.T) {
	ns := kolomoq.Namespace{"room", "ab"}
	got := KeyNamespace(ns)
	if !slices.Equal(got, kolomoq.Namespace{kolomoq.KeyNamespaceField, "room", "ab"}) {
		t.Fatalf("KeyNamespace = %v", got)
	}
	got[1] = "x"
	if ns[0] != "room" {
		t.Fatal("KeyNamespace shares the caller's slice")
	}
	pub := ed25519.PublicKey(bytes.Repeat([]byte{0xab}, 32))
	if KeyTrack(pub) != strings.Repeat("ab", 32) {
		t.Fatalf("KeyTrack = %s", KeyTrack(pub))
	}
	for name, c := range map[string]struct {
		ns kolomoq.Namespace
		ok bool
	}{
		"one field":           {kolomoq.Namespace{"a"}, true},
		"31 fields":           {slices.Repeat(kolomoq.Namespace{"a"}, 31), true},
		"empty":               {kolomoq.Namespace{}, false},
		"32 fields":           {slices.Repeat(kolomoq.Namespace{"a"}, 32), false},
		"empty field":         {kolomoq.Namespace{"a", ""}, false},
		"reserved first":      {kolomoq.Namespace{kolomoq.KeyNamespaceField}, false},
		"reserved later":      {kolomoq.Namespace{"a", kolomoq.KeyNamespaceField}, true},
		"key name 4096":       {kolomoq.Namespace{strings.Repeat("a", 4096-9-64)}, true},
		"key name over 4096":  {kolomoq.Namespace{strings.Repeat("a", 4096-9-64+1)}, false},
		"two fields too long": {kolomoq.Namespace{strings.Repeat("a", 2000), strings.Repeat("a", 2024)}, false},
	} {
		if err := checkKeyNamespace(c.ns); (err == nil) != c.ok {
			t.Errorf("%s: %v", name, err)
		} else if err != nil && err != kolomoq.ErrInvalidName {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestKeyMessageRedaction(t *testing.T) {
	m := testKeyMessage()
	b := appendKeyMessage(nil, &m)
	for _, v := range []any{m, &m, []keyMessage{m}, struct{ M keyMessage }{m}} {
		noSecret(t, [][]byte{testBase[:], b}, v)
	}
	if s := fmt.Sprint(m); s != "secobj.keyMessage{redacted}" {
		t.Fatalf("fmt = %s", s)
	}
	m.erase()
	if m.base != ([keySize]byte{}) {
		t.Fatal("erase left key bytes")
	}
}
