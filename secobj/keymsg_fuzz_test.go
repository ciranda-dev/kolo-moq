package secobj

import (
	"bytes"
	"slices"
	"testing"

	kolomoq "github.com/ciranda-dev/kolo-moq"
)

// FuzzKeyMessage parses arbitrary bytes: only the canonical encoding of a message within the
// profile's limits is accepted, and every refusal is the bare sentinel.
func FuzzKeyMessage(f *testing.F) {
	m := testKeyMessage()
	valid := appendKeyMessage(nil, &m)
	f.Add(valid)
	f.Add(append(bytes.Clone(valid), 0))
	f.Add(valid[:len(valid)-1])
	m.ns = slices.Repeat(kolomoq.Namespace{"a"}, 31)
	f.Add(appendKeyMessage(nil, &m))
	m.ns = kolomoq.Namespace{kolomoq.KeyNamespaceField}
	f.Add(appendKeyMessage(nil, &m))
	f.Add([]byte{})
	f.Add([]byte{1, 0, 4})
	f.Fuzz(func(t *testing.T, b []byte) {
		in := bytes.Clone(b)
		got, err := parseKeyMessage(b)
		if !bytes.Equal(in, b) {
			t.Fatal("parse changed its input")
		}
		if err != nil {
			if err != ErrKeyMessage {
				t.Fatalf("error %v", err)
			}
			return
		}
		if err := checkKeyNamespace(got.ns); err != nil {
			t.Fatalf("accepted namespace out of the profile: %v", err)
		}
		if again := appendKeyMessage(nil, &got); !bytes.Equal(again, b) {
			t.Fatalf("accepted a non-canonical message %x", b)
		}
	})
}
