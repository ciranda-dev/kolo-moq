package kolomoq

import (
	"io"
	"testing"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// msg frames a control message; the tests never build one that is too long.
func msg(typ uint64, body []byte) []byte {
	b, err := wire.AppendMessage(nil, typ, body)
	if err != nil {
		panic(err)
	}
	return b
}

// appendObject appends o to a subgroup stream; the tests keep IDs increasing.
func appendObject(w *wire.SubgroupWriter, b []byte, o *wire.Object) []byte {
	b, err := w.Append(b, o)
	if err != nil {
		panic(err)
	}
	return b
}

// mustWrite publishes an object; it must run on the test goroutine.
func mustWrite(t testing.TB, gw *GroupWriter, payload []byte) {
	t.Helper()
	if _, err := gw.WriteObject(payload); err != nil {
		t.Fatal(err)
	}
}

// mustSend writes b to a raw stream; it must run on the test goroutine.
func mustSend(t testing.TB, w io.Writer, b []byte) {
	t.Helper()
	if _, err := w.Write(b); err != nil {
		t.Fatal(err)
	}
}
