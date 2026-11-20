package wire

import (
	"bufio"
	"bytes"
	"io"
	"reflect"
	"testing"
)

func FuzzVarint(f *testing.F) {
	for _, s := range []string{"25", "8025", "bbbd", "ed7f3e7d", "ffffffffffffffffff", "c0"} {
		f.Add(unhexF(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := NewReader(b)
		v, err := r.Varint()
		sv, serr := ReadVarint(bufio.NewReader(bytes.NewReader(b)))
		if (err == nil) != (serr == nil) || v != sv {
			t.Fatalf("reader %d %v, stream %d %v", v, err, sv, serr)
		}
		if err != nil {
			return
		}
		got, err := NewReader(AppendVarint(nil, v)).Varint()
		if err != nil || got != v {
			t.Fatalf("round trip %d: %d %v", v, got, err)
		}
	})
}

func FuzzKeyValues(f *testing.F) {
	f.Add(unhexF("020501026162398 12c"))
	f.Add(unhexF("0b030b0100"))
	f.Fuzz(func(t *testing.T, b []byte) {
		kvs, err := ParseKVs(b)
		if err != nil {
			return
		}
		again, err := ParseKVs(AppendKVs(nil, kvs))
		if err != nil || !reflect.DeepEqual(again, kvs) {
			t.Fatalf("round trip %+v: %+v %v", kvs, again, err)
		}
		CheckObjectProperties(kvs)
	})
}

func FuzzNamespace(f *testing.F) {
	f.Add(AppendNamespace(nil, []string{"example.net", "team2", "project_x"}))
	f.Add([]byte{33})
	f.Fuzz(func(t *testing.T, b []byte) {
		ns, err := ReadNamespace(NewReader(b))
		if err != nil {
			return
		}
		again, err := ReadNamespace(NewReader(AppendNamespace(nil, ns)))
		if err != nil || !reflect.DeepEqual(again, ns) {
			t.Fatalf("round trip %q: %q %v", ns, again, err)
		}
	})
}

var controlTypes = []uint64{
	MsgSetup, MsgGoAway, MsgSubscribe, MsgSubscribeOK, MsgPublishStateNotify, MsgPublish, MsgPublishDone,
	MsgFetch, MsgFetchOK, MsgTrackStatus, MsgPublishNamespace, MsgSubscribeNamespace, MsgSubscribeTracks,
	MsgNamespace, MsgNamespaceDone, MsgPublishSkipped, MsgRequestUpdate, MsgRequestOK, MsgRequestError,
}

// parseAny parses a control message body and re-encodes it; ok is false
// when the body does not parse.
func parseAny(typ uint64, body []byte) (parsed any, again func() (any, error), ok bool) {
	switch typ {
	case MsgSetup:
		m, err := ParseSetup(body)
		return m, func() (any, error) { return ParseSetup(m.Append(nil)) }, err == nil
	case MsgGoAway:
		m, err := ParseGoAway(body)
		return m, func() (any, error) { return ParseGoAway(m.Append(nil)) }, err == nil
	case MsgSubscribeOK:
		m, err := ParseSubscribeOK(body)
		return m, func() (any, error) { return ParseSubscribeOK(m.Append(nil)) }, err == nil
	case MsgPublishDone:
		m, err := ParsePublishDone(body)
		return m, func() (any, error) { return ParsePublishDone(m.Append(nil)) }, err == nil
	case MsgFetchOK:
		m, err := ParseFetchOK(body)
		return m, func() (any, error) { return ParseFetchOK(m.Append(nil)) }, err == nil
	case MsgRequestUpdate:
		m, err := ParseRequestUpdate(body)
		return m, func() (any, error) { return ParseRequestUpdate(m.Append(nil)) }, err == nil
	case MsgRequestOK:
		m, err := ParseRequestOK(body)
		return m, func() (any, error) { return ParseRequestOK(m.Append(nil)) }, err == nil
	case MsgRequestError:
		m, err := ParseRequestError(body)
		return m, func() (any, error) { return ParseRequestError(m.Append(nil)) }, err == nil
	case MsgPublishStateNotify:
		m, err := ParsePublishStateNotify(body)
		return m, func() (any, error) { return ParsePublishStateNotify(AppendParams(nil, m)) }, err == nil
	case MsgNamespace, MsgNamespaceDone:
		m, err := ParseNamespaceSuffix(body)
		return m, func() (any, error) { return ParseNamespaceSuffix(AppendNamespace(nil, m)) }, err == nil
	case MsgPublishSkipped:
		ns, name, err := ParsePublishSkipped(body)
		pair := [2]any{ns, name}
		return pair, func() (any, error) {
			ns2, name2, err := ParsePublishSkipped(appendName(AppendNamespace(nil, ns), name))
			return [2]any{ns2, name2}, err
		}, err == nil
	}
	m, err := ParseRequest(typ, body)
	return m, func() (any, error) { return ParseRequest(typ, m.Append(nil)) }, err == nil
}

func FuzzControlMessage(f *testing.F) {
	f.Add(byte(2), unhexF("00010161016202200a0105"))
	f.Add(byte(0), unhexF("07086b6f6c6f2d6d6f71"))
	f.Add(byte(18), unhexF("340100000101 6e0174"))
	f.Add(byte(8), unhexF("0103040000"))
	f.Add(byte(16), unhexF("04011000"))
	f.Fuzz(func(t *testing.T, sel byte, body []byte) {
		typ := controlTypes[int(sel)%len(controlTypes)]
		m, again, ok := parseAny(typ, body)
		if !ok {
			return
		}
		m2, err := again()
		if err != nil || !reflect.DeepEqual(m, m2) {
			t.Fatalf("0x%x round trip:\n%+v\n%+v %v", typ, m, m2, err)
		}
	})
}

func FuzzReadMessage(f *testing.F) {
	f.Add(msgBytes(MsgGoAway, []byte{0, 0}), 100)
	f.Fuzz(func(t *testing.T, b []byte, max int) {
		if max < 0 || max > MaxMessageLen {
			return
		}
		_, body, err := ReadMessage(bufio.NewReader(bytes.NewReader(b)), max)
		if err == nil && (len(body) > max || len(body) > len(b)) {
			t.Fatalf("body of %d bytes from %d", len(body), len(b))
		}
	})
}

func FuzzToken(f *testing.F) {
	f.Add([]byte{1, 5, 0, 'x'})
	f.Fuzz(func(t *testing.T, b []byte) { TokenAliasType(b) })
}

func FuzzSubgroupStream(f *testing.F) {
	f.Add(unhexF("310205000003616263010278010164000000 03"))
	f.Add(unhexF("1401020309"))
	f.Fuzz(func(t *testing.T, b []byte) {
		br := bufio.NewReader(bytes.NewReader(b))
		typ, err := ReadVarint(br)
		if err != nil {
			return
		}
		h, err := ReadSubgroupHeader(br, typ)
		if err != nil {
			return
		}
		if again := h.Append(nil); !IsSubgroupType(h.Flags) || len(again) == 0 {
			t.Fatal("header")
		}
		sr := &SubgroupReader{R: br, Header: h, MaxPayload: 1 << 16}
		var w SubgroupWriter
		var objs []*Object
		var enc []byte
		for {
			o, err := sr.Next()
			if err != nil {
				if err != io.EOF {
					return
				}
				break
			}
			objs = append(objs, o)
			var werr error
			if enc, werr = w.Append(enc, o); werr != nil {
				t.Fatalf("IDs from a reader do not increase: %v", werr)
			}
		}
		// Objects re-encoded with properties always present parse back the same.
		h2 := *h
		h2.Flags |= SubgroupProperties
		r2 := &SubgroupReader{R: bufio.NewReader(bytes.NewReader(enc)), Header: &h2, MaxPayload: 1 << 16}
		for _, want := range objs {
			got, err := r2.Next()
			if err != nil || got.ID != want.ID || got.Status != want.Status || !bytes.Equal(got.Payload, want.Payload) || len(got.Properties) != len(want.Properties) {
				t.Fatalf("round trip %+v: %+v %v", want, got, err)
			}
		}
	})
}

func FuzzFetchStream(f *testing.F) {
	f.Add(false, unhexF("1c04078002686900016107020201623e01000102020100810c08040100"))
	f.Add(true, unhexF("1c0000000008050 0"))
	f.Fuzz(func(t *testing.T, desc bool, b []byte) {
		fr := &FetchReader{R: bufio.NewReader(bytes.NewReader(b)), Descending: desc, MaxPayload: 1 << 16}
		w := FetchWriter{Descending: desc}
		var entries []*FetchObject
		var enc []byte
		for {
			o, err := fr.Next()
			if err != nil {
				break
			}
			entries = append(entries, o)
			if o.EndOfRange != 0 {
				enc = w.AppendEndOfRange(enc, o.EndOfRange, Location{o.Group, o.ID})
			} else {
				if o.Datagram {
					o.Subgroup = 0
				}
				enc = w.Append(enc, &o.Object)
			}
		}
		r2 := &FetchReader{R: bufio.NewReader(bytes.NewReader(enc)), Descending: desc, MaxPayload: 1 << 16}
		for _, want := range entries {
			got, err := r2.Next()
			if err != nil || got.Group != want.Group || got.ID != want.ID || got.EndOfRange != want.EndOfRange ||
				(want.EndOfRange == 0 && (got.Subgroup != want.Subgroup || got.Priority != want.Priority || !bytes.Equal(got.Payload, want.Payload))) {
				t.Fatalf("round trip %+v: %+v %v", want, got, err)
			}
		}
	})
}

func unhexF(s string) []byte {
	var out []byte
	var hi byte
	n := 0
	for _, c := range s {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = byte(c - '0')
		case c >= 'a' && c <= 'f':
			v = byte(c-'a') + 10
		default:
			continue
		}
		if n%2 == 0 {
			hi = v
		} else {
			out = append(out, hi<<4|v)
		}
		n++
	}
	return out
}

func FuzzMessageRoundTrip(f *testing.F) {
	f.Add(uint64(MsgGoAway), []byte{0, 0})
	f.Add(uint64(MsgSetup), make([]byte, MaxMessageLen+1))
	f.Fuzz(func(t *testing.T, typ uint64, body []byte) {
		b, err := AppendMessage(nil, typ, body)
		if len(body) > MaxMessageLen {
			if err != ErrMessageTooLong || len(b) != 0 {
				t.Fatalf("body of %d bytes: %v", len(body), err)
			}
			return
		}
		if err != nil {
			t.Fatal(err)
		}
		gt, gb, err := ReadMessage(bufio.NewReader(bytes.NewReader(b)), MaxMessageLen)
		if err != nil || gt != typ || !bytes.Equal(gb, body) {
			t.Fatalf("round trip: %d %x %v", gt, gb, err)
		}
	})
}

func FuzzSubgroupWriter(f *testing.F) {
	f.Add([]byte{0, 1, 2, 9}, []byte("payload"))
	f.Add([]byte{5, 3}, []byte{})
	f.Fuzz(func(t *testing.T, ids []byte, payload []byte) {
		var w SubgroupWriter
		var enc []byte
		var want []uint64
		last, started := uint64(0), false
		for _, id := range ids {
			var err error
			out, err := w.Append(enc, &Object{ID: uint64(id), Payload: payload})
			if started && uint64(id) <= last {
				if err != ErrIDNotIncreasing || len(out) != len(enc) {
					t.Fatalf("ID %d after %d: %v", id, last, err)
				}
				continue
			}
			if err != nil {
				t.Fatalf("ID %d: %v", id, err)
			}
			enc, last, started = out, uint64(id), true
			want = append(want, uint64(id))
		}
		h := &SubgroupHeader{Flags: SubgroupTypeBit | SubgroupDefaultPrio | SubgroupProperties}
		r := &SubgroupReader{R: bufio.NewReader(bytes.NewReader(enc)), Header: h, MaxPayload: 1 << 16}
		for _, id := range want {
			o, err := r.Next()
			if len(payload) == 0 {
				// An empty payload is followed by a status; ours is Normal.
				if err != nil || o.ID != id {
					t.Fatalf("ID %d: %+v %v", id, o, err)
				}
				continue
			}
			if err != nil || o.ID != id || !bytes.Equal(o.Payload, payload) {
				t.Fatalf("ID %d: %+v %v", id, o, err)
			}
		}
		if _, err := r.Next(); err != io.EOF {
			t.Fatalf("trailing data: %v", err)
		}
	})
}
