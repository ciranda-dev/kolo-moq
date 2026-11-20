package wire

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"errors"
	"io"
	"math"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

func unhex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// Table 4 of draft section 8.1.
func TestVarintVectors(t *testing.T) {
	for _, tc := range []struct {
		hex     string
		v       uint64
		minimal bool
	}{
		{"25", 37, true},
		{"8025", 37, false},
		{"bbbd", 15293, true},
		{"ed7f3e7d", 226442877, true},
		{"faa1a0e403d8", 2893212287960, true},
		{"fc8998abc66bc0", 151288809941952, true},
		{"fefa318fa8e3ca11", 70423237261249041, true},
		{"ffffffffffffffffff", math.MaxUint64, true},
		{"00", 0, true},
		{"8000", 0, false},
		{"c00000", 0, false},
	} {
		b := unhex(t, tc.hex)
		r := NewReader(b)
		v, err := r.Varint()
		if err != nil || v != tc.v || r.Len() != 0 {
			t.Errorf("%s: %d %v", tc.hex, v, err)
		}
		v, err = ReadVarint(bufio.NewReader(bytes.NewReader(b)))
		if err != nil || v != tc.v {
			t.Errorf("%s stream: %d %v", tc.hex, v, err)
		}
		if tc.minimal && !bytes.Equal(AppendVarint(nil, tc.v), b) {
			t.Errorf("encode %d: %x", tc.v, AppendVarint(nil, tc.v))
		}
	}
}

func TestVarintBoundaries(t *testing.T) {
	for n := 1; n <= 8; n++ {
		max := uint64(1)<<(7*n) - 1
		for _, v := range []uint64{max, max + 1} {
			b := AppendVarint(nil, v)
			if len(b) != VarintLen(v) {
				t.Fatalf("%d: len %d", v, len(b))
			}
			got, err := NewReader(b).Varint()
			if err != nil || got != v {
				t.Fatalf("%d: %d %v", v, got, err)
			}
		}
	}
	if _, err := NewReader([]byte{0xC0, 0}).Varint(); err == nil {
		t.Fatal("truncated varint accepted")
	}
	if _, err := ReadVarint(bufio.NewReader(bytes.NewReader([]byte{0xC0}))); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated stream varint: %v", err)
	}
	if _, err := ReadVarint(bufio.NewReader(bytes.NewReader(nil))); err != io.EOF {
		t.Fatalf("empty stream: %v", err)
	}
}

// Figure 3 of draft section 8.3: types are delta encoded; odd types carry a length.
func TestKeyValueVectors(t *testing.T) {
	kvs := []KV{{Type: 2, Value: 5}, {Type: 3, Bytes: []byte("ab")}, {Type: 0x3C, Value: 300}}
	want := unhex(t, "02 05 01 02 6162 39 812c")
	if got := AppendKVs(nil, kvs); !bytes.Equal(got, want) {
		t.Fatalf("encode %x", got)
	}
	got, err := ParseKVs(want)
	if err != nil || !reflect.DeepEqual(got, kvs) {
		t.Fatalf("decode %+v %v", got, err)
	}
	// Unsorted input is sorted, so deltas are never negative.
	if b := AppendKVs(nil, []KV{kvs[2], kvs[0], kvs[1]}); !bytes.Equal(b, want) {
		t.Fatalf("unsorted %x", b)
	}
	for name, b := range map[string][]byte{
		"type overflow":  append(AppendVarint(nil, math.MaxUint64), 0, 1, 0),
		"value too long": append([]byte{1}, AppendVarint(nil, 1<<16)...),
		"truncated":      {3, 5, 'a'},
	} {
		if _, err := ParseKVs(b); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

// Section 8.7 and the example of section 8.8.
func TestNamespaceVectors(t *testing.T) {
	ns := []string{"example.net", "team2", "project_x"}
	want := append(append(append([]byte{3, 11}, "example.net"...), append([]byte{5}, "team2"...)...), append([]byte{9}, "project_x"...)...)
	if got := AppendNamespace(nil, ns); !bytes.Equal(got, want) {
		t.Fatalf("encode %x", got)
	}
	got, err := ReadNamespace(NewReader(want))
	if err != nil || !reflect.DeepEqual(got, ns) {
		t.Fatalf("decode %v %v", got, err)
	}
	fields := make([]string, 33)
	for i := range fields {
		fields[i] = "f"
	}
	for name, b := range map[string][]byte{
		"33 fields":   AppendNamespace(nil, fields),
		"empty field": AppendNamespace(nil, []string{""}),
		"too long":    AppendNamespace(nil, []string{strings.Repeat("a", 2049), strings.Repeat("b", 2048)}),
	} {
		_, err := ReadNamespace(NewReader(b))
		var we *Error
		if !errors.As(err, &we) || we.Code != CodeProtocolViolation {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func message(t *testing.T, typ uint64, body string) []byte {
	return msgBytes(typ, unhex(t, body))
}

// Figures 5 to 23 of draft section 9.
func TestControlMessageVectors(t *testing.T) {
	prm := &MessageParams{SubscriberPriority: 10, Filter: LocationFilter{Type: FilterNextObject}}
	prm.Set(ParamSubscriberPriority)
	prm.Set(ParamLocationFilter)
	sub := &Request{Type: MsgSubscribe, RequestID: 0, Namespace: []string{"a"}, Name: "b", Params: prm}
	if got, want := msgBytes(MsgSubscribe, sub.Append(nil)), message(t, 0x03, "00 01 0161 0162 02 20 0a 01 05"); !bytes.Equal(got, want) {
		t.Fatalf("SUBSCRIBE %x, want %x", got, want)
	}
	if !bytes.Equal(message(t, 0x03, "00"), unhex(t, "03 0001 00")) {
		t.Fatal("framing")
	}
	for _, tc := range []struct {
		name string
		m    appender
		hex  string
	}{
		{"SETUP", &Setup{Options: []KV{{Type: OptMoqtImplementation, Bytes: []byte("kolo-moq")}}}, "07 08 6b6f6c6f2d6d6f71"},
		{"GOAWAY", &GoAway{Timeout: 1000}, "00 83e8"},
		{"GOAWAY URI", &GoAway{URI: "x", Timeout: 0}, "01 78 00"},
		{"REQUEST_ERROR", &RequestError{Code: 0x10, Reason: "no"}, "10 00 02 6e6f"},
		{"REQUEST_ERROR redirect", &RequestError{Code: RequestErrorRedirect, RetryInterval: 1, Redirect: &Redirect{Namespace: []string{"n"}, Name: "t"}}, "34 01 00 00 01 016e 0174"},
		{"PUBLISH_DONE", &PublishDone{Status: 2, StreamCount: 3}, "02 03 00"},
		{"FETCH_OK", &FetchOK{EndOfTrack: true, End: Location{3, 4}}, "01 03 04 00"},
		{"SUBSCRIBE_OK", &SubscribeOK{TrackAlias: 9, Properties: []KV{{Type: 0x0E, Value: 128}}}, "09 00 0e 8080"},
		{"REQUEST_OK", &RequestOK{Params: largestParam(Location{1, 2})}, "01 09 01 02"},
		{"REQUEST_UPDATE", &RequestUpdate{RequestID: 4, Params: forwardParam(0)}, "04 01 10 00"},
		{"PUBLISH_NAMESPACE", &Request{Type: MsgPublishNamespace, RequestID: 2, Namespace: []string{"x"}}, "02 01 0178 00"},
		{"FETCH", &Request{Type: MsgFetch, RequestID: 6, Namespace: []string{}, Name: "t", Params: filterParam(LocationFilter{Type: FilterAbsoluteRange, StartGroup: 1, StartObject: 2, EndGroup: 3, EndObject: 5})}, "06 00 0174 01 21 04 01 02 02 05"},
		{"PUBLISH", &Request{Type: MsgPublish, RequestID: 8, Namespace: []string{"p"}, Name: "q", TrackAlias: 1, Properties: []KV{{Type: 2, Value: 1}}}, "08 01 0170 0171 01 00 02 01"},
	} {
		if got := tc.m.Append(nil); !bytes.Equal(got, unhex(t, tc.hex)) {
			t.Errorf("%s: %x, want %s", tc.name, got, tc.hex)
		}
	}
}

type appender interface{ Append([]byte) []byte }

func largestParam(l Location) *MessageParams {
	p := &MessageParams{Largest: l}
	p.Set(ParamLargestObject)
	return p
}

func forwardParam(v uint8) *MessageParams {
	p := &MessageParams{Forward: v}
	p.Set(ParamForward)
	return p
}

func filterParam(f LocationFilter) *MessageParams {
	p := &MessageParams{Filter: f}
	p.Set(ParamLocationFilter)
	return p
}

func TestParseMessagesRoundTrip(t *testing.T) {
	fill := &MessageParams{GroupOrder: 1, Filter: LocationFilter{Type: FilterRelativeStart, StartGroup: 1}}
	fill.Set(ParamGroupOrder)
	fill.Set(ParamLocationFilter)
	prm := &MessageParams{ObjectTimeout: 5, SubgroupTimeout: 6, SubscriberPriority: 1, Forward: 1, GroupOrder: 2,
		Filter: LocationFilter{Type: FilterGroupEnd, StartGroup: 4, StartObject: 1, EndGroup: 9}, Fill: fill,
		AuthTokens: [][]byte{{TokenUseValue, 0, 'a'}, {TokenUseValue, 0, 'b'}}, NewGroupRequest: 3, IncludeProperties: 0,
		RangeFilters: []RawParam{{Type: ParamSubgroupFilter, Bytes: []byte{0}}}}
	for _, t2 := range []uint64{ParamObjectTimeout, ParamSubgroupTimeout, ParamSubscriberPriority, ParamForward, ParamGroupOrder,
		ParamLocationFilter, ParamFillParameters, ParamAuthToken, ParamNewGroupRequest, ParamIncludeProperties, ParamSubgroupFilter} {
		prm.Set(t2)
	}
	m := &Request{Type: MsgSubscribe, RequestID: 10, Namespace: []string{"a", "b"}, Name: "c", Params: prm}
	got, err := ParseRequest(MsgSubscribe, m.Append(nil))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, m) {
		t.Fatalf("got %+v\nwant %+v", got.Params, m.Params)
	}
}

func TestParamRules(t *testing.T) {
	body := func(params ...byte) []byte {
		b := AppendVarint(nil, 0)
		b = AppendNamespace(b, []string{"a"})
		b = appendName(b, "b")
		return append(b, params...)
	}
	for name, tc := range map[string]struct {
		b  []byte
		ok bool
	}{
		"repeated priority":     {body(2, 0x20, 1, 0, 2), false},
		"repeated token":        {body(2, 0x03, 3, 3, 0, 'a', 0, 3, 3, 0, 'b'), true},
		"group order 3":         {body(1, 0x22, 3), false},
		"include properties 2":  {body(1, 0x35, 2), false},
		"filter end overflow":   {body(1, 0x21, 3, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 1), false},
		"fill inside fill":      {body(1, 0x23, 4, 1, 0x23, 1, 0), false},
		"fill bad inner":        {body(1, 0x23, 3, 1, 0x02, 5), false},
		"fill trailing byte":    {body(1, 0x23, 4, 1, 0x20, 7, 0), false},
		"fill exact":            {body(1, 0x23, 3, 1, 0x20, 7), true},
		"count beyond the body": {body(5, 0x20, 1), false},
	} {
		_, err := ParseRequest(MsgSubscribe, tc.b)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestTokenAliasType(t *testing.T) {
	for name, tc := range map[string]struct {
		b  []byte
		at uint64
		ok bool
	}{
		"delete":    {[]byte{0, 5}, TokenDelete, true},
		"register":  {[]byte{1, 5, 0, 'x', 'y'}, TokenRegister, true},
		"use alias": {[]byte{2, 5}, TokenUseAlias, true},
		"use value": {[]byte{3, 0}, TokenUseValue, true},
		"unknown":   {[]byte{4}, 0, false},
		"empty":     {nil, 0, false},
		"trailing":  {[]byte{0, 5, 1}, 0, false},
	} {
		at, err := TokenAliasType(tc.b)
		if (err == nil) != tc.ok || at != tc.at {
			t.Errorf("%s: %d %v", name, at, err)
		}
	}
}

// Figures 26 and 27 of draft section 11.3.
func TestSubgroupVectors(t *testing.T) {
	h := &SubgroupHeader{Flags: SubgroupTypeBit | SubgroupProperties | SubgroupDefaultPrio, TrackAlias: 2, Group: 5}
	var w SubgroupWriter
	b := h.Append(nil)
	b = subgroupBytes(&w, b, &Object{ID: 0, Payload: []byte("abc")})
	b = subgroupBytes(&w, b, &Object{ID: 2, Properties: []KV{{Type: 0x78, Value: 1}}, Payload: []byte("d")})
	b = subgroupBytes(&w, b, &Object{ID: 3, Status: StatusEndOfGroup})
	want := unhex(t, "31 02 05  00 00 03 616263  01 02 7801 01 64  00 00 00 03")
	if !bytes.Equal(b, want) {
		t.Fatalf("encode %x\nwant   %x", b, want)
	}
	br := bufio.NewReader(bytes.NewReader(want))
	typ, _ := ReadVarint(br)
	gh, err := ReadSubgroupHeader(br, typ)
	if err != nil || gh.TrackAlias != 2 || gh.Group != 5 {
		t.Fatalf("header %+v %v", gh, err)
	}
	sr := &SubgroupReader{R: br, Header: gh, MaxPayload: 100}
	var ids []uint64
	for {
		o, err := sr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, o.ID)
	}
	if !reflect.DeepEqual(ids, []uint64{0, 2, 3}) {
		t.Fatalf("ids %v", ids)
	}
	explicit := &SubgroupHeader{Flags: SubgroupTypeBit | SubgroupModeExplicit<<1, TrackAlias: 1, Group: 2, Subgroup: 3, Priority: 9}
	if got := explicit.Append(nil); !bytes.Equal(got, unhex(t, "14 01 02 03 09")) {
		t.Fatalf("explicit header %x", got)
	}
}

func TestSubgroupRules(t *testing.T) {
	for name, tc := range map[string]struct {
		b   string
		err error
	}{
		"mode 3":                  {"16 01 02", nil},
		"bit 4 clear":             {"21 01 02", nil},
		"fin inside object":       {"30 01 02 00 05 61", nil},
		"unknown status":          {"30 01 02 00 00 05", nil},
		"properties on end":       {"31 01 02 00 02 7801 00 03", nil},
		"too large":               {"30 01 02 00 8100", ErrTooLarge},
		"mandatory track prop":    {"31 01 02 00 04 c0400001 01 61", ErrMalformedTrack},
		"nested immutable":        {"31 01 02 00 05 0b 03 0b 01 00 01 61", ErrMalformedTrack},
		"repeated prior gap":      {"31 01 02 00 04 3c 01 00 01 01 61", ErrMalformedTrack},
		"object ID overflow":      {"30 01 02 ffffffffffffffffff 01 61 00 01 61", nil},
		"properties too long":     {"31 01 02 00 c10000", nil},
		"header ends in priority": {"10 01 02", nil},
	} {
		b := unhex(t, tc.b)
		br := bufio.NewReader(bytes.NewReader(b))
		typ, _ := ReadVarint(br)
		h, err := ReadSubgroupHeader(br, typ)
		if err == nil {
			sr := &SubgroupReader{R: br, Header: h, MaxPayload: 64}
			for err == nil {
				_, err = sr.Next()
			}
		}
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%s: %v", name, err)
			}
			continue
		}
		var we *Error
		if !errors.As(err, &we) || we.Code != CodeProtocolViolation {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// Figure 29 and Tables 8 to 10 of draft section 11.4.
func TestFetchVectors(t *testing.T) {
	objs := []*Object{
		{Group: 4, ID: 7, Priority: 128, Payload: []byte("hi")},
		{Group: 4, ID: 8, Priority: 128, Payload: []byte("a")},
		{Group: 4, ID: 10, Subgroup: 2, Priority: 128, Payload: []byte("b")},
		{Group: 6, ID: 0, Subgroup: 3, Priority: 1, Properties: []KV{{Type: 2, Value: 1}}},
	}
	var w FetchWriter
	b := AppendVarint(nil, StreamTypeFetch)
	b = AppendVarint(b, 3)
	for _, o := range objs {
		b = w.Append(b, o)
	}
	b = w.AppendEndOfRange(b, EndOfUnknownRange, Location{8, 4})
	b = w.Append(b, &Object{Group: 8, ID: 5, Subgroup: 3, Priority: 1})
	want := unhex(t, "05 03"+
		" 1c 04 07 80 02 6869"+ // group and object present, priority, subgroup 0
		" 00 01 61"+ // next object, same group and priority
		" 07 02 02 01 62"+ // subgroup present, object delta 2
		" 3e 01 00 01 02 0201 00"+ // next group, subgroup prior+1, object 0, priority 1, properties
		" 810c 08 04"+ // End of Unknown Range at {8, 4}
		" 01 00") // object {8, 5}, same subgroup and priority
	if !bytes.Equal(b, want) {
		t.Fatalf("encode %x\nwant   %x", b, want)
	}
	br := bufio.NewReader(bytes.NewReader(b[2:]))
	fr := &FetchReader{R: br, MaxPayload: 10}
	var got []Location
	for {
		o, err := fr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, Location{o.Group, o.ID})
		if o.EndOfRange == 0 && o.Subgroup != map[uint64]uint64{7: 0, 8: 0, 10: 2, 0: 3, 5: 3}[o.ID] {
			t.Fatalf("subgroup of %+v", o)
		}
	}
	if want := []Location{{4, 7}, {4, 8}, {4, 10}, {6, 0}, {8, 4}, {8, 5}}; !reflect.DeepEqual(got, want) {
		t.Fatalf("locations %v", got)
	}
}

func TestFetchDescending(t *testing.T) {
	w := FetchWriter{Descending: true}
	var b []byte
	in := []*Object{{Group: 9, ID: 1}, {Group: 5, ID: 0}, {Group: 5, ID: 1}, {Group: 0, ID: 3}}
	for _, o := range in {
		b = w.Append(b, o)
	}
	fr := &FetchReader{R: bufio.NewReader(bytes.NewReader(b)), Descending: true, MaxPayload: 1}
	for _, want := range in {
		o, err := fr.Next()
		if err != nil || o.Group != want.Group || o.ID != want.ID {
			t.Fatalf("got %+v %v, want %+v", o, err, want)
		}
	}
}

func TestFetchRules(t *testing.T) {
	for name, b := range map[string]string{
		"first without group":   "14 07 00 00",
		"first prior subgroup":  "1d 01 02 00 00",
		"first prior priority":  "0c 01 02 00",
		"reserved flags":        "8100 00 00",
		"group underflow desc":  "1c 00 00 00 00 08 05 00",
		"end of range priority": "810c 01 01 0c 02 00 00",
		"truncated":             "1c 01 02",
		"payload truncated":     "1c 01 02 00 05 61",
	} {
		fr := &FetchReader{R: bufio.NewReader(bytes.NewReader(unhex(t, b))), Descending: true, MaxPayload: 10}
		var err error
		for err == nil {
			_, err = fr.Next()
		}
		var we *Error
		if !errors.As(err, &we) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestReadMessageLimits(t *testing.T) {
	b := msgBytes(MsgSubscribe, make([]byte, 100))
	if _, _, err := ReadMessage(bufio.NewReader(bytes.NewReader(b)), 99); err == nil {
		t.Fatal("over the limit")
	}
	if _, _, err := ReadMessage(bufio.NewReader(bytes.NewReader(b[:50])), 100); err != io.ErrUnexpectedEOF {
		t.Fatalf("truncated: %v", err)
	}
	if !bytes.Equal(Preface(), append([]byte{7}, "moqt-22"...)) {
		t.Fatal("preface")
	}
}

func TestAnnouncedPayloadNotReserved(t *testing.T) {
	b := AppendVarint(nil, 1<<30)
	b = append(b, "short"...)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := readPayload(bufio.NewReader(bytes.NewReader(b[VarintLen(1<<30):])), 1<<30)
	runtime.ReadMemStats(&after)
	if err == nil {
		t.Fatal("truncated payload accepted")
	}
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 1<<20 {
		t.Fatalf("allocated %d bytes for 5 received", grew)
	}
}

func msgBytes(typ uint64, body []byte) []byte {
	b, err := AppendMessage(nil, typ, body)
	if err != nil {
		panic(err)
	}
	return b
}

func subgroupBytes(w *SubgroupWriter, b []byte, o *Object) []byte {
	b, err := w.Append(b, o)
	if err != nil {
		panic(err)
	}
	return b
}

// A body that does not fit the 16-bit length is refused, not cut.
func TestAppendMessageTooLong(t *testing.T) {
	if b, err := AppendMessage(nil, MsgSubscribe, make([]byte, MaxMessageLen)); err != nil || len(b) != 1+2+MaxMessageLen {
		t.Fatalf("largest body: %d bytes, %v", len(b), err)
	}
	b, err := AppendMessage([]byte("keep"), MsgSubscribe, make([]byte, MaxMessageLen+1))
	if !errors.Is(err, ErrMessageTooLong) || string(b) != "keep" {
		t.Fatalf("body of 65536 bytes: %q, %v", b, err)
	}
}

// The subgroup encoder never writes a delta that wraps.
func TestSubgroupWriterRefusesNonIncreasing(t *testing.T) {
	var w SubgroupWriter
	b, err := w.Append(nil, &Object{ID: 5, Payload: []byte("a")})
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []uint64{5, 4, 0} {
		out, err := w.Append(b, &Object{ID: id, Payload: []byte("b")})
		if !errors.Is(err, ErrIDNotIncreasing) || !bytes.Equal(out, b) {
			t.Fatalf("ID %d after 5: %v", id, err)
		}
	}
	if _, err := w.Append(b, &Object{ID: 6, Payload: []byte("c")}); err != nil {
		t.Fatalf("ID 6 after 5: %v", err)
	}
	// The refused object left the writer where it was.
	if _, err := w.Append(b, &Object{ID: 6, Payload: []byte("c")}); !errors.Is(err, ErrIDNotIncreasing) {
		t.Fatalf("ID 6 twice: %v", err)
	}
}

func TestNewGroupRequestUpdate(t *testing.T) {
	for _, v := range []uint64{0, 1, 1 << 40, 1<<62 - 1} {
		prm := &MessageParams{NewGroupRequest: v}
		prm.Set(ParamNewGroupRequest)
		got, err := ParseRequestUpdate((&RequestUpdate{RequestID: 3, Params: prm}).Append(nil))
		if err != nil || !got.Params.Has(ParamNewGroupRequest) || got.Params.NewGroupRequest != v || got.Params.Types() != Params(ParamNewGroupRequest) {
			t.Errorf("value %d: %+v %v", v, got, err)
		}
	}
	// Next to a priority, a request keeps both; a parameter no version of the draft names is still a violation.
	prm := &MessageParams{NewGroupRequest: 5, SubscriberPriority: 9}
	prm.Set(ParamNewGroupRequest)
	prm.Set(ParamSubscriberPriority)
	got, err := ParseRequestUpdate((&RequestUpdate{RequestID: 3, Params: prm}).Append(nil))
	if err != nil || got.Params.NewGroupRequest != 5 || got.Params.SubscriberPriority != 9 {
		t.Fatalf("%+v %v", got, err)
	}
	if _, err := ParseRequestUpdate([]byte{3, 1, 0x7e, 0}); err == nil {
		t.Error("an unknown parameter parsed")
	}
	// A value cut short, a request repeated and a value past 62 bits are errors, never panics.
	for _, b := range [][]byte{{3, 1, 0x32}, {3, 2, 0x32, 1, 0, 1}, {3, 1, 0x32, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}} {
		ParseRequestUpdate(b)
	}
}
