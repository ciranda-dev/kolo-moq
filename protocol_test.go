package kolomoq

import (
	"crypto/ed25519"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	kolotransport "github.com/ciranda-dev/kolo-transport"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

func sessionErr(t *testing.T, err error, code SessionCode) {
	t.Helper()
	var se *SessionError
	if !errors.As(err, &se) || se.Code != code {
		t.Fatalf("err %v, want session error %v", err, code)
	}
}

func TestVersionPreface(t *testing.T) {
	for name, preface := range map[string][]byte{
		"other version": append(wire.AppendVarint(nil, 7), "moqt-23"...),
		"other length":  append(wire.AppendVarint(nil, 8), "moqt-220"...),
		"no preface":    {},
	} {
		t.Run(name, func(t *testing.T) {
			checkLeaks(t)
			r, res := newRawClient(t, nil, nil)
			r.openControl(preface, setupMsg(nil))
			sr := <-res
			if !errors.Is(sr.err, ErrVersion) {
				t.Fatalf("err %v", sr.err)
			}
			sessionErr(t, sr.err, CodeProtocolViolation)
			if c := r.closedWith(); c != CodeProtocolViolation {
				t.Fatalf("closed with %v", c)
			}
		})
	}
}

func TestSetupTimeout(t *testing.T) {
	checkLeaks(t)
	r, res := newRawClient(t, &Config{SetupTimeout: time.Second}, nil)
	sr := <-res
	if !errors.Is(sr.err, ErrTimeout) {
		t.Fatalf("err %v", sr.err)
	}
	if c := r.closedWith(); c != CodeControlMessageTimeout {
		t.Fatalf("closed with %v", c)
	}
}

func TestControlStreamMustStartWithSetup(t *testing.T) {
	checkLeaks(t)
	r, res := newRawClient(t, nil, nil)
	r.openControl(wire.Preface(), msg(wire.MsgGoAway, (&wire.GoAway{}).Append(nil)))
	sr := <-res
	sessionErr(t, sr.err, CodeProtocolViolation)
}

func TestServerSetupOptions(t *testing.T) {
	for name, tc := range map[string]struct {
		opt  wire.KV
		code SessionCode
	}{
		"path":      {wire.KV{Type: wire.OptPath, Bytes: []byte("/x")}, CodeInvalidPath},
		"authority": {wire.KV{Type: wire.OptAuthority, Bytes: []byte("h")}, CodeInvalidAuthority},
		"bad token": {wire.KV{Type: wire.OptAuthToken, Bytes: []byte{9}}, CodeKeyValueFormatting},
		"alias use": {wire.KV{Type: wire.OptAuthToken, Bytes: []byte{wire.TokenUseAlias, 1}}, CodeProtocolViolation},
	} {
		t.Run(name, func(t *testing.T) {
			checkLeaks(t)
			_, res := newRawServer(t, nil, wire.Preface(), setupMsg([]wire.KV{tc.opt}))
			sessionErr(t, (<-res).err, tc.code)
		})
	}
}

func TestSetupIgnoresUnknownOptions(t *testing.T) {
	checkLeaks(t)
	opts := []wire.KV{
		{Type: 0x9D, Value: 1}, {Type: 0x9D, Value: 2}, {Type: 0x11C, Bytes: []byte("grease")},
		{Type: wire.OptPath, Bytes: []byte("/ignored")}, {Type: wire.OptAuthority, Bytes: []byte("ignored")},
		{Type: wire.OptAuthToken, Bytes: []byte{wire.TokenUseValue, 0, 'x'}},
		{Type: wire.OptMoqtImplementation, Bytes: []byte("peer\x1b[31m")},
		{Type: wire.OptMaxRequestUpdates, Value: 4},
	}
	r, res := newRawClient(t, nil, nil)
	r.openControl(wire.Preface(), setupMsg(opts))
	sr := <-res
	if sr.err != nil {
		t.Fatal(sr.err)
	}
	if got := sr.s.PeerImplementation(); got != `peer\x1b[31m` {
		t.Fatalf("implementation %q", got)
	}
}

func TestRequestIDRules(t *testing.T) {
	t.Run("parity", func(t *testing.T) {
		checkLeaks(t)
		r, s := connected(t, nil)
		r.request(subscribeMsg(1, Namespace{"a"}, "b", nil))
		if c := r.closedWith(); c != CodeInvalidRequestID {
			t.Fatalf("closed with %v", c)
		}
		<-s.Done()
	})
	t.Run("repeat", func(t *testing.T) {
		checkLeaks(t)
		r, _ := connected(t, nil)
		_, br := r.request(subscribeMsg(0, Namespace{"a"}, "b", nil))
		r.expectError(br, ReqDoesNotExist)
		r.request(subscribeMsg(0, Namespace{"a"}, "b", nil))
		if c := r.closedWith(); c != CodeInvalidRequestID {
			t.Fatalf("closed with %v", c)
		}
	})
}

func TestInvalidMessages(t *testing.T) {
	sub := func(b []byte) []byte { return msg(wire.MsgSubscribe, b) }
	valid := subscribeMsg(0, Namespace{"a"}, "b", nil).Append(nil)
	param := func(t uint64, v ...byte) []byte {
		b := wire.AppendVarint(nil, 0)
		b = wire.AppendNamespace(b, []string{"a"})
		b = append(b, 1, 'b', 1)
		b = wire.AppendVarint(b, t)
		return sub(append(b, v...))
	}
	many := make([]string, 33)
	for i := range many {
		many[i] = "x"
	}
	for name, tc := range map[string]struct {
		b    []byte
		code SessionCode
	}{
		"unknown type":         {msg(0x7F, nil), CodeProtocolViolation},
		"response first":       {msg(wire.MsgSubscribeOK, (&wire.SubscribeOK{}).Append(nil)), CodeProtocolViolation},
		"truncated":            {sub(valid[:len(valid)-1]), CodeProtocolViolation},
		"trailing bytes":       {sub(append(valid, 0)), CodeProtocolViolation},
		"unknown parameter":    {param(0x40, 0), CodeProtocolViolation},
		"misplaced parameter":  {param(wire.ParamExpires, 0), CodeProtocolViolation},
		"forward out of range": {param(wire.ParamForward, 2), CodeProtocolViolation},
		"bad location filter":  {param(wire.ParamLocationFilter, 9), CodeProtocolViolation},
		"empty field":          {sub(append(wire.AppendNamespace([]byte{0}, []string{""}), 0, 0)), CodeProtocolViolation},
		"too many fields":      {sub(append(wire.AppendNamespace([]byte{0}, many), 0, 0)), CodeProtocolViolation},
		"name too long":        {sub(append(wire.AppendNamespace([]byte{0}, []string{strings.Repeat("x", 4000)}), append(wire.AppendVarint(nil, 200), []byte(strings.Repeat("y", 200)+"\x00")...)...)), CodeProtocolViolation},
		"token register":       {param(wire.ParamAuthToken, 4, wire.TokenRegister, 1, 0, 'x'), CodeAuthTokenCacheOverflow},
		"token alias":          {param(wire.ParamAuthToken, 2, wire.TokenUseAlias, 1), CodeUnknownAuthTokenAlias},
		"token malformed":      {param(wire.ParamAuthToken, 1, 7), CodeKeyValueFormatting},
	} {
		t.Run(name, func(t *testing.T) {
			checkLeaks(t)
			r, _ := connected(t, &Config{Origin: newOrigin(t)})
			r.send(tc.b)
			if c := r.closedWith(); c != tc.code {
				t.Fatalf("closed with %v, want %v", c, tc.code)
			}
		})
	}
}

func TestControlMessageTooLarge(t *testing.T) {
	checkLeaks(t)
	r, _ := connected(t, &Config{MaxControlMessageSize: 8192})
	r.send(msg(wire.MsgSubscribe, make([]byte, 9000)))
	if c := r.closedWith(); c != CodeInternalError {
		t.Fatalf("closed with %v", c)
	}
}

func TestUnknownStreamType(t *testing.T) {
	for name, b := range map[string][]byte{
		"unknown":         wire.AppendVarint(nil, 0x06),
		"second control":  wire.Preface(),
		"setup type":      wire.AppendVarint(nil, wire.MsgSetup),
		"reserved mode":   {0x16, 0, 0},
		"large type flag": wire.AppendVarint(nil, 0x90),
	} {
		t.Run(name, func(t *testing.T) {
			checkLeaks(t)
			r, _ := connected(t, nil)
			st, err := r.conn.OpenUniStream(testCtx(t))
			if err != nil {
				t.Fatal(err)
			}
			mustSend(t, st, b)
			if c := r.closedWith(); c != CodeProtocolViolation {
				t.Fatalf("closed with %v", c)
			}
		})
	}
}

func TestPaddingStreamDiscarded(t *testing.T) {
	checkLeaks(t)
	r, s := connected(t, nil)
	st, err := r.conn.OpenUniStream(testCtx(t))
	if err != nil {
		t.Fatal(err)
	}
	mustSend(t, st, append(wire.AppendVarint(nil, wire.StreamTypePadding), make([]byte, 100000)...))
	st.Close()
	_, br := r.request(subscribeMsg(0, Namespace{"a"}, "b", nil))
	r.expectError(br, ReqDoesNotExist)
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
}

func TestRequestErrors(t *testing.T) {
	ns := Namespace{"a"}
	filter := &wire.MessageParams{RangeFilters: []wire.RawParam{{Type: wire.ParamSubgroupFilter, Bytes: []byte{0, 1}}}}
	filter.Set(wire.ParamSubgroupFilter)
	for name, tc := range map[string]struct {
		cfg  *Config
		m    *wire.Request
		code RequestCode
	}{
		"publish":          {nil, &wire.Request{Type: wire.MsgPublish, Namespace: ns, Name: "t", Params: &wire.MessageParams{}}, ReqNotSupported},
		"subscribe tracks": {nil, &wire.Request{Type: wire.MsgSubscribeTracks, Namespace: ns, Params: &wire.MessageParams{}}, ReqNotSupported},
		"range filter":     {nil, subscribeMsg(0, ns, "t", filter), ReqInvalidFilter},
		"reserved":         {nil, subscribeMsg(0, Namespace{"."}, "t", nil), ReqDoesNotExist},
		"session level":    {nil, subscribeMsg(0, Namespace{".session"}, "", nil), ReqDoesNotExist},
		"field limit":      {&Config{MaxNamespaceFields: 1}, subscribeMsg(0, Namespace{"a", "b"}, "t", nil), ReqNotSupported},
		"length limit":     {&Config{MaxNameLength: 4}, subscribeMsg(0, ns, "long", nil), ReqNotSupported},
		"no track":         {nil, subscribeMsg(0, ns, "t", nil), ReqDoesNotExist},
		"fetch nothing":    {nil, &wire.Request{Type: wire.MsgFetch, Namespace: ns, Name: "t", Params: &wire.MessageParams{}}, ReqDoesNotExist},
	} {
		t.Run(name, func(t *testing.T) {
			checkLeaks(t)
			r, s := connected(t, tc.cfg)
			tc.m.RequestID = r.id()
			_, br := r.request(tc.m)
			r.expectError(br, tc.code)
			if _, _, err := wire.ReadMessage(br, wire.MaxMessageLen); err != io.EOF {
				t.Fatalf("after REQUEST_ERROR: %v", err)
			}
			if s.Err() != nil {
				t.Fatal(s.Err())
			}
		})
	}
}

func TestUnauthorized(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	if _, err := origin.CreateTrack(Namespace{"private"}, "t", nil); err != nil {
		t.Fatal(err)
	}
	var calls []RequestKind
	var mu sync.Mutex
	cfg := &Config{Origin: origin, Authorize: func(peer ed25519.PublicKey, kind RequestKind, ns Namespace, track string) error {
		mu.Lock()
		calls = append(calls, kind)
		mu.Unlock()
		if len(peer) != ed25519.PublicKeySize {
			t.Errorf("peer key %x", peer)
		}
		if ns[0] == "private" {
			return errors.New("no")
		}
		return nil
	}}
	p := newPair(t, nil, cfg)
	ctx := testCtx(t)
	_, err := p.client.Subscribe(ctx, Namespace{"private"}, "t", nil)
	if requestCode(err) != ReqUnauthorized {
		t.Fatalf("subscribe: %v", err)
	}
	if _, err := p.client.Fetch(ctx, Namespace{"private"}, "t", nil); requestCode(err) != ReqUnauthorized {
		t.Fatalf("fetch: %v", err)
	}
	if _, err := p.client.TrackStatus(ctx, Namespace{"private"}, "t"); requestCode(err) != ReqUnauthorized {
		t.Fatalf("track status: %v", err)
	}
	if _, err := p.client.PublishNamespace(ctx, Namespace{"private"}); requestCode(err) != ReqUnauthorized {
		t.Fatalf("publish namespace: %v", err)
	}
	if _, err := p.client.SubscribeNamespace(ctx, Namespace{"private"}); requestCode(err) != ReqUnauthorized {
		t.Fatalf("subscribe namespace: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	want := []RequestKind{KindSubscribe, KindFetch, KindTrackStatus, KindPublishNamespace, KindSubscribeNamespace}
	if len(calls) != len(want) {
		t.Fatalf("calls %v", calls)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("calls %v", calls)
		}
	}
}

func TestMaxRequests(t *testing.T) {
	checkLeaks(t)
	r, _ := connected(t, &Config{MaxRequests: 2})
	for range 2 {
		_, br := r.request(&wire.Request{Type: wire.MsgPublishNamespace, RequestID: r.id(), Namespace: Namespace{"n", string(rune('a' + r.nextID))}, Params: &wire.MessageParams{}})
		r.expect(br, wire.MsgRequestOK)
	}
	_, br := r.request(&wire.Request{Type: wire.MsgPublishNamespace, RequestID: r.id(), Namespace: Namespace{"x"}, Params: &wire.MessageParams{}})
	_, _, err := wire.ReadMessage(br, wire.MaxMessageLen)
	var te *kolotransport.Error
	if !errors.As(err, &te) || te.Code != resetExcessiveLoad {
		t.Fatalf("third request: %v", err)
	}
}

func TestMaxSubscriptions(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	mustTrack(t, origin, Namespace{"a"}, "t", nil)
	p := newPair(t, nil, &Config{Origin: origin, MaxSubscriptions: 1})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, Namespace{"a"}, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.client.Subscribe(ctx, Namespace{"a"}, "t", nil); requestCode(err) != ReqExcessiveLoad {
		t.Fatalf("second: %v", err)
	}
	sub.Close()
	eventually(t, "the first subscription to end", func() bool {
		p.server.mu.Lock()
		defer p.server.mu.Unlock()
		return p.server.pubSubs == 0
	})
	if _, err := p.client.Subscribe(ctx, Namespace{"a"}, "t", nil); err != nil {
		t.Fatalf("after close: %v", err)
	}
}

func TestGoAwayRules(t *testing.T) {
	t.Run("twice", func(t *testing.T) {
		checkLeaks(t)
		r, _ := connected(t, nil)
		g := msg(wire.MsgGoAway, (&wire.GoAway{}).Append(nil))
		mustSend(t, r.ctrl, append(g, g...))
		if c := r.closedWith(); c != CodeProtocolViolation {
			t.Fatalf("closed with %v", c)
		}
	})
	t.Run("client sends URI", func(t *testing.T) {
		checkLeaks(t)
		r, _ := connected(t, nil)
		mustSend(t, r.ctrl, msg(wire.MsgGoAway, (&wire.GoAway{URI: "moqt://x"}).Append(nil)))
		if c := r.closedWith(); c != CodeProtocolViolation {
			t.Fatalf("closed with %v", c)
		}
	})
	t.Run("other message on control stream", func(t *testing.T) {
		checkLeaks(t)
		r, _ := connected(t, nil)
		write(t, r.ctrl, wire.MsgSubscribe, subscribeMsg(0, Namespace{"a"}, "b", nil))
		if c := r.closedWith(); c != CodeProtocolViolation {
			t.Fatalf("closed with %v", c)
		}
	})
	t.Run("control stream closed", func(t *testing.T) {
		checkLeaks(t)
		r, _ := connected(t, nil)
		r.ctrl.Close()
		if c := r.closedWith(); c != CodeProtocolViolation {
			t.Fatalf("closed with %v", c)
		}
	})
}

func TestObjectTooLarge(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, &Config{MaxObjectSize: 1024})
	ctx := testCtx(t)
	subc := make(chan *Subscription, 1)
	go func() {
		sub, err := s.Subscribe(ctx, Namespace{"a"}, "t", nil)
		if err != nil {
			t.Error(err)
		}
		subc <- sub
	}()
	st, _, _ := r.accept()
	write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 7, Params: &wire.MessageParams{}})
	sub := <-subc
	ds, err := r.conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := &wire.SubgroupHeader{Flags: wire.SubgroupTypeBit | wire.SubgroupDefaultPrio, TrackAlias: 7}
	b := h.Append(nil)
	b = append(b, 0)                // object ID delta
	b = wire.AppendVarint(b, 1<<40) // payload length
	mustSend(t, ds, b)
	if _, err := sub.ReadObject(ctx); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("err %v", err)
	}
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
}

func TestMalformedTrack(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	subc := make(chan *Subscription, 1)
	go func() {
		sub, err := s.Subscribe(ctx, Namespace{"a"}, "t", nil)
		if err != nil {
			t.Error(err)
		}
		subc <- sub
	}()
	st, _, _ := r.accept()
	write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 1, Params: &wire.MessageParams{}})
	sub := <-subc
	ds, err := r.conn.OpenUniStream(ctx)
	if err != nil {
		t.Fatal(err)
	}
	h := &wire.SubgroupHeader{Flags: wire.SubgroupTypeBit | wire.SubgroupDefaultPrio | wire.SubgroupProperties, TrackAlias: 1}
	var w wire.SubgroupWriter
	// A mandatory track property must never appear on an object.
	mustSend(t, ds, appendObject(&w, h.Append(nil), &wire.Object{Properties: []wire.KV{{Type: 0x4000, Value: 1}}, Payload: []byte("x")}))
	if _, err := sub.ReadObject(ctx); !errors.Is(err, ErrMalformedTrack) {
		t.Fatalf("err %v", err)
	}
}

func TestDuplicateTrackAlias(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	for _, name := range []string{"one", "two"} {
		done := make(chan error, 1)
		go func() {
			_, err := s.Subscribe(ctx, Namespace{"a"}, name, nil)
			done <- err
		}()
		st, _, _ := r.accept()
		write(t, st, wire.MsgSubscribeOK, &wire.SubscribeOK{TrackAlias: 3, Params: &wire.MessageParams{}})
		err := <-done
		if name == "two" {
			sessionErr(t, err, CodeDuplicateTrackAlias)
		} else if err != nil {
			t.Fatal(err)
		}
	}
}

func TestNamespaceDoneBeforeNamespace(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, nil)
	ctx := testCtx(t)
	nsc := make(chan *NamespaceSubscription, 1)
	go func() {
		n, err := s.SubscribeNamespace(ctx, Namespace{"a"})
		if err != nil {
			t.Error(err)
		}
		nsc <- n
	}()
	st, _, _ := r.accept()
	write(t, st, wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}})
	n := <-nsc
	write(t, st, wire.MsgNamespaceDone, nsSuffix{"b"})
	if _, err := n.Next(ctx); err == nil {
		t.Fatal("no error")
	}
	sessionErr(t, s.Err(), CodeProtocolViolation)
}

func TestTooManyNamespaces(t *testing.T) {
	checkLeaks(t)
	r, s := serving(t, &Config{MaxNamespaces: 3})
	ctx := testCtx(t)
	nsc := make(chan *NamespaceSubscription, 1)
	go func() {
		n, err := s.SubscribeNamespace(ctx, nil)
		if err != nil {
			t.Error(err)
		}
		nsc <- n
	}()
	st, _, _ := r.accept()
	write(t, st, wire.MsgRequestOK, &wire.RequestOK{Params: &wire.MessageParams{}})
	n := <-nsc
	for i := range 5 {
		write(t, st, wire.MsgNamespace, nsSuffix{string(rune('a' + i))})
	}
	for i := range 3 {
		if _, err := n.Next(ctx); err != nil {
			t.Fatal(i, err)
		}
	}
	if _, err := n.Next(ctx); !errors.Is(err, ErrTooManyNamespaces) {
		t.Fatalf("err %v", err)
	}
	if s.Err() != nil {
		t.Fatal(s.Err())
	}
}
