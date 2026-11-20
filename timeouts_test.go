package kolomoq

import (
	"bytes"
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// immutableProp is an Immutable Properties property (draft section 10.7)
// holding kvs.
func immutableProp(kvs ...wire.KV) Property {
	return Property{Type: wire.PropImmutable, Bytes: wire.AppendKVs(nil, kvs)}
}

// keyIDProp is the Key ID property of a protected object: type 0x78 inside
// Immutable Properties.
func keyIDProp(kid uint64) Property { return immutableProp(wire.KV{Type: 0x78, Value: kid}) }

func TestObjectTimeouts(t *testing.T) {
	const a, b = 5 * time.Second, 7 * time.Second
	imm := func(kvs ...wire.KV) wire.KV {
		return wire.KV{Type: wire.PropImmutable, Bytes: wire.AppendKVs(nil, kvs)}
	}
	for name, tc := range map[string]struct {
		kvs          []wire.KV
		wantO, wantS time.Duration
	}{
		"none":                   {nil, a, b},
		"top level object":       {[]wire.KV{{Type: 0x02, Value: 30}}, 30 * time.Millisecond, b},
		"top level subgroup":     {[]wire.KV{{Type: 0x06, Value: 40}}, a, 40 * time.Millisecond},
		"inside 0x0B object":     {[]wire.KV{imm(wire.KV{Type: 0x02, Value: 30})}, 30 * time.Millisecond, b},
		"inside 0x0B subgroup":   {[]wire.KV{imm(wire.KV{Type: 0x06, Value: 40})}, a, 40 * time.Millisecond},
		"inside 0x0B both":       {[]wire.KV{imm(wire.KV{Type: 0x02, Value: 30}, wire.KV{Type: 0x06, Value: 40})}, 30 * time.Millisecond, 40 * time.Millisecond},
		"inside 0x0B overrides":  {[]wire.KV{{Type: 0x02, Value: 90}, imm(wire.KV{Type: 0x02, Value: 30})}, 30 * time.Millisecond, b},
		"inside 0x0B, 0 means 0": {[]wire.KV{imm(wire.KV{Type: 0x02, Value: 0})}, 0, b},
		"Key ID 0x78":            {[]wire.KV{imm(wire.KV{Type: 0x78, Value: 1})}, a, b},
		"other properties":       {[]wire.KV{{Type: 0x3803, Bytes: []byte("x")}, imm(wire.KV{Type: 0x04, Value: 1})}, a, b},
		"unparsable 0x0B":        {[]wire.KV{{Type: 0x0B, Bytes: []byte{0x02}}}, a, b},
		"huge value":             {[]wire.KV{imm(wire.KV{Type: 0x02, Value: 1<<62 - 1})}, ms(1<<62 - 1), b},
	} {
		if o, s := objectTimeouts(tc.kvs, a, b); o != tc.wantO || s != tc.wantS {
			t.Errorf("%s: got %v and %v, want %v and %v", name, o, s, tc.wantO, tc.wantS)
		}
	}
	for _, kid := range append(rangeIDs(301), 1<<14, 1<<30, 1<<62-1) {
		kvs := []wire.KV{{Type: wire.PropImmutable, Bytes: wire.AppendKVs(nil, []wire.KV{{Type: 0x78, Value: kid}})}}
		if o, s := objectTimeouts(kvs, a, b); o != a || s != b {
			t.Fatalf("Key ID %d changed the timeouts to %v and %v", kid, o, s)
		}
	}
}

func rangeIDs(n int) []uint64 {
	out := make([]uint64, n)
	for i := range out {
		out[i] = uint64(i)
	}
	return out
}

// bigObjects fills a group beyond the stream's flow control window.
func bigObjects(t *testing.T, gw *GroupWriter, first Property) {
	t.Helper()
	big := make([]byte, 64<<10)
	if _, err := gw.WriteObject(big, first); err != nil {
		t.Fatal(err)
	}
	for range 15 {
		mustWrite(t, gw, big)
	}
}

func TestDeliveryTimeoutsInsideImmutable(t *testing.T) {
	checkLeaks(t)
	for name, tc := range map[string]struct {
		prop  Property
		close bool
	}{
		"object timeout":   {immutableProp(wire.KV{Type: 0x02, Value: 50}), false},
		"subgroup timeout": {immutableProp(wire.KV{Type: 0x06, Value: 50}), true},
	} {
		origin := newOrigin(t)
		ns := Namespace{"imm"}
		tw := mustTrack(t, origin, ns, "t", nil)
		r, s := stalledSubscriber(t, &Config{Origin: origin}, ns, "t", nil)
		gw := mustGroup(t, tw)
		bigObjects(t, gw, tc.prop)
		if tc.close {
			gw.Close()
		}
		eventually(t, name+" expiry", func() bool { return s.Stats().ExpiredGroups == 1 })
		if codes := readResets(t, r, 1); !slices.Equal(codes, []uint64{resetDeliveryTimeout}) {
			t.Fatalf("%s: reset codes %v", name, codes)
		}
	}
}

// TestKeyIDDoesNotChangeDelivery checks that a Key ID property, of any value,
// neither expires the stream of a stalled subscriber nor is changed on its way
// through a relay.
func TestKeyIDDoesNotChangeDelivery(t *testing.T) {
	checkLeaks(t)
	kids := append(rangeIDs(301), 1<<14, 1<<30, 1<<62-1)
	origin := newOrigin(t)
	ns := Namespace{"kid"}
	tw := mustTrack(t, origin, ns, "stalled", nil)
	_, s := stalledSubscriber(t, &Config{Origin: origin, MaxBufferedGroups: 1000}, ns, "stalled", nil)
	for _, kid := range []uint64{0, 1, 2, 127, 128, 300, 1 << 30} {
		bigObjects(t, mustGroup(t, tw), keyIDProp(kid))
	}
	time.Sleep(500 * time.Millisecond)
	if st := s.Stats(); st.ExpiredGroups != 0 {
		t.Fatalf("expired groups %d", st.ExpiredGroups)
	}

	for name, viaRelay := range map[string]bool{"direct": false, "relay": true} {
		origin := newOrigin(t)
		cfg := &Config{Origin: origin, MaxBufferedGroups: 1000}
		tw := mustTrack(t, origin, ns, name, &TrackOptions{CacheGroups: 1000})
		var client *Session
		var served []*Session
		if viaRelay {
			rl := newRelay(t, &RelayConfig{CacheGroups: 1000, Session: Config{MaxBufferedGroups: 1000}})
			pub, pubOnRelay := joinRelay(t, rl, cfg)
			if _, err := pub.PublishNamespace(testCtx(t), ns); err != nil {
				t.Fatal(err)
			}
			var subOnRelay *Session
			client, subOnRelay = joinRelay(t, rl, &Config{MaxBufferedGroups: 1000})
			served = []*Session{pubOnRelay, subOnRelay, pub}
		} else {
			p := newPair(t, &Config{MaxBufferedGroups: 1000}, cfg)
			client, served = p.client, []*Session{p.server}
		}
		ctx := testCtx(t)
		sub, err := client.Subscribe(ctx, ns, name, nil)
		if err != nil {
			t.Fatal(err)
		}
		eventually(t, name+" subscription", func() bool { return tw.Subscribers() == 1 })
		for _, kid := range kids {
			gw := mustGroup(t, tw)
			if _, err := gw.WriteObject([]byte(fmt.Sprint(kid)), keyIDProp(kid)); err != nil {
				t.Fatal(err)
			}
		}
		got := map[string]Object{}
		for len(got) < len(kids) {
			o, err := sub.ReadObject(ctx)
			if err != nil {
				t.Fatalf("%s: after %d objects: %v", name, len(got), err)
			}
			if o.Status == StatusNormal {
				got[string(o.Payload)] = o
			}
		}
		for _, kid := range kids {
			o, ok := got[fmt.Sprint(kid)]
			if !ok || len(o.Properties) != 1 || o.Properties[0].Type != wire.PropImmutable || !bytes.Equal(o.Properties[0].Bytes, keyIDProp(kid).Bytes) {
				t.Fatalf("%s: Key ID %d arrived as %+v", name, kid, o)
			}
		}
		for _, sess := range served {
			if st := sess.Stats(); st.ExpiredGroups != 0 || st.ResetGroups != 0 {
				t.Fatalf("%s: stats %+v", name, st)
			}
		}
	}
}
