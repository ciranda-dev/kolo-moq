package kolomoq

import (
	"bytes"
	"cmp"
	"errors"
	"fmt"
	"io"
	"slices"
	"testing"
)

func TestPublishSubscribe(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"example", "room"}
	tw, err := origin.CreateTrack(ns, "video", nil)
	if err != nil {
		t.Fatal(err)
	}
	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	sub, err := p.client.Subscribe(ctx, ns, "video", nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := p.client.PeerImplementation(); got != "kolo-moq" {
		t.Errorf("peer implementation %q", got)
	}
	prop := Property{Type: 0x79, Bytes: []byte("meta")}
	for g := range 3 {
		gw, err := tw.NewGroup()
		if err != nil {
			t.Fatal(err)
		}
		for i := range 4 {
			props := []Property{{Type: 0x78, Value: uint64(i)}}
			if i == 0 {
				props = append(props, prop)
			}
			if _, err := gw.WriteObject([]byte(fmt.Sprintf("g%d-o%d", g, i)), props...); err != nil {
				t.Fatal(err)
			}
		}
		if err := gw.Close(); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	var got []Object
	for {
		o, err := sub.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, o)
	}
	slices.SortStableFunc(got, func(a, b Object) int { return cmp.Compare(a.Group, b.Group) })
	// 3 groups of 4 objects and an End of Group each, then End of Track
	// in a group of its own.
	if len(got) != 16 {
		t.Fatalf("got %d objects", len(got))
	}
	for g := range 3 {
		for i := range 4 {
			o := got[g*5+i]
			if o.Group != uint64(g) || o.ID != uint64(i) || o.Status != StatusNormal {
				t.Fatalf("object %d/%d: %+v", g, i, o)
			}
			if want := fmt.Sprintf("g%d-o%d", g, i); string(o.Payload) != want {
				t.Fatalf("payload %q, want %q", o.Payload, want)
			}
			if o.Priority != DefaultPriority {
				t.Fatalf("priority %d", o.Priority)
			}
			wantProps := 1
			if i == 0 {
				wantProps = 2
			}
			if len(o.Properties) != wantProps || o.Properties[0].Type != 0x78 || o.Properties[0].Value != uint64(i) {
				t.Fatalf("properties %+v", o.Properties)
			}
			if i == 0 && (o.Properties[1].Type != 0x79 || !bytes.Equal(o.Properties[1].Bytes, []byte("meta"))) {
				t.Fatalf("properties %+v", o.Properties)
			}
		}
		if end := got[g*5+4]; end.Status != StatusEndOfGroup || end.ID != 4 {
			t.Fatalf("end marker %+v", end)
		}
	}
	if end := got[15]; end.Status != StatusEndOfTrack || end.Group != 3 || end.ID != 0 {
		t.Fatalf("end of track %+v", end)
	}
	if _, err := sub.ReadObject(ctx); err != io.EOF {
		t.Fatalf("after end: %v", err)
	}
}

func TestSubscribeUnknownTrack(t *testing.T) {
	checkLeaks(t)
	p := newPair(t, nil, &Config{Origin: newOrigin(t)})
	_, err := p.client.Subscribe(testCtx(t), Namespace{"none"}, "x", nil)
	if requestCode(err) != ReqDoesNotExist {
		t.Fatalf("err %v", err)
	}
	if p.client.Err() != nil {
		t.Fatal(p.client.Err())
	}
}

func TestSessionClose(t *testing.T) {
	checkLeaks(t)
	p := newPair(t, nil, nil)
	p.client.Close()
	<-p.server.Done()
	var se *SessionError
	if !errors.As(p.server.Err(), &se) || se.Code != CodeNoError || !se.Remote {
		t.Fatalf("server err %v", p.server.Err())
	}
	if !errors.Is(p.client.Err(), ErrClosed) {
		t.Fatalf("client err %v", p.client.Err())
	}
}
