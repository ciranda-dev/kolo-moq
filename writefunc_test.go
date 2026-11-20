package kolomoq

import (
	"errors"
	"fmt"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

func TestWriteObjectFunc(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	ns := Namespace{"wf"}
	tw := mustTrack(t, origin, ns, "t", &TrackOptions{})
	gw := mustGroup(t, tw)
	prop := Property{Type: 0x3802, Value: 9}
	var seen []uint64
	for i := range 3 {
		id, err := gw.WriteObjectFunc(func(id uint64) ([]byte, []Property, error) {
			seen = append(seen, id)
			return []byte(fmt.Sprintf("obj%d", id)), []Property{prop}, nil
		})
		if err != nil || id != uint64(i) {
			t.Fatalf("write %d: id %d %v", i, id, err)
		}
	}
	// WriteObject takes the next ID after WriteObjectFunc and the reverse.
	if id, err := gw.WriteObject([]byte("plain")); err != nil || id != 3 {
		t.Fatalf("WriteObject: %d %v", id, err)
	}
	if id, err := gw.WriteObjectFunc(func(id uint64) ([]byte, []Property, error) { return nil, nil, nil }); err != nil || id != 4 {
		t.Fatalf("empty object: %d %v", id, err)
	}
	if fmt.Sprint(seen) != "[0 1 2]" {
		t.Fatalf("build saw %v", seen)
	}

	p := newPair(t, nil, &Config{Origin: origin})
	ctx := testCtx(t)
	f, err := p.client.Fetch(ctx, ns, "t", nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, want := range []string{"obj0", "obj1", "obj2", "plain", ""} {
		o, err := f.ReadObject(ctx)
		if err != nil || o.ID != uint64(i) || string(o.Payload) != want {
			t.Fatalf("object %d: %+v %v", i, o, err)
		}
		if i < 3 && (len(o.Properties) != 1 || o.Properties[0].Type != prop.Type || o.Properties[0].Value != prop.Value) {
			t.Fatalf("object %d properties %+v", i, o.Properties)
		}
	}
}

func TestWriteObjectFuncFailureKeepsID(t *testing.T) {
	checkLeaks(t)
	origin, err := NewOrigin(&OriginConfig{MaxObjectSize: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	tw := mustTrack(t, origin, Namespace{"wf"}, "t", nil)
	gw := mustGroup(t, tw)
	boom := errors.New("boom")
	ok := func(id uint64) ([]byte, []Property, error) { return []byte("ok"), nil, nil }
	for name, tc := range map[string]struct {
		build func(uint64) ([]byte, []Property, error)
		want  error
	}{
		"build error":  {func(uint64) ([]byte, []Property, error) { return []byte("x"), nil, boom }, boom},
		"too large":    {func(uint64) ([]byte, []Property, error) { return make([]byte, 1<<10+1), nil, nil }, ErrObjectTooLarge},
		"bad property": {func(uint64) ([]byte, []Property, error) { return nil, []Property{{Type: 2, Bytes: []byte("x")}}, nil }, ErrInvalidProperty},
		"nested 0x0B": {func(uint64) ([]byte, []Property, error) {
			return nil, []Property{{Type: wire.PropImmutable, Bytes: wire.AppendKVs(nil, []wire.KV{{Type: wire.PropImmutable}})}}, nil
		}, ErrInvalidProperty},
		"two 0x0B": {func(uint64) ([]byte, []Property, error) { return nil, []Property{{Type: 0x0B}, {Type: 0x0B}}, nil }, ErrInvalidProperty},
		"properties big": {func(uint64) ([]byte, []Property, error) {
			return nil, []Property{{Type: 1, Bytes: make([]byte, 65535)}, {Type: 3, Bytes: make([]byte, 65535)}}, nil
		}, ErrInvalidProperty},
	} {
		id, err := gw.WriteObjectFunc(tc.build)
		if !errors.Is(err, tc.want) || id != 0 {
			t.Fatalf("%s: id %d, %v", name, id, err)
		}
		if got, err := gw.WriteObjectFunc(ok); err != nil || got != 0 {
			t.Fatalf("%s: the next write got id %d, %v", name, got, err)
		}
		gw = mustGroup(t, tw)
	}
}

func TestWriteObjectFuncClosed(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"wf"}, "t", nil)
	gw := mustGroup(t, tw)
	gw.Close()
	called := false
	if _, err := gw.WriteObjectFunc(func(uint64) ([]byte, []Property, error) { called = true; return nil, nil, nil }); !errors.Is(err, ErrClosed) || called {
		t.Fatalf("closed group: %v, build called %v", err, called)
	}
	gw = mustGroup(t, tw)
	tw.Close()
	if _, err := gw.WriteObjectFunc(func(uint64) ([]byte, []Property, error) { called = true; return nil, nil, nil }); !errors.Is(err, ErrClosed) || called {
		t.Fatalf("closed track: %v, build called %v", err, called)
	}
}

// kolo-media relies on WriteObject checking the size before the state of the
// group, to test whether a payload fits without opening a group.
func TestWriteObjectChecksSizeBeforeClosed(t *testing.T) {
	checkLeaks(t)
	origin, err := NewOrigin(&OriginConfig{MaxObjectSize: 1 << 10})
	if err != nil {
		t.Fatal(err)
	}
	tw := mustTrack(t, origin, Namespace{"wf"}, "t", nil)
	gw := mustGroup(t, tw)
	gw.Close()
	if _, err := gw.WriteObject(make([]byte, 1<<10+1)); !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("oversized object on a closed group: %v", err)
	}
	if _, err := gw.WriteObject([]byte("x")); !errors.Is(err, ErrClosed) {
		t.Fatalf("object on a closed group: %v", err)
	}
}

func TestWriteObjectFuncCopies(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"wf"}, "t", nil)
	gw := mustGroup(t, tw)
	payload, b := []byte("abc"), []byte("xyz")
	if _, err := gw.WriteObjectFunc(func(uint64) ([]byte, []Property, error) {
		return payload, []Property{{Type: 0x3803, Bytes: b}}, nil
	}); err != nil {
		t.Fatal(err)
	}
	payload[0], b[0] = 'Z', 'Z'
	objs := tw.t.snapshot(wire.Location{}, wire.Location{Group: 1}, OrderAscending)
	if len(objs) != 1 || string(objs[0].obj.Payload) != "abc" || string(objs[0].obj.Properties[0].Bytes) != "xyz" {
		t.Fatalf("cached %+v", objs)
	}
}

// TestWriteObjectFuncRace has many writers use one group; the ID each build
// call received must be the ID the object was published with, and no two build
// calls overlap.
func TestWriteObjectFuncRace(t *testing.T) {
	checkLeaks(t)
	origin := newOrigin(t)
	tw := mustTrack(t, origin, Namespace{"wf"}, "t", &TrackOptions{CacheGroups: 1})
	gw := mustGroup(t, tw)
	const writers, each = 8, 50
	var inBuild atomic.Int32
	var wg sync.WaitGroup
	errs := make(chan error, 3*writers*each)
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				var built uint64
				id, err := gw.WriteObjectFunc(func(id uint64) ([]byte, []Property, error) {
					if inBuild.Add(1) != 1 {
						errs <- errors.New("build calls overlap")
					}
					defer inBuild.Add(-1)
					built = id
					return []byte("id=" + strconv.FormatUint(id, 10)), nil, nil
				})
				switch {
				case err != nil:
					errs <- err
				case id != built:
					errs <- fmt.Errorf("writer %d: built id %d, published id %d", w, built, id)
				}
				if w%2 == 0 {
					if _, err := gw.WriteObject([]byte("plain")); err != nil {
						errs <- err
					}
				}
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	objs := tw.t.snapshot(wire.Location{}, wire.Location{Group: 1}, OrderAscending)
	if want := writers*each + writers/2*each; len(objs) != want {
		t.Fatalf("%d objects, want %d", len(objs), want)
	}
	for i, e := range objs {
		if e.obj.ID != uint64(i) {
			t.Fatalf("object %d has ID %d", i, e.obj.ID)
		}
		if s := string(e.obj.Payload); s != "plain" && s != "id="+strconv.Itoa(i) {
			t.Fatalf("object %d carries %q", i, s)
		}
	}
}
