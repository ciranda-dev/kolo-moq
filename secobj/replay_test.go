package secobj

import (
	"fmt"
	"testing"
)

type replayStep struct {
	kid, group uint64
	object     uint32
	want       error
}

func runReplay(t *testing.T, w *replayWindow, steps []replayStep) {
	t.Helper()
	for i, s := range steps {
		if err := w.check(s.kid, s.group, s.object); err != s.want {
			t.Fatalf("step %d (kid %d, group %d, object %d): got %v, want %v", i, s.kid, s.group, s.object, err, s.want)
		}
		checkReplayInvariants(t, w)
	}
}

func checkReplayInvariants(t *testing.T, w *replayWindow) {
	t.Helper()
	n := 0
	if len(w.kids) > replayKIDs {
		t.Fatalf("%d key IDs held", len(w.kids))
	}
	for _, kw := range w.kids {
		if kw.kid < w.minKID {
			t.Fatalf("key ID %d below %d held", kw.kid, w.minKID)
		}
		for i, g := range kw.groups {
			if g.id < kw.floor || g.id > kw.newest || kw.newest-g.id > w.maxGroups || len(g.objects) == 0 {
				t.Fatalf("group %d outside [%d, %d] or empty", g.id, kw.floor, kw.newest)
			}
			if i > 0 && kw.groups[i-1].id >= g.id {
				t.Fatal("groups not ascending")
			}
			for j := 1; j < len(g.objects); j++ {
				if g.objects[j-1] >= g.objects[j] {
					t.Fatal("objects not ascending")
				}
			}
			n += len(g.objects)
		}
	}
	if n != w.n || n > w.maxObjects {
		t.Fatalf("count %d, recorded %d, max %d", n, w.n, w.maxObjects)
	}
}

func TestReplayDuplicates(t *testing.T) {
	w := newReplayWindow(defaultReplayGroups, defaultReplayObjects)
	runReplay(t, w, []replayStep{
		{1, 0, 0, nil},
		{1, 0, 0, ErrReplay}, // the same object from a FETCH after the subscription
		{1, 0, 1, nil},
		{1, 1, 0, nil},
		{1, 0, 1, ErrReplay},
		{1, 0, 3, nil}, // a gap is not a replay
		{1, 0, 2, nil}, // nor is a late object
		{1, 0, 2, ErrReplay},
		{2, 0, 0, nil}, // the same location under the next key
		{2, 0, 0, ErrReplay},
		{1, 1, 0, ErrReplay}, // the previous key is still checked
		{1, 2, 0, nil},
	})
}

func TestReplayGroupWindow(t *testing.T) {
	w := newReplayWindow(64, 8192)
	runReplay(t, w, []replayStep{
		{0, 30, 0, nil},
		{0, 100, 0, nil},
		{0, 36, 0, nil},         // 64 groups behind the newest
		{0, 35, 0, ErrReplay},   // 65 groups behind
		{0, 30, 1, ErrReplay},   // dropped with its group
		{0, 30, 0, ErrReplay},   // replayed after it left the window
		{0, 99, 0, nil},         // late but inside
		{0, 1 << 40, 0, nil},    // a jump moves the window
		{0, 100, 1, ErrReplay},  // far behind now
		{0, 1<<40 - 64, 0, nil}, // still inside
		{0, 1<<40 - 65, 0, ErrReplay},
	})
	if w.n != 2 {
		t.Fatalf("%d entries left, want 2", w.n)
	}

	w = newReplayWindow(0, 8192)
	runReplay(t, w, []replayStep{
		{0, 5, 0, nil},
		{0, 5, 1, nil},
		{0, 4, 0, ErrReplay},
		{0, 6, 0, nil},
		{0, 5, 2, ErrReplay},
	})
}

func TestReplayObjectCap(t *testing.T) {
	w := newReplayWindow(64, 4)
	runReplay(t, w, []replayStep{
		{0, 1, 0, nil},
		{0, 1, 1, nil},
		{0, 2, 0, nil},
		{0, 2, 1, nil},
		{0, 3, 0, nil},       // drops group 1, the oldest
		{0, 1, 2, ErrReplay}, // group 1 is forgotten, so it is refused
		{0, 2, 1, ErrReplay}, // group 2 is still remembered
		{0, 2, 2, nil},
		{0, 2, 3, ErrReplay}, // accepting it would drop group 2 itself
		{0, 2, 4, ErrReplay}, // and group 2 is now forgotten
		{0, 3, 1, nil},
		{0, 4, 0, nil},
	})

	// A window full of one group refuses the rest of that group.
	w = newReplayWindow(64, 3)
	runReplay(t, w, []replayStep{
		{0, 0, 0, nil},
		{0, 0, 1, nil},
		{0, 0, 2, nil},
		{0, 0, 3, ErrReplay},
		{0, 0, 4, ErrReplay},
		{0, 1, 0, nil},
		{0, 0, 0, ErrReplay},
	})

	// The previous key's groups go first.
	w = newReplayWindow(64, 2)
	runReplay(t, w, []replayStep{
		{1, 9, 0, nil},
		{2, 0, 0, nil},
		{2, 0, 1, nil}, // drops key 1's group 9
		{1, 9, 1, ErrReplay},
		{2, 0, 0, ErrReplay},
		{2, 1, 0, nil}, // drops key 2's group 0
		{2, 0, 2, ErrReplay},
	})
}

func TestReplayKeyIDs(t *testing.T) {
	w := newReplayWindow(64, 8192)
	runReplay(t, w, []replayStep{
		{5, 0, 0, nil},
		{7, 0, 0, nil},
		{3, 0, 0, ErrReplay}, // older than both held key IDs
		{8, 0, 0, nil},       // drops key 5
		{5, 0, 1, ErrReplay},
		{6, 0, 0, ErrReplay}, // below the dropped key ID
		{7, 0, 0, ErrReplay},
		{7, 0, 1, nil},
		{8, 0, 1, nil},
	})
	w.reset()
	runReplay(t, w, []replayStep{
		{0, 0, 0, nil}, // a restarted sender begins at Key ID 0 again
		{7, 0, 0, nil},
		{0, 0, 0, ErrReplay},
	})
}

func TestReplayMaxGroup(t *testing.T) {
	const top = 1<<64 - 1
	w := newReplayWindow(64, 2)
	runReplay(t, w, []replayStep{
		{0, top, 0, nil},
		{0, top - 64, 0, nil},
		{0, top - 65, 0, ErrReplay},
		{0, top, 1, nil},       // drops group top-64
		{0, top, 2, ErrReplay}, // drops group 2^64-1 itself
		{0, top, 3, ErrReplay},
		{0, top - 1, 0, ErrReplay},
		{1, 0, 0, nil},
	})
}

func TestReplayDefaults(t *testing.T) {
	w := newReplayWindow(defaultReplayGroups, defaultReplayObjects)
	for o := range uint32(defaultReplayObjects) {
		if err := w.check(0, 0, o); err != nil {
			t.Fatalf("object %d: %v", o, err)
		}
	}
	if err := w.check(0, 0, defaultReplayObjects); err != ErrReplay {
		t.Fatalf("object %d: %v", defaultReplayObjects, err)
	}
	checkReplayInvariants(t, w)
	w.reset()
	if err := w.check(0, defaultReplayGroups, 0); err != nil {
		t.Fatal(err)
	}
	if err := w.check(0, 0, 0); err != nil {
		t.Fatalf("group %d behind: %v", defaultReplayGroups, err)
	}
	if err := w.check(0, defaultReplayGroups+1, 0); err != nil {
		t.Fatal(err)
	}
	if err := w.check(0, 0, 1); err != ErrReplay {
		t.Fatalf("group %d behind: %v", defaultReplayGroups+1, err)
	}
}

// TestReplayNeverAcceptsTwice feeds random, often repeated, objects and checks that no
// (Key ID, Group ID, Object ID) is accepted twice and the bounds hold.
func TestReplayNeverAcceptsTwice(t *testing.T) {
	for _, limits := range [][2]int{{0, 1}, {1, 3}, {4, 16}, {64, 100}, {64, 8192}} {
		t.Run(fmt.Sprint(limits), func(t *testing.T) {
			w := newReplayWindow(limits[0], limits[1])
			seed := uint64(limits[0]*1000 + limits[1] + 1)
			rnd := func(n uint64) uint64 {
				seed ^= seed << 13
				seed ^= seed >> 7
				seed ^= seed << 17
				return seed % n
			}
			type loc struct {
				kid, group uint64
				object     uint32
			}
			seen := map[loc]bool{}
			accepted := 0
			var kid, group uint64
			for range 50000 {
				switch rnd(100) {
				case 0:
					kid++
				case 1, 2, 3:
					group += rnd(5)
				}
				l := loc{kid - min(kid, rnd(3)), group - min(group, rnd(80)), uint32(rnd(20))}
				err := w.check(l.kid, l.group, l.object)
				if err == nil {
					if seen[l] {
						t.Fatalf("%+v accepted twice", l)
					}
					seen[l] = true
					accepted++
				} else if err != ErrReplay {
					t.Fatal(err)
				}
				checkReplayInvariants(t, w)
			}
			if accepted == 0 {
				t.Fatal("nothing accepted")
			}
		})
	}
}
