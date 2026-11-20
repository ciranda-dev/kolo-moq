package secobj

import (
	"cmp"
	"math"
	"slices"
)

const (
	// defaultReplayGroups is the RFC 3711 section 3.3.2 minimum window.
	defaultReplayGroups = 64
	// defaultReplayObjects matches kolo-media's playout MaxFrames.
	defaultReplayObjects = 8192
	// replayKIDs matches the keys a receiver holds per sender: the current and the previous one.
	replayKIDs = 2
)

// replayWindow remembers the authenticated (Key ID, Group ID, Object ID) of one track.
// It is not safe for concurrent use.
type replayWindow struct {
	maxGroups  uint64
	maxObjects int
	n          int
	minKID     uint64 // lower Key IDs were dropped
	kids       []kidWindow
}

type kidWindow struct {
	kid    uint64
	newest uint64
	floor  uint64 // lower groups are refused
	closed bool   // group 2^64-1 was dropped, so every group is refused
	groups []groupObjects
}

type groupObjects struct {
	id      uint64
	objects []uint32 // ascending
}

// newReplayWindow refuses groups more than groups behind the newest and holds at most
// objects entries; groups >= 0 and objects >= 1.
func newReplayWindow(groups, objects int) *replayWindow {
	return &replayWindow{maxGroups: uint64(groups), maxObjects: objects}
}

// check records an authenticated object, or returns ErrReplay if it was seen or falls outside
// the window.
func (w *replayWindow) check(kid, group uint64, object uint32) error {
	if kid < w.minKID {
		return ErrReplay
	}
	kw := w.kidWindow(kid)
	if kw == nil {
		return ErrReplay
	}
	if kw.closed || group < kw.floor {
		return ErrReplay
	}
	if group > kw.newest {
		kw.newest = group
		if f := group - min(group, w.maxGroups); f > kw.floor {
			kw.floor = f
		}
		i := 0
		for i < len(kw.groups) && kw.groups[i].id < kw.floor {
			w.n -= len(kw.groups[i].objects)
			i++
		}
		kw.groups = slices.Delete(kw.groups, 0, i)
	}
	gi, found := slices.BinarySearchFunc(kw.groups, group, func(g groupObjects, id uint64) int { return cmp.Compare(g.id, id) })
	if !found {
		kw.groups = slices.Insert(kw.groups, gi, groupObjects{id: group})
	}
	g := &kw.groups[gi]
	oi, found := slices.BinarySearch(g.objects, object)
	if found {
		return ErrReplay
	}
	g.objects = slices.Insert(g.objects, oi, object)
	w.n++
	for w.n > w.maxObjects {
		if w.evictOldest(kid, group) {
			return ErrReplay
		}
	}
	return nil
}

// kidWindow returns the window of kid, creating it and dropping the lowest Key ID beyond
// replayKIDs. It returns nil if kid itself would be dropped.
func (w *replayWindow) kidWindow(kid uint64) *kidWindow {
	for i := range w.kids {
		if w.kids[i].kid == kid {
			return &w.kids[i]
		}
	}
	if len(w.kids) == replayKIDs {
		low := 0
		for i := range w.kids {
			if w.kids[i].kid < w.kids[low].kid {
				low = i
			}
		}
		if kid < w.kids[low].kid {
			return nil
		}
		for _, g := range w.kids[low].groups {
			w.n -= len(g.objects)
		}
		w.minKID = w.kids[low].kid + 1
		w.kids = slices.Delete(w.kids, low, low+1)
	}
	w.kids = append(w.kids, kidWindow{kid: kid})
	return &w.kids[len(w.kids)-1]
}

// evictOldest drops the oldest group of the lowest Key ID that has one and reports whether
// that group was (kid, group).
func (w *replayWindow) evictOldest(kid, group uint64) bool {
	low := -1
	for i := range w.kids {
		if len(w.kids[i].groups) > 0 && (low < 0 || w.kids[i].kid < w.kids[low].kid) {
			low = i
		}
	}
	kw := &w.kids[low]
	g := kw.groups[0]
	w.n -= len(g.objects)
	kw.groups = slices.Delete(kw.groups, 0, 1)
	if g.id == math.MaxUint64 {
		kw.closed = true
	} else {
		kw.floor = g.id + 1
	}
	return kw.kid == kid && g.id == group
}

// reset forgets everything, for a sender that restarted with new keys.
func (w *replayWindow) reset() {
	w.n, w.minKID, w.kids = 0, 0, nil
}
