package kolomoq

import (
	"errors"
	"fmt"
	"testing"
)

func TestOriginTrackCap(t *testing.T) {
	o, err := NewOrigin(nil)
	if err != nil {
		t.Fatal(err)
	}
	for i := range 1200 {
		if _, err := o.CreateTrack(Namespace{"room"}, fmt.Sprint("t", i), nil); err != nil {
			t.Fatalf("track %d with no cap: %v", i, err)
		}
	}
	o, err = NewOrigin(&OriginConfig{MaxTracks: 2})
	if err != nil {
		t.Fatal(err)
	}
	for i := range 2 {
		if _, err := o.CreateTrack(Namespace{"room"}, fmt.Sprint("t", i), nil); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := o.CreateTrack(Namespace{"room"}, "t2", nil); !errors.Is(err, ErrTooManyTracks) {
		t.Fatalf("track over MaxTracks: %v", err)
	}
	if _, err := NewOrigin(&OriginConfig{MaxTracks: -1}); !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("MaxTracks -1: %v", err)
	}
}
