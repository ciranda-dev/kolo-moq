package kolomoq

import (
	"crypto/ed25519"
	"fmt"
	"time"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// Config sets the behavior and limits of a Session. A zero field takes its
// default.
type Config struct {
	// Origin holds the tracks this side publishes. Nil means requests for tracks are answered DOES_NOT_EXIST.
	Origin *Origin
	// Authorize decides each request from the peer: a non-nil error refuses it with UNAUTHORIZED.
	// Nil allows every request; the peer is already authenticated by its kolo-id key.
	Authorize func(peer ed25519.PublicKey, kind RequestKind, ns Namespace, track string) error

	// SetupTimeout bounds the exchange of version prefaces and SETUP. Default 10s, from 1s to 10m.
	SetupTimeout time.Duration
	// RequestTimeout bounds the wait for a response, for the first message of a request stream and for a data stream header, the wait for the data stream of a fetch after FETCH_OK, and the time a data stream the peer does not read may stay blocked before it is reset. Default 10s, from 1s to 10m.
	RequestTimeout time.Duration
	// MaxRequests caps the requests the peer may have open at once; more are reset. Default 1000, from 1 to 1000000.
	MaxRequests int
	// MaxSubscriptions caps the peer's open subscriptions; more are refused with EXCESSIVE_LOAD. Default 1000, from 1 to 1000000.
	MaxSubscriptions int
	// MaxObjectSize caps an object payload received from the peer, in bytes. Default 16 MiB, from 1 KiB to 1 GiB.
	MaxObjectSize int
	// MaxControlMessageSize caps a control message from the peer, in bytes. Default and maximum 65535 (the draft's 16-bit length), from 8192.
	MaxControlMessageSize int
	// MaxNamespaceFields caps the fields of a namespace in a request. Default and maximum 32 (the draft limit), from 1.
	MaxNamespaceFields int
	// MaxNameLength caps a namespace plus track name in a request, in bytes. Default and maximum 4096 (the draft limit), from 1.
	MaxNameLength int
	// MaxBufferedGroups caps the groups queued for one subscription, on either side. Default 64, from 1 to 1000000.
	MaxBufferedGroups int
	// MaxBufferedBytes caps the payload bytes queued for one subscription, on either side. Default 32 MiB or MaxObjectSize if larger, from MaxObjectSize to 64 GiB.
	MaxBufferedBytes int64
	// MaxSessionBufferedBytes caps the payload bytes queued for all of the session's subscriptions together, on either side, so MaxSubscriptions times MaxBufferedBytes is not the memory bound. The subscription that goes over drops its oldest groups. Default eight times MaxBufferedBytes, from MaxBufferedBytes to 64 GiB.
	MaxSessionBufferedBytes int64
	// MaxNamespaces caps the namespaces one namespace subscription tracks, on either side. Default 1000, from 1 to 1000000.
	MaxNamespaces int
	// MaxFetchBytes caps the bytes of cached objects held at once for the peer's FETCHes and fills, and in a relay the objects it buffers for the peer's forwarded FETCHes. A FETCH beyond it is refused with EXCESSIVE_LOAD, a fill is skipped and a forwarded FETCH is reset. Default MaxBufferedBytes, from MaxObjectSize to 64 GiB.
	MaxFetchBytes int64

	src source
}

type limit[T int | int64 | time.Duration] struct {
	name          string
	def, min, max T
}

func (l limit[T]) apply(v *T) error {
	if *v == 0 {
		*v = l.def
	}
	if *v < l.min || *v > l.max {
		return fmt.Errorf("%w: %s %v out of range [%v, %v]", ErrInvalidConfig, l.name, *v, l.min, l.max)
	}
	return nil
}

func (c *Config) resolve() (Config, error) {
	var out Config
	if c != nil {
		out = *c
	}
	errs := []error{
		limit[time.Duration]{"SetupTimeout", 10 * time.Second, time.Second, 10 * time.Minute}.apply(&out.SetupTimeout),
		limit[time.Duration]{"RequestTimeout", 10 * time.Second, time.Second, 10 * time.Minute}.apply(&out.RequestTimeout),
		limit[int]{"MaxRequests", 1000, 1, 1_000_000}.apply(&out.MaxRequests),
		limit[int]{"MaxSubscriptions", 1000, 1, 1_000_000}.apply(&out.MaxSubscriptions),
		limit[int]{"MaxObjectSize", 16 << 20, 1 << 10, 1 << 30}.apply(&out.MaxObjectSize),
		limit[int]{"MaxControlMessageSize", wire.MaxMessageLen, 8192, wire.MaxMessageLen}.apply(&out.MaxControlMessageSize),
		limit[int]{"MaxNamespaceFields", wire.MaxNamespaceFields, 1, wire.MaxNamespaceFields}.apply(&out.MaxNamespaceFields),
		limit[int]{"MaxNameLength", wire.MaxFullNameLen, 1, wire.MaxFullNameLen}.apply(&out.MaxNameLength),
		limit[int]{"MaxBufferedGroups", 64, 1, 1_000_000}.apply(&out.MaxBufferedGroups),
		limit[int]{"MaxNamespaces", 1000, 1, 1_000_000}.apply(&out.MaxNamespaces),
	}
	for _, err := range errs {
		if err != nil {
			return out, err
		}
	}
	if err := (limit[int64]{"MaxBufferedBytes", max(32<<20, int64(out.MaxObjectSize)), int64(out.MaxObjectSize), 64 << 30}).apply(&out.MaxBufferedBytes); err != nil {
		return out, err
	}
	if err := (limit[int64]{"MaxSessionBufferedBytes", min(8*out.MaxBufferedBytes, 64<<30), out.MaxBufferedBytes, 64 << 30}).apply(&out.MaxSessionBufferedBytes); err != nil {
		return out, err
	}
	if err := (limit[int64]{"MaxFetchBytes", out.MaxBufferedBytes, int64(out.MaxObjectSize), 64 << 30}).apply(&out.MaxFetchBytes); err != nil {
		return out, err
	}
	if out.src == nil && out.Origin != nil {
		out.src = out.Origin
	}
	return out, nil
}

// checkName applies the configured name limits.
func (c *Config) checkName(ns Namespace, name string, hasName bool) error {
	if len(ns) > c.MaxNamespaceFields {
		return ErrInvalidName
	}
	n := len(name)
	for _, f := range ns {
		if f == "" {
			return ErrInvalidName
		}
		n += len(f)
	}
	if n > c.MaxNameLength || (!hasName && name != "") {
		return ErrInvalidName
	}
	return nil
}
