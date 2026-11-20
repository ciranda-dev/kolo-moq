package kolomoq

import (
	"context"
	"fmt"
	"io"

	"github.com/ciranda-dev/kolo-moq/internal/wire"
)

// PublishedNamespace is a namespace this side announced with
// PUBLISH_NAMESPACE.
type PublishedNamespace struct {
	s    *Session
	r    *reqStream
	done chan struct{}
}

// PublishNamespace tells the peer this side has tracks under ns, and
// returns once the peer accepted it or refused it (*RequestError).
func (s *Session) PublishNamespace(ctx context.Context, ns Namespace) (*PublishedNamespace, error) {
	if err := s.cfg.checkName(ns, "", false); err != nil {
		return nil, err
	}
	if keyNamespace(ns) {
		return nil, fmt.Errorf("%w: first field %q is reserved", ErrInvalidName, KeyNamespaceField)
	}
	id, err := s.newRequestID()
	if err != nil {
		return nil, err
	}
	r, t, body, err := s.request(ctx, &wire.Request{Type: wire.MsgPublishNamespace, RequestID: id, Namespace: ns, Params: &wire.MessageParams{}}, false)
	if err != nil {
		return nil, err
	}
	if t != wire.MsgRequestOK {
		return nil, s.refused(r, t, body)
	}
	if err := checkPlainOK(body); err != nil {
		s.protocolErr(err)
		return nil, s.errOr(err)
	}
	p := &PublishedNamespace{s: s, r: r, done: make(chan struct{})}
	started := s.start(func() {
		defer close(p.done)
		goaways := 0
		for {
			t, body, err := r.read(s.cfg.MaxControlMessageSize)
			if err != nil {
				if err != io.EOF {
					s.protocolErr(err)
				}
				r.cancel(resetCancelled)
				return
			}
			if t != wire.MsgGoAway {
				s.fail(CodeProtocolViolation, ErrProtocol)
				return
			}
			if !s.requestGoAway(body, &goaways) {
				return
			}
		}
	})
	if !started {
		r.cancel(resetCancelled)
		return nil, s.errOr(ErrClosed)
	}
	return p, nil
}

// checkPlainOK parses a REQUEST_OK that must carry no track properties.
func checkPlainOK(body []byte) error {
	m, err := wire.ParseRequestOK(body)
	if err != nil {
		return err
	}
	if len(m.Properties) > 0 || m.Params.Has(wire.ParamLargestObject) {
		return &wire.Error{Code: uint64(CodeProtocolViolation), Msg: "unexpected field in REQUEST_OK"}
	}
	return nil
}

// Done is closed when the peer revoked the namespace or the session ended.
func (p *PublishedNamespace) Done() <-chan struct{} { return p.done }

// Close withdraws the namespace.
func (p *PublishedNamespace) Close() error {
	p.r.cancel(resetCancelled)
	return nil
}

// NamespaceEvent reports a namespace the peer starts (Active) or stops
// publishing.
type NamespaceEvent struct {
	Namespace Namespace
	Active    bool
}

// NamespaceSubscription receives the namespaces the peer publishes under a
// prefix.
type NamespaceSubscription struct {
	s       *Session
	r       *reqStream
	prefix  Namespace
	active  map[string]bool
	goaways int
}

// SubscribeNamespace asks the peer for the namespaces under prefix and
// their changes, and returns once the peer accepted or refused
// (*RequestError).
func (s *Session) SubscribeNamespace(ctx context.Context, prefix Namespace) (*NamespaceSubscription, error) {
	if err := s.cfg.checkName(prefix, "", false); err != nil {
		return nil, err
	}
	id, err := s.newRequestID()
	if err != nil {
		return nil, err
	}
	r, t, body, err := s.request(ctx, &wire.Request{Type: wire.MsgSubscribeNamespace, RequestID: id, Namespace: prefix, Params: &wire.MessageParams{}}, true)
	if err != nil {
		return nil, err
	}
	if t != wire.MsgRequestOK {
		return nil, s.refused(r, t, body)
	}
	if err := checkPlainOK(body); err != nil {
		s.protocolErr(err)
		return nil, s.errOr(err)
	}
	return &NamespaceSubscription{s: s, r: r, prefix: prefix, active: map[string]bool{}}, nil
}

// Next returns the next change. When the peer ends the subscription it
// returns io.EOF; every namespace reported active is then gone. Calls must
// not overlap.
func (n *NamespaceSubscription) Next(ctx context.Context) (NamespaceEvent, error) {
	s := n.s
	stop := interruptOnDone(ctx, n.r.st.SetReadDeadline)
	defer stop()
	for {
		t, body, err := n.r.read(s.cfg.MaxControlMessageSize)
		if err != nil {
			if ctx.Err() != nil {
				n.Close()
				return NamespaceEvent{}, ctx.Err()
			}
			s.protocolErr(err)
			if err != io.EOF {
				if _, ok := streamCode(err); ok {
					err = io.EOF
				}
			}
			return NamespaceEvent{}, s.errOr(err)
		}
		if t != wire.MsgGoAway {
			return n.event(t, body)
		}
		if !s.requestGoAway(body, &n.goaways) {
			return NamespaceEvent{}, s.Err()
		}
	}
}

func (n *NamespaceSubscription) event(t uint64, body []byte) (NamespaceEvent, error) {
	s := n.s
	if t != wire.MsgNamespace && t != wire.MsgNamespaceDone {
		s.fail(CodeProtocolViolation, ErrProtocol)
		return NamespaceEvent{}, s.Err()
	}
	suffix, err := wire.ParseNamespaceSuffix(body)
	if err != nil {
		s.protocolErr(err)
		return NamespaceEvent{}, s.errOr(err)
	}
	ns := append(append(Namespace{}, n.prefix...), suffix...)
	if len(ns) > wire.MaxNamespaceFields || wire.NamespaceLen(ns) > wire.MaxFullNameLen {
		s.fail(CodeProtocolViolation, ErrProtocol)
		return NamespaceEvent{}, s.Err()
	}
	k := ns.key()
	active := t == wire.MsgNamespace
	if !active && !n.active[k] {
		// NAMESPACE_DONE before NAMESPACE (draft section 4.2).
		s.fail(CodeProtocolViolation, ErrProtocol)
		return NamespaceEvent{}, s.Err()
	}
	if active {
		if !n.active[k] && len(n.active) >= s.cfg.MaxNamespaces {
			n.Close()
			return NamespaceEvent{}, ErrTooManyNamespaces
		}
		n.active[k] = true
	} else {
		delete(n.active, k)
	}
	return NamespaceEvent{Namespace: ns, Active: active}, nil
}

// Close ends the namespace subscription.
func (n *NamespaceSubscription) Close() error {
	n.r.cancel(resetCancelled)
	return nil
}
