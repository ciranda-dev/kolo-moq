package kolomoq

import (
	"context"
	"fmt"
	"math/rand/v2"
	"runtime"
	"sync"
	"testing"
	"time"
)

// TestShedLockOrderStress publishes, subscribes, closes sessions and sheds session budgets at once, directly and through a
// relay whose publishers also subscribe to each other, so track.add holds track.mu while Session.shed takes Session.mu and
// the mu of other subscriptions. Run it with -race; a lock-order inversion shows as a deadlock, which the watchdog reports.
func TestShedLockOrderStress(t *testing.T) {
	checkLeaks(t)
	const objSize = 4 << 10
	small := func(o *Origin) *Config {
		return &Config{Origin: o, MaxObjectSize: 16 << 10, MaxBufferedBytes: 32 << 10, MaxSessionBufferedBytes: 64 << 10}
	}
	watchdog := time.AfterFunc(60*time.Second, func() {
		buf := make([]byte, 1<<22)
		panic(fmt.Sprintf("TestShedLockOrderStress made no progress for 60 s, a lock cycle is likely:\n%s", buf[:runtime.Stack(buf, true)]))
	})
	defer watchdog.Stop()
	r := newRelay(t, &RelayConfig{Session: *small(nil)})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	type pub struct {
		ns     Namespace
		names  []string
		tws    []*TrackWriter
		peer   *Session
		remote *Session
	}
	newPub := func(name string) *pub {
		p := &pub{ns: Namespace{name}}
		o := newOrigin(t)
		for i := range 4 {
			n := fmt.Sprint("t", i)
			p.names = append(p.names, n)
			p.tws = append(p.tws, mustTrack(t, o, p.ns, n, &TrackOptions{CacheBytes: 64 << 10}))
		}
		p.peer, p.remote = joinRelay(t, r, small(o))
		if _, err := p.peer.PublishNamespace(testCtx(t), p.ns); err != nil {
			t.Fatal(err)
		}
		return p
	}
	pubs := []*pub{newPub("p"), newPub("q")}
	direct := newOrigin(t)
	var directTws []*TrackWriter
	for i := range 4 {
		directTws = append(directTws, mustTrack(t, direct, Namespace{"d"}, fmt.Sprint("t", i), nil))
	}
	pair := newPair(t, small(nil), small(direct))

	stop := make(chan struct{})
	var writers sync.WaitGroup
	write := func(tw *TrackWriter) {
		defer writers.Done()
		payload := make([]byte, objSize)
		for {
			select {
			case <-stop:
				return
			default:
			}
			gw, err := tw.NewGroup()
			if err != nil {
				return
			}
			for range 4 {
				if _, err := gw.WriteObject(payload); err != nil {
					return
				}
			}
			gw.Close()
			time.Sleep(200 * time.Microsecond)
		}
	}
	for _, p := range pubs {
		for _, tw := range p.tws {
			writers.Add(1)
			go write(tw)
		}
	}
	for _, tw := range directTws {
		writers.Add(1)
		go write(tw)
	}

	var readers sync.WaitGroup
	read := func(sub *Subscription) {
		defer readers.Done()
		for {
			if _, err := sub.ReadObject(ctx); err != nil {
				return
			}
		}
	}
	var subs []*Subscription
	subscribe := func(s *Session, ns Namespace, name string, reading bool) {
		sctx, scancel := context.WithTimeout(ctx, 5*time.Second)
		defer scancel()
		sub, err := s.Subscribe(sctx, ns, name, nil)
		if err != nil {
			return
		}
		subs = append(subs, sub)
		if reading {
			readers.Add(1)
			go read(sub)
		}
	}
	for i, p := range pubs {
		other := pubs[1-i]
		for _, n := range other.names {
			subscribe(p.peer, other.ns, n, false)
		}
	}
	for i := range 4 {
		subscribe(pair.client, Namespace{"d"}, fmt.Sprint("t", i), i%2 == 0)
	}

	rng := rand.New(rand.NewPCG(1, 2))
	var remotes []*Session
	sessions := 0
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); sessions++ {
		peer, remote := joinRelay(t, r, small(nil))
		remotes = append(remotes, remote)
		for range 3 {
			p := pubs[rng.IntN(len(pubs))]
			subscribe(peer, p.ns, p.names[rng.IntN(len(p.names))], rng.IntN(2) == 0)
		}
		time.Sleep(time.Duration(rng.IntN(30)) * time.Millisecond)
		if len(subs) > 0 && rng.IntN(3) == 0 {
			subs[rng.IntN(len(subs))].Close()
		}
		if rng.IntN(4) != 0 {
			peer.Close()
		}
	}

	close(stop)
	writers.Wait()
	for _, s := range []*Session{pubs[0].peer, pubs[1].peer, pair.client, pair.server} {
		s.Close()
	}
	for _, s := range remotes {
		s.Close()
	}
	cancel()
	readers.Wait()
	var reset, dropped uint64
	for _, s := range append(remotes, pubs[0].remote, pubs[1].remote, pair.server) {
		reset += s.Stats().ResetGroups
	}
	for _, sub := range subs {
		dropped += sub.Dropped()
	}
	if reset == 0 || dropped == 0 {
		t.Fatalf("nothing was shed: %d groups reset, %d dropped", reset, dropped)
	}
	t.Logf("%d sessions, %d subscriptions, %d groups reset by publishers, %d dropped by subscribers", sessions, len(subs), reset, dropped)
}
