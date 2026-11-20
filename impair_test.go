package kolomoq

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"testing"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolosecure "github.com/ciranda-dev/kolo-secure"

	"github.com/ciranda-dev/kolo-moq/internal/netsim"
)

const mbps = 1000 * 1000 / 8

// feed publishes what a call does: audio of 120 bytes every 20 ms, each frame its own group at priority 48, and video of
// bitrate bits a second at 30 frames a second, a key frame of 9 times the others every 60 frames starting a group, at
// priority 68. It stops with ctx.
func feed(ctx context.Context, t *testing.T, o *Origin, ns Namespace, bitrate int) {
	audio, err := o.CreateTrack(ns, "audio", &TrackOptions{Priority: 48, SubgroupDeliveryTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	video, err := o.CreateTrack(ns, "video", &TrackOptions{Priority: 68, SubgroupDeliveryTimeout: 30 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		a := time.NewTicker(20 * time.Millisecond)
		v := time.NewTicker(time.Second / 30)
		defer a.Stop()
		defer v.Stop()
		var gv *GroupWriter
		n := 0
		small := bitrate / 8 / 30 * 60 / 69 // 60 frames of which one is 9 times
		for {
			select {
			case <-ctx.Done():
				return
			case <-a.C:
				if g, err := audio.NewGroup(); err == nil {
					g.WriteObject(make([]byte, 120))
					g.Close()
				}
			case <-v.C:
				size := small
				if n%60 == 0 {
					if gv != nil {
						gv.Close()
					}
					gv, _ = video.NewGroup()
					size = small * 9
				}
				n++
				if gv != nil {
					gv.WriteObject(make([]byte, size))
				}
			}
		}
	}()
}

type counts struct{ audio, video atomic.Uint64 }

// watch subscribes to both tracks as kolo-media does, delivery timeouts of 450 ms included, and counts the objects.
func watch(ctx context.Context, t *testing.T, s *Session, ns Namespace) *counts {
	var c counts
	for _, tr := range []struct {
		name string
		n    *atomic.Uint64
		join Join
	}{{"audio", &c.audio, JoinNextObject}, {"video", &c.video, JoinCurrentGroup}} {
		sub, err := s.Subscribe(ctx, ns, tr.name, &SubscribeOptions{Priority: DefaultPriority, Join: tr.join,
			ObjectDeliveryTimeout: 450 * time.Millisecond, SubgroupDeliveryTimeout: 450 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			for {
				if _, err := sub.ReadObject(ctx); err != nil {
					return
				}
				tr.n.Add(1)
			}
		}()
	}
	return &c
}

type point struct {
	at           time.Duration
	audio, video uint64
}

// impairedSessions returns a publisher session and a subscriber session whose connection goes through a link.
func impairedSessions(t *testing.T, up, down netsim.Profile, origin *Origin) (pub, sub *Session, link *netsim.Link) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	srvID, _ := koloid.Generate()
	cliID, _ := koloid.Generate()
	cfg := &kolosecure.Config{Transport: testTransport}
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", srvID, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	link, err = netsim.New(l.Addr().String(), up, down)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { link.Close() })
	srv := make(chan *Session, 1)
	go func() {
		c, err := l.Accept(ctx)
		if err != nil {
			srv <- nil
			return
		}
		s, err := NewServer(ctx, c, &Config{Origin: origin})
		if err != nil {
			s = nil
		}
		srv <- s
	}()
	cc, err := kolosecure.Dial(ctx, link.Addr(), cliID, srvID.PublicKey(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	sub, err = NewClient(ctx, cc, nil)
	if err != nil {
		t.Fatal(err)
	}
	pub = <-srv
	if pub == nil {
		t.Fatal("no server session")
	}
	t.Cleanup(func() { sub.Close(); pub.Close() })
	return pub, sub, link
}

func rates(s []point, from, to time.Duration) (audio, video float64) {
	var a, z *point
	for i := range s {
		if s[i].at >= from && a == nil {
			a = &s[i]
		}
		if s[i].at <= to {
			z = &s[i]
		}
	}
	if a == nil || z == nil || z.at <= a.at {
		return 0, 0
	}
	d := (z.at - a.at).Seconds()
	return float64(z.audio-a.audio) / d, float64(z.video-a.video) / d
}

// viaRelay returns a subscriber session that reaches the publisher through a relay: the publisher's connection to the
// relay goes through a link (a guest on a mobile network) and the subscriber's is a clean loopback one (the host).
func viaRelay(t *testing.T, up, down netsim.Profile, origin *Origin, ns Namespace) (pubSess, relaySessToPub, sub *Session, link *netsim.Link) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	relay, err := NewRelay(nil)
	if err != nil {
		t.Fatal(err)
	}
	srvID, _ := koloid.Generate()
	cliID, _ := koloid.Generate()
	cfg := &kolosecure.Config{Transport: testTransport}
	l, err := kolosecure.Listen(ctx, "127.0.0.1:0", srvID, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	link, err = netsim.New(l.Addr().String(), up, down)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { link.Close() })
	got := make(chan *Session, 1)
	go func() {
		for {
			c, err := l.Accept(ctx)
			if err != nil {
				return
			}
			s, err := relay.NewServer(ctx, c)
			if err != nil {
				continue
			}
			got <- s
		}
	}()
	cc, err := kolosecure.Dial(ctx, link.Addr(), cliID, srvID.PublicKey(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	pubSess, err = NewClient(ctx, cc, &Config{Origin: origin})
	if err != nil {
		t.Fatal(err)
	}
	relaySessToPub = <-got
	if _, err := pubSess.PublishNamespace(ctx, ns); err != nil {
		t.Fatal(err)
	}
	// The subscriber's connection to the relay is loopback and clean.
	subID, _ := koloid.Generate()
	cc2, err := kolosecure.Dial(ctx, l.Addr().String(), subID, srvID.PublicKey(), cfg)
	if err != nil {
		t.Fatal(err)
	}
	sub, err = NewClient(ctx, cc2, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { sub.Close(); pubSess.Close() })
	return pubSess, relaySessToPub, sub, link
}

// TestImpairedFeedReport prints the objects a second a subscriber gets over each path; set KOLO_MOQ_IMPAIR=<seconds>.
func TestImpairedFeedReport(t *testing.T) {
	v := os.Getenv("KOLO_MOQ_IMPAIR")
	if v == "" {
		t.Skip("set KOLO_MOQ_IMPAIR=<seconds> to measure")
	}
	dur, _ := time.ParseDuration(v + "s")
	for _, c := range []struct {
		name          string
		rate          int
		loss          float64
		bitrate       int
		cutAt, cutFor time.Duration
		relay         bool
	}{
		{"clean 2 Mbps video", 0, 0, 2000000, 0, 0, false},
		{"RELAY 3 Mbps loss 1%, 1.9 Mbps video, outage 3s at 8s", 3 * mbps, 0.01, 1900000, 8 * time.Second, 3 * time.Second, true},
		{"RELAY 3 Mbps loss 1%, 0.6 Mbps video, outage 3s at 8s", 3 * mbps, 0.01, 600000, 8 * time.Second, 3 * time.Second, true},
		{"3 Mbps loss 1%, 1.9 Mbps video", 3 * mbps, 0.01, 1900000, 0, 0, false},
		{"3 Mbps loss 1%, 1.9 Mbps video, outage 3s at 8s", 3 * mbps, 0.01, 1900000, 8 * time.Second, 3 * time.Second, false},
		{"3 Mbps loss 1%, 0.6 Mbps video, outage 3s at 8s", 3 * mbps, 0.01, 600000, 8 * time.Second, 3 * time.Second, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			origin := newOrigin(t)
			ns := Namespace{"call"}
			pr := netsim.Profile{Rate: c.rate, Delay: 60 * time.Millisecond, Jitter: 20 * time.Millisecond, Loss: c.loss, Seed: 1}
			dn := pr
			dn.Seed = 2
			var pub, sub *Session
			var link *netsim.Link
			if c.relay {
				pub, _, sub, link = viaRelay(t, dn, pr, origin, ns)
			} else {
				pub, sub, link = impairedSessions(t, dn, pr, origin)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			feed(ctx, t, origin, ns, c.bitrate)
			n := watch(ctx, t, sub, ns)
			var series []point
			start := time.Now()
			cut := false
			for now := range time.Tick(100 * time.Millisecond) {
				el := now.Sub(start)
				if c.cutAt > 0 && !cut && el >= c.cutAt {
					cut = true
					link.Cut(c.cutFor)
				}
				series = append(series, point{el, n.audio.Load(), n.video.Load()})
				if el >= dur {
					break
				}
			}
			a1, v1 := rates(series, 0, dur)
			a2, v2 := rates(series, dur-5*time.Second, dur)
			st := pub.Stats()
			t.Log("\n" + fmt.Sprintf("%-50s audio/s %.1f (last 5s %.1f) video objects/s %.1f (last 5s %.1f) | sender: sent %d KB queued %d KB delay %v reset %d expired %d",
				c.name, a1, a2, v1, v2, st.SentBytes/1000, st.QueuedBytes/1000, st.QueueDelay.Round(time.Millisecond), st.ResetGroups, st.ExpiredGroups))
		})
	}
}

// Over a path that loses 1%, delays 60 ms and goes silent for 3 s, the audio of a publisher whose connection to a
// relay is that path keeps arriving at a subscriber of the relay while the video track is overloaded (1.9 Mbit/s over
// 1 Mbit/s): audio has the higher priority, so it never waits for the video's backlog. A video within the path's
// capacity arrives too, and the sender's Stats show the overload as a queue that grows.
func TestAudioIsNotHeldUpByAVideoBacklog(t *testing.T) {
	if testing.Short() {
		t.Skip("takes 20 s")
	}
	checkLeaks(t)
	run := func(t *testing.T, bitrate int) (audio, video float64, st SessionStats) {
		origin := newOrigin(t)
		ns := Namespace{"call"}
		pr := netsim.Profile{Rate: 1 * mbps, Delay: 60 * time.Millisecond, Jitter: 20 * time.Millisecond, Loss: 0.01, Seed: 1}
		dn := pr
		dn.Seed = 2
		pub, _, sub, link := viaRelay(t, pr, dn, origin, ns)
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		feed(ctx, t, origin, ns, bitrate)
		n := watch(ctx, t, sub, ns)
		var series []point
		start := time.Now()
		cut := false
		for now := range time.Tick(100 * time.Millisecond) {
			el := now.Sub(start)
			if !cut && el >= 5*time.Second {
				cut = true
				link.Cut(3 * time.Second)
			}
			series = append(series, point{el, n.audio.Load(), n.video.Load()})
			if el >= 16*time.Second {
				break
			}
		}
		audio, video = rates(series, 11*time.Second, 16*time.Second)
		return audio, video, pub.Stats()
	}
	t.Run("overloaded", func(t *testing.T) {
		audio, video, st := run(t, 1_900_000)
		t.Logf("audio %.1f objects/s, video %.1f; sender queue %v, %d KB", audio, video, st.QueueDelay.Round(time.Millisecond), st.QueuedBytes/1000)
		if audio < 90 {
			t.Errorf("audio %.1f objects a second after the outage, want 100", audio)
		}
		if st.QueueDelay < time.Second {
			t.Errorf("the overload shows as a queue of %v, want more than 1 s", st.QueueDelay)
		}
	})
	t.Run("within the path", func(t *testing.T) {
		audio, video, st := run(t, 500_000)
		t.Logf("audio %.1f objects/s, video %.1f; sender queue %v", audio, video, st.QueueDelay.Round(time.Millisecond))
		if audio < 90 || video < 20 {
			t.Errorf("audio %.1f, video %.1f objects a second after the outage, want 100 and 30", audio, video)
		}
	})
}
