// Command publisher publishes the track example/clock, one object every
// 100ms and one group a second, to every peer that connects.
//
//	publisher -listen 127.0.0.1:4433 -key /path/to/publisher.key
//
// The key file is created on the first run. The publisher prints its
// public key, which subscribers pass as -peer.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolomoq "github.com/ciranda-dev/kolo-moq"
	kolosecure "github.com/ciranda-dev/kolo-secure"
	kolotransport "github.com/ciranda-dev/kolo-transport"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:4433", "IPv4 address to listen on")
	keyFile := flag.String("key", "", "identity key file, created if missing")
	flag.Parse()
	if *keyFile == "" {
		log.Fatal("usage: publisher -listen <address> -key <key file>")
	}
	id, err := loadIdentity(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	origin, err := kolomoq.NewOrigin(nil)
	if err != nil {
		log.Fatal(err)
	}
	track, err := origin.CreateTrack(kolomoq.Namespace{"example"}, "clock", nil)
	if err != nil {
		log.Fatal(err)
	}
	defer track.Close()
	// Each subscription holds one request stream and one stream per group.
	cfg := &kolosecure.Config{Transport: &kolotransport.Config{MaxIncomingStreams: 256}}
	ln, err := kolosecure.Listen(ctx, *listen, id, cfg)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	fmt.Printf("publishing example/clock on %s as %s\n", ln.Addr(), id.PublicKeyString())

	go publish(ctx, track)
	for {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		go func() {
			s, err := kolomoq.NewServer(ctx, conn, &kolomoq.Config{Origin: origin})
			if err != nil {
				log.Printf("session: %v", err)
				return
			}
			select {
			case <-s.Done():
			case <-ctx.Done():
				s.Close()
			}
		}()
	}
}

func publish(ctx context.Context, track *kolomoq.TrackWriter) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	var group *kolomoq.GroupWriter
	for i := 0; ; i++ {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			if i%10 == 0 {
				var err error
				if group, err = track.NewGroup(); err != nil {
					return
				}
			}
			group.WriteObject([]byte(now.Format(time.TimeOnly + ".000")))
		}
	}
}

func loadIdentity(path string) (*koloid.Identity, error) {
	id, err := koloid.Load(path)
	if errors.Is(err, os.ErrNotExist) {
		if id, err = koloid.Generate(); err != nil {
			return nil, err
		}
		err = id.SaveNew(path)
	}
	return id, err
}
