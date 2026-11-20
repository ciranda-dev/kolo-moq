// Command quickstart publishes a track to a relay and subscribes to it through the relay, all on 127.0.0.1.
package main

import (
	"context"
	"fmt"
	"io"
	"log"
	"time"

	koloid "github.com/ciranda-dev/kolo-id"
	kolomoq "github.com/ciranda-dev/kolo-moq"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	relayID, pubID, subID := must(koloid.Generate()), must(koloid.Generate()), must(koloid.Generate())

	// The relay listens and serves every peer that connects.
	relay := must(kolomoq.NewRelay(nil))
	ln := must(kolosecure.Listen(ctx, "127.0.0.1:0", relayID, nil))
	defer ln.Close()
	go func() {
		for {
			conn, err := ln.Accept(ctx)
			if err != nil {
				return
			}
			relay.NewServer(ctx, conn)
		}
	}()
	dial := func(id *koloid.Identity, cfg *kolomoq.Config) *kolomoq.Session {
		conn := must(kolosecure.Dial(ctx, ln.Addr().String(), id, relayID.PublicKey(), nil))
		return must(kolomoq.NewClient(ctx, conn, cfg))
	}

	// The publisher dials the relay and announces the namespace "demo".
	origin := must(kolomoq.NewOrigin(nil))
	pub := dial(pubID, &kolomoq.Config{Origin: origin})
	defer pub.Close()
	ns := kolomoq.Namespace{"demo"}
	must(pub.PublishNamespace(ctx, ns))
	track := must(origin.CreateTrack(ns, "chat", nil))

	// The subscriber dials the same relay and subscribes to the track.
	sess := dial(subID, nil)
	defer sess.Close()
	sub := must(sess.Subscribe(ctx, ns, "chat", nil))

	// The publisher writes one group of three objects, then ends the track.
	group := must(track.NewGroup())
	for i := range 3 {
		must(group.WriteObject([]byte(fmt.Sprintf("hello %d", i))))
	}
	track.Close()

	for obj, err := sub.ReadObject(ctx); err != io.EOF; obj, err = sub.ReadObject(ctx) {
		if err != nil {
			log.Fatal(err)
		}
		if obj.Status == kolomoq.StatusNormal {
			fmt.Printf("group %d object %d: %s\n", obj.Group, obj.ID, obj.Payload)
		}
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		log.Fatal(err)
	}
	return v
}
