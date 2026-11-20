// Command basic publishes a track and subscribes to it over a loopback
// Kolo connection.
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
	alice, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}
	bob, err := koloid.Generate()
	if err != nil {
		log.Fatal(err)
	}

	// Alice publishes the track example/clock from her origin.
	origin, err := kolomoq.NewOrigin(nil)
	if err != nil {
		log.Fatal(err)
	}
	ns := kolomoq.Namespace{"example"}
	track, err := origin.CreateTrack(ns, "clock", nil)
	if err != nil {
		log.Fatal(err)
	}
	ln, err := kolosecure.Listen(ctx, "127.0.0.1:0", alice, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept(ctx)
		if err != nil {
			return
		}
		s, err := kolomoq.NewServer(ctx, conn, &kolomoq.Config{Origin: origin})
		if err != nil {
			log.Print(err)
			return
		}
		<-s.Done()
	}()

	// Bob dials alice and subscribes.
	conn, err := kolosecure.Dial(ctx, ln.Addr().String(), bob, alice.PublicKey(), nil)
	if err != nil {
		log.Fatal(err)
	}
	session, err := kolomoq.NewClient(ctx, conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	sub, err := session.Subscribe(ctx, ns, "clock", nil)
	if err != nil {
		log.Fatal(err)
	}

	// Alice writes two groups of three objects, then ends the track.
	for range 2 {
		group, err := track.NewGroup()
		if err != nil {
			log.Fatal(err)
		}
		for range 3 {
			now := time.Now().Format(time.TimeOnly)
			if _, err := group.WriteObject([]byte(now)); err != nil {
				log.Fatal(err)
			}
		}
	}
	track.Close()

	for {
		obj, err := sub.ReadObject(ctx)
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatal(err)
		}
		if obj.Status == kolomoq.StatusNormal {
			fmt.Printf("group %d object %d: %s\n", obj.Group, obj.ID, obj.Payload)
		}
	}
}
