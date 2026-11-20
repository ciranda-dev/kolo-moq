// Command subscriber joins the track example/clock of a publisher at its
// current group and prints the objects it receives.
//
//	subscriber -addr 127.0.0.1:4433 -peer <publisher key> -key /path/to/subscriber.key
//
// The key file is created on the first run.
package main

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"os/signal"

	koloid "github.com/ciranda-dev/kolo-id"
	kolomoq "github.com/ciranda-dev/kolo-moq"
	kolosecure "github.com/ciranda-dev/kolo-secure"
)

func main() {
	addr := flag.String("addr", "127.0.0.1:4433", "IPv4 address of the publisher")
	peer := flag.String("peer", "", "publisher public key, in hex")
	keyFile := flag.String("key", "", "identity key file, created if missing")
	count := flag.Int("n", 30, "objects to print before leaving")
	flag.Parse()
	peerKey, err := hex.DecodeString(*peer)
	if err != nil || len(peerKey) != ed25519.PublicKeySize || *keyFile == "" {
		log.Fatal("usage: subscriber -addr <address> -peer <hex public key> -key <key file>")
	}
	id, err := loadIdentity(*keyFile)
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	conn, err := kolosecure.Dial(ctx, *addr, id, peerKey, nil)
	if err != nil {
		log.Fatal(err)
	}
	session, err := kolomoq.NewClient(ctx, conn, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer session.Close()
	sub, err := session.Subscribe(ctx, kolomoq.Namespace{"example"}, "clock",
		&kolomoq.SubscribeOptions{Priority: kolomoq.DefaultPriority, Join: kolomoq.JoinCurrentGroup})
	if err != nil {
		log.Fatal(err)
	}
	defer sub.Close()
	for printed := 0; printed < *count; {
		obj, err := sub.ReadObject(ctx)
		if err == io.EOF {
			return
		}
		if err != nil {
			log.Fatal(err)
		}
		if obj.Status == kolomoq.StatusNormal {
			// The payload comes from the peer: quote it so it cannot drive the terminal.
			fmt.Printf("group %d object %d: %q\n", obj.Group, obj.ID, obj.Payload)
			printed++
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
