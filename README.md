# kolo-moq

MoQ Transport publish, subscribe and relay over Kolo connections.

[![status: experimental](https://img.shields.io/badge/status-experimental-orange)](#status)
[![license: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue)](#license)
[![go: 1.26+](https://img.shields.io/badge/go-1.26%2B-00ADD8)](go.mod)

## What it is

kolo-moq implements
[MoQ Transport, draft-ietf-moq-transport-22](https://datatracker.ietf.org/doc/html/draft-ietf-moq-transport-22),
and protects objects end to end through relays with a Kolo profile of
[draft-ietf-moq-secure-objects-01](https://datatracker.ietf.org/doc/html/draft-ietf-moq-secure-objects-01).
It runs on a connection that kolo-secure or kolo-relay already authenticated.
A publisher writes tracks of groups of objects, subscribers receive them live
or fetch cached groups, and a relay fans one track out to many subscribers.

It is Go only, with no cgo and nothing to install. It knows nothing about
media: any application data can be a track.

## Install

```sh
go get github.com/ciranda-dev/kolo-moq
```

## Quick start

A publisher and a subscriber meet through a relay, all on 127.0.0.1.

```go
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
```

```text
$ go run ./examples/quickstart
group 0 object 0: hello 0
group 0 object 1: hello 1
group 0 object 2: hello 2
```

## Packages and API

| Symbol | What it does |
|---|---|
| `NewClient`, `NewServer` | Start a `Session` on a connection; the dialer is the client |
| `NewOrigin`, `Origin.CreateTrack` | Hold the tracks a side publishes; `TrackWriter` and `GroupWriter` write them |
| `Session.Subscribe` | Receive a track live, or join at the current group |
| `Session.Fetch`, `Session.TrackStatus` | Read cached objects, or ask for a track's Largest Object |
| `Session.PublishNamespace`, `Session.SubscribeNamespace` | Announce and discover namespaces |
| `NewRelay`, `Relay.NewServer` | Share one upstream subscription among many subscribers, with a cache |
| `Config.Authorize` | Decide each request by the peer's kolo-id key |
| `RoomPolicy` | An `Authorize` for a relay of rooms: a peer announces only its own namespace in the room, and members read |
| `TrackOptions.Readers` | Limit a track to listed peers, whatever `Authorize` decides |
| `GroupWriter.WriteObjectFunc` | Publish an object built from its own Object ID, holding the group |
| `KeyNamespaceField` | Reserved first namespace field for key tracks, refused by `PublishNamespace` and by a relay |
| Package `secobj` | Objects protected end to end through relays (the Kolo profile of MoQ Secure Objects): `Sender` gives each member its key, `Keyring` receives keys, `Opener` opens a track's objects. Every member holds each sender's key and objects are not signed per sender, so a member who controls a relay can forge another member's objects. Keys are overwritten as far as Go allows, with no guarantee that no copy remains; Go's AES-GCM is constant time only for amd64 and arm64 with AES instructions, ppc64x and s390x |

## Standards

draft-ietf-moq-transport-22, on streams only (Kolo connections have no datagrams).

- Implemented: SETUP, GOAWAY, SUBSCRIBE, REQUEST_UPDATE, FETCH, TRACK_STATUS, PUBLISH_DONE, PUBLISH_NAMESPACE, SUBSCRIBE_NAMESPACE, priorities, delivery timeouts, and the section 12.1 rules a relay cache can check.
- Answered `NOT_SUPPORTED`: PUBLISH, SUBSCRIBE_TRACKS, namespace-prefix updates.
- Not implemented: relay merge of several publishers (section 7.6), RENDEZVOUS_TIMEOUT, dynamic groups.

Draft-22 is a moving draft, so a later draft will be a breaking change.

## Platforms

| Platform | What was run |
|---|---|
| macOS (arm64) | `go test`, `go test -race` and the interop suite against a second draft-22 implementation pass |
| Linux | `go vet` passes; tests not run |
| Windows | `go vet` passes; tests not run |

More: [guide](docs/guide.md), [limits](docs/limits.md), [protocol coverage](docs/protocol.md).

## License

Licensed under either of the [Apache License, Version 2.0](LICENSE) or the [MIT license](LICENSE-MIT), at your option.

## Status

Experimental. The API may change before v1.0.0.
