# Guide

How to use kolo-moq beyond the README quick start. Defaults and ranges of
every limit are in [limits.md](limits.md); the draft coverage is in
[protocol.md](protocol.md).

## Sessions

- `NewClient(ctx, conn, cfg)` and `NewServer(ctx, conn, cfg)` exchange the
  version preface and SETUP within `Config.SetupTimeout` and return a
  `*Session`. `conn` is any `kolomoq.Conn`; `*kolosecure.Conn` and
  `*kolorelay.Conn` satisfy it.
- The side that dialed the connection runs `NewClient`, the side that
  accepted it `NewServer`. The session owns the connection: it is the only
  caller of `AcceptStream` and `AcceptUniStream`, and closes the connection
  when it ends.
- Each subscription holds one bidirectional stream and one unidirectional
  stream per group in flight, so raise kolo-transport's `MaxIncomingStreams`
  (default 16) to match the subscriptions you expect.
- `Config.Origin` holds the tracks this side publishes; without it, track
  requests are answered `DOES_NOT_EXIST`.
- `Config.Authorize(peer, kind, namespace, track)` decides every request from
  the peer (SUBSCRIBE, FETCH, TRACK_STATUS, PUBLISH_NAMESPACE,
  SUBSCRIBE_NAMESPACE) with the peer's kolo-id key; an error refuses it with
  `UNAUTHORIZED`. A SUBSCRIBE that also asks for cached objects (a fill)
  needs `KindFetch` too. Nil allows all, since the peer is already
  authenticated.
- `Close` ends the session with `NO_ERROR` and waits for its goroutines.
  `Done` and `Err` report the end: `ErrClosed`, a `*SessionError` with the
  termination code, or a wrapped kolo-transport error.
- `GoAway(ctx, timeout)` sends GOAWAY, refuses new requests with
  `GOING_AWAY`, and closes the session once the peer has no request open, or
  with `GOAWAY_TIMEOUT` after `timeout`, and returns nil once it closed the
  session (`Err` tells which); a second call returns `ErrGoingAway`.
  `GoingAway()` is closed when the peer sent GOAWAY; new requests then return
  `ErrGoingAway`, `Update` still works.
- `MaxFetchBytes` bounds the cached objects a session holds for its peer's
  FETCHes and fills: a FETCH whose snapshot does not fit in what is left is
  refused with `EXCESSIVE_LOAD`, and a fill that does not fit is skipped, as
  when another fill runs.
- `Stats` counts groups this side reset for slow subscribers or streams the
  peer stopped reading (`ResetGroups`) and for delivery timeouts
  (`ExpiredGroups`), and says how far behind sending is: `SentBytes` handed
  to the transport, `QueuedBytes` waiting and `QueueDelay`, the age of the
  oldest unsent object. A publisher whose `QueueDelay` grows publishes more
  than its path carries; lowering the bitrate then keeps its groups from
  expiring. `Transport` is the `kolotransport.ConnStats` of the session's
  connection: round-trip times, packets and bytes lost, `CongestionWindow`,
  `BytesInFlight`, the congestion controller and path changes (the
  kolo-transport guide, "Connection statistics", defines each one). With a
  growing `QueueDelay`, `Transport` tells whether the path is slow
  (`SmoothedRTT` far above `MinRTT`, `PacketsLost` rising) or the sender is
  not limited by the network (`BytesInFlight` far below `CongestionWindow`).
  It comes from an optional `Stats() kolotransport.ConnStats` method of the
  `Conn`, which `*kolosecure.Conn` has; it is the zero value for a `Conn`
  without one, such as a `*kolorelay.Conn`, and after the connection ends.
  `PeerImplementation` returns the peer's
  MOQT_IMPLEMENTATION, escaped.

`examples/publisher` and `examples/subscriber` run the two sides as separate
programs; both take the address and an identity key file as flags.
`examples/basic` connects the two directly, without a relay.

## Publishing

- `NewOrigin(cfg)` holds tracks and can serve many sessions.
  `CreateTrack(ns, name, opts)` returns a `*TrackWriter`; `TrackOptions` sets
  the publisher priority, group order, delivery timeouts, extra track
  properties and the cache.
- `TrackWriter.NewGroup` ends the open group and starts the next (IDs from
  0); `GroupWriter.WriteObject(payload, props...)` publishes the next object
  and returns its ID; `GroupWriter.WriteObjectFunc(build)` publishes the next
  object with the payload and properties `build` returns for its Object ID
  while holding the group, so a payload that depends on the ID (a sealed
  object) cannot pair with another object's ID; `build` must not call a
  method of the same track's writers, and when it or the checks of its
  result fail no ID is used. `GroupWriter.Close` ends the group with an End of Group
  object; `TrackWriter.Close` ends the track, subscribers get `PUBLISH_DONE
  TRACK_ENDED`, and the track leaves the origin. `Subscribers` counts the
  current subscriptions.
- `TrackOptions.Readers` restricts a track to the listed kolo-id public keys:
  SUBSCRIBE, FETCH and TRACK_STATUS from any other peer get `DOES_NOT_EXIST`,
  whatever `Config.Authorize` decides, also with a nil `Authorize`. `Authorize`
  still applies to a listed reader. Nil means no restriction; an empty
  non-nil slice admits nobody; each key must be 32 bytes (`ErrInvalidConfig`).
  A relay subscribes to a publisher as its own peer, so a relay that is not
  listed cannot read the track and never forwards it.
- Delivery timeouts are read from an object's properties both at the top
  level and inside Immutable Properties (0x0B), as draft section 10.7
  requires; inside, they apply as at the top level, and win when both are
  present. A Key ID type must therefore not be 0x02 or 0x06.
- Writes never block. Each subscriber has its own queue; when it holds more
  than `MaxBufferedGroups` open subgroups or `MaxBufferedBytes` bytes (each
  object counts its payload, its properties and a fixed overhead), the
  oldest group's stream is reset with `EXCESSIVE_LOAD` for that subscriber
  only. All of a session's queues together stay within
  `MaxSessionBufferedBytes`; over it, the subscriber that holds the most
  loses its oldest group.

## Priorities

Objects are handed to the transport one at a time per session, most urgent
first: subscriber priority, then publisher priority, then group order, then
subgroup. Lower numbers are more urgent; the default is 128
(`DefaultPriority`). `Subscription.Update` changes the subscriber priority
while the subscription runs.

Each subscription or fetch has its own send queue, and queues of equal
priority take turns, so a subscription at high group IDs cannot starve
another one. Group order only compares groups within one subscription, and
its fill objects go before its live objects of the same group (draft section
5.1.2). A stream that wrote nothing in its turn, because the peer does not
read it, gets 1 ms turns until it makes progress, so it delays the others by
at most that. When a fill's group order differs from the subscription's,
the live write goes first. Control and request streams are not gated.
kolo-transport has no stream priorities, so this gate is what orders
writes.

Delivery and cancellation:

- `OBJECT_DELIVERY_TIMEOUT` is checked before each object is written and
  bounds the write with a deadline. `SUBGROUP_DELIVERY_TIMEOUT` starts when
  the subgroup ends and stops when its last byte and FIN are handed to the
  transport. Expired streams are reset with `DELIVERY_TIMEOUT` and not
  reopened. The smaller of the publisher's and subscriber's non-zero values
  applies, and a timeout property on the first object of a subgroup
  overrides the track's.
- PUBLISH_DONE's Stream Count counts a stream once its first bytes are
  written, so a stream reset before that does not make the subscriber wait
  for it. A header still in the transport's buffer when the stream is reset
  is lost with it; the subscriber's wait for missing streams covers that.
- A requester may FIN its side and cancel later with STOP_SENDING only.
  kolo-transport reports STOP_SENDING only to a write, so a served request
  checks with a zero-length write every `RequestTimeout`, and a subscription
  also before each new group stream.
- A fill needs `Config.Authorize` to allow `KindFetch`, and a subscription
  runs at most one fill stream at a time.
- Objects reach a subscriber's subgroup stream in increasing ID order: an
  object that arrives late (a repeat, or an older ID from a second stream
  of the same subgroup) is cached but not written to a stream that is past
  it.
- A GOAWAY on a request stream is accepted once per stream, from a client
  with no URI (draft section 9.2); it does not change the session.
  REQUEST_UPDATE stays allowed after a GOAWAY.

## Subscribing

- `Session.Subscribe(ctx, ns, track, opts)` returns a `*Subscription` once
  the peer accepted, or a `*RequestError`. `SubscribeOptions` sets the
  subscriber priority, group order, `Join` (`JoinNextObject`,
  `JoinCurrentGroup` to receive the current group's earlier objects from the
  publisher's cache, `JoinNextGroup`), `Paused`, and delivery timeouts.
- `ReadObject(ctx)` returns objects in arrival order with their group,
  subgroup and object IDs, priority, status and properties; `io.EOF` after
  the publisher ended the track, a `*PublishDoneError` after any other
  PUBLISH_DONE. Groups travel on separate streams, so a later group can
  arrive before an earlier one. A reader that falls more than
  `MaxBufferedGroups` groups or `MaxBufferedBytes` behind loses the oldest
  groups (`Dropped`), and so does the subscription of a session that holds
  the most when the session's queues pass `MaxSessionBufferedBytes`: a
  track nobody reads does not take the objects of the others.
- After PUBLISH_DONE the subscription waits for the announced stream count,
  or at most the larger of `RequestTimeout` and the delivery timeouts, then
  ends. Once no stream it received is open, it waits for the missing ones
  only the larger delivery timeout, when one is set: a stream reset before
  its header left the publisher never arrives. If the session ends first,
  the subscription ends at once with the session's error. An object over `MaxObjectSize`, or one that breaks a track rule this
  side can check alone (draft sections 3.7, 10.7 to 10.9), cancels the
  subscription with `ErrObjectTooLarge` or `ErrMalformedTrack`; the session
  stays up. A data stream for an unknown Track Alias waits up to
  `RequestTimeout` for its SUBSCRIBE_OK.
- `Update(ctx, SubscriptionUpdate{Priority, Paused})` changes priority and
  pauses or resumes; `Close` unsubscribes. `Largest` and `Properties` return
  what SUBSCRIBE_OK reported (`Properties` a copy).

### Asking for a new group

A subscriber that lost a group, or just joined a video track, does not have to wait for the next group.
`Subscription.RequestNewGroup(ctx)` sends NEW_GROUP_REQUEST in a REQUEST_UPDATE that changes nothing else.
The value is 0 while no group arrived on the subscription, else the largest group ID received plus one. At most
one request goes out every `NewGroupRequestInterval` (1 s) per subscription; a sooner call returns
`ErrNewGroupTooSoon`.

The publisher reads `TrackWriter.NewGroupRequests()`, a channel of capacity 1 that never blocks the session.
When it fires the application calls `NewGroup` and starts the group with what a joiner needs (for video, a key
frame). A request whose value is not above the track's largest group ID is answered and ignored, because a newer
group exists. Requests merge while one is pending, and the track signals at most once every
`NewGroupRequestInterval` (1 s), however many subscriptions ask: a request inside the interval is dropped, because
the group that answered the last one reaches every subscriber. A subscriber that repeats the request, or opens many
subscriptions, cannot make the publisher cut groups more often, so an application that answers each signal with a
key frame sends at most one a second for the track. A `Relay` passes a request for a relayed track on to the
publisher on its upstream subscription, at most one at a time and one every second.

## Track cache and fetch

Each track keeps the newest `CacheGroups` groups within `CacheBytes`. A
late joiner reads them with `JoinCurrentGroup`, and `Session.Fetch(ctx, ns,
track, opts)` asks for them directly: the newest `RecentGroups` groups, or
an absolute range. `Fetch.ReadObject` returns them in order and `io.EOF` at
the end. `Session.TrackStatus` returns the Largest Object and track
properties without subscribing. A FETCH over objects the cache evicted gets
an End of Unknown Range marker instead of a false "does not exist".

## Namespaces

- `Session.PublishNamespace(ctx, ns)` announces a namespace;
  `PublishedNamespace.Close` withdraws it. `Session.PeerNamespaces` lists what
  the peer announced.
- `Session.SubscribeNamespace(ctx, prefix)` returns a
  `*NamespaceSubscription` whose `Next` reports namespaces the peer starts or
  stops publishing under the prefix (from an origin, the namespaces of its
  tracks).
- The first namespace field `kolo-keys` (`KeyNamespaceField`) is reserved for
  key tracks. `PublishNamespace` refuses it (`ErrInvalidName`) and a peer's
  PUBLISH_NAMESPACE under it gets `UNAUTHORIZED`; a SUBSCRIBE_NAMESPACE
  answer never lists such a namespace, also for the empty prefix and for
  `{"kolo-keys"}`. Tracks under it are created with `TrackOptions.Readers`.

## Relay

- `NewRelay(cfg)` returns a `*Relay`; `Relay.NewServer` and `Relay.NewClient`
  start its sessions. Publishers announce namespaces with PUBLISH_NAMESPACE
  (decided by `Config.Authorize`); a peer cannot announce a namespace equal
  to or under one another peer announced.
- A relay refuses every request whose namespace starts with `kolo-keys`
  (`UNAUTHORIZED`): key tracks never pass through it.
- `RoomPolicy{Room, Member}.Authorize` is an `Authorize` for a relay that
  serves rooms. Under `Room`, a peer may announce only `Room` plus the
  lowercase hex of its own public key as one more field, and SUBSCRIBE,
  FETCH, TRACK_STATUS and SUBSCRIBE_NAMESPACE are allowed only if `Member`
  returns true (a nil `Member` admits nobody); everything else, including
  every request outside `Room`, is refused with `UNAUTHORIZED` (draft section
  15.3.3). Announcing needs no `Member` check: a non-member can announce only
  its own namespace and cannot read.
- A SUBSCRIBE for a track under an announced namespace opens one upstream
  subscription to the publisher with the longest matching namespace, shared
  by all subscribers and cached (`CacheGroups`, `CacheBytes`) for late
  joiners and FETCH. The upstream subscription joins at the current group,
  and the first subscriber is answered once that fill is cached, within
  `RequestTimeout`. The upstream subscription ends when the last subscriber
  leaves.
- A track ends at the relay as soon as its End of Track object or its
  PUBLISH_DONE arrives, before the last streams PUBLISH_DONE announces. From
  then on a SUBSCRIBE, FETCH or TRACK_STATUS for its name goes to the
  publisher again, so a track the publisher ended and created again under
  the same name is served as the new track, and the subscribers of the
  ended one get its last objects and its end. An ended track counts against
  `MaxCacheBytes` until its upstream subscription ends or its last
  subscriber leaves. A SUBSCRIBE that reaches the relay before
  either end signal joins the ended track and gets its end: a track name
  does not tell two tracks apart, so a subscriber that knows of a newer one
  subscribes again.
- When the publisher ends the track, subscribers get its PUBLISH_DONE
  status. When the publisher's session ends, they get `GOING_AWAY` only if a
  GOAWAY was sent or received on that session (draft section 12.4), and
  `INTERNAL_ERROR` if it was closed, lost or broken without one.
  `MALFORMED_TRACK` means the relay found the track malformed, and
  `INTERNAL_ERROR` also covers other upstream failures. A FETCH or
  TRACK_STATUS for a track the relay does not hold is forwarded to the
  publisher.
- A relay is configured with `RelayConfig`. `MaxCacheBytes` is the memory
  of all relayed tracks together, cached objects and a fixed cost for each
  track; a cache over it drops its oldest objects, the newest included, so
  live subscribers get every object and a late joiner or a FETCH finds
  less. A session may use its share of it, at most
  `MaxSessionCacheBytes` (a tenth of `MaxCacheBytes` by default): a SUBSCRIBE
  beyond the budget or the share gets `EXCESSIVE_LOAD`, so one subscriber
  cannot use it all and other sessions are still admitted. There is no cap
  on the number of tracks. `MaxSessionFetches` caps the FETCHes of one session
  forwarded to publishers at once. A forwarded FETCH is read at once into a
  buffer within the subscriber session's `MaxFetchBytes` (set in
  `RelayConfig.Session`), and reset with `EXCESSIVE_LOAD` when it overflows,
  so a subscriber that does not read cannot stall the publisher's session. The upstream FETCH carries
  subscriber priority 255, the least urgent (draft section 5.1.3 leaves the value to the relay), so the
  relay's live subscriptions on that session go first. Defaults and ranges are in
  [limits.md](limits.md).
- Two publishers that announce the same namespace (a reconnect): new
  subscriptions go to the newest announcement, never to a session that sent
  GOAWAY. The empty namespace is refused with `UNAUTHORIZED`.
- `RelayConfig.Resume` lets a publisher come back after it lost its
  connection. A session that ends because the connection timed out or failed,
  or because the peer called `Session.Suspend` (it closes with `CodeSuspend`,
  a code of kolo-moq's own), keeps its announcements for `Resume` (1 s to 1
  h), so the subscribers of the namespace, and a `SubscribeNamespace` of the
  room, do not see the publisher leave. A session closed by either side
  (`Close`, a local close, a termination code) withdraws them at once. When a
  new session of the same peer announces the same namespace, it takes over:
  the older session of that peer, if it still runs, is closed, and its
  relayed tracks end, so subscribers subscribe again and reach the new session.
  A held announcement is reserved for its peer: no other peer can announce
  its namespace or one under it (`UNAUTHORIZED`), and a request for a track
  under it is never routed to another peer, even one that announced a wider
  namespace, so it gets `DOES_NOT_EXIST` until the publisher is back or
  `Resume` is over. The hold ends when the peer announces the namespace
  again, when that later session closes cleanly, and when `Resume` is over.
  A relay keeps no ended session for it, only the namespace and the peer key,
  and holds at most `MaxResumeHeld` announcements, `MaxPeerResumeHeld` for
  one peer key; one that does not fit is withdrawn with its session. Without
  `Resume`, the default, announcements go with the session.

## Protected objects

Package `secobj` protects objects end to end through relays with the Kolo
profile of MoQ Secure Objects; the format is in its package documentation.

- `NewSender(origin, ns, cfg)` holds one sender's key for the media namespace
  `ns`. `SetMembers` gives the key to each member on its own key track over
  the pairwise session (`KeyNamespace(ns)`, `KeyTrack(member)`, readable only
  by that member) and rotates when the set changes. `Write(g, track, payload,
  private...)` seals the next object of a group under its track's priority;
  write each track's objects in increasing (Group ID, Object ID) order, since
  an object out of order means a re-created track and rotates. `Changed`
  reports each new key.
- `NewKeyring(cfg)` receives keys: `Receive(ctx, session, self, ns)` takes
  them from the session's peer only if `Authorize` says it owns `ns`.
- `Keyring.Opener(session, ns, track)` makes the Opener of one reader of a
  track, for example one subscription. It fails with `ErrWrongSession` unless
  the session's peer owns `ns` or is a listed relay, so a member cannot serve
  another member's tracks, data tracks included, on its own session. Each
  Opener has its own replay window: it refuses an object it opened before,
  and several readers, such as a second watch after a reconnect, can share one
  Keyring.
- A replaced key opens objects for `Retain` after the first object under its
  successor, and for `RetainMax` at most after its successor arrived, so a
  removed member who kept it cannot use it for long even if a relay withholds
  the newer objects. Bounds are in [limits.md](limits.md#secobj).
- Objects are authenticated as coming from a holder of the sender's key, not from the sender: every member that receives a key can seal objects under it, and nothing is signed per sender. A member that runs or controls a relay listed in `KeyringConfig.Relays`, or colludes with its operator, can therefore make objects that open as another member's.

## Errors

Sentinels start with `kolomoq:`: `ErrClosed`, `ErrGoingAway`, `ErrVersion`,
`ErrProtocol`, `ErrTimeout`, `ErrInvalidConfig`, `ErrInvalidName`,
`ErrInvalidProperty`, `ErrTrackExists`, `ErrTooManyTracks`,
`ErrObjectTooLarge`, `ErrMalformedTrack`, `ErrTooManyNamespaces`,
`ErrUnsupportedProperty`, `ErrRequestCanceled`. `*SessionError`,
`*RequestError` and `*PublishDoneError` carry the draft's code
(`SessionCode`, `RequestCode`, `DoneCode`). A peer's reason phrase is kept,
at most 1024 bytes and escaped, in `Reason`, and never put in `Error()`.
