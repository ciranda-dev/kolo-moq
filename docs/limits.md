# Limits

Every limit has a default and a range. A zero field takes the default; a
value outside the range returns `ErrInvalidConfig`. This page is reference
material: the README does not repeat it.

## Config (per session)

| Field | Default | Range | What it bounds |
|---|---|---|---|
| `SetupTimeout` | 10s | 1s to 10m | The exchange of version prefaces and SETUP |
| `RequestTimeout` | 10s | 1s to 10m | The wait for a response, for the first message of a request stream and for a data stream header, the wait for the data stream of a fetch after FETCH_OK, and the time a data stream the peer does not read may stay blocked before it is reset |
| `MaxRequests` | 1000 | 1 to 1000000 | Requests the peer may have open; more are reset with `EXCESSIVE_LOAD` |
| `MaxSubscriptions` | 1000 | 1 to 1000000 | The peer's open subscriptions; more are refused with `EXCESSIVE_LOAD` |
| `MaxObjectSize` | 16 MiB | 1 KiB to 1 GiB | An object payload received from the peer |
| `MaxControlMessageSize` | 65535 | 8192 to 65535 | A control message from the peer; 65535 is the draft's 16-bit length |
| `MaxNamespaceFields` | 32 | 1 to 32 | Fields of a namespace in a request; 32 is the draft limit |
| `MaxNameLength` | 4096 | 1 to 4096 | A namespace plus track name in a request, in bytes; 4096 is the draft limit |
| `MaxBufferedGroups` | 64 | 1 to 1000000 | Groups queued for one subscription, on both sides |
| `MaxBufferedBytes` | 32 MiB, or `MaxObjectSize` if larger | `MaxObjectSize` to 64 GiB | Bytes queued for one subscription, on both sides |
| `MaxNamespaces` | 1000 | 1 to 1000000 | Namespaces one namespace subscription tracks, on both sides |
| `MaxFetchBytes` | `MaxBufferedBytes` | `MaxObjectSize` to 64 GiB | Bytes of cached objects held at once for the peer's FETCHes and fills, and, in a relay, the objects buffered for its forwarded FETCHes. A FETCH beyond it is refused with `EXCESSIVE_LOAD`, a fill is skipped and a forwarded FETCH is reset |

A `MaxNamespaceFields` or `MaxNameLength` below the draft limit makes a
request beyond it get `NOT_SUPPORTED`; a request beyond the draft limit
closes the session, as section 8.7 requires.

## Origin and tracks

| Field | Default | Range | What it bounds |
|---|---|---|---|
| `OriginConfig.MaxTracks` | 0 (no cap) | 0 or more | Open tracks in an `Origin`, if you set a cap. Only the local publisher creates tracks, and each track's cache is already bounded by `CacheBytes`. A `secobj.Sender` opens one key track per member |
| `OriginConfig.MaxObjectSize` | 16 MiB | 1 KiB to 1 GiB | An object payload written to the origin |
| `TrackOptions.Priority` | 128 (`DefaultPriority`) | 0 to 255 | Publisher priority; lower is more urgent |
| `TrackOptions.CacheGroups` | 16 | 1 to 1000000 | Newest groups kept for FETCH and late joiners |
| `TrackOptions.CacheBytes` | 32 MiB | 1 KiB to 64 GiB | Payload bytes kept in the cache |
| `TrackOptions` delivery timeouts | none | millisecond precision | A value below 1 ms is rounded up to 1 ms |

## Relay

| Field | Default | Range | What it bounds |
|---|---|---|---|
| `RelayConfig.MaxTracks` | 1000 | 1 to 1000000 | Tracks relayed at once, ended ones whose upstream subscription is still open included |
| `RelayConfig.MaxSessionTracks` | `MaxTracks / 10`, at least 1 | 1 to `MaxTracks` | Relayed tracks one session's SUBSCRIBEs opened and that are still relayed; more are refused with `EXCESSIVE_LOAD` |
| `RelayConfig.MaxSessionFetches` | 16 | 1 to 1000000 | FETCHes of one session the relay forwards to publishers at once; more are refused with `EXCESSIVE_LOAD` |
| `RelayConfig.CacheGroups` | 16 | 1 to 1000000 | Cache of each relayed track, as in `TrackOptions` |
| `RelayConfig.CacheBytes` | 32 MiB | 1 KiB to 64 GiB | Cache of each relayed track, as in `TrackOptions` |
| `RelayConfig.Resume` | 0 (off) | 1 s to 1 h | How long a publisher whose connection was lost keeps its announcements |
| `RelayConfig.MaxResumeHeld` | 10000 (ten times the default `MaxRequests`) | 1 to 1000000 | Announcements held for ended sessions at once; one that does not fit is withdrawn with its session. Each costs its namespace (up to 4096 bytes), the peer key and a timer for `Resume`; the ended session is not kept |
| `RelayConfig.MaxPeerResumeHeld` | The `Session`'s `MaxRequests` (1000), or `MaxResumeHeld` if lower | 1 to `MaxResumeHeld` | Announcements held for one peer key, so one key cannot fill `MaxResumeHeld` |

`RelayConfig.Session` is a `Config` that applies to every relay session; its
`Origin` must be nil. Its `MaxFetchBytes` is the budget of each session, so a relay buffers at most that much per
subscriber for forwarded fetches.

## Fixed values

| Value | Where |
|---|---|
| Reason phrases from a peer are kept up to 1024 bytes, escaped, in `Reason`, and never put in `Error()` | The draft, section 8.5 |
| `PeerImplementation` is cut to 1024 bytes and escaped | `Session.PeerImplementation` |
| Each object counts its payload, its properties (48 bytes each) and 64 bytes toward `MaxBufferedBytes` and the cache, so empty objects are not free | Queues and cache |
| A payload over 64 KiB is read as it arrives, so a peer that announces a large object and sends nothing reserves no memory | Receiving |
| Request IDs are checked for repeats in a window of the last 65536 numbers (an 8 KiB bitmap); older IDs count as repeats | Sessions |
| A write holds the send gate for at most `RequestTimeout / 100`; a stream that wrote nothing in its turn gets 1 ms turns until it makes progress | Sending |
| A stream that makes no progress for `RequestTimeout` is reset with `EXCESSIVE_LOAD` (a fetch or fill stream) or counted in `ResetGroups` (a subgroup stream) | Sending |
| A subscription runs at most one fill fetch stream at a time | Subscriptions |
| A track signals `TrackWriter.NewGroupRequests` at most once every `NewGroupRequestInterval` (1 s), whatever the number of subscriptions; an application that answers each signal with a key frame should not send more | Publishing |
| A subgroup stream for an unknown Track Alias waits up to `RequestTimeout` for its SUBSCRIBE_OK | Subscriptions |
| At most one REQUEST_UPDATE per request is outstanding (MAX_REQUEST_UPDATES is obeyed) | SETUP |
| This side keeps no authorization token aliases (MAX_AUTH_TOKEN_CACHE_SIZE is 0) and takes no range filters (MAX_FILTER_RANGES is 0) | SETUP |

## secobj

| Field | Default | Range | What it bounds |
|---|---|---|---|
| `KeyringConfig.Retain` | 450ms | up to 1m | How long a replaced key still opens objects after the first object under its successor; kolo-media's playout drops later frames anyway |
| `KeyringConfig.RetainMax` | `Retain` plus 400ms | `Retain` to 2m | How long a replaced key opens objects at most after its successor arrived, even if no object under the successor opens; 400 ms is kolo-media's hold for objects whose key is in flight |
| `KeyringConfig.MaxSenders` | 0 (no cap) | 0 or more | Namespaces a Keyring holds keys for, if you set a cap; more `Receive` calls fail with `ErrTooManySenders`. Your application chooses which senders it receives, so no peer can add one |
| `KeyringConfig.MaxKeyRate` | 64 per second | 1 to 1024 | Key messages per namespace per second; more are dropped and counted in `Stats`. A message costs 0.35 us to install, and the next object of each track re-derives its key at 2.7 us (Go benchmark, Apple M5, Go 1.27.4), up to 1024 tracks: 2.8 ms a message in the worst case, 0.18 of a core per namespace at 64 a second. Raise it only if a sender rotates faster, for example one `SetMembers` per join in a large call, or batch the joins in one `SetMembers` call |
| `KeyringConfig.ReplayGroups` | 64 | 1 to 1000000 | Groups an `Opener` accepts behind the newest of a Key ID |
| `KeyringConfig.ReplayObjects` | 8192 | 1 to 1000000 | Entries of an `Opener`'s replay window, oldest groups dropped first |
| `SenderConfig.MaxTracks` | 1024 | 1 to 1000000 | Tracks sealed under one key; one more rotates |

- A track key seals at most 2^24 units of 16 KiB of plaintext (RFC 9846 section 5.5), then the Sender rotates.
- A Keyring keeps derived keys for at most 1024 tracks per namespace, least recently used dropped first; an `Opener` keeps its replay window when its track's keys are dropped.
- Object IDs are below 2^32: the nonce holds a 32-bit Object ID.
- A media namespace has 1 to 31 fields, and its key track's full name is within 4096 bytes.

## kolo-transport streams

Each subscription holds one bidirectional stream and one unidirectional
stream per group in flight. kolo-transport's `MaxIncomingStreams` defaults
to 16 (range 1 to 1000), so raise it to match the subscriptions you expect,
as `examples/publisher` does.
