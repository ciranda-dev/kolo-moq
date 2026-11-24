# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `RelayConfig.MaxCacheBytes`, the memory of all relayed tracks together: their cached bytes and 50 KiB for each track itself (the heap one relayed track costs, measured in `TestMeasureRelayHeap` on darwin/arm64). Each session gets a share of it, the budget divided by the sessions with tracks open and at least one full track. A SUBSCRIBE beyond the budget or the share gets `EXCESSIVE_LOAD`; a cache that grows past either drops its oldest objects, the newest included, so the budget holds whatever the size of the objects. Default 1 GiB.
- `RelayConfig.MaxSessionCacheBytes`, the most of `MaxCacheBytes` the tracks one session opened may hold, so one session cannot take the budget and have every other refused. Default a tenth of `MaxCacheBytes` (the share `MaxSessionTracks` gave) or `CacheBytes` plus 50 KiB if larger, up to `MaxCacheBytes`.
- `BenchmarkKeyInstall` in secobj, the benchmark behind the key message cost in docs/limits.md.
- `Config.MaxSessionBufferedBytes`, the bytes queued for all of a session's subscriptions together, on both sides. Default eight times `MaxBufferedBytes` (256 MiB). The subscription of the session that holds the most drops its oldest groups, so a subscription nobody reads does not make the others lose their objects.

### Changed

- **Breaking:** `RelayConfig.MaxTracks` and `RelayConfig.MaxSessionTracks` are removed, and with them the cap of 1000 relayed tracks and 100 per session. `MaxCacheBytes` bounds the relay by bytes: a relay holds as many tracks as fit, 1500 in the default budget with room to spare. Code that set either field no longer compiles; set `MaxCacheBytes` instead.
- **Breaking:** a session's subscriptions together may queue at most `MaxSessionBufferedBytes` (256 MiB by default), where only each subscription was bounded by `MaxBufferedBytes`; a peer that holds more in queues now has its oldest groups dropped, so raise the field if you need more.
- **Breaking:** a relayed track can cache less than `CacheBytes` and `CacheGroups`, even nothing, when the relay or the session that opened it is over `MaxCacheBytes` or its share; live subscribers still get every object, but a late joiner or a FETCH then finds fewer groups, and a SUBSCRIBE can be refused by bytes where it was admitted. A relay session that opens many tracks is held to `MaxSessionCacheBytes`, a tenth of `MaxCacheBytes` by default.
- **Breaking:** `OriginConfig.MaxTracks` defaults to 0, no cap, instead of 1000, and has no upper range. A `secobj.Sender` opens one key track per member, so a call of more than 1000 members could not be keyed. A negative value is `ErrInvalidConfig`; a positive one still caps the origin with `ErrTooManyTracks`.
- **Breaking:** `secobj.KeyringConfig.MaxSenders` defaults to 0, no cap, instead of 64, and has no upper range. A negative value is `ErrInvalidConfig`; a positive one still caps the Keyring with `ErrTooManySenders`.
- **Breaking:** `Config.MaxBufferedBytes`, `Config.MaxFetchBytes`, `TrackOptions.CacheBytes` and `RelayConfig.CacheBytes` no longer stop at 64 GiB, and the new `RelayConfig.MaxCacheBytes` and `Config.MaxSessionBufferedBytes` have no 1 TiB or 64 GiB maximum: a larger value is now accepted, where it returned `ErrInvalidConfig`. Every byte budget stops only at 2^59 - 1 bytes (about 512 PiB), which keeps its int64 counter from overflowing (docs/limits.md). With `MaxBufferedBytes` above 8 GiB the default `MaxSessionBufferedBytes` is eight times it, where it stopped at 64 GiB.
- `secobj.KeyringConfig.MaxKeyRate` keeps its default of 64 a second, now derived from the measured cost of a key message instead of a peer count (see docs/limits.md).

### Fixed

- A subgroup stream that ended on a write error left its queued objects counted in `SessionStats.QueuedBytes` and against `MaxBufferedBytes`.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-moq.
