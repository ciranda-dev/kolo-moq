# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- `RelayConfig.MaxCacheBytes`, the memory of all relayed tracks together: their cached bytes and 50 KiB for each track itself (the heap one relayed track costs, measured in `TestMeasureRelayHeap`). Each session gets a share of it, the budget divided by the sessions with tracks open and at least one full track. A SUBSCRIBE beyond the budget or the share gets `EXCESSIVE_LOAD`; a cache that grows past either drops its oldest objects. Default 1 GiB, up to 1 TiB.
- `Config.MaxSessionBufferedBytes`, the bytes queued for all of a session's subscriptions together, on both sides. Default eight times `MaxBufferedBytes` (256 MiB), up to 64 GiB. The subscription that goes over drops its oldest groups.

### Changed

- **Breaking:** `RelayConfig.MaxTracks` and `RelayConfig.MaxSessionTracks` are removed, and with them the cap of 1000 relayed tracks and 100 per session. `MaxCacheBytes` bounds the relay by bytes: a relay holds as many tracks as fit, 1500 in the default budget with room to spare. Code that set either field no longer compiles; set `MaxCacheBytes` instead.
- **Breaking:** a session's subscriptions together may queue at most `MaxSessionBufferedBytes` (256 MiB by default), where only each subscription was bounded by `MaxBufferedBytes`; a peer that holds more in queues now has its oldest groups dropped, so raise the field if you need more.
- **Breaking:** `OriginConfig.MaxTracks` defaults to 0, no cap, instead of 1000, and has no upper range. A `secobj.Sender` opens one key track per member, so a call of more than 1000 members could not be keyed. A negative value is `ErrInvalidConfig`; a positive one still caps the origin with `ErrTooManyTracks`.
- **Breaking:** `secobj.KeyringConfig.MaxSenders` defaults to 0, no cap, instead of 64, and has no upper range. A negative value is `ErrInvalidConfig`; a positive one still caps the Keyring with `ErrTooManySenders`.
- `secobj.KeyringConfig.MaxKeyRate` keeps its default of 64 a second, now derived from the measured cost of a key message instead of a peer count (see docs/limits.md).

### Fixed

- A subgroup stream that ended on a write error left its queued objects counted in `SessionStats.QueuedBytes` and against `MaxBufferedBytes`.

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-moq.
