# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- **Breaking:** `OriginConfig.MaxTracks` defaults to 0, no cap, instead of 1000, and has no upper range. A `secobj.Sender` opens one key track per member, so a call of more than 1000 members could not be keyed. A negative value is `ErrInvalidConfig`; a positive one still caps the origin with `ErrTooManyTracks`.
- **Breaking:** `secobj.KeyringConfig.MaxSenders` defaults to 0, no cap, instead of 64, and has no upper range. A negative value is `ErrInvalidConfig`; a positive one still caps the Keyring with `ErrTooManySenders`.
- `secobj.KeyringConfig.MaxKeyRate` keeps its default of 64 a second, now derived from the measured cost of a key message instead of a peer count (see docs/limits.md).

## [0.1.0] - 2026-11-20

### Added

- First release of kolo-moq.
