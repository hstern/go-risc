# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0]

### Added

- Producer-side `New…` constructors for every non-deprecated event type
  (`NewAccountDisabled`, `NewCredentialCompromise`, …). The required
  subject is a positional argument, so an event can be built in a single
  expression and "forgot the subject" is a compile error rather than a
  runtime `AddTo` failure. `NewCredentialCompromise` also takes its
  required `credential_type` positionally. The deprecated
  `sessions-revoked` event has no constructor by design.

### Changed

- `ExampleAddTo` and the README now build events with the constructors
  instead of declaring a value and assigning `Subject` separately. No
  wire-shape or decode-path change.

## [0.1.0]

Initial release: the OpenID RISC Profile 1.0 event vocabulary.

### Added

- Exported event-type URI constants for every RISC event type
  (13 active plus the deprecated `sessions-revoked`).
- One typed payload struct per event implementing go-secevent's `Event`
  interface, with the common `Subject` (RFC 9493 Subject Identifier)
  and per-event fields (`account-disabled` reason; `identifier-changed`
  new-value; `credential-compromise` credential_type, event_timestamp,
  reason_admin, reason_user).
- `init`-based registration of every decoder into go-secevent's
  registry, so a blank import wires the whole vocabulary in.
- `Validate` for the spec's required-field MUSTs (subject on every
  event, credential_type on credential-compromise, email/phone subject
  format on the identifier events) and `AddTo` for placing a validated
  event into a SET's events claim.
- Byte-stable preservation of unrecognized event-payload members via
  each event's `Extra` map.

[Unreleased]: https://github.com/hstern/go-risc/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hstern/go-risc/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hstern/go-risc/releases/tag/v0.1.0
