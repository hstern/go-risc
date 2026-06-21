# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/hstern/go-risc/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/hstern/go-risc/releases/tag/v0.1.0
