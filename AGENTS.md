# AGENTS.md — go-risc

Go library implementing the OpenID RISC (Risk Incident Sharing and
Coordination) Profile 1.0 event vocabulary for Security Event Tokens.

## Dependencies

- **Runtime: the standard library plus go-secevent.** The RISC events
  this library defines ride inside an RFC 8417 SET, parsed by
  [`github.com/hstern/go-secevent`](https://github.com/hstern/go-secevent),
  which is the only direct non-stdlib runtime dependency. The Subject
  Identifier type ([`github.com/hstern/go-subjectid`](https://github.com/hstern/go-subjectid),
  RFC 9493) comes in transitively through go-secevent. Any *other*
  runtime dependency needs a discussion and a justification in the PR
  description; the default answer is "no" — this library is an event
  vocabulary, not a JOSE, HTTP, or transport stack (those concerns live
  in sibling libraries).
- **Tests: standard library only by default.** Test-only deps still
  need a one-line justification.
- **Build-time tooling: unconstrained.** Linters and release tooling
  are invoked via `go run` with a pinned version (see the CI `lint`
  job); they never end up in library users' `go.sum`.
- **`go.mod`**: keep the `module` path stable at
  `github.com/hstern/go-risc` (no `/vN` suffix for v0.x/v1.x — Go
  SemVer rule). Major-version bumps follow the `go-jose` branch
  pattern.

## What this library is (and is not)

The RISC event vocabulary, and nothing else. It defines one exported
event-type URI constant and one typed payload struct per RISC event,
each implementing go-secevent's `Event` interface, and registers a
decoder for every type from an `init` function so a side-effect import
wires the whole vocabulary into go-secevent's registry.

Deliberately out of scope, in dedicated libraries:

- **The SET envelope, parsing, validation, and the event-type registry
  mechanism** — `go-secevent`.
- **JWS sign/verify, transport, streams, and delivery** — a Shared
  Signals transport's job.
- **CAEP events** (the ongoing-session half of Shared Signals) —
  `go-caep`, the structural sibling. Keep the two vocabularies'
  event-base and registration shapes consistent; do not share code
  beyond go-secevent.

## Conventions

- Every `.go` file starts with the two-line copyright + SPDX header
  (see any existing source file).
- Lenient unmarshal, strict marshal: decoding tolerates anything
  well-formed; `Validate` (and `AddTo`, which validates before
  encoding) enforces the spec's required-field MUSTs.
- Open / unrecognized event-payload members are preserved as
  `json.RawMessage` (in each event's `Extra`) for byte-stable
  round-trips — never `map[string]any`.
- The RISC `sessions-revoked` event is deprecated by the profile in
  favour of CAEP `session-revoked`; this library decodes it for
  compatibility but offers no encouraging constructor.
