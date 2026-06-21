# go-risc

a typed event vocabulary for the **OpenID RISC (Risk Incident Sharing
and Coordination) Profile 1.0**, registered into
[go-secevent](https://github.com/hstern/go-secevent) so a Security
Event Token's `events` decode to typed Go values.

Spec: <https://openid.net/specs/openid-risc-profile-specification-1_0.html>

## What this library is

RISC is the **account-lifecycle** half of the Shared Signals family
(CAEP is the ongoing-session half): its events report that an account
was disabled, purged, enabled, had a credential compromised, or had an
identifier changed or recycled. Each event is a JSON object carried
under an event-type URI in an RFC 8417 SET's `events` claim.

This library defines one exported event-type URI constant and one typed
payload struct per RISC event — each implementing go-secevent's `Event`
interface — and registers a decoder for every type from an `init`
function. The SET envelope itself, JWS verification, and the transport
are out of scope; they belong to go-secevent and a Shared Signals
transport respectively.

## Install

```bash
go get github.com/hstern/go-risc
```

Runtime dependencies: the standard library plus
[go-secevent](https://github.com/hstern/go-secevent) (which brings in
[go-subjectid](https://github.com/hstern/go-subjectid) for the
`subject` field).

## Decode RISC events from a SET

A blank import wires every RISC decoder into go-secevent's registry;
after that, `secevent.Parse` followed by `Events.Typed` yields typed
RISC events.

```go
import (
	"fmt"

	secevent "github.com/hstern/go-secevent"
	risc "github.com/hstern/go-risc" // registers every RISC event type
)

func handle(payload []byte) error {
	set, err := secevent.Parse(payload) // payload: the verified claims-set bytes
	if err != nil {
		return err
	}
	ev, ok, err := set.Events.Typed(risc.AccountDisabledURI)
	switch {
	case err != nil:
		return err // a registered decoder rejected the payload
	case ok:
		disabled := ev.(risc.AccountDisabled)
		fmt.Println(disabled.Subject.Format(), disabled.Reason)
	}
	return nil
}
```

If you only need the side-effect registration (you decode by iterating
`set.Events`), import the package for its effect alone:

```go
import _ "github.com/hstern/go-risc"
```

An event-type URI this build does not import stays raw in
`set.Events.Raw()` and round-trips byte-for-byte.

## Build a RISC event into a SET

Each event type has a `New…` constructor that takes the required
`subject` (and any other required field) positionally; optional members
are set on the returned value. `AddTo` then validates and stores the
event under its URI.

```go
events := secevent.Events{}

e := risc.NewAccountDisabled(subjectid.IssSubID{Iss: "https://idp.example.com/", Sub: "user-7f3e2a"})
e.Reason = "hijacking"

if err := risc.AddTo(events, e); err != nil {
	return err // e.g. a credential-compromise missing its credential_type
}
// events now carries the account-disabled member, ready for a *secevent.SET.
```

`credential-compromise` carries a second required field, so its
constructor takes it positionally:
`risc.NewCredentialCompromise(subject, "password")`. The deprecated
`sessions-revoked` event has no constructor by design; prefer the CAEP
`session-revoked` event.

`AddTo` applies the library's strict-marshal contract: it calls
`Validate` first and refuses to emit a half-built event.

## Event types

Base URI: `https://schemas.openid.net/secevent/risc/event-type/`

`account-credential-change-required`, `account-purged`,
`account-disabled`, `account-enabled`, `identifier-changed`,
`identifier-recycled`, `credential-compromise`, `opt-in`,
`opt-out-initiated`, `opt-out-cancelled`, `opt-out-effective`,
`recovery-activated`, `recovery-information-changed`.

The profile's `sessions-revoked` event is **deprecated** in favour of
CAEP `session-revoked`; this library decodes it for compatibility with
deployed SETs but offers no constructor that encourages emitting it.

## Forward compatibility & validation

- **Open fields preserved.** Members not defined for an event type are
  kept verbatim in the event's `Extra` (`map[string]json.RawMessage`)
  and round-trip byte-for-byte.
- **Lenient decode, strict marshal.** Decoding tolerates anything
  well-formed; `Validate(event)` enforces the spec's MUSTs (a subject
  on every event, a `credential_type` on credential-compromise, an
  `email`/`phone_number` subject on the identifier events).

## Status

**`v0.1.0`** — the first tagged release. As a `v0.x` series the public
API may still change per [SemVer](https://semver.org/) before
`v1.0.0`. Runtime dependencies: the standard library plus go-secevent.

## License

[Apache-2.0](LICENSE).
