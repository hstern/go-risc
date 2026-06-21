// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc

import (
	"encoding/json"

	"github.com/hstern/go-secevent"
	"github.com/hstern/go-subjectid"
)

// Event-type URIs defined by the OpenID RISC Profile 1.0. Each is the key under
// which its event is carried in a SET's events claim and the value its type's
// EventTypeURI method returns.
const (
	// AccountCredentialChangeRequiredURI signals that the subject must change
	// an account credential.
	AccountCredentialChangeRequiredURI = eventTypeBase + "account-credential-change-required"
	// AccountPurgedURI signals that the subject's account was deleted.
	AccountPurgedURI = eventTypeBase + "account-purged"
	// AccountDisabledURI signals that the subject's account was disabled.
	AccountDisabledURI = eventTypeBase + "account-disabled"
	// AccountEnabledURI signals that the subject's account was (re-)enabled.
	AccountEnabledURI = eventTypeBase + "account-enabled"
	// IdentifierChangedURI signals that one of the subject's identifiers
	// changed. The subject names the old identifier.
	IdentifierChangedURI = eventTypeBase + "identifier-changed"
	// IdentifierRecycledURI signals that one of the subject's identifiers was
	// recycled to a different user.
	IdentifierRecycledURI = eventTypeBase + "identifier-recycled"
	// CredentialCompromiseURI signals that one of the subject's credentials
	// was compromised.
	CredentialCompromiseURI = eventTypeBase + "credential-compromise"
	// OptInURI signals that the subject opted in to RISC event sharing.
	OptInURI = eventTypeBase + "opt-in"
	// OptOutInitiatedURI signals that the subject began opting out of sharing.
	OptOutInitiatedURI = eventTypeBase + "opt-out-initiated"
	// OptOutCancelledURI signals that the subject cancelled an opt-out.
	OptOutCancelledURI = eventTypeBase + "opt-out-cancelled"
	// OptOutEffectiveURI signals that the subject's opt-out took effect.
	OptOutEffectiveURI = eventTypeBase + "opt-out-effective"
	// RecoveryActivatedURI signals that account recovery was activated.
	RecoveryActivatedURI = eventTypeBase + "recovery-activated"
	// RecoveryInformationChangedURI signals that the subject's recovery
	// information changed.
	RecoveryInformationChangedURI = eventTypeBase + "recovery-information-changed"
	// SessionsRevokedURI is the RISC sessions-revoked event-type URI.
	//
	// Deprecated: the RISC profile deprecates this event; new implementations
	// MUST use the CAEP session-revoked event (github.com/hstern/go-caep). This
	// package still decodes it because it appears in deployed SETs, but offers
	// no constructor that encourages emitting it.
	SessionsRevokedURI = eventTypeBase + "sessions-revoked"
)

// subjectEvent is the common shape of every RISC event: a required subject
// (RFC 9493 Subject Identifier, github.com/hstern/go-subjectid) plus any
// open-extension members the spec leaves to the implementation, preserved
// verbatim for forward-compatible round-trips. Concrete event types embed it;
// the subject-only events use its codec unchanged, while events with extra
// members override MarshalJSON and UnmarshalJSON.
type subjectEvent struct {
	// Subject is the RISC subject — the account the event concerns. RISC
	// carries the subject inside the event payload (distinct from the SET's
	// top-level sub_id).
	Subject subjectid.SubjectIdentifier
	// Extra holds members not defined by this event type, preserved verbatim
	// so an unrecognized field round-trips byte-for-byte. It is nil when the
	// payload carried only known members.
	Extra map[string]json.RawMessage
}

func (e subjectEvent) subject() subjectid.SubjectIdentifier { return e.Subject }

// UnmarshalJSON decodes the subject through go-subjectid and preserves every
// other member in Extra.
func (e *subjectEvent) UnmarshalJSON(b []byte) error {
	sub, rest, err := splitObject(b)
	if err != nil {
		return err
	}
	e.Subject = sub
	e.Extra = nonEmpty(rest)
	return nil
}

// MarshalJSON re-emits the subject and any preserved extra members.
func (e subjectEvent) MarshalJSON() ([]byte, error) {
	return marshalEvent(e.Subject, e.Extra, nil)
}

// withSubject is implemented by every RISC event through the embedded
// subjectEvent; it lets Validate reach the subject without a per-type branch.
type withSubject interface {
	subject() subjectid.SubjectIdentifier
}

// AccountCredentialChangeRequired is the account-credential-change-required
// event: the subject is required to change an account credential.
type AccountCredentialChangeRequired struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (AccountCredentialChangeRequired) EventTypeURI() string {
	return AccountCredentialChangeRequiredURI
}

// AccountPurged is the account-purged event: the subject's account was deleted.
type AccountPurged struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (AccountPurged) EventTypeURI() string { return AccountPurgedURI }

// AccountEnabled is the account-enabled event: the subject's account was
// (re-)enabled.
type AccountEnabled struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (AccountEnabled) EventTypeURI() string { return AccountEnabledURI }

// IdentifierRecycled is the identifier-recycled event: an identifier
// previously belonging to the subject was recycled to a different user. The
// subject MUST be in email or phone_number format.
type IdentifierRecycled struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (IdentifierRecycled) EventTypeURI() string { return IdentifierRecycledURI }

// OptIn is the opt-in event: the subject opted in to RISC event sharing.
type OptIn struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (OptIn) EventTypeURI() string { return OptInURI }

// OptOutInitiated is the opt-out-initiated event.
type OptOutInitiated struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (OptOutInitiated) EventTypeURI() string { return OptOutInitiatedURI }

// OptOutCancelled is the opt-out-cancelled event.
type OptOutCancelled struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (OptOutCancelled) EventTypeURI() string { return OptOutCancelledURI }

// OptOutEffective is the opt-out-effective event.
type OptOutEffective struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (OptOutEffective) EventTypeURI() string { return OptOutEffectiveURI }

// RecoveryActivated is the recovery-activated event.
type RecoveryActivated struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (RecoveryActivated) EventTypeURI() string { return RecoveryActivatedURI }

// RecoveryInformationChanged is the recovery-information-changed event.
type RecoveryInformationChanged struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (RecoveryInformationChanged) EventTypeURI() string {
	return RecoveryInformationChangedURI
}

// SessionsRevoked is the RISC sessions-revoked event.
//
// Deprecated: the RISC profile deprecates this event in favour of the CAEP
// session-revoked event (github.com/hstern/go-caep). It is decoded for
// compatibility with deployed SETs; prefer CAEP session-revoked when emitting.
type SessionsRevoked struct{ subjectEvent }

// EventTypeURI implements secevent.Event.
func (SessionsRevoked) EventTypeURI() string { return SessionsRevokedURI }

// AccountDisabled is the account-disabled event: the subject's account was
// disabled.
type AccountDisabled struct {
	subjectEvent
	// Reason is an optional machine-readable reason. The spec suggests
	// "hijacking" and "bulk-account", but the field is open: an unrecognized
	// value is preserved rather than rejected.
	Reason string
}

// EventTypeURI implements secevent.Event.
func (AccountDisabled) EventTypeURI() string { return AccountDisabledURI }

// UnmarshalJSON decodes the subject and the optional reason member.
func (e *AccountDisabled) UnmarshalJSON(b []byte) error {
	sub, rest, err := splitObject(b)
	if err != nil {
		return err
	}
	e.Subject = sub
	if err := takeString(rest, "reason", &e.Reason); err != nil {
		return err
	}
	e.Extra = nonEmpty(rest)
	return nil
}

// MarshalJSON re-emits the subject, the reason (when set), and extra members.
func (e AccountDisabled) MarshalJSON() ([]byte, error) {
	return marshalEvent(e.Subject, e.Extra, map[string]any{"reason": e.Reason})
}

// IdentifierChanged is the identifier-changed event: one of the subject's
// identifiers changed. The subject names the old identifier and MUST be in
// email or phone_number format.
type IdentifierChanged struct {
	subjectEvent
	// NewValue is the replacement identifier value. Its JSON member is the
	// hyphenated "new-value".
	NewValue string
}

// EventTypeURI implements secevent.Event.
func (IdentifierChanged) EventTypeURI() string { return IdentifierChangedURI }

// UnmarshalJSON decodes the subject and the optional new-value member.
func (e *IdentifierChanged) UnmarshalJSON(b []byte) error {
	sub, rest, err := splitObject(b)
	if err != nil {
		return err
	}
	e.Subject = sub
	if err := takeString(rest, "new-value", &e.NewValue); err != nil {
		return err
	}
	e.Extra = nonEmpty(rest)
	return nil
}

// MarshalJSON re-emits the subject, the new-value (when set), and extra members.
func (e IdentifierChanged) MarshalJSON() ([]byte, error) {
	return marshalEvent(e.Subject, e.Extra, map[string]any{"new-value": e.NewValue})
}

// CredentialCompromise is the credential-compromise event: one of the
// subject's credentials was compromised. It is the only RISC event with the
// extended field set.
type CredentialCompromise struct {
	subjectEvent
	// CredentialType is the type of credential that was compromised, using the
	// CAEP credential-type vocabulary (e.g. "password", "pin", "x509"). It is
	// required.
	CredentialType string
	// EventTimestamp is the optional time the compromise occurred.
	EventTimestamp *secevent.NumericDate
	// ReasonAdmin is an optional administrator-facing explanation.
	ReasonAdmin string
	// ReasonUser is an optional user-facing explanation.
	ReasonUser string
}

// EventTypeURI implements secevent.Event.
func (CredentialCompromise) EventTypeURI() string { return CredentialCompromiseURI }

// UnmarshalJSON decodes the subject, credential_type, event_timestamp, and the
// optional reason members.
func (e *CredentialCompromise) UnmarshalJSON(b []byte) error {
	sub, rest, err := splitObject(b)
	if err != nil {
		return err
	}
	e.Subject = sub
	if err := takeString(rest, "credential_type", &e.CredentialType); err != nil {
		return err
	}
	if raw, ok := rest["event_timestamp"]; ok {
		var ts secevent.NumericDate
		if err := json.Unmarshal(raw, &ts); err != nil {
			return err
		}
		e.EventTimestamp = &ts
		delete(rest, "event_timestamp")
	}
	if err := takeString(rest, "reason_admin", &e.ReasonAdmin); err != nil {
		return err
	}
	if err := takeString(rest, "reason_user", &e.ReasonUser); err != nil {
		return err
	}
	e.Extra = nonEmpty(rest)
	return nil
}

// MarshalJSON re-emits every set field plus extra members.
func (e CredentialCompromise) MarshalJSON() ([]byte, error) {
	known := map[string]any{
		"credential_type": e.CredentialType,
		"reason_admin":    e.ReasonAdmin,
		"reason_user":     e.ReasonUser,
	}
	if e.EventTimestamp != nil {
		known["event_timestamp"] = e.EventTimestamp
	}
	return marshalEvent(e.Subject, e.Extra, known)
}
