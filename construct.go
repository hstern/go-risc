// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc

import "github.com/hstern/go-subjectid"

// This file provides the producer-side constructors for the RISC event types.
// Each event embeds the unexported subjectEvent, so a consumer cannot set the
// required subject in a composite literal; the New… constructors take the
// subject (and any other required field) positionally, making "forgot the
// subject" a compile error rather than a runtime AddTo failure.
//
// Optional members (AccountDisabled.Reason, IdentifierChanged.NewValue,
// CredentialCompromise.ReasonAdmin, …) are exported fields set on the returned
// value. Construction is lenient: the constructors do not validate the subject
// format (identifier-changed/-recycled require email or phone_number); that
// check stays at the marshal boundary in AddTo/Validate (Postel's law).
//
// The deprecated sessions-revoked event has no constructor by design, so the
// API does not encourage emitting it; prefer the CAEP session-revoked event.

// NewAccountCredentialChangeRequired builds an account-credential-change-required
// event for subject.
func NewAccountCredentialChangeRequired(subject subjectid.SubjectIdentifier) AccountCredentialChangeRequired {
	return AccountCredentialChangeRequired{subjectEvent{Subject: subject}}
}

// NewAccountPurged builds an account-purged event for subject.
func NewAccountPurged(subject subjectid.SubjectIdentifier) AccountPurged {
	return AccountPurged{subjectEvent{Subject: subject}}
}

// NewAccountDisabled builds an account-disabled event for subject. Set the
// optional Reason on the returned value.
func NewAccountDisabled(subject subjectid.SubjectIdentifier) AccountDisabled {
	return AccountDisabled{subjectEvent: subjectEvent{Subject: subject}}
}

// NewAccountEnabled builds an account-enabled event for subject.
func NewAccountEnabled(subject subjectid.SubjectIdentifier) AccountEnabled {
	return AccountEnabled{subjectEvent{Subject: subject}}
}

// NewIdentifierChanged builds an identifier-changed event for subject, which
// names the old identifier and must be in email or phone_number format. Set
// the optional NewValue on the returned value.
func NewIdentifierChanged(subject subjectid.SubjectIdentifier) IdentifierChanged {
	return IdentifierChanged{subjectEvent: subjectEvent{Subject: subject}}
}

// NewIdentifierRecycled builds an identifier-recycled event for subject, which
// must be in email or phone_number format.
func NewIdentifierRecycled(subject subjectid.SubjectIdentifier) IdentifierRecycled {
	return IdentifierRecycled{subjectEvent{Subject: subject}}
}

// NewCredentialCompromise builds a credential-compromise event for subject.
// credentialType is required (the CAEP credential-type vocabulary, e.g.
// "password", "pin", "x509"). Set the optional EventTimestamp, ReasonAdmin,
// and ReasonUser on the returned value.
func NewCredentialCompromise(subject subjectid.SubjectIdentifier, credentialType string) CredentialCompromise {
	return CredentialCompromise{
		subjectEvent:   subjectEvent{Subject: subject},
		CredentialType: credentialType,
	}
}

// NewOptIn builds an opt-in event for subject.
func NewOptIn(subject subjectid.SubjectIdentifier) OptIn {
	return OptIn{subjectEvent{Subject: subject}}
}

// NewOptOutInitiated builds an opt-out-initiated event for subject.
func NewOptOutInitiated(subject subjectid.SubjectIdentifier) OptOutInitiated {
	return OptOutInitiated{subjectEvent{Subject: subject}}
}

// NewOptOutCancelled builds an opt-out-cancelled event for subject.
func NewOptOutCancelled(subject subjectid.SubjectIdentifier) OptOutCancelled {
	return OptOutCancelled{subjectEvent{Subject: subject}}
}

// NewOptOutEffective builds an opt-out-effective event for subject.
func NewOptOutEffective(subject subjectid.SubjectIdentifier) OptOutEffective {
	return OptOutEffective{subjectEvent{Subject: subject}}
}

// NewRecoveryActivated builds a recovery-activated event for subject.
func NewRecoveryActivated(subject subjectid.SubjectIdentifier) RecoveryActivated {
	return RecoveryActivated{subjectEvent{Subject: subject}}
}

// NewRecoveryInformationChanged builds a recovery-information-changed event for
// subject.
func NewRecoveryInformationChanged(subject subjectid.SubjectIdentifier) RecoveryInformationChanged {
	return RecoveryInformationChanged{subjectEvent{Subject: subject}}
}
