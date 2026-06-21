// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc

import (
	"fmt"

	"github.com/hstern/go-secevent"
	"github.com/hstern/go-subjectid"
)

// ValidationError reports a RISC event that violates a spec requirement. It is
// returned by Validate (and by AddTo, which validates before encoding).
type ValidationError struct {
	// EventType is the event-type URI of the offending event.
	EventType string
	// Field is the member at fault (e.g. "subject", "credential_type").
	Field string
	// Message describes the violation.
	Message string
}

func (e *ValidationError) Error() string {
	return fmt.Sprintf("risc: %s: %q %s", e.EventType, e.Field, e.Message)
}

// Validate reports whether a RISC event satisfies the OpenID RISC Profile's
// well-formedness rules. Decoding is lenient (Postel's law); Validate is the
// opt-in strict check, applied at the marshal boundary by AddTo.
//
// Every RISC event requires a subject. credential-compromise additionally
// requires credential_type. identifier-changed and identifier-recycled
// require a subject in email or phone_number format. An event that is not one
// of this package's RISC types validates as nil — there is nothing for this
// package to check.
func Validate(e secevent.Event) error {
	ws, ok := e.(withSubject)
	if !ok {
		return nil
	}
	subject := ws.subject()
	switch v := e.(type) {
	case IdentifierChanged:
		return validateIdentifierFormat(v.EventTypeURI(), subject)
	case IdentifierRecycled:
		return validateIdentifierFormat(v.EventTypeURI(), subject)
	case CredentialCompromise:
		if err := requireSubject(v.EventTypeURI(), subject); err != nil {
			return err
		}
		if v.CredentialType == "" {
			return &ValidationError{v.EventTypeURI(), "credential_type", "is required"}
		}
		return nil
	default:
		return requireSubject(e.EventTypeURI(), subject)
	}
}

func requireSubject(uri string, s subjectid.SubjectIdentifier) error {
	if s == nil {
		return &ValidationError{uri, "subject", "is required"}
	}
	return nil
}

func validateIdentifierFormat(uri string, s subjectid.SubjectIdentifier) error {
	if err := requireSubject(uri, s); err != nil {
		return err
	}
	switch s.Format() {
	case "email", "phone_number":
		return nil
	default:
		return &ValidationError{uri, "subject", `format must be "email" or "phone_number"`}
	}
}
