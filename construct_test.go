// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"encoding/json"
	"testing"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
	subjectid "github.com/hstern/go-subjectid"
)

// Concrete subject fixtures for the producer-side constructors. The identifier
// events require an email or phone_number subject (see validate.go).
var (
	ctorIssSub = subjectid.IssSubID{Iss: "https://idp.example.com/", Sub: "user-7f3e2a"}
	ctorEmail  = subjectid.EmailID{Email: "user@example.com"}
	ctorPhone  = subjectid.PhoneNumberID{PhoneNumber: "+12065550100"}
)

// constructorCase pairs an event built through its New… constructor with the
// URI it must carry. The deprecated sessions-revoked event has no constructor
// and so does not appear here.
type constructorCase struct {
	name string
	ev   secevent.Event
}

func constructorCases() []constructorCase {
	return []constructorCase{
		{"account-credential-change-required", risc.NewAccountCredentialChangeRequired(ctorIssSub)},
		{"account-purged", risc.NewAccountPurged(ctorIssSub)},
		{"account-disabled", risc.NewAccountDisabled(ctorIssSub)},
		{"account-enabled", risc.NewAccountEnabled(ctorIssSub)},
		{"identifier-changed", risc.NewIdentifierChanged(ctorEmail)},
		{"identifier-recycled", risc.NewIdentifierRecycled(ctorPhone)},
		{"credential-compromise", risc.NewCredentialCompromise(ctorIssSub, "password")},
		{"opt-in", risc.NewOptIn(ctorIssSub)},
		{"opt-out-initiated", risc.NewOptOutInitiated(ctorIssSub)},
		{"opt-out-cancelled", risc.NewOptOutCancelled(ctorIssSub)},
		{"opt-out-effective", risc.NewOptOutEffective(ctorIssSub)},
		{"recovery-activated", risc.NewRecoveryActivated(ctorIssSub)},
		{"recovery-information-changed", risc.NewRecoveryInformationChanged(ctorIssSub)},
	}
}

// TestConstructorCoverage guards that every non-deprecated event type has a
// constructor case, and that the deprecated sessions-revoked event does not —
// so adding an event type without a constructor (or adding a constructor for
// sessions-revoked) fails here.
func TestConstructorCoverage(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range constructorCases() {
		covered[c.ev.EventTypeURI()] = true
	}
	for _, uri := range allEventURIs {
		if uri == risc.SessionsRevokedURI {
			if covered[uri] {
				t.Errorf("deprecated %s should have no constructor", uri)
			}
			continue
		}
		if !covered[uri] {
			t.Errorf("event type %s has no constructor", uri)
		}
	}
}

// TestConstructorRoundTrip is the consumer-side acceptance check: build each
// event through its constructor, place it in a SET with AddTo, parse the SET
// back, and assert the decoded event is equal to the one constructed.
//
// Equality is checked on the marshaled wire form (jsonEqual), matching the
// repo's TestRoundTrip: the decode path canonicalizes a subject to a pointer
// (*subjectid.IssSubID) where a constructor may hold a value, so the Go values
// differ representationally while the events are identical on the wire — which
// is the round-trip contract this library makes.
func TestConstructorRoundTrip(t *testing.T) {
	for _, c := range constructorCases() {
		t.Run(c.name, func(t *testing.T) {
			events := secevent.Events{}
			if err := risc.AddTo(events, c.ev); err != nil {
				t.Fatalf("AddTo: %v", err)
			}
			raw, ok := events[c.ev.EventTypeURI()]
			if !ok {
				t.Fatalf("AddTo did not store event under %s", c.ev.EventTypeURI())
			}
			back := typedEvent(t, c.ev.EventTypeURI(), string(raw))
			out, err := json.Marshal(back)
			if err != nil {
				t.Fatalf("Marshal decoded: %v", err)
			}
			if !jsonEqual(t, out, raw) {
				t.Errorf("round-trip mismatch\n got: %s\nwant: %s", out, raw)
			}
		})
	}
}

// TestConstructorSetsSubject confirms the required subject is carried on the
// returned value — the footgun the constructors exist to remove.
func TestConstructorSetsSubject(t *testing.T) {
	e := risc.NewAccountDisabled(ctorIssSub)
	if e.Subject != ctorIssSub {
		t.Errorf("Subject = %#v, want %#v", e.Subject, ctorIssSub)
	}
}

// TestNewCredentialCompromiseSetsRequiredFields confirms credential-compromise
// takes its second required field (credential_type) positionally.
func TestNewCredentialCompromiseSetsRequiredFields(t *testing.T) {
	e := risc.NewCredentialCompromise(ctorIssSub, "password")
	if e.Subject != ctorIssSub {
		t.Errorf("Subject = %#v, want %#v", e.Subject, ctorIssSub)
	}
	if e.CredentialType != "password" {
		t.Errorf("CredentialType = %q, want password", e.CredentialType)
	}
}
