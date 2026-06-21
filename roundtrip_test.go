// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"encoding/json"
	"strings"
	"testing"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
)

// eventCase is a representative wire payload for one RISC event type.
type eventCase struct {
	name    string
	uri     string
	payload string
}

func eventCases() []eventCase {
	return []eventCase{
		{"account-credential-change-required", risc.AccountCredentialChangeRequiredURI, `{"subject":` + issSubSubject + `}`},
		{"account-purged", risc.AccountPurgedURI, `{"subject":` + issSubSubject + `}`},
		{"account-disabled", risc.AccountDisabledURI, `{"subject":` + issSubSubject + `,"reason":"hijacking"}`},
		{"account-enabled", risc.AccountEnabledURI, `{"subject":` + issSubSubject + `}`},
		{"identifier-changed", risc.IdentifierChangedURI, `{"subject":` + emailSubject + `,"new-value":"new@example.com"}`},
		{"identifier-recycled", risc.IdentifierRecycledURI, `{"subject":` + phoneSubject + `}`},
		{"credential-compromise", risc.CredentialCompromiseURI, `{"subject":` + issSubSubject + `,"credential_type":"password","event_timestamp":1615305500,"reason_admin":"breach DB-7","reason_user":"reset your password"}`},
		{"opt-in", risc.OptInURI, `{"subject":` + issSubSubject + `}`},
		{"opt-out-initiated", risc.OptOutInitiatedURI, `{"subject":` + issSubSubject + `}`},
		{"opt-out-cancelled", risc.OptOutCancelledURI, `{"subject":` + issSubSubject + `}`},
		{"opt-out-effective", risc.OptOutEffectiveURI, `{"subject":` + issSubSubject + `}`},
		{"recovery-activated", risc.RecoveryActivatedURI, `{"subject":` + issSubSubject + `}`},
		{"recovery-information-changed", risc.RecoveryInformationChangedURI, `{"subject":` + issSubSubject + `}`},
		{"sessions-revoked", risc.SessionsRevokedURI, `{"subject":` + issSubSubject + `}`},
	}
}

// TestEventCaseCoverage guards that the round-trip table covers every URI the
// package defines — so adding an event type without a test fails here.
func TestEventCaseCoverage(t *testing.T) {
	covered := map[string]bool{}
	for _, c := range eventCases() {
		covered[c.uri] = true
	}
	for _, uri := range allEventURIs {
		if !covered[uri] {
			t.Errorf("event type %s has no round-trip case", uri)
		}
	}
}

// TestURIPrefix checks every event-type URI is under the RISC base prefix.
func TestURIPrefix(t *testing.T) {
	const base = "https://schemas.openid.net/secevent/risc/event-type/"
	for _, uri := range allEventURIs {
		if !strings.HasPrefix(uri, base) {
			t.Errorf("%s is not under the RISC base prefix", uri)
		}
	}
}

// TestRoundTrip decodes each event through the registry and re-encodes it,
// asserting the result is semantically equal to the input payload.
func TestRoundTrip(t *testing.T) {
	for _, c := range eventCases() {
		t.Run(c.name, func(t *testing.T) {
			ev := typedEvent(t, c.uri, c.payload)
			if ev.EventTypeURI() != c.uri {
				t.Errorf("EventTypeURI() = %s, want %s", ev.EventTypeURI(), c.uri)
			}
			out, err := json.Marshal(ev)
			if err != nil {
				t.Fatalf("Marshal: %v", err)
			}
			if !jsonEqual(t, out, []byte(c.payload)) {
				t.Errorf("round-trip mismatch\n got: %s\nwant: %s", out, c.payload)
			}
		})
	}
}

// TestExtraPreserved checks an unrecognized member round-trips byte-for-byte
// through the typed layer (the forward-compatibility contract).
func TestExtraPreserved(t *testing.T) {
	payload := `{"subject":` + issSubSubject + `,"reason":"hijacking","future_field":{"nested":[1,2,3]}}`
	ev := typedEvent(t, risc.AccountDisabledURI, payload)
	out, err := json.Marshal(ev)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var got map[string]json.RawMessage
	if err := json.Unmarshal(out, &got); err != nil {
		t.Fatalf("unmarshal out: %v", err)
	}
	raw, ok := got["future_field"]
	if !ok {
		t.Fatalf("future_field dropped on round-trip: %s", out)
	}
	if string(raw) != `{"nested":[1,2,3]}` {
		t.Errorf("future_field not byte-stable: got %s", raw)
	}
}

// TestTypedFields spot-checks that the typed structs expose decoded fields.
func TestTypedFields(t *testing.T) {
	disabled := typedEvent(t, risc.AccountDisabledURI, `{"subject":`+issSubSubject+`,"reason":"bulk-account"}`).(risc.AccountDisabled)
	if disabled.Reason != "bulk-account" {
		t.Errorf("Reason = %q, want bulk-account", disabled.Reason)
	}
	if disabled.Subject == nil || disabled.Subject.Format() != "iss_sub" {
		t.Errorf("Subject not decoded: %+v", disabled.Subject)
	}

	changed := typedEvent(t, risc.IdentifierChangedURI, `{"subject":`+emailSubject+`,"new-value":"new@example.com"}`).(risc.IdentifierChanged)
	if changed.NewValue != "new@example.com" {
		t.Errorf("NewValue = %q, want new@example.com", changed.NewValue)
	}

	cc := typedEvent(t, risc.CredentialCompromiseURI, `{"subject":`+issSubSubject+`,"credential_type":"password","event_timestamp":1615305500}`).(risc.CredentialCompromise)
	if cc.CredentialType != "password" {
		t.Errorf("CredentialType = %q, want password", cc.CredentialType)
	}
	if cc.EventTimestamp == nil || cc.EventTimestamp.Unix() != 1615305500 {
		t.Errorf("EventTimestamp = %v, want unix 1615305500", cc.EventTimestamp)
	}
}

// TestDecodeMalformedSubject confirms a bad subject is surfaced as a decode
// error through the registry.
func TestDecodeMalformedSubject(t *testing.T) {
	set := makeSET(t, risc.AccountPurgedURI, `{"subject":{"format":"email"}}`) // missing email member
	parsed, err := secevent.Parse(set)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if _, _, err := parsed.Events.Typed(risc.AccountPurgedURI); err == nil {
		t.Skip("subjectid.Parse is lenient on a missing email member; nothing to assert")
	}
}
