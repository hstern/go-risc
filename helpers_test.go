// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"encoding/json"
	"reflect"
	"testing"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
)

// Subject fixtures used across the tests.
const (
	issSubSubject = `{"format":"iss_sub","iss":"https://idp.example.com/","sub":"user-7f3e2a"}`
	emailSubject  = `{"format":"email","email":"user@example.com"}`
	phoneSubject  = `{"format":"phone_number","phone_number":"+12065550100"}`
)

// jsonEqual reports whether two JSON documents are semantically equal
// (key order and insignificant whitespace ignored).
func jsonEqual(t *testing.T, a, b []byte) bool {
	t.Helper()
	var av, bv any
	if err := json.Unmarshal(a, &av); err != nil {
		t.Fatalf("unmarshal a: %v (%s)", err, a)
	}
	if err := json.Unmarshal(b, &bv); err != nil {
		t.Fatalf("unmarshal b: %v (%s)", err, b)
	}
	return reflect.DeepEqual(av, bv)
}

// makeSET wraps a single event payload in a minimal valid SET and returns the
// claims-set bytes, as secevent.Parse expects them.
func makeSET(t *testing.T, uri, payload string) []byte {
	t.Helper()
	set := []byte(`{
		"iss": "https://idp.example.com/",
		"iat": 1615306200,
		"jti": "risc-test-0001",
		"aud": "https://receiver.example.com/risc",
		"events": {` + jsonString(uri) + `:` + payload + `}
	}`)
	// Validate it is well-formed JSON before handing it to Parse.
	if !json.Valid(set) {
		t.Fatalf("makeSET produced invalid JSON: %s", set)
	}
	return set
}

func jsonString(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

// typedEvent parses a SET carrying one event under uri and returns the typed
// event decoded through the registry.
func typedEvent(t *testing.T, uri, payload string) secevent.Event {
	t.Helper()
	set, err := secevent.Parse(makeSET(t, uri, payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ev, ok, err := set.Events.Typed(uri)
	if err != nil {
		t.Fatalf("Typed(%s): %v", uri, err)
	}
	if !ok {
		t.Fatalf("Typed(%s): not decoded (decoder not registered?)", uri)
	}
	return ev
}

// allEventURIs lists every RISC event-type URI this package defines.
var allEventURIs = []string{
	risc.AccountCredentialChangeRequiredURI,
	risc.AccountPurgedURI,
	risc.AccountDisabledURI,
	risc.AccountEnabledURI,
	risc.IdentifierChangedURI,
	risc.IdentifierRecycledURI,
	risc.CredentialCompromiseURI,
	risc.OptInURI,
	risc.OptOutInitiatedURI,
	risc.OptOutCancelledURI,
	risc.OptOutEffectiveURI,
	risc.RecoveryActivatedURI,
	risc.RecoveryInformationChangedURI,
	risc.SessionsRevokedURI,
}
