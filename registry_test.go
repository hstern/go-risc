// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"fmt"
	"testing"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
)

// TestRegisteredTypes confirms every RISC event type decodes to the matching
// concrete Go type through go-secevent's registry (the blank-import contract).
func TestRegisteredTypes(t *testing.T) {
	wantType := map[string]string{
		risc.AccountCredentialChangeRequiredURI: "risc.AccountCredentialChangeRequired",
		risc.AccountPurgedURI:                   "risc.AccountPurged",
		risc.AccountDisabledURI:                 "risc.AccountDisabled",
		risc.AccountEnabledURI:                  "risc.AccountEnabled",
		risc.IdentifierChangedURI:               "risc.IdentifierChanged",
		risc.IdentifierRecycledURI:              "risc.IdentifierRecycled",
		risc.CredentialCompromiseURI:            "risc.CredentialCompromise",
		risc.OptInURI:                           "risc.OptIn",
		risc.OptOutInitiatedURI:                 "risc.OptOutInitiated",
		risc.OptOutCancelledURI:                 "risc.OptOutCancelled",
		risc.OptOutEffectiveURI:                 "risc.OptOutEffective",
		risc.RecoveryActivatedURI:               "risc.RecoveryActivated",
		risc.RecoveryInformationChangedURI:      "risc.RecoveryInformationChanged",
		risc.SessionsRevokedURI:                 "risc.SessionsRevoked",
	}
	for _, uri := range allEventURIs {
		ev := typedEvent(t, uri, `{"subject":`+issSubSubject+`}`)
		if got := typeName(ev); got != wantType[uri] {
			t.Errorf("%s decoded to %s, want %s", uri, got, wantType[uri])
		}
	}
}

// TestUnregisteredStaysRaw confirms an event type this build did not register
// is not decoded and round-trips byte-stably in the raw events map.
func TestUnregisteredStaysRaw(t *testing.T) {
	const unknownURI = "https://schemas.openid.net/secevent/risc/event-type/not-a-real-event"
	const payload = `{"subject":` + issSubSubject + `,"x":1}`
	set, err := secevent.Parse(makeSET(t, unknownURI, payload))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ev, ok, err := set.Events.Typed(unknownURI)
	if err != nil {
		t.Fatalf("Typed: %v", err)
	}
	if ok || ev != nil {
		t.Fatalf("unregistered URI decoded unexpectedly: ok=%v ev=%v", ok, ev)
	}
	if !jsonEqual(t, set.Events.Raw()[unknownURI], []byte(payload)) {
		t.Errorf("raw payload not preserved: %s", set.Events.Raw()[unknownURI])
	}
}

func typeName(v any) string {
	return fmt.Sprintf("%T", v)
}
