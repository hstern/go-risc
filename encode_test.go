// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"encoding/json"
	"testing"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
)

// TestAddTo checks AddTo stores a decodable event under its event-type URI.
func TestAddTo(t *testing.T) {
	events := secevent.Events{}
	e := risc.AccountDisabled{Reason: "hijacking"}
	e.Subject = issSub()
	if err := risc.AddTo(events, e); err != nil {
		t.Fatalf("AddTo: %v", err)
	}
	raw, ok := events[risc.AccountDisabledURI]
	if !ok {
		t.Fatal("event not stored under its URI")
	}
	var back risc.AccountDisabled
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatalf("stored bytes do not decode: %v", err)
	}
	if back.Reason != "hijacking" || back.Subject == nil || back.Subject.Format() != "iss_sub" {
		t.Errorf("round-trip lost data: %+v", back)
	}
}

// TestAddToValidates checks AddTo rejects an invalid event before storing it.
func TestAddToValidates(t *testing.T) {
	events := secevent.Events{}
	if err := risc.AddTo(events, risc.CredentialCompromise{}); err == nil {
		t.Error("AddTo stored an event with no subject/credential_type")
	}
	if len(events) != 0 {
		t.Errorf("invalid event was stored anyway: %v", events)
	}
}

// TestAddToNilMap checks AddTo reports a nil events map.
func TestAddToNilMap(t *testing.T) {
	e := risc.OptIn{}
	e.Subject = issSub()
	if err := risc.AddTo(nil, e); err == nil {
		t.Error("AddTo(nil, ...) should error")
	}
}

// TestAddToSETRoundTrip checks an AddTo'd event decodes back through a full SET.
func TestAddToSETRoundTrip(t *testing.T) {
	events := secevent.Events{}
	e := risc.AccountPurged{}
	e.Subject = issSub()
	if err := risc.AddTo(events, e); err != nil {
		t.Fatalf("AddTo: %v", err)
	}
	setBytes := makeSET(t, risc.AccountPurgedURI, string(events[risc.AccountPurgedURI]))
	parsed, err := secevent.Parse(setBytes)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	ev, ok, err := parsed.Events.Typed(risc.AccountPurgedURI)
	if err != nil || !ok {
		t.Fatalf("Typed: ok=%v err=%v", ok, err)
	}
	if _, isPurged := ev.(risc.AccountPurged); !isPurged {
		t.Errorf("decoded to %T, want risc.AccountPurged", ev)
	}
}
