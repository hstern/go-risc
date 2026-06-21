// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
)

// TestConformanceFixtures drives every SET fixture in testdata/ through the
// full pipeline: parse the SET, decode each event through the registry, check
// the typed value validates, and re-encode it byte-equivalently. The fixtures
// are derived from the OpenID RISC Profile example figures; with no upstream
// interop harness, they are this library's conformance source of truth.
func TestConformanceFixtures(t *testing.T) {
	files, err := filepath.Glob("testdata/*.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(files) == 0 {
		t.Fatal("no conformance fixtures found in testdata/")
	}
	for _, f := range files {
		t.Run(filepath.Base(f), func(t *testing.T) {
			raw, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			set, err := secevent.Parse(raw)
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if err := set.Validate(); err != nil {
				t.Fatalf("SET.Validate: %v", err)
			}
			if set.Events.Len() == 0 {
				t.Fatal("fixture carries no events")
			}
			for uri, rawPayload := range set.Events.Raw() {
				ev, ok, err := set.Events.Typed(uri)
				if err != nil {
					t.Fatalf("Typed(%s): %v", uri, err)
				}
				if !ok {
					t.Fatalf("Typed(%s): not registered", uri)
				}
				if ev.EventTypeURI() != uri {
					t.Errorf("EventTypeURI() = %s, want %s", ev.EventTypeURI(), uri)
				}
				if err := risc.Validate(ev); err != nil {
					t.Errorf("Validate(%s): %v", uri, err)
				}
				out, err := json.Marshal(ev)
				if err != nil {
					t.Fatalf("Marshal(%s): %v", uri, err)
				}
				if !jsonEqual(t, out, rawPayload) {
					t.Errorf("re-encode mismatch for %s\n got: %s\nwant: %s", uri, out, rawPayload)
				}
			}
		})
	}
}

// TestConformanceCoverage ensures testdata/ has a fixture for every RISC event
// type the package defines.
func TestConformanceCoverage(t *testing.T) {
	seen := map[string]bool{}
	files, _ := filepath.Glob("testdata/*.json")
	for _, f := range files {
		raw, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		set, err := secevent.Parse(raw)
		if err != nil {
			t.Fatalf("Parse %s: %v", f, err)
		}
		for uri := range set.Events.Raw() {
			seen[uri] = true
		}
	}
	for _, uri := range allEventURIs {
		if !seen[uri] {
			t.Errorf("no conformance fixture covers %s", uri)
		}
	}
}
