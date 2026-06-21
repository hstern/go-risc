// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc

import (
	"encoding/json"
	"fmt"

	"github.com/hstern/go-secevent"
)

// AddTo validates e, marshals it, and stores it in events under e's
// event-type URI, ready to be carried in a SET's events claim. It is the
// producer-side counterpart to decoding a RISC event through
// secevent.Events.Typed.
//
// AddTo validates before encoding (the library's strict-marshal contract), so
// a half-built event — for example a credential-compromise without a
// credential_type — is rejected with a *ValidationError rather than emitted.
// events must be non-nil.
func AddTo(events secevent.Events, e secevent.Event) error {
	if events == nil {
		return fmt.Errorf("risc: AddTo: nil events map")
	}
	if err := Validate(e); err != nil {
		return err
	}
	raw, err := json.Marshal(e)
	if err != nil {
		return fmt.Errorf("risc: AddTo: encode %s: %w", e.EventTypeURI(), err)
	}
	events[e.EventTypeURI()] = raw
	return nil
}
