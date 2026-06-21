// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc

import (
	"encoding/json"

	"github.com/hstern/go-secevent"
)

// register wires a decoder for the RISC event type T under uri into
// go-secevent's process-wide registry. The decoder unmarshals the verbatim
// events-claim member bytes into a fresh T and returns it as a secevent.Event.
//
// secevent.RegisterEventType panics on a duplicate, empty, or nil
// registration; because each URI is registered exactly once from the init
// function below, those are init-time programmer errors, not runtime
// conditions.
func register[T secevent.Event](uri string) {
	secevent.RegisterEventType(uri, func(raw json.RawMessage) (secevent.Event, error) {
		var e T
		if err := json.Unmarshal(raw, &e); err != nil {
			return nil, err
		}
		return e, nil
	})
}

// init registers every RISC event type, so a blank import of this package
// (import _ "github.com/hstern/go-risc") makes secevent.Parse decode RISC
// events into their typed values.
func init() {
	register[AccountCredentialChangeRequired](AccountCredentialChangeRequiredURI)
	register[AccountPurged](AccountPurgedURI)
	register[AccountDisabled](AccountDisabledURI)
	register[AccountEnabled](AccountEnabledURI)
	register[IdentifierChanged](IdentifierChangedURI)
	register[IdentifierRecycled](IdentifierRecycledURI)
	register[CredentialCompromise](CredentialCompromiseURI)
	register[OptIn](OptInURI)
	register[OptOutInitiated](OptOutInitiatedURI)
	register[OptOutCancelled](OptOutCancelledURI)
	register[OptOutEffective](OptOutEffectiveURI)
	register[RecoveryActivated](RecoveryActivatedURI)
	register[RecoveryInformationChanged](RecoveryInformationChangedURI)
	register[SessionsRevoked](SessionsRevokedURI)
}
