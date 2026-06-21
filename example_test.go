// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"encoding/json"
	"fmt"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
	subjectid "github.com/hstern/go-subjectid"
)

// Example decodes a SET carrying a RISC account-disabled event into its typed
// Go value. The blank import of go-risc (see the package documentation) wires
// every RISC decoder into go-secevent's registry.
func Example() {
	payload := []byte(`{
		"iss": "https://idp.example.com/",
		"iat": 1615306200,
		"jti": "risc-0001",
		"aud": "https://receiver.example.com/risc",
		"events": {
			"https://schemas.openid.net/secevent/risc/event-type/account-disabled": {
				"subject": {"format": "iss_sub", "iss": "https://idp.example.com/", "sub": "user-7f3e2a"},
				"reason": "hijacking"
			}
		}
	}`)

	set, err := secevent.Parse(payload)
	if err != nil {
		panic(err)
	}
	ev, ok, err := set.Events.Typed(risc.AccountDisabledURI)
	if err != nil || !ok {
		panic("account-disabled not decoded")
	}
	disabled := ev.(risc.AccountDisabled)
	fmt.Println(disabled.Subject.Format(), disabled.Reason)
	// Output: iss_sub hijacking
}

// ExampleAddTo builds a RISC event and places it in a SET's events claim. The
// constructor takes the required subject positionally; optional members such
// as Reason are set on the returned value.
func ExampleAddTo() {
	events := secevent.Events{}

	e := risc.NewAccountDisabled(subjectid.IssSubID{Iss: "https://idp.example.com/", Sub: "user-7f3e2a"})
	e.Reason = "bulk-account"

	if err := risc.AddTo(events, e); err != nil {
		panic(err)
	}

	var back risc.AccountDisabled
	if err := json.Unmarshal(events[risc.AccountDisabledURI], &back); err != nil {
		panic(err)
	}
	fmt.Println(back.Subject.Format(), back.Reason)
	// Output: iss_sub bulk-account
}
