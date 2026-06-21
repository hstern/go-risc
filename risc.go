// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

// Package risc implements the OpenID RISC (Risk Incident Sharing and
// Coordination) Profile 1.0 event vocabulary for Security Event Tokens.
//
// RISC is the account-lifecycle half of the Shared Signals family: its events
// report that an account was disabled, purged, had a credential compromised,
// or had an identifier recycled. Each event is a JSON object carried under an
// event-type URI key in an RFC 8417 SET's events claim, decoded by
// github.com/hstern/go-secevent. This package defines one exported event-type
// URI constant and one typed payload struct per RISC event, each implementing
// go-secevent's Event interface, and registers a decoder for every type from
// an init function.
//
// Wiring the whole vocabulary into go-secevent's registry is a blank import:
//
//	import _ "github.com/hstern/go-risc"
//
// after which secevent.Parse followed by Events.Typed yields typed RISC events.
//
// The companion CAEP vocabulary (the ongoing-session half of Shared Signals)
// lives in github.com/hstern/go-caep; the two register into the same registry
// and differ only in their event sets.
package risc

// SpecVersion is the OpenID RISC profile version this package implements.
const SpecVersion = "OpenID RISC Profile 1.0"

// eventTypeBase is the URI prefix every RISC event-type URI shares
// (OpenID RISC Profile 1.0).
const eventTypeBase = "https://schemas.openid.net/secevent/risc/event-type/"
