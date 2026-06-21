// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc

import (
	"encoding/json"
	"fmt"
	"maps"

	"github.com/hstern/go-subjectid"
)

// splitObject decodes a RISC event payload into its subject (parsed through
// go-subjectid) and the remaining members, leaving the "subject" key out of
// the returned map. A missing subject yields a nil SubjectIdentifier rather
// than an error — required-subject enforcement is Validate's job, keeping
// decode lenient (Postel's law). The remaining members keep their bytes
// verbatim so callers preserve unrecognized fields.
func splitObject(b []byte) (subjectid.SubjectIdentifier, map[string]json.RawMessage, error) {
	var members map[string]json.RawMessage
	if err := json.Unmarshal(b, &members); err != nil {
		return nil, nil, fmt.Errorf("risc: decode event: %w", err)
	}
	var subject subjectid.SubjectIdentifier
	if raw, ok := members["subject"]; ok {
		s, err := subjectid.Parse(raw)
		if err != nil {
			return nil, nil, fmt.Errorf("risc: decode subject: %w", err)
		}
		subject = s
		delete(members, "subject")
	}
	return subject, members, nil
}

// takeString decodes the member named key, when present, into dst as a JSON
// string and removes it from members so it does not fall through to Extra.
func takeString(members map[string]json.RawMessage, key string, dst *string) error {
	raw, ok := members[key]
	if !ok {
		return nil
	}
	if err := json.Unmarshal(raw, dst); err != nil {
		return fmt.Errorf("risc: decode %s: %w", key, err)
	}
	delete(members, key)
	return nil
}

// nonEmpty returns m, or nil when m has no entries, so an event with no extra
// members carries a nil Extra map rather than an empty one.
func nonEmpty(m map[string]json.RawMessage) map[string]json.RawMessage {
	if len(m) == 0 {
		return nil
	}
	return m
}

// marshalEvent renders a RISC event object from its subject, preserved extra
// members, and the event's known fields. A known field is emitted only when it
// is a non-empty string or a non-nil non-string value (the omitempty
// convention); the subject is emitted when non-nil. Output key order is
// canonical (encoding/json sorts object keys); the bytes of preserved extra
// members round-trip verbatim.
func marshalEvent(subject subjectid.SubjectIdentifier, extra map[string]json.RawMessage, known map[string]any) ([]byte, error) {
	out := make(map[string]json.RawMessage, len(extra)+len(known)+1)
	maps.Copy(out, extra)
	if subject != nil {
		b, err := json.Marshal(subject)
		if err != nil {
			return nil, fmt.Errorf("risc: encode subject: %w", err)
		}
		out["subject"] = b
	}
	for k, v := range known {
		if s, ok := v.(string); ok && s == "" {
			continue
		}
		b, err := json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("risc: encode %s: %w", k, err)
		}
		out[k] = b
	}
	return json.Marshal(out)
}
