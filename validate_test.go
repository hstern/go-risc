// Copyright 2026 The go-risc Authors
// SPDX-License-Identifier: Apache-2.0

package risc_test

import (
	"errors"
	"testing"

	risc "github.com/hstern/go-risc"
	secevent "github.com/hstern/go-secevent"
	subjectid "github.com/hstern/go-subjectid"
)

func issSub() subjectid.SubjectIdentifier {
	return subjectid.IssSubID{Iss: "https://idp.example.com/", Sub: "user-1"}
}

func emailSub() subjectid.SubjectIdentifier {
	return subjectid.EmailID{Email: "user@example.com"}
}

func validationField(t *testing.T, err error) string {
	t.Helper()
	var ve *risc.ValidationError
	if !errors.As(err, &ve) {
		t.Fatalf("error is not *risc.ValidationError: %v", err)
	}
	return ve.Field
}

// TestValidateRequiresSubject checks every RISC event rejects a nil subject.
func TestValidateRequiresSubject(t *testing.T) {
	zero := []secevent.Event{
		risc.AccountCredentialChangeRequired{}, risc.AccountPurged{},
		risc.AccountDisabled{}, risc.AccountEnabled{},
		risc.OptIn{}, risc.OptOutInitiated{}, risc.OptOutCancelled{},
		risc.OptOutEffective{}, risc.RecoveryActivated{},
		risc.RecoveryInformationChanged{}, risc.SessionsRevoked{},
		risc.CredentialCompromise{CredentialType: "password"},
		risc.IdentifierChanged{}, risc.IdentifierRecycled{},
	}
	for _, ev := range zero {
		if got := validationField(t, risc.Validate(ev)); got != "subject" {
			t.Errorf("%T: ValidationError.Field = %q, want subject", ev, got)
		}
	}
}

// TestValidateCredentialType checks credential-compromise needs credential_type.
func TestValidateCredentialType(t *testing.T) {
	e := risc.CredentialCompromise{}
	e.Subject = issSub()
	if got := validationField(t, risc.Validate(e)); got != "credential_type" {
		t.Errorf("Field = %q, want credential_type", got)
	}
	e.CredentialType = "password"
	if err := risc.Validate(e); err != nil {
		t.Errorf("valid credential-compromise rejected: %v", err)
	}
}

// TestValidateIdentifierFormat checks the email/phone subject-format rule.
func TestValidateIdentifierFormat(t *testing.T) {
	bad := risc.IdentifierChanged{}
	bad.Subject = issSub() // iss_sub is not email/phone
	if err := risc.Validate(bad); err == nil {
		t.Error("identifier-changed with iss_sub subject should fail")
	}

	good := risc.IdentifierChanged{NewValue: "new@example.com"}
	good.Subject = emailSub()
	if err := risc.Validate(good); err != nil {
		t.Errorf("identifier-changed with email subject rejected: %v", err)
	}

	rec := risc.IdentifierRecycled{}
	rec.Subject = subjectid.PhoneNumberID{PhoneNumber: "+12065550100"}
	if err := risc.Validate(rec); err != nil {
		t.Errorf("identifier-recycled with phone subject rejected: %v", err)
	}
}

// TestValidateSubjectOnlyOK checks a well-formed subject-only event passes.
func TestValidateSubjectOnlyOK(t *testing.T) {
	e := risc.AccountPurged{}
	e.Subject = issSub()
	if err := risc.Validate(e); err != nil {
		t.Errorf("valid account-purged rejected: %v", err)
	}
}
