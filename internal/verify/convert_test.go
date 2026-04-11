package verify

import (
	"errors"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
)

func TestOutcomeFromE2EEResult_Nil(t *testing.T) {
	if got := outcomeFromE2EEResult(nil); got != nil {
		t.Errorf("outcomeFromE2EEResult(nil) = %v, want nil", got)
	}
}

func TestE2EEResultFromOutcome_Nil(t *testing.T) {
	if got := e2eeResultFromOutcome(nil); got != nil {
		t.Errorf("e2eeResultFromOutcome(nil) = %v, want nil", got)
	}
}

func TestOutcomeFromE2EEResult_Success(t *testing.T) {
	r := &attestation.E2EETestResult{
		Attempted: true,
		APIKeyEnv: "VENICE_API_KEY",
		Detail:    "2 encrypted chunks decrypted",
	}
	o := outcomeFromE2EEResult(r)
	if !o.Attempted {
		t.Error("Attempted should be true")
	}
	if o.Failed {
		t.Error("Failed should be false")
	}
	if o.ErrMsg != "" {
		t.Errorf("ErrMsg = %q, want empty", o.ErrMsg)
	}
	if o.APIKeyEnv != "VENICE_API_KEY" {
		t.Errorf("APIKeyEnv = %q, want VENICE_API_KEY", o.APIKeyEnv)
	}
	if o.Detail != "2 encrypted chunks decrypted" {
		t.Errorf("Detail = %q", o.Detail)
	}
}

func TestOutcomeFromE2EEResult_WithError(t *testing.T) {
	r := &attestation.E2EETestResult{
		Attempted: true,
		Err:       errors.New("decryption failed"),
		Detail:    "failed after 1 chunk",
	}
	o := outcomeFromE2EEResult(r)
	if !o.Failed {
		t.Error("Failed should be true when Err is set")
	}
	if o.ErrMsg != "decryption failed" {
		t.Errorf("ErrMsg = %q, want 'decryption failed'", o.ErrMsg)
	}
}

func TestE2EEResultFromOutcome_Success(t *testing.T) {
	o := &capture.E2EEOutcome{
		Attempted: true,
		APIKeyEnv: "NEARCLOUD_API_KEY",
		Detail:    "ok",
	}
	r := e2eeResultFromOutcome(o)
	if !r.Attempted {
		t.Error("Attempted should be true")
	}
	if r.Err != nil {
		t.Errorf("Err should be nil, got %v", r.Err)
	}
	if r.APIKeyEnv != "NEARCLOUD_API_KEY" {
		t.Errorf("APIKeyEnv = %q", r.APIKeyEnv)
	}
}

func TestE2EEResultFromOutcome_WithError(t *testing.T) {
	o := &capture.E2EEOutcome{
		Attempted: true,
		Failed:    true,
		ErrMsg:    "timeout",
	}
	r := e2eeResultFromOutcome(o)
	if r.Err == nil {
		t.Fatal("Err should be non-nil when Failed is true")
	}
	if r.Err.Error() != "timeout" {
		t.Errorf("Err = %q, want 'timeout'", r.Err)
	}
}

func TestE2EEResultFromOutcome_FailedEmptyMsg(t *testing.T) {
	o := &capture.E2EEOutcome{
		Attempted: true,
		Failed:    true,
		ErrMsg:    "",
	}
	r := e2eeResultFromOutcome(o)
	if r.Err == nil {
		t.Fatal("Err should be non-nil when Failed is true")
	}
	if r.Err.Error() == "" {
		t.Error("Err message should not be empty for failed outcome with empty ErrMsg")
	}
}

func TestOutcomeE2EERoundTrip(t *testing.T) {
	original := &attestation.E2EETestResult{
		Attempted: true,
		NoAPIKey:  true,
		APIKeyEnv: "CHUTES_API_KEY",
		Err:       errors.New("connection refused"),
		Detail:    "test detail",
	}
	outcome := outcomeFromE2EEResult(original)
	restored := e2eeResultFromOutcome(outcome)

	if restored.Attempted != original.Attempted {
		t.Errorf("Attempted mismatch")
	}
	if restored.NoAPIKey != original.NoAPIKey {
		t.Errorf("NoAPIKey mismatch")
	}
	if restored.APIKeyEnv != original.APIKeyEnv {
		t.Errorf("APIKeyEnv mismatch")
	}
	if restored.Detail != original.Detail {
		t.Errorf("Detail mismatch")
	}
	if restored.Err == nil {
		t.Fatal("Err should survive round-trip")
	}
	if restored.Err.Error() != original.Err.Error() {
		t.Errorf("Err message = %q, want %q", restored.Err.Error(), original.Err.Error())
	}
}
