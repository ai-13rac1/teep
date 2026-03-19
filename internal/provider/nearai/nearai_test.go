package nearai_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nearai"
)

// validArrayResponseJSON simulates the model_attestations array form.
const validArrayResponseJSON = `{
	"verified": true,
	"model_attestations": [
		{
			"model": "llama-3.1-70b",
			"intel_quote": "dGVzdHF1b3Rl",
			"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.sig",
			"signing_key": "04" + "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
			"nonce": ""
		},
		{
			"model": "llama-3.1-405b",
			"intel_quote": "dGVzdHF1b3RlMg==",
			"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test2.sig2",
			"signing_key": "04" + "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
			"nonce": ""
		}
	]
}`

// validFlatResponseJSON simulates the flat (non-array) response form.
const validFlatResponseJSON = `{
	"verified": true,
	"model": "llama-3.1-70b",
	"intel_quote": "dGVzdHF1b3Rl",
	"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.sig",
	"signing_key": "04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
	"nonce": ""
}`

func makeServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestAttester_FetchAttestation_ArrayResponse_ExactMatch(t *testing.T) {
	// Array response with two models — we request the second one.
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			},
			{
				"model": "llama-3.1-405b",
				"intel_quote": "cXVvdGUy",
				"nvidia_payload": "jwt2",
				"signing_key": "04bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "llama-3.1-405b", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.Model != "llama-3.1-405b" {
		t.Errorf("Model = %q, want %q", raw.Model, "llama-3.1-405b")
	}
	if raw.IntelQuote != "cXVvdGUy" {
		t.Errorf("IntelQuote = %q, want second entry's quote", raw.IntelQuote)
	}
}

func TestAttester_FetchAttestation_ArrayResponse_FallsBackToFirst(t *testing.T) {
	// Array response, but we request a model not in the list.
	// The first entry should be returned as fallback.
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model": "llama-3.1-70b",
				"intel_quote": "cXVvdGUx",
				"nvidia_payload": "jwt1",
				"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "unknown-model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.Model != "llama-3.1-70b" {
		t.Errorf("Model = %q, want %q (first-entry fallback)", raw.Model, "llama-3.1-70b")
	}
}

func TestAttester_FetchAttestation_FlatResponse(t *testing.T) {
	srv := makeServer(t, http.StatusOK, validFlatResponseJSON)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "llama-3.1-70b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if raw.Model != "llama-3.1-70b" {
		t.Errorf("Model = %q, want %q", raw.Model, "llama-3.1-70b")
	}
	if raw.IntelQuote != "dGVzdHF1b3Rl" {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, "dGVzdHF1b3Rl")
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want %q", raw.TEEProvider, "TDX+NVIDIA")
	}
}

func TestAttester_FetchAttestation_SetsAuthHeader(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validFlatResponseJSON))
	}))
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "nearai-secret")
	_, err := a.FetchAttestation(context.Background(), "llama-3.1-70b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if capturedAuth != "Bearer nearai-secret" {
		t.Errorf("Authorization = %q, want %q", capturedAuth, "Bearer nearai-secret")
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeServer(t, http.StatusInternalServerError, `{"error":"server error"}`)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidJSON(t *testing.T) {
	srv := makeServer(t, http.StatusOK, `not json`)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAttester_FetchAttestation_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := a.FetchAttestation(ctx, "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestAttester_FetchAttestation_TEEProviderIsSet(t *testing.T) {
	// Both array and flat responses should set TEEProvider = "TDX+NVIDIA".
	body := `{
		"verified": true,
		"model_attestations": [
			{
				"model": "m",
				"intel_quote": "dA==",
				"nvidia_payload": "j",
				"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
			}
		]
	}`
	srv := makeServer(t, http.StatusOK, body)
	defer srv.Close()

	a := nearai.NewAttester(srv.URL, "key")
	raw, err := a.FetchAttestation(context.Background(), "m", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want %q", raw.TEEProvider, "TDX+NVIDIA")
	}
}

// --- Preparer tests ---

func TestPreparer_PrepareRequest_SetsAuthHeader(t *testing.T) {
	p := nearai.NewPreparer("nearai-key")
	req, _ := http.NewRequest(http.MethodPost, "https://api.near.ai/v1/chat/completions", nil)

	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	if err := p.PrepareRequest(req, session); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	if got := req.Header.Get("Authorization"); got != "Bearer nearai-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer nearai-key")
	}
}

func TestPreparer_PrepareRequest_NoSessionRequired(t *testing.T) {
	// NEAR AI's PrepareRequest should not error when session has no model key.
	p := nearai.NewPreparer("key")
	req, _ := http.NewRequest(http.MethodPost, "https://api.near.ai/", nil)
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}

	// ModelKeyHex is empty — should not error for NEAR AI.
	if err := p.PrepareRequest(req, session); err != nil {
		t.Fatalf("PrepareRequest with empty session: %v", err)
	}
}
