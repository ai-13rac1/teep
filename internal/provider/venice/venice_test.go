package venice_test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/venice"
)

// validAttestationJSON is a minimal but structurally complete Venice attestation
// response. The signing_key and intel_quote are intentionally short placeholder
// values — real attestation verification happens in the attestation package.
const validAttestationJSON = `{
	"verified": true,
	"nonce": "aabbccddeeff00112233445566778899aabbccddeeff001122334455667788990000000000000000000000000000000000000000000000000000000000000000",
	"model": "e2ee-qwen3-5-122b-a10b",
	"tee_provider": "TDX+NVIDIA",
	"signing_key": "04aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
	"signing_address": "0xdeadbeef",
	"intel_quote": "dGVzdHF1b3Rl",
	"nvidia_payload": "eyJhbGciOiJSUzI1NiJ9.test.payload"
}`

// makeAttestationServer starts an httptest server that serves body as the
// attestation response with the given HTTP status code.
func makeAttestationServer(t *testing.T, status int, body string) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
}

func TestAttester_FetchAttestation_Success(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, validAttestationJSON)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "test-api-key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "e2ee-qwen3-5-122b-a10b", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation returned unexpected error: %v", err)
	}

	if !raw.Verified {
		t.Error("Verified = false, want true")
	}
	if raw.Model != "e2ee-qwen3-5-122b-a10b" {
		t.Errorf("Model = %q, want %q", raw.Model, "e2ee-qwen3-5-122b-a10b")
	}
	if raw.TEEProvider != "TDX+NVIDIA" {
		t.Errorf("TEEProvider = %q, want %q", raw.TEEProvider, "TDX+NVIDIA")
	}
	if raw.IntelQuote == "" {
		t.Error("IntelQuote is empty, want non-empty")
	}
	if raw.NvidiaPayload == "" {
		t.Error("NvidiaPayload is empty, want non-empty")
	}
	if raw.SigningKey == "" {
		t.Error("SigningKey is empty, want non-empty")
	}
	if raw.SigningAddress != "0xdeadbeef" {
		t.Errorf("SigningAddress = %q, want %q", raw.SigningAddress, "0xdeadbeef")
	}
}

func TestAttester_FetchAttestation_EchoesNonce(t *testing.T) {
	// The server captures the nonce query parameter and echoes it back.
	var capturedNonce string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedNonce = r.URL.Query().Get("nonce")
		resp := map[string]interface{}{
			"verified":       true,
			"nonce":          capturedNonce,
			"model":          "e2ee-test",
			"tee_provider":   "TDX",
			"signing_key":    "04" + "aa" + "bb" + "cc", // placeholder
			"intel_quote":    "dGVzdA==",
			"nvidia_payload": "",
		}
		_ = json.NewEncoder(w).Encode(resp)
	}))
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	nonce := attestation.NewNonce()

	raw, err := a.FetchAttestation(context.Background(), "e2ee-test", nonce)
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if capturedNonce != nonce.Hex() {
		t.Errorf("server received nonce %q, want %q", capturedNonce, nonce.Hex())
	}
	if raw.Nonce != nonce.Hex() {
		t.Errorf("RawAttestation.Nonce = %q, want %q", raw.Nonce, nonce.Hex())
	}
}

func TestAttester_FetchAttestation_SendsAuthHeader(t *testing.T) {
	var capturedAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedAuth = r.Header.Get("Authorization")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validAttestationJSON))
	}))
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "my-secret-key")
	_, err := a.FetchAttestation(context.Background(), "e2ee-model", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	want := "Bearer my-secret-key"
	if capturedAuth != want {
		t.Errorf("Authorization header = %q, want %q", capturedAuth, want)
	}
}

func TestAttester_FetchAttestation_SendsModelParam(t *testing.T) {
	var capturedModel string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedModel = r.URL.Query().Get("model")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(validAttestationJSON))
	}))
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "e2ee-qwen3-5-122b-a10b", attestation.NewNonce())
	if err != nil {
		t.Fatalf("FetchAttestation: %v", err)
	}

	if capturedModel != "e2ee-qwen3-5-122b-a10b" {
		t.Errorf("model query param = %q, want %q", capturedModel, "e2ee-qwen3-5-122b-a10b")
	}
}

func TestAttester_FetchAttestation_HTTP500(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusInternalServerError, `{"error":"internal server error"}`)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 500, got nil")
	}
}

func TestAttester_FetchAttestation_HTTP401(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusUnauthorized, `{"error":"unauthorized"}`)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "bad-key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for HTTP 401, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidJSON(t *testing.T) {
	srv := makeAttestationServer(t, http.StatusOK, `not json at all`)
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid JSON, got nil")
	}
}

func TestAttester_FetchAttestation_ContextCancelled(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Block indefinitely — the cancelled context should abort before this matters.
		<-r.Context().Done()
	}))
	defer srv.Close()

	a := venice.NewAttester(srv.URL, "key")
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	_, err := a.FetchAttestation(ctx, "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for cancelled context, got nil")
	}
}

func TestAttester_FetchAttestation_InvalidBaseURL(t *testing.T) {
	// A base URL with a control character that makes url.Parse fail.
	a := venice.NewAttester("://bad url\x00", "key")
	_, err := a.FetchAttestation(context.Background(), "model", attestation.NewNonce())
	if err == nil {
		t.Fatal("expected error for invalid base URL, got nil")
	}
}

// --- Preparer tests ---

func TestPreparer_PrepareRequest_SetsHeaders(t *testing.T) {
	p := venice.NewPreparer("test-api-key")

	// Generate two distinct sessions: one for the client, one to supply a real
	// model public key (must be a valid secp256k1 point).
	clientSession, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession (client): %v", err)
	}
	modelSession, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession (model): %v", err)
	}
	modelKey := modelSession.PublicKeyHex // guaranteed valid secp256k1 point

	if err := clientSession.SetModelKey(modelKey); err != nil {
		t.Fatalf("SetModelKey: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/api/v1/chat/completions", nil)
	if err := p.PrepareRequest(req, clientSession); err != nil {
		t.Fatalf("PrepareRequest: %v", err)
	}

	if got := req.Header.Get("X-Venice-TEE-Client-Pub-Key"); got != clientSession.PublicKeyHex {
		t.Errorf("X-Venice-TEE-Client-Pub-Key = %q, want %q", got, clientSession.PublicKeyHex)
	}
	if got := req.Header.Get("X-Venice-TEE-Model-Pub-Key"); got != modelKey {
		t.Errorf("X-Venice-TEE-Model-Pub-Key = %q, want %q", got, modelKey)
	}
	if got := req.Header.Get("X-Venice-TEE-Signing-Algo"); got != "ecdsa" {
		t.Errorf("X-Venice-TEE-Signing-Algo = %q, want %q", got, "ecdsa")
	}
	if got := req.Header.Get("Authorization"); got != "Bearer test-api-key" {
		t.Errorf("Authorization = %q, want %q", got, "Bearer test-api-key")
	}
}

func TestPreparer_PrepareRequest_EmptyModelKey(t *testing.T) {
	p := venice.NewPreparer("key")
	session, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	// Do NOT call SetModelKey — ModelKeyHex is empty.

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/", nil)
	err = p.PrepareRequest(req, session)
	if err == nil {
		t.Fatal("expected error for empty ModelKeyHex, got nil")
	}
}

func TestPreparer_PrepareRequest_EmptyPublicKeyHex(t *testing.T) {
	p := venice.NewPreparer("key")
	// Construct a session with ModelKeyHex set but PublicKeyHex empty.
	// This shouldn't happen in normal usage (NewSession always sets PublicKeyHex),
	// but we guard against it defensively.
	modelSession, err := attestation.NewSession()
	if err != nil {
		t.Fatalf("NewSession: %v", err)
	}
	session := &attestation.Session{
		ModelKeyHex:  modelSession.PublicKeyHex, // valid key
		PublicKeyHex: "",                        // deliberately empty
	}

	req, _ := http.NewRequest(http.MethodPost, "https://api.venice.ai/", nil)
	err = p.PrepareRequest(req, session)
	if err == nil {
		t.Fatal("expected error for empty PublicKeyHex, got nil")
	}
}
