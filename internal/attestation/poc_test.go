package attestation

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// TestCheckQuoteMultisigFullFlow exercises the complete 3-peer multisig flow:
// Stage 1: collect nonces from 3 peers, Stage 2: chain partial sigs, final JWT.
func TestCheckQuoteMultisigFullFlow(t *testing.T) {
	hexQuote := "aabbccdd"

	// Track calls per peer to serve correct stage responses.
	var peerCalls [3]atomic.Int32

	monikers := []string{"alice", "bob", "carol"}
	nonces := []string{"nonce_alice", "nonce_bob", "nonce_carol"}
	testJWT := "header.payload.signature"

	makePeer := func(idx int) *httptest.Server {
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}

			call := peerCalls[idx].Add(1)

			// Call 1 = stage 1 (nonce request), Call 2 = stage 2 (signing).
			if call == 1 {
				// Stage 1: return nonce.
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"moniker":   monikers[idx],
					"nonce":     nonces[idx],
				})
				return
			}

			// Stage 2: signing.
			if idx < 2 {
				// Non-final signers return partial sigs.
				sigs := map[string]string{}
				for j := 0; j <= idx; j++ {
					sigs[monikers[j]] = "partialsig_" + monikers[j]
				}
				json.NewEncoder(w).Encode(sigs)
			} else {
				// Final signer returns the JWT.
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"label":     "test-machine",
					"jwt":       testJWT,
				})
			}
		}))
	}

	servers := make([]*httptest.Server, 3)
	peers := make([]string, 3)
	for i := range 3 {
		servers[i] = makePeer(i)
		peers[i] = servers[i].URL
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	client := &http.Client{}
	poc := NewPoCClient(peers, PoCQuorum, client)
	// Override JWT verification because the test uses a synthetic non-JWT token.
	// Production code uses verifyPoCJWTClaims by default (F-39).
	poc.jwtVerifyFn = func(jwtStr, machineID string) error { return nil }
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err != nil {
		t.Fatalf("CheckQuote: unexpected error: %v", result.Err)
	}
	if !result.Registered {
		t.Error("expected Registered=true")
	}
	if result.MachineID != "deadbeef" {
		t.Errorf("MachineID: got %q, want %q", result.MachineID, "deadbeef")
	}
	if result.Label != "test-machine" {
		t.Errorf("Label: got %q, want %q", result.Label, "test-machine")
	}
	if result.JWT != testJWT {
		t.Errorf("JWT: got %q, want %q", result.JWT, testJWT)
	}
}

// TestCheckQuote_DeterministicStage2Order verifies that stage 2 visits peers
// in sorted URL order regardless of goroutine scheduling in stage 1. Without
// this invariant, capture/replay round-tripping breaks because stage 2 POST
// bodies (which include partial_sigs from prior peers) differ across runs.
func TestCheckQuote_DeterministicStage2Order(t *testing.T) {
	hexQuote := "aabbccdd"
	monikers := []string{"alice", "bob", "carol"}
	nonceVals := []string{"nonce_alice", "nonce_bob", "nonce_carol"}

	// stage2Order records the URL of each peer as it receives its stage 2 POST.
	var mu sync.Mutex
	var stage2Order []string

	// finalIdx is the creation index of the peer that should return the final
	// JWT. Set after all servers are created (once we know sorted URL order).
	var finalIdx atomic.Int32

	makePeer := func(idx int) *httptest.Server {
		var calls atomic.Int32
		return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			var body map[string]json.RawMessage
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				http.Error(w, "bad body", http.StatusBadRequest)
				return
			}

			call := calls.Add(1)
			if call == 1 {
				// Stage 1: return nonce.
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"moniker":   monikers[idx],
					"nonce":     nonceVals[idx],
				})
				return
			}

			// Stage 2: record visit order.
			mu.Lock()
			stage2Order = append(stage2Order, r.Host)
			mu.Unlock()

			// Last peer in sorted URL order returns JWT; others return partial sigs.
			if int32(idx) == finalIdx.Load() {
				json.NewEncoder(w).Encode(map[string]string{
					"machineId": "deadbeef",
					"label":     "test-machine",
					"jwt":       "header.payload.signature",
				})
			} else {
				json.NewEncoder(w).Encode(map[string]string{
					monikers[idx]: "partialsig_" + monikers[idx],
				})
			}
		}))
	}

	servers := make([]*httptest.Server, 3)
	peers := make([]string, 3)
	for i := range 3 {
		servers[i] = makePeer(i)
		peers[i] = servers[i].URL
	}
	defer func() {
		for _, s := range servers {
			s.Close()
		}
	}()

	// Determine which idx is last in sorted URL order. httptest.NewServer
	// assigns random ports, so we can't assume idx 2 is last.
	type urlIdx struct {
		url string
		idx int
	}
	sortedByURL := make([]urlIdx, len(peers))
	for i, p := range peers {
		sortedByURL[i] = urlIdx{url: p, idx: i}
	}
	sort.Slice(sortedByURL, func(i, j int) bool {
		return sortedByURL[i].url < sortedByURL[j].url
	})
	finalIdx.Store(int32(sortedByURL[len(sortedByURL)-1].idx))

	expectedHosts := make([]string, len(sortedByURL))
	for i, s := range sortedByURL {
		expectedHosts[i] = strings.TrimPrefix(s.url, "http://")
	}

	poc := NewPoCClient(peers, PoCQuorum, &http.Client{})
	poc.jwtVerifyFn = func(jwtStr, machineID string) error { return nil }
	result := poc.CheckQuote(context.Background(), hexQuote)

	if result.Err != nil {
		t.Fatalf("CheckQuote: %v", result.Err)
	}

	// Verify stage 2 visit order matches sorted peer URLs.
	if len(stage2Order) != len(expectedHosts) {
		t.Fatalf("stage 2 visited %d peers, want %d", len(stage2Order), len(expectedHosts))
	}
	for i := range stage2Order {
		if stage2Order[i] != expectedHosts[i] {
			t.Errorf("stage 2 visit[%d]: got %s, want %s", i, stage2Order[i], expectedHosts[i])
		}
	}
	t.Logf("stage 2 order: %v", stage2Order)
}

// TestCheckQuoteNotWhitelisted verifies 403 handling.
func TestCheckQuoteNotWhitelisted(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		json.NewEncoder(w).Encode(map[string]string{"error": "Machine is not whitelisted."})
	}))
	defer server.Close()

	poc := NewPoCClient([]string{server.URL}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), "aabbccdd")

	if result.Err != nil {
		t.Fatalf("expected no error for 403, got: %v", result.Err)
	}
	if result.Registered {
		t.Error("expected Registered=false for 403")
	}
}

// TestCheckQuoteNetworkError verifies network error handling.
func TestCheckQuoteNetworkError(t *testing.T) {
	poc := NewPoCClient([]string{"http://127.0.0.1:1"}, 1, &http.Client{})
	result := poc.CheckQuote(context.Background(), "aabbccdd")

	if result.Err == nil {
		t.Fatal("expected error for unreachable server")
	}
}

// TestPoCPeers verifies the hardcoded peer list meets quorum requirements.
func TestPoCPeers(t *testing.T) {
	if len(PoCPeers) < PoCQuorum {
		t.Errorf("PoCPeers has %d entries, need at least %d for quorum", len(PoCPeers), PoCQuorum)
	}
	for _, p := range PoCPeers {
		if !strings.HasPrefix(p, "https://") {
			t.Errorf("peer %q does not use HTTPS", p)
		}
		if strings.HasSuffix(p, "/") {
			t.Errorf("peer %q has trailing slash", p)
		}
	}
}

// --------------------------------------------------------------------------
// verifyPoCJWTClaims tests
// --------------------------------------------------------------------------

// buildTestJWT constructs a minimal JWT (unsigned) with the given claims payload.
func buildTestJWT(t *testing.T, claims map[string]any) string {
	t.Helper()
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"EdDSA","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)
	sig := base64.RawURLEncoding.EncodeToString([]byte("fakesig"))
	return header + "." + payloadB64 + "." + sig
}

func TestVerifyPoCJWTClaims_Valid(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":       time.Now().Add(time.Hour).Unix(),
		"machineId": "deadbeef",
	})
	err := verifyPoCJWTClaims(token, "deadbeef")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_ValidNoMachineIDCheck(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// Empty expected machineID skips the check.
	err := verifyPoCJWTClaims(token, "")
	if err != nil {
		t.Errorf("expected no error with empty machineID, got: %v", err)
	}
}

func TestVerifyPoCJWTClaims_Expired(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":       time.Now().Add(-time.Hour).Unix(),
		"machineId": "deadbeef",
	})
	err := verifyPoCJWTClaims(token, "deadbeef")
	if err == nil {
		t.Fatal("expected error for expired JWT")
	}
	if !strings.Contains(err.Error(), "expired") {
		t.Errorf("error should mention expired: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MissingExp(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"machineId": "deadbeef",
	})
	err := verifyPoCJWTClaims(token, "deadbeef")
	if err == nil {
		t.Fatal("expected error for missing exp")
	}
	if !strings.Contains(err.Error(), "exp") {
		t.Errorf("error should mention exp: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MachineIDMismatch(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp":       time.Now().Add(time.Hour).Unix(),
		"machineId": "aaaaaaaa",
	})
	err := verifyPoCJWTClaims(token, "bbbbbbbb")
	if err == nil {
		t.Fatal("expected error for machineId mismatch")
	}
	if !strings.Contains(err.Error(), "does not match") {
		t.Errorf("error should mention mismatch: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MissingMachineID(t *testing.T) {
	token := buildTestJWT(t, map[string]any{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	err := verifyPoCJWTClaims(token, "expected-id")
	if err == nil {
		t.Fatal("expected error for missing machineId")
	}
	if !strings.Contains(err.Error(), "missing machineId") {
		t.Errorf("error should mention missing machineId: %v", err)
	}
}

func TestVerifyPoCJWTClaims_MalformedJWT(t *testing.T) {
	err := verifyPoCJWTClaims("not.a.valid.jwt.token", "")
	if err == nil {
		t.Fatal("expected error for malformed JWT")
	}
	if !strings.Contains(err.Error(), "malformed") {
		t.Errorf("error should mention malformed: %v", err)
	}
}

func TestVerifyPoCJWTClaims_BadBase64(t *testing.T) {
	err := verifyPoCJWTClaims("header.!!!invalid!!!.sig", "")
	if err == nil {
		t.Fatal("expected error for bad base64")
	}
}

func TestVerifyPoCJWTClaims_BadJSON(t *testing.T) {
	badPayload := base64.RawURLEncoding.EncodeToString([]byte("not json"))
	err := verifyPoCJWTClaims("header."+badPayload+".sig", "")
	if err == nil {
		t.Fatal("expected error for bad JSON payload")
	}
}

// --------------------------------------------------------------------------
// verifyPoCJWT (cryptographic EdDSA verification) tests
// --------------------------------------------------------------------------

func mustEdKey(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	return pub, priv
}

func signTestJWT(t *testing.T, privKey ed25519.PrivateKey, claims jwt.MapClaims) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	signed, err := token.SignedString(privKey)
	if err != nil {
		t.Fatalf("sign JWT: %v", err)
	}
	return signed
}

func TestVerifyPoCJWT_ValidSignature(t *testing.T) {
	pub, priv := mustEdKey(t)
	pc := &PoCClient{signingKey: pub}

	token := signTestJWT(t, priv, jwt.MapClaims{
		"exp":       time.Now().Add(time.Hour).Unix(),
		"machineId": "deadbeef",
	})
	err := pc.verifyPoCJWT(token, "deadbeef")
	if err != nil {
		t.Errorf("expected no error, got: %v", err)
	}
}

func TestVerifyPoCJWT_InvalidSignature(t *testing.T) {
	_, priv1, _ := ed25519.GenerateKey(nil)
	pub2, _, _ := ed25519.GenerateKey(nil)
	pc := &PoCClient{signingKey: pub2}

	// Sign with priv1 but verify with pub2.
	token := signTestJWT(t, priv1, jwt.MapClaims{
		"exp":       time.Now().Add(time.Hour).Unix(),
		"machineId": "deadbeef",
	})
	err := pc.verifyPoCJWT(token, "deadbeef")
	if err == nil {
		t.Fatal("expected error for mismatched signing key")
	}
	if !strings.Contains(err.Error(), "verification failed") {
		t.Errorf("error should mention verification failed: %v", err)
	}
}

func TestVerifyPoCJWT_ExpiredToken(t *testing.T) {
	pub, priv := mustEdKey(t)
	pc := &PoCClient{signingKey: pub}

	token := signTestJWT(t, priv, jwt.MapClaims{
		"exp":       time.Now().Add(-time.Hour).Unix(),
		"machineId": "deadbeef",
	})
	err := pc.verifyPoCJWT(token, "deadbeef")
	if err == nil {
		t.Fatal("expected error for expired token")
	}
}

func TestVerifyPoCJWT_MachineIDMismatch(t *testing.T) {
	pub, priv := mustEdKey(t)
	pc := &PoCClient{signingKey: pub}

	token := signTestJWT(t, priv, jwt.MapClaims{
		"exp":       time.Now().Add(time.Hour).Unix(),
		"machineId": "aaa",
	})
	err := pc.verifyPoCJWT(token, "bbb")
	if err == nil {
		t.Fatal("expected error for machineId mismatch")
	}
	if !strings.Contains(err.Error(), "machineId") {
		t.Errorf("error should mention machineId: %v", err)
	}
}

func TestVerifyPoCJWT_NoMachineIDCheck(t *testing.T) {
	pub, priv := mustEdKey(t)
	pc := &PoCClient{signingKey: pub}

	token := signTestJWT(t, priv, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	// Empty expected machineID skips the check.
	err := pc.verifyPoCJWT(token, "")
	if err != nil {
		t.Errorf("expected no error with empty machineID, got: %v", err)
	}
}

func TestVerifyPoCJWT_MissingMachineID(t *testing.T) {
	pub, priv := mustEdKey(t)
	pc := &PoCClient{signingKey: pub}

	token := signTestJWT(t, priv, jwt.MapClaims{
		"exp": time.Now().Add(time.Hour).Unix(),
	})
	err := pc.verifyPoCJWT(token, "expected-id")
	if err == nil {
		t.Fatal("expected error for missing machineId claim")
	}
}

func TestVerifyPoCJWT_WrongAlgorithm(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pc := &PoCClient{signingKey: pub}

	// Craft a JWT with HS256 header but it won't parse as EdDSA.
	err := pc.verifyPoCJWT("eyJhbGciOiJIUzI1NiJ9.eyJleHAiOjk5OTk5OTk5OTl9.fake", "")
	if err == nil {
		t.Fatal("expected error for wrong algorithm")
	}
}

// --------------------------------------------------------------------------
// NewPoCClientWithSigningKey tests
// --------------------------------------------------------------------------

func TestNewPoCClientWithSigningKey(t *testing.T) {
	pub, _, _ := ed25519.GenerateKey(nil)
	pc := NewPoCClientWithSigningKey(PoCPeers, PoCQuorum, &http.Client{}, pub)
	if pc.signingKey == nil {
		t.Error("signingKey should be set")
	}
	if len(pc.peers) != len(PoCPeers) {
		t.Errorf("peers len = %d, want %d", len(pc.peers), len(PoCPeers))
	}
}

func TestNewPoCClientWithSigningKey_NilKey(t *testing.T) {
	pc := NewPoCClientWithSigningKey(PoCPeers, PoCQuorum, &http.Client{}, nil)
	if pc.signingKey != nil {
		t.Error("signingKey should be nil")
	}
}

// --------------------------------------------------------------------------
// NewPoCClientWithCertPins tests
// --------------------------------------------------------------------------

func TestNewPoCClientWithCertPins_EmptyPins(t *testing.T) {
	client := &http.Client{}
	pc := NewPoCClientWithCertPins(PoCPeers, PoCQuorum, client, nil)
	// With no pins, the client should be the same.
	if pc.client != client {
		t.Error("with empty pins, client should not be wrapped")
	}
}

func TestNewPoCClientWithCertPins_WithPins(t *testing.T) {
	client := &http.Client{}
	pins := map[string][]string{
		"trust-server.scrtlabs.com": {"aabbccdd"},
	}
	pc := NewPoCClientWithCertPins(PoCPeers, PoCQuorum, client, pins)
	// With pins, the client should be different (wrapped).
	if pc.client == client {
		t.Error("with pins, client should be wrapped with cert pin transport")
	}
}

// --------------------------------------------------------------------------
// pocCertPinTransport.RoundTrip tests
// --------------------------------------------------------------------------

func TestPocCertPinTransport_NoPinsForHost(t *testing.T) {
	// No pins for the host — should pass through.
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	transport := &pocCertPinTransport{
		base: http.DefaultTransport,
		pins: map[string][]string{
			"other-host.example.com": {"aabbccdd"},
		},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestPocCertPinTransport_PinnedHostNoTLS(t *testing.T) {
	// Pin configured for host, but connection is HTTP (not HTTPS).
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	// Extract host from URL.
	host := strings.TrimPrefix(ts.URL, "http://")
	hostname := strings.Split(host, ":")[0]

	transport := &pocCertPinTransport{
		base: http.DefaultTransport,
		pins: map[string][]string{
			hostname: {"aabbccdd"},
		},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(ts.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error for non-TLS connection to pinned host")
	}
	if !strings.Contains(err.Error(), "HTTPS required") {
		t.Errorf("error should mention HTTPS required: %v", err)
	}
}

func TestPocCertPinTransport_PinnedHostMatchingCert(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	// Compute the SHA-256 fingerprint of the test server's certificate.
	cert := ts.TLS.Certificates[0]
	leaf, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	fp := sha256.Sum256(leaf.Raw)
	fpHex := hex.EncodeToString(fp[:])
	t.Logf("test server cert fingerprint: %s", fpHex)

	hostname := strings.TrimPrefix(ts.URL, "https://")
	hostname = strings.Split(hostname, ":")[0]

	transport := &pocCertPinTransport{
		base: ts.Client().Transport,
		pins: map[string][]string{
			hostname: {fpHex},
		},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(ts.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want 200", resp.StatusCode)
	}
}

func TestPocCertPinTransport_PinnedHostNonMatchingCert(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	}))
	defer ts.Close()

	hostname := strings.TrimPrefix(ts.URL, "https://")
	hostname = strings.Split(hostname, ":")[0]

	transport := &pocCertPinTransport{
		base: ts.Client().Transport,
		pins: map[string][]string{
			hostname: {"0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}
	client := &http.Client{Transport: transport}
	resp, err := client.Get(ts.URL)
	if err == nil {
		resp.Body.Close()
		t.Fatal("expected error for non-matching cert fingerprint")
	}
	if !strings.Contains(err.Error(), "pinned fingerprint") {
		t.Errorf("error should mention pinned fingerprint: %v", err)
	}
}

// --------------------------------------------------------------------------
// CheckQuote with signing key integration test
// --------------------------------------------------------------------------

func TestCheckQuoteWithSigningKey(t *testing.T) {
	pub, priv := mustEdKey(t)
	hexQuote := "aabbccdd"

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		call := calls.Add(1)
		if call == 1 {
			// Stage 1
			json.NewEncoder(w).Encode(map[string]string{
				"machineId": "deadbeef",
				"moniker":   "alice",
				"nonce":     "nonce_alice",
			})
			return
		}
		// Stage 2: return signed JWT.
		signed := signTestJWT(t, priv, jwt.MapClaims{
			"exp":       time.Now().Add(time.Hour).Unix(),
			"machineId": "deadbeef",
		})
		json.NewEncoder(w).Encode(map[string]string{
			"machineId": "deadbeef",
			"label":     "test-machine",
			"jwt":       signed,
		})
	}))
	defer server.Close()

	pc := NewPoCClientWithSigningKey([]string{server.URL}, 1, &http.Client{}, pub)
	result := pc.CheckQuote(context.Background(), hexQuote)

	if result.Err != nil {
		t.Fatalf("CheckQuote: %v", result.Err)
	}
	if !result.Registered {
		t.Error("expected Registered=true")
	}
}

// TestBuildReportWithPoCRegistered verifies cpu_id_registry Pass with PoC result.
func TestBuildReportWithPoCRegistered(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	pocResult := &PoCResult{Registered: true, Label: "test-machine"}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Pass {
		t.Errorf("cpu_id_registry with PoC registered: got %s, want PASS; detail: %s", f.Status, f.Detail)
	}
	if !strings.Contains(f.Detail, "test-machine") {
		t.Errorf("detail should contain label: %s", f.Detail)
	}
}

// TestBuildReportWithPoCNotRegistered verifies cpu_id_registry Fail.
func TestBuildReportWithPoCNotRegistered(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	pocResult := &PoCResult{Registered: false}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Fail {
		t.Errorf("cpu_id_registry with PoC not registered: got %s, want FAIL", f.Status)
	}
}

// TestBuildReportWithPoCError verifies cpu_id_registry Skip on error.
func TestBuildReportWithPoCError(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	pocResult := &PoCResult{Err: http.ErrHandlerTimeout}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, PoC: pocResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Skip {
		t.Errorf("cpu_id_registry with PoC error: got %s, want SKIP", f.Status)
	}
}

// TestBuildReportWithPPIDOffline verifies cpu_id_registry Skip with PPID.
func TestBuildReportWithPPIDOffline(t *testing.T) {
	nonce := NewNonce()
	raw := buildMinimalRaw(nonce, validSigningKey(t))
	tdxResult := &TDXVerifyResult{
		PPID:      "aabbccddee112233aabbccddee112233",
		TeeTCBSVN: make([]byte, 16),
	}

	report := BuildReport(&ReportInput{Provider: "venice", Model: "m", Raw: raw, Nonce: nonce, TDX: tdxResult, AllowFail: DefaultAllowFail})
	f := findFactor(t, report, "cpu_id_registry")
	if f.Status != Skip {
		t.Errorf("cpu_id_registry with PPID offline: got %s, want SKIP", f.Status)
	}
	if !strings.Contains(f.Detail, "aabbccdd") {
		t.Errorf("detail should contain PPID prefix: %s", f.Detail)
	}
}
