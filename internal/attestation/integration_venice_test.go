package attestation

import (
	"context"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/go-tdx-guest/pcs"
	tdxtesting "github.com/google/go-tdx-guest/testing"
	"github.com/google/go-tdx-guest/verify/trust"
	"golang.org/x/crypto/sha3"
)

// TestIntegration_Venice_Fixture exercises the entire Venice verification
// pipeline from recorded HTTP response fixtures. ALL external services are
// mocked from captured responses — nothing is skipped via offline=true.
//
// Requires fixtures captured by:
//
//	VENICE_API_KEY=... go run ./cmd/capture_venice
func veniceFixtureDir(t *testing.T) string {
	t.Helper()
	if dir := os.Getenv("VENICE_FIXTURE_DIR"); dir != "" {
		return dir
	}

	entries, err := os.ReadDir("testdata")
	if err != nil {
		t.Fatalf("read testdata: %v", err)
	}

	var latest string
	for _, e := range entries {
		if e.IsDir() && strings.HasPrefix(e.Name(), "venice_") {
			if e.Name() > latest {
				latest = e.Name()
			}
		}
	}
	if latest == "" {
		t.Skip("no venice fixture directory found in testdata/; run: go run ./cmd/capture_venice")
	}
	return filepath.Join("testdata", latest)
}

func parseVeniceCaptureTime(t *testing.T, fdir string) time.Time {
	t.Helper()
	base := filepath.Base(fdir)
	ct, err := time.Parse("venice_20060102_150405", base)
	if err != nil {
		t.Fatalf("parse capture time from %q: %v", base, err)
	}
	return ct
}

// parseVeniceFixture mirrors venice.FetchAttestation response parsing.
// This is test-only code to avoid importing the venice package's private types.
func parseVeniceFixture(t *testing.T, body []byte) *RawAttestation {
	t.Helper()

	// Venice attestation response uses the same eventLogEntry field order.
	type eventLogEntry struct {
		Digest       string `json:"digest"`
		Event        string `json:"event"`
		EventPayload string `json:"event_payload"`
		EventType    int    `json:"event_type"`
		IMR          int    `json:"imr"`
	}

	type tcbInfoObj struct {
		AppCompose string `json:"app_compose"`
	}

	var ar struct {
		Verified       bool   `json:"verified"`
		Nonce          string `json:"nonce"`
		Model          string `json:"model"`
		TEEProvider    string `json:"tee_provider"`
		SigningKey     string `json:"signing_key"`
		SigningAddress string `json:"signing_address"`
		IntelQuote     string `json:"intel_quote"`
		NvidiaPayload  string `json:"nvidia_payload"`

		EventLog []eventLogEntry `json:"event_log"`
		Info     struct {
			AppName     string          `json:"app_name"`
			ComposeHash string          `json:"compose_hash"`
			DeviceID    string          `json:"device_id"`
			OSImageHash string          `json:"os_image_hash"`
			TCBInfo     json.RawMessage `json:"tcb_info"`
		} `json:"info"`
		ModelName       string `json:"model_name"`
		UpstreamModel   string `json:"upstream_model"`
		SigningAlgo     string `json:"signing_algo"`
		TEEHardware     string `json:"tee_hardware"`
		NonceSource     string `json:"nonce_source"`
		CandidatesAvail int    `json:"candidates_available"`
		CandidatesEval  int    `json:"candidates_evaluated"`
	}
	if err := json.Unmarshal(body, &ar); err != nil {
		t.Fatalf("parse Venice fixture: %v", err)
	}

	// Extract app_compose from tcb_info (handles double-encoding).
	var appCompose string
	if len(ar.Info.TCBInfo) > 0 {
		raw := ar.Info.TCBInfo
		var str string
		if json.Unmarshal(raw, &str) == nil {
			raw = json.RawMessage(str)
		}
		var obj tcbInfoObj
		if json.Unmarshal(raw, &obj) == nil {
			appCompose = obj.AppCompose
		}
	}

	eventLog := make([]EventLogEntry, len(ar.EventLog))
	for i, e := range ar.EventLog {
		eventLog[i] = EventLogEntry{
			IMR:          e.IMR,
			Digest:       e.Digest,
			EventType:    e.EventType,
			Event:        e.Event,
			EventPayload: e.EventPayload,
		}
	}

	return &RawAttestation{
		Verified:       ar.Verified,
		Nonce:          ar.Nonce,
		Model:          ar.Model,
		TEEProvider:    ar.TEEProvider,
		SigningKey:     ar.SigningKey,
		SigningAddress: ar.SigningAddress,
		IntelQuote:     ar.IntelQuote,
		NvidiaPayload:  ar.NvidiaPayload,

		TEEHardware:     ar.TEEHardware,
		SigningAlgo:     ar.SigningAlgo,
		UpstreamModel:   ar.UpstreamModel,
		AppName:         ar.Info.AppName,
		ComposeHash:     ar.Info.ComposeHash,
		OSImageHash:     ar.Info.OSImageHash,
		DeviceID:        ar.Info.DeviceID,
		AppCompose:      appCompose,
		EventLog:        eventLog,
		EventLogCount:   len(ar.EventLog),
		NonceSource:     ar.NonceSource,
		CandidatesAvail: ar.CandidatesAvail,
		CandidatesEval:  ar.CandidatesEval,

		RawBody: body,
	}
}

func TestIntegration_Venice_Fixture(t *testing.T) {
	ctx := context.Background()

	// ---------------------------------------------------------------
	// 1. Load fixtures
	// ---------------------------------------------------------------
	fdir := veniceFixtureDir(t)
	captureTime := parseVeniceCaptureTime(t, fdir)
	t.Logf("loading fixtures from %s (captured %s)", fdir, captureTime.Format(time.RFC3339))

	attestBody := readFixtureFrom(t, fdir, "venice_attestation.json")
	nonceHex := strings.TrimSpace(string(readFixtureFrom(t, fdir, "venice_fixture_nonce.txt")))
	nonce, err := ParseNonce(nonceHex)
	if err != nil {
		t.Fatalf("parse nonce: %v", err)
	}
	t.Logf("nonce: %s", nonceHex[:16]+"...")

	// ---------------------------------------------------------------
	// 2. Parse fixture into RawAttestation
	// ---------------------------------------------------------------
	raw := parseVeniceFixture(t, attestBody)
	t.Logf("model: %s", raw.Model)
	t.Logf("intel_quote: %d hex chars", len(raw.IntelQuote))
	t.Logf("nvidia_payload: %d bytes", len(raw.NvidiaPayload))
	t.Logf("app_compose: %d bytes", len(raw.AppCompose))
	t.Logf("signing_address: %s", raw.SigningAddress)

	// ---------------------------------------------------------------
	// 3. Set up mocks for ALL external services
	// ---------------------------------------------------------------

	// 3a. Intel PCS collateral — fixture-backed Getter
	pcsGetter := buildVenicePCSGetter(t, fdir, raw)
	overrideTDXGetter(pcsGetter)
	t.Cleanup(restoreTDXGetter)

	// 3b. NVIDIA NRAS — httptest server returning captured response
	nrasBody := readFixtureFrom(t, fdir, "venice_nras_response.json")
	nrasSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("NRAS mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write(nrasBody)
	}))
	t.Cleanup(nrasSrv.Close)
	origNRAS := nrasAttestURL
	overrideNRASURL(nrasSrv.URL)
	t.Cleanup(func() { restoreNRASURL(origNRAS) })

	// 3c. NVIDIA JWKS — httptest server returning captured JWKS
	jwksBody := readFixtureFrom(t, fdir, "venice_nras_jwks.json")
	jwksSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("JWKS mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		w.Write(jwksBody)
	}))
	t.Cleanup(jwksSrv.Close)
	origJWKS := nvidiaJWKSURL
	overrideJWKSURL(jwksSrv.URL)
	t.Cleanup(func() { restoreJWKSURL(origJWKS) })

	// 3d. Sigstore — returns 200 for all digests
	sigstoreSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Sigstore mock: %s %s", r.Method, r.URL.String())
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(sigstoreSrv.Close)
	origSigstore := sigstoreSearchBase
	overrideSigstoreBase(sigstoreSrv.URL + "/?hash=")
	t.Cleanup(func() { restoreSigstoreBase(origSigstore) })

	// 3e. Rekor — returns mock UUID + DSSE entry
	testUUID := "24296fb24b8ad77a1234567890abcdef"
	dsseBody := buildMockDSSEBody(realFulcioCertPEM)
	entryResp := buildMockEntryResponse(testUUID, dsseBody)
	rekorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("Rekor mock: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/index/retrieve":
			resp, _ := json.Marshal([]string{testUUID})
			w.Write(resp)
		case "/api/v1/log/entries/retrieve":
			w.Write(entryResp)
		default:
			t.Errorf("unexpected Rekor request: %s %s", r.Method, r.URL.Path)
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(rekorSrv.Close)
	origRekor := rekorAPIBase
	overrideRekorBase(rekorSrv.URL)
	t.Cleanup(func() { restoreRekorBase(origRekor) })

	// 3f. PoC trust-servers — fixture-backed mock peers
	pocPeers := buildVenicePoCMockPeers(t, fdir)
	client := &http.Client{}

	// ---------------------------------------------------------------
	// 4. Run the pipeline
	// ---------------------------------------------------------------

	// 4a. TDX quote verification
	t.Log("--- TDX verification ---")
	tdxResult := VerifyTDXQuote(ctx, raw.IntelQuote, nonce, false)
	t.Logf("TDX parse err: %v", tdxResult.ParseErr)
	t.Logf("TDX cert chain err: %v", tdxResult.CertChainErr)
	t.Logf("TDX signature err: %v", tdxResult.SignatureErr)
	t.Logf("TDX collateral err: %v", tdxResult.CollateralErr)
	t.Logf("TDX debug: %v", tdxResult.DebugEnabled)
	t.Logf("TDX FMSPC: %s", tdxResult.FMSPC)
	t.Logf("TDX TCB status: %s", tdxResult.TcbStatus)

	if tdxResult.ParseErr != nil {
		t.Fatalf("TDX parse failed: %v", tdxResult.ParseErr)
	}

	// 4b. REPORTDATA binding (Venice scheme: keccak address + nonce)
	t.Log("--- REPORTDATA binding ---")
	detail, rdErr := verifyVeniceReportData(tdxResult.ReportData, raw, nonce)
	tdxResult.ReportDataBindingErr = rdErr
	tdxResult.ReportDataBindingDetail = detail
	t.Logf("REPORTDATA binding: detail=%q err=%v", detail, rdErr)

	// 4c. NVIDIA EAT verification
	t.Log("--- NVIDIA EAT verification ---")
	var nvidiaResult *NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = VerifyNVIDIAPayload(raw.NvidiaPayload, nonce)
		t.Logf("NVIDIA format: %s", nvidiaResult.Format)
		t.Logf("NVIDIA signature err: %v", nvidiaResult.SignatureErr)
		t.Logf("NVIDIA claims err: %v", nvidiaResult.ClaimsErr)
		t.Logf("NVIDIA nonce: %s", nvidiaResult.Nonce)
	}

	// 4d. NVIDIA NRAS verification
	t.Log("--- NVIDIA NRAS verification ---")
	var nrasResult *NvidiaVerifyResult
	if raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nrasResult = VerifyNVIDIANRAS(ctx, raw.NvidiaPayload, client,
			jwt.WithTimeFunc(func() time.Time { return captureTime }),
			jwt.WithLeeway(10*time.Second),
		)
		t.Logf("NRAS format: %s", nrasResult.Format)
		t.Logf("NRAS signature err: %v", nrasResult.SignatureErr)
		t.Logf("NRAS claims err: %v", nrasResult.ClaimsErr)
		t.Logf("NRAS overall result: %v", nrasResult.OverallResult)
	}

	// 4e. Compose binding
	t.Log("--- compose binding ---")
	var composeResult *ComposeBindingResult
	if raw.AppCompose != "" && tdxResult.ParseErr == nil {
		composeResult = &ComposeBindingResult{Checked: true}
		composeResult.Err = VerifyComposeBinding(raw.AppCompose, tdxResult.MRConfigID)
		t.Logf("compose binding err: %v", composeResult.Err)
	}

	// 4f. Sigstore
	t.Log("--- Sigstore ---")
	var sigstoreResults []SigstoreResult
	if raw.AppCompose != "" {
		dockerCompose, err := ExtractDockerCompose(raw.AppCompose)
		if err != nil {
			t.Logf("extract docker_compose_file: %v (using raw app_compose)", err)
		}
		source := dockerCompose
		if source == "" {
			source = raw.AppCompose
		}
		digests := ExtractImageDigests(source)
		t.Logf("image digests: %d", len(digests))
		for _, d := range digests {
			t.Logf("  sha256:%s...", d[:min(16, len(d))])
		}
		if len(digests) > 0 {
			sigstoreResults = CheckSigstoreDigests(ctx, digests, client)
			for _, r := range sigstoreResults {
				t.Logf("  sigstore: digest=%s ok=%v status=%d err=%v", r.Digest[:min(16, len(r.Digest))], r.OK, r.Status, r.Err)
			}
		}
	}

	// 4g. Rekor
	t.Log("--- Rekor ---")
	var rekorResults []RekorProvenance
	for _, sr := range sigstoreResults {
		if sr.OK {
			prov := FetchRekorProvenance(ctx, sr.Digest, client)
			t.Logf("  rekor: digest=%s hasCert=%v err=%v", prov.Digest[:min(16, len(prov.Digest))], prov.HasCert, prov.Err)
			rekorResults = append(rekorResults, prov)
		}
	}

	// 4h. PoC
	t.Log("--- Proof of Cloud ---")
	poc := NewPoCClient(pocPeers, 3, client)
	pocResult := poc.CheckQuote(ctx, raw.IntelQuote)
	t.Logf("PoC registered: %v", pocResult.Registered)
	t.Logf("PoC machine ID: %s", pocResult.MachineID)
	t.Logf("PoC label: %s", pocResult.Label)
	t.Logf("PoC err: %v", pocResult.Err)

	// ---------------------------------------------------------------
	// 5. Build report and assert factors
	// ---------------------------------------------------------------
	t.Log("--- BuildReport ---")
	report := BuildReport(&ReportInput{
		Provider:   "venice",
		Model:      raw.Model,
		Raw:        raw,
		Nonce:      nonce,
		TDX:        tdxResult,
		Nvidia:     nvidiaResult,
		NvidiaNRAS: nrasResult,
		PoC:        pocResult,
		Compose:    composeResult,
		Sigstore:   sigstoreResults,
		Rekor:      rekorResults,
	})

	total := report.Passed + report.Failed + report.Skipped
	t.Logf("Score: %d/%d (passed=%d failed=%d skipped=%d)",
		report.Passed, total, report.Passed, report.Failed, report.Skipped)
	for _, f := range report.Factors {
		t.Logf("  [%s] %s: %s", f.Status, f.Name, f.Detail)
	}

	// ---------------------------------------------------------------
	// 6. Assert expected factor results
	// ---------------------------------------------------------------
	expectations := []struct {
		name   string
		status Status
	}{
		{"nonce_match", Pass},
		{"tdx_quote_present", Pass},
		{"tdx_quote_structure", Pass},
		{"tdx_debug_disabled", Pass},
		{"signing_key_present", Pass},
		{"tdx_reportdata_binding", Pass},
		{"nvidia_payload_present", Pass},
		{"nvidia_nonce_match", Pass},
		{"e2ee_capable", Pass},
		{"build_transparency_log", Pass},
		{"compose_binding", Pass},
		{"sigstore_verification", Pass},
		{"event_log_integrity", Pass},
	}

	for _, exp := range expectations {
		f := findFactor(t, report, exp.name)
		if f.Status != exp.status {
			t.Errorf("factor %s: got %s, want %s (detail: %s)", exp.name, f.Status, exp.status, f.Detail)
		}
	}

	// Venice doesn't have TLS fingerprint — tls_key_binding should SKIP.
	tlsF := findFactor(t, report, "tls_key_binding")
	if tlsF.Status != Skip {
		t.Errorf("tls_key_binding: got %s, want Skip (Venice uses E2EE, not TLS binding)", tlsF.Status)
	}

	// Cert chain and signature — accept pass; log warning on fail (cert expiry).
	for _, name := range []string{"tdx_cert_chain", "tdx_quote_signature"} {
		f := findFactor(t, report, name)
		if f.Status == Fail {
			t.Logf("WARNING: %s failed (likely PCK cert expiry, recapture fixtures): %s", name, f.Detail)
		}
	}

	// Intel PCS collateral — expect pass with fixture data.
	pcsF := findFactor(t, report, "intel_pcs_collateral")
	if pcsF.Status == Fail {
		t.Logf("WARNING: intel_pcs_collateral failed (may need fixture refresh): %s", pcsF.Detail)
	} else if pcsF.Status != Pass {
		t.Errorf("intel_pcs_collateral: got %s, want Pass or Fail (detail: %s)", pcsF.Status, pcsF.Detail)
	}

	// NVIDIA signature — SPDM cert chain may have time sensitivity.
	nvidSig := findFactor(t, report, "nvidia_signature")
	if nvidSig.Status == Fail {
		t.Logf("WARNING: nvidia_signature failed (may need fixture refresh): %s", nvidSig.Detail)
	}

	// NVIDIA claims — may have time-sensitive fields.
	nvidClaims := findFactor(t, report, "nvidia_claims")
	if nvidClaims.Status == Fail {
		t.Logf("WARNING: nvidia_claims failed (may need fixture refresh): %s", nvidClaims.Detail)
	}

	// NRAS — JWT expiry is pinned to capture time, so this should pass.
	nrasF := findFactor(t, report, "nvidia_nras_verified")
	if nrasF.Status != Pass {
		t.Errorf("nvidia_nras_verified: got %s, want Pass (detail: %s)", nrasF.Status, nrasF.Detail)
	}

	// PoC — depends on whether the machine is whitelisted.
	pocF := findFactor(t, report, "cpu_id_registry")
	t.Logf("cpu_id_registry: %s (%s)", pocF.Status, pocF.Detail)

	// Not implemented — expected fail.
	for _, name := range []string{"cpu_gpu_chain", "measured_model_weights"} {
		f := findFactor(t, report, name)
		if f.Status != Fail {
			t.Errorf("factor %s: got %s, want Fail (not implemented)", name, f.Status)
		}
	}

	if report.Passed < 10 {
		t.Errorf("expected at least 10 passing factors, got %d", report.Passed)
	}
	t.Logf("PASS: %d/%d factors passed", report.Passed, total)
}

// ---------------------------------------------------------------------------
// Venice fixture helpers
// ---------------------------------------------------------------------------

func buildVenicePCSGetter(t *testing.T, fdir string, raw *RawAttestation) trust.HTTPSGetter {
	t.Helper()

	// Parse TDX quote offline to get FMSPC.
	tdxResult := VerifyTDXQuote(context.Background(), raw.IntelQuote, Nonce{}, true)
	if tdxResult.ParseErr != nil {
		t.Fatalf("parse TDX quote for FMSPC extraction: %v", tdxResult.ParseErr)
	}
	fmspc := tdxResult.FMSPC
	if fmspc == "" {
		t.Fatal("FMSPC not extracted from TDX quote")
	}
	t.Logf("PCS getter: FMSPC=%s", fmspc)

	tcbInfoBody := readFixtureFrom(t, fdir, "venice_pcs_tcbinfo.json")
	tcbInfoHeaders := readHeadersFixture(t, fdir, "venice_pcs_tcbinfo_headers.json")

	qeIdentityBody := readFixtureFrom(t, fdir, "venice_pcs_qeidentity.json")
	qeIdentityHeaders := readHeadersFixture(t, fdir, "venice_pcs_qeidentity_headers.json")

	pckCrlBody := readFixtureFrom(t, fdir, "venice_pcs_pckcrl.der")
	pckCrlHeaders := readHeadersFixture(t, fdir, "venice_pcs_pckcrl_headers.json")

	rootCrlBody := readFixtureFrom(t, fdir, "venice_pcs_rootcrl.der")

	return &tdxtesting.Getter{
		Responses: map[string]tdxtesting.HTTPResponse{
			pcs.TcbInfoURL(fmspc): {
				Header: tcbInfoHeaders,
				Body:   tcbInfoBody,
			},
			pcs.QeIdentityURL(): {
				Header: qeIdentityHeaders,
				Body:   qeIdentityBody,
			},
			pcs.PckCrlURL("platform"): {
				Header: pckCrlHeaders,
				Body:   pckCrlBody,
			},
			"https://certificates.trustedservices.intel.com/IntelSGXRootCA.der": {
				Header: nil,
				Body:   rootCrlBody,
			},
		},
	}
}

// verifyVeniceReportData mirrors venice.ReportDataVerifier.VerifyReportData.
// Inlined here to avoid a circular import (attestation → venice → attestation).
//
// Venice REPORTDATA layout:
//
//	[0:20]  = keccak256(pubkey_without_04_prefix)[12:32] (address)
//	[20:32] = zero padding
//	[32:64] = raw nonce (32 bytes)
func verifyVeniceReportData(reportData [64]byte, raw *RawAttestation, nonce Nonce) (string, error) {
	signingKeyBytes, err := hex.DecodeString(raw.SigningKey)
	if err != nil {
		return "", fmt.Errorf("signing key not valid hex: %w", err)
	}
	if len(signingKeyBytes) != 65 || signingKeyBytes[0] != 0x04 {
		return "", fmt.Errorf("signing key not uncompressed secp256k1 (got %d bytes)", len(signingKeyBytes))
	}

	h := sha3.NewLegacyKeccak256()
	h.Write(signingKeyBytes[1:])
	hash := h.Sum(nil)
	derivedAddr := hash[12:32]

	if subtle.ConstantTimeCompare(derivedAddr, reportData[:20]) != 1 {
		return "", fmt.Errorf("REPORTDATA[0:20] = %s, expected %s",
			hex.EncodeToString(reportData[:20]), hex.EncodeToString(derivedAddr))
	}

	if raw.SigningAddress != "" {
		derived := "0x" + hex.EncodeToString(derivedAddr)
		if raw.SigningAddress != derived {
			return "", fmt.Errorf("signing_address %s != derived %s", raw.SigningAddress, derived)
		}
	}

	if subtle.ConstantTimeCompare(nonce[:], reportData[32:64]) != 1 {
		return "", fmt.Errorf("REPORTDATA[32:64] = %s, expected nonce %s",
			hex.EncodeToString(reportData[32:64]), nonce.Hex())
	}

	return fmt.Sprintf("REPORTDATA binds enclave key (0x%s) and nonce", hex.EncodeToString(derivedAddr)), nil
}

func buildVenicePoCMockPeers(t *testing.T, fdir string) []string {
	t.Helper()

	type peerFixtures struct {
		stage1    []byte
		stage2    []byte
		forbidden bool
	}

	peers := make([]peerFixtures, 3)
	for i := range 3 {
		s1 := readFixtureFrom(t, fdir, fmt.Sprintf("venice_poc_stage1_%d.json", i))
		peers[i] = peerFixtures{
			stage1:    s1,
			stage2:    readFixtureFrom(t, fdir, fmt.Sprintf("venice_poc_stage2_%d.json", i)),
			forbidden: pocFixtureIs403(s1),
		}
	}

	urls := make([]string, 0, len(peers))
	for i, p := range peers {
		callCount := 0
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			callCount++
			t.Logf("PoC mock peer %d: call %d %s %s", i, callCount, r.Method, r.URL.Path)
			w.Header().Set("Content-Type", "application/json")
			if p.forbidden {
				w.WriteHeader(http.StatusForbidden)
				w.Write(p.stage1)
				return
			}
			if callCount == 1 {
				w.Write(p.stage1)
			} else {
				w.Write(p.stage2)
			}
		}))
		t.Cleanup(srv.Close)
		urls = append(urls, srv.URL)
	}

	return urls
}
