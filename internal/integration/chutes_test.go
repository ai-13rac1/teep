package integration

import (
	"context"
	"net/url"
	"path"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/defaults"
	"github.com/13rac1/teep/internal/provider/chutes"
)

// extractChuteID extracts the chute UUID from the first captured instances request.
// Chutes resolves human-readable model names via API, but fixtures already have the UUID
// embedded in the captured request path.
func extractChuteID(t *testing.T, entries []capture.RecordedEntry) string {
	t.Helper()
	for i := range entries {
		if strings.Contains(entries[i].URL, "/e2e/instances/") {
			u, err := url.Parse(entries[i].URL)
			if err != nil {
				t.Fatalf("parse instances URL: %v", err)
			}
			// Extract UUID from /e2e/instances/{uuid}
			parts := strings.Split(strings.TrimPrefix(path.Clean(u.Path), "/"), "/")
			if len(parts) >= 3 && parts[1] == "instances" {
				return parts[2]
			}
		}
	}
	t.Fatal("no chute UUID found in captured instances request")
	return ""
}

func TestIntegration_Chutes_Fixture(t *testing.T) {
	ctx := context.Background()
	env := loadFixture(t, "chutes")

	// Extract chute UUID from captured request to bypass model resolution.
	chuteID := extractChuteID(t, env.entries)
	t.Logf("extracted chute ID: %s", chuteID)

	attester := chutes.NewAttester("https://api.chutes.ai", "", true)
	attester.SetClient(env.client)
	raw, err := attester.FetchAttestation(ctx, chuteID, env.nonce)
	if err != nil {
		t.Fatalf("fetch attestation: %v", err)
	}
	t.Logf("model=%s intel_quote=%d gpu_evidence=%d signing_key=%d",
		raw.Model, len(raw.IntelQuote), len(raw.GPUEvidence), len(raw.SigningKey))

	// TDX
	tdxResult := attestation.VerifyTDXQuoteOnline(ctx, raw.IntelQuote, attestation.NewCollateralGetter(env.client))
	if tdxResult.ParseErr != nil {
		t.Fatalf("TDX parse: %v", tdxResult.ParseErr)
	}
	t.Logf("TDX: cert_chain=%v sig=%v collateral=%v fmspc=%s tcb=%s",
		tdxResult.CertChainErr, tdxResult.SignatureErr, tdxResult.CollateralErr,
		tdxResult.FMSPC, tdxResult.TcbStatus)

	// REPORTDATA binding
	detail, rdErr := chutes.ReportDataVerifier{}.VerifyReportData(tdxResult.ReportData, raw, env.nonce)
	tdxResult.ReportDataBindingErr = rdErr
	tdxResult.ReportDataBindingDetail = detail
	t.Logf("REPORTDATA: detail=%q err=%v", detail, rdErr)

	// NVIDIA EAT
	var nvidiaResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" {
		nvidiaResult = attestation.VerifyNVIDIAPayload(ctx, raw.NvidiaPayload, env.nonce)
		t.Logf("NVIDIA EAT: format=%s sig_err=%v claims_err=%v", nvidiaResult.Format, nvidiaResult.SignatureErr, nvidiaResult.ClaimsErr)
	}

	// NVIDIA NRAS (time-pinned)
	var nrasResult *attestation.NvidiaVerifyResult
	if raw.NvidiaPayload != "" && raw.NvidiaPayload[0] == '{' {
		nrasResult = attestation.DefaultNVIDIAVerifier().VerifyNRAS(ctx, raw.NvidiaPayload, env.client,
			jwt.WithTimeFunc(func() time.Time { return env.manifest.CapturedAt }),
			jwt.WithLeeway(10*time.Second),
		)
		t.Logf("NRAS: format=%s sig_err=%v claims_err=%v result=%v",
			nrasResult.Format, nrasResult.SignatureErr, nrasResult.ClaimsErr, nrasResult.OverallResult)
	}

	// PoC
	poc := attestation.NewPoCClient(attestation.PoCPeers, attestation.PoCQuorum, env.client)
	pocResult := poc.CheckQuote(ctx, raw.IntelQuote)
	t.Logf("PoC: registered=%v err=%v", pocResult.Registered, pocResult.Err)

	modelPolicy, _ := defaults.MeasurementDefaults("chutes")
	report := attestation.BuildReport(&attestation.ReportInput{
		Provider:          "chutes",
		Model:             env.manifest.Model,
		Raw:               raw,
		Nonce:             env.nonce,
		TDX:               tdxResult,
		Nvidia:            nvidiaResult,
		NvidiaNRAS:        nrasResult,
		PoC:               pocResult,
		Policy:            modelPolicy,
		SupplyChainPolicy: nil,
		AllowFail:         serveAllowFail("chutes"),
		E2EEConfigured:    true, // Chutes always uses E2EE
		Inapplicable:      chutes.InapplicableFactors(),
	})

	logReportFactors(t, report)

	assertChutesReport(t, report)
}

func assertChutesReport(t *testing.T, report *attestation.VerificationReport) {
	t.Helper()

	assertMustPass(t, report, []string{
		"nonce_match",
		"tee_quote_present",
		"tee_quote_structure",
		"tee_cert_chain",
		"tee_quote_signature",
		"tee_debug_disabled",
		"tee_measurement",
		"signing_key_present",
		"tee_reportdata_binding",
		"nvidia_payload_present",
		"e2ee_capable",
	})

	// Not Applicable: factors handled by Chutes' applicability layer.
	for _, name := range []string{
		"compose_binding",
		"build_transparency_log",
		"sigstore_verification",
		"event_log_integrity",
		"sigstore_code_verified",
		"nvswitch_binding",
	} {
		assertFactorStatus(t, report, name, attestation.NotApplicable)
	}

	// Chutes uses whole-body E2EE and does not use pinned TLS key binding.
	assertFactorStatus(t, report, "tls_key_binding", attestation.Skip)

	// Fixture replay currently lacks data required for NVIDIA verification.
	assertFactorStatus(t, report, "nvidia_nonce_client_bound", attestation.Fail)
	assertFactorStatus(t, report, "nvidia_claims", attestation.Fail)
	assertFactorStatus(t, report, "e2ee_usable", attestation.Skip)

	if report.Passed < 10 {
		t.Errorf("expected at least 10 passing factors, got %d", report.Passed)
	}
	logReportScore(t, report)
	t.Logf("RESULT: %d/%d factors passed", report.Passed, total(report))
}
