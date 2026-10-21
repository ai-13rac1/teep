package verify

import (
	"net/http"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/attestation/sigstoretest"
	"github.com/13rac1/teep/internal/capture"
	"github.com/13rac1/teep/internal/provider/tinfoil"
)

func tinfoilRouterReplayClient(t *testing.T) *http.Client {
	t.Helper()
	_, entries, err := capture.Load("../integration/testdata/tinfoil_v3_cloud_glm-5-2_20260817_003424")
	if err != nil {
		t.Fatal(err)
	}
	return &http.Client{Transport: capture.NewReplayTransport(entries)}
}

// TestVerifyTinfoilSupplyChainSigstoreFailure replays no GitHub data, so the
// bundle fetch fails. The result records the failure for the component.
func TestVerifyTinfoilSupplyChainSigstoreFailure(t *testing.T) {
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatTinfoil}
	client := &http.Client{Transport: capture.NewReplayTransport(nil)}
	result := verifyTinfoilSupplyChain(t.Context(), raw, nil, nil, "tinfoil_v3_cloud", "model",
		attestation.MeasurementPolicy{}, false, client, sigstoretest.TrustedRoot(attestation.NewStaticTrustedRootSource))
	if result.SigstoreVerified || result.SigstoreErr == nil {
		t.Fatalf("Sigstore result verified=%v err=%v, want a failure", result.SigstoreVerified, result.SigstoreErr)
	}
	if len(result.Components) != 1 || result.Components[0].Repo != tinfoil.RouterRepo || result.Components[0].SigstoreErr == nil {
		t.Fatalf("components = %+v, want one failed router component", result.Components)
	}
}

// TestVerifyTinfoilSupplyChainTDXMismatch verifies the captured router bundle
// with the static trusted root, then compares it with an empty TDX result.
// The code measurements must not match, and the hardware measurement fetch,
// which the capture does not hold, must fail.
func TestVerifyTinfoilSupplyChainTDXMismatch(t *testing.T) {
	raw := &attestation.RawAttestation{BackendFormat: attestation.FormatTinfoil}
	tdx := &attestation.TDXVerifyResult{}
	result := verifyTinfoilSupplyChain(t.Context(), raw, tdx, nil, "tinfoil_v3_cloud", "model",
		attestation.MeasurementPolicy{}, false, tinfoilRouterReplayClient(t), sigstoretest.TrustedRoot(attestation.NewStaticTrustedRootSource))
	if !result.SigstoreVerified {
		t.Fatalf("router bundle not verified: %v", result.SigstoreErr)
	}
	if result.CodeMatch || result.CodeMatchErr == nil {
		t.Fatalf("code match = %v, err = %v; want a mismatch", result.CodeMatch, result.CodeMatchErr)
	}
	if result.HWMatchErr == nil || !strings.Contains(result.HWMatchErr.Error(), "fetch hardware measurements") {
		t.Fatalf("hardware match error = %v, want a fetch failure", result.HWMatchErr)
	}
	if len(result.Components) != 2 || result.Components[1].Repo != tinfoil.HardwareMeasurementsRepo || result.Components[1].SigstoreErr == nil {
		t.Fatalf("components = %+v, want a failed hardware measurements component", result.Components)
	}
}
