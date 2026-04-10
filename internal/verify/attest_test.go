package verify

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider"
)

// --------------------------------------------------------------------------
// fetchAttestation
// --------------------------------------------------------------------------

type failAttester struct{}

func (failAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	return nil, errors.New("mock fetch error")
}

type successAttester struct{ raw *attestation.RawAttestation }

func (a successAttester) FetchAttestation(_ context.Context, _ string, _ attestation.Nonce) (*attestation.RawAttestation, error) {
	return a.raw, nil
}

func TestFetchAttestation_Error(t *testing.T) {
	ctx := context.Background()
	nonce := attestation.NewNonce()

	var a provider.Attester = failAttester{}
	_, err := fetchAttestation(ctx, a, "test", "model", nonce)
	t.Logf("fetchAttestation error: %v", err)
	if err == nil {
		t.Fatal("expected error from failing attester")
	}
	if !strings.Contains(err.Error(), "mock fetch error") {
		t.Errorf("error should wrap the mock error: %v", err)
	}
}

func TestFetchAttestation_Success(t *testing.T) {
	ctx := context.Background()
	nonce := attestation.NewNonce()
	want := &attestation.RawAttestation{IntelQuote: "test-quote"}

	raw, err := fetchAttestation(ctx, successAttester{raw: want}, "test", "model", nonce)
	if err != nil {
		t.Fatalf("fetchAttestation unexpected error: %v", err)
	}
	if raw.IntelQuote != want.IntelQuote {
		t.Errorf("IntelQuote = %q, want %q", raw.IntelQuote, want.IntelQuote)
	}
}

// --------------------------------------------------------------------------
// verifyTDX nil-guard
// --------------------------------------------------------------------------

func TestVerifyTDX_EmptyQuote(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{IntelQuote: ""}
	result := verifyTDX(ctx, raw, attestation.Nonce{}, "venice", true)
	if result != nil {
		t.Errorf("verifyTDX with empty quote: expected nil, got %v", result)
	}
}

// --------------------------------------------------------------------------
// verifyNVIDIA nil-guard
// --------------------------------------------------------------------------

func TestVerifyNVIDIA_EmptyPayload(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{} // no NvidiaPayload, no GPUEvidence
	eat, nras := verifyNVIDIA(ctx, raw, attestation.Nonce{}, nil, true)
	if eat != nil {
		t.Errorf("verifyNVIDIA empty: eat = %v, want nil", eat)
	}
	if nras != nil {
		t.Errorf("verifyNVIDIA empty: nras = %v, want nil", nras)
	}
}

// --------------------------------------------------------------------------
// checkPoC nil-guard
// --------------------------------------------------------------------------

func TestCheckPoC_Offline(t *testing.T) {
	ctx := context.Background()
	result := checkPoC(ctx, "some-quote", nil, true)
	if result != nil {
		t.Errorf("checkPoC offline: expected nil, got %v", result)
	}
}

func TestCheckPoC_EmptyQuote(t *testing.T) {
	ctx := context.Background()
	result := checkPoC(ctx, "", nil, false)
	if result != nil {
		t.Errorf("checkPoC empty quote: expected nil, got %v", result)
	}
}

// --------------------------------------------------------------------------
// verifyNearcloudGateway nil-guard
// --------------------------------------------------------------------------

func TestVerifyNearcloudGateway_NoQuote(t *testing.T) {
	ctx := context.Background()
	raw := &attestation.RawAttestation{GatewayIntelQuote: ""}
	tdx, compose, poc := verifyNearcloudGateway(ctx, raw, attestation.Nonce{}, nil, true)
	if tdx != nil {
		t.Errorf("expected nil tdx, got %v", tdx)
	}
	if compose != nil {
		t.Errorf("expected nil compose, got %v", compose)
	}
	if poc != nil {
		t.Errorf("expected nil poc, got %v", poc)
	}
}

// --------------------------------------------------------------------------
// checkSigstore nil-guard
// --------------------------------------------------------------------------

func TestCheckSigstore_Empty(t *testing.T) {
	ctx := context.Background()
	sig, rekor := checkSigstore(ctx, []string{}, nil, false)
	if sig != nil {
		t.Errorf("expected nil sigstore results for empty digests, got %v", sig)
	}
	if rekor != nil {
		t.Errorf("expected nil rekor results for empty digests, got %v", rekor)
	}
}

func TestCheckSigstore_Offline(t *testing.T) {
	ctx := context.Background()
	sig, rekor := checkSigstore(ctx, []string{"sha256:abc123"}, nil, true)
	if sig != nil {
		t.Errorf("expected nil sigstore results in offline mode, got %v", sig)
	}
	if rekor != nil {
		t.Errorf("expected nil rekor results in offline mode, got %v", rekor)
	}
}
