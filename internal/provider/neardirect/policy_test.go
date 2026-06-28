package neardirect_test

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/neardirect"
)

func TestDefaultMeasurementPolicy(t *testing.T) {
	p := neardirect.DefaultMeasurementPolicy()

	if len(p.MRSeamAllow) == 0 {
		t.Error("MRSeamAllow should not be empty")
	}
	for i := range 3 {
		if len(p.RTMRAllow[i]) == 0 {
			t.Errorf("RTMRAllow[%d] should not be empty", i)
		}
	}
	t.Logf("MRSeamAllow: %d entries, RTMR0: %d, RTMR1: %d, RTMR2: %d",
		len(p.MRSeamAllow), len(p.RTMRAllow[0]), len(p.RTMRAllow[1]), len(p.RTMRAllow[2]))
}

func TestSupplyChainPolicy(t *testing.T) {
	p := neardirect.SupplyChainPolicy()
	if p == nil {
		t.Fatal("SupplyChainPolicy should not be nil")
	}
	if len(p.Images) == 0 {
		t.Fatal("SupplyChainPolicy should have images")
	}

	// All neardirect images should be model-tier.
	for _, img := range p.Images {
		if !img.ModelTier {
			t.Errorf("image %q should be model-tier", img.Repo)
		}
	}
	t.Logf("SupplyChainPolicy: %d images", len(p.Images))
}

func TestSupplyChainPolicyTrustsOpenTelemetrySigner(t *testing.T) {
	p := neardirect.SupplyChainPolicy()
	img := p.Lookup("otel/opentelemetry-collector-contrib")
	if img == nil {
		t.Fatal("OpenTelemetry collector component missing from policy")
	}
	if img.Provenance != attestation.SigstorePresent {
		t.Fatalf("OpenTelemetry provenance = %v, want SigstorePresent", img.Provenance)
	}
	const wantFingerprint = "a8bd282038915eaf2ca9ac7d4cc2605ce6e7ae8aed5b19b06370e285f8a9d72e"
	if img.KeyFingerprint != wantFingerprint {
		t.Fatalf("OpenTelemetry key fingerprint = %q, want %q", img.KeyFingerprint, wantFingerprint)
	}
	if !p.TrustedProviderSigner(img) {
		t.Fatal("OpenTelemetry signer should be trusted provider-wide")
	}
}
