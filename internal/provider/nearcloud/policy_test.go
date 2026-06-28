package nearcloud_test

import (
	"testing"

	"github.com/13rac1/teep/internal/attestation"
	"github.com/13rac1/teep/internal/provider/nearcloud"
)

func TestDefaultMeasurementPolicy(t *testing.T) {
	p := nearcloud.DefaultMeasurementPolicy()

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

func TestDefaultGatewayMeasurementPolicy(t *testing.T) {
	p := nearcloud.DefaultGatewayMeasurementPolicy()

	if len(p.MRSeamAllow) == 0 {
		t.Error("gateway MRSeamAllow should not be empty")
	}
	for i := range 3 {
		if len(p.RTMRAllow[i]) == 0 {
			t.Errorf("gateway RTMRAllow[%d] should not be empty", i)
		}
	}
}

func TestSupplyChainPolicy(t *testing.T) {
	p := nearcloud.SupplyChainPolicy()
	if p == nil {
		t.Fatal("SupplyChainPolicy should not be nil")
	}
	if len(p.Images) == 0 {
		t.Fatal("SupplyChainPolicy should have images")
	}

	// nearcloud has gateway-tier images.
	hasGateway := false
	for _, img := range p.Images {
		if img.GatewayTier {
			hasGateway = true
			break
		}
	}
	if !hasGateway {
		t.Error("nearcloud SupplyChainPolicy should include gateway-tier images")
	}
	t.Logf("SupplyChainPolicy: %d images", len(p.Images))
}

func TestSupplyChainPolicyTrustsOpenTelemetrySigner(t *testing.T) {
	p := nearcloud.SupplyChainPolicy()
	img := p.Lookup("otel/opentelemetry-collector-contrib")
	if img == nil {
		t.Fatal("OpenTelemetry collector component missing from policy")
	}
	if !img.ModelTier || !img.GatewayTier {
		t.Fatalf("OpenTelemetry component tiers: model=%v gateway=%v, want both", img.ModelTier, img.GatewayTier)
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
