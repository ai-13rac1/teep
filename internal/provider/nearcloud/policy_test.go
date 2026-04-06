package nearcloud_test

import (
	"testing"

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
