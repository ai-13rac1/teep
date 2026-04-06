package nanogpt_test

import (
	"testing"

	"github.com/13rac1/teep/internal/provider/nanogpt"
)

func TestDefaultMeasurementPolicy(t *testing.T) {
	p := nanogpt.DefaultMeasurementPolicy()

	if len(p.MRSeamAllow) == 0 {
		t.Error("MRSeamAllow should not be empty")
	}
	for i := range 3 {
		if len(p.RTMRAllow[i]) == 0 {
			t.Errorf("RTMRAllow[%d] should not be empty", i)
		}
	}
	// nanogpt has broader allowlists than single-deployment providers.
	if len(p.RTMRAllow[0]) < 2 {
		t.Errorf("RTMRAllow[0] should have multiple entries, got %d", len(p.RTMRAllow[0]))
	}
	t.Logf("MRSeamAllow: %d, RTMR0: %d, RTMR1: %d, RTMR2: %d",
		len(p.MRSeamAllow), len(p.RTMRAllow[0]), len(p.RTMRAllow[1]), len(p.RTMRAllow[2]))
}
