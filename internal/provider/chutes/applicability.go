package chutes

import "github.com/13rac1/teep/internal/attestation"

// InapplicableFactors returns the set of factors that don't apply to Chutes.
func InapplicableFactors() attestation.InapplicableFactors {
	return attestation.InapplicableFactors{
		"compose_binding":        "Chutes uses cosign image admission + IMA, not docker-compose",
		"build_transparency_log": "Chutes supply chain verification is validator-side only",
		"sigstore_verification":  "Chutes cosign verification is validator-side only",
		"event_log_integrity":    "Chutes RTMR verification is validator-side; event log not exposed",
		"sigstore_code_verified": "Sigstore code verification is Tinfoil-specific",
		"nvswitch_binding":       "NVSwitch fabric verification is Tinfoil-specific",
	}
}
