package tinfoil

import "github.com/13rac1/teep/internal/attestation"

// InapplicableFactors returns the set of factors that don't apply to Tinfoil.
// Tinfoil uses Sigstore DSSE instead of compose/Rekor, and binds GPU nonce
// freshness via REPORTDATA rather than direct SPDM nonce. The 3 other NVIDIA
// factors (payload_present, signature, claims) ARE applicable — GPURawJSON is
// translated to GPUEvidence and verified via VerifyNVIDIAGPUDirect.
func InapplicableFactors() attestation.InapplicableFactors {
	return attestation.InapplicableFactors{
		// NVIDIA: nonce freshness via REPORTDATA chain, NRAS is EAT-specific.
		"nvidia_nonce_client_bound": "Tinfoil binds GPU nonce freshness via REPORTDATA hash chain, not direct SPDM nonce",
		"nvidia_nras_verified":      "NRAS is an EAT-JWT cloud service; Tinfoil uses direct SPDM verification",

		// Supply chain: Tinfoil uses Sigstore DSSE, not compose/Rekor model.
		"compose_binding":       "Tinfoil uses Sigstore DSSE, not compose-based binding",
		"sigstore_verification": "Tinfoil uses Sigstore DSSE, not per-image cosign verification",
		"event_log_integrity":   "Tinfoil does not expose TDX event logs",
	}
}
