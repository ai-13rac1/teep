# Attestation Security Gaps

This directory contains reports that document current verifiability gaps in deployed private inference infrastructure.

The reports in this directory look machine generated because they are.

All report research and mitigation recommendations were carefully guided and reviewed by humans.

New reports should follow [TEMPLATE.md](TEMPLATE.md).

## Reports

- [Dstack Integrity Chain: In-Band Discovery Gap](dstack_integrity.md)
- [NEAR DeepSeek Image Provenance: Platform Digest Discovery Gap](near_image_provenance.md)
- [NearCloud E2EE: Gateway Header-Forwarding Gaps](e2ee_plaintext_gaps.md)
- [Hardware Attestation Binding Issues and Mitigations](gpu_cpu_binding.md)
- [Model Weight Authentication](model_weights.md)
- [Proof of Cloud Registry: JWT Validation Failure](poc_jwt_validation.md)
- [Chutes/sek8s Integrity Chain](sek8s_integrity.md)
- [Venice ACI/1: Attested Gateway, Unattested Inference Host](venice_aci_gateway.md)

NearCloud sends an authenticated model-key routing hint, but gateway behavior
can ignore it and non-chat backend affinity is not established. Generic image
errors do not identify key retirement, so automatic image recovery is unsupported.
See [NEAR routing limitations](../providers/near/near_attestation.md#nearcloud-model-routing).

For neardirect, nearcloud and Venice, teep finds the Rekor `dsse` entry for each
signed image digest through Rekor's digest search. It verifies the entry SET and
inclusion proof, then verifies that the entry certificate chains to a Fulcio CA in
the Sigstore trusted root, with an SCT, at the integrated time that the SET
authenticates, before it reads the signer identity. Teep does not verify the DSSE
signature, because Rekor stores only the envelope and payload hashes. Teep also
does not prove that the signed payload names the image digest: that link comes
from the search index, which no signature covers. Rekor indexes the in-toto
subject digests and the SLSA build material digests of an entry, so an entry that
names the digest only as a build material, for example the provenance of an image
built from it, is found by the same search. If a workflow identity that the policy
trusts signed such an entry, teep accepts it as provenance for the digest. The
[Fulcio chain verification plan](../plans/fulcio_chain_verification.md) describes
the envelope check that closes this gap. See also
[model weight authentication](model_weights.md) and
[NEAR supply chain verification](../providers/near/near_attestation.md#supply-chain-verification).
