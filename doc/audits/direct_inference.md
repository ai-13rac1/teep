# Direct Inference Provider Audit

This repository implements a proxy that ensures private LLM inference by performing end-to-end encryption of inference data, using attestation for encryption key binding, and validating proof-of-integrity of infrastructure.

Please verify every stage of attestation for the requested provider, following this audit guide to produce a detailed report.

This audit applies to direct inference providers, where the API endpoint is running the inference directly on the same machine, meaning that there will only be one layer of attestation to verify.

The report MUST cite the source code locations relevant to BOTH positive AND negative audit findings, using relative markdown links to the source locations, for human validation of audit claims.

## Model Routing

In this direct inference model, the attestation covers a single model server. There is a model mapping routing API that the teep proxy consults to determine the destination host for a particular model identity string.

Certificate Transparency MUST be consulted for the TLS certificate of this model router endpoint. This CT log report SHOULD be cached.

## Attestation Verification

Upon connection to the model server, the attestation API of this model server MUST be queried and fully validated before any inference request is sent to the model server.

Certificate Transparency MUST be consulted for the TLS certificate of this model endpoint. This CT log report SHOULD be cached.

The attestation information is provided by an API endpoint as a JSON object that includes the Intel TEE attestation, NVIDIA TEE attestation, and auxillary information such as the docker compose file contents.

Signatures over the Intel TEE attestation MUST be verified for the ENTIRE certificate chain. Document the signature validation in your audit report, and document how the trust root information is obtained. Ensure any third party libraries that perform this signature validatation are being used correctloy.

### CVM Image Verification

The attestation API will provide a full docker compose stanza, or equivalent podman or cloud config image description, as an auxillary portion of the attestion API response.

The code MUST calculate a hash of these contents, which MUST be verified to be properly attested in the TDX mrconfig field.

### CVM Image Component Verification

The docker compose file (or podman/cloud config) will list a series of sub-images. Each of these sub images MUST be checked against Sigstore and Rekor (or equivalent systems), to establish that they are official open source builds, and not custom variations.

### CVM Verification Cache Safety

The necessary verification information MAY be cached locally so that sigstore and rektor do not need to be queried on every single connection attempt.

However, the docker compose hash MUST be verified against either cached or live data, for EACH new TLS connection to the API provider.

If the docker compose hash is not predent in the cache, or the any of the sub-images are not present in the cache, these must be validated againdt Sigstore and Rekor before proceeding.

### TODO: Other TDX fields

- mrtd, rtmr0, rtmr1, rtmr2, rtmr3

- other contents of report data

### Encryption Binding

The attestation report will bind the TLS fingerprint and/or any E2EE keys.

The code MUST validate this binding cryptographiclly, by verifying signatures over the attestation, all the way to the trust root for the report.

## Connection Lifetime Safety

TLS connections to a model server SHOULD be kept open and re-used for subsequent requests, to avoid the need to re-attest upon every HTTP request.

If any connection times out or is prematurely closed, full attestion MUST be performed again.

## NVDIA TEE

The attestation report will include NVIDIA TEE attestation.

The code MUST verify the presence and cryptographic integrity of this information.

## Proof-of-Cloud

Ensure that the code verifies that the machine ID from the attestation is covered in proof-of-cloud.

XXX: Is anyone using DCEA (https://arxiv.org/abs/2510.12469)? Are there TPM quotes in the attestation API JSON as well?