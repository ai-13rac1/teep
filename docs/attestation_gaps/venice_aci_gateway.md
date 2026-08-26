# Venice ACI/1: Attested Gateway, Unattested Inference Host

Venice's ACI/1 models (10 of 13 TEE models as of 2026-08) route through a
TEE-attested gateway, the `private-ai-gateway` CVM. The gateway is well
attested — hardware quote, measured compose manifest with digest-pinned
images, KMS-issued keys — but it is the only attested principal: no CPU
attestation of the machine that runs the model exists, and the encrypted
channel terminates inside the gateway. This document records the evidence
for that classification, what teep verifies and waives, and the residual
exposure.

## The Problem

A user who sends a prompt to a Venice ACI/1 model gets a hardware-backed
guarantee about the proxy that forwards the prompt, not about the machine
that processes it. The gateway decrypts the user's traffic and forwards it
over its own TLS connection to a downstream inference API. The GPUs that
answer are real and prove their identity fresh for each request, but
nothing proves which host they are in or what software drives them.

## Evidence: the attestation describes a shared gateway

Observed live on 2026-08-25 against two models with different upstream
vendors (`e2ee-glm-5-2-p` → z-ai/glm-5.2, `e2ee-gpt-oss-120b-p` →
openai/gpt-oss-120b); asserted continuously by
`TestVeniceACI_GatewayIdentityAcrossModels`
(`internal/integration/venice_aci_test.go`):

- The attested VM reports `num_gpus: 0` (16 vCPU, 32 GiB) while the
  response carries 8 Hopper GPU attestation entries — relayed evidence.
- Both models present identical gateway identity: the same
  `workload_keyset_digest`, signing key, TLS keys for three service
  domains, compose manifest, and TDX measurements. Only the relayed GPU
  evidence differs — each model's backend has its own GPUs.
- `evidence.downstream_tls_binding` pins `api.redpill.ai` — a downstream
  hop a backend would not have.
- `service_capabilities.serving` is `"aggregator"`.
- `source_provenance.repo_url` names `Dstack-TEE/private-ai-gateway`.

## What teep verifies (Tier 4 + enforced binding factors)

- The gateway TDX quote: structure, Intel cert chain, signature, debug bit,
  MRTD/MRSEAM against the dstack base allowlist, event log replay against
  all four RTMRs, Proof of Cloud registration.
- `gateway_tee_reportdata_binding`: the quote's REPORTDATA binds the
  gateway's E2EE key (keccak256 address scheme) and the client nonce. E2EE
  authorization reads this factor for ACI/1 — the core
  `tee_reportdata_binding` never passes.
- `aci_key_custody`: the workload keyset digest recomputes (SHA-256 over
  the JCS-canonicalized keyset), the E2EE key teep encrypts to is a member
  of that keyset, the dstack-KMS custody chain verifies (the app key signs
  the key's derivation purpose, the KMS root signs the app key together with
  the gateway app id, and the recovered root must be an accepted dstack-KMS
  root), the app id is on an accepted-app-id list — so the chain identifies
  the private-ai-gateway, not merely a tenant of the same KMS — a non-null
  keyset subject must restate that app id, and the keyset must not have
  expired. The app id is read from the RTMR3 "app-id" runtime event, whose
  digest the event-log replay recomputes from its semantic fields, so
  `gateway_event_log_integrity` authenticates the value against the quote.
- `gateway_compose_binding` (enforced): the gateway publishes its
  `app_compose` and `sha256(app_compose)` matches the quote's MRConfigID.
  The manifest pins its four images by sha256 digest
  (`dstacktee/dstack-ingress`, `ghcr.io/redpill-ai/private-ai-launcher`,
  `dstacktee/dstack-verifier`, `prom/node-exporter`); three of the four
  digests are present in the Sigstore transparency log.
- The relayed NVIDIA evidence: per-GPU cert chains and SPDM signatures
  verify, and the EAT nonce matches the client nonce (fresh, not replayed).

## What fails and is waived (`VeniceACIDefaultAllowFail`)

Every core factor that describes the inference host: the twelve `tee_*`
factors, `measured_model_weights`, `event_log_integrity`,
`cpu_id_registry`, and the model-tier supply-chain factors. `cpu_gpu_chain`
fails because the GPUs cannot be bound to any attested CPU — the only
attested CPU is the gateway's, and the GPUs are not in it. These render as
failed-but-allowed so the gap stays visible in every report; removing an
entry from the list blocks every ACI/1 model.

## Residual exposure

1. **The inference host is unattested.** The operator of the downstream
   host can read prompts and responses in plaintext. This is the gap the
   waived core factors state on every report. The downstream API
   (`api.redpill.ai`) is Phala's inference API, which teep models
   separately as the `phalacloud` provider — with per-instance attestation
   — but ACI/1 gives no way to connect this gateway's forwarding to a
   specific attested instance.
2. **The KMS root and gateway app id are trust-on-first-use.** The accepted
   dstack-KMS root and the accepted gateway app id in
   `internal/provider/venice/keyset.go` were recovered from live
   attestations of two models. Whoever controls those lists controls which
   key-releasing authority and which dstack app teep accepts as the gateway.
   Corroborate the KMS root against the dstack KmsAuth registry (Phala
   publishes it on-chain) before extending it.
3. **A malicious provider can downgrade a dstack model to ACI/1 reporting.**
   teep has no authenticated binding from a model name to its expected
   attestation format, so the provider chooses the format per response and
   thereby selects the enforcement list (`config.MergedAllowFail` keys on
   the parsed format). A Venice model that today attests its own inference
   host through the dstack format could instead be answered with a genuine
   ACI/1 gateway attestation, and teep would report it gateway-only —
   losing the host-attestation assurance while still passing. A third party
   cannot exploit this: passing the ACI/1 list now requires presenting the
   real gateway's quote (pinned app id and KMS root, REPORTDATA binding the
   client nonce), which only the gateway can produce. The residual is a
   provider-integrity downgrade of a specific model's assurance level.
   Closing it needs a per-model expected-format pin (from the model listing
   or trust-on-first-use), tracked as follow-up.
4. **Gateway measurements churn.** The gateway image is a dev channel
   (`dstack-dev-*`); RTMR0-2 change with each redeploy, so
   `gateway_tee_hardware_config` and `gateway_tee_boot_config` are waived.
   MRTD/MRSEAM (enforced) come from the shared dstack base list.
5. **The downstream TLS pin is reported, not verified.** The gateway
   attests the SPKI it pins for `api.redpill.ai`, but teep never dials that
   domain, so the report carries it as `gateway_downstream_tls` metadata.
   Cross-provider correlation with the phalacloud provider's live SPKI is
   possible follow-up work.
6. **Gateway image provenance can tighten.** Rekor holds Fulcio provenance
   for `dstacktee/dstack-ingress` (built from Dstack-TEE/dstack-examples)
   and `dstacktee/dstack-verifier` (Dstack-TEE/dstack). The policy
   currently records the four gateway images as `ComposeBindingOnly` — the
   digest pin in the measured manifest; upgrading the two Dstack-TEE images
   to Fulcio-signed policy entries would add signer identity checks.

## Remediation

For Venice / the private-ai-gateway project: publish attestation for the
inference host and bind it to the gateway's forwarding decision (the ACI
spec's attested-session mechanism describes this; no session evidence is
exposed to clients today), or expose the downstream instance identity so a
client can correlate it with the host's own attestation.

For teep: track the ACI attested-session surface as it stabilizes;
corroborate the KMS root on-chain; correlate the downstream TLS pin with
phalacloud instance attestations.
