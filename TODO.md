# TODO

Follow-up work from the Venice ACI/1 gateway support (GH #113). Each item is
a tracked residual from `docs/attestation_gaps/venice_aci_gateway.md`; none is
third-party exploitable after the fixes on this branch.

## Corroborate the dstack-KMS root and gateway app id on-chain

The accepted KMS root (`defaultACIKMSRootAllow`) and gateway app id
(`defaultACIGatewayAppIDAllow`) in `internal/provider/venice/keyset.go` are
trust-on-first-use: both were recovered from the attestation responses
themselves, not from a source independent of the provider. The upstream
reference verifier is also config-pinned (`accepted_dstack_kms_root_public_keys`),
so this is an improvement over the reference, not a gap unique to teep.

dstack governs KMS key release through an on-chain `KmsAuth` contract, which
holds the KMS root identity and the per-app authorization (which app id and
compose hash the KMS releases keys to). Reading it corroborates both pins —
and the per-app authorization corroborates the app id, which is the stronger
anchor (it identifies the private-ai-gateway, not merely a tenant of the same
KMS).

Step zero, before any design commitment: identify the `KmsAuth` contract
address and chain for the KMS backing `0334c76e…`, confirm the on-chain root
matches the recovered value, and confirm the contract exposes the per-app
authorization.

Design direction (SEE the assessment recorded with this branch):

- Pin the `KmsAuth` contract address + chain id as the durable anchor, not the
  raw root value. The address is immutable and publicly auditable; the root
  can rotate without a teep release.
- Read finalized state through a multi-RPC quorum, the trust model teep
  already uses for Proof of Cloud (`internal/attestation` PoC quorum,
  `internal/multi`). A single trusted RPC is a building block only.
- Read the per-app authorization from the same contract, not the root alone.
- A consensus light-client state proof is the trustless endpoint but a
  substantial dependency against teep's stdlib posture; keep it as a
  graduation path, not the first step.

Requirements, or the read pretends to corroborate rather than corroborates:

- Fail closed and gate the read like other online collateral (Intel PCS,
  NRAS): skipped under `--offline`, governed by `allow_fail`, and a fetch
  failure is a factor failure — never a silent fall-back to the stale pin
  reported as success.
- Cache with a long TTL (the root rotates on a governance cadence, not per
  request), evict so a since-revoked root cannot pass, and read finalized
  state only to avoid reorgs.
- Pin the block number in captures so the JSON-RPC read replays
  deterministically through the capture/replay harness.

Residual even then: the contract-address pin is still trust-on-first-use, but
a far better one — auditable on a public explorer and stable across root
rotations.

## Pin the expected attestation format per model

`config.MergedAllowFail` selects the allow_fail list from the format parsed
out of the response, and teep has no authenticated binding from a model name
to its expected format. A provider can answer a dstack model with a genuine
ACI/1 gateway attestation and teep reports it gateway-only, losing the
host-attestation assurance for that model while still passing. A third party
cannot exploit this — passing the ACI/1 list requires the genuine gateway
quote — so the residual is a provider-integrity downgrade of a specific
model's assurance level.

Close it with a per-model expected-format pin (from the model listing at
startup, or trust-on-first-use cached alongside the report) that fails closed
when a later response changes a model to a weaker format.
SEE: `docs/attestation_gaps/venice_aci_gateway.md` residual exposure 3.

## Emit or require the ACI/1 spec REPORTDATA to anchor keyset metadata

Venice's gateway REPORTDATA binds only the E2EE signing key and the client
nonce (the dstack keccak256-address scheme), not the `workload_keyset_digest`
the ACI/1 spec binds. So `not_after`, `subject`, and `tls_public_keys` are
self-asserted: the `not_after` check is a rotation bound that holds against an
honest gateway, not a hardware-enforced expiry. No teep-side code closes this
while the gateway uses the dstack REPORTDATA layout; it needs Venice to emit
the spec REPORTDATA (the statement digest over the whole keyset).
SEE: `docs/attestation_gaps/venice_aci_gateway.md` residual exposure 7.

## Tighten gateway image provenance

The four gateway images are recorded as `ComposeBindingOnly`
(`internal/provider/venice/policy.go`) — the digest pin in the measured
manifest. Rekor holds Fulcio provenance for `dstacktee/dstack-ingress`
(Dstack-TEE/dstack-examples) and `dstacktee/dstack-verifier` (Dstack-TEE/dstack);
upgrading those two to Fulcio-signed policy entries would add signer identity
checks. SEE: `docs/attestation_gaps/venice_aci_gateway.md` residual exposure 6.

## Correlate the attested downstream TLS pin

The gateway attests the SPKI it pins for `api.redpill.ai`, reported as
`gateway_downstream_tls` metadata; teep never dials that domain. Cross-provider
correlation with the phalacloud provider's live SPKI would turn the reported
pin into a verified one. SEE: `docs/attestation_gaps/venice_aci_gateway.md`
residual exposure 5.
