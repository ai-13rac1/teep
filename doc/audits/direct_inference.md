# Direct Inference Provider Audit

This repository implements a proxy that ensures private LLM inference by performing attestation-bound TLS pinning to model servers, validating that the remote machine runs genuine TEE hardware with verifiable software, and preventing man-in-the-middle attacks through cryptographic binding of the TLS channel to the attestation report.

Please verify every stage of attestation for the requested provider, following this audit guide to produce a detailed report.

This audit applies to direct inference providers, where the API endpoint is running the inference directly on the same machine, meaning that there will only be one layer of attestation to verify.

The report MUST cite the source code locations relevant to BOTH positive AND negative audit findings, using relative markdown links to the source locations, for human validation of audit claims.

The report MUST also distinguish between:
- checks that are computed but do not block traffic, and
- checks that are enforced fail-closed (request rejected on failure).

## Model Routing

In this direct inference model, the attestation covers a single model server. There is a model mapping routing API that the teep proxy consults to determine the destination host for a particular model identity string.

Certificate Transparency MUST be consulted for the TLS certificate of this model router endpoint. This CT log report SHOULD be cached.

The audit MUST verify model routing safety controls, including:
- model-to-domain mapping cache TTL and refresh behavior,
- rejection of malformed endpoint domains (scheme/path/whitespace injection),
- rejection of domains without a dot (non-qualified hostnames),
- exact model selection behavior when multiple endpoint entries map different models to different domains (last-wins, first-wins, or explicit conflict handling),
- concurrency behavior for refreshes (singleflight or equivalent anti-stampede control),
- behavior when the discovery endpoint is unreachable (stale-on-error vs hard failure),
- maximum response size limits to prevent memory exhaustion from a malicious discovery response.

## Attestation Fetch and Response Parsing

Upon connection to the model server, the attestation API of this model server MUST be queried and fully validated before any inference request is sent to the model server.

Certificate Transparency MUST be consulted for the TLS certificate of this model endpoint. This CT log report SHOULD be cached.

The attestation information is provided by an API endpoint as a JSON object that includes the Intel TEE attestation, NVIDIA TEE attestation, and auxiliary information such as docker compose contents and event log metadata.

The audit MUST verify the attestation response parsing path, including:
- maximum response body size limit (to prevent memory exhaustion),
- JSON strict unmarshalling behavior (unknown fields rejection or warning),
- handling of polymorphic response formats (array vs flat object),
- bounds checking on array lengths (model_attestations, all_attestations) to cap iteration,
- model selection logic when the response contains multiple attestation entries (exact match, prefix, or fuzzy), and whether failure to find a matching model is a hard error,
- that no provider-asserted "verified" field is trusted without independent verification.

### Nonce Freshness and Replay Resistance

The verifier MUST generate a fresh 32-byte cryptographic nonce per attestation attempt.

The code MUST verify nonce equality using constant-time comparison and fail closed on mismatch.

If cryptographic randomness fails, nonce generation MUST fail closed (no weak fallback mode). The recommended behavior is to panic or abort — never fall back to a weaker entropy source.

The nonce MUST be transmitted to the attestation endpoint by the proxy, not delegated to the server. The auditor must verify that the nonce originates solely from the client and is not sourced from or influenced by the server response.

### TDX Quote Verification

Signatures over the Intel TEE attestation MUST be verified for the entire certificate chain, including:
- quote structure parsing (supported quote versions),
- PCK chain validation back to Intel trust roots,
- quote signature verification,
- debug bit check (debug enclaves rejected for production trust),
- TCB collateral and currency classification when online.

Document how trust roots are obtained (embedded/provisioned), and how third-party verification libraries are called and interpreted.

The audit MUST explicitly describe the two-pass verification architecture if present (offline first, online collateral second), and whether a Pass-1-only result (no collateral) is still treated as blocking or advisory.

### TDX Measurement Fields and Policy Expectations

The audit MUST explicitly cover the following TDX fields from the parsed quote body:
- MRTD,
- RTMR0, RTMR1, RTMR2, RTMR3,
- MRSEAM,
- MRSIGNERSEAM,
- MROWNER,
- MROWNERCONFIG,
- MRCONFIGID,
- REPORTDATA.

For each field, the report MUST distinguish between:
- extraction/visibility only (field parsed and logged),
- structural integrity checks (length/format/consistency), and
- policy enforcement (allowlist/denylist or expected value matching).

Current direct-provider expectation:
- MRCONFIGID is expected to be cryptographically checked via compose binding,
- RTMR fields are expected to be consistency-checked via event log replay when event logs are present,
- REPORTDATA is expected to be cryptographically verified via the provider-specific binding scheme,
- all other TDX measurement fields MUST be documented as either policy-checked or currently informational-only, with residual risk called out.

The auditor MUST note whether MRTD and MRSEAM are checked against any known-good baseline. If not, this means the implementation trusts any TDX module and any VM image that happens to have the correct compose hash — the residual risk MUST be explicitly quantified.

### CVM Image Verification

The attestation API will provide a full docker compose stanza, or equivalent podman/cloud config image description, as an auxiliary portion of the attestation API response.

The code MUST calculate a hash of these contents, which MUST be verified to be properly attested in the TDX MRConfigID field.

The audit MUST verify the exact binding format expected by the implementation (for example, 48-byte MRConfigID layout, prefix rules, and byte-level comparison semantics).

The audit MUST also verify the extraction path for the app_compose field, including:
- whether the tcb_info field supports double-encoded JSON (string-within-JSON),
- that the extracted compose content is the raw value that was hashed, not a re-serialized version that could differ in whitespace or key ordering.

### CVM Image Component Verification

The docker compose file (or podman/cloud config) will list a series of sub-images. Each of these sub-images MUST be checked against Sigstore and Rekor (or equivalent systems) to establish that they are official builds and not custom variations.

The audit MUST verify:
- extraction logic for image digests from compose content (regex vs structured parsing, and whether non-sha256 digest algorithms are handled or rejected),
- deduplication of extracted digests,
- Sigstore query behavior and failure handling (is a Sigstore timeout a hard fail or a skip?),
- Rekor provenance extraction logic,
- issuer/identity checks used to classify provenance as trusted (what OIDC issuer values are accepted?),
- behavior when a digest appears in Sigstore but has no Fulcio certificate (raw key signature — is this treated as passing provenance or only presence?).

### Verification Cache Safety

The necessary verification information MAY be cached locally so that Sigstore and Rekor do not need to be queried on every single connection attempt.

However, the attestation report MUST be verified against either cached or live data, for EACH new TLS connection to the API provider.

The audit MUST explicitly document each cache layer, its keys, TTLs, expiry/pruning behavior, maximum entry limits, and whether stale data is ever served. Specifically:

| Cache | Expected Keys | Expected TTL | Security-Critical Properties |
|-------|--------------|-------------|------------------------------|
| Attestation report cache | (provider, model) | ~minutes | Signing key MUST NOT be cached; must be fetched fresh for each E2EE session |
| Negative cache | (provider, model) | ~seconds | Must prevent upstream hammering; must expire so recovery is possible |
| SPKI pin cache | (domain, spkiHash) | ~hour | Must be populated only after successful attestation; eviction must force re-attestation |
| Endpoint mapping cache | model→domain | ~minutes | Stale mapping must not bypass attestation |

The audit MUST verify that cache eviction under memory pressure does not silently allow unattested connections. A cache miss MUST trigger re-attestation, never a pass-through.

### Encryption Binding (REPORTDATA)

The attestation report must bind channel identity and key material in a way that prevents key-substitution attacks.

For each provider, the audit MUST document the exact REPORTDATA scheme and verify it byte-for-byte.

For the NEAR AI provider, this includes verifying:
- `REPORTDATA[0:32]` = `SHA256(signing_address_bytes || tls_fingerprint_bytes)`
- `REPORTDATA[32:64]` = raw client nonce bytes (32 bytes, not hex-encoded)

The audit MUST verify:
- that `signing_address` hex decoding handles optional "0x" prefix stripping,
- that `tls_fingerprint` is decoded from hex before hashing (not hashed as ASCII),
- that the concatenation order is strictly `(address || fingerprint)` with no separator or length prefix,
- that both halves of the 64-byte REPORTDATA are verified (not just the first half),
- that the binding comparison uses constant-time comparison (`subtle.ConstantTimeCompare` or equivalent),
- that failure of this check is enforced (blocks forwarding), not merely logged.

The audit MUST also verify that the REPORTDATA verifier is pluggable per provider (so different providers can use different binding schemes) and that a missing or unconfigured verifier fails safely (no default pass-through).

### TLS Pinning and Connection-Bound Attestation

For direct inference providers that use attestation-bound TLS pinning:
- the live TLS certificate SPKI hash MUST be extracted from the same active TLS connection used for attestation,
- the SPKI hash algorithm MUST be documented (SHA-256 of DER-encoded SubjectPublicKeyInfo is standard),
- the attested TLS fingerprint MUST match the live connection SPKI using exact string comparison,
- attestation fetch and inference request MUST occur on the same TLS connection to prevent TOCTOU swaps,
- closing the response body MUST close the underlying TCP connection (preventing connection reuse for a different unattested host),
- any TLS verification bypass mode (for example, `InsecureSkipVerify` / custom pinning replacing CA checks) MUST be justified and cryptographically compensated by attestation checks,
- the `ServerName` field MUST still be set on the TLS config (for SNI) even when CA verification is bypassed.

The audit MUST verify pin-cache behavior:
- TTL and maximum entries per domain,
- eviction strategy (LRU, random, or oldest) and whether it is bounded,
- that a cache miss always triggers full re-attestation (never a pass-through),
- that concurrent attestation attempts for the same (domain, SPKI) are collapsed (singleflight) with a double-check-after-winning pattern,
- that the singleflight key includes both domain and SPKI (so a certificate rotation triggers a new attestation rather than coalescing with the old one).

### NVIDIA TEE Verification Depth

The audit MUST verify both layers when present:

**Local NVIDIA evidence verification (EAT/SPDM):**
- EAT JSON parsing and top-level nonce verification (constant-time),
- per-GPU certificate chain validation against a pinned NVIDIA root CA (not system trust store),
- the root CA pinning method (embedded certificate with hardcoded SHA-256 fingerprint check),
- SPDM message parsing (GET_MEASUREMENTS request/response structure, variable-length field handling),
- SPDM signature verification algorithm (ECDSA P-384 with SHA-384 is expected),
- the signed-data construction (must include both request and response-minus-signature, in order),
- all-or-nothing semantics (one GPU failure must fail the entire check),
- extraction of GPU count and architecture for reporting.

**Remote NVIDIA NRAS verification:**
- JWT signature verification using a cached JWKS endpoint (accepted algorithms: ES256, ES384, ES512 only — HS256 MUST be rejected),
- JWKS caching behavior (auto-refresh, rate-limited unknown-kid fallback),
- JWT claims validation (expiration, issuer, overall attestation result),
- nonce forwarding to NRAS (is it the same client-generated nonce?),
- the exact NRAS endpoint URL and whether it is configurable or hardcoded.

If offline mode exists, the audit MUST state which NVIDIA checks remain active and which are skipped.

### Event Log Integrity

If event logs are present in provider attestation payloads, the code MUST replay them and verify recomputed RTMR values against quote RTMR fields.

The audit MUST describe replay algorithm details, including:
- hash algorithm used for extend operations (SHA-384 is expected for TDX RTMRs),
- initial RTMR state (48 zero bytes),
- extend formula: `RTMR_new = SHA-384(RTMR_old || digest)`,
- handling of short digests (padding to 48 bytes),
- IMR index validation (must be within [0, 3]),
- failure semantics: does a malformed event log entry skip the entry or fail the entire replay?

The audit MUST also state the exact security boundary of this check: event log replay validates internal consistency of event-log-derived RTMR values with quoted RTMR values, but does not by itself prove that RTMR values match an approved software baseline. If no baseline policy is enforced for MRTD/RTMR/MRSEAM-class measurements, that gap MUST be reported explicitly.

## Connection Lifetime Safety

TLS connections to the model server MUST be closed after each request-response cycle (Connection: close) to ensure each new request triggers a fresh attestation or SPKI cache check.

If the implementation reuses connections, the audit MUST verify that re-attestation is correctly triggered on every new request, not just on new connections.

The audit MUST verify:
- that the response body wrapper closes the underlying TCP connection when the body is consumed or closed,
- that connection read/write timeouts are set and reasonable (preventing indefinite hangs),
- that a half-closed or errored connection cannot be mistakenly reused for a subsequent request.

## Enforcement Policy and Failure Semantics

The audit report MUST include a table of verification factors with:
- pass/fail/skip semantics,
- whether the factor is enforced by policy,
- whether failure blocks request forwarding,
- whether failure disables confidentiality guarantees without blocking traffic.

This section is required to prevent regressions where checks continue to be reported but are no longer security-enforcing.

The audit MUST also verify:
- the mechanism by which the enforced factor list is configured (hardcoded defaults, config file, environment),
- that misspelled or unknown factor names in the enforcement config are rejected at startup (not silently ignored),
- that there is a code path (`Blocked()` or equivalent) that inspects the report before every forwarded request and returns an error response to the client when any enforced factor has failed.

The current expected default enforced factors are:
- `nonce_match` — prevents replay of stale attestations,
- `tdx_debug_disabled` — prevents debug enclaves from being trusted,
- `signing_key_present` — ensures the enclave provided a public key,
- `tdx_reportdata_binding` — prevents key-substitution MITM.

The audit MUST evaluate whether additional factors should be enforced by default (for example, `tdx_quote_signature` or `tdx_cert_chain`), and document the rationale for the current enforcement boundary.

## Negative Cache and Failure Recovery

The audit MUST verify the negative cache behavior:
- that a failed attestation attempt records a negative entry preventing repeated upstream requests,
- that negative entries expire after a bounded TTL (not indefinitely cached),
- that the negative cache has bounded size with eviction of expired entries under pressure,
- that a negative cache hit returns a clear error to the client (for example, HTTP 503) rather than silently failing open or forwarding unauthenticated.

## Offline Mode Safety

If the system supports an offline mode, the audit MUST enumerate exactly which checks are skipped (for example, Intel PCS collateral, NRAS, Sigstore, Rekor, Proof-of-Cloud) and which checks still execute locally (for example, quote parsing/signature checks, report-data binding, event-log replay).

For the pinned connection path, the audit MUST verify whether offline mode is honored (the PinnedHandler receives an `offline` flag). The offline flag must suppress only network-dependent checks — all local cryptographic verification must remain active.

The report MUST include residual risk of running in offline mode.

## Proof-of-Cloud

Ensure that the code verifies that the machine ID from the attestation is covered in proof-of-cloud.

The audit MUST document:
- machine identity derivation inputs (for example, PPID from the PCK certificate),
- remote registry verification flow,
- quorum/threshold requirements if multiple trust servers are used (expected: 3-of-3 nonce collection, then chained partial signatures),
- behavior when Proof-of-Cloud is unavailable (skip with informational status, or hard fail),
- whether the Proof-of-Cloud result is cached and under what conditions it is re-queried.

Track future expansion items separately (for example, DCEA and TPM quote integration), but keep this audit focused on checks currently implemented and required for production security decisions.

## HTTP Request Construction Safety

For direct inference providers that construct raw HTTP requests on the underlying TLS connection (bypassing Go's http.Client connection pooling), the audit MUST verify:
- that the Host header is always set and matches the attested domain,
- that Content-Length is derived from the actual body length (not caller-supplied),
- that no user-supplied data is interpolated into HTTP request lines or headers without sanitization (HTTP header injection prevention),
- that the request path is constructed from trusted constants plus URL-encoded query parameters.

## Response Size and Resource Limits

The audit MUST verify that all HTTP response bodies read by the proxy are bounded:
- attestation responses (recommended: ≤1 MiB),
- endpoint discovery responses (recommended: ≤1 MiB),
- SSE streaming buffers (bounded scanner buffer sizes with pooling),
- any other external data read during verification (Sigstore, Rekor, NRAS, PCS).

Unbounded reads from untrusted sources represent a denial-of-service vector and MUST be flagged.

## Sensitive Data Handling

The audit MUST verify:
- that API keys are not logged in plaintext (redaction to first-N characters),
- that the config file permission check warns on group- or world-readable files,
- that ephemeral cryptographic key material (E2EE session keys) is zeroed after use, with acknowledgment of language-level limitations (GC may copy),
- that attestation nonces are not reused across requests.