# Tinfoil Cloud Integrity: Router Plaintext and Unbound Backend Evidence

Tinfoil cloud routing protects traffic to an attested confidential router, but that router decrypts inference content and is also the component that chooses and verifies the model backend. Even if the client verifies that the reviewed open-source router release is running, that establishes only the identity of the intermediary: the client still trusts its plaintext handling and a mutable backend admission decision that can accept a supply-chain-compromised release without any change to the router measurement. That trust expansion is an architectural choice, not an unavoidable cost of gateway routing: NEAR AI's E2EE gateway path exposes fresh model evidence, encrypts sensitive content to the model's attested key, and provides a model-signed request and response binding.

## The Problem

Tinfoil cloud routing introduces two related gaps.

First, inference bodies are confidential only as far as the router. The router decrypts each body, reads and may rewrite it, selects a backend, and opens a new protected connection to that backend. Both network hops are encrypted, but the router remains able to observe and alter requests and responses.

Second, clients receive no backend-authenticated proof of the endpoint, release, and hardware state that processed a request. Tinfoil exposes useful router status, backend attribution metadata, and endpoint-specific audit bundles, but these are separate observations. The router identifies the selected host, and a client can later verify that an acceptable host exists; the backend does not authenticate that it handled the request under the evidence being inspected.

### Why Router Attestation Is Not Backend Proof

It is tempting to treat the architecture as a complete transitive proof: the client attests the router, the router attests a backend, so the client has effectively attested the backend. That conclusion adds a trust step and loses evidence. The client proves which router release received the request, but does not receive the backend evidence needed to independently reproduce the router's admission decision or a backend-authenticated record of which endpoint handled that request.

Even granting exact source-to-measurement correspondence, exhaustive review, flawless router code, and faithful policy enforcement, the distinction remains. The router measurement fixes the verification and routing program; it does not fix the program's mutable inputs and results: the selected endpoint, backend quote, key epoch, GPU state, release digest, provenance material, or association with a particular request and response. Those values can all change while the attested router measurement stays identical. The client-visible claim is therefore “this measured router says it enforced its policy,” not “the client verified and can later prove that backend X, under release Y and hardware epoch Z, processed this request using model Omega.”

This distinction matters most when the backend release path is compromised. An attacker who controls an authorized maintainer or build workflow can produce a malicious backend with valid provenance, transparency-log inclusion, and an internally consistent measurement. A correctly attested router can then admit that release exactly as its audited code requires, without the router image or measurement changing. The backend can target selected traffic, appear benign to ordinary audits, and be replaced before a later endpoint audit. Because the cloud response does not preserve the admitted digest, supply-chain evidence, attestation epoch, and a backend-authenticated request receipt, the client cannot reconstruct that event afterward. Auditing the router source explains how releases are checked; it does not make every backend release benign or independently auditable.

The router's confidential VM is an important compensating control, not a resolution of these gaps. Memory encryption is designed to hide the router's memory from the host; it is not access control against the router workload itself. The router software still receives each inference body as plaintext so it can parse and modify it. Attestation lets a client confirm that an authorized measured router release holds the connection keys. Neither control proves that the measured code and its dependencies are free of exploitable vulnerabilities, prevents that code from reading data it is explicitly authorized to decrypt, or proves how it behaved for a particular request.

This distinction is about authority, not whether the router is currently known to be malicious. If the router has authority to decrypt inference content, a router vulnerability can expose that content. Even a perfectly implemented and honest router cannot make its own backend attribution equivalent to proof authenticated by the backend itself.

NEAR AI Cloud provides a useful counterexample. Its gateway and model are separate attested principals: the client can obtain fresh model evidence through the gateway, encrypt protected fields to the model's attested key so the gateway cannot read them, and verify a model signature over request and response hashes. These properties are mode-dependent rather than automatic, but they demonstrate that a unified gateway need not be the only client-visible root of trust. The [comparative design](#contrast-near-ai-keeps-the-model-in-the-client-verification-chain) below describes the differences and qualifications.

These properties are weaker than direct inference, where the endpoint that decrypts the request is also the endpoint whose hardware, software, and keys the client verifies. They should be explicit parts of the Tinfoil cloud security model rather than described as end-to-end confidentiality or request-bound backend integrity.

## Impact

Tinfoil has compensating controls, but none closes either gap. Body encryption protects data through browsers and TLS-terminating proxies that cannot enforce an attested TLS fingerprint. The router verifies backend CPU attestation and pins the next TLS hop. Backend boot code validates attached GPUs before serving. Router status and endpoint-specific bundles support independent fleet auditing. These controls protect each stage, but they neither keep plaintext from the router nor bind backend evidence to a request.

**Security impact:**

- A compromised, vulnerable, or malicious router workload can observe or alter chat messages, uploaded documents, audio, tool inputs, credentials embedded in router options, and model outputs.
- Defense in depth between the client and router does not protect against compromise inside the router boundary because both body encryption and any direct router TLS pin terminate there.
- A client cannot prove that the backend handling a request had a particular fresh CPU quote, GPU state, topology, key epoch, or authorized release digest.
- The router can attribute a response to a backend that exists and verifies correctly at audit time without producing backend-authenticated proof that this backend handled the earlier request.
- A compromised authorized release workflow can publish a malicious backend that passes provenance and measurement checks without changing the router release. Targeted behavior can then distinguish ordinary audit traffic from selected tenants or prompts.
- Short-lived backend releases can disappear between periodic status or bundle checks, leaving no client-held evidence that the router admitted them.

**Operational impact:**

- Security-conscious customers must choose between router features and minimizing the plaintext trusted computing base through direct inference.
- External reports must distinguish router-enforced CPU admission and TLS pinning, backend-boot-enforced GPU validation, current-fleet auditing, and properties actually bound to a request.
- Auditors can monitor current endpoints but must continuously archive status and bundles to detect transient fleet changes, and even then cannot prove request handling.
- The limitation is a protocol and product choice rather than an inherent cost of confidential gateway routing; customers can compare it with providers that keep backend evidence and content encryption client-verifiable.
- Cloud security claims must avoid “end-to-end to the inference enclave” and “client-verified backend” unless the routing protocol changes.

---

## Technical Background

### Cloud Request Flow

Tinfoil cloud routing has three processing boundaries:

```text
client
  |
  |  body encrypted to router HPKE key
  |  outer TLS may terminate at router or a proxy
  v
Tinfoil confidential model router
  |
  |  body is plaintext, parsed, routed, and possibly modified
  |  new TLS connection pinned to backend's attested TLS key
  v
selected model inference enclave
```

The client verifies the router and encrypts the body to the router CVM's attested HPKE key. A client capable of direct TLS pinning can also enforce the router's attested TLS fingerprint. Browsers and proxy deployments may be unable to enforce that fingerprint end to end, and EHBP remains valuable in those cases because the body stays encrypted through the intermediary. In all cloud deployments, however, the inner body encryption ends at the router rather than the model backend.

The router verifies backend CPU attestation, checks the runtime measurement against the authorized model release measurement, and constructs a reverse proxy pinned to the backend's attested TLS key. The backend also has an attested HPKE key, but the router records that key as metadata and does not use it for forwarding.

### EHBP Trust Boundary

EHBP encrypts HTTP bodies to a server HPKE key. Server middleware replaces an encrypted request body with a decrypted stream before invoking the application handler, and encrypts the body written by that handler on the way back. Its AEAD uses empty associated data, so ordinary HTTP headers such as `Tinfoil-Enclave` are not authenticated by EHBP body encryption ([EHBP specification](https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/8528a8dc5ad45c213f14f9bab46a748fda7e18cc/SPEC.md#L59-L69)).

Each Tinfoil CVM has its own HPKE identity. A router CVM therefore has a router key and an inference CVM has a different backend key. Security depends on which CVM the client verifies and addresses; default cloud routing verifies and encrypts to the router.

### Backend Admission and GPU Enforcement

The router's backend admission path requests the nonce-less legacy CPU attestation document. It verifies the CPU quote, applicable TDX platform measurements, the release measurement, and the attested TLS and HPKE values.

GPU enforcement occurs elsewhere. During backend boot, the CVM locally validates GPU SPDM evidence and applicable topology before enabling GPU request processing. A nonce-bearing V3 attestation request can collect fresh CPU, GPU, and NVSwitch evidence, but the router admission path does not make that request. The router instead trusts the measured backend boot code to have enforced GPU policy.

### Existing Audit Surfaces

Tinfoil exposes three useful but separate audit surfaces:

- Router status publishes model repositories, release tags, source measurements, backend hostnames, and backend TLS/HPKE metadata.
- Each ordinary backend response includes a router-generated `Tinfoil-Enclave` header naming the selected host.
- ATC accepts an enclave URL and repository and can assemble an endpoint-specific bundle containing CPU attestation, release digest and tag, Sigstore evidence, VCEK, and the enclave certificate.

Together these let a client identify the host claimed by the router and independently audit that endpoint later. They do not bind the later evidence to the earlier request, preserve a history of router admission decisions, or make the attribution a backend-authenticated statement.

### Contrast: NEAR AI Keeps the Model in the Client Verification Chain

NEAR AI Cloud also offers a unified confidential gateway in front of model TEEs, but deliberately keeps the model backend in the client's cryptographic verification chain.

The gateway attestation endpoint returns model attestations in response to a client nonce. Each model record exposes CPU and GPU evidence, the model signing key, and the digest-pinned compose manifest; the TDX report data binds the signing identity and nonce, while the compose hash is checked against the verified `mr_config` measurement ([NEAR model verification](https://docs.near.ai/cloud/verification/model/)). The client therefore has the backend evidence and exact container configuration as verification inputs rather than receiving only the gateway's verdict. NEAR's verifier uses the image digests from that attested manifest to locate source and Sigstore build provenance, associate a deployed image with a source revision and workflow, and support independent supply-chain review ([NEAR AI Cloud Verifier](https://github.com/nearai/nearai-cloud-verifier/tree/6a9c0c57dd9b2b47bbd2682df4a685c50210096e)).

For confidentiality, NEAR's opt-in E2EE mode encrypts protected request fields to the model public key obtained from model attestation. The gateway routing form carries `X-Model-Pub-Key`, which NEAR documents as required when routing encrypted requests through the gateway; `X-Encrypt-All-Fields` extends protection beyond message content to tool definitions, tool calls, and other sensitive fields ([NEAR E2EE guide](https://docs.near.ai/cloud/guides/e2ee-chat-completions/)). This separates router-visible routing metadata from model-confidential inference content instead of giving the gateway the content decryption key.

For processing integrity, a NEAR `provider_tee` signature is produced by the model TEE under the signing identity from model attestation. It covers the model ID, the hash of the exact request bytes received by the model, and the hash of the exact response bytes it sent ([NEAR chat verification](https://docs.near.ai/cloud/verification/chat/)). This is the backend-authenticated receipt missing from Tinfoil cloud routing.

| Property | Tinfoil cloud routing | NEAR AI E2EE gateway path |
|---|---|---|
| Backend evidence available to client | Router status and a separately requested endpoint bundle | Fresh client-nonce-bound model CPU/GPU evidence and attested compose manifest |
| Sensitive-content recipient | Router HPKE key; router workload receives plaintext | Model-attested public key; gateway forwards protected fields as ciphertext |
| Backend selection and attribution | Router selects a host and emits `Tinfoil-Enclave` | Client selects an attested model key for E2EE; model TEE can sign the processing record |
| Request/response binding | No backend-authenticated commitment | `provider_tee` signature covers model ID, request hash, and response hash |
| Supply-chain audit input | Backend digest and bundle consumed internally by router | Digest-pinned backend compose exposed in quote-bound evidence for independent provenance review |

This comparison does not claim that signed provenance makes every NEAR artifact benign; an authorized release path can still be compromised. The difference is auditability and data-plane binding: the exact backend configuration and signing identity are visible to the client, protected content is addressed to that identity, and the backend can authenticate what it processed. E2EE must be enabled, full sensitive-field coverage requires `X-Encrypt-All-Fields`, and gateway-rewritten response streams can carry a gateway signature rather than a byte-exact `provider_tee` signature. The `provider_tee` signature binds processing to the model identity but does not itself cover the release digest or attestation epoch, so it is a precedent for backend authentication rather than the complete stage 2 design proposed below. NEAR also offers direct model endpoints when clients want to remove the gateway from the path entirely ([NEAR private inference](https://docs.near.ai/cloud/private-inference/)). These qualifications limit the guarantee for particular modes, but the design still provides concrete, deployed precedents for the changes proposed in this report.

Tinfoil already has much of the machinery needed to follow this pattern: the router authenticates the backend's HPKE key, TLS key, measurements, and release evidence. The central change is to preserve those results across the client boundary and use the backend key and identity in the data plane, rather than consuming them only inside the router.

---

## Detailed Gap Analysis

### Gap 1: EHBP Terminates Before the Router Workload

The shim creates EHBP middleware and applies it outside the handler that invokes the local workload proxy ([shim/api.go:194-L219](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/api.go#L194-L219)). The proxy director then targets local HTTP and removes the encapsulated-key header before forwarding ([shim/api.go:197-L206](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/api.go#L197-L206)).

The middleware calls `DecryptRequestWithContext`, installs the decrypted stream, prepares response encryption, and only then calls the next application handler ([identity/middleware.go:52-L123](https://github.com/tinfoilsh/encrypted-http-body-protocol/blob/8528a8dc5ad45c213f14f9bab46a748fda7e18cc/identity/middleware.go#L52-L123)). The router README accurately summarizes that the router terminates TLS and optional EHBP before inspecting the model name and selecting an inference enclave ([router README](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/README.md#L1-L3)).

The router then exercises intentional plaintext features:

- It parses speech and multipart audio requests to select or default models ([main.go:630-L665](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L630-L665)).
- It fully reads and decodes generic OpenAI-compatible bodies, extracts router-only options, and resolves the model ([main.go:668-L723](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L668-L723)).
- It rewrites file inputs, strips or injects priority, injects cache-routing state, modifies streaming usage options, and re-marshals the request ([main.go:726-L831](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L726-L831)).
- It may execute router-owned tool loops before ordinary backend dispatch ([main.go:833-L864](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/main.go#L833-L864)).

This is conclusive evidence that cloud EHBP provides confidentiality to the router, not through the router. The selected inference endpoint has its own HPKE key, but the cloud client never uses that key for its request body.

The key ownership follows directly from the boot path. `HPKEKeyPath` is private to CVM boot, egress, and shim processes ([boot/paths.go:15-L23](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/internal/boot/paths.go#L15-L23)). Boot loads or creates the identity and exports its public key ([boot/identity.go:38-L79](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/boot/identity.go#L38-L79)), binds it with the TLS key in CPU attestation ([boot/cpuattest.go:24-L33](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/boot/cpuattest.go#L24-L33)), and the shim loads the same private identity ([shim/main.go:146-L162](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/main.go#L146-L162)). In cloud routing those operations occur in the router CVM.

### Gap 2: Backend Evidence Is Not Bound to Request Processing

The router performs meaningful admission control, but its evidence is not carried into a client-verifiable processing proof. `addEnclave` fetches legacy CPU attestation without a nonce, verifies it and applicable TDX platform measurements, compares the backend and source measurements, and stores the TLS and HPKE values ([manager.go:247-L342](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L247-L342)). Backend forwarding uses a reverse proxy with `TLSBoundRoundTripper` pinned to the admitted TLS fingerprint ([proxy.go:176-L205](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/proxy.go#L176-L205)). The stored backend HPKE key is not part of the forwarding transport.

The router does not verify fresh backend GPU evidence during admission. Backend boot verifies GPUs before enabling them ([boot/main.go:113-L138](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/boot/main.go#L113-L138)), while fresh GPU/NVSwitch collection occurs only on a nonce-bearing V3 attestation request ([shim/api.go:326-L375](https://github.com/tinfoilsh/cvmimage/blob/282479badb65e7b866afd733cf586367c0599911/tinfoil/cmd/shim/api.go#L326-L375)). The cloud chain therefore proves that the router admitted code expected to enforce GPU policy, not that the router or client inspected fresh backend GPU evidence for the request.

The current attribution and audit features narrow the gap but do not close it:

- Status serializes repository, tag, source measurement, backend hostname, TLS fingerprint, and HPKE key ([manager.go:46-L50](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L46-L50), [manager.go:366-L382](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L366-L382), [manager.go:840-L848](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L840-L848)). It does not include the verified digest, supply-chain bundle, fresh evidence, or admission history.
- `Tinfoil-Enclave` names the host selected by the router ([manager.go:806-L822](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L806-L822)). It is neither produced by the backend nor authenticated as part of the EHBP response body.
- ATC can assemble a bundle for a caller-supplied enclave and repository ([atc.ts:11-L57](https://github.com/tinfoilsh/tinfoil-js/blob/50e664521d69f45de84c494b1fdca2131465d028/packages/tinfoil/src/atc.ts#L11-L57), [attestation.go:354-L385](https://github.com/tinfoilsh/tinfoil-go/blob/173ed2fb593ba8cebab1f97a32f114395153c083/verifier/attestation/attestation.go#L354-L385)). It verifies an endpoint separately, but contains no commitment to the earlier request or response.

Consequently, a client can show that an acceptable endpoint exists, but not that it processed the inference under the inspected hardware, key, and release epoch.

### Supply-Chain Consequences

The router selects the latest release tag, fetches its artifact digest and Sigstore bundle, verifies the bundle, and retains the tag and resulting measurement ([manager.go:927-L966](https://github.com/tinfoilsh/confidential-model-router/blob/91c9bbe971046c93bacb4b889a10595399ce7be8/manager/manager.go#L927-L966)). Status does not expose the digest or transparency material, and the router keeps no client-visible history of previously admitted releases.

Signed provenance authenticates a release path; it does not establish that every artifact produced by that path is benign. Relevant incidents demonstrate the needed attack primitives:

- A compromised ESLint maintainer account published malicious patch versions, including one unpublished after 36 minutes ([ESLint postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/)).
- An authorized event-stream maintainer introduced a targeted encrypted payload that behaved harmlessly outside the victim environment and remained difficult to detect for months ([npm incident report](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)).
- A poisoned GitHub Actions cache caused malicious code to execute in a legitimate TanStack release runner and use its OIDC trusted-publisher capability; the publish workflow itself was not modified ([TanStack postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)).

Auditing the router source establishes how it validates this material, but not that every artifact subsequently emitted by the authorized backend release path is benign. A similarly compromised accepted backend release path could produce an internally valid measurement and provenance record without changing the router. A targeted backend could then handle normal audit traffic honestly while intercepting selected requests. Without request-bound backend evidence or a durable admission log, later endpoint auditing may miss both the affected request and a short-lived release.

NEAR's design does not prevent an authorized workflow from producing a malicious artifact either, but it changes what the client can audit. Its model evidence exposes the digest-pinned backend compose manifest, and its model signing identity can be connected to both that evidence and a processing receipt. A client can therefore archive the exact artifact identity used in its trust decision, apply its own provenance policy, and link the selected backend identity to the request. Tinfoil already produces most of the underlying evidence; the gap is that cloud routing consumes it behind the router boundary instead of preserving it for the client and binding it to processing.

---

## Remediation

The confidentiality and integrity gaps require separate changes. Publishing evidence does not remove router plaintext, and backend encryption alone does not provide a durable release and processing record.

### 1. Preserve Direct Inference for the Strongest Boundary

Clients that require plaintext to be visible only inside the inference endpoint should connect directly to per-model enclaves. The client can then verify the backend's own fresh attestation, bind transport keys to that evidence, and encrypt bodies to its HPKE key.

This is the simplest way to ensure that the endpoint decrypting the request is the endpoint whose CPU, GPU, software, and keys the client verified. It sacrifices router-owned rewriting, routing defaults, and tool behavior unless those features move elsewhere.

### 2. Staple Backend Evidence and a Backend Receipt

Cloud responses should carry evidence for the backend that handled the request:

- stable backend identity and hostname;
- fresh client-nonce-bound CPU, GPU, and applicable NVSwitch evidence;
- attested TLS fingerprint and HPKE key;
- release digest, tag, signing identity, and transparency evidence;
- a backend-authenticated receipt covering a request commitment, response commitment, attestation epoch, and release digest.

A router signature over its routing decision is useful for accountability but cannot replace the backend receipt: it remains an assertion by the component whose enforcement is being audited. This stage would let clients verify processing integrity while leaving the router in the plaintext trusted computing base.

NEAR's `provider_tee` signature is a concrete precedent for this stage: an attested model signing identity authenticates the model ID together with request and response hashes. Tinfoil could adopt the same pattern while additionally covering its release digest and attestation epoch.

### 3. Add End-to-Backend Body Encryption

Removing router plaintext requires a two-stage protocol:

1. The router selects a backend and returns its fresh attestation and HPKE key.
2. The client verifies the evidence and encrypts inference content to that backend key.
3. The router forwards the opaque body.
4. The backend decrypts it and authenticates its response and processing receipt.

The request envelope must separate router-visible routing metadata from backend-confidential inference content. Existing router features that inspect or rewrite prompts, files, tool options, priority, usage settings, or cache state would need privacy-preserving redesign, relocation to the client/backend, or explicit exclusion from this mode.

NEAR's E2EE gateway path is a concrete precedent for this separation. The client obtains a model-attested public key, sends the selected key as routing metadata, encrypts sensitive fields to that key, and supplies a client key for the model's encrypted response. The gateway retains model selection and routing while losing authority to decrypt the protected fields.

### Deployment Priority

| Stage | Change | Security gained | Residual gap |
|---|---|---|---|
| 1 | Document the actual boundary and preserve direct inference | Accurate claims and a strong option for sensitive workloads | Cloud router still sees plaintext; no cloud processing proof |
| 2 | Staple fresh backend evidence and backend receipt | Request-bound backend integrity and durable release evidence | Router still sees plaintext |
| 3 | Encrypt inference content to the backend | Router removed from the content plaintext boundary | Router-visible metadata and optional router features remain in scope |

Until stages 2 and 3 exist, cloud mode should be described as router-attested body confidentiality, router-enforced backend CPU admission and TLS pinning, backend-boot-enforced GPU validation, and out-of-band endpoint auditing—not end-to-inference encryption or backend-authenticated request processing.

---

## References

**Tinfoil source code:**

- [cvmimage at `282479badb65e7b866afd733cf586367c0599911`](https://github.com/tinfoilsh/cvmimage/tree/282479badb65e7b866afd733cf586367c0599911)
- [confidential-model-router at `91c9bbe971046c93bacb4b889a10595399ce7be8`](https://github.com/tinfoilsh/confidential-model-router/tree/91c9bbe971046c93bacb4b889a10595399ce7be8)
- [encrypted-http-body-protocol at `8528a8dc5ad45c213f14f9bab46a748fda7e18cc`](https://github.com/tinfoilsh/encrypted-http-body-protocol/tree/8528a8dc5ad45c213f14f9bab46a748fda7e18cc)
- [tinfoil-js at `50e664521d69f45de84c494b1fdca2131465d028`](https://github.com/tinfoilsh/tinfoil-js/tree/50e664521d69f45de84c494b1fdca2131465d028)
- [tinfoil-go at `173ed2fb593ba8cebab1f97a32f114395153c083`](https://github.com/tinfoilsh/tinfoil-go/tree/173ed2fb593ba8cebab1f97a32f114395153c083)

**Supply-chain incidents:**

- [ESLint malicious package postmortem](https://eslint.org/blog/2018/07/postmortem-for-malicious-package-publishes/)
- [npm event-stream incident report](https://blog.npmjs.org/post/180565383195/details-about-the-event-stream-incident)
- [TanStack npm supply-chain compromise postmortem](https://tanstack.com/blog/npm-supply-chain-compromise-postmortem)

**NEAR AI comparison:**

- [NEAR AI model verification](https://docs.near.ai/cloud/verification/model/)
- [NEAR AI end-to-end encrypted chat completions](https://docs.near.ai/cloud/guides/e2ee-chat-completions/)
- [NEAR AI chat message verification](https://docs.near.ai/cloud/verification/chat/)
- [NEAR AI private inference and direct completions](https://docs.near.ai/cloud/private-inference/)
- [nearai-cloud-verifier at `6a9c0c57dd9b2b47bbd2682df4a685c50210096e`](https://github.com/nearai/nearai-cloud-verifier/tree/6a9c0c57dd9b2b47bbd2682df4a685c50210096e)
- [NEAR AI documentation source at `e94e73f938cb4852c6d3ab274dad35c345a9e3ff`](https://github.com/nearai/docs/tree/e94e73f938cb4852c6d3ab274dad35c345a9e3ff/docs/cloud)

---

## Teep Status

Teep exposes two Tinfoil provider aliases with materially different verification subjects. Both use the fail-closed V3 attestation path, but a passing factor means only that the endpoint named in the corresponding column was verified.

| Property | `tinfoil_v3_cloud` | `tinfoil_v3_direct` |
|---|---|---|
| Endpoint Teep attests | Confidential model router | Selected per-model inference enclave |
| Fresh hardware evidence Teep verifies | Router CPU evidence and any hardware evidence belonging to the router boundary | Selected backend's CPU, GPU, and, when applicable, NVSwitch evidence and topology |
| Supply-chain release Teep verifies | `tinfoilsh/confidential-model-router` | Per-model deployment repository returned by discovery |
| Meaning of `measured_model_weights=Pass` | Router-mediated trust: the verified router release contains the backend-admission policy; Teep does not compare the selected backend to its per-model release | Direct trust: the selected backend's measured configuration matches its per-model Sigstore release and commits to the model volume's dm-verity root |
| Attested TLS and HPKE keys | Router keys; EHBP plaintext is available to the router workload | Selected backend keys; EHBP terminates in the inference enclave |
| Data-plane authentication visible to Teep | Request and response are AEAD-authenticated to the router boundary | Request and response are AEAD-authenticated to the selected inference-enclave key |

In `tinfoil_v3_cloud`, Teep can therefore establish that an expected, freshly attested router release received the request and was programmed to enforce Tinfoil's backend policy. Backend CPU admission and TLS pinning remain router-enforced, GPU validation remains backend-boot-enforced, and status plus endpoint bundles remain out-of-band audit inputs. None of the router's passing factors should be reported as Teep having independently verified the identity, freshness, GPU state, release, or model weights of the backend selected for a request.

`tinfoil_v3_direct` performs those additional checks at the inference boundary. Teep resolves the requested model to a backend domain and per-model deployment repository, obtains a client-nonce-bound attestation from that backend, validates its CPU and GPU evidence and applicable NVSwitch evidence, and compares its measured configuration with the authenticated Sigstore release for that model deployment. The release-authenticated configuration commits to a particular read-only model-weight volume through its dm-verity root; the measured boot chain authenticates that configuration, and dm-verity validates blocks as the inference runtime reads the weights. Teep then pins the live TLS connection and EHBP encryption to keys from the same backend attestation. Taken together, these checks establish that the selected enclave authorized to decrypt and serve the request is running the specific model deployment release and committed model-weight volume that Teep verified, rather than merely establishing that an acceptable backend exists somewhere behind an attested router.

The model-weight conclusion is deliberately transitive: Teep does not download and hash every weight file itself. It verifies `Sigstore release -> measured configuration -> dm-verity root`, while the attested kernel enforces the final block-level checks. A failure or skip anywhere in that chain must prevent Teep from reporting the model weights as verified.

Direct mode closes the router-boundary gaps, but it does not produce a durable backend-signed receipt over the request and response. Users requiring end-to-inference body encryption, direct verification of fresh backend hardware evidence, or verification of the specific model-weight release used must reject `tinfoil_v3_cloud` and use `tinfoil_v3_direct`. Users requiring backend-authenticated request attribution for later audit must wait until Tinfoil adds a request-bound backend signature or equivalent protocol evidence, or use NEAR AI.
