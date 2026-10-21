# Plan: Fulcio Certificate Chain Verification for Rekor Provenance

This plan covers GitHub issue #164: for neardirect, nearcloud and Venice,
teep reads the Fulcio signer identity from a Rekor certificate it does not
verify.

## 1. Defect

`fetchRekorProvenance` (`internal/attestation/rekor.go`) takes the verifier
certificate from each Rekor entry, and `parseFulcioProvenance` copies its SAN
URI and Fulcio extensions into `RekorProvenance`. No step verifies the
certificate chain, the validity at the integrated time, or an SCT.
`verifyFulcioEntry` (`internal/attestation/report.go`) compares these fields
with the `FulcioSigned` policy entry. The SET and inclusion proof verify,
because Rekor did record the entry.

Rekor accepts any X.509 certificate as a `dsse` verifier. A party that can
change the attested compose can deploy an image digest, log a `dsse` entry
for it signed with a self-signed certificate that carries the GitHub Actions
issuer and the expected `nearai/*` workflow SAN, and pass
`build_transparency_log`, `provider_signer_recognition` and
`component_signature_recognition`. These factors are enforced for neardirect
and nearcloud.

## 2. Evidence

- **Entry bodies.** The 97 Rekor entries in `internal/integration/testdata`
  are 92 `dsse` 0.0.1 and 5 `intoto` 0.0.1. Each `dsse` body holds only
  `spec.envelopeHash`, `spec.payloadHash` and `spec.signatures` (one item:
  `signature`, `verifier`), never the DSSE payload. This is Rekor's canonical
  form: `V001Entry.Canonicalize` in `sigstore/rekor` drops `ProposedContent`.
- **Why DSSE is skipped.** `verifyDSSESignature` reads
  `spec.content.envelope`, which no stored body has, so it fails for every
  entry. All seven Rekor `FulcioSigned` entries (`neardirect/policy.go`,
  `nearcloud/policy.go`; Venice uses the neardirect policy) set
  `NoDSSE: true`. Its comment ("DSSE envelope lacks signatures") is wrong:
  the envelope is signed, but Rekor does not store the signed payload, so
  teep cannot verify the signature from Rekor data.
- **Certificates.** Of the 65 certificate verifiers, 64 are issued by
  `O=sigstore.dev, CN=sigstore-intermediate` and one by "Scribe Security
  Test Intermediate CA" (no Fulcio extensions); 27 verifiers are raw keys.
  All 65 are valid at their entry's `integratedTime` (leaf lifetime is ten
  minutes). The Fulcio leaves embed an SCT from `ctfe.sigstore.dev/2022`
  (log ID `dd3d306a…`), which the public-good trusted root lists.
- **Third-party entries.** The alpine digest `4b7ce070…` returns raw-key
  entries, a `BuoyantIO/enterprise-linkerd` certificate and two Docker
  builder certificates. Rekor indexes in-toto subject digests and SLSA
  `materials` digests (`V001Entry.Unmarshal`); no signature covers the index.
- **Envelope source.** For `nearaidev/cvm-ingress` digest `1653c232…`, the
  GitHub attestations API returns a Sigstore v0.3 bundle whose payload
  SHA-256 equals the Rekor entry's `payloadHash` (`1c8f8a0a…`) and whose
  in-toto subject is that image digest.
- **Tinfoil path.** `internal/provider/tinfoil/sigstore.go` verifies a full
  bundle with `verify.NewVerifier` (SCT, tlog and observer timestamp
  thresholds), `WithArtifactDigest` and `WithCertificateIdentity`. It fetches
  the trusted root through TUF with `tuf.DefaultOptions()` and a new
  `tlsct.NewHTTPClient`, not the injected client. Tinfoil fixtures hold no
  TUF responses, so Tinfoil replay tests send requests to
  `tuf-repo-cdn.sigstore.dev` and write `~/.sigstore/root`.

## 3. Decisions

### 3.1 Verifier

**Option A: the sigstore-go bundle verifier on a bundle built from the Rekor
entry.** It checks the chain, SCT, tlog entry, DSSE signature and artifact
digest in one call. It cannot work on Rekor data alone: a bundle needs the
DSSE envelope with its payload, and the Rekor body does not hold it.

**Option B: direct verification with sigstore-go functions.** For each
certificate entry whose SET verifies with the pinned Rekor key:

1. `verify.VerifyLeafCertificate(time.Unix(integratedTime, 0), leaf, root)`
   checks the chain to a Fulcio CA in the trusted root, the CA validity
   window, the leaf validity and the code-signing EKU at that time.
2. `verify.VerifySignedCertificateTimestamp(chains, 1, root)` checks one
   embedded SCT from a CT log in the trusted root.
3. `certificate.SummarizeCertificate(leaf)` gives the SAN and Fulcio
   extensions. It replaces `parseFulcioProvenance`, `hasFulcioPrefix` and
   `decodeExtensionValue` and its raw UTF-8 path.

Option B proves that Fulcio issued the certificate to the stated identity,
and that while it was valid Rekor accepted a `dsse` envelope signed by its
key with the logged `payloadHash`. It does not check the DSSE signature
(Rekor checked it at admission; the SET covers only the stored body), and it
does not prove that the payload names the image digest as its subject: that
link comes from Rekor's unsigned search index.

**Decision: Option B.** It fixes the defect with the data teep already
fetches, adds no network host, and works in replay. Only a SET-verified
entry has an authenticated `integratedTime`, so the chain check runs only
after the SET check passes. Phase 4 uses Option A with an envelope from the
GitHub attestations API to close the subject gap.

### 3.2 Trusted root acquisition

- **One source.** Phase 1 moves the trusted root fetch from
  `internal/provider/tinfoil` to `internal/attestation` as an interface,
  `TrustedRootSource.TrustedRoot(ctx) (root.TrustedMaterial, error)`. The
  production implementation keeps today's Tinfoil behavior (embedded TUF
  root, `tuf-repo-cdn.sigstore.dev`, single-attempt `newTrustedRootFetcher`).
  Tinfoil and the Rekor path both use it.
- **Injection.** `NewRekorClient` takes a `TrustedRootSource` and panics on
  nil. `proxy.New` and `verify.checkSigstore` pass the production source. No
  package-level state.
- **One fetch per verification.** `FetchRekorProvenancesForPolicy` gets the
  root once, before it starts the per-digest goroutines, and gives each the
  same immutable `TrustedMaterial`. On a fetch error every result gets
  `Err` "Sigstore trusted root: …" and the three factors fail; no earlier
  root is reused. A server-wide cache belongs with
  `docs/plans/supply_chain_caching.md`.
- **`--offline`.** Unchanged. `checkSigstore` and the proxy send no Rekor or
  TUF request, `in.Rekor` is empty, and the factors report Fail:
  `build_transparency_log` "no Rekor provenance fetched for attested
  component digests"; the two recognition factors "no Rekor provenance
  available for …". All three are in `OnlineFactors`, so
  `WithOfflineAllowFail` adds them to `allow_fail` and they do not block.
- **Replay and tests.** TUF metadata cannot be replayed: go-tuf sets
  `RefTime` to `time.Now()`, and the timestamp role expires about one week
  after a fetch (a fetch on 2026-10-19 expires 2026-10-25). The trusted root
  target has no expiry; its CA, CT and Rekor keys have validity windows that
  are checked at the integrated time. Tests use a static source,
  `root.NewTrustedRootFromJSON` on one checked-in file,
  `internal/attestation/testdata/sigstore_trusted_root.json`, with a note
  that records its TUF target SHA-256, fetch date and `targets.json` version.
  Unit, integration and `verify.Replay` tests load it by relative path, as
  `near_capture_test.go` loads fixtures.
- **No root from a capture.** A capture directory is untrusted input; a root
  read from it would let a forged capture add its own CA. `teep verify
  --replay` uses the production TUF source, as Tinfoil replay does today.
  Fixtures get no TUF metadata and no per-fixture root.
- **Currency.** The checked-in root changes only when Sigstore adds or
  rotates a Fulcio CA, CT log or Rekor key that a new fixture uses. Then
  replay fails with a chain or SCT error, and the file is replaced from a
  live TUF fetch.

### 3.3 The `NoDSSE` entries

Phase 3 deletes `ImageProvenance.NoDSSE`, `RekorProvenance.SignatureVerified`
and `SignatureErr`, `verifyDSSESignature` and `buildPAE`. No skip remains.
The `FulcioSigned` comment states the checked property: a SET-verified Rekor
`dsse` entry, found by digest search, whose certificate chains to the
Sigstore trusted root at the integrated time with a valid SCT, and whose
identity matches the policy.

Entry body rules (Phase 2): `kind` is `dsse`, `apiVersion` is `0.0.1`,
`envelopeHash` and `payloadHash` are SHA-256 hex, and `signatures` holds
exactly one item. Teep rejects any other entry with a warn-level diagnostic
that names the UUID and the reason. A rejected or unverifiable entry does
not end the search: anyone can log an entry for a public digest, so failing
the digest on one bad entry would let that party block a provider. When no
entry for a `FulcioSigned` component passes, `build_transparency_log` fails
with the last rejection reason, and both recognition factors fail on the
same `RekorProvenance`.

### 3.4 Factor semantics after the change

For neardirect, nearcloud and Venice:

- `build_transparency_log`: each signed component digest has a Rekor entry
  with a valid SET and inclusion proof, and each `FulcioSigned` entry's
  certificate chains to a Fulcio CA in the Sigstore trusted root, with an
  SCT, at the SET-authenticated integrated time.
- `component_signature_recognition`: each signed component's chain-verified
  Fulcio identity (issuer, SAN, source repository), or its pinned key for
  `SigstorePresent`, matches the policy entry for that component.
- `provider_signer_recognition`: each signed component's chain-verified
  signer, or pinned key, is one that the policy trusts provider-wide.

| Where | Today | After |
|---|---|---|
| `formatBuildTransparencyResult` Pass | `N component(s) verified by Fulcio provenance` | `N component(s) with Fulcio certificate chain and SCT verified at log time` |
| `verifyFulcioEntry` | `DSSE envelope signature verification failed: …` | removed |
| `verifyFulcioEntry` | `expected Fulcio certificate but entry has non-Fulcio X.509 cert (no OIDC issuer OID)` | `expected Fulcio certificate but no entry certificate chains to the Sigstore trusted root: …` |
| `verifyFulcioEntry` | — | `Fulcio certificate chain not verified` (checked before identity) |
| `classifyRekorEntry`, `verifyComponentSignature` | `Rekor provenance fetch failed: …` | `Rekor provenance unavailable: …` (cause: fetch, parse, trusted root or chain) |

The recognition factors keep their Pass texts; their failure texts come from
`verifyFulcioEntry`. Tinfoil factor texts do not change.

## 4. Phases

One commit per phase; `make check` before each commit.

### Phase 1: Shared Sigstore trusted root source

- Behavior: add `internal/attestation/sigstore_root.go` with
  `TrustedRootSource`, a TUF implementation and a static implementation;
  move `newTrustedRootFetcher` and `trustedRootDo` from the tinfoil package;
  `tinfoil.NewSigstoreVerifier` takes a source. Production behavior does
  not change.
- Tests: move `redirect_test.go` and `root_cancellation_test.go`; the static
  source rejects empty and malformed JSON; the checked-in root parses and
  holds the Fulcio CA, the `ctfe.sigstore.dev/2022` key and the Rekor log ID
  of `rekorLogPublicKeyPEM` (`c0d23d6a…`). Tinfoil replay tests use the
  static source and send no TUF requests.
- Documents: `docs/providers/tinfoil/tinfoil_support.md` (root source, test
  coverage); the note for the root file.

### Phase 2: Strict Rekor response and entry parsing

- Behavior: `fetchRekorUUIDs`, `fetchRekorEntry` and the body parser use
  `jsonstrict.Unmarshal` and return unknown field names; the caller rejects
  the entry. Bound the UUID list length. Apply the body rules in 3.3;
  `intoto` entries get an explicit rejection reason.
- Tests: unknown fields; wrong kind or version; zero or two signatures;
  missing or malformed hashes; a verifier that is neither certificate nor
  public key. Fixture replay results and documents do not change.

### Phase 3: Fulcio chain verification

- Behavior: `NewRekorClient` takes a `TrustedRootSource`. Per entry: SET and
  inclusion proof, then Option B steps 1 to 3 for certificates. Rename
  `HasCert` to `FulcioVerified`; identity fields are set only when it is
  true. A failed certificate is rejected for selection (3.3). Both
  `verifyFulcioEntry` and the no-policy branches of `classifyRekorEntry`
  require `FulcioVerified`. Remove `NoDSSE` and the DSSE code. Identity
  comparisons stay constant-time.
- Regression tests:
  - A self-signed certificate with Fulcio OIDs, the GitHub issuer and the
    `nearai/compose-manager` SAN, in an entry with a valid test SET and
    inclusion proof, is rejected, and all three factors fail. Run against
    the checked-in root and a test root.
  - A leaf from a CA that is not in the trusted root is rejected.
  - An integrated time outside the leaf validity or the CA window is
    rejected; a leaf valid at the integrated time but expired now passes.
  - A leaf without an SCT, or with an SCT from a log not in the root, is
    rejected.
  - An invalid SET gives no chain check and no Fulcio identity.
  - An attacker entry listed before the legitimate entry does not change
    the selected entry; the attacker entry alone fails the factors.
  - A trusted root source error fails all three factors.
  - Concurrent `FetchRekorProvenancesForPolicy` calls under `-race` fetch the
    root once per call and share no mutable state.
- Replay tests: NEAR and Venice fixtures pass the three factors with
  `FulcioVerified` true for every `FulcioSigned` component. Update the
  `near_tls_only/*/report.txt` lines that
  `TestNearTLSOnlySignedCaptureReplay` compares exactly.
- Documents: `README.md` and `README_ADVANCED.md` factor tables (row 28,
  and rows for the two recognition factors);
  `docs/attestation_gaps/model_weights.md` (remove the DSSE claims in the
  diagram and the "Verified today" table; state chain, SCT, SET and the
  subject gap);
  a gap entry in `docs/attestation_gaps/README.md`;
  `docs/plans/supply_chain_attestation_map.md` (remove `NoDSSE=true`, mark
  the earlier text historical); `NoDSSE` lines in `docs/audit_prompts/`;
  `docs/providers/near/near_attestation.md` (supply chain trust boundary).

### Phase 4: DSSE envelope and subject binding

- Behavior: for each selected `FulcioSigned` entry, fetch the bundle for the
  digest from the GitHub attestations API for a repository in the policy
  `SourceRepos`, through the attestation client with bounded reads. Require
  the envelope payload SHA-256 to equal the entry `payloadHash`
  (constant-time), verify the DSSE signature with the chain-verified leaf
  key, and require an in-toto subject with the image digest. A missing
  bundle or a mismatch fails `build_transparency_log` with
  `component %q: DSSE envelope not verified: …`; the recognition factors
  fail on the same result.
- Tests: payload hash mismatch; digest only in `materials`; wrong subject;
  envelope signed by another key; API errors; oversized bodies. NEAR
  fixtures are recaptured to include the GitHub responses.
- Documents: close the subject gap; NEAR provider document; the host table
  in `docs/transport/redirects.md`.

## 5. Risks

- **Expiry.** Fixture leaves expired ten minutes after issue. Checks use the
  integrated time, not the current time; a Phase 3 test covers this.
- **sigstore-go v1.2.1.** `VerifyLeafCertificate` returns one generic error
  ("leaf certificate verification failed"), so details name the step, not
  the x509 cause. `VerifySignedCertificateTimestamp` skips SCTs from unknown
  logs and fails only below the threshold. `pkg/testing/ca` leaves have no
  SCT and an email SAN, so SCT-positive tests use fixture certificates and
  negative tests use a teep test CA with a URI SAN.
- **Passing providers.** Every selected NEAR and Venice fixture entry is
  issued by `sigstore-intermediate` with a `ctfe 2022` SCT, so no fixture
  result changes. Live, a failed TUF fetch now fails three enforced NEAR
  factors and blocks, as it does for Tinfoil today. Tinfoil results do not
  change.
- **Rekor v2.** The trusted root lists `log2025-1.rekor.sigstore.dev`. If
  GitHub attestations move to Rekor v2, the v1 search will not find new
  entries and the factors fail closed. Phase 4 bundles carry their own tlog
  entries and do not need the v1 search.
- **GitHub API (Phase 4).** Unauthenticated requests are limited to 60 per
  hour per address, and one NEAR verification checks up to seven
  `FulcioSigned` digests. Without a cache or token, `teep serve` can reach
  the limit and block.
- **Not in scope.** `verifyInclusionProof` uses the response's `rootHash`
  and does not verify the checkpoint, so the SET is the only log signature.

## 6. Open questions for the maintainer

1. Phase 4 makes `api.github.com` a NEAR dependency. Accept it, require a
   token, or use another envelope source such as OCI registry referrers?
2. Replace the `rekorLogPublicKeyPEM` constant with the Rekor key from the
   trusted root, so that one source holds all Sigstore keys?
3. Add checkpoint signature verification to this plan, or track it as a
   separate issue?
