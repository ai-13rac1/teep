# Tinfoil NVSwitch Evidence: JSON Re-encoding Hash Mismatch

Tinfoil's V3 attestation endpoint serves NVSwitch evidence whose
`report_data.nvswitch_evidence_hash` does not match the SHA-256 of the
NVSwitch JSON bytes in the HTTP response. The server computes the hash
over the raw `nvattest` CLI output (serialized by NVIDIA's C++
`nlohmann/json` library), but Go's `json.Marshal` re-encodes the
`json.RawMessage` when embedding it in the response, producing different
bytes. This causes all 8-GPU Hopper inference enclaves that serve
NVSwitch evidence to fail REPORTDATA binding verification. The gap is
open on all Tinfoil 8-GPU Hopper deployments until the server-side code
compacts the `nvattest` output before hashing.

## The Problem

Tinfoil's confidential VM image serves a V3 attestation document at
`/.well-known/tinfoil-attestation?nonce=<hex>`. For 8-GPU Hopper
systems, the document includes NVSwitch attestation evidence in a
`nvswitch` JSON field and a corresponding `nvswitch_evidence_hash` in
`report_data`. The hash is bound into the CPU hardware attestation
report's REPORTDATA field, cryptographically tying the NVSwitch evidence
to the CPU quote.

The problem is that the hash reported in `report_data.nvswitch_evidence_hash`
does not match `SHA-256(raw_nvswitch_json_bytes)` from the HTTP response.
The server computes the hash over the raw output of the `nvattest`
command-line tool, which uses NVIDIA's C++ `nlohmann/json` library for
serialization. When the server embeds this output as a `json.RawMessage`
in the `Attestation` struct and serializes the full response with Go's
`json.Marshal` or `json.NewEncoder`, Go re-encodes the `json.RawMessage`,
changing the byte sequence (compacting whitespace, potentially reordering
or re-escaping). The hash was computed over the pre-re-encoding bytes,
but the response contains the post-re-encoding bytes.

This means any external verifier that hashes the NVSwitch JSON bytes from
the response — which is the only data available to a remote client — will
compute a different hash than the one bound into the hardware attestation
report. The REPORTDATA verification fails, which cascades to GPU-CPU
binding and NVSwitch binding verification failures.

## Impact

**Security impact:** The NVSwitch evidence hash mismatch prevents
independent verification of GPU-CPU binding for 8-GPU Hopper systems.
While the GPU evidence itself (SPDM reports, certificate chains) is
present and independently verifiable, the cryptographic binding between
NVSwitch evidence and the CPU hardware quote cannot be confirmed. An
attacker who could substitute NVSwitch evidence in transit would not be
detected by the REPORTDATA hash check, because the check fails regardless
of whether the evidence is authentic or tampered.

However, the GPU evidence hash (for the `gpu` field) is NOT affected by
this bug — GPU evidence is collected via `json.Marshal` in Go, which
produces compact JSON from the start, so the hash matches the response
bytes. Only NVSwitch evidence, collected via the external `nvattest` CLI,
is affected.

**Operational impact:** All 8-GPU Hopper Tinfoil inference enclaves
(e.g. `glm-5-2`) fail attestation verification. Teep correctly fails
closed, blocking requests to these enclaves. Single-GPU enclaves
(e.g. `gemma4-31b`) are unaffected because they do not serve NVSwitch
evidence.

---

## Technical Background

### V3 Attestation Document Structure

The Tinfoil V3 attestation response is a JSON document with the
following structure:

```json
{
  "format": "https://tinfoil.sh/predicate/attestation/v3",
  "report_data": {
    "tls_key_fp": "<64 hex>",
    "hpke_key": "<64 hex>",
    "nonce": "<64 hex>",
    "gpu_evidence_hash": "<64 hex>",
    "nvswitch_evidence_hash": "<64 hex>"
  },
  "cpu": { "platform": "tdx|sev-snp", "report": "<base64>" },
  "gpu": { "evidences": [...] },
  "nvswitch": { "evidences": [...], "result_code": 0, "result_message": "..." },
  "certificate": "<PEM>",
  "signature": "<base64 ECDSA>"
}
```

The `report_data.gpu_evidence_hash` and
`report_data.nvswitch_evidence_hash` fields contain SHA-256 hashes of
the raw `gpu` and `nvswitch` JSON field bytes, respectively. These
hashes are included in the REPORTDATA preimage:

```
REPORTDATA[0:32] = SHA-256(tls_key_fp || hpke_key || nonce || gpu_evidence_hash || nvswitch_evidence_hash)
REPORTDATA[32:64] = zeros
```

The CPU hardware attestation report (TDX quote or SEV-SNP report) signs
the REPORTDATA, cryptographically binding the GPU and NVSwitch evidence
to the CPU enclave identity.

### Server-Side Evidence Collection

The Tinfoil CVM image collects GPU and NVSwitch evidence differently:

**GPU evidence** is collected via NVML (Go bindings):
- `CollectGPUEvidence` calls `nvml.GetConfComputeGpuAttestationReport`
- The evidence is marshaled with Go's `json.Marshal(gpuEvidence)`,
  producing compact JSON
- The compact JSON is used as `json.RawMessage` for both hashing and
  response embedding
- Hash and response bytes match → verification passes

**NVSwitch evidence** is collected via the `nvattest` CLI:
- `CollectNVSwitchEvidence` runs `nvattest collect-evidence --device
  nvswitch --nonce <hex> --format json`
- The CLI output (serialized by NVIDIA's C++ `nlohmann/json` library)
  is used directly as `json.RawMessage(out)`
- `EvidenceHash(nvswitchJSON)` computes SHA-256 over the raw CLI output
  bytes
- The `Attestation` struct is serialized with
  `json.NewEncoder(w).Encode(fresh)`, which calls `json.Marshal`
  internally
- `json.Marshal` re-encodes the `json.RawMessage`, changing the byte
  sequence
- Hash was computed over pre-re-encoding bytes; response contains
  post-re-encoding bytes → mismatch

### Go's json.RawMessage Re-encoding Behavior

Go's `encoding/json` package treats `json.RawMessage` as a raw JSON
value that implements `MarshalJSON()`. When `json.Marshal` encounters a
`json.RawMessage`, it calls `MarshalJSON()` which returns the raw bytes
as-is. However, `json.Marshal` then validates and potentially re-encodes
the returned bytes to ensure they are valid JSON embedded in the parent
structure.

Specifically, `json.Marshal` compacts `json.RawMessage` bytes: it
strips whitespace (spaces, newlines, tabs) between JSON tokens. If the
`nvattest` CLI outputs pretty-printed JSON (which `nlohmann/json` does
not do by default, but the CLI may configure), the compacted bytes will
differ from the original.

Even if the `nvattest` output is already compact, `nlohmann/json` and
Go's `encoding/json` may produce different byte sequences for the same
data due to:
- Different number formatting (integers vs floats)
- Different string escaping (unicode escape sequences)
- Different key ordering (though both preserve insertion order by
  default)

---

## Detailed Gap Analysis

### Server Source Code Analysis

The bug is in
[`CollectNVSwitchEvidence`](https://github.com/tinfoilsh/confidential-cvmimage/blob/main/tinfoil/internal/attestation/gpu.go)
in the `cvmimage` repository:

```go
func CollectNVSwitchEvidence(nonce [32]byte) (json.RawMessage, error) {
    nonceHex := hex.EncodeToString(nonce[:])
    ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
    defer cancel()

    out, err := exec.CommandContext(ctx, "nvattest", "collect-evidence",
        "--device", "nvswitch",
        "--nonce", nonceHex,
        "--format", "json",
    ).Output()
    if err != nil {
        return nil, fmt.Errorf("nvattest collect-evidence nvswitch: %w", err)
    }

    if !json.Valid(out) {
        return nil, fmt.Errorf("nvattest returned invalid JSON")
    }

    return json.RawMessage(out), nil  // ← raw CLI output, not compacted
}
```

The function returns the raw `nvattest` CLI output as `json.RawMessage`
without normalizing it. This raw output is then:

1. Passed to `BuildAttestation`, which calls
   `EvidenceHash(nvswitchJSON)` — hashing the raw CLI output bytes
2. Set as the `NVSwitch` field on the `Attestation` struct
3. Serialized with `json.NewEncoder(w).Encode(fresh)` — which re-encodes
   the `json.RawMessage`, potentially changing the bytes

The GPU evidence path does not have this issue because
`CollectGPUEvidence` returns a Go struct (`*GPUEvidenceCollection`),
which is marshaled with `json.Marshal(gpuEvidence)` at the call site
(line 335 of `api.go`), producing compact Go-native JSON. The same
compact bytes are used for both the hash and the response.

### Empirical Verification

Two attestation responses were fetched from
`glm-5-2.tinfoil.containers.tinfoil.dev` (8-GPU Hopper TDX enclave).
For each response, the NVSwitch JSON bytes were extracted from the raw
HTTP response body and hashed with SHA-256. The computed hash was
compared against the `report_data.nvswitch_evidence_hash` field.

| Attempt | Reported Hash | Computed Hash (from response bytes) | Match? |
|---|---|---|---|
| 1 | `bffc94fd...` | `cd8e37fc...` | ✗ |
| 2 | `985ab210...` | `5e0a6c02...` | ✗ |

Multiple re-encoding strategies were tested against the response bytes:
compact, pretty-printed (2-space, 1-space, tab indent), with/without
trailing newline, re-marshaled via `json.Marshal`, and normalized via
`json.Compact`. None matched the reported hash.

The GPU evidence hash was also checked and matches perfectly in both
responses, confirming the issue is specific to the NVSwitch evidence
collection path.

### Teep Report Factor Behavior

The NVSwitch hash mismatch causes the following factor cascade in teep:

1. `tee_reportdata_binding` → **Fail**: The `verifyNVSwitchEvidenceHash`
   function in `internal/provider/tinfoil/verify.go` computes
   `SHA-256(raw.NVSwitchRawJSON)` and compares against
   `raw.TinfoilNVSwitchEvidenceHash`. The mismatch causes
   `VerifyReportData` to return an error, which sets
   `ReportDataBindingErr` on the TDX/SEV result.

2. `cpu_gpu_chain` → **Fail**: Because `GPUHashBound` is false (the
   REPORTDATA binding failed before reaching the GPU hash check),
   `evalCPUGPUChain` returns Fail.

3. `nvswitch_binding` → **Fail**: Because `GPUHashBound` is false,
   `evalNVSwitchBinding` takes the "no GPU evidence" Skip path, which
   is promoted to Fail by the enforced-factor promotion logic.

4. `measured_model_weights` → **Fail**: Because
   `sigstore_code_verified` also fails (the `glm-5-2` repo returns 404
   from GitHub releases API — a separate issue), the transitive model
   weight chain cannot be established.

---

## Remediation

### Server-Side Fix (Required)

The fix is in `CollectNVSwitchEvidence` in the `cvmimage` repository.
The function must compact the `nvattest` CLI output before returning it
as `json.RawMessage`, ensuring the hash is computed over the same bytes
that `json.Marshal` will produce in the response:

```go
func CollectNVSwitchEvidence(nonce [32]byte) (json.RawMessage, error) {
    // ... existing nvattest call ...

    if !json.Valid(out) {
        return nil, fmt.Errorf("nvattest returned invalid JSON")
    }

    // Compact the JSON to ensure hash consistency: json.Marshal will
    // compact json.RawMessage when embedding it in the response, so
    // the hash must be computed over the compacted form.
    var compacted bytes.Buffer
    if err := json.Compact(&compacted, out); err != nil {
        return nil, fmt.Errorf("compact nvswitch JSON: %w", err)
    }
    return json.RawMessage(compacted.Bytes()), nil
}
```

This ensures `EvidenceHash(nvswitchJSON)` computes the hash over compact
bytes, and `json.Marshal(att)` preserves those exact compact bytes in
the response.

**Important caveat:** `json.Compact` only strips whitespace — it does
not reorder keys, change number formatting, or modify string escaping.
If the `nvattest` CLI output differs from Go's `json.Marshal` output in
any of these aspects, `json.Compact` alone will not fix the mismatch.
In that case, the server should parse the `nvattest` output into a Go
data structure and re-marshal it with `json.Marshal` before hashing:

```go
var parsed interface{}
if err := json.Unmarshal(out, &parsed); err != nil {
    return nil, fmt.Errorf("parse nvswitch JSON: %w", err)
}
compacted, err := json.Marshal(parsed)
if err != nil {
    return nil, fmt.Errorf("re-marshal nvswitch JSON: %w", err)
}
return json.RawMessage(compacted), nil
```

This guarantees the hash is computed over Go-native JSON bytes that
`json.Marshal` will reproduce exactly in the response.

### Client-Side Workaround (Not Recommended)

A client-side workaround would require re-implementing the `nvattest`
CLI's JSON serialization format (determined by NVIDIA's C++
`nlohmann/json` library) in Go. This is fragile and would break when
the `nvattest` CLI or `nlohmann/json` library updates. No client-side
workaround is recommended.

### Deployment Priority

1. **Server-side fix** (required, blocks all 8-GPU Hopper verification)
2. **Client-side workaround** (not recommended — fragile, unreliable)

---

## References

- **Server source code:**
  [`CollectNVSwitchEvidence`](https://github.com/tinfoilsh/confidential-cvmimage/blob/main/tinfoil/internal/attestation/gpu.go)
  in `tinfoilsh/confidential-cvmimage`
- **Server attestation builder:**
  [`BuildAttestation`](https://github.com/tinfoilsh/confidential-cvmimage/blob/main/tinfoil/internal/attestation/attestation.go)
  in `tinfoilsh/confidential-cvmimage`
- **nvattest CLI:** Built from
  [NVIDIA/attestation-sdk](https://github.com/NVIDIA/attestation-sdk)
  using `nlohmann/json` for serialization
- **Go json.RawMessage:** [encoding/json documentation](https://pkg.go.dev/encoding/json#RawMessage)
- **Tinfoil SPEC §4.8:** TDX policy validation including XFAM and
  TD_ATTRIBUTES pins

---

## Teep Status

**Affected factors:**
- `tee_reportdata_binding` — Fail (NVSwitch evidence hash mismatch)
- `cpu_gpu_chain` — Fail (cascade from REPORTDATA binding failure)
- `nvswitch_binding` — Fail (cascade from GPUHashBound=false)
- `measured_model_weights` — Fail (cascade from sigstore_code_verified
  failure, which is a separate issue for `glm-5-2`)

**Teep behavior:** Teep correctly fails closed on the NVSwitch evidence
hash mismatch. The `verifyNVSwitchEvidenceHash` function in
`internal/provider/tinfoil/verify.go` computes
`SHA-256(raw.NVSwitchRawJSON)` from the exact bytes in the HTTP response
and constant-time compares against `report_data.nvswitch_evidence_hash`.
On mismatch, it returns an error that causes `VerifyReportData` to fail,
which cascades to GPU and NVSwitch binding factors.

**Workaround:** None. Teep cannot reproduce the server's hash
computation from the response bytes because the `nvattest` CLI's JSON
serialization format (C++ `nlohmann/json`) differs from Go's
`encoding/json` in ways that cannot be reliably reverse-engineered.

**Post-fix enforcement:** Once the server-side fix is deployed, teep
will automatically verify the NVSwitch evidence hash correctly. No teep
code changes are required — teep already implements the correct
verification logic. The `tee_reportdata_binding`, `cpu_gpu_chain`, and
`nvswitch_binding` factors will pass for 8-GPU Hopper enclaves.
