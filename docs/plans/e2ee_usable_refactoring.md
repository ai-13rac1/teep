# Plan: Refactoring `e2ee_usable` Factor Enforcement

## Background

PR #33 ("Make chutes E2EE work; also add api integration tests") surfaced
fundamental architectural issues with how the `e2ee_usable` report factor
interacts with the proxy's request-blocking mechanism, the report cache, and
integration tests. The PR author's review replies confirm these are known
problems requiring a dedicated redesign rather than point fixes.

This document describes the problems, a short-term plan (incremental fixes
already in progress), and a long-term plan (clean architectural redesign).

---

## Progress

The following work has been completed on the `chutes_integrity` branch as
part of PR #33 review fixes:

| Commit | Description | Plan item |
|--------|-------------|-----------|
| `3eaa490` | Add `e2ee_usable` to `ChutesDefaultAllowFail` and `NearcloudDefaultAllowFail` | Short-term step 1 |
| `e4b075c` | Guard `MarkE2EEUsable` against `Skipped` counter underflow; add `slog.Warn` | S2 (partial) |
| `6de38de` | Document cache mutation race with TODO comments at both `MarkE2EEUsable` call sites | S1 (documented, not yet fixed) |
| `2ac5f5a` | Validate Chutes `apiBaseURL` has scheme and host before E2EE URL rewrite | S3 (done) |
| `a9850b9` | Require `ChuteID` in `testE2EEChutes` instead of falling back to model name | S4 (done) |
| (chutes-reliability) | `ParseAttestationResponse` iterates evidence entries to match known instances | New: fleet dynamics fix |
| (chutes-reliability) | Retry loop (up to 3 attempts) for Chutes E2EE upstream failures with instance failover | New: transport-level retry |
| (chutes-reliability) | Integration test client timeout increased from 120s to 5 minutes | Test infra |
| `89276e6` | Validate E2EE material (pubkey + nonces) at evidence match time; fail closed on `meta != nil && meta.Session == nil`; introduce `upstreamBody` struct decoupling instance tracking from `meta` | New: pre-relay guard, interface change |
| `db1ed0a` | Fix inaccurate comments (retry failover wording, ParseAttestationResponse doc, test comments) | Comment fixes |
| `7c27ae0` | `CandidatesEval` tracks skipped entries; error counters on fail-closed path (`s.stats.errors`, `ms.errors`, `slog.ErrorContext`) | Step 4 (partial), observability |

The following work has been completed on the `refactor-cyclomatic-complexity`
and `e2ee_update` branches:

| Commit | Description | Plan item |
|--------|-------------|-----------|
| `c870285` | Reduce cyclomatic complexity: extract `attestAndCache`, `enforceReport`, `relayResponse`, `doUpstreamRoundtrip`, `buildUpstreamBody`; introduce `httpError`, `attestResult`, `upstreamResult` types | Refactor (prerequisite for steps 2–4) |
| `eba0cf3` | Security audit: block pinned E2EE when `report == nil`; abort unparseable SSE events (was `continue`); `writeStreamError` falls back to `http.Error(502)` pre-header; `ErrNoVerifier` is now a hard error | Fail-closed hardening |
| `04f47db` | Add `StreamStats` return to relay functions (`RelayStream`, `RelayReassembledNonStream`, `RelayStreamChutes`); `ReassembleNonStream` returns `([]byte, StreamStats, error)` | Step 3 (partial: return `StreamStats`, not yet `error`) |
| `9dd5e17` | Review findings: `enforceReport` logs `e2ee_will_activate` in `--force` path; misc strictness | Observability |
| `261c224` | PR #41 review: preserve timing on error paths; fix SSE error handling | Error-path timing |
| `f598a06` | Distinguish E2EE prep errors (`e2ee_failed`) from upstream transport errors (`upstream_failed`) in client responses via `httpError.status` | Step 2 (partial: error classification) |

These commits resolve P1 (chicken-and-egg blocking) by making `e2ee_usable`
allowed-to-fail for all providers. The cyclomatic complexity refactor
(`c870285`) decomposed `handleChatCompletions` from complexity 57→19 by
extracting five helper functions, which is a prerequisite for the remaining
short-term work. The security audit (`eba0cf3`) added fail-closed paths
that complement the plan's post-relay enforcement design. Relay functions
now return `StreamStats` (`04f47db`) — a stepping stone toward returning
`error` (step 3). The remaining short-term work (steps 2–4, 6–8 and the
full S1/S2 fixes) is described below.

---

## Problems

### P1: Chicken-and-egg blocking (critical)

When `e2ee_usable` is enforced (not in a provider's `allow_fail` list),
`BuildReport` promotes the initial `Skip` → `Fail (enforced)`, which causes
`Blocked()` to return `true`. The proxy then refuses the request with HTTP 502.
But `e2ee_usable` can only pass after a successful live E2EE roundtrip — which
requires a request to go through first.

**Affected providers**: Chutes and NearCloud enforce `e2ee_usable` by default
(it is absent from `ChutesDefaultAllowFail` and `NearcloudDefaultAllowFail`).
Venice and NearDirect are unaffected because `e2ee_usable` appears in their
`allow_fail` lists (`DefaultAllowFail` and `NeardirectDefaultAllowFail`).

**Code path** (proxy non-pinned):
1. `handleChatCompletions` calls `attestAndCache` on cache miss
   (`internal/proxy/proxy.go` line 695→line 791)
2. `attestAndCache` calls `fetchAndVerify` which calls `BuildReport` with
   `E2EEConfigured: prov.E2EE` and `E2EETest: nil` (line 476→line 537)
3. `evalE2EEUsable` returns `Skip "E2EE configured; pending live test"`
   (`internal/attestation/report.go` line 889)
4. `BuildReport` promotes enforced `Skip` → `Fail (enforced)` (line 386)
5. `enforceReport` checks `report.Blocked()` → request rejected (line 1069)
6. `MarkE2EEUsable` is never reached (line 852)

**Code path** (proxy pinned, NearCloud):
Same issue: the report is built with `E2EEConfigured=true` and `E2EETest=nil`
inside the pinned handler's attestation path. `enforceReport` fires before the
E2EE relay at line 948.

### P2: Cache mutation race

`MarkE2EEUsable()` mutates the `*VerificationReport` pointer stored in the
cache in-place. The cache's `Get()` returns the same pointer to all concurrent
callers. This means:

- Two concurrent requests for the same provider/model can race on
  `MarkE2EEUsable`, observing a half-mutated `Factors` slice.
- The `/v1/tee/report` endpoint can read the report mid-mutation.
- `report.Passed++` and `report.Skipped--` are non-atomic int mutations.

**Locations**:
- Non-pinned path: `internal/proxy/proxy.go` line 852
- Pinned path: `internal/proxy/proxy.go` line 994

### P3: Counter desync risk

`MarkE2EEUsable()` manually adjusts `Passed` and `Skipped` counters
(`internal/attestation/report.go` line 123):

```go
func (r *VerificationReport) MarkE2EEUsable(detail string) {
    for i := range r.Factors {
        if r.Factors[i].Name == "e2ee_usable" {
            if r.Factors[i].Status == Skip {
                r.Factors[i].Status = Pass
                r.Factors[i].Detail = detail
                r.Passed++
                r.Skipped--
            }
            return
        }
    }
}
```

If the factor was promoted from `Skip` to `Fail (enforced)` by `BuildReport`
(as happens when `e2ee_usable` is enforced per P1), the guard
`Status == Skip` prevents the transition — but the factor remains `Fail` and
is never corrected. If the guard were removed without also adjusting the
`Failed` counter, counters would desync. There is also no guard against
`Skipped` underflowing below zero.

### P4: Divergent verify vs proxy paths

`teep verify` and `teep serve` use fundamentally different lifecycles for
`e2ee_usable`:

| Aspect | `teep verify` | `teep serve` (proxy) |
|--------|--------------|---------------------|
| When E2EE is tested | During report-build via `testE2EE()` | After first successful relay |
| `E2EETest` | Populated in `ReportInput` | Always `nil` |
| `E2EEConfigured` | Not used (irrelevant) | Set from `prov.E2EE` |
| Factor result | Clean `Pass`/`Fail`/`Skip` from `evalE2EEUsable` | Initially `Skip`, retroactively patched via `MarkE2EEUsable` |
| Report mutation | None | Yes (cache in-place mutation) |

**Verify path** (`cmd/teep/main.go`):
- `testE2EE()` (~line 654) dispatches to provider-specific E2EE test functions
- Returns `*E2EETestResult` which is passed to `BuildReport` as `E2EETest`
- `evalE2EEUsable` evaluates the test result and produces a clean factor

**Proxy path** (`internal/proxy/proxy.go`):
- `attestAndCache` calls `fetchAndVerify` which passes
  `E2EETest: nil, E2EEConfigured: prov.E2EE` to `BuildReport`
- `e2ee_usable` starts as `Skip` (or `Fail` if enforced)
- After a successful relay, `MarkE2EEUsable` patches the cached report

### P5: Inconsistent enforcement across providers

`e2ee_usable` enforcement varies across providers' default `allow_fail` lists,
with no clear rationale for the differences:

| Provider | `allow_fail` list | `e2ee_usable` in list? | Enforced? |
|----------|------------------|----------------------|-----------|
| Venice (default) | `DefaultAllowFail` | Yes | No |
| NearDirect | `NeardirectDefaultAllowFail` | Yes | No |
| NearCloud | `NearcloudDefaultAllowFail` | **No** | **Yes** |
| Chutes | `ChutesDefaultAllowFail` | **No** | **Yes** |

NearCloud and Chutes both support E2EE and have it enabled by default in
config. Having `e2ee_usable` enforced for them triggers P1, while Venice
(also E2EE-enabled by default) doesn't have this problem because
`e2ee_usable` is in the default allow_fail list.

---

## E2EE Relay Error Handling (current state)

When E2EE is active and decryption fails in the relay functions, the current
behavior is:

- **Streaming** (`RelayStream`/`relaySSELine` in `internal/e2ee/relay.go`):
  Writes an SSE error event `{"error":{"message":"stream decryption failed",
  "type":"decryption_error"}}` and ends the stream. The HTTP 200 status has
  already been sent, so no status code change is possible. Now returns
  `StreamStats` (since `04f47db`).

- **Non-streaming** (`RelayReassembledNonStream` in `internal/e2ee/relay.go`):
  Returns HTTP 502 "response decryption failed". Now returns `StreamStats`
  (since `04f47db`). `ReassembleNonStream` returns `([]byte, StreamStats, error)`.

- **Chutes streaming** (`RelayStreamChutes` in
  `internal/e2ee/relay_chutes.go`): Uses the extracted `writeStreamError`
  helper (since `eba0cf3`): returns HTTP 502 if failure occurs before first
  chunk; writes SSE error event via `WriteSSEError` if after headers.
  Unparseable SSE events now **abort the stream** (was `continue` —
  security audit fix in `eba0cf3`). Logs `data_len` instead of raw event
  data. Init and chunk processing extracted into `handleChutesInit` and
  `handleChutesChunk` helpers (since `c870285`). Returns `StreamStats`.

- **Chutes non-streaming** (`RelayNonStreamChutes`): Returns HTTP 502
  "response decryption failed".

**Key observation**: None of these paths currently invalidate the cached report
or prevent future requests. A decryption failure is treated as a transient
error for the current request only.

**Progress toward step 3**: Relay functions now return `StreamStats` (since
`04f47db`), which is a structural prerequisite for returning `error`.
`StreamStats` has `Chunks`, `Tokens`, and `Duration` fields; adding an
`Error` field or changing the return to `(StreamStats, error)` is the
remaining work.

### Chutes Instance Retry Loop (current state)

The Chutes-specific retry loop (`chutesMaxAttempts = 3`) now lives in
the extracted `doUpstreamRoundtrip` function (line 1137, since `c870285`),
rather than inline in `handleChatCompletions`. It wraps the
body-build → upstream-request cycle. It handles **transport-level** failures
(connection errors, HTTP 429/500-504) by marking the failed instance via
`NoncePool.MarkFailed(chuteID, instanceID)`, zeroing crypto material via
`zeroE2EESessions`, and retrying with a fresh nonce/key from a different
instance.

`doUpstreamRoundtrip` returns `(*upstreamResult, error)`. The `upstreamResult`
struct (line 1125) carries `Resp`, `Session`, `Meta`, `Cancel`, `E2EEDur`,
and `UpstreamDur`. On error it returns an `httpError` (line 1114) with a
`status` field that distinguishes E2EE preparation errors (`"e2ee_failed"`,
HTTP 500) from transport errors (`"upstream_failed"`, HTTP 502). The caller
(`handleChatCompletions`) maps these to different client messages:
`"failed to prepare encrypted request"` vs `"upstream request failed"`
(since `f598a06`).

`buildUpstreamBody` (line 1273) returns an `upstreamBody` struct (line 181)
that carries `Body`, `Session`, `Meta`, `ChuteID`, and `InstanceID`. The
`ChuteID`/`InstanceID` fields are populated from the raw attestation (or
nonce pool) and are independent of `meta.Session` being populated — this
decoupling allows the retry loop to track instances for `MarkFailed` even
when the encryptor returns `meta == nil` (e.g. in tests or non-E2EE paths).

This is distinct from the plan's post-relay enforcement (step 4), which
covers **cryptographic** failures (decryption failed after a successful HTTP
response). The retry loop runs *before* the relay; post-relay enforcement
runs *after* it.

**Hazard — escalation gap**: When all 3 retry attempts fail, the current
implementation returns an `httpError` with `"upstream_failed"` status.
Per-instance `MarkFailed` now fires on every retryable failure including the
final attempt (within `doUpstreamRoundtrip`), so the nonce pool correctly
deprioritizes all failed instances on subsequent requests. However, the
provider+model pair is NOT marked as persistently failed — the next
request will still retry from scratch. Once the E2EE state machine
(long-term step 1) is implemented, retry exhaustion should escalate to
`E2EETracker.MarkFailed(provider, model)` with full cache invalidation.
See "Nonce pool failure escalation" in Future Considerations.

**Hazard — retry + decryption failure interaction**: If the retry loop
succeeds on the last attempt (transport OK) but the relay then detects a
decryption failure, the plan's step 4 post-relay enforcement must still
fire using the *last successful attempt's* instance info for the
`MarkFailed` / `Invalidate` call. Instance info is available via
`attemptChuteID` / `attemptInstanceID` (from the `upstreamBody` struct),
not from `meta`.

**Safeguard — pre-relay session guard**: A fail-closed check
(`meta != nil && meta.Session == nil`) runs in `handleChatCompletions`
*before* the relay dispatch switch (line ~841). This catches a different
class of failure than post-relay enforcement: if Chutes E2EE metadata
was populated (meta is non-nil) but key encapsulation failed to produce
a session, the guard returns HTTP 500 instead of forwarding ciphertext
as plaintext. Error counters (`s.stats.errors`, `ms.errors`) and
`slog.ErrorContext` are incremented. This is complementary to post-relay
enforcement — it catches pre-relay invariant violations, while step 4
catches post-relay cryptographic failures.

**Safeguard — pinned E2EE nil report block**: The pinned (NearCloud) path
now blocks when `prov.E2EE && report == nil` (since `eba0cf3`, line ~932).
Without a report, the signing key cannot be verified as bound to the TDX
quote, so E2EE would degrade to plaintext. This records a negative cache
entry and returns HTTP 502.

---

## Short-Term Plan: Enforce E2EE at relay, not at report

Keep `e2ee_usable` as a report factor but make it always allowed-to-fail
(informational). Move E2EE correctness enforcement to the relay layer.

### Design

The key insight from the PR #33 discussion is: "We always send encrypted
requests when E2EEConfigured=True. We don't want to allow this factor to
fail for reports, and if the proxy ever receives unencrypted responses back
… we stop accepting further inference and return an error."

This means `e2ee_usable` as a blocking factor at report-build time is the
wrong enforcement point. Instead:

- When `prov.E2EE && ReportDataBindingPassed()`, the proxy always encrypts.
- If decryption fails on the response, block the response AND future requests.
- `e2ee_usable` in the report becomes a status indicator, not a gate.

### Changes required

1. ~~**Add `e2ee_usable` to all provider allow_fail lists**~~: **DONE** (`3eaa490`)
   — Added to `NearcloudDefaultAllowFail` and `ChutesDefaultAllowFail`
   with TODO comments explaining the chicken-and-egg problem.

2. **Add E2EE failure tracking**: `internal/proxy/proxy.go`
   - Add a per-provider/model E2EE failure flag to the `Server` struct.
     This can be a simple concurrent map: `e2eeFailed sync.Map` keyed by
     `cacheKey{provider, model}`.
   - In `handleChatCompletions`, after `enforceReport` (line 1069), if
     `e2eeFailed.Load(key)` returns true, return 502 with a message like
     "E2EE previously failed; re-attestation required".
   - **Partial progress** (`f598a06`): `doUpstreamRoundtrip` already
     classifies errors via `httpError.status` (`"e2ee_failed"` for
     build/prep errors, `"upstream_failed"` for transport errors), and
     `handleChatCompletions` maps these to distinct client messages. The
     remaining work is to persist these classifications across requests
     via the `e2eeFailed` map.

3. **Relay error detection**: `internal/e2ee/relay.go` and
   `internal/e2ee/relay_chutes.go`
   - Modify relay functions to return `error` (nil on success, non-nil on
     decryption failure). The current signatures return `StreamStats`
     (since `04f47db`) but not `error`; changing to `(StreamStats, error)`
     is straightforward. Callers already handle the `StreamStats` return
     via `relayResponse` (line 1092), which would propagate the error up.

4. **Post-relay enforcement**: `internal/proxy/proxy.go`
   `handleChatCompletions` (after the `relayResponse` call at line ~848)
   - After the relay call, if error indicates decryption failure AND
     `e2eeActive` was true:
     ```go
     s.e2eeFailed.Store(cacheKey{prov.Name, upstreamModel}, true)
     s.cache.Delete(prov.Name, upstreamModel)
     s.signingKeyCache.Delete(prov.Name, upstreamModel)
     // Chutes nonce pool: discard cached instances/nonces for this chute.
     // attemptChuteID comes from upstreamBody struct, not meta.
     if prov.E2EEMaterialFetcher != nil {
         prov.E2EEMaterialFetcher.Invalidate(attemptChuteID)
     }
     // Zero crypto material from the current session.
     zeroE2EESessions(session, meta)
     // Increment error counters so monitoring captures this failure.
     s.stats.errors.Add(1)
     if ms != nil {
         ms.errors.Add(1)
     }
     ```
   - Note: the nonce pool (`E2EEMaterialFetcher`) is a third cache alongside
     the report cache and signing key cache. All three must be invalidated
     together on E2EE failure to prevent serving cached nonces from a
     compromised or broken instance.
   - Note: by this point the (possibly corrupted) response has already been
     written to the client. For streaming, the HTTP 200 was sent with the
     first chunk. This is unavoidable without buffering the entire response.
     The enforcement is *forward-looking*: block the next request.
   - Note: this enforcement is distinct from the Chutes retry loop, which
     handles transport-level failures *before* the relay. Post-relay
     enforcement catches cryptographic failures (e.g. decryption failure
     after HTTP 200) that indicate a more severe problem (possible MITM
     or server-side E2EE breakage). See "Chutes Instance Retry Loop
     (current state)" section above for the full picture.

5. **Keep `MarkE2EEUsable` but fix it**: `internal/attestation/report.go`
   - Since `e2ee_usable` is now always allowed-to-fail, it will stay `Skip`
     (not promoted to `Fail`). `MarkE2EEUsable`'s guard
     `Status == Skip` will always be safe.
   - Underflow guard added (`e4b075c`): `Skipped > 0` check with
     `slog.Warn` on desync. **Partial fix** — full counter recomputation
     (S2) and report cloning (S1) still needed.
   - Still fix the cache mutation race (see S1 below).
   - Still fix counter consistency (see S2 below).

6. **Report endpoint**: No change needed. `e2ee_usable` remains in the
   factor list as informational. After first successful roundtrip, it shows
   as `Pass`.

7. **Integration tests**: `internal/proxy/integration_*_test.go`
   - No change to assertions — `e2ee_usable` will still transition to `Pass`
     after a successful roundtrip (via `MarkE2EEUsable` on the cloned
     report).
   - The tests work today because the first chat request succeeds and
     promotes the factor before the report is fetched.

8. **Cache `Delete` method**: `internal/attestation/attestation.go`
   - Add a `Delete(provider, model)` method to the report cache if one
     doesn't exist. Same for `SigningKeyCache`.

### Shared fixes (apply to short-term plan)

#### S1: Cache mutation race

**Status**: Documented with TODO comments (`6de38de`). **Not yet fixed.**

**Problem**: `MarkE2EEUsable` (and the subsequent `cache.Put`) mutates a
shared `*VerificationReport` pointer.

**Fix**: Clone the report before mutating. Apply in both non-pinned
(line 852) and pinned (line 994) paths.

```go
// Deep-copy report before mutation.
func cloneReport(src *VerificationReport) *VerificationReport {
    if src == nil {
        return nil
    }
    dst := *src
    dst.Factors = make([]FactorResult, len(src.Factors))
    copy(dst.Factors, src.Factors)
    // Metadata map: shallow copy is sufficient (values are strings).
    if src.Metadata != nil {
        dst.Metadata = make(map[string]string, len(src.Metadata))
        for k, v := range src.Metadata {
            dst.Metadata[k] = v
        }
    }
    return &dst
}
```

Usage:
```go
if e2eeActive {
    cloned := cloneReport(report)
    cloned.MarkE2EEUsable("E2EE roundtrip succeeded via proxy")
    s.cache.Put(prov.Name, upstreamModel, cloned)
}
```

**Files**: `internal/proxy/proxy.go`, `internal/attestation/report.go` (add
`cloneReport` or a `Clone` method on `VerificationReport`).

#### S2: Counter recomputation

**Status**: Partial fix (`e4b075c`) — added `Skipped > 0` guard with
`slog.Warn` to prevent underflow. **Full recomputation not yet implemented.**

**Problem**: `MarkE2EEUsable` manually adjusts `Passed` and `Skipped`
counters. This is fragile — if the factor status is unexpected, counters
desync.

**Fix**: Replace manual counter adjustment with a recomputation:

```go
func (r *VerificationReport) MarkE2EEUsable(detail string) {
    for i := range r.Factors {
        if r.Factors[i].Name == "e2ee_usable" {
            if r.Factors[i].Status == Skip {
                r.Factors[i].Status = Pass
                r.Factors[i].Detail = detail
                r.recomputeCounters()
            }
            return
        }
    }
}

func (r *VerificationReport) recomputeCounters() {
    passed, failed, skipped := 0, 0, 0
    enforcedFailed, allowedFailed := 0, 0
    for _, f := range r.Factors {
        switch f.Status {
        case Pass:
            passed++
        case Fail:
            failed++
            if f.Enforced {
                enforcedFailed++
            } else {
                allowedFailed++
            }
        case Skip:
            skipped++
        }
    }
    r.Passed = passed
    r.Failed = failed
    r.Skipped = skipped
    r.EnforcedFailed = enforcedFailed
    r.AllowedFailed = allowedFailed
}
```

**Files**: `internal/attestation/report.go`

#### S3: Chutes URL validation

**Status**: **DONE** (`2ac5f5a`). Validation added in `PrepareRequest`
after `url.Parse`: rejects URLs with empty `Scheme` or `Host`. Unit test
`TestPreparer_RejectsInvalidAPIBaseURL` covers empty, no-scheme, and
path-only cases.

**File**: `internal/provider/chutes/chutes.go`

#### S4: ChuteID fallback

**Status**: **DONE** (`a9850b9`). `testE2EEChutes` now returns an error
when `raw.ChuteID` is empty instead of falling back to `model`. Unit test
`TestTestE2EEChutes_MissingChuteID` covers this.

**File**: `cmd/teep/main.go` `testE2EEChutes`

### Short-term remaining work

S3–S4 are done. S1 and S2 have partial fixes (TODOs and underflow guard).
The cyclomatic complexity refactor (`c870285`) extracted the key functions
that remaining steps plug into. The remaining short-term work is:

1. **S1 full fix**: Clone report before `MarkE2EEUsable` mutation (both
   non-pinned at line 852 and pinned at line 994).
2. **S2 full fix**: Replace manual counter adjustment with `recomputeCounters`.
3. **Step 2 full fix**: Add `e2eeFailed sync.Map` to `Server` struct;
   check it in `handleChatCompletions` after `enforceReport` (line 1069).
   `httpError.status` already classifies E2EE vs transport errors; persist
   this across requests.
4. **Step 3**: Change relay functions from returning `StreamStats` to
   `(StreamStats, error)`. `relayResponse` (line 1092) propagates the new
   return to `handleChatCompletions`.
5. **Step 4**: Post-relay enforcement — mark failed, invalidate caches.
   The `doUpstreamRoundtrip` / `handleChatCompletions` split (since
   `c870285`) means this logic goes in `handleChatCompletions` after the
   `relayResponse` call.
6. **Step 8**: Add `Delete` method to report cache and signing key cache.

### Short-term tradeoffs

- **Pro**: Minimal refactor. `e2ee_usable` remains a factor with the same
  name and semantics — just no longer enforced at the report level.
- **Pro**: Runtime enforcement at the relay layer checks actual behavior
  (did decryption actually work?) rather than a cached test result.
- **Pro**: Matches the stated ideal behavior: "always send encrypted; block
  on decryption failure."
- **Pro**: Venice, NearCloud, and Chutes all get consistent behavior without
  per-provider exceptions.
- **Con**: `e2ee_usable` becomes informational — a user looking at the report
  could see all factors "passed" while E2EE has silently failed (if the
  failure happens between report cache and next request).
- **Con**: Still requires fixing the cache mutation race (S1) for the
  informational `MarkE2EEUsable` call to be correct.
- **Con**: For streaming responses, the first decryption failure is already
  partially relayed to the client. Enforcement is forward-looking only.
- **Con**: The relay signature change (returning `error` alongside `StreamStats`)
  is still needed.

---

## Long-Term Plan: Two-tier report with E2EE state machine

The long-term design cleanly separates two concerns that the current
architecture conflates:

1. **Attestation Validation** — cryptographic verification of the TEE
   environment (TDX quote, NVIDIA GPU attestation, container measurements,
   Sigstore/Rekor transparency, data binding). These factors determine
   whether a request should be forwarded. They are evaluated once at
   attestation time and produce an immutable report. This is the existing
   factor system.

2. **Provider Functionality** — live verification that provider features
   work as expected (E2EE roundtrip, future tool call tests). These require
   an actual inference roundtrip and cannot be evaluated at attestation time.
   In the proxy, they are enforced at the relay layer. In `teep verify`,
   they are evaluated via probe requests and displayed in a separate
   "Provider Functionality" tier of the report.

### Architecture overview

```
teep serve (proxy)                    teep verify (CLI)
──────────────────                    ─────────────────

Attestation factors                   Attestation factors
  → BuildReport()                       → BuildReport()
  → immutable VerificationReport        → immutable VerificationReport
  → Blocked() gates requests            → displayed in Attestation Tier

E2EE state machine                    E2EE probe
  → per-provider/model tracker          → testE2EE() probe request
  → Pending → Active → Failed          → result displayed in Functionality Tier
  → enforced at relay layer             → NOT passed to BuildReport
  → exposed in report metadata          → separate section in formatReport()
```

The proxy never runs an E2EE probe. It tracks E2EE state via the actual
relay lifecycle. `teep verify` runs an explicit probe and displays the
result. In both cases, `e2ee_usable` is **not** an attestation factor —
it does not participate in `BuildReport`, `Blocked()`, or the `allow_fail`
system.

### E2EE state machine (proxy only)

Per provider+model pair:

```
                     ┌─────────┐
                     │ Pending │  (E2EE configured, not yet tested)
                     └────┬────┘
                          │ first successful encrypted roundtrip
                          ▼
                     ┌─────────┐
                     │ Active  │  (E2EE verified working)
                     └────┬────┘
                          │ decryption failure on response
                          ▼
                     ┌─────────┐
                     │ Failed  │  (block all subsequent requests)
                     └─────────┘
```

- **Pending**: Provider has `E2EE=true` in config. The proxy encrypts
  outgoing requests when `ReportDataBindingPassed()`. If the roundtrip
  succeeds, transition to `Active`.
- **Active**: E2EE has been verified working. Continue encrypting.
- **Failed**: A previously-working E2EE roundtrip returned data that could
  not be decrypted. This indicates either a key mismatch (possible MITM) or
  server-side E2EE breakage. **Block all subsequent requests** for this
  provider+model (fail-closed). Invalidate the report cache entry and signing
  key cache entry. Require full re-attestation to recover.

### `teep verify` E2EE probe

`teep verify` continues to run provider-specific E2EE test functions
(`testE2EEVenice`, `testE2EENearCloud`, `testE2EEChutes`) as it does today.
The difference is that the result is no longer fed into `BuildReport` as
`E2EETest`. Instead, it is displayed in a separate "Provider Functionality"
section of the report output, visually distinct from the attestation factor
table.

Example `teep verify` output:

```
Attestation Validation
──────────────────────
  ✓ tdx_quote          TDX quote signature valid
  ✓ gpu_attestation    NVIDIA EAT token verified
  ✓ container_hash     Matches allowed measurement
  ✓ data_binding       Signing key bound to TDX report
  ✓ sigstore           Rekor log entry verified
  ...

  12 passed, 0 failed, 0 skipped

Provider Functionality
──────────────────────
  ✓ e2ee_usable        E2EE roundtrip succeeded (streaming + non-streaming)
```

This makes the distinction clear: attestation factors determine whether the
provider's TEE environment is trustworthy. Provider functionality tests
verify that features work correctly through the attested environment.

### Changes required

1. **New file**: `internal/proxy/e2ee_state.go`
   - Define `E2EEState` type with `Pending`/`Active`/`Failed` constants.
   - Define `E2EETracker` struct: concurrent-safe map of `cacheKey{provider,
     model}` → `E2EEState`. Methods: `Get`, `MarkActive`, `MarkFailed`.
   - Add `E2EETracker` field to `Server` struct in `internal/proxy/proxy.go`.

2. **Remove `e2ee_usable` from the factor system**: `internal/attestation/report.go`
   - Remove `evalE2EEUsable` from the evaluator list returned by
     `buildEvaluators()`.
   - Remove `e2ee_usable` from `KnownFactors`, `DefaultAllowFail`,
     `NearcloudDefaultAllowFail`, `NeardirectDefaultAllowFail`,
     `ChutesDefaultAllowFail`, and `OnlineFactors`.
   - Delete the `MarkE2EEUsable` method. This eliminates P2 and P3 entirely.
   - Delete the `E2EEConfigured` field from `ReportInput`.
   - Delete the `E2EETest` field from `ReportInput` and the
     `E2EETestResult` type (if no longer needed), or keep
     `E2EETestResult` as a standalone type for the verify path.

3. **Proxy non-pinned path**: `internal/proxy/proxy.go` `handleChatCompletions`
   - After `enforceReport` (line 1069), add E2EE state check:
     if `e2eeTracker.Get(prov.Name, model) == Failed`, block with 502.
   - After successful relay (line ~848, via `relayResponse` at line 1092),
     call `e2eeTracker.MarkActive(prov.Name, model)`.
   - Remove all `MarkE2EEUsable` calls (line 852 non-pinned, line 994 pinned).
   - Remove `E2EEConfigured` and `E2EETest` from `ReportInput` construction.

4. **Relay error propagation**: `internal/e2ee/relay.go` and
   `internal/e2ee/relay_chutes.go`
   - Change relay functions from returning `StreamStats` to
     `(StreamStats, error)` indicating whether decryption failed. The
     `relayResponse` helper (line 1092) dispatches to all relay functions
     and would propagate the error to `handleChatCompletions`.
   - In `handleChatCompletions`, if the relay reports a decryption failure
     AND E2EE was active, call `e2eeTracker.MarkFailed(prov.Name, model)`
     and `s.cache.Delete(prov.Name, model)` and
     `s.signingKeyCache.Delete(prov.Name, model)`.
   - For Chutes (or any provider with `E2EEMaterialFetcher`), also call
     `prov.E2EEMaterialFetcher.Invalidate(chuteID)` to discard cached
     nonces. The nonce pool is a third cache that must be invalidated
     alongside the report cache and signing key cache.
   - Note: `doUpstreamRoundtrip` (line 1137) already handles pre-relay
     errors including E2EE prep failures. Post-relay enforcement in
     `handleChatCompletions` handles the complementary case of
     cryptographic failure after a successful HTTP response.

5. **Report endpoint**: `internal/proxy/proxy.go` report handler
   - Include E2EE state (Pending/Active/Failed) in the JSON report as a
     metadata field, e.g. `"e2ee_status": "active"`.
   - The report endpoint code that serves `/v1/tee/report` currently
     returns the cached `VerificationReport` directly. Add the E2EE status
     to the `Metadata` map before serializing (on a clone, not in-place).

6. **Verify path**: `cmd/teep/main.go`
   - Keep `testE2EE()` and all provider-specific E2EE test functions.
   - Remove `E2EETest` from the `ReportInput` passed to `BuildReport`.
   - Display the E2EE test result in a separate "Provider Functionality"
     section of `formatReport()`, after the attestation factor table.
   - The functionality section should use the same pass/fail/skip
     iconography as the factor table but be clearly labeled as a distinct
     tier.

7. **Shared E2EE probe functions** (optional cleanup): `internal/e2ee/probe.go`
   - Factor out the core E2EE test logic from `cmd/teep/main.go` into a
     shared package. This is good hygiene but not strictly required since
     only `teep verify` runs probes.
   - `ProbeVenice(ctx, signingKey, apiKey, baseURL, model) error`
   - `ProbeNearCloud(ctx, signingKey, apiKey, baseURL, model) error`
   - `ProbeChutes(ctx, raw, apiKey, baseURL, model) error`
   - Currently `testE2EEVenice` is in `cmd/teep/main.go` ~line 682,
     `testE2EENearCloud` ~line 724, `testE2EEChutes` ~line 761.
   - Note: `testE2EE`'s stream validation logic (`doE2EEStreamTest`,
     `doE2EEChutesStreamTest`) is thorough and tests both streaming and
     non-streaming paths. This thoroughness is appropriate for the verify
     command since it runs once per invocation, unlike a proxy probe which
     would add latency to every request.

8. **Integration tests**: Update `internal/proxy/integration_*_test.go`
   - Remove assertions that `e2ee_usable` factor is `Pass`.
   - Instead, check the report's `Metadata["e2ee_status"]` is `"active"`
     after a successful E2EE roundtrip.

9. **Config validation**: `internal/config/config.go`
   - Remove `e2ee_usable` from being a valid `allow_fail` entry. Reject
     unknown factor names at config load time (no backwards-compatible
     no-ops).

10. **Cache `Delete` method**: `internal/attestation/attestation.go`
    - Add a `Delete(provider, model)` method to the report cache if one
      doesn't exist. Same for `SigningKeyCache`.

11. **Unit tests**:
    - `internal/attestation/report_test.go`: Remove `TestMarkE2EEUsable`
      tests and `e2ee_usable` from factor evaluation tests.
    - `internal/proxy/e2ee_state_test.go`: Add tests for the new
      `E2EETracker` (state transitions, concurrent access, fail-closed
      behavior).
    - `cmd/teep/`: Update verify output tests to expect the two-tier
      report format.

### Tradeoffs

- **Pro**: Cleanest separation of concerns. Attestation factors are
  immutable after `BuildReport` — no report mutation, no counter desync, no
  cache race (eliminates P2, P3, and the need for S1/S2 entirely).
- **Pro**: Eliminates the chicken-and-egg problem permanently (P1). The
  proxy never needs to evaluate `e2ee_usable` before an inference roundtrip.
- **Pro**: E2EE failure triggers fail-closed at the right layer — after
  observing actual decryption failure, not at report-build time.
- **Pro**: Unified behavior across all providers (eliminates P5). No
  per-provider `allow_fail` exceptions for `e2ee_usable`.
- **Pro**: `teep verify` still displays `e2ee_usable` via a probe, giving
  operators full visibility into provider functionality without conflating
  it with attestation validation.
- **Pro**: The two-tier report format scales naturally to future live-test
  checks (e.g. tool call test factor) that face the same chicken-and-egg
  problem.
- **Con**: Most invasive change when migrating from the short-term plan.
  Touches relay function signatures, report format, config validation, and
  `teep verify` output formatting.
- **Con**: External tools that parse `e2ee_usable` from the report's
  `Factors` JSON array will need to look in `Metadata["e2ee_status"]`
  instead (proxy) or parse the new functionality tier (verify).
- **Con**: New E2EE state machine is another concurrent data structure to
  maintain alongside the report cache and signing key cache.

---

## Future considerations

- **Tool call test factor**: A forthcoming factor that tests whether tool
  calls work through the E2EE path. It will face the same chicken-and-egg
  problem as `e2ee_usable`. Under the long-term plan, it belongs in the
  Provider Functionality tier alongside `e2ee_usable`, not in the
  attestation factor system.
- **E2EE key rotation**: When a signing key rotates (VM restart), the proxy
  logs a warning but continues. The E2EE state machine should reset state to
  `Pending` on key rotation, requiring re-verification of the E2EE path
  with the new key.
- **Report cache TTL vs E2EE state**: The report cache has a 5-minute TTL.
  Since E2EE state is tracked independently of the report cache in the
  long-term plan, the E2EE state persists across report cache misses. A
  cache miss triggers re-attestation but does not reset E2EE state.
- **Client-facing E2EE status**: Consider adding an `X-Teep-E2EE` response
  header so clients can verify E2EE was used for each request without
  fetching the full report.
- **Nonce pool failure escalation**: The Chutes `NoncePool` tracks
  per-instance failure counts via `MarkFailed` and prefers instances with
  fewer failures. The Chutes retry loop (`chutesMaxAttempts = 3` in
  `doUpstreamRoundtrip`, line 1137) is the concrete location where
  escalation should occur. Two open design questions:
  1. When all retry attempts exhaust for a single request, should this
     immediately escalate to `E2EETracker.MarkFailed` (fail-closed for
     the provider+model), or should it allow subsequent requests to retry
     independently? The current implementation allows independent retry.
  2. When all instances in the nonce pool have accumulated failures (across
     multiple requests), should the pool itself signal "no healthy instances"
     back to the proxy for escalation? Currently `Take` returns an error
     only when no nonces remain, not when all instances are unhealthy.
  The escalation threshold and recovery path (full re-attestation) should
  be specified when the E2EE state machine is implemented.
- **Crypto material lifecycle in retry**: `zeroE2EESessions` in
  `internal/proxy/proxy.go` (line 190) is the canonical helper for zeroing
  E2EE crypto material between retry attempts. It is called at four points
  in `doUpstreamRoundtrip` (lines 1200, 1208, 1233, 1248) covering all
  error and retry paths. The plan's step 4 (post-relay enforcement) and
  S1 (cache mutation race) should use the same pattern when invalidating
  material after decryption failure.
