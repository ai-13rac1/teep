# Plan: Refactoring `e2ee_usable` Factor Enforcement

## Background

PR #33 ("Make chutes E2EE work; also add api integration tests") surfaced
fundamental architectural issues with how the `e2ee_usable` report factor
interacts with the proxy's request-blocking mechanism, the report cache, and
integration tests. The PR author's review replies confirm these are known
problems requiring a dedicated redesign rather than point fixes.

This document describes the problems, presents three implementation options,
and lists shared fixes that apply regardless of which option is chosen.

---

## Progress

The following work has been completed on the `chutes_integrity` branch as
part of PR #33 review fixes:

| Commit | Description | Plan item |
|--------|-------------|-----------|
| `3eaa490` | Add `e2ee_usable` to `ChutesDefaultAllowFail` and `NearcloudDefaultAllowFail` | Option C step 1 |
| `e4b075c` | Guard `MarkE2EEUsable` against `Skipped` counter underflow; add `slog.Warn` | S2 (partial) |
| `6de38de` | Document cache mutation race with TODO comments at both `MarkE2EEUsable` call sites | S1 (documented, not yet fixed) |
| `2ac5f5a` | Validate Chutes `apiBaseURL` has scheme and host before E2EE URL rewrite | S3 (done) |
| `a9850b9` | Require `ChuteID` in `testE2EEChutes` instead of falling back to model name | S4 (done) |

These commits resolve P1 (chicken-and-egg blocking) by making `e2ee_usable`
allowed-to-fail for all providers. The remaining Option C work (steps 2–4,
6–8 and the full S1/S2 fixes) is described below.

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
1. `handleChatCompletions` calls `fetchAndVerify` on cache miss
   (`internal/proxy/proxy.go` ~line 605)
2. `fetchAndVerify` calls `BuildReport` with `E2EEConfigured: prov.E2EE`
   and `E2EETest: nil` (~line 520)
3. `evalE2EEUsable` returns `Skip "E2EE configured; pending live test"`
   (`internal/attestation/report.go` ~line 869)
4. `BuildReport` promotes enforced `Skip` → `Fail (enforced)` (~line 380)
5. `report.Blocked()` returns `true` → request rejected (~line 617)
6. `MarkE2EEUsable` is never reached (~line 734)

**Code path** (proxy pinned, NearCloud):
Same issue: the report is built with `E2EEConfigured=true` and `E2EETest=nil`
inside the pinned handler's attestation path. `Blocked()` fires before the
E2EE relay at ~line 810.

### P2: Cache mutation race

`MarkE2EEUsable()` mutates the `*VerificationReport` pointer stored in the
cache in-place. The cache's `Get()` returns the same pointer to all concurrent
callers. This means:

- Two concurrent requests for the same provider/model can race on
  `MarkE2EEUsable`, observing a half-mutated `Factors` slice.
- The `/v1/tee/report` endpoint can read the report mid-mutation.
- `report.Passed++` and `report.Skipped--` are non-atomic int mutations.

**Locations**:
- Non-pinned path: `internal/proxy/proxy.go` ~line 734
- Pinned path: `internal/proxy/proxy.go` ~line 873

### P3: Counter desync risk

`MarkE2EEUsable()` manually adjusts `Passed` and `Skipped` counters
(`internal/attestation/report.go` ~line 116-127):

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
- `fetchAndVerify` passes `E2EETest: nil, E2EEConfigured: prov.E2EE` to
  `BuildReport`
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

Understanding how relay functions currently handle errors is important
context for the options below.

When E2EE is active and decryption fails in the relay functions, the current
behavior is:

- **Streaming** (`RelayStream`/`relaySSELine` in `internal/e2ee/relay.go`):
  Writes an SSE error event `{"error":{"message":"stream decryption failed",
  "type":"decryption_error"}}` and ends the stream. The HTTP 200 status has
  already been sent, so no status code change is possible.

- **Non-streaming** (`RelayReassembledNonStream` in `internal/e2ee/relay.go`):
  Returns HTTP 502 "response decryption failed".

- **Chutes streaming** (`RelayStreamChutes` in
  `internal/e2ee/relay_chutes.go`): Returns HTTP 502 if failure occurs before
  first chunk; writes SSE error event via `WriteSSEError` if after headers.

- **Chutes non-streaming** (`RelayNonStreamChutes`): Returns HTTP 502
  "response decryption failed".

**Key observation**: None of these paths currently invalidate the cached report
or prevent future requests. A decryption failure is treated as a transient
error for the current request only.

---

## Option A: Separate E2EE into a distinct lifecycle

Remove `e2ee_usable` from the report factor system entirely. Track E2EE
state as an independent per-provider/model state machine in the proxy.

### Design

**E2EE state machine** (per provider+model pair):

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

### Changes required

1. **New file**: `internal/proxy/e2ee_state.go`
   - Define `E2EEState` type with `Pending`/`Active`/`Failed` constants.
   - Define `E2EETracker` struct: concurrent-safe map of `cacheKey{provider,
     model}` → `E2EEState`. Methods: `Get`, `MarkActive`, `MarkFailed`.
   - Add `E2EETracker` field to `Server` struct in `internal/proxy/proxy.go`.

2. **Remove factor**: `internal/attestation/report.go`
   - Remove `evalE2EEUsable` from the evaluator list returned by
     `buildEvaluators()`.
   - Remove `e2ee_usable` from `KnownFactors`, `DefaultAllowFail`,
     `NearcloudDefaultAllowFail`, `NeardirectDefaultAllowFail`,
     `ChutesDefaultAllowFail`, and `OnlineFactors`.
   - Delete the `MarkE2EEUsable` method.
   - Delete the `E2EEConfigured` field from `ReportInput`.
   - Keep `E2EETest` and the `E2EETestResult` type for the verify path, but
     move the result into report `Metadata` instead of a factor.

3. **Proxy non-pinned path**: `internal/proxy/proxy.go` `handleChatCompletions`
   - After `report.Blocked()` check (~line 617), add E2EE state check:
     if `e2eeTracker.Get(prov.Name, model) == Failed`, block with 502.
   - After successful relay (~line 733), call
     `e2eeTracker.MarkActive(prov.Name, model)`.
   - Remove `MarkE2EEUsable` calls.

4. **Relay error propagation**: `internal/e2ee/relay.go` and
   `internal/e2ee/relay_chutes.go`
   - Change relay functions to return an error (or a status) indicating
     whether decryption failed. Currently they write directly to
     `http.ResponseWriter` and return nothing.
   - In `handleChatCompletions`, if the relay reports a decryption failure
     AND E2EE was active, call `e2eeTracker.MarkFailed(prov.Name, model)`
     and `s.cache.Delete(prov.Name, model)` and
     `s.signingKeyCache.Delete(prov.Name, model)`.

5. **Report endpoint**: `internal/proxy/proxy.go` report handler
   - Include E2EE state (Pending/Active/Failed) in the JSON report as a
     metadata field, e.g. `"e2ee_status": "active"`.
   - The report endpoint code that serves `/v1/tee/report` currently
     returns the cached `VerificationReport` directly. Add the E2EE status
     to the `Metadata` map before serializing (on a clone, not in-place).

6. **Verify path**: `cmd/teep/main.go`
   - Keep `testE2EE()` and provider-specific test functions.
   - Instead of passing `E2EETest` to `BuildReport`, display the E2EE test
     result in a separate section of `formatReport()`, after the factor
     table.
   - Remove `E2EETest` from `ReportInput` or repurpose it as metadata-only.

7. **Integration tests**: Update `internal/proxy/integration_*_test.go`
   - Remove assertions that `e2ee_usable` factor is `Pass`.
   - Instead, check the report's `Metadata["e2ee_status"]` is `"active"`
     after a successful E2EE roundtrip.

8. **Config validation**: `internal/config/config.go`
   - Remove `e2ee_usable` from being a valid `allow_fail` entry (or keep it
     as a no-op for backwards compatibility with existing config files).

9. **Unit tests**: `internal/attestation/report_test.go`
   - Remove `TestMarkE2EEUsable` tests.
   - Remove `e2ee_usable` from factor evaluation tests.
   - Add tests for the new `E2EETracker`.

### Tradeoffs

- **Pro**: Cleanest separation; eliminates chicken-and-egg; no report mutation;
  no counter desync; unified behavior across providers.
- **Pro**: E2EE failure triggers fail-closed at the right layer (after
  observing actual decryption failure, not at report-build time).
- **Con**: Most invasive change. Touches relay function signatures (currently
  `void`), report format (removes a known factor), and config validation.
- **Con**: External tools that parse `e2ee_usable` from the report JSON will
  break.
- **Con**: New state machine is another concurrent data structure to maintain
  alongside the report cache and signing key cache.

---

## Option B: Pre-flight E2EE probe during attestation

Run a lightweight E2EE test during `fetchAndVerify`, before the report is
cached. This populates `E2EETest` in `ReportInput`, matching what
`teep verify` does.

### Design

After `fetchAndVerify` completes attestation verification and before calling
`BuildReport`, execute a probe: encrypt a minimal test payload with the
provider's E2EE protocol, send it to the provider, and validate the encrypted
response can be decrypted. If the probe succeeds, `E2EETest.Attempted=true`
and `e2ee_usable=Pass` from the start. If it fails, `E2EETest.Err` is set
and `e2ee_usable=Fail` — enforcement can block immediately.

### Changes required

1. **Probe functions**: Factor out the core E2EE test logic from
   `cmd/teep/main.go` into a shared package (e.g. `internal/e2ee/probe.go`).
   - `ProbeVenice(ctx, signingKey, apiKey, baseURL, model) error`
   - `ProbeNearCloud(ctx, signingKey, apiKey, baseURL, model) error`
   - `ProbeChutes(ctx, raw, apiKey, baseURL, model) error`
   - Each function encrypts a minimal message ("test"), sends it, reads the
     response, and validates decryption succeeds.
   - Currently `testE2EEVenice` is in `cmd/teep/main.go` ~line 682,
     `testE2EENearCloud` ~line 724, `testE2EEChutes` ~line 761. These would
     be moved or refactored so both `teep verify` and the proxy call the
     same underlying probe.

2. **Proxy `fetchAndVerify`**: `internal/proxy/proxy.go` ~line 370-525
   - After all attestation verification steps, if `prov.E2EE` is true and
     `ReportDataBindingPassed()` on a preliminary check of the TDX result:
     ```go
     var e2eeResult *attestation.E2EETestResult
     if prov.E2EE && tdxBindingOK {
         e2eeResult = probeE2EE(ctx, prov.Name, raw, prov, upstreamModel)
     }
     ```
   - Pass `E2EETest: e2eeResult` to `BuildReport` instead of `E2EETest: nil`.
   - Remove `E2EEConfigured` from `ReportInput` (no longer needed).

3. **Remove `MarkE2EEUsable`**: `internal/attestation/report.go`
   - Delete the `MarkE2EEUsable` method.
   - Remove calls in `proxy.go` ~line 734 and ~line 873.
   - The report is now immutable after `BuildReport`.

4. **Remove `E2EEConfigured`**: `internal/attestation/report.go`
   - Delete the `E2EEConfigured` field from `ReportInput`.
   - Simplify `evalE2EEUsable`: the `E2EEConfigured` branch
     ("pending live test") is no longer needed.

5. **Chutes consideration**: Chutes has `SkipSigningKeyCache=true` and
   fetches fresh attestation on every request. The probe adds one extra
   roundtrip per request. This may be acceptable for Chutes given it already
   does per-request attestation, but the latency impact should be measured.
   - Alternative for Chutes: skip the probe and use Option C's approach for
     Chutes only (enforce at relay, not at report).

6. **Integration tests**: `internal/proxy/integration_*_test.go`
   - `e2ee_usable` assertions should now pass on the first report fetch
     (no need to wait for a chat roundtrip to promote it).
   - However, the probe itself requires a working E2EE path, so integration
     tests still need API keys and network access.

7. **Unit tests**: `internal/attestation/report_test.go`
   - Remove `TestMarkE2EEUsable`.
   - Add tests for probe functions.
   - Update `evalE2EEUsable` tests to remove `E2EEConfigured` cases.

8. **Verify path**: `cmd/teep/main.go`
   - Refactor to call the same shared probe functions.
   - Minor: `testE2EE`'s stream validation logic (`doE2EEStreamTest`,
     `doE2EEChutesStreamTest`) is more thorough than a probe needs to be.
     The shared probe can be simpler (non-streaming, minimal message).

### Tradeoffs

- **Pro**: Unifies verify and proxy paths — both use the same E2EE test at
  report-build time.
- **Pro**: Report is immutable after build — eliminates P2 and P3 entirely.
- **Pro**: `e2ee_usable` remains a well-defined factor with clean lifecycle.
- **Con**: Adds latency to every cache-miss request (one extra roundtrip for
  E2EE probe). For Chutes (per-request attestation), this doubles the
  inference request count.
- **Con**: Probe failures block the request even if regular E2EE would have
  worked (the probe could hit transient errors).
- **Con**: Requires factoring out E2EE test logic from `cmd/teep/main.go`
  into a shared package, touching both the CLI and proxy.

---

## Option C: Enforce E2EE at relay, not at report (minimal change)

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
   - In `handleChatCompletions`, after the `Blocked()` check, if
     `e2eeFailed.Load(key)` returns true, return 502 with a message like
     "E2EE previously failed; re-attestation required".

3. **Relay error detection**: `internal/e2ee/relay.go` and
   `internal/e2ee/relay_chutes.go`
   - Modify relay functions to signal decryption failure back to the caller.
     Two approaches:
     - **(a) Return value**: Change `RelayStream`, `RelayNonStream`,
       `RelayReassembledNonStream`, `RelayStreamChutes`,
       `RelayNonStreamChutes` to return an `error` (nil on success,
       non-nil on decryption failure). This is a larger signature change.
     - **(b) Context/callback**: Pass a callback or write to a channel that
       the caller checks after relay completes.
     - **(c) Shared flag**: Pass a `*atomic.Bool` that the relay sets on
       decryption failure. Simplest but least idiomatic.
   - Recommendation: Return `error`. The current `void` signatures already
     handle HTTP writing internally; adding a return value is straightforward.

4. **Post-relay enforcement**: `internal/proxy/proxy.go`
   `handleChatCompletions` (~line 733 area)
   - After the relay call, if error indicates decryption failure AND
     `e2eeActive` was true:
     ```go
     s.e2eeFailed.Store(cacheKey{prov.Name, upstreamModel}, true)
     s.cache.Delete(prov.Name, upstreamModel)
     s.signingKeyCache.Delete(prov.Name, upstreamModel)
     ```
   - Note: by this point the (possibly corrupted) response has already been
     written to the client. For streaming, the HTTP 200 was sent with the
     first chunk. This is unavoidable without buffering the entire response.
     The enforcement is *forward-looking*: block the next request.

5. **Keep `MarkE2EEUsable` but fix it**: `internal/attestation/report.go`
   - Since `e2ee_usable` is now always allowed-to-fail, it will stay `Skip`
     (not promoted to `Fail`). `MarkE2EEUsable`'s guard
     `Status == Skip` will always be safe.
   - Underflow guard added (`e4b075c`): `Skipped > 0` check with
     `slog.Warn` on desync. **Partial fix** — full counter recomputation
     (Shared Fix S2) and report cloning (Shared Fix S1) still needed.
   - Still fix the cache mutation race (see Shared Fix S1 below).
   - Still fix counter consistency (see Shared Fix S2 below).

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

### Tradeoffs

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
- **Con**: Still requires fixing the cache mutation race (Shared Fix S1) for
  the informational `MarkE2EEUsable` call to be correct.
- **Con**: For streaming responses, the first decryption failure is already
  partially relayed to the client. Enforcement is forward-looking only.
- **Con**: The relay signature change (returning `error`) is still needed.

---

## Shared fixes (apply to all options)

### S1: Cache mutation race

**Status**: Documented with TODO comments (`6de38de`). **Not yet fixed.**

**Problem**: `MarkE2EEUsable` (and the subsequent `cache.Put`) mutates a
shared `*VerificationReport` pointer.

**Fix**: Clone the report before mutating. Apply in both non-pinned
(~line 734) and pinned (~line 873) paths.

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

**If Option A is chosen**: `MarkE2EEUsable` is removed entirely, making this
fix unnecessary.

**If Option B is chosen**: `MarkE2EEUsable` is removed entirely, making this
fix unnecessary.

**Files**: `internal/proxy/proxy.go`, `internal/attestation/report.go` (add
`cloneReport` or a `Clone` method on `VerificationReport`).

### S2: Counter recomputation

**Status**: Partial fix (`e4b075c`) — added `Skipped > 0` guard with
`slog.Warn` to prevent underflow. **Full recomputation not yet implemented.**

**Problem**: `MarkE2EEUsable` manually adjusts `Passed` and `Skipped`
counters. This is fragile — if the factor status is unexpected, counters
desync.

**Fix** (if `MarkE2EEUsable` is retained): Replace manual counter adjustment
with a recomputation:

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

**If Option A or B is chosen**: `MarkE2EEUsable` is removed; this fix is
unnecessary.

**Files**: `internal/attestation/report.go`

### S3: Chutes URL validation

**Status**: **DONE** (`2ac5f5a`). Validation added in `PrepareRequest`
after `url.Parse`: rejects URLs with empty `Scheme` or `Host`. Unit test
`TestPreparer_RejectsInvalidAPIBaseURL` covers empty, no-scheme, and
path-only cases.

**Problem**: `p.apiBaseURL + "/e2e/invoke"` can produce an invalid URL if
`apiBaseURL` is empty or missing a scheme.

**File**: `internal/provider/chutes/chutes.go`

### S4: ChuteID fallback

**Status**: **DONE** (`a9850b9`). `testE2EEChutes` now returns an error
when `raw.ChuteID` is empty instead of falling back to `model`. Unit test
`TestTestE2EEChutes_MissingChuteID` covers this.

**Problem**: `testE2EEChutes` falls back to `chuteID = model` when
`raw.ChuteID` is empty. If `model` is a human-readable name (not a UUID),
the E2EE test fails for reasons unrelated to cryptography.

**File**: `cmd/teep/main.go` `testE2EEChutes`

---

## Recommendation

**Short-term** (partially completed): Option C step 1 and shared fixes
S3–S4 are done. S1 and S2 have partial fixes (TODOs and underflow guard).
The remaining Option C work is:

1. **S1 full fix**: Clone report before `MarkE2EEUsable` mutation (both
   non-pinned and pinned paths).
2. **S2 full fix**: Replace manual counter adjustment with `recomputeCounters`.
3. **Step 2**: Add `e2eeFailed sync.Map` to `Server` struct; check it after
   `Blocked()` gate.
4. **Step 3**: Change relay functions to return `error` on decryption failure.
5. **Step 4**: Post-relay enforcement — mark failed, invalidate caches.
6. **Step 8**: Add `Delete` method to report cache and signing key cache.

**Medium-term**: Evaluate **Option A** for a future refactor. Separating
E2EE lifecycle from the report factor system is the cleanest architecture
and will scale better as new "live test" factors are added (e.g. the
forthcoming tool call test factor). Option A should be considered when the
tool call factor is designed, since it will face the same chicken-and-egg
problem.

**Option B** is a reasonable middle ground if the latency of a pre-flight
probe is acceptable. It should be prototyped and benchmarked — if the probe
adds <200ms to cache-miss requests, it may be preferable to Option C's
post-hoc mutation pattern.

---

## Future considerations

- **Tool call test factor**: A forthcoming factor that tests whether tool
  calls work through the E2EE path. It will face the same chicken-and-egg
  problem as `e2ee_usable`. The design chosen here should account for this.
- **E2EE key rotation**: When a signing key rotates (VM restart), the proxy
  logs a warning but continues. If E2EE state is tracked separately (Option
  A), key rotation should reset the E2EE state to `Pending`.
- **Report cache TTL vs E2EE state**: The report cache has a 5-minute TTL.
  If E2EE state is tracked in the report (Options B, C), a cache miss
  resets `e2ee_usable` to `Skip`. If tracked separately (Option A), the
  E2EE state can persist independently of the report cache TTL.
- **Client-facing E2EE status**: Consider adding an `X-Teep-E2EE` response
  header so clients can verify E2EE was used for each request without
  fetching the full report.
