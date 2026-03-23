# Direct Inference Audit Prompt Pack

This prompt pack defines the audit process for direct inference providers.

It is intended to be delegated to sub-agents in self-contained sections.

## Dispatch Model (Orchestrator)

The audit is to be performed by four sub-agents, each given one the following groups of prompt files from this directory:

1. Baseline Input Surface
    - [`00_shared_preamble.md`](00_shared_preamble.md)
	- [`01_model_routing.md`](01_model_routing.md)
	- [`02_attestation_fetch.md`](02_attestation_fetch.md)
	- [`03_transport_safety.md`](03_transport_safety.md)
	- Why grouped: endpoint/domain selection, attestation fetch/parse, and request-surface/resource bounds are evaluated on the same ingress path.

2. TDX Core Integrity & Binding
    - [`00_shared_preamble.md`](00_shared_preamble.md)
	- [`04_tdx_quote.md`](04_tdx_quote.md)
	- [`05_tdx_measurements.md`](05_tdx_measurements.md)
	- [`06_event_log.md`](06_event_log.md)
	- [`07_tls_binding.md`](07_tls_binding.md)
	- Why grouped: quote parsing feeds measurement fields and RTMR replay checks; findings overlap on baseline integrity and fail-closed semantics.

3. Supply-Chain Provenance
    - [`00_shared_preamble.md`](00_shared_preamble.md)
	- [`08_cvm_image.md`](08_cvm_image.md)
	- [`09_policy_caching.md`](09_policy_caching.md)
	- Why grouped: compose-to-MRCONFIGID binding and Sigstore/Rekor provenance form one supply-chain verification chain. The cache operation is key to usage integrity.

4. Auxiliary Attestation Signals
    - [`00_shared_preamble.md`](00_shared_preamble.md)
	- [`10_nvidia_tee.md`](10_nvidia_tee.md)
	- [`11_proof_of_cloud.md`](11_proof_of_cloud.md)
	- Why grouped: both are auxiliary/adjacent trust signals with weaker coupling to the core TDX+binding enforcement path.

Note that *all* of the four (4) sub-agents are given [`00_shared_preamble.md`](00_shared_preamble.md).

The four sub-agents are *not* given this README file. This README file contains orchestration and report assembly instructions only. You MAY give this README file to a fifth sub-agent, along with all of the results from the four other sub-agents, to write the final report file.

## Final Report Assembly Rules

The assembled final report MUST include:
- executive summary with severity counts and one-paragraph overall risk statement,
- findings summary table (severity, location, impact),
- findings-first narrative sections (ordered by severity within each section),
- for every major section, at least one concrete positive control observation and one concrete negative/residual-risk observation,
- verification-factor matrix (pass/fail/skip + enforcement status),
- cache-layer table (keys, TTL, bounds, stale behavior),
- offline-mode matrix (active checks vs skipped checks),
- explicit open questions / assumptions where behavior cannot be proven from code.

Each finding MUST include:
- severity + exploitability context,
- exact impacted control,
- whether control is enforced fail-closed,
- realistic CIA impact statement,
- concrete remediation guidance,
- at least one source citation.

If a delegated section has no issues, that section must still state: **"no issues found in this section"** and include residual risk / test gap notes.

## Merge & Conflict Policy

- Deduplicate cross-sectional findings by code location + control name.
- Preserve all source citations from delegated outputs.
- If severity disagrees across sections, keep the higher severity and note disagreement.
- Keep implementation facts separate from recommendations (no implicit policy assumptions).
