# Dstack Integrity Chain Issues

Many dstack-based inference providers already publish two useful artifacts with their attestation responses:

- a TDX quote
- a Docker Compose manifest bound into `MRCONFIGID`

That is enough for teep to prove that the attested CVM declared a specific compose file, but it is **not** enough to prove that the CVM booted the expected dstack OS image, ran the expected kernel and root filesystem, and then faithfully executed that compose file.

The missing piece is the base-image trust chain:

- `MRSEAM` for the Intel TDX module version
- `MRTD` for the TD virtual firmware image
- `RTMR0`, `RTMR1`, and `RTMR2` for the measured boot configuration, kernel, initrd, and root filesystem

Without published golden values for those registers, teep can verify application-layer binding, but it cannot verify the full dstack boot process. For a security product, that is a high-severity residual risk: a malicious lower stack can declare it is using the expected compose config hash while actually running different code.

## Affected teep validation factors

Base-image measurement enforcement:

- **`tdx_quote_structure`** — enforces `MRTD` and `MRSEAM` allowlists for the
    inference CVM when `mrtd_allow` and `mrseam_allow` are configured
- **`gateway_tdx_quote_structure`** — enforces `MRTD` and `MRSEAM` allowlists
    for the gateway CVM when `gateway_mrtd_allow` and `gateway_mrseam_allow`
    are configured

Measured-boot and runtime replay enforcement:

- **`event_log_integrity`** — replays the inference CVM event log and enforces
    `RTMR0`-`RTMR3` allowlists when configured; this gap exists when providers do
    not publish authenticated baselines for `RTMR0`-`RTMR2`
- **`gateway_event_log_integrity`** — replays the gateway CVM event log and
    enforces `gateway_rtmr0_allow`-`gateway_rtmr3_allow`; this gap exists when
    providers do not publish authenticated gateway baselines for `RTMR0`-`RTMR2`

Application-layer factors that remain necessary but are not sufficient:

- **`compose_binding`** — proves `MRCONFIGID` matches the published
    `app_compose`, but does not authenticate the underlying dstack boot image,
    kernel, or root filesystem
- **`gateway_compose_binding`** — gateway equivalent of `compose_binding`; it
    can pass even when the gateway lower stack is not independently authenticated

---

## TDX in One Page

Intel TDX does not know what Docker Compose is. It does not pull container images, parse YAML, or orchestrate workloads. TDX does one narrower but critical job: it measures VM state and produces a hardware-signed quote containing those measurements.

The key registers are:

- `MRSEAM`: identity of the Intel TDX module
- `MRTD`: measurement of the initial TD image, effectively the virtual firmware root of trust
- `RTMR0`: measured hardware and boot-policy configuration
- `RTMR1`: measured kernel and boot-loader state
- `RTMR2`: measured kernel command line, initrd, root filesystem related state
- `RTMR3`: runtime and application-layer events, replayable from the event log
- `MRCONFIGID`: 48-byte configuration field included in the quote
- `REPORTDATA`: caller-bound cryptographic binding field used for nonce and key binding

The security meaning of those fields is not symmetric:

- `MRSEAM`, `MRTD`, and `RTMR0-2` establish whether the **platform and guest boot chain** are trustworthy
- `RTMR3` and `MRCONFIGID` establish whether **runtime metadata and app configuration** match what dstack reported

This distinction is the core of the gap. A correct `MRCONFIGID` does not compensate for an unverified `MRTD` or `RTMR1`.

## Full Dstack TDX Authentication

dstack’s attestation model is documented in the upstream [dstack attestation guide](https://github.com/Dstack-TEE/dstack/blob/master/attestation.md) and in Phala’s operator-facing documentation, including [Trust Center Technical Details](https://docs.phala.com/dstack/trust-center-technical) and [Verify the Platform](https://docs.phala.com/phala-cloud/attestation/verify-the-platform).

The intended verification story is:

1. build or reproduce the dstack base image
2. derive golden values for `MRTD`, `RTMR0`, `RTMR1`, and `RTMR2` for a specific deployment shape
3. identify the expected `MRSEAM` for the deployed TDX module version
4. verify the quote against those golden values
5. replay the event log to validate `RTMR3`
6. verify that `MRCONFIGID` binds the published compose manifest to the attested TD

In other words, dstack attestation is meant to combine **base-image measurements** and **runtime/application measurements**. The compose file is only one input into that larger chain.

The trust chain looks like this:

```mermaid
graph TD
    A["Intel TDX module\nMRSEAM"] --> B["Virtual firmware / TD image\nMRTD"]
    B --> C["Boot policy and virtual hardware\nRTMR0"]
    B --> D["Kernel and boot loader\nRTMR1"]
    D --> E["Cmdline, initrd, rootfs\nRTMR2"]
    E --> F["dstack runtime"]
    F --> G["MRCONFIGID = 0x01 || SHA256(compose)"]
    F --> H["RTMR3 event log extensions"]
    F --> I["Containers launched from compose"]

    style A fill:#f66,stroke:#333
    style B fill:#f66,stroke:#333
    style C fill:#f96,stroke:#333
    style D fill:#f96,stroke:#333
    style E fill:#f96,stroke:#333
    style F fill:#ff9,stroke:#333
    style G fill:#9f9,stroke:#333
    style H fill:#9f9,stroke:#333
    style I fill:#ff9,stroke:#333
```

If teep verifies only the green part of that chain, it is trusting the yellow and orange parts without evidence.

That creates several realistic failure modes:

- a modified TDX module could report quote contents that look valid enough for policy unless `MRSEAM` is pinned
- a substituted firmware image could boot a different kernel while preserving the expected runtime metadata unless `MRTD` is pinned
- a modified kernel or root filesystem could lie about orchestration behavior while still emitting the expected compose hash unless `RTMR0-2` are pinned
- a malicious runtime could set `MRCONFIGID` to the expected compose hash and extend `RTMR3` consistently while running different code

For teep, the consequence is direct: confidential traffic could be forwarded to a TD whose application metadata looks right, but whose lower stack is untrusted.

## Teep Dstack Verification

When a provider supplies a quote, event log, and compose manifest, teep does several meaningful checks:

- verify the TDX quote structure and PCS collateral
- verify caller binding through `REPORTDATA` where the provider-specific protocol supports it
- verify `MRCONFIGID` against the published compose manifest
- replay the event log and check `RTMR3` consistency
- inspect compose-listed images and apply repository allowlists and supply-chain checks such as Sigstore and Rekor

Those controls matter. They provide application-layer assurance and supply-chain visibility for the images named in the compose file.

However, if the provider does **not** publish golden values for `MRSEAM`, `MRTD`, `RTMR0`, `RTMR1`, and `RTMR2`, teep cannot actually ensure that the docker compose file is actually used: an attacker with hypervisor-level control could preserve the expected compose binding while substituting the firmware, kernel, initrd, or root filesystem.

### What Providers Must Publish

To let teep authenticate the full dstack boot process, providers need to publish enough information for an operator or client to independently validate both the base image and the workload layer.

At minimum, a provider should publish:

1. the dstack OS or equivalent CVM image version used in production
2. the CPU and RAM configuration for each deployment class, because these affect `RTMR0`
3. the expected TDX module version and corresponding `MRSEAM`
4. golden values for `MRTD`, `RTMR0`, `RTMR1`, and `RTMR2` for each supported deployment class
5. the event-log format and any runtime identifiers needed to interpret `RTMR3`
6. the raw `app_compose` manifests for both gateway and model CVMs where both exist
7. the image digests and provenance expectations for every compose-listed component image

That publication set lets teep treat the quote as a full chain-of-trust object rather than an application metadata carrier.

## Recommended Publication Model

The cleanest approach is to publish a signed, versioned measurement manifest alongside the compose and image provenance materials.

### Recommended Manifest Contents

Each manifest should be immutable and scoped to a concrete deployment class, for example a specific gateway image version or inference image version with a fixed CPU and RAM profile.

A practical manifest should include:

- provider name and environment
- deployment role: gateway, inference, or both
- dstack base-image version or source revision
- TDX module version
- CPU count and memory size
- `MRSEAM`
- `MRTD`
- `RTMR0`
- `RTMR1`
- `RTMR2`
- expected event-log schema or version
- `app_compose` digest
- compose-listed image digests and repository identities
- issuance timestamp, validity period, and replacement version

### Recommended Authentication Mechanism

To fit teep’s existing supply-chain posture, providers should publish that manifest in the same style they publish compose-listed images:

1. sign the manifest with Sigstore
2. record it in Rekor
3. host it at a stable versioned location or API endpoint

This mirrors the provenance model already used for container images. teep can then verify:

- the manifest was issued by the expected provider identity
- the manifest has not been tampered with
- the manifest version corresponds to the compose and image digests being attested

If Sigstore is not practical, the next-best option is a provider-signed JSON manifest served from a stable HTTPS endpoint with a pinned signing identity. What matters is that the measurement baselines are authenticated, versioned, and machine-readable.

### How teep Would Use Published Manifests

With authenticated measurement manifests in place, teep could:

1. fetch the provider’s measurement manifest for the declared deployment class
2. verify the manifest signature and provenance
3. load the manifest’s `MRSEAM`, `MRTD`, and `RTMR0-2` values into policy allowlists
4. compare the attested quote fields against those exact values
5. replay the event log for `RTMR3`
6. verify `MRCONFIGID` against the raw compose file
7. verify dstack base and compose-listed images against repository policy and Sigstore/Rekor expectations
8. block the request if any link in that chain fails

That is the end state teep needs: fail-closed verification of both the **boot image** and the **application payload**.

## Practical Recommendations

For providers:

1. publish reproducible build guidance or immutable references for the dstack base image
2. publish per-deployment-class golden values for `MRSEAM`, `MRTD`, and `RTMR0-2`
3. publish those values in a signed, versioned machine-readable manifest
4. bind that manifest to the same release lifecycle as the compose file and component image digests
5. document how rollouts and measurement rotation work so verifiers can safely accept old and new values during controlled upgrades

For builders using teep:

1. treat compose binding as necessary but insufficient
2. where providers do not publish authenticated baselines, pin the currently observed measurement values in teep policy for both inference and gateway hosts using `mrseam_allow`, `mrtd_allow`, `rtmr0_allow`, `rtmr1_allow`, `rtmr2_allow`, and the corresponding `gateway_mrseam_allow`, `gateway_mrtd_allow`, `gateway_rtmr0_allow`, `gateway_rtmr1_allow`, `gateway_rtmr2_allow` settings
3. treat that pinning workflow as a stopgap that detects unexpected measurement drift, not as proof of private inference, because observed values are only truly trustworthy when they come from a reproducibly built and independently verifiable image
4. require provider-published measurement manifests before claiming full dstack integrity
