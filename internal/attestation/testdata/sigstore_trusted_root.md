# Sigstore trusted root provenance

`sigstore_trusted_root.json` is the public-good Sigstore trusted root. Tests
load it with `sigstoretest.TrustedRoot(attestation.NewStaticTrustedRootSource)`
(package `internal/attestation/sigstoretest`), so that unit,
integration and replay tests send no TUF request. Production code and
`teep verify --replay` fetch the root through TUF and do not read this file.

| Property | Value |
|---|---|
| TUF repository | `https://tuf-repo-cdn.sigstore.dev` |
| TUF target | `trusted_root.json` |
| Target SHA-256 | `6494e21ea73fa7ee769f85f57d5a3e6a08725eae1e38c755fc3517c9e6bc0b66` |
| Target length | 6787 bytes |
| `targets.json` version | 14 |
| `root.json` version | 16 |
| Fetch date | 2026-10-21 |

The fetch used sigstore-go v1.2.1 `tuf.New` with `tuf.DefaultOptions()`, an
empty cache directory, and the TUF root that sigstore-go embeds. The TUF
client verified the target length and SHA-256 against the signed
`targets.json` metadata.

The file holds:

- Fulcio CA `O=sigstore.dev, CN=sigstore` (valid 2021-03-07 to 2022-12-31),
  and Fulcio CA `O=sigstore.dev, CN=sigstore` with the intermediate
  `CN=sigstore-intermediate` (valid from 2022-04-13).
- CT logs `ctfe.sigstore.dev/test` (2021-03-14 to 2022-10-31) and
  `ctfe.sigstore.dev/2022` (from 2022-10-20, log ID `dd3d306a…`).
- Rekor logs `rekor.sigstore.dev` (log ID `c0d23d6a…`, the key that
  `rekorLogPublicKeyPEM` pins) and `log2025-1.rekor.sigstore.dev`.
- The timestamp authority `timestamp.sigstore.dev` (from 2025-07-04).

Replace the file only when Sigstore adds or rotates a Fulcio CA, CT log or
Rekor key that a new fixture uses. Fetch it again through TUF as above,
then update this table and the hash in `TestCheckedInTrustedRootHash`.
