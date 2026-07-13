# Changelog

All notable changes to `der-verified` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] — 2026-07-13

First functional release.

### Verification
- **L3 (Kani / CBMC):** 161 proof harnesses across 25 modules — memory safety, no panics, no overflow,
  plus round-trip, canonicality/minimality, and rejection of malformed / non-canonical encodings.
- **L4 (Aeneas → Lean 4):** the `length`, `big_integer`, and `oid` codecs proven for inputs of *any*
  length, `sorry`-free.
- 294 unit and regression tests (incl. seeded-bad specimens). `./check.sh` reproduces the whole thing
  from a fresh clone. See [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) for the honest proof envelope.

### Added
- The verified DER/X.690 encoding codecs (tag, length, TLV, and the canonical content codecs) and the
  structural X.509 framing modules (`x509_*`, composition only — no crypto/semantics).
- Crate-level documentation with a usage example; `#![deny(missing_docs)]` on the public API.

### Notes
- `#![forbid(unsafe_code)]`, zero dependencies, allocation-free on the decode paths.
- Scope is deliberately narrow (encoding layer + structural framing); no signature/crypto verification,
  no certificate-path or trust validation, no full RFC 5280 profile semantics.

## [0.0.0] — 2026-07-13

- Initial name-reservation release on crates.io.

[0.1.0]: https://github.com/ivmat/rs-verified-der/releases/tag/v0.1.0
[0.0.0]: https://github.com/ivmat/rs-verified-der/releases/tag/v0.0.0
