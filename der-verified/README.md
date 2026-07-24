# der-verified

A **formally verified** DER (X.690) encoding/decoding core in Rust — the encoding layer where real
X.509 parser differentials live. Every public codec carries machine-checkable evidence, re-runnable
from a fresh clone: the proofs are the product, not a badge.

- **L3 — Kani** (bounded model checking): 164 proof harnesses over 25 modules — memory safety, no
  panics, no overflow, plus functional properties (round-trip, canonicality/minimality, rejection of
  malformed/non-canonical encodings).
- **L4 — Aeneas → Lean 4** (unbounded proofs): six codecs (`length`, `big_integer`, `oid`, `tag`,
  `tlv`, `sequence`) are additionally proven over inputs of **any length**, `sorry`-free.
- **309** unit and regression tests (concrete vectors, incl. seeded-bad specimens).

> Read [`PROOF_MANIFEST.md`](https://github.com/ivmat/rs-verified-der/blob/main/PROOF_MANIFEST.md)
> before relying on any of this — the honest proof envelope: exactly what is proven, under what bounds
> and assumptions, what is stubbed, and what is **not** proven. Counts are inventory, not a coverage
> guarantee.

## Scope

**Verified:** the DER encoding layer — tag/length fields and the canonical content codecs (`BOOLEAN`,
`INTEGER`, `NULL`, `OBJECT IDENTIFIER`, `BIT STRING`, `OCTET STRING`, `ENUMERATED`, the restricted
strings, `UTF8String`, `UTCTime`, `GeneralizedTime`, `SEQUENCE`, `SET OF` §11.6 ordering).
**Structural framing (no semantics):** the `x509_*` modules parse RFC 5280 objects by composing the
verified codecs. **Typed profile layer (tested, not Kani/Lean-proven):** the `profile` module checks
three RFC 5280 cross-field rules (signature-algorithm equality, extensions-require-v3, and the
UTCTime/GeneralizedTime year-2050 encoding choice) by `#[test]` only — see `PROOF_MANIFEST.md`.
**Out of scope:** signature/crypto verification, path/trust validation, and every other RFC 5280
profile rule (name constraints, key usage, basic constraints, validity-against-clock).

## Usage

```rust
use der_verified::length::decode_length;
use der_verified::x509_certificate::parse_certificate;

// Every decoder is strict: it accepts a byte string only if it is the unique canonical DER encoding.
let (length_value, consumed) = decode_length(&bytes)?;   // rejects non-minimal / non-canonical lengths
let cert = parse_certificate(der_bytes)?;                // structural X.509 framing (no crypto)
```

The crate is `#![forbid(unsafe_code)]` and allocation-free on the decode paths.

## License

Dual-licensed under either [MIT](https://github.com/ivmat/rs-verified-der/blob/main/LICENSE-MIT) or
[Apache-2.0](https://github.com/ivmat/rs-verified-der/blob/main/LICENSE-APACHE), at your option.
