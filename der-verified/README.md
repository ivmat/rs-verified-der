# der-verified

A **formally verified** DER (X.690) encoding/decoding core in Rust — the encoding layer where real
X.509 parser differentials live. Every **primitive** codec carries machine-checkable evidence,
re-runnable from a fresh clone: the proofs are the product, not a badge.

**Status:** pre-1.0 (`0.1.1`). The proofs and their evidence are real, re-runnable and honestly
bounded; the API is not yet stable, and the crate carries no production deployment record. Treat it
as a verified building block to evaluate, not as a drop-in hardened parser.

Read "primitive" strictly: the `x509_*` layer is **structural framing composing verified
primitives**, not proven to the same bar (see Scope below). The crate's name should not be read as
claiming more than that.

- **L3 — Kani** (bounded model checking): 203 proof harnesses over 33 modules — memory safety, no
  panics, no overflow, plus functional properties (round-trip, canonicality/minimality, rejection of
  malformed/non-canonical encodings).
- **L4 — Aeneas → Lean 4** (unbounded proofs): six codecs (`length`, `big_integer`, `oid`, `tag`,
  `tlv`, `sequence`) are additionally proven over inputs of **any length**, `sorry`-free.
- **485** unit and regression tests (concrete vectors, incl. seeded-bad specimens).

> Read [`PROOF_MANIFEST.md`](https://github.com/ivmat/rs-verified-der/blob/main/PROOF_MANIFEST.md)
> before relying on any of this — the honest proof envelope: exactly what is proven, under what bounds
> and assumptions, what is stubbed, and what is **not** proven. Counts are inventory, not a coverage
> guarantee.

> **`acceptance.toml` ships in this package**, next to this README, with its evidence records in
> `evidence/acceptance-records/`. It is the same envelope in machine-checkable form: every claim
> with its grade, its evidence, and whether it is *weighted*. **13 of 39 claims are weighted** —
> they carry a mutation control that was watched to fail. The other 26 are published as unweighted
> and each states why.
>
> You do not need this repository to check it. The paths it cites are relative to the manifest, so
> they resolve in the unpacked crate; run the acceptance/0 validator from
> [github.com/ivmat/acceptance-format](https://github.com/ivmat/acceptance-format) at the revision
> its own `validator_sha` names:
>
> ```sh
> python3 check_acceptance.py --strict --strict-weight acceptance.toml
> ```

## Scope

**Verified:** the DER encoding layer — tag/length fields and the canonical content codecs (`BOOLEAN`,
`INTEGER`, `NULL`, `OBJECT IDENTIFIER`, `BIT STRING`, `OCTET STRING`, `ENUMERATED`, the restricted
strings, `UTF8String`, `UTCTime`, `GeneralizedTime`, `SEQUENCE`, `SET OF` §11.6 ordering).
**Structural framing (no semantics):** the `x509_*` modules parse RFC 5280 objects by composing the
verified codecs. **Signature-container framing (no semantics):** `ecdsa_sig_value` parses the ASN.1
`ECDSA-Sig-Value` (RFC 3279 §2.2.3 / RFC 5480, `SEQUENCE { r INTEGER, s INTEGER }`), exposing `r`/`s`
as opaque validated bytes — no curve-order range check, no low-S policy, no cryptographic
interpretation. **`pkcs8`** parses the PKCS#8 v1 `PrivateKeyInfo` container (RFC 5208 §5), v1 only
(RFC 5958 v2 out of scope), exposing `privateKey`/`attributes` as opaque bytes. The sibling
key/signature containers — `rsa_public_key` (PKCS#1 `RSAPublicKey`), `ec_private_key`
(SEC1 `ECPrivateKey`), `rsa_private_key` (PKCS#1 `RSAPrivateKey`), and `encrypted_private_key_info`
(RFC 5958 `EncryptedPrivateKeyInfo`) — parse the same way: DER framing/canonicality only, key
material exposed as opaque validated bytes, no cryptographic interpretation. **Typed profile
layer (Kani-proven, no Lean lid):** the `profile` module checks
three RFC 5280 cross-field rules (signature-algorithm equality, extensions-require-v3, and the
UTCTime/GeneralizedTime year-2050 encoding choice); each is proven as a biconditional over symbolic
field values, as is their documented precedence — see `PROOF_MANIFEST.md`.
**Out of scope:** signature/crypto verification, path/trust validation, curve-order range and low-S
checks on `ECDSA-Sig-Value`, and every other RFC 5280 profile rule (name constraints, key usage, basic
constraints, validity-against-clock).

## Usage

```rust
use der_verified::length::decode_length;
use der_verified::x509_certificate::parse_certificate;

// Decoders reject non-canonical encodings of the value they consume; the `_strict` entry points
// additionally reject any trailing bytes (composable decoders leave the caller to check consumption).
let (length_value, consumed) = decode_length(&bytes)?;   // rejects non-minimal / non-canonical lengths
let cert = parse_certificate(der_bytes)?;                // structural X.509 framing (no crypto)
```

The crate is `#![forbid(unsafe_code)]` and allocation-free on the decode paths.

## Security considerations

This crate parses attacker-controlled input, so be precise about what the proofs buy you.

- **The proofs are bounded.** Each Kani harness decides its properties up to a declared buffer width
  and unwind depth (`PROOF_MANIFEST.md` §4 lists every bound). "No panic at the proven bound" is not
  "no panic at any size". The six Lean lids are the exception — unbounded in input length, and for
  `sequence` in child count too.
- **Resource exhaustion is the residual surface and is not proven away.** Deeply nested input is
  exactly what a bounded proof cannot speak to, and the crate imposes no recursion-depth or
  total-work limit of its own. **Bound input size and nesting depth yourself before feeding it
  untrusted certificates.** A stack overflow aborts the process — not memory-unsafe, but a denial
  of service you own.
- **No cryptography.** Encoding layer only: no signature verification, no chain building, no trust
  decisions. Framing that parses is not a valid certificate.
- **The trusted base is real:** Kani/CBMC/SAT soundness, the Lean kernel, and the fidelity of the
  Aeneas extraction (the lids prove a Lean model of the shipped Rust, not the Rust itself). See
  [`ASSUMPTIONS.md`](https://github.com/ivmat/rs-verified-der/blob/main/ASSUMPTIONS.md).

## License

Dual-licensed under either [MIT](https://github.com/ivmat/rs-verified-der/blob/main/LICENSE-MIT) or
[Apache-2.0](https://github.com/ivmat/rs-verified-der/blob/main/LICENSE-APACHE), at your option.
