# der-verified

A DER (X.690) encoding/decoding core in Rust **under formal verification** — the encoding layer where
real X.509 parser differentials live. Codec evidence is machine-checkable and re-runnable from a fresh
clone, but it is **uneven**: read the shipped per-claim assurance manifest (`acceptance.toml`) before
relying on any of it.

**Status:** pre-1.0 (`0.1.1`). **Most manifest claims are not yet at the target assurance band A3**
(the shipped `acceptance.toml` gives the exact per-claim split) — the crate is not uniformly formally
verified and is not done. The proofs and their evidence are real, re-runnable and honestly bounded;
the API is not yet stable, and the crate carries no production deployment record. Treat it as a
building block to evaluate, not as a drop-in hardened parser.

Read "primitive" strictly: the `x509_*` layer is **structural framing composing the core codecs**,
not proven to the same bar (see Scope below). The crate's name should not be read as claiming more
than that.

- **L3 — Kani** (bounded model checking): 203 proof harnesses over 33 modules establish default
  safety checks (memory safety, no panics, no overflow) on their bounded domains; functional claims
  (round-trip, canonicality/minimality, rejection of malformed encodings) vary by harness and are
  listed per claim in `acceptance.toml` / `PROOF_MANIFEST.md`.
- **L4 — Aeneas → Lean 4:** *selected properties* of six codecs (`length`, `big_integer`, `oid`,
  `tag`, `tlv`, `sequence`) hold for **any input length**; `sequence` also covers any child count.
  The lids are `sorry`-free; `tag` canonicality *rejection* remains Kani-bounded at 7 bytes.
- **485** unit and regression tests (concrete vectors, incl. seeded-bad specimens).

> Read [`PROOF_MANIFEST.md`](https://github.com/ivmat/rs-verified-der/blob/main/PROOF_MANIFEST.md)
> before relying on any of this — the honest proof envelope: exactly what is proven, under what bounds
> and assumptions, what is stubbed, and what is **not** proven. Counts are inventory, not a coverage
> guarantee.

## What ships in this package vs. the repository

Some of the evidence travels with the crate and some of it does not, so here is the split, plainly.

**In this package** (what you get from `cargo add der-verified`, no clone and no network):

- **All 34 source files, including every one of the 203 Kani proof harnesses.** They are
  `#[cfg(kani)]` modules inside the same sources you compile, so with
  [Kani](https://model-checking.github.io/kani/) installed you can re-run them here:
  ```sh
  cargo kani --harness integer::proofs::decode_accepts_only_minimal --exact -Z stubbing
  ```
- **`acceptance.toml`** — the proof envelope in machine-checkable form: every claim with its grade,
  its evidence, and whether it is *weighted*. **13 of 39 claims are weighted**, meaning they carry a
  mutation control that was watched to fail; the other 26 are published as unweighted, each stating
  why.
- **All 273 evidence records** in `evidence/acceptance-records/` — including the 17 Lean-lid
  records, so the Lean results are *readable and hash-checkable* here even though the proofs
  themselves are not.
- The manifest's `record` paths are relative to the manifest, so they resolve inside the unpacked
  crate. Check it offline with the acceptance/0 validator from
  [github.com/ivmat/acceptance-format](https://github.com/ivmat/acceptance-format), at the revision
  the manifest's own `validator_sha` names (`c8c00bb`):
  ```sh
  python3 check_acceptance.py --strict --strict-weight acceptance.toml
  ```

**Repository only** (not in the package):

- **The 12 Lean/Aeneas proof sources** (`lean/`) that establish the six unbounded lids.
- **The full gate** (`check.sh`, `gates/`) and the vendored validator copy the project runs itself.

**So:** the **Kani** claims are re-runnable from this package alone; the **Lean-lid** claims are
re-runnable from the repository. For everything in between — what each claim rests on, and what is
*not* claimed — read `acceptance.toml` here, and `PROOF_MANIFEST.md` in the repository.

**Repository:** <https://github.com/ivmat/rs-verified-der>. Each release is tagged (`v0.1.1` for
this one) and that tag is the exact source this package was built from.

## Scope

**Core codecs (assurance varies by claim — see `acceptance.toml`):** the DER encoding layer —
tag/length fields and the canonical content codecs (`BOOLEAN`, `INTEGER`, `NULL`, `OBJECT
IDENTIFIER`, `BIT STRING`, `OCTET STRING`, `ENUMERATED`, the restricted strings, `UTF8String`,
`UTCTime`, `GeneralizedTime`, `SEQUENCE`, `SET OF` §11.6 ordering). **Structural framing (no
semantics):** the `x509_*` modules parse RFC 5280 objects by composing the core codecs. **Signature-container framing (no semantics):** `ecdsa_sig_value` parses the ASN.1
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

> **Framing is not validity.** `tlv::decode_tlv`, its `_strict` sibling, and the `sequence` child
> walk accept structurally framed values without deciding whether the identifier is legal for DER —
> this includes constructed encodings of primitive-only universal types and the reserved EOC
> identifier. Typed TLV parsers (`octet_string`, `pkcs8`, the `x509_*` modules) check their own
> identifiers; content-level codecs never see one. `identifier_form` adds opt-in form-checking for a
> *single* identifier (form + EOC exclusion) — it does not validate content or descendants, and it is
> not wired into the base TLV/sequence APIs. See `PROOF_MANIFEST.md` §6.3.

## Usage

```rust
use der_verified::length::decode_length;
use der_verified::x509_certificate::parse_certificate;

// `decode_length` and the typed content codecs reject non-canonical encodings of the value they
// consume; the `_strict` entry points additionally reject trailing bytes. Base TLV/sequence *framing*
// decides structure only, not whether an identifier is legal DER — see "Framing is not validity".
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
- **Two composition bounds are especially small.** `x509_certificate` proves panic-freedom only
  through **12 bytes** versus a ~170-byte fixture, and `rsa_private_key` only through **20 bytes**
  versus a ~317-byte fixture. Beyond those bounds, confidence rests on an un-machine-checked
  compositional argument plus concrete witnesses (some of which are themselves modular, using stubs),
  not a symbolic proof over real-size inputs. See `PROOF_MANIFEST.md` §6.2.
- **Resource exhaustion is the residual surface and is not proven away.** Deeply nested input is
  exactly what a bounded proof cannot speak to, and the crate imposes no recursion-depth or
  total-work limit of its own. **Bound input size and nesting depth yourself before feeding it
  untrusted certificates.** A stack overflow aborts the process — not memory-unsafe, but a denial
  of service you own.
- **No cryptography.** Encoding layer only: no signature verification, no chain building, no trust
  decisions. Framing that parses is not a valid certificate.
- **The trusted base is real.** Claims depend on Kani/CBMC/SAT soundness, the Lean kernel, the pinned
  toolchains, and the fidelity of the Aeneas extraction (the lids prove a Lean model of the shipped
  Rust, not the Rust itself). The lids' **13 declared axioms specify upstream `core` primitives, not
  this crate's code**; `PROOF_MANIFEST.md` §8.2 also names **three known-unsatisfiable covers** and
  their separate witnesses. See
  [`ASSUMPTIONS.md`](https://github.com/ivmat/rs-verified-der/blob/main/ASSUMPTIONS.md).

## License

Dual-licensed under either [MIT](https://github.com/ivmat/rs-verified-der/blob/main/LICENSE-MIT) or
[Apache-2.0](https://github.com/ivmat/rs-verified-der/blob/main/LICENSE-APACHE), at your option.
