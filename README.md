# der-verified

A **formally verified** DER (X.690) encoding/decoding core in Rust — the encoding layer where real
X.509 parser differentials live. Every public codec carries machine-checkable evidence, and that
evidence is **re-runnable from a fresh clone**: the proofs are the product, not a badge.

- **L3 — Kani** (bounded model checking): 160 proof harnesses over 25 modules — memory safety, no
  panics, no overflow, plus the functional properties (round-trip, canonicality/minimality, rejection
  of malformed/non-canonical encodings).
- **L4 — Aeneas → Lean 4** (unbounded proofs): three codecs (`length`, `big_integer`, `oid`) are
  additionally proven over inputs of **any length**, `sorry`-free.
- **294** unit and regression tests (concrete vectors, incl. seeded-bad specimens) alongside the proofs.

> **Read [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) before relying on any of this.** It is the honest
> proof envelope: exactly what is proven, under what bounds and assumptions, what is stubbed, and
> **what is *not* proven**. Counts are inventory, not a coverage guarantee.

## Scope — proven vs. tested vs. out of scope

**In scope (verified):** the DER encoding layer — identifier (tag) and definite-length fields, and
the canonical content codecs: `BOOLEAN`, `INTEGER` (`i64` and arbitrary-magnitude), `NULL`,
`OBJECT IDENTIFIER`, `BIT STRING`, `OCTET STRING`, `ENUMERATED`, the ASCII-restricted strings,
`UTF8String`, `UTCTime`, `GeneralizedTime`, `SEQUENCE`, and `SET OF` member-ordering (§11.6).

**Structural composition (framing only, no semantics):** the `x509_*` modules parse RFC 5280 objects
(`AlgorithmIdentifier`, `SubjectPublicKeyInfo`, `Name`, `Validity`, `Extension`/`Extensions`,
`TBSCertificate`, `Certificate`) by composing the verified codecs. They interpret **no**
algorithm/key/signature/certificate semantics — a demonstration that the verified core is usable
downstream, inside the same fence.

**Out of scope (not implemented, not proven):** signature/crypto verification; certificate-path or
trust validation; full X.509/RFC 5280 profile semantics (name constraints, cross-field rules,
validity-against-clock); general `SET` (§10.3). The crate is a strict, deliberately narrowed profile —
the narrowings (e.g. leap-second rejection, range caps, primitive-form-only rules) are design
decisions recorded in [`DECISIONS.md`](DECISIONS.md).

## Use

Not yet published to crates.io. Use as a git dependency:

```toml
[dependencies]
der-verified = { git = "https://github.com/<owner>/rs-verified-der" }
```

```rust
use der_verified::length::decode_length;
use der_verified::x509_certificate::parse_certificate;

// Every decoder is strict: it accepts a byte string only if it is the unique canonical DER encoding.
let (length_value, consumed) = decode_length(&bytes)?;  // rejects non-minimal / non-canonical lengths
let cert = parse_certificate(der_bytes)?;               // structural X.509 framing (no crypto)
```

The crate is `#![forbid(unsafe_code)]` and allocation-free on the decode paths.

## Verify it yourself (the point of this crate)

The evidence is re-runnable. From a fresh clone:

### 1. Tests + the L3 Kani proof floor

```sh
# Rust: the repo pins a stable toolchain via rust-toolchain.toml (rustup selects it automatically).
cargo test                                    # 294 tests

# Kani (bounded model checker) — https://model-checking.github.io/kani/install-guide.html
cargo install --locked kani-verifier            # add `--version 0.67.0` to match the pinned toolchain
cargo kani setup
cargo kani -Z stubbing                          # 160 proof harnesses
```

Or run the whole gate — hygiene checks + tests + Kani + the (guarded) Lean lids:

```sh
./check.sh          # full gate (Kani + Lean run here; minutes)
./check_fast.sh     # fast subset: doc/provenance gates + cargo test
```

`-Z stubbing` is required: two X.509 harnesses are **modular** proofs that stub an
independently-proven sub-parser (disclosed in `PROOF_MANIFEST.md`). Harnesses without a stub are
unaffected by the flag.

### 2. The L4 Lean lids (optional; unbounded proofs on 3 codecs)

`./check.sh` runs the Lean lids if — and only if — the Aeneas/Lean toolchain is present; otherwise it
**skips them and still passes on the Kani floor**. To run them you need, in an isolated location
(default `~/Downloads/verified_rs_tools`, overridable via the `VERIFIED_RS_TOOLS` env var):

- [`elan`](https://github.com/leanprover/elan) (Lean is pinned to `v4.30.0-rc2` by
  `lean/lean-toolchain`, resolved per-directory);
- [Aeneas](https://github.com/AeneasVerif/aeneas) and [Charon](https://github.com/AeneasVerif/charon)
  at the exact commits pinned in `lean/check_lean.sh` (it fails on revision drift, because the proofs
  are checked against a specific Aeneas Std semantics).

The lid **re-extracts each codec from the shipped `.rs`** and fails if the regenerated model differs,
so it provably concerns the shipped source. It also fails closed on any `sorry`.

## Toolchain pins

| Tool | Version | Source of truth |
|---|---|---|
| rustc | `stable` channel (checked at `1.96.1`) | `rust-toolchain.toml` pins the channel |
| Kani | `0.67.0` (pinned in CI; bundles CBMC) | `.github/workflows/ci.yml` |
| Lean 4 | `v4.30.0-rc2` | `lean/lean-toolchain` |
| Aeneas / Charon | pinned commits | `lean/check_lean.sh` |

The crate builds on the current `stable` toolchain; `1.96.1` is the release these claims were last
checked against. For a byte-identical Kani reproduction, install the pinned Kani version (below).

## Continuous integration

[GitHub Actions](.github/workflows/ci.yml) runs `cargo test`, `cargo clippy -D warnings`, and the
**memory-tractable share of the Kani proof floor** on every push and PR — 135 of the 160 harnesses,
sharded by module across runners. The other 25 harnesses (`set_of`, `sequence`, `x509_name`,
`x509_tbs_certificate`, `x509_certificate`, `x509_extension`) peak above a standard 7 GB runner's RAM
(the heaviest, `x509_extension`, needs ~20 GB), so — like the L4 Lean lids — they are a **local-milestone
check**: run the full floor with `./check.sh` (or on a ≥24 GB runner via the `kani-heavy` job stub in the
workflow). Every harness is still verified from a fresh clone; the split is purely about CI runner memory.

## Documentation

- [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) — what is proven, bounds, assumptions, stubs, and non-goals.
- [`DECISIONS.md`](DECISIONS.md) — the contestable-decisions ledger: every scope narrowing and design
  fork, with its rationale and review outcome.
- [`SECURITY.md`](SECURITY.md) — private vulnerability disclosure.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above,
without any additional terms or conditions.
