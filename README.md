# der-verified

[![crates.io](https://img.shields.io/crates/v/der-verified.svg)](https://crates.io/crates/der-verified)
[![docs.rs](https://img.shields.io/docsrs/der-verified)](https://docs.rs/der-verified)
[![license: MIT OR Apache-2.0](https://img.shields.io/crates/l/der-verified.svg)](#license)

A DER (X.690) encoding/decoding core in Rust **under formal verification**, with re-runnable
evidence and an explicit claim-by-claim assurance map.

**Status:** pre-1.0 (`0.3.0`). The acceptance 0.4.0 manifest has **876 requirement claims**: **2 A4**, **195 A3**, and **172 weighted**. It also records 130 evidenced A0 claims, 25 gaps, 305 excluded requirements, and 219 not-applicable requirements. Counts are inventory, not a coverage percentage. The API is unstable. Evaluate this crate as a building block with bounded and uneven evidence.

## Evidence at a glance

The floor of record at `d3de34e` verifies all 302 harnesses in one pass at a 24 GB cap. It returns exit 0 and Lean lid PASS. Full logs are kept outside git, available on request.

- **L3 — Kani:** 302 proof harnesses over 33 modules establish default safety checks on their
  bounded domains; functional claims vary by harness and are listed in the proof manifest.
- **L4/L5 — Aeneas → Lean 4:** selected properties of six codecs (`length`, `big_integer`, `oid`,
  `tag`, `tlv`, `sequence`) hold for any input length; `sequence` also covers any child count. The
  lids are `sorry`-free; `tag` canonicality rejection remains Kani-bounded at 7 bytes.
- **Tests:** 710 unit and regression tests plus 34 doc-tests cover concrete vectors. Counts are
  inventory, not coverage.

Read [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) for the exact properties, bounds, stubs and non-goals;
[`ASSUMPTIONS.md`](ASSUMPTIONS.md) for the trusted base; and generated
[`acceptance.toml`](der-verified/acceptance.toml) for every claim's evidence, grade and weight. The
manifest and [records](der-verified/evidence/acceptance-records/) ship in the crate; the
[crate README](der-verified/README.md) explains what remains repository-only. The manifest follows
acceptance format 0.4.0 with the Rust verification profile; its generated header names the exact
validator-closure commit.

## Scope

- **Core codecs:** tag, definite length, TLV framing, primitive content codecs, `SEQUENCE`, and
  `SET OF` member ordering. Read “primitive” strictly: properties and bounds differ by codec.
- **Structural containers:** `x509_*` and the signature/private-key containers compose the core.
  Their evidence is bounded framing, not algorithm, key, signature, or certificate semantics.
- **Profile:** four value-level RFC 5280 cross-field rules are covered; this is not full profile or
  path validation.
- **Out of scope:** cryptographic verification, trust/path validation, remaining RFC 5280 profile
  rules, and general `SET` (§10.3). See [`DECISIONS.md`](DECISIONS.md), `PROOF_MANIFEST.md` §6, and
  the module docs.

Two composition bounds are especially important: `x509_certificate` proves panic-freedom only
through 12 bytes versus a roughly 170-byte fixture, and `rsa_private_key` only through 20 bytes
versus a roughly 317-byte fixture. Beyond those bounds, confidence rests on an un-machine-checked
compositional argument plus concrete witnesses, not a symbolic proof over real-size inputs. See
`PROOF_MANIFEST.md` §6.2.

> **Framing is not validity.** `tlv::decode_tlv`, its strict sibling, and the `sequence` child walk
> accept structurally framed values without deciding whether the identifier is legal for DER; this
> includes constructed encodings of primitive-only universal types and reserved EOC. Typed TLV
> parsers (`octet_string`, `pkcs8`, the `x509_*` modules) check their own identifiers; content-level
> codecs never see one. `identifier_form` adds opt-in form-checking, but it is not wired into the base
> TLV or sequence APIs. See `PROOF_MANIFEST.md` §6.3.

## Verification map

This generated summary reads one claim per requirement. Band, grade and weight are separate fields. Use
[`COVERAGE.md`](COVERAGE.md) when the question is whether a particular DER or RFC 5280 rule is
decided. The summary also lists declared limits and planned work.

<!-- BEGIN GENERATED:map (gates/gen_verification_map.py) -->
**197 of 876** claims reach A3 or better; **679** do not. The total includes excluded, gap and not-applicable requirements.

The acceptance axis is one claim per requirement. Counts are inventory, not a coverage percentage.

| Status | Band | Grade | Weight | Claims |
|---|---|---|---|---:|
| evidenced | A0 | probe | unweighted | 48 |
| evidenced | A0 | test-only | unweighted | 82 |
| evidenced | A3 | contract | unweighted | 25 |
| evidenced | A3 | contract | weighted | 170 |
| evidenced | A4 | contract | weighted | 2 |
| gap | A0 | not-covered | unweighted | 25 |
| gap | A0 | out-of-scope | unweighted | 305 |
| not-applicable | not-applicable | ungraded | unweighted | 219 |

Weighted claims: **172**.

Band meanings:
- A4 unbounded functional proof, kernel-checked, red mutation control — 2 claim(s)
- A3 bounded functional contract, red mutation control — 195 claim(s)
- A2 memory safety on the unsafe surface, with a control — 0 claim(s)
- A1 non-vacuous but not state-exhaustive, and no functional control — 0 claim(s)
- A0 ran or asserted, with NO control watched to fail — the claim is not done — 460 claim(s)

Source inventory only; these module names carry no aggregate assurance band:
`big_integer`, `bit_string`, `boolean`, `context_tag`, `ec_private_key`, `ecdsa_sig_value`, `encrypted_private_key_info`, `enumerated`, `generalized_time`, `identifier_form`, `integer`, `length`, `null`, `octet_string`, `oid`, `pkcs8`, `profile`, `restricted_string`, `rsa_private_key`, `rsa_public_key`, `sequence`, `set_of`, `tag`, `tlv`, `utc_time`, `utf8_string`, `x509_algorithm_identifier`, `x509_certificate`, `x509_extension`, `x509_name`, `x509_spki`, `x509_tbs_certificate`, `x509_validity`.

Lean-lid source modules: `big_integer`, `length`, `oid`, `sequence`, `tag`, `tlv`.

Read [`der-verified/acceptance.toml`](der-verified/acceptance.toml) for each requirement. Subject commit `d3de34e`; generated `2026-10-28T15:12:43Z`. A band above A1 needs a mutation control naming the claim that was watched to fail; without one a claim stops at A1 (and an ungraded claim at A0).

Declared limits and planned work:
- Name constraints (RFC 5280 §4.2.1.10) (planned; source: `PROOF_MANIFEST.md:538 ("Not covered at all: name constraints, key usage, basic constraints, validity-against-clock, path validation")`).
- Key usage (RFC 5280 §4.2.1.3) (planned; source: `PROOF_MANIFEST.md:538`).
- Basic constraints (RFC 5280 §4.2.1.9) (planned; source: `PROOF_MANIFEST.md:538`).
- Validity-against-clock (RFC 5280 §4.1.2.5) (planned; source: `PROOF_MANIFEST.md:538`).
- X.509 structural-module Lean lid (L4) (planned; source: `DER-REMAINING-WORK.md:157-165 ("All X.509 structural modules (x509_*) are Kani-only — no L4 lid... still the crate's one open breadth item")`).
- Signature / crypto verification (out-of-scope; source: `README.md:47-48 ("Out of scope (not implemented, not proven): signature/crypto verification...")`).
- Certificate-path / trust validation (out-of-scope; source: `README.md:47-48 ("...certificate-path or trust validation...")`).
- General SET (X.690 §10.3) (out-of-scope; source: `README.md:49-50 ("general SET (§10.3)"); DECISIONS.md:463 (D13 — "general SET (§10.3) stays out of scope")`).
<!-- END GENERATED:map -->

## Strict decoding

Top-level strict entry points reject trailing bytes. `tlv::decode_tlv_strict` and
`sequence::decode_sequence_tlv_strict` require exactly one value; composable variants leave a suffix
only so containers can parse children. Kani checks strict rejection on its bounded domain, while the
TLV consumption/no-over-read property also has an unbounded Lean lid. This does not turn the base
framing APIs into DER-validity checks; the identifier-form residual above still applies.

## Use

```sh
cargo add der-verified
```

```rust
use der_verified::length::decode_length;
use der_verified::x509_certificate::parse_certificate;

let (length_value, consumed) = decode_length(&bytes)?; // canonical length field
let cert = parse_certificate(der_bytes)?;              // strict structural framing; no crypto
```

The crate has zero runtime dependencies, is `#![forbid(unsafe_code)]`, and is allocation-free on the
decode paths. It is not `#![no_std]` today.

## Security considerations

- **Bounded means bounded.** A Kani result covers only its harness's buffer and unwind domain; the
  selected Lean properties are the stated exceptions. Deep nesting and resource exhaustion are not
  proven away, and the crate imposes no recursion-depth or total-work limit of its own. Bound
  untrusted input size and nesting depth; a Rust stack overflow aborts the process.
- **No cryptography or trust decision.** A structurally parsed object is not thereby a valid
  certificate, key, or signature.
- **The trusted base is real.** Claims depend on Kani/CBMC/SAT, the Lean kernel, pinned toolchains,
  and Aeneas extraction fidelity: the lids prove a model of the Rust. Their 13 declared axioms
  specify upstream `core` primitives, not crate code. The proof manifest also names three
  known-unsatisfiable covers and their separate witnesses. See [`ASSUMPTIONS.md`](ASSUMPTIONS.md).

For vulnerability reporting, see [`SECURITY.md`](SECURITY.md).

## Verify it yourself (the point of this crate)

The evidence is re-runnable. From a fresh clone:

### Laptop replay

```sh
./replay.sh
./replay.sh --with-lean
```

The default replays tests, the acceptance gate, one Kani harness, and negative controls; it validates
recorded Lean evidence but does not run Lean. `--with-lean` re-extracts and checks the lids, but is
**accept-only** — it confirms the lids hold; the recorded Lean mutation controls are validated as
records, not re-run. Neither mode runs the full Kani floor or establishes X.509 correctness; read
[`REPLAY.md`](REPLAY.md).

### Tests and full gates

```sh
cargo test                                      # 710 tests + 34 doc-tests
cargo install --locked kani-verifier --version 0.67.0
cargo kani setup
cargo kani -Z stubbing                          # 302 proof harnesses, needs a large machine
```

```sh
./check_fast.sh     # docs/manifests + tests
./check.sh          # full Kani floor; Lean runs only when its pinned toolchain is present
```

`-Z stubbing` is required for the 29 modular harnesses in the generated inventory.
Their stub obligations are listed in `PROOF_MANIFEST.md` §8.4. The profile totality and precedence
proofs remain conditional on `has_repeated_leading_oid` being total. Its totality is not discharged;
its comparison results have unit-test evidence only. The Lean step re-extracts the shipped Rust, fails on drift or
`sorry`, and requires the exact Aeneas/Charon/Lean pins below.

## Toolchain pins

| Tool | Version | Source of truth |
|---|---|---|
| rustc | floating `stable` channel | `rust-toolchain.toml` |
| Kani | `0.67.0` (pinned in CI; bundles CBMC) | `.github/workflows/ci.yml` |
| Lean 4 | `v4.30.0-rc2` | `lean/lean-toolchain` |
| Aeneas / Charon | pinned commits | `lean/check_lean.sh` |

## Continuous integration

[GitHub Actions](.github/workflows/ci.yml) runs hygiene and parity gates, tests, clippy, and the
memory-tractable **225 of 302** Kani harnesses. The remaining heavy modules are a local milestone via
`./check.sh`; the full floor needs roughly 24 GB available (largest harness peaks ~20 GB). Indicative shard timings and
memory measurements live in [`docs/verification-cost.md`](docs/verification-cost.md).

The `x509_name` proof's split from a monolithic >100 GB attempt into discharged modular proofs is
explained in [`docs/why-verified.md`](docs/why-verified.md#a-war-story-the-proof-that-needed-100-gb).

## Documentation

- [`docs/why-verified.md`](docs/why-verified.md) — why a verified DER decoder, the two-layer
  (Kani + Aeneas→Lean) approach, the honesty envelope, and the modular-proof war story.
- [`COVERAGE.md`](COVERAGE.md) — the per-rule coverage ledger: one row per X.690 / RFC 5280 rule,
  its evidence strength, and a self-verify command per row. Start here if your question is "is *this
  rule* verified?" rather than "does *this module* have harnesses?".
- [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) — what is proven, bounds, assumptions, stubs, and non-goals.
- [`DECISIONS.md`](DECISIONS.md) — the contestable-decisions ledger: every scope narrowing and design
  fork, with its rationale and review outcome.
- [`SECURITY.md`](SECURITY.md) — private vulnerability disclosure.
- [`DOCS-SYNC.md`](DOCS-SYNC.md) — which documents to update when code or proofs change.

## License

Dual-licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE))
- MIT license ([LICENSE-MIT](LICENSE-MIT))

at your option. Unless you explicitly state otherwise, any contribution intentionally submitted for
inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above,
without any additional terms or conditions.
