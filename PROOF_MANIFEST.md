# Proof manifest — `der-verified`

This document is the **honest proof envelope**. It states exactly what is machine-checked, under
what bounds, with what assumptions and stubs, and — as importantly — **what is not proven**.

> **Counts are inventory, not coverage.** "309 tests, 164 Kani harnesses, 6 Lean lids" describes how
> much verification exists, not a guarantee that every reachable behaviour is covered. The claim of
> this crate is precisely the per-property, per-bound statement below — nothing broader. Read the
> harnesses and proofs themselves as ground truth; this manifest is a map to them.

## Toolchain pins (the versions these claims were checked against)

| Tool | Version / revision | Role |
|---|---|---|
| rustc | `1.96.1` — the stable release these claims were checked against (`rust-toolchain.toml` pins the `stable` *channel*, which floats to whatever stable is installed) | crate build + `cargo test` |
| Kani | `cargo-kani 0.67.0` (bundles its own toolchain + CBMC; the CI job pins this exact version) | L3 bounded proofs |
| Lean 4 | `leanprover/lean4:v4.30.0-rc2` (pinned by `lean/lean-toolchain`) | L4 unbounded proofs |
| Aeneas | commit `45061fa1a5b4bad876f17c03d3a5544d818622e6` | Rust → Lean functional translation |
| Charon | commit `40ee060a8df43f4e7e0842d3f05387b0a4426aaf` | Rust → LLBC front-end for Aeneas |
| extract shims | Rust `nightly-2026-06-01` (Charon's nightly; `lean/extract*/rust-toolchain.toml`) | drive extraction only |

The Aeneas/Charon revisions are **enforced** by `lean/check_lean.sh` (it fails on drift), because the
proofs are checked against a specific Aeneas Std semantics. Kani/CBMC versions are recorded here; the
CI job (`.github/workflows`) installs the pinned Kani.

## The proof stack — two lineages

### L3 floor — Kani (`cargo kani`) — **bounded**

Kani compiles each `#[kani::proof]` harness to CBMC and discharges it as a bit-precise SAT/SMT query.
Every harness proves, by Kani's default checks, **memory safety, absence of panics, and absence of
arithmetic overflow** on its input domain — plus the **functional properties** each harness asserts
(round-trip, canonicality/minimality, and rejection of malformed/non-canonical encodings).

**What "bounded" means here, precisely.** Each harness constructs a *fixed-size symbolic input*
(`kani::any()` byte arrays of a chosen length), optionally narrowed by `kani::assume(...)`
preconditions, and unrolls loops to a stated `#[kani::unwind(N)]` depth. The proof is therefore
**complete over that bounded input domain** and no larger. It is **not** a statement about inputs
longer than the harness's buffers. Where an unbounded (∀-length) guarantee is needed, an L4 Lean lid
supplies it (below). Unwind depths in use range from 1 to 22 (most codecs at 16); the per-module
column lists each module's range.

- **164 Kani harnesses** across 25 modules. Run: `cargo kani -Z stubbing` (or `./check.sh`).
- **309 unit and regression tests** (`cargo test`) exercise concrete vectors (incl. seeded-bad
  specimens) alongside the proofs. These are example-based tests, not property-based/generator-driven.

### L4/L5 reach — Aeneas → Lean (`lean/check_lean.sh`) — **unbounded, on six codecs**

Six codecs are additionally extracted Rust → Charon → Aeneas → Lean 4 (mathlib) and machine-checked
over inputs of **any length** (and, for `sequence`, ALSO any number of children — the crate's first
unbounded-LOOP lid), lifting the corresponding bounded Kani harnesses to ∀-length/∀-children:

| Codec | Lean file | Unbounded property proven |
|---|---|---|
| `length` (§8.1.3) | `lean/LengthProofs.lean` | every branch of `decode_length` ∀-length; round-trip canonicality (`decode_accepts_only_canonical`), which also proves both loops of `encode_length` |
| `big_integer` (§8.3) | `lean/BigIntProofs.lean` | minimality biconditional (validate side) and encode-side round-trip / canonicality, ∀-length |
| `oid` (§8.19) | `lean/OidProofs.lean` | OID canonical-form biconditional (validate side), ∀-length |
| `tag` (§8.1.2, the identifier octet(s) reader) | `lean/TagProofs.lean` | `decode_tag`'s totality and consumption bound, ∀-length (`tag_decode_total`, `tag_decode_used_bounds`): `decode_tag` never fails/diverges, and an accepted decode always consumes `1..=input.length` bytes. Required a behaviour-preserving refactor of `decode_tag`'s high-tag loop (return-inside-loop → break-with-`Result`) to unblock Aeneas extraction (mirrors the D25 `validate_oid` fix). Landing this lid **discharged the 4 `tag_decode_*` trust-axiom instances** the `tlv` and `sequence` lids below previously assumed about `decode_tag` — they now rest on real theorems instead. |
| `tlv` (the TLV reader, composing `tag`+`length`) | `lean/TlvProofs.lean` | `decode_tlv`'s structural correctness ∀-length (`decode_tlv_structure`): an accepted TLV's `used` equals `header + declared-length`, its value is exactly that window, and — the security-critical no-over-read fact — `used ≤ input.length`, for an input of *any* length. The first L4 lid on the crate's structural *composition* layer (not a leaf codec) — see its docstring for the disclosed 6-axiom trust surface (now that `decode_tag` is backed by the `tag` lid's own theorems rather than assumed as a bodyless axiom). |
| `sequence` (the SEQUENCE/SET child-walk, composing `tag`+`length`+`tlv`) | `lean/SequenceProofs.lean` | `decode_sequence`'s structural correctness, ∀-length AND ∀-children (`decode_sequence_structure`): whenever `decode_sequence content` accepts, the child-walk it performs reaches a state whose remaining suffix is exhausted — the walk consumes *exactly* `content`'s bytes, for a content slice of *any* length and *any* number of children (no bound on the walk's trip count, unlike Kani's `#[kani::unwind(16)]`-capped harness). The crate's first coverage of an **unbounded LOOP** in Lean (`tlv::decode_tlv` is itself loop-free) — proved via `loop.spec_decr_nat` with measure `iter.rest.length`, strictly decreasing each accepted child. Reuses the same disclosed 6-axiom trust surface as `tlv`'s lid (restated for this pass's own extraction namespace — see its docstring). |

All L4 proofs are **`sorry`-free**, and this is a *gate*, not an eyeball check: `lean/check_lean.sh`
fails closed if `sorryAx` or a `declaration uses 'sorry'` warning appears. The full non-standard axiom
set each proof rests on is disclosed via `#print axioms` in the Lean sources (propext,
`Classical.choice`, `Quot.sound`, `bv_decide`'s certificate axiom, and the named Aeneas-Std spec
axioms). The lid **re-extracts from the shipped `.rs` and fails on drift**, so it provably concerns
the shipped source, not a stale snapshot.

**Trust base for L4:** the Lean proofs trust the *Aeneas model* of the Rust code (the translation is
not itself formally verified against rustc semantics). This is the standard Aeneas assurance
boundary and is stated here rather than hidden.

### L4 is guarded

`lean/check_lean.sh` **no-ops (exit 0) when the Aeneas/Lean toolchain is absent**, so `./check.sh`
still passes on the L3 Kani floor alone on a machine without the extraction stack. The L4 lids are
*additive* assurance, not a build prerequisite. Installing the stack: see the README.

## Modular proofs via stubs (disclosed — 4 stubs, 3 harnesses)

Three X.509 composition harnesses are **modular proofs**: they replace an already-independently-proven
sub-parser with a `#[kani::stub]` that captures its proven contract, so CBMC can verify the
composition glue tractably. This is sound *because each stubbed function is separately proven at its
own harness* — but it is a compositional argument, not a single monolithic proof, and is disclosed as
such:

| Harness (module) | Stubs | Each stub's own proof lives at |
|---|---|---|
| `x509_name` never-panics | `validate_rdn` | `x509_name::validate_rdn_never_panics` |
| `x509_tbs_certificate` never-panics | `validate_name`, `validate_extensions` | `x509_name`, `x509_extension` harnesses |
| `x509_certificate` never-panics | `parse_tbs_certificate` | `x509_tbs_certificate` harness |

The chain is a DAG (`x509_certificate` → `x509_tbs_certificate` → {`x509_name` → `x509_name` lemma,
`x509_extension`}); each link is a real function separately proven panic-free. **Each stub's contract
is discharged over a *symbolic input length* (`0..=N`)**, covering every length the caller can pass a
suffix slice at — not just the full `N`-byte buffer; a fixed-length discharge would leave the shorter
call lengths unproven, since the parsers' control flow is length-dependent. `x509_name`'s harness is
modular because the monolithic proof's SET-OF §11.6 ordering over symbolic content is intractable
(>100 GB in CBMC symbolic execution); see that module's Kani comment and DECISIONS.md D26.

`cargo kani -Z stubbing` (in `check.sh`) enables the feature; harnesses without a `#[kani::stub]` are
unaffected by the flag.

## Assumptions (`kani::assume`) narrow what is proven

Harnesses use `kani::assume(...)` preconditions (136 across the crate) to constrain the symbolic
input — e.g. bounding a declared length so a loop stays within its unwind depth. **An assumption
excludes inputs from the proof's domain.** The properties hold *for inputs satisfying the
assumptions*; inputs outside them are simply not claimed. The assumptions are visible inline in each
harness. The six Lean lids remove the length-bound assumption for their codecs (that is the point
of the L4 layer).

## Deliberate deviations from full DER/X.509 (documented, not defects)

This crate implements a **strict, deliberately narrowed** profile. The narrowings are design
decisions, each recorded in `DECISIONS.md`:

- **Range boundaries** on numeric/time fields (e.g. `integer` capped at `i64`; `big_integer` is the
  arbitrary-magnitude complement) — `DECISIONS.md` D2, D14.
- **Leap second `SS=60` is rejected** in the time types (a profile narrowing) — D9.
- **Time types validate single-field ranges, not calendar validity** (e.g. day-of-month vs. month)
  — D10.
- **`OCTET STRING` accepts primitive form only**, rejecting the BER constructed/segmented form
  (itself a parser-differential hardening) — see the module docs.
- **General `SET` (§10.3) is out of scope**; only `SET OF` (§11.6) member-ordering is validated — D6,
  D13.
- The `x509_*` modules are **structural** parsers: they frame RFC 5280 objects by composing the
  verified codecs, and interpret **no** algorithm/key/signature/certificate semantics.

## Typed profile-validation layer (`profile`) — tested, not Kani/Lean-proven

The `profile` module is a **first slice** of a typed layer, built strictly *on top of* the
structural `x509_*` parsers, that checks cross-field RFC 5280 rules those parsers deliberately leave
"to the caller" (see the `x509_certificate`/`x509_tbs_certificate`/`x509_validity` module docs, which
name this split explicitly). It performs no DER decoding of its own — only comparisons/checks over
already-materialized fields of an already-structurally-valid `Certificate`.

**Currently enforces three rules**, checked in this order and returning the first violation:

1. **§4.1.1.2** — the outer `Certificate.signatureAlgorithm` must equal
   `tbsCertificate.signature` (both independently-valid `AlgorithmIdentifier`s that nothing in the
   ASN.1 grammar ties together).
2. **§4.1.2.1 / §4.1.2.9** — `extensions` is a v3-only field: a certificate carrying `extensions`
   but declaring a `version` other than v3 is rejected.
3. **§4.1.2.5 / §4.1.2.5.1 / §4.1.2.5.2** — `notBefore`/`notAfter` must each use the RFC-mandated
   encoding for their calendar year (UTCTime through 2049, GeneralizedTime from 2050 on). Only the
   GeneralizedTime-too-early direction needs a runtime check; the UTCTime-too-late direction is
   structurally impossible by construction (`utc_time::full_year_rfc5280`'s codomain is exactly
   `1950..=2049` — see the module's own exhaustive-over-`u8` test,
   `full_year_rfc5280_never_reaches_2050`, for the machine-checked argument).

**Honesty note — this layer is *not* the same grade of evidence as the codecs above.** `profile.rs`
carries `#[test]` unit/regression tests (14, counted in the 309 total) exercising both the accept and
each reject path, but **no `#[kani::proof]` harness and no Lean lid** — it is example-based coverage
only, not bounded-model-checked or unbounded-proven. Treat its correctness claim as "tested against
the cases above", not "proven" in the sense the rest of this manifest uses that word. Not yet covered
by this layer: name constraints, key usage, basic constraints, path validation, and any other RFC
5280 cross-field rule beyond the three listed — see `DER-REMAINING-WORK.md`/`TODO.md` for the roadmap.

## What is NOT proven (scope fence)

- **No cryptography**: no signature verification, no key/algorithm semantics, no certificate-path or
  trust validation. `der-verified` is an *encoding-layer* core.
- **Full X.509 profile semantics are only partly covered, and only by tests, not proofs**: the
  `profile` module (above) now checks three cross-field RFC 5280 rules, but by `#[test]` only — no
  Kani/Lean evidence backs it. Every other cross-field rule (name constraints, key usage, basic
  constraints, validity-against-clock, path validation) is still left to the caller entirely.
- **Not unbounded except the six L4 codecs**: every other property is bounded verification over the
  harness input domain described above (and `profile`'s three rules are not Kani/Lean-covered at
  all — see above).
- **rustc-semantics gap for L4**: the Aeneas translation, not rustc, is what the Lean proofs check
  (stated above).
- **Tests are not proofs**: the 309 `cargo test` cases are concrete vectors; the assurance claim
  rests on the Kani harnesses and Lean lids, with tests as regression/road-signs (and, for `profile`,
  as the *only* current evidence — see above).

## Per-module inventory

Entry points are the module's `pub fn`s. "Kani" is the harness count; "Unwind" the `#[kani::unwind]`
range; "L4" marks a codec additionally lifted to ∀-length in Lean.

| Module | X.690/RFC | Public entry points | Kani | Unwind | L4 |
|---|---|---|---:|---|:--:|
| `tag` | §8.1.2 | `encode_tag`, `decode_tag` | 7 | 12 | ✅ |
| `length` | §8.1.3, §10.1 | `encode_length`, `decode_length` | 9 | 10 | ✅ |
| `tlv` | §8.1 | `decode_tlv`, `decode_tlv_strict`, `encode_tlv_into` | 5 | 16 | ✅ |
| `context_tag` | §8.14.2 | `decode_explicit_context` | 1 | 20 | |
| `boolean` | §8.2 | `encode_bool`, `decode_bool` | 3 | — | |
| `integer` | §8.3 | `encode_integer`, `decode_integer` | 7 | 12 | |
| `big_integer` | §8.3 | `validate_integer_content`, `is_negative`, `encode_minimal_integer_into` | 13 | 1..22 | ✅ |
| `null` | §8.8 | `decode_null` | 1 | — | |
| `oid` | §8.19 | `validate_oid` | 5 | 8 | ✅ |
| `bit_string` | §8.6, §11.2 | `decode_bit_string`, `require_octet_aligned`, `encode_bit_string_into` | 8 | 6..8 | |
| `octet_string` | §8.7 | `decode_octet_string`, `encode_octet_string_into` | 6 | 16 | |
| `enumerated` | §8.4 | `decode_enumerated`, `encode_enumerated` | 3 | 12 | |
| `restricted_string` | §8.23/25 | `validate_content`, `decode_restricted_string`, `encode_restricted_string_into` (+ per-type wrappers) | 26 | 6..16 | |
| `utf8_string` | UNIVERSAL 12 | `validate_utf8`, `decode_utf8_string`, `decode_utf8_str`, `encode_utf8_string_into` | 9 | 6..16 | |
| `utc_time` | §11.8 | `decode_utc_time`, `encode_utc_time`, `full_year_rfc5280` | 13 | 14..18 | |
| `generalized_time` | §11.7 | `decode_generalized_time`, `encode_generalized_time_into`, `require_no_fraction` | 16 | 16..20 | |
| `sequence` | §8.9, §8.10 | `decode_sequence`, `decode_sequence_tlv`, `decode_sequence_tlv_strict`, `encode_sequence_into` | 7 | 16 | |
| `set_of` | §11.6 | `cmp_padded`, `decode_set_of`, `decode_set_of_tlv`, `decode_set_of_tlv_strict`, `encode_set_of_into` | 13 | 16 | |
| `x509_algorithm_identifier` | RFC 5280 §4.1.1.2 | `parse_algorithm_identifier` | 1 | 20 | |
| `x509_spki` | §4.1.2.7 | `parse_subject_public_key_info` | 1 | 20 | |
| `x509_name` | §4.1.2.4 | `validate_name` | 2 | 10..12 | modular (stub) |
| `x509_validity` | §4.1.2.5 | `parse_validity` | 2 | 20 | |
| `x509_extension` | §4.1.2.9 | `parse_extension`, `validate_extensions` | 3 | 12..20 | |
| `x509_tbs_certificate` | §4.1.1.1 | `parse_tbs_certificate` | 2 | 12 | modular (stub) |
| `x509_certificate` | §4.1 | `parse_certificate` | 1 | 12 | modular (stub) |
| `profile` | RFC 5280 (cross-field) | `validate_profile` | 0 | — | tested only, no Kani/Lean (see above) |

`boolean` and `null` have no `#[kani::unwind]` (no loops to unroll). Entry-point lists are the exact
`pub fn`s; per-property assertions and `kani::assume` preconditions are inline in each harness.
`profile`'s Kani count is 0 by design — it has no `#[kani::proof]` harness; see the dedicated section
above for its (test-only) evidence.

## Reproduce

```
./check.sh        # doc gate + cargo test + cargo kani (L3) + Lean lids (L4, guarded)
```

See the README for a fresh-clone walkthrough (rustc + Kani install, and the optional Aeneas/Lean
stack for the L4 lids).
