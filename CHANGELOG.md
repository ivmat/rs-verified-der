# Changelog

All notable changes to `der-verified` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation / assurance process
- **`PROOF_MANIFEST.md` is now generated from source and gated.** New
  `gates/gen_proof_manifest.py` derives every number in the manifest — harness counts, `pub fn`
  entry points and which of them no harness names, symbolic buffer widths, unwind depths,
  `kani::assume` split into harness preconditions vs stub postconditions vs generator setup (plus a
  size/range-versus-content classification that names every content-restricting assumption),
  `kani::cover` counts, stub applications, the cover-vacuity registry and whether each witness is
  itself stub-mediated, the hand-written oracle/helper surface, Lean lid theorem/axiom counts, and the
  toolchain pins.
  `--check` runs in `check.sh` and `check_fast.sh` and fails on drift, including drift in
  count-claims made in `README.md`, `docs/` and the manifest's own prose. The manifest was
  restructured around the five headings of the publication checklist, and now states explicitly:
  which entry points **no** harness names (12, classified), what is **not** proven per module, the
  non-vacuity audit and its three disclosed known-unsatisfiable covers, the oracle/specification
  trust surface, and the provenance of both the L3 and L4 verdicts. Entry-point detection covers
  free `pub fn`s, public inherent-`impl` methods and trait-`impl` methods (68 in total).
- **Corrected counts** (all previously derived by hand-grep, all off by the same class of error —
  prose mentions inside comments counted as code): `#[test]` total is **309**, not 310;
  the `#[kani::unwind]` distribution totals **145** attributes, not 157; **22 of 25** harnessed
  modules carry a `kani::cover`, not 23. No proof or property changed — only the counts describing
  them. `DOCS-SYNC.md` documents the trap and now points at the script as the single source of truth.
- **Cover-vacuity findings are machine-countable.** Each of the three carries a
  `// VACUITY-DISCLOSED: <harness> -> witness <harness>` line (comment-only, no proof semantics
  touched). Kani does not fail a harness for an unsatisfied cover, so these gaps were previously
  visible in prose only.
- **Newly disclosed, not newly true:** `./check.sh` needs ~24 GB RAM for the full Kani floor; the
  Lean layer no-ops (announcing `SKIP`, but not failing) when the Aeneas/Charon/Lean stack is absent;
  no raw proof-run log is committed in the repository, so every full-suite verdict in the docs is a
  prose transcription; the accept path of the `x509_name`/`x509_tbs_certificate`/`x509_certificate`
  composition is evidenced by `#[test]` only, because the covers that witness it sit in stub-bearing
  harnesses and so witness glue-reachability under a fabricated sub-parser `Ok`; the oracle surface
  (9 hand-written reference predicates) is part of the trust base and nothing gates its fidelity to
  X.690; and nothing machine-checks that each `restricted_string` per-charset wrapper passes its
  *own* `Charset`.
- **Newly claimed, having been under-claimed:** the recorded L4 verdict still concerns the bytes
  shipped at HEAD (no file any lid extracts from has changed since the last recorded
  `check_lean.sh` pass, and the extraction shims `#[path]`-include module files rather than importing
  the crate), and public CI — machine-readable and third-party-inspectable — was green on the
  preceding commit.

### Verification
- **Closed the last cheap non-vacuity residual.** `enumerated::decode_delegates_to_integer` proves an
  *agreement* between `decode_enumerated` and `crate::integer::decode_integer` — a property that would
  hold even if both sides only ever rejected — and carried no `kani::cover`, so its non-vacuity rested
  on `integer`'s proofs rather than its own witness. It now carries five covers (accept at `n == 1`, at
  an intermediate `2 ≤ n ≤ 7`, and at full width `n == 8`; an `Ok` with a negative two's-complement
  value; and the exact `Err(NonMinimal)`): `5 of 5` satisfied, 0 of 138 checks failed, 0.229 s. They are
  reachability witnesses — the agreement itself is proven for every `n` in `1..=8`. The unreachable
  `Empty` / `TooLarge` variants are deliberately left uncovered, with the reasoning in-line, because a
  known-unsatisfiable cover is reported by Kani as `SUCCESSFUL`. Crate-wide: 47 → **52** covers, **23**
  of 25 harnessed modules now carry one. No new property proven and no source behaviour changed.
- **L3 (Kani / CBMC):** Kani harness count is now **164** (was 161 at 0.1.0) — cover-retrofit added
  `kani::cover` properties across most proof modules (a T6-style non-vacuity check, not new
  properties proven) and a handful of new harnesses landed alongside it (notably
  `x509_extension`/`x509_validity`/`x509_tbs_certificate` each gained a positive-construction
  "Ok-path witnessed" harness that closes a cover-vacuity finding — see `DER-REMAINING-WORK.md` §4).
  Test count is now **309** (was 294).
- **L4/L5 (Aeneas → Lean 4):** two new lids landed, bringing the total to **6** (was 3 at 0.1.0):
  - 4th lid, `tlv` — `decode_tlv`'s structural/no-over-read correctness, ∀-length
    (`lean/TlvProofs.lean`, `decode_tlv_structure`). The first L4 lid on the crate's structural
    *composition* layer, not a leaf codec.
  - 5th lid, `sequence` — `decode_sequence`'s structural/no-over-read correctness, ∀-length AND
    ∀-children (`lean/SequenceProofs.lean`, `decode_sequence_structure`). The crate's first
    unbounded-**loop** lid.
  - 6th lid, `tag` — `decode_tag`'s totality and consumption bound, ∀-length
    (`lean/TagProofs.lean`, `tag_decode_total`/`tag_decode_used_bounds`). Required a
    behaviour-preserving refactor of `decode_tag`'s high-tag loop to unblock Aeneas extraction.
    Landing this lid discharged the 4 `tag_decode_*` trust-axiom instances the `tlv`/`sequence`
    lids previously assumed about `decode_tag` (7-axiom trust surface → 6, for each).

### Added
- **`profile` module** — a first slice of a typed profile-validation layer, built on top of (not
  inside) the structural `x509_*` parsers: checks three RFC 5280 cross-field rules the transfer-
  syntax modules deliberately leave "to the caller" — §4.1.1.2's `signatureAlgorithm` /
  `tbsCertificate.signature` equality, §4.1.2.1/§4.1.2.9's extensions-require-v3 rule, and
  §4.1.2.5's UTCTime-through-2049/GeneralizedTime-from-2050 encoding-choice rule. **Tested
  (`#[test]`) only** — no Kani harness or Lean lid backs this layer yet; see `PROOF_MANIFEST.md`.

### Fixed
- `cargo clippy -D warnings`: `#[allow(clippy::redundant_closure)]` on the Aeneas-required
  `map_err` closures (point-free form would break Lean extraction — never revert this to
  point-free).

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
