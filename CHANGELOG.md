# Changelog

All notable changes to `der-verified` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation / assurance process
- **`PROOF_MANIFEST.md` is now generated from source and gated.** New
  `gates/gen_proof_manifest.py` derives every number in the manifest — harness counts, `pub fn`
  entry points and which of them no harness names, symbolic buffer widths, unwind depths,
  `kani::assume` split into harness preconditions vs stub postconditions, `kani::cover` counts, stub
  applications, the cover-vacuity registry, Lean lid theorem/axiom counts, and the toolchain pins.
  `--check` runs in `check.sh` and `check_fast.sh` and fails on drift, including drift in
  count-claims made in `README.md` and `docs/`. The manifest was restructured around the five
  headings of the publication checklist, and now states explicitly: which entry points **no** harness
  names (11, classified), what is **not** proven per module, the non-vacuity audit and its three
  disclosed known-unsatisfiable covers, and the provenance of the L3 verdict.
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
  Lean layer silently no-ops when the Aeneas/Charon/Lean stack is absent; and there is no committed
  raw proof-run log in the repository — every verdict in the docs is a prose transcription.

### Verification
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
