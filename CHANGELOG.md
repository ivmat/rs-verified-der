# Changelog

All notable changes to `der-verified` are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to
[Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Documentation / assurance process
- **`paper/der-verified.tex` brought back in sync with `PROOF_MANIFEST.md`.** The artifact/experience
  paper had drifted to a snapshot from before the `tag`/`tlv`/`sequence` L4 lids landed: it said
  "three L4 lids" and "161 harnesses" throughout. Now says six lids (`length`, `big_integer`, `oid`,
  `tag`, `tlv`, `sequence`, with theorem names in the L4 table and a note on the `tag` refactor
  discharging four trust-axiom instances from `tlv`/`sequence`, 7→6 each), 171 Kani harnesses across
  26 modules, 320 tests, 136 `kani::assume` preconditions, seven stub applications across four
  harnesses (was "four stubs across three harnesses"), a mention of the `profile` module in the scope
  paragraph, and a sentence on the D29 per-commit lid-staleness tripwire. No `pdflatex`/`tectonic` was
  available to recompile; `paper/README.md` now says the checked-in `der-verified.pdf` is stale
  relative to the `.tex` and must be recompiled before any Zenodo upload.
- **Added a per-commit tripwire for Lean-lid source drift** (`gates/check_lid_staleness.py` +
  `lean/lid-source-state.txt`, wired into `check_fast.sh`/`check.sh`): the six Aeneas-extracted
  source files can silently break the extracted Lean model on any edit, but the gate that catches
  it only ran at milestones — this closes the per-commit gap without claiming to re-verify
  anything through Lean itself (see DECISIONS.md D29).
- **The count-claim guard was passing over three stale counts, one of them in the crates.io README.**
  Adding 11 tests (309 → 320) surfaced it: `--check` reported PASS while `README.md`,
  `der-verified/README.md` and `docs/why-verified.md` all still said 309. Two independent causes, both
  invisible from the gate's own output. A number written as `- **309** unit and regression tests` puts
  markdown emphasis between the number and the space, so the guard's `\s+` could not match — that is
  the crate's headline assurance figure, in its two most-read files. And `docs/why-verified.md` says
  *"concrete and regression tests"* where the guard only knew *"unit and regression tests"* — a guard
  is a fixed phrase list, so a synonym is simply invisible to it. `NUM` now consumes a trailing
  emphasis marker and the wording variant is a guard of its own; the crates.io README was found *by*
  the widened guard rather than by hand. Each of the three was then re-staled individually and the
  gate went rc=1 on each. ⚠ **The general lesson is recorded in `DOCS-SYNC.md` and is not fixed:** the
  gate's PASS line counts the *documents* it scanned, not the claims it covered, so it must never be
  read as coverage of every number in those documents.
- **Every module now carries a runnable usage example: 1 doctest → 27.** All 26 modules outside
  `lib.rs` gained a `# Examples` block in their module documentation. The byte specimens are lifted
  from each module's own passing `#[cfg(test)]` fixtures rather than invented, so an example cannot
  assert an encoding the crate's own tests do not already agree with — which matters more here than
  in most crates, since a wrong "example" of a DER encoding is a wrong claim about X.690. Every
  example is self-checking; flipping one expected value takes the suite to `26 passed; 1 failed`, so
  the green is a check rather than a compile. Documentation-only: 414 inserted lines, all `//!`, zero
  deletions, no proof or behaviour touched.
- **A second full-gate run is committed, at HEAD: `evidence/check-28e1429.log`** — 171
  `VERIFICATION: SUCCESSFUL`, 0 `FAILED`, `cargo test` green, L4 Lean `PASS (sorry-free)` in the same
  pass, 91 min wall under a `MemoryMax=22G` cgroup scope. The three unsatisfied covers are again
  exactly the three §8.2 discloses — the second independent confirmation of that table.
- **"Does a committed run still speak for HEAD?" is now derived instead of written down.** It was a
  hand-written sentence naming specific commits, which had to be rewritten at the next run and rots
  toward *over*-claiming. It is now computed as `git diff <run-commit>..HEAD -- der-verified/src lean`
  being empty, and rendered in a new **advisory** region: a docs, gate or CI commit after a run no
  longer invalidates it, and a source commit does, with no prose to remember. Advisory rather than
  gate-enforced because it needs git history that a tarball or shallow clone may lack — the same test
  `pins-observed` meets, and keeping it out of the enforced set is what stops `./check.sh` depending
  on the reader's environment again. Every count in the evidence table stays enforced, since those are
  read out of the committed log itself. Gated by 7 new tests (27 total), including that the region
  stays advisory, that a run with `FAILED` verdicts never counts as speaking for HEAD, and that an
  unanswerable git query reports "unknown" rather than defaulting to yes.
- **Fixed an order-dependence bug in the gate's own test suite.** Two mutation tests restored
  `ADVISORY` to a *hardcoded* literal instead of the value they captured, so any legitimate change to
  that set silently reverted mid-run and failed a later test — the failure appearing in the wrong
  place entirely. Both now capture and restore.
- **The proof-manifest gate no longer fails for third parties, and now has its own test set.**
  `gates/gen_proof_manifest.py --check` byte-compared the manifest's "Observed on the machine that
  last regenerated this section" line, which reports the ambient rustc/Kani/Aeneas/Charon — none of
  which a reader can reproduce. Anyone whose rustc differed from ours (or who had not installed
  Kani or Aeneas) therefore failed `./check.sh` at the manifest gate **before any proof ran**, and
  was told the manifest was "stale" and to run `--write` — which would have silently rewritten the
  recorded pins for a source change that never happened. Bad for a crate whose pitch is "re-run the
  evidence yourself". That sentence now lives in its own `pins-observed` region, regenerated by
  `--write` but not gate-enforced, and labelled in the manifest as provenance rather than a pin; the
  *declared* pins (channel, Kani version, Lean toolchain, Aeneas/Charon revisions, extract nightly)
  are read from in-tree files and stay fully enforced. `--check` failures now name the disagreeing
  region and print the differing lines instead of claiming blanket staleness. New
  `gates/test_gen_proof_manifest.py` (18 tests, pure stdlib, wired into `check.sh`/`check_fast.sh`)
  gates both directions: an unfamiliar toolchain must not fail the gate, and a drifted count, a
  drifted declared pin, a widened advisory set or a missing region marker must still fail it — the
  last four asserted on `--check`'s exit code, not just on its internals. Three of the tests are
  **mutation checks**: they break the gate on purpose (revert the fix, short-circuit the region
  comparison, widen the advisory set) and require named tests to catch each mutant, so the test set
  cannot quietly go vacuous either.
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
- **11 reject-differential vectors, and the finding is how few were missing.** A module-by-module
  sweep of the BER-versus-DER divergences a lax parser would wave through — non-minimal long-form
  lengths, indefinite length, non-minimal INTEGER/ENUMERATED, BOOLEAN content outside `0x00`/`0xFF`,
  BIT STRING unused-bit rules, non-minimal or unterminated OID arcs, SET OF ordering and duplicates,
  UTCTime/GeneralizedTime fractional seconds and non-`Z` zones, non-shortest UTF-8, trailing bytes —
  found **every one already covered**, usually by a concrete vector *and* an independent Kani oracle.
  The genuine gap was structural rather than a missing rule: only `octet_string` had *concrete*
  specimens driving a **non-minimal high-tag identifier** (X.690 §8.1.2.4.2) and a **non-minimal
  long-form length** (§8.1.3) through its own public entry point. Both hold generically for all TLVs
  by the `tag`/`length` harnesses, but no sibling TLV-composing module exercised them at its own door,
  so a composition regression would have been caught only one layer down. Now closed for
  `utf8_string`, `restricted_string`, `sequence`, `set_of`, `context_tag`, `x509_extension` and
  `x509_algorithm_identifier`. Each asserts the exact error variant, never `.is_err()`. Tests 309 →
  **320**. **No crate defect found** — nothing accepted anything DER forbids.
- **`profile` is now Kani-proven — six harnesses, and the shape of the statements is the point.** The
  typed RFC 5280 profile layer was `#[test]`-only and was the largest single unproven public entry
  point in the crate. Each of its three cross-field rules is now proven as a **biconditional** (the
  rule fires *exactly* when the RFC says it should, so neither a missing check nor an over-eager one
  passes), with rule 2 ranging over all 256 `version` values rather than 0/1/2. A fourth harness pins
  the documented **precedence** between the rules with all four violations independently symbolic; a
  fifth proves totality; a sixth proves the §4.1.2.5.1 `1950..=2049` window that rule 3's
  impossible-by-construction half rests on. `validate_profile` is now named by a harness, so the
  manifest's unharnessed-entry-point count drops 12 → 11. Still **no Lean lid** — these are bounded
  proofs over field values, not ∀-length statements, and `PROOF_MANIFEST.md` §7 keeps that boundary
  explicit. Harness total 164 → **171**, covers 52 → **75**, modules with harnesses 25 → **26**.
- **Cheapest module in the crate, by design:** ~0.52 s total solve time, ~205 MB peak RSS. `profile`
  decodes nothing, so its harnesses take a symbolic *value* rather than a symbolic DER buffer plus a
  parse — which is why it joins CI's `codecs-b` shard (CI coverage 135 → **143** of 171 harnesses)
  instead of the heavy local-milestone tier.
- **Closed an assumption that was holding up a "by construction" claim.**
  `utc_time::decode_postcondition_fields_in_range` proves, over symbolic content, that every `UtcTime`
  the decoder returns has all six fields in canonical range — in particular `year2 <= 99`.
  `full_year_pivot_is_correct` *assumes* that bound, and `profile` relies on the consequence ("a
  `Time::Utc` can never denote a year >= 2050"); since `UtcTime`'s fields are `pub`, a hand-written
  `UtcTime { year2: 200, .. }` maps to `2100`, so the claim was sound only for decoder-produced values
  and nothing stated that as a proved property. It now composes into an unconditional statement about
  decoder output, with the hand-constructed case disclosed rather than implicit.
- **Hardened the `enumerated` delegation harness after a second review, and retracted three
  overclaims.** The harness domain widened from `1..=8` to the wrapper's whole reachable input space
  (a 9-octet buffer, symbolic length `0..=9`), so `Err(Empty)` and `Err(TooLarge)` are now **witnessed
  through the delegation** instead of excluded and explained away by pointing at `integer`'s
  harnesses: **7 of 7** covers satisfied. `encode_delegates_to_integer` gained 3 covers of its own,
  which makes the manifest's "only harness whose non-vacuity points elsewhere" claim true rather than
  refutable from the same diff. Retracted: that each cover individually refutes a do-nothing body (a
  constant `Ok(0)` satisfies the positive-width ones — it is the *set* plus the assert that does the
  work); that the `n == 8` cover shows the accumulator loop runs eight times (it shows an 8-octet
  slice was accepted); and that a negative value was witnessed at full width (its cheapest witness was
  `[0x80]` at `n == 1`, hence an added `&& n == 8`).
- **A tractability trap worth knowing: a missing `#[kani::unwind]` is indistinguishable from an
  intractable harness.** `profile::rule1` compares two `Option<&[u8]>` fields; unbounded, it sent CBMC
  into `memcmp` unwinding past 18,000 iterations until the run was OOM-killed — the same symptom as a
  genuinely heavy harness. With `#[kani::unwind(4)]` it verifies in 0.119 s, and CBMC's own unwinding
  assertion (a checked property) confirms 4 suffices, so the bound costs no generality. Documented in
  `docs/verification-cost.md`.
- **The full proof floor is now a committed artifact rather than a prose transcription.**
  `./check.sh` ran end-to-end at commit `b355f76` (2026-07-30) and the log is in the repository under
  `evidence/`: **164 `VERIFICATION: SUCCESSFUL`, 0 `FAILED`** over all 164 harnesses run
  sequentially, plus `cargo test` (309 + 1 doctest) and the L4 Lean gate `PASS (sorry-free)`
  (1704 `lake` jobs) in the same pass — 52 min wall under a `MemoryMax=22G` cgroup scope. Each run
  commits two files: a distilled per-harness verdict log, which `gates/gen_proof_manifest.py` reads
  to populate the manifest's run-evidence table, and the complete 28 MB raw log gzipped under
  `evidence/raw/`, so the distillation is checkable instead of trusted (the distilling `grep` and the
  raw log's sha256 are stated in the distilled file's header). Before this, every full-suite verdict
  in the docs was transcribed by hand.
- **The disclosed-vacuity table is now machine-confirmed.** Exactly three harnesses reported
  `0 of 1 cover properties satisfied`, and they are exactly the three `PROOF_MANIFEST.md` §8.2
  discloses — nothing undisclosed appeared, and no disclosed gap had quietly become satisfiable.
- **`x509_extension::validate_extensions_never_panics`'s cover status is resolved: UNSATISFIED.** It
  was previously the one cover in the crate whose status was *not determined* — the harness had only
  ever OOM-ed past the slicing/SSA stage under both `cadical` and `kissat`, so
  `docs/verification-cost.md` logged it as unknown rather than claiming either way. It reached a
  verdict in this run and joins the other two disclosed known-unsatisfiable covers.
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
