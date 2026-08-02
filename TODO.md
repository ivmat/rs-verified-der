# TODO / open issues

Tracked roadmap for `der-verified`. Grouped by theme; check items off as they land. See
`PROOF_MANIFEST.md` for what is currently proven and `DECISIONS.md` for the rationale behind each
scope boundary referenced below.

## Known limitations (verification)

- [x] **`x509_name::validate_never_panics` — RESOLVED via a modular proof (DECISIONS.md D26).** The
      monolithic harness blew up (>100 GB in CBMC symbolic execution: `set_of::cmp_padded` re-derived
      over symbolic content). Split into `validate_rdn_never_panics` (the heavy SET-OF/ATV layer at
      one-RDN scale, ~17 GB) + `validate_never_panics` stubbing `validate_rdn` with its proven
      postcondition (~510 MB). Same theorem, now compositional; `./check.sh` completes end-to-end
      (161/161 Kani at the time — now 171/171 — + the L4 lids). The same review also fixed a
      pre-existing fixed-vs-symbolic input length gap across all modular harnesses.
- [x] Record, per harness, the wall-clock/solver cost so the intractable ones are visible up front —
      [`docs/verification-cost.md`](docs/verification-cost.md) (cost tiers, the heavy `set_of` §11.6
      family, the two harnesses that need a >16 GB box, and a measured solver-selection note).

## Open, and surfaced by the 2026-07-30 proof-manifest pass

- [x] **`PROOF_MANIFEST.md` is generated from source and gated** —
      [`gates/gen_proof_manifest.py`](gates/gen_proof_manifest.py) derives every number in it, and
      `--check` runs in `check.sh`/`check_fast.sh`, and is itself tested by
      [`gates/test_gen_proof_manifest.py`](gates/test_gen_proof_manifest.py) — 18 committed tests
      covering both failure directions (over-strict: an unfamiliar toolchain must pass;
      over-lenient: a drifted count or declared pin must still fail). The five negative checks this
      line used to cite were run by hand during the pass and never committed; treat only the tests
      in that file as gated. Restructured around
      the publication checklist's five headings; now states which entry points no harness names, what
      is not proven per module, the non-vacuity audit, and the provenance of the L3 verdict.
- [x] **Ran `./check.sh` end-to-end and committed the log under `evidence/`** (2026-07-30, at commit
      `b355f76`): **164 `VERIFICATION: SUCCESSFUL`, 0 `FAILED`**, `cargo test` 309 green and the L4
      Lean gate `PASS (sorry-free)` (1704 `lake` jobs) in the same run — 52 min wall, sequential
      harnesses, `MemoryMax=22G` cgroup scope. Two artifacts per run: a distilled per-harness verdict
      log (what the generator parses) plus the complete 28 MB raw log gzipped under `evidence/raw/`,
      with the distilling `grep` and the raw log's sha256 stated in the distilled file's header, so
      the projection is checkable rather than trusted. **Exactly three harnesses reported an
      unsatisfied cover, and they are exactly the three §8.2 discloses** — one of which
      (`x509_extension`) had never previously reached a verdict at all. This closes the old
      "164/164 is not a single run at HEAD" caveat: the run covers `tag.rs` and `profile` as they
      stand. Every verdict in the docs was a prose transcription before this.
- [x] **Closed the `enumerated` cover residual, then widened the harness domain after review.** The
      harness proves an *agreement* between `decode_enumerated` and `decode_integer`, which would hold
      even if both sides only ever rejected — so it needed its own witnesses. Final shape: a 9-octet
      buffer with symbolic length `0..=9` (the wrapper's WHOLE reachable input space, not `integer`'s
      `1..=8`) and **7 of 7** covers satisfied, including `Err(Empty)` and `Err(TooLarge)` reached
      *through the delegation* — an intermediate version excluded those two lengths and explained them
      away by pointing at `integer`'s harnesses, which a second-model review correctly called stopping
      one byte short. `encode_delegates_to_integer` gained 3 covers of its own for the same reason, so
      `x509_name::validate_rdn_never_panics` is now genuinely the crate's only harness whose
      non-vacuity argument points elsewhere (`PROOF_MANIFEST.md` §8.2). Three overclaims in the first
      version's prose were retracted in the same pass — see the manifest.
- [ ] **Make the evidence reproducible on a laptop.** `./check.sh` needs ~24 GB RAM for the full Kani
      floor, which is a real adoption barrier: the re-runnable evidence *is* the product, and a
      prospective user who cannot run it gets a much weaker offer. Consider a documented
      `check_tractable.sh` (or a `--tier` flag) running the CI-sized share — the same 143 harnesses
      CI already shards — so a stranger can reproduce most of the floor on ordinary hardware, with the
      two heavy harnesses clearly marked as a large-box milestone.
- [x] **`profile` is now Kani-proven** (six harnesses; still no Lean lid, which is the remaining gap).
      It was the largest single unproven public entry point in the crate; `validate_profile` is now
      named by a harness, so the manifest's unharnessed-entry-point count drops 12 → 11. Each of the
      three RFC 5280 cross-field rules is proven as a **biconditional** (the rule fires exactly when it
      should — rule 2 over all 256 `version` values, not just 0/1/2), plus the documented precedence
      with all four violations independently symbolic, plus totality. Cheapest module in the crate:
      ~0.52 s solve, ~205 MB peak, because the harnesses take a symbolic *value* rather than a symbolic
      DER buffer — so it went into CI's `codecs-b` shard, not the heavy tier.
      Two things fell out of it: `utc_time::decode_postcondition_fields_in_range` now proves the
      decoder postcondition (`year2 <= 99`) that `profile`'s "a `Time::Utc` can never denote 2050 or
      later, by construction" was silently resting on (`UtcTime`'s fields are `pub`, and a
      hand-written `year2: 200` maps to 2100); and a missing `#[kani::unwind]` was found to mimic an
      intractable harness exactly — see `docs/verification-cost.md`.
- [ ] **A Lean lid for `profile`** — the remaining evidence gap for that module. Its harnesses are
      bounded proofs over field *values*; there is no ∀-length statement. Lower value than the codec
      lids (the module decodes nothing, so "any length" is not the axis its correctness turns on), but
      it is what keeps `profile` below the L4/L5 grade.

## Verification breadth

- [x] **A 4th L4 (Aeneas→Lean) lid — landed on `tlv` (DECISIONS.md D27).** The first L4 lid on the
      crate's structural *composition* layer (composing `tag` + `length`), not another leaf codec:
      `decode_tlv`'s structural/no-over-read correctness, ∀-length (`lean/TlvProofs.lean`). Required a
      one-line behavior-preserving source fix (`tlv.rs`'s point-free `map_err` → explicit closures, to
      unblock an Aeneas naming clash) — re-verified by Kani + tests. 7 disclosed assumed specs (2 of
      which restate an already-proved `LengthProofs.lean` fact, worked around a duplicate-extraction
      namespace collision, not new trust). `check_lean.sh` extended + confirmed non-vacuous
      (sorry-injection test). The lids now cover `length`, `big_integer`, `oid`, `tlv`; the larger
      `sequence`/consumer-walk lid (a loop over an unbounded child count) and a `tag.rs` D25-style
      refactor to fully de-opaque `decode_tag` remain open, larger, separate items.
- [x] **A 5th L4/L5 (Aeneas→Lean) lid — landed on `sequence` (DECISIONS.md D28).** The larger
      `sequence`/consumer-walk lid flagged above: `decode_sequence`'s structural/no-over-read
      correctness, ∀-length AND ∀-children (`lean/SequenceProofs.lean`) — the crate's first
      **unbounded-LOOP** lid (`tlv::decode_tlv` is itself loop-free). Required the SAME map_err
      name-clash fix as D27, this time in `sequence.rs`, plus a documented `check_lean.sh` patch step
      working around a genuine Aeneas codegen gap (the `Iterator` trait's `step_by`/`enumerate`/`take`
      defaults aren't filled for a user-defined `impl Iterator` that only defines `next`) — filled with
      Aeneas's own generic default-method combinators, inert for this lid's scope. Same 7 disclosed
      assumed specs as `tlv`'s lid (restated for the new extraction pass's namespace). `check_lean.sh`
      extended + confirmed non-vacuous (sorry-injection test, both at the `lake build` and full-gate
      level). The lids now cover `length`, `big_integer`, `oid`, `tlv`, `sequence`; a `tag.rs`
      D25-style refactor to fully de-opaque `decode_tag` remains open, a separate item.
- [x] **A 6th L4/L5 (Aeneas→Lean) lid — landed on `tag` (commit `0c2948a`).** The `tag.rs` D25-style
      refactor flagged above: `decode_tag`'s high-tag loop refactored (return-inside-loop →
      break-with-`Result`, behaviour-preserving) to unblock Aeneas extraction, then proved
      `tag_decode_total` + `tag_decode_used_bounds` ∀-length in a new `lean/TagProofs.lean`.
      **Discharged the 4 `tag_decode_*` trust-axiom instances** the `tlv`/`sequence` lids previously
      assumed about `decode_tag` (their disclosed trust surface drops from 7 axioms to 6 each). The
      lids now cover `length`, `big_integer`, `oid`, `tag`, `tlv`, `sequence` — six total.
- [ ] Add the L4/L5 Lean job to CI if a hosted runner can provision the pinned Aeneas/Charon/Lean
      stack (currently a local-milestone check — see the README).

## API / scope

- [x] **A typed / profile API layer enforcing cross-field RFC 5280 rules — first slice landed
      (commits `d65e7f0`, `6bcb8be`).** New `profile` module, built on top of (not inside) the
      structural `x509_*` parsers: `signatureAlgorithm == tbsCertificate.signature` (§4.1.1.2);
      `version` v3-required-if-extensions (§4.1.2.1/§4.1.2.9); UTCTime `≤ 2049` /
      GeneralizedTime `≥ 2050` encoding choice (§4.1.2.5). **Tested (`#[test]`) only so far — no
      Kani harness or Lean lid yet.** Still open, not yet covered by this layer: name constraints,
      key usage, basic constraints, path validation.
- [ ] `oid`: optionally materialize arcs (allocation-aware) — currently validate-only.
- [ ] **`no_std` support (later).** The crate is already `#![forbid(unsafe_code)]`, allocation-free on
      decode paths, and near-`core`-only (one `std::` use). Making it `#![no_std]` (gated on a `std`
      feature) would make a zero-dep, formally-verified DER core usable in embedded / bootloader /
      kernel contexts. Low priority; a strong differentiator when done.

## 0.1.0 release checklist

`0.0.0` is published (name reservation). For the first *real* release:

> **Reconciled 2026-07-31 against the actual tree — most of this list was already done.**
> `der-verified/Cargo.toml` already declares `version = "0.1.0"` and `rust-version = "1.70"`, and
> `lib.rs` already carries `#![deny(missing_docs)]`; 0.1.0 was published to crates.io on 2026-07-13.
> The rustdoc item listed five broken intra-doc links; four had already been fixed and the fifth
> (`profile` → the private `check_time_encoding_year`) was fixed in the profile-proofs pass, so
> `cargo doc` is now warning-free. Items are checked off accordingly rather than left implying work
> that no longer exists.

- [x] Bump `version` to `0.1.0` in `der-verified/Cargo.toml`.
- [x] **Fixed rustdoc intra-doc links** — `cargo doc --no-deps` is warning-free as of 2026-07-31.
      The last one was `profile`'s module doc linking to the private `check_time_encoding_year`.
- [x] `#![deny(missing_docs)]` is in `lib.rs`, and the crate doc carries a runnable example
      (`lib.rs`'s doctest passes in `cargo test`).
- [ ] Add `CHANGELOG.md` (Keep-a-Changelog) with the 0.1.0 entry.
- [x] MSRV declared: `rust-version = "1.70"` in `der-verified/Cargo.toml`. **Not** CI-checked
      against that exact toolchain — CI builds on the pinned channel, so the MSRV is a declaration,
      not a verified claim. That check is still open.
- [ ] Confirm CI is green on the public repo and that docs.rs builds cleanly.
- [ ] Final public-API review (0.1.0 is the API you're committing to; breaking changes still allowed
      pre-1.0 but keep it coherent).
- [x] `cargo publish` the 0.1.0. **DONE — measured 2026-08-02, not inferred.** This box's egress
      blocks the crates.io JSON API (`curl .../api/v1/crates/der-verified` → HTTP **000**), but the
      **sparse index** is reachable, and `cargo search der-verified` returns
      `der-verified = "0.1.0"`. Controlled three ways before believing it: `cargo search serde`
      returns a live current version (positive), a nonsense crate name returns **nothing**
      (negative, so it discriminates), and `--offline` **errors** with *"attempting to make an HTTP
      request"* (so it is a live query, not a cache). This item was the outlier — the `## Publishing`
      section below and line 133 both already recorded the 2026-07-13 publication, so `TODO.md`
      contradicted itself rather than contradicting the README.

## Publishing

- [x] crates.io prep done: `publish = false` removed, package metadata filled (`authors`, `readme`,
      description, license, keywords, categories), crate README added, crate name `der-verified`
      confirmed available. Version deliberately kept at `0.0.0` (name-reservation / initial release
      per owner) — bump for the first real release.
- [x] `repository` URL confirmed = `https://github.com/ivmat/rs-verified-der`.
- [x] Published `der-verified` to crates.io — 0.0.0 (name reservation) then 0.1.0 (2026-07-13).
- [x] Reproducibility: the full L3+L4 toolchain (Kani + Aeneas/Charon/Lean) was rebuilt from scratch
      and `./check.sh` is green end-to-end (2026-07-12). A pristine-container run is still nice-to-have
      before a tagged release.

## Good first issues

- [ ] More reject-differential test vectors (non-canonical encodings a lax parser would accept).
- [ ] Rustdoc usage examples per module (they double as doctests).
- [x] A "why / threat-model" writeup covering what a verified decoder buys you —
      [`docs/why-verified.md`](docs/why-verified.md).
