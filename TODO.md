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
- [x] **Make the evidence reproducible on a laptop.** `check_tractable.sh` closes this, and the claim
      is now **measured rather than asserted** (2026-08-02). The test run was deliberately *not* "record
      the peak on a 30 GB box" — that answers the wrong question. It was run under a cap set to a
      modest laptop, because what a stranger needs to know is whether it *completes* on their machine:
      ```
      systemd-run --user --scope -p MemoryMax=8G -p MemoryHigh=7G -p MemorySwapMax=0 -- sh ./check_tractable.sh
      Complete - 143 successfully verified harnesses, 0 failures, 143 total.
      Elapsed (wall clock): 6:15.29     Maximum resident set size: 2,838,608 KB (2.71 GB)     rc=0
      ```
      **2.71 GB peak, 6m15s, 143/143** — comfortably inside the 8 GB cap and well under the script's own
      "~7 GB" estimate, so the header comment is conservative rather than optimistic. The one disclosed
      unsatisfied cover appeared exactly once, as `PROOF_MANIFEST.md` §8.2 predicts; more would have been
      a new finding. ⚠ Still the LIGHT tier only — a green run here is the CI-sized share, **not** the
      full floor, which remains a large-box milestone (`gates/tiers.txt`, gated by
      `gates/check_tier_parity.py`).
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
      ⊕ **SCOPED 2026-08-03. The `if` is the whole item, and it now has numbers.** Installed footprint
      on the reference box: **1.8 GB** for Aeneas+Charon and **2.7 GB** for the Lean toolchain under
      `elan` — ~4.5 GB, which fits a standard hosted runner's disk. Size is not the obstacle. The
      obstacle is that both pins are built *from source* (Charon in Rust, Aeneas in OCaml), so without
      a warm cache every run pays that build before it proves anything.
      ⚠ **And the honest blocker is not cost, it is verifiability.** A CI workflow cannot be exercised
      on this box, and pushing to the public repo is owner-gated — so writing the job would produce a
      gate whose failing direction has never been seen, on a repo whose whole claim is that its checks
      are re-runnable. This crate has already been bitten twice by exactly that (`check_kb`-style
      vacuity, and the L4 lid sitting UNRUN for four commits — see `evidence/FLOOR-2026-08-03.md` §3).
      **A green that has never been watched to go red is not the deliverable here.** Land it in a
      session that can push and watch a real run fail.

## API / scope

- [x] **A typed / profile API layer enforcing cross-field RFC 5280 rules — first slice landed
      (commits `d65e7f0`, `6bcb8be`).** New `profile` module, built on top of (not inside) the
      structural `x509_*` parsers: `signatureAlgorithm == tbsCertificate.signature` (§4.1.1.2);
      `version` v3-required-if-extensions (§4.1.2.1/§4.1.2.9); UTCTime `≤ 2049` /
      GeneralizedTime `≥ 2050` encoding choice (§4.1.2.5). **Tested (`#[test]`) only so far — no
      Kani harness or Lean lid yet.** Still open, not yet covered by this layer: name constraints,
      key usage, basic constraints, path validation.
- [ ] `oid`: optionally materialize arcs (allocation-aware) — currently validate-only.
      ⊕ **SCOPED 2026-08-03 — this is a DESIGN decision, not a task, and it collides with two others.**
      Materializing arcs needs `alloc`. The crate's own module docs already rule that out in terms:
      `x509_name.rs` says an owned tree *"would need `alloc` … which this heap-free crate forbids"*,
      and `big_integer` is deliberately built on the same "validate, don't materialize" stance. So
      this item cannot be implemented without either breaking that invariant or introducing an
      `alloc` feature gate — and an `alloc` gate interacts directly with the `no_std` item below and
      with what "allocation-free decode paths" means in the README's offer. **Owner's call on the
      crate's shape, not something to land quietly under a checkbox.**
- [ ] **`no_std` support (later).** The crate is already `#![forbid(unsafe_code)]`, allocation-free on
      decode paths, and near-`core`-only (one `std::` use). Making it `#![no_std]` (gated on a `std`
      feature) would make a zero-dep, formally-verified DER core usable in embedded / bootloader /
      kernel contexts. Low priority; a strong differentiator when done.
      ⊕ **SCOPED 2026-08-03, deliberately NOT landed.** "Later" is not a size, so it was measured:
      * **Exactly one `std::` path in all of `der-verified/src`** — `utf8_string.rs:507`, inside a
        `#[test]` assertion *message*, not library code.
      * **All 25 `Vec`/`String`/`vec!`/`Box` occurrences are inside `#[cfg(test)]` modules** (test
        builders like `der_length`, `wrap`, `build_certificate`). None is reachable from a non-test
        build. Zero dependencies; no `std::error`, no `std::io`.
      * **26 `#[cfg(test)]` modules and 26 `#[cfg(kani)]` proof modules, and they are disjoint** — so
        `#![cfg_attr(not(test), no_std)]` would put the Kani floor on the *shipped* configuration,
        not on a std one.
      * **The claim would be checkable, which it was not before today:** `thumbv7em-none-eabi` is now
        installed here, so `cargo build --target thumbv7em-none-eabi` is a gate that fails the moment
        anything pulls `std` back in — the same shape of fix the MSRV declaration got.
      ⛔ **Why not landed:** it is a source change, and the L3 floor **cannot currently be run to
      completion on this box** (`evidence/FLOOR-2026-08-03.md`: OOM-killed at the computed 20 GiB cap,
      below this crate's own documented ~22 GiB requirement). Landing source now would leave the crate
      with *weaker* proof evidence than it has, to buy a capability nothing is waiting on.
      ⚠ Unsettled, and the reason the change must carry its own guard: **whether `cargo kani` sets
      `cfg(test)`**. If it ever did, `#![cfg_attr(not(test), no_std)]` would silently verify the std
      configuration. Ship it with `#[cfg(all(kani, test))] compile_error!(...)` rather than resting on
      the assumption.

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
- [x] Add `CHANGELOG.md` (Keep-a-Changelog) with the 0.1.0 entry. **Was already done and this line
      was stale** — `CHANGELOG.md` was added by the release commit `1b2dc54` ("release: der-verified
      0.1.0") itself, carries the Keep-a-Changelog header and SemVer statement, and has `[0.1.0]`,
      `[0.0.0]` and `[Unreleased]` sections with release-tag links. Closed by looking, 2026-08-03.
      Second item in three days that was parked while being answerable in one command.
- [x] MSRV declared: `rust-version = "1.70"` in `der-verified/Cargo.toml`. **Not** CI-checked
      against that exact toolchain — CI builds on the pinned channel, so the MSRV is a declaration,
      not a verified claim. That check is still open.
- [x] Confirm CI is green on the public repo and that docs.rs builds cleanly. **Measured
      2026-08-03.** Public CI: the `CI` workflow's most recent run is `conclusion: success` on
      `f6bda7b`, which is HEAD — so the green is *at* HEAD, not merely somewhere in history; the five
      most recent runs are all `success`. docs.rs: `https://docs.rs/crate/der-verified/0.1.0/status.json`
      returns `{"doc_status":true,"version":"0.1.0"}` (HTTP 200), and `0.0.0` likewise. Locally
      `cargo doc --no-deps` is warning-free.
      ⊕ **CLOSED 2026-08-03 (later) — the failing direction IS now exhibited.** The warning this
      line used to carry was right: the probe had only ever been seen say `true`. Fixed by
      measurement, not by relabelling. docs.rs publishes its own list of recent FAILED builds at
      `https://docs.rs/releases/failures`; `status.json` for four crates taken from it returns
      **HTTP 200 with `"doc_status":false`** — `core-nightly/2015.1.7`, `deno/2.9.4`,
      `bevy_wgpu/0.5.0`, `polars-lazy/0.54.4`. So the probe discriminates **three** states, not two:
      built-clean (`200` + `true`), built-and-FAILED (`200` + `false`), and nonexistent (no response
      at all). `der-verified` 0.1.0 and 0.0.0 both return `200` + `true` against that control.
      Evidence: `evidence/docsrs-probe-2026-08-03.log`.
      ⚠ Two residuals, stated rather than glossed: the `false` cases are *other people's* crates, so
      what has been watched to fail is the **probe**, not this crate's docs build; and the HTTP `000`
      on a nonexistent version is **this box's egress behaviour**, not a documented docs.rs response
      — on a box with unrestricted egress that case is likely a 404, and that path is untested here.
- [ ] Final public-API review (0.1.0 is the API you're committing to; breaking changes still allowed
      pre-1.0 but keep it coherent).
      ⊕ **Confirmed 2026-08-03 as owner-gated, not worked.** It is a judgement about what the crate
      commits to, and it is the one remaining item that is *supposed* to sit with a person. Flagged
      because it now has a deadline shape it did not have: the stated next application target is
      Open Internet Stack with this crate as the exhibit.
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

- [x] More reject-differential test vectors (non-canonical encodings a lax parser would accept).
      **Done 2026-08-03 — 309 → 320 tests.** ⚠ **The headline result is how little was missing.** A
      module-by-module sweep of the obvious BER-versus-DER divergences — non-minimal long-form
      lengths, indefinite length, non-minimal INTEGER/ENUMERATED, BOOLEAN content outside
      `0x00`/`0xFF`, BIT STRING unused-bit rules, non-minimal or unterminated OID arcs, SET OF
      ordering and duplicates, UTCTime/GeneralizedTime fractional seconds and non-`Z` zones,
      non-shortest UTF-8, trailing bytes — found **every one already covered**, usually by a concrete
      vector *and* an independent Kani oracle.
      The real gap was narrower and structural: `octet_string` alone had *concrete* specimens for a
      **non-minimal high-tag identifier** (§8.1.2.4.2) and a **non-minimal long-form length**
      (§8.1.3) reaching it through its own public entry point. Both properties are proven generically
      for all TLVs by `tag`/`length` harnesses, but no sibling TLV-composing module exercised them at
      its own door. The 11 new vectors close that for `utf8_string`, `restricted_string`, `sequence`,
      `set_of`, `context_tag`, `x509_extension` and `x509_algorithm_identifier`.
      Each asserts the **exact** error variant, never `.is_err()`. Controlled by feeding
      `set_of::rejects_non_minimal_length` the *canonical* `31 00` instead of the non-minimal
      `31 81 00`: it fails with `left: Ok(([], 2))`, so the test discriminates non-minimal from
      minimal rather than rejecting everything. **No crate defect found** — nothing accepted anything
      DER forbids.
- [x] Rustdoc usage examples per module (they double as doctests). **Done 2026-08-03 — 1 doctest →
      27.** Every one of the 26 modules outside `lib.rs` gained a `# Examples` block in its `//!`
      documentation. The byte specimens are lifted from each module's own passing `#[cfg(test)]`
      fixtures rather than invented, so an example cannot assert a DER encoding the crate's own tests
      do not already agree with.
      **Watched to fail before being trusted:** every example is self-checking (each carries at least
      one `assert`), and flipping a single expected value in `boolean`'s example takes the suite to
      `26 passed; 1 failed`, rc=101 — so `27 passed` is a real check and not a compile-only pass.
      Documentation-only: all **414** inserted lines are `//!` lines and there are zero deletions, so
      no body, signature, test or `#[kani::…]` harness moved. `cargo doc --no-deps` stays
      warning-free, `cargo clippy --all-targets -D warnings` is rc=0, and `check_fast.sh` (hygiene +
      proof-manifest self-test + proof-manifest gate + workspace tests) is rc=0.
- [x] A "why / threat-model" writeup covering what a verified decoder buys you —
      [`docs/why-verified.md`](docs/why-verified.md).
