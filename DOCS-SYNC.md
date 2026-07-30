# Docs-sync checklist

**Rule: any code/proof/feature change MUST be accompanied by a docs-sync pass in the same change (or
the next one, immediately) — not deferred indefinitely.** This crate's whole pitch is "the proofs are
the product, not a badge"; a stale count or an undocumented capability quietly breaks that promise for
anyone reading the docs instead of re-running `./check.sh`. Docs are part of the deliverable, not an
afterthought.

**Honesty rule, always:** never invent a number. If you can't confirm a count by grepping/counting the
actual source, mark it `≈`/TODO rather than assert it. Counts in this crate's docs are *inventory*, not
a coverage guarantee (`PROOF_MANIFEST.md`'s own framing) — keep that distinction sharp whenever you
edit a count.

## Quick lookup: change → docs to touch

| Kind of change | Docs to update |
|---|---|
| **Kani harness added/removed** (any module) | Re-count with `grep -rE '#\[kani::proof(_for_contract)?' der-verified/src` and update the total + per-module count in: `README.md` (top bullet + CI section if the module's shard changed), `der-verified/README.md`, `PROOF_MANIFEST.md` (top note, "L3 floor" bullet, per-module inventory table, and the assumption count if `kani::assume` changed too), `docs/why-verified.md`, `docs/verification-cost.md` (cost tiers table if the harness is slow/heavy). |
| **`#[test]` added/removed** | Re-count with `grep -rc '#\[test\]'` and update the total in: `README.md`, `der-verified/README.md`, `PROOF_MANIFEST.md` (top note + "tests are not proofs" footer), `docs/why-verified.md`. |
| **New Lean lid (or a lid's trust-axiom count changes)** | `PROOF_MANIFEST.md` (the L4/L5 table — add a row; update the "N codecs" framing in the section header and the top inventory note; update the axiom-count prose on any *other* lid whose trust surface changed as a side effect — e.g. de-opaquing a shared dependency), `README.md` (L4/L5 bullet + "Verify it yourself" section 2 heading), `der-verified/README.md`, `docs/why-verified.md`, `der-verified/src/lib.rs`'s crate-doc "Verification" paragraph, `TODO.md` (check off / log the item), `DER-REMAINING-WORK.md` (append an UPDATE block, don't rewrite history). |
| **New module/feature** (e.g. a new codec, a new validation layer) | `README.md` scope section, `der-verified/README.md` scope section, `PROOF_MANIFEST.md` (add to per-module inventory table; if it's NOT backed by Kani/Lean, say so explicitly — don't let a tested-only feature borrow the crate's proof-grade framing), `der-verified/src/lib.rs` crate-doc module list, `CHANGELOG.md` (`[Unreleased]` entry), `DER-REMAINING-WORK.md` / `TODO.md` (roadmap — check off if it closes an open item, add follow-ups if it doesn't fully close it). |
| **Trust-axiom count changes on an existing lid** (e.g. de-opaquing a shared dependency) | `PROOF_MANIFEST.md`'s L4/L5 table entry for every lid that shares the affected axiom (check ALL lids that reference it, not just the one you touched), `CHANGELOG.md`. |
| **CI shard / sharding change** (`.github/workflows/ci.yml`) | `README.md`'s "Continuous integration" section (harness counts per shard, heavy-tier module list) — re-derive shard totals from the current per-module Kani counts, don't just trust the old number. |
| **Any scope narrowing/decision** (a design fork, a deliberate limitation) | `DECISIONS.md` (new dated `## Dxx` entry, append-only — never edit past entries' content, only add), `PROOF_MANIFEST.md`'s "Deliberate deviations" / "What is NOT proven" sections if it changes the fence. |
| **A cover-vacuity finding (opened or closed)** | The `// VACUITY-DISCLOSED:` registry line in the module (see below — the gate counts these), `DER-REMAINING-WORK.md` §4, `docs/verification-cost.md`'s cover-retrofit section. |
| **Anything the manifest gate covers** (harness, `pub fn`, bound, stub, cover, lid, pin) | Run `python3 gates/gen_proof_manifest.py --write`; it rewrites `PROOF_MANIFEST.md`'s generated regions. Then read the diff — the *prose* claims around the regenerated numbers are hand-written and the script cannot update them for you. |
| **A security-relevant fix or new disclosed assumption** | `SECURITY.md` if it changes reporting scope; `PROOF_MANIFEST.md`'s assumptions section. |

## How to get the authoritative numbers (don't guess, and don't hand-grep either)

**One command. It is the source of truth for every count in this repo's docs:**

```sh
python3 gates/gen_proof_manifest.py --json     # all derived facts, per module and crate-wide
python3 gates/gen_proof_manifest.py --write     # regenerate PROOF_MANIFEST.md's generated regions
python3 gates/gen_proof_manifest.py --check     # the gate (runs in check.sh + check_fast.sh)
```

It derives, from source: harness counts (total and per module), `pub fn` entry points and which of
them no harness names, symbolic buffer widths, unwind depths, `kani::assume` counts split into
harness preconditions vs stub-body postconditions, `kani::cover` counts, `#[kani::stub]`
applications, the disclosed cover-vacuity registry, Lean lid theorem and axiom counts, toolchain
pins, and the `#[test]` total.

**Do not go back to hand-grepping.** The naive greps this file used to recommend are wrong in ways
that are invisible until someone checks:

- `grep -rE '#\[test\]' . | wc -l` counts `#[test]` **mentioned inside doc comments** — `lib.rs`
  has exactly one such mention, so the naive grep says 310 where `cargo test` runs 309.
- `grep '#\[kani::unwind(' | wc -l` likewise counts unwind depths quoted in prose (12 such
  mentions), and the attribute may sit either above or below `#[kani::proof]`.
- `grep 'kani::cover'` counts prose mentions too (2 of them).

The script strips comment lines before counting, and every one of these cases is covered by its
negative tests. If you need a number it does not derive, **add it to the script** rather than
grepping by hand — that is the point.

Never accept a stale doc's own number as ground truth for a new doc's number. If a count can't be
derived cheaply (exact wall-clock/RAM figures need a real proof run), leave the old measurement in
place but flag it as *not re-measured this pass* rather than silently repeating it as current — see
`docs/verification-cost.md` for the pattern.

### The count-claim guard

`--check` also scans `README.md`, `der-verified/README.md`, `docs/*.md`, `PROOF_MANIFEST.md` and
`der-verified/src/lib.rs` for count-claims in prose (`"164 Kani harnesses"`, `"309 tests"`,
`"six codecs"`, …) and fails if any disagrees with source. So a stale count in a secondary document
now breaks the gate instead of quietly misinforming a reader. `CHANGELOG.md`, `DECISIONS.md` and
`DER-REMAINING-WORK.md` are deliberately **not** guarded: they are dated, append-only records where
a historical count is correct *as history*.

If you add a new prose phrasing for a count, add its pattern to `GUARDS` in the script.

### Disclosing a cover-vacuity finding

A harness whose `kani::cover` is known-unsatisfiable at its bound must carry, next to the narrative,
one declarative line the script can count:

```rust
// VACUITY-DISCLOSED: <finding harness> -> witness <positive-construction harness>
```

Kani reports such a harness as `VERIFICATION: SUCCESSFUL` with `0 of 1 cover properties satisfied`
— it does **not** fail. Without this registry the gap is invisible to every gate, and
`PROOF_MANIFEST.md` would silently understate it.

## Append-only documents — don't rewrite history

`DECISIONS.md` and `DER-REMAINING-WORK.md` are dated, point-in-time records (a decisions ledger and a
work-status log, respectively). When their content goes stale, **append an `UPDATE <date>` note**
pointing at what changed, rather than editing the old prose to read as if it were always current. This
preserves the audit trail. `CHANGELOG.md` follows Keep-a-Changelog: put unreleased work under
`## [Unreleased]`, never edit a shipped version's entry.

## Docs in scope for a sync pass

`README.md` · `der-verified/README.md` · `PROOF_MANIFEST.md` (the most important — the honest proof
envelope) · `CHANGELOG.md` · `DER-REMAINING-WORK.md` · `TODO.md` · `DECISIONS.md` · `SECURITY.md` ·
`docs/verification-cost.md` · `docs/why-verified.md` · `der-verified/src/lib.rs`'s crate-level doc
comment (module list + "Verification" paragraph) · each module's own doc comment, if the change
affects that module's claims specifically.
