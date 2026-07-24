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
| **A cover-vacuity finding (opened or closed)** | `DER-REMAINING-WORK.md` §4, `docs/verification-cost.md`'s cover-retrofit section. |
| **A security-relevant fix or new disclosed assumption** | `SECURITY.md` if it changes reporting scope; `PROOF_MANIFEST.md`'s assumptions section. |

## How to get the authoritative numbers (don't guess, count)

```sh
# Kani harnesses (total + per-module)
grep -rE '#\[kani::proof(_for_contract)?' --include="*.rs" der-verified/src | wc -l
grep -rcE '#\[kani::proof(_for_contract)?' --include="*.rs" der-verified/src/*.rs

# Tests
grep -rE '#\[test\]' --include="*.rs" . | wc -l

# kani::assume preconditions
grep -c 'kani::assume' der-verified/src/*.rs | awk -F: '{sum+=$2} END {print sum}'

# Lean lids (the *ProofsProof files, not the extraction shims)
find lean -iname "*Proofs.lean" -not -path "*/target/*" -not -path "*/.lake/*"
grep -rn "sorry\|axiom" lean/*.lean   # spot-check sorry-freedom + the disclosed axiom set
```

Never accept a stale doc's own number as ground truth for a new doc's number — always re-derive from
source. If a count can't be re-derived cheaply (e.g. exact wall-clock/RAM figures that need a real
proof run), leave the old measurement in place but flag it as *not re-measured this pass* rather than
silently repeating it as current — see `docs/verification-cost.md` for the pattern.

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
