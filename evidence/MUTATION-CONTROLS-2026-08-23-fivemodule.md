---
type: reference
---

# Mutation controls on `octet_string`, `restricted_string`, `utf8_string`, `boolean`, `set_of` — 2026-08-23

**What this closes.** These five modules are five of the eleven targets a prior re-review sweep
over this crate's own claim inventory names as needing a functional-oracle read before a claim
grade can be assigned — until now, none of the five carried any control evidence at all (no
artifact anybody had watched fail on a real defect). This campaign supplies exactly that: one real
defect class per module, caught by the harness whose documented job is to catch it, in the same
format and under the same protocol as the 2026-08-18 and 2026-08-19 campaigns
(`evidence/MUTATION-CONTROLS-2026-08-18.md`, `evidence/MUTATION-CONTROLS-2026-08-19-oid-sequence.md`).
It does not by itself change any of the five claims' grade — that re-review is a separate, human act
(reading `PROOF_MANIFEST.md` §8.3's oracle-completeness table), not something a mutation control can
settle.

**Method — identical protocol, run LOCALLY (not a cloud VM), one solver run at a time.** For each
module: plant one subtly-wrong implementation (a real defect class, not a no-op), run the specific
harness documented to catch that class with
`cargo kani --manifest-path der-verified/Cargo.toml --harness <fq-name> --exact -Z stubbing`,
observe `VERIFICATION:- FAILED`, revert, confirm the source file is byte-identical to its
pre-mutation sha256, and re-run to confirm `VERIFICATION:- SUCCESSFUL`. Each run executed inside its
own `systemd-run --user --scope` unit: LIGHT-tier modules (`octet_string`, `restricted_string`,
`utf8_string`, `boolean`) capped at `MemoryMax=8G MemoryHigh=7G`; `set_of` (HEAVY tier, per its
prior structural-sibling-sweep classification) capped at `MemoryMax=20G MemoryHigh=18G`. Predictions
were recorded before the measurements were read (`verdicts.tsv`'s `predicted` column is authored
ahead of `observed`).

**Result, in one line: fifteen runs (5 modules × baseline/mutated/reverted), fifteen predictions
matched.** Every predicted-RED run observed `VERIFICATION:- FAILED`, every baseline/reverted leg
observed `VERIFICATION:- SUCCESSFUL`, every revert byte-identical by sha256
(`baseline-sha256.txt` == `final-sha256.txt`, line for line), and the working tree was clean
(`final-git-status.txt`, `final-git-diff-stat.txt` both empty) at the end.

## Summary table

| module | planted defect | harness | predicted | observed |
|---|---|---|---|---|
| `octet_string` | accept the BER *constructed* (segmented) form of OCTET STRING — the `if tlv.tag.constructed { return Err(Constructed) }` check commented out | `constructed_form_is_rejected` | RED | **FAILED** |
| `restricted_string` | off-by-one the `VisibleString` upper bound (`b <= 0x7E` → `b <= 0x7D`) | `charset_exactly_matches_oracle_visible` | RED | **FAILED** |
| `utf8_string` | accept UTF-16 surrogate code points (`0xD800..=0xDFFF`) — the surrogate-range rejection commented out | `validate_iff_std` | RED | **FAILED** |
| `boolean` | accept a non-canonical TRUE octet (`0x01`, BER-not-DER) alongside the canonical `0xFF` | `one_octet_is_canonical` | RED | **FAILED** |
| `set_of` | disable the §11.6 ordering check via a `false &&` short-circuit | `unsorted_children_are_rejected` | RED | **FAILED** |

Full per-run prediction/observation table: `verdicts.tsv` (15 rows). Diffs: `octetA.diff`,
`restrictedA.diff`, `utf8A.diff`, `booleanA.diff`, `setofA.diff`.

**Source-state attribution.** Every run executed against the working tree at
`3f2ee5eda183369ebf855e58af7c250684b082e6` (`der-sha.txt`), the same commit this crate's HEAD sits
at when this evidence is committed (`git diff` over the touched files between the run commit and
the commit this file lands on is empty by construction — same commit, no drift to attribute across).

**Toolchain, read from the runs' own banners:** `cargo-kani 0.67.0`, `CBMC 6.8.0 (cbmc-6.8.0)`,
solver `CaDiCaL 2.0.0` (all three banners present in every raw `.log`, none distilled).

## Reproduce

For each module: apply the module's diff (`<module>A.diff`), run
`cargo kani --manifest-path der-verified/Cargo.toml --harness <fq-name> --exact -Z stubbing`
(expect `VERIFICATION:- FAILED`), then `git checkout -- der-verified/src/<module>.rs` and confirm
the file's sha256 matches its pre-mutation value, then re-run the same harness (expect
`VERIFICATION:- SUCCESSFUL`). This directory carries only the evidence artifacts an import reads:
the 15 logs, the 5 diffs, and `verdicts.tsv`; no driver script is committed here.
