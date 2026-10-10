# Mutation controls for `set_of` and `sequence`, 2026-10-10

Seven production mutations, run at `d68eeca`.

| id | file | what it breaks | red harness(es) |
|---|---|---|---|
| `set_of-H1-M1` | `set_of.rs` | child count off by one (`count += 2`) | `duplicate_adjacent_encodings_are_accepted` |
| `set_of-H1-M2` | `set_of.rs` | the section 11.6 ordering rejection bypassed in `decode_set_of` (production walk only) | `unsorted_children_are_rejected` |
| `set_of-H1-M3` | `set_of.rs` | iterator error mapped to the wrong `SetOfError` variant | `refactored_walk_matches_previous_walk` |
| `set_of-H1-M4` | `set_of.rs` | raw-span length derived from the cursor delta is one octet short | `unsorted_children_are_rejected` |
| `set_of-H1-M5` | `sequence.rs` (lidded; transient edit, restored byte-exact) | `Elements::next` advances one octet too little | `set_of::proofs::no_over_read` |
| `sequence-SEQ-A` | `sequence.rs` (lidded; transient) | `decode_sequence` returns `Ok(count + 1)` | `ok_implies_exact_tiling`, `roundtrip_two_children` |
| `sequence-SEQ-B` | `sequence.rs` (lidded; transient) | a malformed child ends the walk instead of returning `Element(e)` | `ok_implies_exact_tiling` (green: `roundtrip_two_children`, a survivor by design) |

`set_of-H1-M2` is the control that replaces the earlier `set_of-S3` (same mutation of the ordering comparison): after the
`Elements` refactor the old text of `set_of-S3` occurs twice in `set_of.rs` (the production walk and the proof-local copy of the previous
walk), so it cannot be applied exactly once; `set_of-H1-M2` anchors on a production-only comment line instead and applies the same
mutation to the production occurrence. `set_of-B-GW-S1` of the leaf sweep is not re-run: its anchor now exists only in the proof-local
copy of the previous walk, so it could not exercise the production code (see the re-run campaign).

`sequence-SEQ-A` and `sequence-SEQ-B` re-apply the two `sequence` mutations of
[`../MUTATION-CONTROLS-2026-08-19-oid-sequence.md`](../MUTATION-CONTROLS-2026-08-19-oid-sequence.md) (sections 3 and 4) verbatim, with the same
red and green harnesses; that campaign's own record of them stopped being current when `sequence.rs` gained the `remaining` accessor.

`sequence.rs` is one of the six lidded sources. The runner restores it from a byte copy after every control and verifies its sha256;
after the whole campaign `gates/check_lid_staleness.py` passed. No Lean re-run is owed, because the restored bytes are the bytes the Lean
lid was run on.


## Spec redaction

The spec in this directory differs from the file the runner executed in one descriptive field: the `claim` text of `set_of-H1-M2` named an internal working label, and the copy here says
"the earlier refactor-time control" instead. The executed fields (`id`, `module`, `src`, `old`, `new`, `red`, `green`, `predicted_assert`, `stubbing`, `timeout_s`) are byte-identical.
sha256 of the file as executed: `abf79ab0b32e765cb22691daa585e7a2e46b48f25f68e6a1f492c1898b3b8dc6`; sha256 of the copy in this directory: `a739e4589c53ab23b7089e32f455c53348c969ec7ac9ee9df2ad15052fd189a0`.

## How the controls were run

Each entry of the spec is one mutation control. For every control the runner:

1. verified first that the unmutated baseline of every named harness is `SUCCESSFUL`;
2. applied the mutation: the text `old` was replaced by `new` in the file `src` (`old` must occur exactly once in the pristine file);
3. ran `cargo kani [-Z stubbing] --manifest-path der-verified/Cargo.toml --harness H --exact` for each harness `H`, expecting every `red` harness to report `FAILED` and every `green` harness to stay `SUCCESSFUL`;
4. restored the source file and checked its sha256 against the pristine copy.

A control counts as `OBSERVED-RED` only when all of that held. `results.jsonl` and `RESULTS.md` hold the verdicts. Under
`<module>/<control id>/` are the applied mutation (`mutation.txt`), the verdict summary (`SUMMARY.txt`) and the gzipped Kani logs of
each red and green run; `<module>/baseline/` holds the baseline logs. All controls ran at commit `d68eeca`, sequentially, as one
memory-capped `systemd --user` service (MemorySwapMax=0; the cap is operator-attested, see below), with the verification slot held
for one control at a time. The predictions were written before any control ran:
[`../CONTROLS-PREDICTIONS-2026-10-10.md`](../CONTROLS-PREDICTIONS-2026-10-10.md).

## Reproduce one control by hand

In a clean checkout: replace the single occurrence of `old` by `new` in `src` (see the control's `mutation.txt`), run
`cargo kani [-Z stubbing] --manifest-path der-verified/Cargo.toml --harness <H> --exact` for each harness in `red` (expect `FAILED`)
and `green` (expect `SUCCESSFUL`), then `git checkout -- <src>`. `check_applicability.py <checkout> --spec <spec>` re-checks
that every `old` still anchors exactly once and that every named harness exists.

## What is not published

The orchestration script is a local tool that takes a machine-local verification-slot lock before it runs Kani, so it is not
published. The spec, the per-control `mutation.txt` and `SUMMARY.txt`, the logs and the results are published. The memory cap and
the cleanliness of the tree beyond the mutated file are operator attested; no log carries them.
