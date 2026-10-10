# Re-run of the leaf-sweep controls whose files changed, 2026-10-10

34 controls of the 2026-10-03 leaf sweep (`utc_time` 8, `profile` 21 including its L4 group, `set_of` 5), re-run
unchanged at `d68eeca`. They were re-run because the engine's carry-over rule is whole-file: `profile.rs`, `utc_time.rs` and
`set_of.rs` differ in bytes between the sweep's commit and `d68eeca` (`profile.rs` and `utc_time.rs` in doc comments only; `set_of.rs`
by the `Elements` refactor), so the 2026-10-03 observations no longer attribute to the shipped bytes.

The spec is the published 2026-10-03 leaf spec restricted to these modules, byte-for-byte per entry, except two controls that are not
re-run:

- `set_of-S3`: its `old` text occurs twice after the refactor (see `../controls-set-of-sequence-2026-10-10/README.md`); superseded by `set_of-H1-M2`.
- `set_of-B-GW-S1`: its `old` text (`let this = &content[off..off + used];`) now exists only in `previous_decode_set_of`, the proof-local copy of the
  previous walk. A mutation there cannot be seen by the production-facing red harness `ordering_matches_whole_encoding_oracle`, so the control
  was not run (it would be a known survivor, not a control). Not re-derived.


## Spec

The executed spec and the copy in this directory are the same bytes (sha256 `c3dda631613cf7df2dfa5b86c332677c19d1f1cc2fdc6e6ff1b5808e4c740ff9`).

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
