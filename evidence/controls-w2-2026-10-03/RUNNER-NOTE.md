# Runner note

## How the controls were run

Each entry of `spec-w2.json` is one mutation control. For every control the runner:

1. verified first that the unmutated baseline of every named harness is `SUCCESSFUL`;
2. applied the mutation: the text `old` was replaced by `new` in the file `src` (`old` must occur exactly once);
3. ran `cargo kani --manifest-path der-verified/Cargo.toml --harness H --exact` for each named harness `H`
   (with `-Z stubbing` where the entry sets `stubbing`), expecting every `red` harness to report `FAILED` and every
   `green` harness to stay `SUCCESSFUL`;
4. restored the source file and checked its sha256 against the pristine copy.

A control counts as `OBSERVED-RED` only when all of that held. `results.jsonl` and `RESULTS.md` hold the verdicts.
Under `<module>/<control id>/` are the applied mutation (`mutation.txt`), the verdict summary (`SUMMARY.txt`) and the
gzipped Kani logs of each red and green run; `<module>/baseline/` holds the baseline logs.

## What is not published

The orchestration script is a local tool that takes a machine-local verification-slot lock before it runs Kani, so it is not
published. The spec, the per-control `mutation.txt` and `SUMMARY.txt`, the logs and the results are published.
`check_applicability.py` (a static check that each `old` still anchors exactly once in `src`) is published.

## Reproduce one control by hand

In a clean checkout: replace the single occurrence of `old` by `new` in `src` (see the control's `mutation.txt`), run
`cargo kani [-Z stubbing] --manifest-path der-verified/Cargo.toml --harness <H> --exact` for each harness in `red` (expect
`FAILED`) and `green` (expect `SUCCESSFUL`), then `git checkout -- <src>`.

`spec-w2.json` is published exactly as executed (no redaction).
