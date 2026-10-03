# Runner note

## How the controls were run

Each entry of `spec-leaf-sweep.json` is one mutation control. For every control the runner:

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

## Spec redaction

The published `spec-leaf-sweep.json` differs from the file the runner executed only in descriptive note fields that were
redacted for publication: 34 of the 86 control entries had a `provenance` string that named a path in a private
working area, and that path was replaced by a path-free phrase (for example "grading record G1"). No other field changed.

The executed fields are byte-identical to the original. Those are the fields the runner reads or records: `id`, `module`,
`src`, `old`, `new`, `red`, `green`, `predicted_assert`, `stubbing`, `timeout_s`. A script that parses both files compared the
JSON of that subset for every control, checked that the key set of every entry is unchanged, and that the only differing key
is `provenance`.

The runner does not record the sha256 of the spec in `results.jsonl` or `RESULTS.md`. The digests are stated so the
difference is not hidden:

- sha256 of the original spec, as executed: `2da8a1d5bbc33e93fd2e8eb00ac068dbf9f38e5b7ed7d6d8845944e9dc3da429`
- sha256 of the published copy in this directory: `6432eb3d6ee1aa3c0d1a0bf4f8bc82bc56c1d0a4e6b0cc8de9470279cf6b592b`
