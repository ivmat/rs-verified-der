# Re-run of the x509_extension controls, 2026-10-10

The ten `x509_extension` controls of the 2026-10-03 W2 campaign (`M-EXT-1` to `M-EXT-10`), re-run unchanged at `d68eeca`.
`x509_extension.rs` differs in bytes from the earlier commit (doc comments only), and the engine's carry-over rule is whole-file, so the earlier
observations do not attribute to the shipped bytes. The spec is the published 2026-10-03 W2 spec restricted to `x509_extension`, byte-for-byte per entry.
These ran with a 24G cap in the owner-named window (`CONTROLS_MEM=24G`); all ten completed within it.


## Spec

The executed spec and the copy in this directory are the same bytes (sha256 `5483507a1e277b3e2b4ca73b42b070462c38bc31bcac700b775e4caed9ad775b`).

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
