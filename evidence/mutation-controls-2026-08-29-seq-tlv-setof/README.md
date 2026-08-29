# mutation-controls-2026-08-29-seq-tlv-setof — re-witness at 402719a

Fifteen Kani mutation-control runs across three modules (`sequence`, `tlv`, `set_of`), re-run at
commit `402719a` after the observing harnesses in these files widened since their last capture
(69bbc9f / 3f2ee5e). The mutated functions themselves are byte-identical across that range, so the
same documented mutation, re-applied verbatim, re-witnesses the same result — this campaign
produces that fresh, honestly-attributed evidence instead of carrying the old runs forward under a
file-level assumption that no longer holds for the widened harness files.

**Runs:** `sequence` x8, `tlv` x4, `set_of` x3 = **15**.

## Protocol

For each control: apply the documented mutation (exact-string replacement, unique anchor
verified), run `cargo kani --manifest-path der-verified/Cargo.toml --harness <fq-name> --exact -Z
stubbing`, confirm the observed verdict, revert the file, confirm the revert is byte-identical
(sha256) to the pre-mutation source. Baseline/reverted legs are expected `VERIFICATION:- SUCCESSFUL`;
mutated legs are expected `VERIFICATION:- FAILED` (except one predicted-green leg, `14-seqB-roundtrip`,
noted below). Run one leg at a time; every mutated file was byte-identical to its pre-mutation
baseline before the next mutation was applied.

## Result

All 15 legs matched their prediction exactly.

| run | module | leg | predicted | observed |
|---|---|---|---|---|
| 02-base-seq-tiling | sequence | baseline | GREEN | SUCCESSFUL |
| 03-base-seq-roundtrip | sequence | baseline | GREEN | SUCCESSFUL |
| 10-seqA-tiling | sequence | mutated | RED | FAILED |
| 11-seqA-roundtrip | sequence | mutated | RED | FAILED |
| 12-seqA-reverted | sequence | reverted | GREEN | SUCCESSFUL |
| 13-seqB-tiling | sequence | mutated | RED | FAILED |
| 14-seqB-roundtrip | sequence | mutated | GREEN (predicted) | SUCCESSFUL |
| 15-seqB-reverted | sequence | reverted | GREEN | SUCCESSFUL |
| 01-tlv-baseline-structure | tlv | baseline | GREEN | SUCCESSFUL |
| 06-tlv-mutated-structure | tlv | mutated | RED | FAILED |
| 06-tlv-mutated-roundtrip | tlv | mutated | RED | FAILED |
| 07-tlv-reverted-structure | tlv | reverted | GREEN | SUCCESSFUL |
| 12-base-set_of | set_of | baseline | GREEN | SUCCESSFUL |
| 13-setofA-unsorted | set_of | mutated | RED | FAILED |
| 14-setofA-reverted | set_of | reverted | GREEN | SUCCESSFUL |

Toolchain: kani 0.67.0, cbmc 6.8.0, CaDiCaL 2.0.0, cargo 1.97.0. Logs are in `logs/`.
