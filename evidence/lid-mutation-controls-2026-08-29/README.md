# lid-mutation-controls-2026-08-29 — re-witness of all 6 Lean lids at 402719a

Six Lean-lid mutation controls (one per lid: `length`, `tag`, `tlv`, `sequence`, `oid`,
`big_integer`), re-run at commit `402719a`. Three of the six proof files (`LengthProofs.lean`,
`TlvProofs.lean`, `SequenceProofs.lean`) grew new content since the mutations were first captured
(69bbc9f), so the file-level carry-over check correctly refuses to carry the old evidence forward
— even though the specific theorem each mutation targets is confirmed byte-identical to the
original capture. This campaign re-applies the same documented mutation, verbatim, against the
current source and records the fresh result.

## Protocol

For each lid: confirm the unmutated lid passes (`lean/check_lean.sh`), apply the documented
mutation (exact-string replacement, unique anchor verified), confirm `lean/check_lean.sh` fails
with the recorded first error, revert the file, confirm the revert is byte-identical (sha256) to
the pre-mutation source, confirm `lean/check_lean.sh` passes again. One lid at a time.

## Result

All 6 lids: PASS -> FAIL -> PASS, exactly as predicted, matching first error line and column.

| lid | file | first error (mutated) |
|---|---|---|
| length | LengthProofs.lean | LengthProofs.lean:959:4: unsolved goals |
| tag | TagProofs.lean | TagProofs.lean:368:2: Type mismatch |
| tlv | TlvProofs.lean | TlvProofs.lean:644:12: Type mismatch |
| sequence | SequenceProofs.lean | SequenceProofs.lean:896:2: Type mismatch |
| oid | OidProofs.lean | OidProofs.lean:287:35: Application type mismatch |
| big_integer | BigIntProofs.lean | BigIntProofs.lean:161:8: unsolved goals |

Toolchain: Lean 4 `leanprover/lean4:v4.30.0-rc2`, Aeneas `45061fa1a5b4bad876f17c03d3a5544d818622e6`,
Charon `40ee060a8df43f4e7e0842d3f05387b0a4426aaf` (the pins declared in the tree). `results.json`
carries the per-run rc/wall-time/sha256 detail; logs are `M<n>-<lid>-{mutated,reverted}.log`.
