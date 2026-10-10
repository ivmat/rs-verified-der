# Lean-lid mutation controls on `tag.rs` — 2026-10-10

Three production mutations of `der-verified/src/tag.rs`, each passed through a real Charon/Aeneas re-extraction and then the Lean lid, at commit
`d68eeca`. They are observed-red controls for the identifier-field theorems of the `tag` lid (`tag_decode_class`, `tag_decode_constructed`,
`tag_decode_identifier_fields`, which pin the decoded class, constructed bit and low-tag number of every accepted `decode_tag` input against a direct
transcription of X.690 section 8.1.2, not against `encode_tag`). The predictions are in
[`../CONTROLS-PREDICTIONS-2026-10-10.md`](../CONTROLS-PREDICTIONS-2026-10-10.md).

| id | mutation | mutated rc | reverted rc | observed |
|---|---|---|---|---|
| `M1-tag-class-wrong-shift` | class selector first >> 6 -> first >> 5 (class bits read from the wrong shift) | `1` (16 s) | `0` (14 s) | `RED` |
| `M2-tag-constructed-wrong-mask` | constructed mask 0x20 -> 0x40 | `1` (18 s) | `0` (14 s) | `RED` |
| `M3-tag-class-map-swap` | Application and ContextSpecific match arms swapped | `1` (15 s) | `0` (14 s) | `RED` |

## Protocol

The driver (a local script, not published, like the Kani control runner) records sha256 of `tag.rs`, the three generated models (`DerTagExtract.lean`,
`DerTlvExtract.lean`, `DerSequenceExtract.lean`), `lean/lid-source-state.txt` and `lean/TagProofs.lean`; runs the baseline lid; and then for each mutant applies the
exact-once replacement, runs the lid gate with `LEAN_REFRESH_MODELS` naming the three models (so that the mutated source reaches Lean through a genuine fresh
extraction instead of stopping at the model-drift check), restores all five files from byte copies, verifies their sha256 and a clean `git status`, and runs the
lid once more on the restored tree (the `reverted` log; expected pass). Results: `results.json`; logs: `logs/`. The lid runs inside a memory-capped
`systemd --user` service (`MemoryMax=20G`, `MemorySwapMax=0`) holding the verification slot.

## What each mutation is expected to break, and did

- `M1-tag-class-wrong-shift`: the class selector reads `first >> 5`. `TagProofs.lean` fails at lines 565, 570, 575 and 598 (type mismatch / omega); the four named identifier-field theorems then depend on `sorryAx`.
- `M2-tag-constructed-wrong-mask`: the constructed mask is `0x40`. `TagProofs.lean` fails at lines 360, 566, 571, 576 and 601, and `tag_decode_constructed` and `tag_decode_identifier_fields` depend on `sorryAx`. **Collateral:** `TlvProofs.lean:336` also fails, because the TLV lid depends on correct tag semantics; that failure is the first error printed in the log, and it does not replace the failure of the named theorem.
- `M3-tag-class-map-swap`: `Application` and `ContextSpecific` swapped. `TagProofs.lean` fails at lines 571 and 576; the class theorem and the composed theorem depend on `sorryAx`.

The low-tag-number projection of `tag_decode_identifier_fields` has no production mutant of its own; no separate observed-red claim is made for it.

## What this does not establish

A red lid run shows the theorem is sensitive to the planted defect in the three places mutated; it does not enumerate other defects. Rust-to-LLBC-to-Lean
extraction fidelity stays trusted, as for every lid.
