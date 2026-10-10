# Predictions for the 2026-10-10 control runs, written before any of them ran

Subject: commit `d68eeca`, tree clean when each run starts (the runner refuses a dirty mutated source). Written 2026-10-10T10:11:04Z (the original, unedited file has sha256
`7ea6ec8d715b60bc265e8b1fb33ca93322652a47197c3ed2e604356eef5e7b9c`), at a time when the split-floor service had been started (10:02:29Z) but was still
queued for the verification slot: the floor itself ran from 10:49:16Z to 13:21:11Z, so these predictions precede the floor result and every control (the first control ran at 14:41:30Z). Every Kani control is predicted `OBSERVED-RED`: every named baseline `SUCCESSFUL`, every red harness `FAILED`,
every green harness `SUCCESSFUL`.

## Set-of and sequence mutants (`controls-set-of-sequence-2026-10-10`)

| id | mutation | red harness | predicted |
|---|---|---|---|
| `set_of-H1-M1` | `count += 1` -> `count += 2` | `set_of::proofs::duplicate_adjacent_encodings_are_accepted` | RED (`Ok(4)` instead of `Ok(2)`) |
| `set_of-H1-M2` | bypass the `cmp_padded` `Greater` rejection (production walk) | `set_of::proofs::unsorted_children_are_rejected` | RED |
| `set_of-H1-M3` | `Element(e)` -> `Tlv(e)` | `set_of::proofs::refactored_walk_matches_previous_walk` | RED, 2 of 3 covers satisfied (long: about 6 min) |
| `set_of-H1-M4` | `used = before.len() - after.len() - 1` | `set_of::proofs::unsorted_children_are_rejected` | RED at the `Unsorted { index: 0 }` assertion |
| `set_of-H1-M5` | `Elements::next`: `rest = &rest[used - 1..]` (lidded `sequence.rs`, transient) | `set_of::proofs::no_over_read` | RED at `new_off == off + expected_used` |
| `sequence-SEQ-A` | `Ok(count)` -> `Ok(count + 1)` | `ok_implies_exact_tiling`, `roundtrip_two_children` | RED, RED (`seen == k`; `Ok(2)`) |
| `sequence-SEQ-B` | `Err(e) => return Err(Element(e))` -> `Err(_e) => break` | `ok_implies_exact_tiling` (green: `roundtrip_two_children`) | RED (`unwrap_failed` in the independent re-walk); green stays SUCCESSFUL |

## Re-run of controls voided by the source change (`controls-rerun-leaf-2026-10-10`: 34, `controls-rerun-w2-extension-2026-10-10`: 10)

All 44 predicted `OBSERVED-RED` with the same red and green sets and the same class of failing assertion as at the earlier commit: `profile.rs`,
`utc_time.rs` and `x509_extension.rs` differ from it in doc comments only, and the `set_of` controls S1, S2, B-GW-S2, R3b-1 and R3b-2 mutate code the
refactor did not touch. Not run: `set_of-S3` (old text no longer unique; superseded by `set_of-H1-M2`) and `set_of-B-GW-S1` (anchor now only in the proof-local copy of the previous walk).

## Lean mutants on production `tag.rs` (`lid-mutation-controls-2026-10-10-tag`)

Baseline (unmutated) `lean lid: PASS (sorry-free)`. M1 (`first >> 6` -> `first >> 5`), M2 (`first & 0x20` -> `first & 0x40`), M3 (the `Application` and
`ContextSpecific` match arms swapped): each RED in Lean elaboration of `TagProofs.lean` after a real Charon/Aeneas re-extraction (not model drift); after the
restore, a reverted run passes again. M2 also breaks `TlvProofs.lean` collaterally.

## Split floor

Main half (295 harnesses) PASS with the Lean lid, then the three heavy companions `1/0/1` each: 298 harnesses in all. Planted twins: every baseline `0 of 1`, every twin `1 of 1`.
