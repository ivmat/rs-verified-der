# Leaf mutation controls — RESULTS

- git HEAD: `d68eecaf0a5aa04bcc5fa5657d3c2bc1d9c39f11`
- kani: `cargo-kani 0.67.0`
- generated: 2026-10-10T15:07:36Z

| id | module | red harnesses → verdict | green → verdict | failed assert | verdict |
|---|---|---|---|---|---|
| set_of-H1-M1 | set_of | `set_of::proofs::duplicate_adjacent_encodings_are_accepted` → FAILED | - | "assertion failed: decode_set_of(&content) == Ok(2)" | **OBSERVED-RED** |
| set_of-H1-M2 | set_of | `set_of::proofs::unsorted_children_are_rejected` → FAILED | - | "assertion failed: decode_set_of(&content) == Err(SetOfError::Unsorted { index: 0 })" | **OBSERVED-RED** |
| set_of-H1-M3 | set_of | `set_of::proofs::refactored_walk_matches_previous_walk` → FAILED | - | "assertion failed: refactored == previous" | **OBSERVED-RED** |
| set_of-H1-M4 | set_of | `set_of::proofs::unsorted_children_are_rejected` → FAILED | - | "assertion failed: decode_set_of(&content) == Err(SetOfError::Unsorted { index: 0 })" | **OBSERVED-RED** |
| set_of-H1-M5 | set_of | `set_of::proofs::no_over_read` → FAILED | - | "assertion failed: new_off == off + expected_used" | **OBSERVED-RED** |
| sequence-SEQ-A | sequence | `sequence::proofs::ok_implies_exact_tiling` → FAILED<br>`sequence::proofs::roundtrip_two_children` → FAILED | - | "assertion failed: seen == k"<br>"assertion failed: decode_sequence(content) == Ok(2)" | **OBSERVED-RED** |
| sequence-SEQ-B | sequence | `sequence::proofs::ok_implies_exact_tiling` → FAILED | `sequence::proofs::roundtrip_two_children` → SUCCESSFUL | "This is a placeholder message; Kani doesn't support message formatted at runtime" | **OBSERVED-RED** |
