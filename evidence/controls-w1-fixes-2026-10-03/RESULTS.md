# Leaf mutation controls — RESULTS

- git HEAD: `42c8165a3993ed8a811f65276bbb2a79291b8bb9`
- kani: `cargo-kani 0.67.0`
- generated: 2026-10-03T16:37:18Z

| id | module | red harnesses → verdict | green → verdict | failed assert | verdict |
|---|---|---|---|---|---|
| bit_string-W1F-1 | bit_string | `bit_string::proofs::require_octet_aligned_exact_on_built_values` → FAILED | `bit_string::proofs::octet_aligned_iff_unused_zero` → SUCCESSFUL | "assertion failed: got == want" | **OBSERVED-RED** |
