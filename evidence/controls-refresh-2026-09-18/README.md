# controls-refresh-2026-09-18 — re-witness of 5 stale controls at `d05d3f2`

Five controls the acceptance engine flagged `missing-control` / `unwitnessed-acknowledgment`
after the 2026-09-17/18 contract campaign (`4fa013f` + `d05d3f2`) landed unrelated EOF `#[test]`
additions in `big_integer.rs`, `integer.rs`, `tlv.rs`, and `x509_tbs_certificate.rs`, and a large
Lean-lid rewrite in `TagProofs.lean` (the flagship tag value-semantics campaign, `8fa75d4`). The
engine's stale-control policy is **per whole file**: a control's carry-over is refused
whenever its mutated-dependency file OR its observing-harness file changed AT ALL since the
control was captured, even when the change is textually unrelated to the mutation site (e.g. a
new unit test appended after the `#[cfg(kani)] mod proofs` block). That is by design — "the file
is unchanged" is a claim about the whole file, not an inference from a diff a human read — and it
is honest: these five controls have not actually been re-observed against the current tree.

This campaign re-witnesses each one, verbatim, against `d05d3f2`:

| claim | prior campaign | why stale | this campaign's legs |
|---|---|---|---|
| `PM/big_integer` | `mutation-controls-2026-08-30-five-modules` (`402719a`) | `big_integer.rs` gained an EOF `#[test]` (`8fa75d4`) | R4 (BIG-A) mutated + reverted |
| `PM/integer` | `mutation-controls-2026-08-30-five-modules` (`402719a`) | `integer.rs` gained an EOF comment (`8fa75d4`) | R3 (INT-A) mutated ×3 + reverted |
| `PM/tlv` | `mutation-controls-2026-08-29-seq-tlv-setof` (`402719a`) | `tlv.rs` gained two EOF `#[test]`s (`8fa75d4`, `1e59d58`) | R7 (TLV-A) mutated ×2 + reverted |
| `PM/lean-tag` | `lid-mutation-controls-2026-08-29` (`402719a`) | `lean/TagProofs.lean` grew +622 lines (`8fa75d4`, the flagship tag lid campaign) | M2-tag mutated + reverted (Lean, not Kani) |
| `PM/x509_tbs_certificate` | `planted-twins-2026-08-18` (`69bbc9f`, carried to `402719a`) | `x509_tbs_certificate.rs` gained EOF `#[test]`s (`8fa75d4`, `1e59d58`) | unsat-baseline + sat-twin re-run (no mutation — these are re-derivations of an existing companion-harness pair, not a planted defect) |

Every mutation is re-applied **verbatim** from its originating campaign; none was re-derived from
prose. The `big_integer`/`integer` mutations are copied byte-for-byte from
`mutation-controls-2026-08-30-five-modules/run_campaign.py`'s own `MUTATIONS` table. The `tlv`
mutation is re-derived directly from `decode_tlv`'s own source (that 2026-08-29 campaign shipped
no committed driver script, only a README-documented defect: "reports its consumed count off by
one (`end + 1` instead of `end`)" — the anchor below is the literal `Ok((...), end))` return line
that description names, confirmed unique). The `lean-tag` mutation is copied from
`lid-mutation-controls-2026-08-29/results.json`'s own recorded `desc`: "raise
`tag_decode_used_bounds`'s lower consumption bound from 1 to 2". The `x509_tbs_certificate` legs
plant no new defect at all — they simply re-run the same two committed harnesses
(`parse_tbs_certificate_never_panics`, `parse_tbs_certificate_ok_path_witnessed`) that
`planted-twins-2026-08-18` already used as its unsat-baseline / sat-twin pair, since that pair's
own source (`der-verified/src/x509_tbs_certificate.rs`'s `mod proofs`) is untouched by the
intervening EOF test additions — only the file-level P3 check can't see that from the outside.

## Protocol

**Kani legs (big_integer, integer, tlv):** `evidence/controls-refresh-2026-09-18/run_campaign.py`
— baseline sha256 of the three files recorded first; predictions preregistered to
`predictions.tsv` before any harness ran; each mutation an exact-string replacement that
hard-fails unless its anchor occurs exactly once; one leg at a time, in a detached
memory-capped `systemd --user` **service** (`MemoryMax=24G MemorySwapMax=0`, plus an explicit
corrected `PATH` — the service manager's default PATH resolves `/usr/bin/cargo` 1.93.1 ahead of
rustup's 1.97.0, the same trap the 2026-08-29/08-30 campaigns hit — and an explicit
`WorkingDirectory`, since a transient unit does not inherit the launching shell's cwd), matching
`check-d05d3f2.log`'s own capped-box method under the 2026-09-18 Law-1 relaxation; revert from
git and re-confirm sha256 byte-identical to baseline before the next mutation.

**Lean leg (tag):** confirmed `lean/check_lean.sh` PASS (sorry-free) first; applied the exact
statement mutation to `lean/TagProofs.lean`; ran `check_lean.sh` again (expect FAIL, named
theorem); reverted via `git checkout`, confirmed sha256 byte-identical to the pre-mutation
baseline; ran `check_lean.sh` a third time (expect PASS again). Toolchain: Lean 4
`leanprover/lean4:v4.30.0-rc2`, the pinned Aeneas/Charon revisions already resolved on this box
(`~/Downloads/verified_rs_tools/aeneas`, `~/.elan`) — unchanged from the 2026-08-29 campaign, and
NOT Kani, so it is unaffected by, and does not need, the Law-1 memory cap.

**x509_tbs_certificate legs:** the two committed harnesses re-run as-is (no mutation, no revert
needed) in the same capped systemd service as the Kani legs above.

Command shape per Kani leg:
```
systemd-run --user --unit=<name> -p MemoryMax=24G -p MemorySwapMax=0 \
    -p Environment=PATH=<rustup-first PATH> -p WorkingDirectory=<repo root> \
    --wait --pipe --collect -- \
    cargo kani --manifest-path der-verified/Cargo.toml --harness <fq-name> --exact -Z stubbing
```

## Result

**All 13 legs matched their prediction exactly.**

| run | module | leg | predicted | observed |
|---|---|---|---|---|
| R4-bigint-mutated-oracle | big_integer | mutated | RED | FAILED — `validate_iff_minimal_oracle.assertion.1` |
| R4-bigint-reverted-oracle | big_integer | reverted | GREEN | SUCCESSFUL |
| R3-integer-mutated-minimal | integer | mutated | RED | FAILED — `decode_accepts_only_minimal.assertion.1` |
| R3-integer-mutated-positive-padding | integer | mutated | RED | FAILED — `redundant_positive_padding_is_non_minimal.assertion.1` |
| R3-integer-mutated-negative-padding | integer | mutated | RED | FAILED — `redundant_negative_padding_is_non_minimal.assertion.1` |
| R3-integer-reverted-minimal | integer | reverted | GREEN | SUCCESSFUL |
| R7-tlv-mutated-structure | tlv | mutated | RED | FAILED — `decode_tlv_structure.assertion.3` (the `used == header + len` oracle) |
| R7-tlv-mutated-roundtrip | tlv | mutated | RED | FAILED — `tlv_roundtrip_small.assertion.3` (the `used == n` oracle) |
| R7-tlv-reverted-structure | tlv | reverted | GREEN | SUCCESSFUL |
| M2-tag-mutated | lean-tag | mutated | RED | FAIL — `TagProofs.lean:370:2: Type mismatch`, `tag_decode_used_bounds`'s proof term has type `1 ≤ ↑used ∧ …` but the mutated statement expects `2 ≤ ↑used ∧ …` |
| M2-tag-reverted | lean-tag | reverted | GREEN | PASS (sorry-free), `lid-source-state.txt` unchanged |
| x509_tbs_certificate-unsat-10B | x509_tbs_certificate | unsat-baseline | VACUOUS (0/1 cover) | VACUOUS — 0 of 1 cover properties satisfied, 0 of 550 checks failed |
| x509_tbs_certificate-sat-135B-concrete-witness | x509_tbs_certificate | sat-twin | SAT (1/1 cover) | SAT — 1 of 1 cover properties satisfied, 0 of 411 checks failed (peak 11.6 GiB, matching the original campaign's own recorded peak) |

The `big_integer`/`integer`/`tlv` predictions were preregistered fresh, to `predictions.tsv`, by
`run_campaign.py` before any harness ran this session. The `lean-tag` and `x509_tbs_certificate`
predictions are **re-witnesses of predictions preregistered by their ORIGINATING campaigns**
(`lid-mutation-controls-2026-08-29/results.json`'s `desc`/`expect_observed` field, and
`planted-twins-2026-08-18`'s own `invocations/planted-twins-2026-08-18.json` `expect_verdict`/
`expect_cover_status` fields respectively) — not re-derived from this session's own observation,
same discipline as the Kani legs, just recorded in a different document.

## Baselines

```
a31118ef827a52af77fbda7c5b7eb56fb60524156cb66e58b94b090965312eb9  der-verified/src/big_integer.rs
ea73dfb63bc980978074560586745e902847bee801686c9bf90147fffffaa7c6  der-verified/src/integer.rs
568ea7d7a81090c710d118b7ce3a500c64563dee776a02c5415e926bc6d8d070  der-verified/src/tlv.rs
```

`final-sha256.txt` is identical (see file). `lean/TagProofs.lean` baseline
`2f1b11885848f336ff9b767ee5e45cf905fa10959f501d98d8155f16ce4d7877`, confirmed byte-identical
after revert. `der-verified/src/x509_tbs_certificate.rs` was never touched by this campaign (no
mutation on that module).

## What this does NOT establish

Same caveat every prior campaign in this repo states: these controls show that **these**
harnesses do fail (or, for x509_tbs_certificate, do/don't satisfy their cover) under **these**
specific, previously-documented conditions, re-observed against the current tree. They are not a
fresh mutation-coverage score and say nothing about defect classes nobody planted. The
`x509_tbs_certificate` legs in particular still carry every caveat `PLANTED-SATISFIED-TWINS-2026-08-18.md`
already disclosed (three stubs on the sat-twin's glue, a companion-harness twin rather than a
same-harness enlargement) — this campaign only re-confirms those same facts hold at `d05d3f2`,
it does not strengthen them.

Toolchain: kani 0.67.0, CBMC 6.8.0, CaDiCaL 2.0.0, cargo 1.97.0 (Kani legs); Lean 4
`leanprover/lean4:v4.30.0-rc2`, Aeneas `45061fa1a5b4bad876f17c03d3a5544d818622e6`, Charon
`40ee060a8df43f4e7e0842d3f05387b0a4426aaf` (Lean leg, pins unchanged from the 2026-08-29 lid
campaign). Logs are in `logs/`; the two x509_tbs_certificate logs are gzipped (matching
`planted-satisfied-twins-2026-08-18`'s own convention) since each is several hundred KB of raw
Kani output — everything else here is a single-harness log, tens of KB, committed uncompressed
like every prior campaign in this evidence tree. Executed on the maintainer's box under the
2026-09-18 Law-1 relaxation (Kani/CBMC may run on the box, memory-capped); the Lean leg was
always permitted on the box (this box owns the Aeneas/Charon/Lean toolchain) and carries no
memory cap.
