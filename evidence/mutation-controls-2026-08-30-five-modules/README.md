# mutation-controls-2026-08-30-five-modules — re-witness at 402719a

Seventeen Kani mutation-control legs across five modules (`length`, `tag`, `integer`,
`big_integer`, `oid`), re-run at commit `402719a`.

## Why this campaign exists

A mutation control is only worth what its provenance is worth. The 2026-08-18 and 2026-08-19
campaigns recorded, for each run, which harness observed the mutation — but they did **not** record,
as a machine-readable field, **which source file each mutation touched**. That fact lived only in the
campaign prose. A reader (or a checker) that will not infer a mutation's site from prose therefore
cannot confirm that these controls still describe the code as it stands, and a control nobody can
confirm is a check nobody watched fail.

The five files below are **byte-identical** between the commit where those campaigns ran (`69bbc9f`)
and `402719a`, so the documented mutations re-apply verbatim and re-witness the same behaviour. This
campaign produces that evidence **fresh**, with the mutated file recorded explicitly as data, rather
than carrying old runs forward on an inference.

The baseline hashes below are identical to the ones the 2026-08-18 / 2026-08-19 documents recorded,
which is what makes "the same mutation, re-applied" a checkable claim rather than an assertion.

## Protocol

This campaign follows the 2026-08-19 protocol, the most mechanically reproducible of the earlier
three, and tightens one thing.

1. **Baselines first.** `sha256` of all five files, recorded before anything is touched
   (`baseline-sha256.txt`).
2. **Predictions are preregistered.** `predictions.tsv` is written to disk **before a single harness
   runs**, so a prediction cannot be edited afterwards to match what was observed. This is the
   tightening: the 2026-08-18 campaign recorded only observations, so its "expected RED" was a
   post-hoc reading. Here the prediction is a committed artifact that predates the evidence.
3. **Exact-string mutation, unique anchor, hard fail.** Each mutation is an exact-string replacement
   that aborts unless its anchor occurs **exactly once** in the file. Nothing is applied by line
   number or by regex.
4. **One mutation at a time, always from a pristine file.** After each mutation's harnesses run, the
   file is reverted from git and its `sha256` is re-checked byte-identical to the baseline before the
   next mutation is applied. (`OID-B`'s anchor is a strict prefix of `OID-A`'s, so this ordering
   discipline is load-bearing, not ceremony.)
5. **Restored tree.** `final-sha256.txt` equals `baseline-sha256.txt`.

The driver is committed as `run_campaign.py` — it is the campaign, not a description of it.

Command shape per leg:
`cargo kani --manifest-path der-verified/Cargo.toml --harness <fq-name> --exact -Z stubbing`,
one leg at a time, in a detached memory-capped service on the local box.

## The six mutations

| id | defect | file / fn | what it breaks |
|---|---|---|---|
| `LEN-A` | long-form minimality removed | `length.rs` / `decode_length` | a long-form encoding of a short-form-representable value is wrongly accepted |
| `TAG-A` | high-tag minimality removed | `tag.rs` / `decode_tag` | a high-tag form of a low-tag-representable number is wrongly accepted |
| `INT-A` | redundant-padding minimality removed | `integer.rs` / `decode_integer` | non-minimal integer encodings are wrongly accepted |
| `BIG-A` | wrong index | `big_integer.rs` / `validate_integer_content` | `c1` is bound to `content[0]` a second time instead of `content[1]`, so minimality no longer inspects the byte X.690 §8.3.2 keys on |
| `OID-A` | subidentifier minimality removed | `oid.rs` / `validate_oid` | a redundant leading `0x80` subidentifier group is wrongly accepted |
| `OID-B` | subidentifier minimality **narrowed** | `oid.rs` / `validate_oid` | an `i == 0` conjunct is added, so a redundant `0x80` opening a *later* subidentifier is wrongly accepted while the leading case still rejects |

`OID-B` is the more interesting of the two: it does not delete the check, it narrows it, and only the
`later_0x80` harness can see the difference. That is the discrimination the pair exists to
demonstrate.

## Result

**All 17 legs matched their prediction exactly.** 11 mutated legs RED, 6 reverted legs GREEN.

| run | module | leg | predicted | observed |
|---|---|---|---|---|
| R1-length-mutated-classify | length | mutated | RED | FAILED |
| R1-length-mutated-canonical | length | mutated | RED | FAILED |
| R1-length-reverted-classify | length | reverted | GREEN | SUCCESSFUL |
| R2-tag-mutated-classify | tag | mutated | RED | FAILED |
| R2-tag-mutated-canonical | tag | mutated | RED | FAILED |
| R2-tag-reverted-classify | tag | reverted | GREEN | SUCCESSFUL |
| R3-integer-mutated-minimal | integer | mutated | RED | FAILED |
| R3-integer-mutated-positive-padding | integer | mutated | RED | FAILED |
| R3-integer-mutated-negative-padding | integer | mutated | RED | FAILED |
| R3-integer-reverted-minimal | integer | reverted | GREEN | SUCCESSFUL |
| R4-bigint-mutated-oracle | big_integer | mutated | RED | FAILED |
| R4-bigint-reverted-oracle | big_integer | reverted | GREEN | SUCCESSFUL |
| R5-oidA-leading | oid | mutated | RED | FAILED |
| R5-oidA-later | oid | mutated | RED | FAILED |
| R5-oidA-reverted | oid | reverted | GREEN | SUCCESSFUL |
| R6-oidB-later | oid | mutated | RED | FAILED |
| R6-oidB-reverted | oid | reverted | GREEN | SUCCESSFUL |

The failed assertions and check counts reproduce the earlier campaigns' recorded ones exactly — e.g.
`R4-bigint-mutated-oracle` fails `accepted == oracle_says_ok` at `1 of 50`, and `R6-oidB-later` fails
`validate_oid(&buf) == Err(OidError::NonMinimalSubid)` at `1 of 81`. Same mutation, same witness,
fresh run.

## Baselines

```
d6a19e010323f58f6fd3501ccb4dc84bf3c21a9dc7ba6d4d9ff11816d45409db  der-verified/src/big_integer.rs
fe478ec1d75fb90be90904cd1fe392444f9edfa004d760f35a35e0eeb12ca94a  der-verified/src/integer.rs
80ada6f0a9d47ae1fb1d6447073591e639dda3aa3c27078655d67a25f39ec2fc  der-verified/src/length.rs
252d5f61c7a125342388e09a923095aa294d22c45e74fd19f07497fae073cfa0  der-verified/src/oid.rs
3951b29aee75f3dd9ede31df6910e44b885d8a35ff9bee8a5eb145643d7c3ebe  der-verified/src/tag.rs
```

`final-sha256.txt` is identical: the tree this campaign ran against is the tree it left behind.

## What this does NOT establish

These controls show that **these** harnesses do fail when **these** specific defects are planted.
They are not a mutation-coverage score, and they say nothing about defect classes nobody planted.
`R6-oidB-reverted` and its `leading_0x80` sibling also show the converse worth stating plainly: one
harness of a pair can be entirely blind to a real defect its partner catches.

## Re-run note (toolchain provenance, same day)

The first pass of this campaign ran with the service manager's inherited `PATH`, which resolves
`/usr/bin/cargo` (system Rust 1.93.1) ahead of the rustup `cargo` (1.97.0) this crate's other
evidence was captured under. All 17 legs were **re-run** with `PATH` corrected, and **every verdict
reproduced exactly** — which is itself the expected result, since Kani compiles the crate with its
own bundled `rustc` rather than the outer `cargo` dispatcher. Only the recorded toolchain
*provenance* needed the correction, not the verification. The logs published here are the corrected
run's. This note exists because "we re-ran it and it came out the same" is a claim a reader is
entitled to see stated rather than discover.

Toolchain: kani 0.67.0, CBMC 6.8.0, CaDiCaL 2.0.0, cargo 1.97.0. Logs are in `logs/`.
