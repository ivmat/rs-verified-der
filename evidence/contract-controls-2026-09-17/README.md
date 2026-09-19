# contract-controls-2026-09-17 — faithful-decode contracts + observed-red mutation controls

Seven modules (`pkcs8`, `ecdsa_sig_value`, `rsa_public_key`, `encrypted_private_key_info`,
`ec_private_key`, `x509_spki`, `x509_algorithm_identifier`) each gained a `*_parse_faithful`
`#[kani::proof]` functional-contract harness, and each contract is backed by at least one
observed-red mutation control: mutate a single exact-tiling (or classification/minimality/
canonical-OID) guard in the shipped parser, confirm `parse_faithful` FAILS on the exact assert the
mutation targets, confirm `parse_never_panics` stays SUCCESSFUL under the same mutation (proving
the contract catches something panic-freedom cannot), then restore the pristine source. This
promotes all seven from A1 `never_panics`-only (PROBE, per the rigor re-review's own vocabulary)
to A3 contract (bounded-backing per Law 6 amendment 2026-09-12 — see "Bounds disclosure" below).

Full narrative and the per-module observed-red table live in
[`../CONTRACT-CONTROLS-2026-09-17.md`](../CONTRACT-CONTROLS-2026-09-17.md); this file documents the
campaign's own protocol and provenance, in the shape the import tooling cross-checks.

## Why a fresh directory, not a hand-authored claim

A mutation control is only worth what its provenance is worth (the same principle
`mutation-controls-2026-08-30-five-modules/README.md` states). Here the runner scripts
(`run_contract_control.sh`, `run_contract_control2.sh`, `pkcs8_control2_classify.sh`,
`x509_control2.sh`) are committed as the campaign drivers — they ARE the mutation specification
(exact-string replacement, aborting unless the anchor occurs exactly once), not a description of
one. Every log is committed (gzipped) beside the driver that produced it.

## Protocol

Each driver, for one module:

1. **Pristine source first.** The module's file is copied in from a pristine snapshot (the
   crate's own committed source at this campaign's attributed commit, `d05d3f2`) before anything
   runs.
2. **Baseline.** `cargo kani --harness <module>::proofs::parse_faithful` — expected SUCCESSFUL, and
   (confirmed from the committed logs, not merely asserted) `1 of 1 cover properties satisfied` for
   the harness's own `kani::cover(result.is_ok())`, so the postcondition-bearing `Ok` branch is
   live at baseline independent of the mutation controls below.
3. **Exact-string mutation, unique anchor, hard fail.** Each mutation is an exact-string
   replacement that aborts unless its anchor occurs **exactly once** in the file. Nothing is
   applied by line number or by regex (`run_contract_control.sh`/`run_contract_control2.sh`'s
   `mutate()`/inline heredoc).
4. **Two control legs per mutation.** `parse_faithful` (expected FAILED — the observed red) and
   `parse_never_panics` (expected SUCCESSFUL — proving the property the contract adds is one
   panic-freedom cannot see).
5. **Restore.** The pristine copy is written back over the module file before the driver exits.
6. **A second, review-added control** (pkcs8, ecdsa_sig_value, rsa_public_key, x509_spki,
   x509_algorithm_identifier): a second, independent mutation targeting the conjunct the 2026-09-17
   critical review specifically asked for beyond exact tiling (`[0]`-attributes classification for
   pkcs8; INTEGER minimality for ecdsa/rsa; BIT STRING classification for x509_spki; canonical-OID
   for x509_algorithm_identifier), run the same way, against the same pristine baseline.

Command shape per leg: `cargo kani [-Z stubbing] --harness <fq-name>`, one leg at a time, against a
local checkout of the crate (Kani is not run on the box in general per project Law 1; these runs
executed on a cloud VM — see `../CONTRACT-CONTROLS-2026-09-17.md` header).

## Bounds disclosure (Law 6 amendment 2026-09-12 — CONTRACT SURFACE / bounded-backing)

Every `parse_faithful` harness uses a 16-octet symbolic backing array with a symbolic length
`0..=16` — a harness **tractability bound**, stated here and in each harness's own doc comments;
the public API carries no such bound. Inputs/operands are symbolic throughout the declared domain.
Report these seven claims as CONTRACT SURFACE / bounded-backing evidence, never as an unrestricted
proof.

## The modules and their control legs

| module | file | control legs | mutation(s) |
|---|---|---|---|
| `pkcs8` | `pkcs8.rs` | tiling + `[0]`-attributes classification | `tlv_used != rest.len()` → `>`; `tag.number != 0` → `false` |
| `ecdsa_sig_value` | `ecdsa_sig_value.rs` | tiling + INTEGER minimality | `s_used != rest.len()` → `>`; drop `validate_integer_content(...)` |
| `rsa_public_key` | `rsa_public_key.rs` | tiling + INTEGER minimality | `exponent_used != rest.len()` → `>`; drop `validate_integer_content(...)` |
| `encrypted_private_key_info` | `encrypted_private_key_info.rs` | tiling | `data_used != rest.len()` → `>` |
| `ec_private_key` | `ec_private_key.rs` | tiling | `!rest.is_empty()` → `false` |
| `x509_spki` | `x509_spki.rs` | tiling + BIT STRING classification | `pk_used != outer_rest.len()` → `>`; `tag.number != BIT_STRING_TAG` → `false` |
| `x509_algorithm_identifier` | `x509_algorithm_identifier.rs` | tiling + canonical-OID | `params_used != rest.len()` → `>`; drop `validate_oid(...)` |

Per-module raw evidence (gzipped Kani logs, `mutation-*.txt`, `SUMMARY*.txt`) lives in the matching
`<module-short-name>/` subdirectory here (`pkcs8/`, `ecdsa/`, `rsa/`, `epki/`, `ec/`, `x509spki/`,
`x509algid/` — the directory names abbreviate; the `module` field in the invocation record and the
table above give the real module/file names).

## Result

**All legs matched their prediction.** Every baseline `parse_faithful` verified SUCCESSFUL (with
its `Ok`-cover satisfied); every control-faithful leg FAILED on the named assert; every
control-neverpanics leg stayed SUCCESSFUL under the same mutation. The exact failed-assert text per
leg is in `../CONTRACT-CONTROLS-2026-09-17.md`'s tables and in each module's own `SUMMARY*.txt`
here.

## Baselines

```
68fd2465a73ea1c11145dba8d828fa5f731ffdc1254d08343af249e62f0b1797  der-verified/src/ecdsa_sig_value.rs
9df28f3ee1c08d753e723359f485d16723a9ae8c3f7a9a7e704d1f9c1fedd3d6  der-verified/src/ec_private_key.rs
843427d8f35575fbdbe655f3ac0bf4dccd1fc566aa2937811c090afe488e04b7  der-verified/src/encrypted_private_key_info.rs
512e024de2cffc5aa4ba1f029cab3eb87f67d6ca168468cb123b6b2f918d4fbd  der-verified/src/pkcs8.rs
d7e3ad0cbe34acbc0165c22a7082c5e70975ef8c091097041252ac5b4efcf7e6  der-verified/src/rsa_public_key.rs
06b44b8273ac06558f6149004d604a1ba171cb1ccefcb7ae0ba3f866c14fff86  der-verified/src/x509_algorithm_identifier.rs
49faf3aec92ed78c0fdd34d11ed5af9f0dc6e61ddde1b486c6447e11bed43e0c  der-verified/src/x509_spki.rs
```

(`baseline-sha256.txt`, computed directly against the seven module files as committed at this
campaign's attributed commit, `d05d3f2`.) `final-sha256.txt` is identical — every driver restores
the pristine copy before it exits, and this campaign's attributed commit is the tree the drivers
ran against and left behind: the source these runs saw is exactly what is committed at `d05d3f2`
for these seven files (confirmed directly, not inferred — each driver's own pristine `COPY` input
was diffed byte-for-byte against the committed `d05d3f2` blob for its file before this record was
written).

## Toolchain and capture provenance

Toolchain: **Kani 0.67.0, CBMC 6.8.0, CaDiCaL 2.0.0** — read directly from every committed log's own
banners (`Kani Rust Verifier 0.67.0 (cargo plugin)`, `CBMC 6.8.0 (cbmc-6.8.0)`,
`Solving with CaDiCaL 2.0.0`), uniform across all 24 legs. These runs executed on a cloud VM (the
box does not run Kani, project Law 1); the logs' own `Compiling der-verified ... (/home/.../
rs-verified-der/der-verified)` path lines show a VM-local home-directory checkout, not this
project's own directory layout, consistent with that. Runs were driven directly by the committed
scripts, not wrapped in `systemd-run`/`/usr/bin/time`, and are captured here as targeted
single-harness `cargo kani --harness <fq-name>` invocations (`-Z stubbing` for the two Track-B
x509 legs whose harnesses use `#[kani::stub]`, per `x509_control2.sh`).

## What this does NOT establish

These controls show that **these** harnesses fail when **these** specific defects are planted. They
are not a mutation-coverage score, and they say nothing about defect classes nobody planted. The
observed-red controls are targeted at the exact conjunct(s) the 2026-09-17 critical review named as
load-bearing for each module's faithful-decode claim (tiling everywhere; the review-added
classification/minimality/canonical-OID conjunct where the review asked for one) — not an
exhaustive mutation sweep of each module.
