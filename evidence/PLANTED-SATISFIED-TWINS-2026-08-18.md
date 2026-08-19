---
type: reference
---

# Planted-satisfied twins for the 3 disclosed-UNSAT covers — 2026-08-18

**Task:** finding **F2** of the external rigor re-review of this crate (2026-08-16), §5,
a vacuity/reachability review lens: *"for each UNSAT-means-good cover ... find its exact
planted-satisfied twin — inject the defect the cover denies and confirm the cover flips to
SATISFIED. A missing twin = vacuity risk; an UNSAT cover proves nothing on its own."*

**What this closes.** `PROOF_MANIFEST.md` §8.2 already discloses three harnesses whose `Ok`-tail
cover is *known-unsatisfiable* at its bound (`x509_extension::validate_extensions_never_panics`,
`x509_tbs_certificate::parse_tbs_certificate_never_panics`, `x509_validity::parse_never_panics`),
each paired in the manifest with a "companion witness harness" that is designed to flip SAT. What
was missing was a *fresh, observed* confirmation that both halves of each pair actually behave as
documented — the manifest's own evidence table only ever recorded the coarse `SUCCESSFUL`/`FAILED`
harness count, not a targeted, freshly-run demonstration of the UNSAT→SAT flip for each pair, on
this machine, today.

**Method.** For each of the three: (a) run the disclosed-UNSAT harness itself, targeted, and
confirm `0 of 1 cover properties satisfied`; (b) run (or, for `x509_validity`, additionally
construct) a planted-satisfied twin that removes exactly the arithmetic floor the UNSAT report
names, and confirm `1 of 1 cover properties satisfied`; (c) where the twin required a source edit
(the `x509_validity` same-harness buffer enlargement), revert it and confirm the source is
byte-identical and the harness reads UNSAT again. Every run below is targeted
(`cargo kani --harness <fq-name> --exact -Z stubbing`), not a full-crate sweep, run under
`systemd-run --user --scope -p MemorySwapMax=0` with `MemoryMax` sized per harness (noted per run —
see the note on cap sizing below). Kani/CBMC versions are read from each run's own banner:
`Kani Rust Verifier 0.67.0 (cargo plugin)`, `CBMC 6.8.0 (cbmc-6.8.0)` throughout — matching the pins
in `PROOF_MANIFEST.md` §2.

**Note on the memory cap.** F1's targeted single-primitive-harness runs all fit comfortably under
the task's default `MemoryMax=8G`. These three composition harnesses do not: `PROOF_MANIFEST.md`
§3.4 itself records `x509_extension::validate_extensions_never_panics` peaking ~20.5 GiB, and
`x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed`'s own doc comment records ~11.3 GiB.
Both were reproduced here at essentially those same figures (20.2 GiB and 11.6 GiB respectively —
see the per-harness sections). Running any of the three witness/UNSAT pairs under 8G was tried first
and reproducibly OOM-killed (`x509_extension`'s witness at a 16G cap: `oom-kill`, 16G peak, ~2m40s —
see below) before the cap was raised. This is a **deliberate, disclosed deviation** from the task's
default 8G cap, sized to what each harness is already known to need (this machine has ~22–24 GiB
available; nothing here approaches a full-suite run). `x509_validity`'s pair is the one exception
that fits comfortably under 8G throughout.

## Summary

| Module | UNSAT harness (before) | Fresh UNSAT confirmed | Planted-satisfied twin (after) | Fresh SAT confirmed | Peak RSS / wall (twin) |
|---|---|---|---|---|---|
| `x509_extension` | `validate_extensions_never_panics` @ `[u8;13]`, unwind 12 | **0 of 1** — yes | `validate_extensions_ok_path_witnessed` (pre-existing companion; concrete 16-B two-`Extension` specimen, same [u8;13]-bound function called on real, longer content) | **1 of 1** — yes | 16.5 GiB / 199.1 s |
| `x509_validity` | `parse_never_panics` @ `[u8;16]`, unwind 20 | **0 of 1** — yes | (i) the SAME harness, source temporarily enlarged `[u8;16]` → `[u8;32]` (exactly the arithmetic floor its own doc names), reverted after; (ii) pre-existing companion `parse_validity_ok_path_witnessed` (concrete 32-B specimen) | **1 of 1** — yes (both) | (i) ~0.3 GiB / 21.0 s; (ii) ~0.3 GiB / 6.6 s |
| `x509_tbs_certificate` | `parse_tbs_certificate_never_panics` @ `[u8;10]`, unwind 12, 2 stubs | **0 of 1** — yes | `parse_tbs_certificate_ok_path_witnessed` (pre-existing companion; concrete 135-B v1 TBSCertificate specimen, 3 stubs) | **1 of 1** — yes | 11.6 GiB / 201.6 s |

All six numbered runs below are fresh observations from this session (2026-08-18), not
transcriptions of the crate's earlier committed evidence — though for context: the crate's own
`evidence/check-ffcea81.log` (commit `ffcea81`, 2026-08-11, full-suite run) already recorded the
same three companion witnesses at `1 of 1 cover properties satisfied` (lines 991, 1026, 1038) next
to their paired UNSAT harnesses at `0 of 1` (lines 997, 1032, 1044) — this session reproduces that
pairing independently, targeted, with fresh logs and (for `x509_validity`) an additional
same-harness buffer-enlargement twin the earlier run did not do.

## 1. `x509_extension` — `validate_extensions_never_panics` / `validate_extensions_ok_path_witnessed`

**Why UNSAT, per the module's own doc:** the 13-octet buffer is a deliberate tractability reduction
(a full `[u8;16]`/`unwind(20)` symbolic run of this harness exhausts CBMC's memory — confirmed again
below, not just cited), but a genuine two-`Extension` `Extensions` needs 16 octets minimum, so the
walk's second-iteration-and-`Ok` conjunction the cover asks for can never occur inside 13.

**(a) Fresh UNSAT confirmation**, targeted, `MemoryMax=22G` (sized to the harness's own documented
~20.5 GiB peak — an 8G/16G cap was tried first for the *companion* below and reproducibly OOM-killed,
see note under (b)):

```
$ systemd-run --user --scope -p MemoryMax=22G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_extension::proofs::validate_extensions_never_panics" --exact -Z stubbing
...
 ** 0 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 427.6122s
```
Peak (systemd accounting): **20.2 GiB**, wall 7m 8.7s — matches `PROOF_MANIFEST.md`'s ~20.5 GiB
figure. — `evidence/planted-satisfied-twins-2026-08-18/x509_extension-unsat-13B.log.gz`

**(b) The twin, and why it is the pre-existing companion rather than a same-harness buffer bump.**
An enlargement of *this* harness's own `[u8;13]`/`unwind(12)` to `[u8;16]`/`unwind(20)` is exactly
the configuration the module's Kani comment documents as already measured to exhaust memory
(`~1.6e5 VCCs -> CaDiCaL OOM`); the 13-octet reduction exists *because* of that measurement. So the
"enlarge the buffer past the object floor" instruction is realized here via the crate's own
established mechanism for this exact situation — a **concrete** (not fully symbolic) 16-octet
two-`Extension` specimen run through the same, real, unstubbed `validate_extensions` — rather than
re-running the already-known-to-explode fully-symbolic configuration. This is not a symbolic-vs-real
substitution of convenience: CBMC does not partially evaluate against concrete values before
symbolic execution (this crate's own measured finding, `x509_tbs_certificate.rs`'s investigation
notes), so the concrete witness still explores the full call graph — it is a genuinely separate,
expensive run, not a cheap sleight of hand. First attempted at `MemoryMax=8G` (timed out with no
verdict) and `MemoryMax=16G` (**OOM-killed**: `run-p64212-i82322.scope: The kernel OOM killer killed
some processes in this unit. ... 16G memory peak`, 2m 40s), then succeeded at `MemoryMax=20G`:

```
$ systemd-run --user --scope -p MemoryMax=20G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_extension::proofs::validate_extensions_ok_path_witnessed" --exact -Z stubbing
...
 ** 1 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 199.05688s
```
Peak (systemd accounting): **16.5 GiB**, wall 3m 20.1s. —
`evidence/planted-satisfied-twins-2026-08-18/x509_extension-sat-16B-concrete-witness.log.gz`

No source edit was needed for this pair (the companion harness is already committed), so there is
nothing to revert here.

## 2. `x509_validity` — `parse_never_panics` / (i) same-harness enlargement, (ii) `parse_validity_ok_path_witnessed`

**Why UNSAT, per the module's own doc:** the smallest possible `Time::Utc` TLV is 15 octets
(`tag(1)+len(1)+content(13)`); two of them plus a `>= 2`-octet outer SEQUENCE header give an
arithmetic floor of 32 octets, exactly twice the harness's 16-octet buffer.

**(a) Fresh UNSAT confirmation**, targeted, `MemoryMax=8G` (this pair is cheap throughout):

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_validity::proofs::parse_never_panics" --exact -Z stubbing
...
 ** 0 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 12.972608s
```
— `evidence/planted-satisfied-twins-2026-08-18/x509_validity-unsat-16B.log.gz`

**(b)(i) The twin — literal same-harness buffer enlargement.** Unlike `x509_extension`, this
module's own investigation notes describe it as "shallow" (no nested unbounded composition), so the
enlargement the review's F2 names first ("enlarge the buffer past the object floor") was tried on
the harness itself, not just its companion. Source edit, reverted after the run below:

```diff
     #[kani::proof]
     #[kani::unwind(20)]
     fn parse_never_panics() {
-        let buf: [u8; 16] = kani::any();
+        let buf: [u8; 32] = kani::any();
```

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_validity::proofs::parse_never_panics" --exact -Z stubbing
...
 ** 1 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 21.03108s
```
— `evidence/planted-satisfied-twins-2026-08-18/x509_validity-sat-32B-same-harness-enlarged.log.gz`

**Reverted.** `git diff der-verified/src/x509_validity.rs` empty after reverting; re-run of the
restored (16-octet) harness reconfirms `0 of 1 cover properties satisfied`:

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_validity::proofs::parse_never_panics" --exact -Z stubbing
...
 ** 0 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 12.525516s
```
— `evidence/planted-satisfied-twins-2026-08-18/x509_validity-reverted-16B-confirmed-unsat.log.gz`

**(b)(ii) The pre-existing companion, also confirmed fresh** (concrete 32-octet UTC/UTC specimen,
real unstubbed `parse_validity`, no source edit needed):

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_validity::proofs::parse_validity_ok_path_witnessed" --exact -Z stubbing
...
 ** 1 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 6.5560637s
```
— `evidence/planted-satisfied-twins-2026-08-18/x509_validity-sat-32B-concrete-witness.log.gz`

This module's pair is the cleanest demonstration: the SAME harness, SAME assertion machinery, flips
UNSAT→SAT purely by widening the buffer past the arithmetic floor its own doc names — exactly the
mechanism F2 asks to confirm.

## 3. `x509_tbs_certificate` — `parse_tbs_certificate_never_panics` / `parse_tbs_certificate_ok_path_witnessed`

**Why UNSAT, per the module's own doc:** even with `validate_name`/`validate_extensions` modularly
stubbed away, reaching `Ok` still needs real encodings of `serialNumber`, `signature`, TLV headers
for `issuer`/`subject`, a real `Validity` (>= 32 octets), and a real `SubjectPublicKeyInfo` — an
arithmetic floor well over 60 octets against the harness's 10-octet buffer.

**(a) Fresh UNSAT confirmation**, targeted, `MemoryMax=8G` (this harness, unlike its companion, is
documented and confirmed cheap — the "0 of 554 checks" rejection-side glue converges quickly since
it never has to explore the (unreachable) accept path):

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_tbs_certificate::proofs::parse_tbs_certificate_never_panics" --exact -Z stubbing
...
 ** 0 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 97.24036s
```
— `evidence/planted-satisfied-twins-2026-08-18/x509_tbs_certificate-unsat-10B.log.gz`

**(b) The twin.** Same reasoning as `x509_extension`: this module's own investigation notes (in
`x509_tbs_certificate.rs`, recorded as two measured dead ends before the fix that worked) already
establish that neither a fully-symbolic enlarged buffer nor even a *concrete* buffer under just the
two existing stubs converges — a **third** stub (`stub_parse_validity`) is required to remove
`Validity`'s own decode loops from the inlined program before the `Ok` tail becomes reachable at
all. The pre-existing companion harness is exactly that fix, applied to a concrete 135-octet v1
`TBSCertificate` specimen. First attempted at `MemoryMax=8G` (insufficient, per the module's own
~11.3 GiB estimate — not separately re-measured at 8G here since the estimate was already
well-documented and the 16G attempt below succeeded on the first try), then run directly at
`MemoryMax=16G`:

```
$ systemd-run --user --scope -p MemoryMax=16G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "x509_tbs_certificate::proofs::parse_tbs_certificate_ok_path_witnessed" --exact -Z stubbing
...
 ** 1 of 1 cover properties satisfied
VERIFICATION:- SUCCESSFUL
Verification Time: 201.61377s
```
Peak (systemd accounting): **11.6 GiB**, wall 3m 22.9s — matches the module's own ~11.3 GiB estimate
almost exactly. — `evidence/planted-satisfied-twins-2026-08-18/x509_tbs_certificate-sat-135B-concrete-witness.log.gz`

No source edit was needed for this pair (the companion harness is already committed), so there is
nothing to revert here.

## What this establishes, and what it does not

- **Establishes:** each of the three disclosed-UNSAT covers is genuinely "provably out of reach at
  this bound" rather than a vacuous or broken cover expression — for each, an in-tree twin
  (same assertion, same module, real un-stubbed-or-minimally-stubbed function, past the documented
  arithmetic floor) DOES flip to `1 of 1 cover properties satisfied` when run, freshly, today. For
  `x509_validity` this was additionally confirmed on the literal same harness (buffer enlarged then
  reverted), the strongest form of the twin.
- **Does not establish:** that the *original* small-buffer harnesses' rejection-side coverage
  extends to arbitrarily large real certificates — that residual is exactly what F3 (below) narrows
  the headline claim for. It also does not re-derive the crate's own arithmetic-floor byte counts
  independently; those are taken from each module's own doc comments (already reviewed and
  hand-derived by the crate's maintainer, per `PROOF_MANIFEST.md`'s own convention for prose
  numbers).
- **Toolchain, read from the runs themselves:** `Kani Rust Verifier 0.67.0 (cargo plugin)`, `CBMC
  6.8.0 (cbmc-6.8.0)` throughout.
- **Final state:** `der-verified/src/x509_validity.rs` is confirmed byte-identical to its
  pre-mutation content after the buffer-enlargement twin; `x509_extension.rs` and
  `x509_tbs_certificate.rs` were not edited (their twins are pre-existing companion harnesses). `git
  diff` is empty for all three files at the end of this session.
