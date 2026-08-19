---
type: reference
---

# Mutation controls on the `oid` and `sequence` oracles — 2026-08-19

**What this closes.** The 2026-08-18 mutation-control campaign
(`evidence/MUTATION-CONTROLS-2026-08-18.md`) covered five primitive oracles — `length`, `tag`,
`tlv`, `integer`, `big_integer` — and said in its own words that it "says nothing about the other 27
modules' oracles". Two of the modules it left out, `oid` and `sequence`, carry the same grade as the
five in this crate's own claim surface: they are part of the DER encoding base, `oid`'s canonicality
biconditional and `sequence`'s exact-tiling/no-over-read properties are both lifted to ∀-length in
Lean (`PROOF_MANIFEST.md` §3.2), and `sequence` is the crate's only lid unbounded in the number of
children as well as in byte length. A claim carrying that much weight with **no artifact anybody had
watched fail** is the gap this file closes, in the same format and under the same protocol as the
2026-08-18 campaign.

**Method — identical to the 2026-08-18 campaign, one difference stated up front.** For each module:
plant one subtly-wrong implementation (a real defect class, not a no-op), run the specific
harness(es) whose documented job is to catch that class with
`cargo kani --manifest-path der-verified/Cargo.toml --harness <fq-name> --exact -Z stubbing`,
observe `VERIFICATION:- FAILED`, revert, confirm the source file is byte-identical to its
pre-mutation sha256, and re-run to confirm `VERIFICATION:- SUCCESSFUL`. **The difference: these runs
were executed on a clean, disposable cloud VM rather than the local box** — a fresh Ubuntu 22.04
instance, `cargo install --locked kani-verifier@0.67.0` + `cargo kani setup`, CBMC 6.8.0 installed
from the upstream release `.deb`, and a **fresh clone of the public repository at commit
`fc0dc5fd82d8d10652806b56ab8f5cf4d6c2eb47`**. Nothing from a developer machine was uploaded except
the run script itself, which is committed beside this file (`run.sh`).

**Predictions were recorded before the measurements were read.** Every run's expected verdict is a
literal argument in `run.sh`, written before the run; the driver compares it against the verdict it
then reads out of that run's own log and writes both columns into `verdicts.tsv`. That separation is
what makes these controls rather than observations.

**Result, in one line: sixteen runs, sixteen predictions matched — including the two predicted
GREENs.** Four planted defects (two per module), every predicted-RED run observed
`VERIFICATION:- FAILED` with the exact assertion named, every revert byte-identical by sha256, every
re-run green. The STOP-and-record protocol (record a gap before "fixing" anything) was not triggered.

**Source-state attribution.** `oid.rs` and `sequence.rs` at the cloned public commit hash to

```
252d5f61c7a125342388e09a923095aa294d22c45e74fd19f07497fae073cfa0  der-verified/src/oid.rs
c81cca7bf4fafbee5f625d005cd2e93eca097dff5b93849e8ed2e9777839a48c  der-verified/src/sequence.rs
```

— the same bytes these two files carry at the commit this evidence lands on, and at `69bbc9f`, the
commit the crate's current full-gate run (`evidence/check-69bbc9f.log`) was taken at:
`git diff fc0dc5f 69bbc9f -- der-verified/src/oid.rs der-verified/src/sequence.rs` is empty. So the
controls below concern the same code the green run does.

**Toolchain, read from the runs' own banners rather than assumed:** `Kani Rust Verifier 0.67.0
(cargo plugin)`, `CBMC 6.8.0 (cbmc-6.8.0)`, rustc `1.97.1` (only the non-Kani build path uses it;
Kani ships its own toolchain). Both match `PROOF_MANIFEST.md` §2's declared pins.

## Summary table

| Module | Planted defect | Harness(es) run against it | Predicted | Observed | Failed assertion |
|---|---|---|---|---|---|
| `oid` | **OID-A** — accept a non-minimal arc: the `0x80`-leading-octet check removed outright | `leading_0x80_is_non_minimal`, `later_0x80_is_non_minimal` | RED, RED | **FAILED** (both) | `validate_oid(&buf) == Err(OidError::NonMinimalSubid)` (`oid.rs:118` / `:129`) |
| `oid` | **OID-B** — accept a non-minimal arc *only in a later position*: the check narrowed to `i == 0` | `later_0x80_is_non_minimal` · `leading_0x80_is_non_minimal` | RED · **GREEN** | **FAILED** · SUCCESSFUL | `validate_oid(&buf) == Err(OidError::NonMinimalSubid)` (`oid.rs:129`) |
| `sequence` | **SEQ-A** — off-by-one the child count (`Ok(count)` → `Ok(count + 1)`) | `ok_implies_exact_tiling`, `roundtrip_two_children` | RED, RED | **FAILED** (both) | `seen == k` (`sequence.rs:280`) / `decode_sequence(content) == Ok(2)` (`:301`) |
| `sequence` | **SEQ-B** — accept a malformed child: the walk breaks instead of returning `Element(e)` | `ok_implies_exact_tiling` · `roundtrip_two_children` | RED · **GREEN** | **FAILED** · SUCCESSFUL | `unwrap_failed` in the independent re-walk (`sequence.rs:272`'s `.unwrap()`) |

The two **predicted-GREEN** rows are the point of the pairs, not padding: they are the runs that show
*which* harness earns its keep. A campaign that only ever plants defects its harnesses catch cannot
tell a load-bearing harness from a redundant one.

## 1. `oid.rs` — OID-A: accept a non-minimal arc encoding

Baseline sha256 `252d5f61c7a125342388e09a923095aa294d22c45e74fd19f07497fae073cfa0`.

**Baseline (green), before mutation** — `leading_0x80_is_non_minimal`:

```
$ cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "oid::proofs::leading_0x80_is_non_minimal" --exact -Z stubbing
...
Complete - 1 successfully verified harnesses, 0 failures, 1 total.
```
— `evidence/mutation-controls-2026-08-19-oid-sequence/00-base-oid-leading.log` (and `01-…-later.log`
for the second harness).

**Mutation planted** (`oid.rs`, `validate_oid`): the X.690 §8.19 minimality check commented out, so a
subidentifier beginning `0x80` — a redundant leading-zero base-128 group — is accepted:

```diff
-        if at_subid_start && b == 0x80 {
-            return Err(OidError::NonMinimalSubid);
-        }
+        // if at_subid_start && b == 0x80 {
+        //     return Err(OidError::NonMinimalSubid);
+        // }
```

**Run against the mutation — observed RED, verbatim:**

```
SUMMARY:
 ** 1 of 79 failed
Failed Checks: assertion failed: validate_oid(&buf) == Err(OidError::NonMinimalSubid)
 File: "der-verified/src/oid.rs", line 118, in oid::proofs::leading_0x80_is_non_minimal

VERIFICATION:- FAILED
Verification Time: 0.052784737s
```
— `04-oidA-leading.log`. The later-position harness catches it independently:

```
SUMMARY:
 ** 1 of 81 failed
Failed Checks: assertion failed: validate_oid(&buf) == Err(OidError::NonMinimalSubid)
 File: "der-verified/src/oid.rs", line 129, in oid::proofs::later_0x80_is_non_minimal

VERIFICATION:- FAILED
```
— `05-oidA-later.log`.

**Reverted.** sha256 confirmed byte-identical to baseline. Re-run of
`leading_0x80_is_non_minimal`: `VERIFICATION:- SUCCESSFUL` — `06-oidA-reverted.log`.

## 2. `oid.rs` — OID-B: accept a non-minimal arc *in a later position only*

The subtler half of the same defect class, and the one that separates the two harnesses. The
minimality check is narrowed to the first octet, so a `0x80`-led **second** subidentifier is
accepted while a `0x80`-led first one is still rejected:

```diff
-        if at_subid_start && b == 0x80 {
+        if at_subid_start && i == 0 && b == 0x80 {
```

This is exactly the defect the crate's own review history calls the "later-position proof gap", and
`later_0x80_is_non_minimal` exists because of it (`oid.rs`'s docstring says so in as many words).

**Predicted RED — observed RED, verbatim** (`07-oidB-later.log`):

```
SUMMARY:
 ** 1 of 81 failed
Failed Checks: assertion failed: validate_oid(&buf) == Err(OidError::NonMinimalSubid)
 File: "der-verified/src/oid.rs", line 129, in oid::proofs::later_0x80_is_non_minimal

VERIFICATION:- FAILED
Verification Time: 0.06136687s
```

**Predicted GREEN — observed GREEN** (`08-oidB-leading.log`): `leading_0x80_is_non_minimal` reports
`VERIFICATION:- SUCCESSFUL` under this mutation. That is the finding worth keeping: the
first-position harness is **blind** to a defect that leaves position 0 correct, and the crate's claim
that OID minimality holds at every subidentifier rests on the later-position harness specifically —
not on the pair being "two tests of the same thing".

**Reverted.** sha256 byte-identical; re-run of `later_0x80_is_non_minimal`:
`VERIFICATION:- SUCCESSFUL` — `09-oidB-reverted.log`.

## 3. `sequence.rs` — SEQ-A: off-by-one the child count

Baseline sha256 `c81cca7bf4fafbee5f625d005cd2e93eca097dff5b93849e8ed2e9777839a48c`.

```diff
-    Ok(count)
+    Ok(count + 1)
 }
```

**Observed RED, verbatim** (`10-seqA-tiling.log`) — `ok_implies_exact_tiling`, whose oracle is an
*independent* re-walk of the content rather than the implementation's own counter:

```
SUMMARY:
 ** 1 of 145 failed
Failed Checks: assertion failed: seen == k
 File: "der-verified/src/sequence.rs", line 280, in sequence::proofs::ok_implies_exact_tiling

VERIFICATION:- FAILED
Verification Time: 226.0129s
```

The round-trip harness catches it too, on concrete children (`11-seqA-roundtrip.log`):

```
SUMMARY:
 ** 1 of 477 failed (46 unreachable)
Failed Checks: assertion failed: decode_sequence(content) == Ok(2)
 File: "der-verified/src/sequence.rs", line 301, in sequence::proofs::roundtrip_two_children

VERIFICATION:- FAILED
```

**Reverted.** sha256 byte-identical; re-run of `ok_implies_exact_tiling`:
`VERIFICATION:- SUCCESSFUL` — `12-seqA-reverted.log`.

## 4. `sequence.rs` — SEQ-B: accept a malformed child instead of rejecting

The DER rule `decode_sequence` enforces is that the children **exactly tile** the content. This
mutation stops the walk on a bad child and reports success for the children seen so far — the
classic "accept a prefix" parser differential, and the shape a trailing-garbage smuggling attack
takes one level up:

```diff
             Ok(_) => count += 1,
-            Err(e) => return Err(SequenceError::Element(e)),
+            Err(_e) => break,
```

**Predicted RED — observed RED, verbatim** (`13-seqB-tiling.log`):

```
SUMMARY:
 ** 1 of 144 failed
Failed Checks: This is a placeholder message; Kani doesn't support message formatted at runtime
 File: ".../library/core/src/result.rs", line 1867, in std::result::unwrap_failed

VERIFICATION:- FAILED
Verification Time: 212.8572s
```

**Read that failure precisely, because its shape is unusual and it would be easy to over- or
under-claim.** The failing check is the `.unwrap()` at `sequence.rs:272` — inside
`ok_implies_exact_tiling`'s independent re-walk, which unwraps each child's `decode_tlv`. Under the
mutation `decode_sequence` returns `Ok(k)` for content whose children do *not* tile it, the harness
therefore enters its `if let Ok(k)` branch, and the re-walk then meets the malformed child the
implementation swallowed. So the oracle did catch the defect, and caught it *at the exact point the
implementation and the specification part company* — but it surfaces as a panic in the oracle's own
walk rather than as a named assertion, which is a weaker diagnostic than SEQ-A's `seen == k`. Both
are `VERIFICATION:- FAILED`; only one tells you why on the first line. Recorded as observed, not
tidied.

**Predicted GREEN — observed GREEN** (`14-seqB-roundtrip.log`): `roundtrip_two_children` reports
`VERIFICATION:- SUCCESSFUL` under this mutation, because its two concrete children are well-formed
and the error path is never taken. The crate's rejection discipline for SEQUENCE therefore rests on
the symbolic tiling harness, not on the round-trip one.

**Reverted.** sha256 byte-identical; re-run of `ok_implies_exact_tiling`:
`VERIFICATION:- SUCCESSFUL` — `15-seqB-reverted.log`.

## What this establishes, and what it does not

- **Establishes:** for `oid` and `sequence`, real defect classes (non-minimal arc acceptance in both
  first and later positions, an off-by-one child count, acceptance of a non-tiling child sequence)
  are caught by the harnesses whose documented job is to catch them, and those harnesses pass on the
  unmutated code — the two-directional control the review's lens 2 asks for, now covering seven of
  the crate's DER base codecs rather than five.
- **Establishes, additionally:** two harnesses are shown to be *individually* load-bearing rather
  than redundant, by the two predicted-GREEN runs — `oid::later_0x80_is_non_minimal` (the only
  harness that sees a later-position minimality defect) and `sequence::ok_implies_exact_tiling` (the
  only one that sees a swallowed malformed child).
- **Does not establish:** that every possible defect in these two modules would be caught. Four
  planted mutations are a sample, not an exhaustive mutation-testing sweep; there is no automated
  mutation tooling in this repository, and each mutation here was scripted by hand. It also says
  nothing about the remaining 25 modules' oracles.
- **Does not establish** anything about the Lean lids for these two codecs — that is a different
  lineage with its own controls (`evidence/LID-MUTATION-CONTROLS-2026-08-19.md`).
- **Final state:** both files confirmed byte-identical to their pre-mutation content
  (`final-sha256.txt` equals `baseline-sha256.txt`), `git status --porcelain` empty on the run host
  at the end of the campaign, and the host itself destroyed afterwards. The machine-readable verdict
  table is `verdicts.tsv`; the driver that produced everything here is `run.sh`; the raw CBMC output
  for the eight `sequence` runs is committed gzipped beside each distilled log, with the raw's
  sha256 and the distilling `grep` in the distilled file's own header.
