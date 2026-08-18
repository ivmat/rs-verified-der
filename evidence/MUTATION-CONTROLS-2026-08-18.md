---
type: reference
---

# Mutation controls on the primitive oracles — `length`/`tag`/`tlv`/`integer`/`big_integer`, 2026-08-18

**Task:** the 2026-08-16 rigor re-review's F1 (`autonomous-run/REVIEW-QUEUE/_RIGOR-REREVIEW-der-2026-08-16.md`
§5), implementing mutation-control review lens 2: *"Plant a subtly-wrong implementation ... and
confirm the oracle FAILS it. Confirm a correct implementation PASSES. If the oracle cannot
distinguish, it is wrong — regardless of a green run."*

**What this closes.** The review found reachability covers (§8.2) prove the `Ok` tail is *live*,
but nothing in the repository recorded the *negative* control: that the canonicality/classification
oracles would actually **FAIL** a wrong decoder. This is that recording, for the five primitive
oracles the review named: `length`, `tag`, `tlv`, `integer`, `big_integer`.

**Method.** For each module: plant one subtly-wrong implementation (a real defect class, not a
no-op), run the specific harness(es) whose job is to catch that class of defect with
`cargo kani --harness <fq-name> --exact -Z stubbing` under
`systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0` (targeted single-harness runs, no
full-crate sweep), observe `VERIFICATION:- FAILED`, revert, confirm the source file is
byte-identical to its pre-mutation sha256, and re-run the same harness to confirm
`VERIFICATION:- SUCCESSFUL` again. Every run recorded below is from `Kani Rust Verifier 0.67.0`
against `CBMC 6.8.0 (cbmc-6.8.0)` — read from each run's own banner, not assumed; both match the
pinned versions in `PROOF_MANIFEST.md` §2.

**Result, in one line: five for five.** Every planted defect flipped every harness run against it
to `FAILED`, with the exact assertion line named. No oracle gap was found — the STOP-and-record
protocol (record a gap before "fixing" anything) was not triggered for any of the five. Every
mutated file was restored to byte-identical (sha256-verified) before the next mutation, and the
full five-file `git diff` is empty at the end of this session.

## Summary table

| Module | Planted defect | Harness(es) run against the defect | Result | Failed assertion |
|---|---|---|---|---|
| `length` | accept a non-minimal long-form length (removed the `val < 0x80 → NonMinimal` check) | `decode_accepts_only_canonical`, `long_form_of_short_value_is_non_minimal` | **FAILED** (both) | `relen == used` / `decode_length(&[0x81, v]) == Err(LengthError::NonMinimal)` |
| `tag` | accept a non-minimal high-tag encoding of a number `<= 30` (removed the `number <= 30 → NonMinimal` check) | `decode_tag_accepts_only_canonical`, `high_tag_of_small_number_is_non_minimal` | **FAILED** (both) | `relen == used` / `decode_tag(&[first, v]) == Err(TagError::NonMinimal)` |
| `tlv` | off-by-one the reported consumed count (`used` returned as `end + 1` instead of `end`) | `decode_tlv_structure`, `tlv_roundtrip_small` | **FAILED** (both) | `used as u64 == header as u64 + len_u32 as u64` / `used == n` |
| `integer` | accept a redundant-padded INTEGER (removed the two-octet leading-`0x00`/`0xFF` `NonMinimal` check) | `decode_accepts_only_minimal`, `redundant_positive_padding_is_non_minimal`, `redundant_negative_padding_is_non_minimal` | **FAILED** (all three) | `relen == n` / `decode_integer(&[0x00, c]) == Err(IntError::NonMinimal)` / `decode_integer(&[0xFF, c]) == Err(IntError::NonMinimal)` |
| `big_integer` | wrong index — the minimality check reads `content[0]` twice instead of `content[0]`/`content[1]` | `validate_iff_minimal_oracle` (the independent, de-tautologized oracle) | **FAILED** | `accepted == oracle_says_ok` |

Every row's "reverted" run (below) reconfirms the SAME harness `VERIFICATION:- SUCCESSFUL` after
the source file's sha256 was checked byte-identical to its pre-mutation value — the two-directional
control the task specifies.

## 1. `length.rs` — accept a non-minimal long-form length

Baseline sha256 `80ada6f0a9d47ae1fb1d6447073591e639dda3aa3c27078655d67a25f39ec2fc`.

**Baseline (green), before mutation** — `decode_length(&[0x81, v])` for `v < 0x80` correctly
classified `NonMinimal` (`length::proofs::long_form_of_short_value_is_non_minimal`):

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "length::proofs::long_form_of_short_value_is_non_minimal" --exact -Z stubbing
```
→ `VERIFICATION:- SUCCESSFUL` — `evidence/mutation-controls-2026-08-18/01-length-baseline-classify.log`

**Mutation planted** (`length.rs`, `decode_length`): commented out the minimality check so a
long-form encoding of a value `< 0x80` is accepted instead of rejected:

```diff
-    if val < 0x80 {
-        return Err(LengthError::NonMinimal); // long form for a short-form value
-    }
+    // if val < 0x80 {
+    //     return Err(LengthError::NonMinimal); // long form for a short-form value
+    // }
     Ok((val, 1 + n))
```

**Run against the mutation — observed RED, verbatim:**

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "length::proofs::long_form_of_short_value_is_non_minimal" --exact -Z stubbing
...
SUMMARY:
 ** 1 of 134 failed
Failed Checks: assertion failed: decode_length(&[0x81, v]) == Err(LengthError::NonMinimal)
 File: "der-verified/src/length.rs", line 204, in length::proofs::long_form_of_short_value_is_non_minimal

VERIFICATION:- FAILED
Verification Time: 0.075747475s

Manual Harness Summary:
Verification failed for - length::proofs::long_form_of_short_value_is_non_minimal
Complete - 0 successfully verified harnesses, 1 failures, 1 total.
```
— `evidence/mutation-controls-2026-08-18/02-length-mutated-classify.log`

The canonicality oracle (`decode_accepts_only_canonical`) independently catches the same defect —
run against the same mutation, before reverting:

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "length::proofs::decode_accepts_only_canonical" --exact -Z stubbing
...
SUMMARY:
 ** 1 of 80 failed
Failed Checks: assertion failed: relen == used
 File: "der-verified/src/length.rs", line 159, in length::proofs::decode_accepts_only_canonical

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/02-length-mutated-canonical.log`

**Reverted.** sha256 confirmed byte-identical to baseline
(`80ada6f0a9d47ae1fb1d6447073591e639dda3aa3c27078655d67a25f39ec2fc`). Re-run of
`long_form_of_short_value_is_non_minimal` on the restored source:
`VERIFICATION:- SUCCESSFUL` — `evidence/mutation-controls-2026-08-18/03-length-reverted-classify.log`.

## 2. `tag.rs` — accept a non-minimal high-tag encoding

Baseline sha256 `3951b29aee75f3dd9ede31df6910e44b885d8a35ff9bee8a5eb145643d7c3ebe`.

**Mutation planted** (`tag.rs`, `decode_tag`): commented out the check that rejects a high-tag-form
encoding of a number `<= 30` (which must use the low-tag form):

```diff
     let (number, i) = state?;
-    if number <= 30 {
-        return Err(TagError::NonMinimal); // high-tag form for a low-tag-representable number
-    }
+    // if number <= 30 {
+    //     return Err(TagError::NonMinimal); // high-tag form for a low-tag-representable number
+    // }
     Ok((Tag { class, constructed, number }, i))
```

**Run against the mutation — observed RED, verbatim** (`high_tag_of_small_number_is_non_minimal`):

```
SUMMARY:
 ** 1 of 141 failed
Failed Checks: assertion failed: decode_tag(&[first, v]) == Err(TagError::NonMinimal)
 File: "der-verified/src/tag.rs", line 233, in tag::proofs::high_tag_of_small_number_is_non_minimal

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/04-tag-mutated-classify.log`

The canonicality oracle also catches it, same mutation:

```
SUMMARY:
 ** 1 of 80 failed
Failed Checks: assertion failed: relen == used
 File: "der-verified/src/tag.rs", line 218, in tag::proofs::decode_tag_accepts_only_canonical

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/04-tag-mutated-canonical.log`

**Reverted.** sha256 confirmed byte-identical to baseline. Re-run of
`high_tag_of_small_number_is_non_minimal`: `VERIFICATION:- SUCCESSFUL` —
`evidence/mutation-controls-2026-08-18/05-tag-reverted-classify.log`.

## 3. `tlv.rs` — off-by-one the consumed count

Baseline sha256 `8912d3e9807032107606962105e7acb312ed9f7ee16a9f106ba35c4dc0d9719d`.

**Mutation planted** (`tlv.rs`, `decode_tlv`): the returned `used` count is `end + 1` instead of
`end` — the classic "off-by-one the consumed count" defect class F1 names explicitly:

```diff
-    Ok((Tlv { tag, value: &input[header..end] }, end))
+    Ok((Tlv { tag, value: &input[header..end] }, end + 1))
```

**Run against the mutation — observed RED, verbatim** (`decode_tlv_structure`, the harness whose
whole purpose is to pin `used` against the spec-level `header + len` sum, independently of
`decode_tlv`'s own internal cast):

```
SUMMARY:
 ** 1 of 130 failed (3 unreachable)
Failed Checks: assertion failed: used as u64 == header as u64 + len_u32 as u64
 File: "der-verified/src/tlv.rs", line 188, in tlv::proofs::decode_tlv_structure

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/06-tlv-mutated-structure.log`

The round-trip harness also catches it, same mutation:

```
SUMMARY:
 ** 1 of 224 failed (21 unreachable)
Failed Checks: assertion failed: used == n
 File: "der-verified/src/tlv.rs", line 206, in tlv::proofs::tlv_roundtrip_small

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/06-tlv-mutated-roundtrip.log`

**Reverted.** sha256 confirmed byte-identical to baseline. Re-run of `decode_tlv_structure`:
`VERIFICATION:- SUCCESSFUL` — `evidence/mutation-controls-2026-08-18/07-tlv-reverted-structure.log`.

## 4. `integer.rs` — accept a redundant-padded INTEGER

Baseline sha256 `fe478ec1d75fb90be90904cd1fe392444f9edfa004d760f35a35e0eeb12ca94a`.

**Mutation planted** (`integer.rs`, `decode_integer`): commented out the two-octet leading-padding
check — the defect class F1 names explicitly ("accept a redundant-padded integer"):

```diff
-    if content.len() >= 2 {
-        let c0 = content[0];
-        let c1 = content[1];
-        if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
-            return Err(IntError::NonMinimal);
-        }
-    }
+    // if content.len() >= 2 {
+    //     let c0 = content[0];
+    //     let c1 = content[1];
+    //     if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
+    //         return Err(IntError::NonMinimal);
+    //     }
+    // }
```

**Run against the mutation — observed RED, verbatim**, on all three harnesses that exercise this
check:

```
SUMMARY:
 ** 1 of 71 failed
Failed Checks: assertion failed: relen == n
 File: "der-verified/src/integer.rs", line 137, in integer::proofs::decode_accepts_only_minimal

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/08-integer-mutated-minimal.log`

```
SUMMARY:
 ** 1 of 96 failed
Failed Checks: assertion failed: decode_integer(&[0x00, c]) == Err(IntError::NonMinimal)
 File: "der-verified/src/integer.rs", line 153, in integer::proofs::redundant_positive_padding_is_non_minimal

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/08-integer-mutated-positive-padding.log`

```
SUMMARY:
 ** 1 of 96 failed
Failed Checks: assertion failed: decode_integer(&[0xFF, c]) == Err(IntError::NonMinimal)
 File: "der-verified/src/integer.rs", line 161, in integer::proofs::redundant_negative_padding_is_non_minimal

VERIFICATION:- FAILED
```
— `evidence/mutation-controls-2026-08-18/08-integer-mutated-negative-padding.log`

**Reverted.** sha256 confirmed byte-identical to baseline. Re-run of `decode_accepts_only_minimal`:
`VERIFICATION:- SUCCESSFUL` — `evidence/mutation-controls-2026-08-18/09-integer-reverted-minimal.log`.

## 5. `big_integer.rs` — wrong index in the minimality check

Baseline sha256 `d6a19e010323f58f6fd3501ccb4dc84bf3c21a9dc7ba6d4d9ff11816d45409db`.

**Mutation planted** (`big_integer.rs`, `validate_integer_content`): the defect class F1 names
explicitly ("wrong index") — `c1` is bound to `content[0]` a second time instead of `content[1]`, so
the minimality check no longer inspects the byte that X.690 §8.3.2 actually keys on:

```diff
     if content.len() >= 2 {
         let c0 = content[0];
-        let c1 = content[1];
+        let c1 = content[0];
         if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
             return Err(BigIntError::NonMinimal);
         }
     }
```

Note on which harness this targets, precisely, and why it matters (this is the crate's flagship
Lens-2 case, per the review): the mutated condition degenerates to "reject whenever `content[0]` is
`0x00` or `0xFF`", independent of `content[1]`. That makes it **stricter** than correct in one
direction — e.g. `[0x00, 0x80, ...]` (minimal: the `0x00` guard byte IS required because
`content[1]`'s top bit is set) is now wrongly rejected as `NonMinimal`. The crate's own
`redundant_positive_padding_is_non_minimal`-style 2-octet harnesses only exercise the *known-bad
input is rejected* direction and would not surface this false rejection (both the correct and the
mutated conditions reject their fixed `[0x00, c]`/`[0xFF, c]` specimens the same way, by
construction of the assumed `c`) — this crate's own docs call out exactly this shape of risk
(`PROOF_MANIFEST.md` §8.3: "a shared misreading would survive" a structurally-similar oracle). The
biconditional `validate_iff_minimal_oracle` is the harness actually built to catch it, because
`is_minimal_oracle` is independently phrased against the *implied sign-extension byte* of
`content[1]` rather than replaying the same two-branch `if`-chain — so it is the one run here.

**Run against the mutation — observed RED, verbatim:**

```
$ systemd-run --user --scope -p MemoryMax=8G -p MemorySwapMax=0 -- \
    cargo kani --manifest-path der-verified/Cargo.toml \
    --harness "big_integer::proofs::validate_iff_minimal_oracle" --exact -Z stubbing
...
SUMMARY:
 ** 1 of 50 failed
Failed Checks: assertion failed: accepted == oracle_says_ok
 File: "der-verified/src/big_integer.rs", line 177, in big_integer::proofs::validate_iff_minimal_oracle

VERIFICATION:- FAILED
Verification Time: 0.07885997s
```
— `evidence/mutation-controls-2026-08-18/10-bigint-mutated-oracle.log`

**Reverted.** sha256 confirmed byte-identical to baseline. Re-run of `validate_iff_minimal_oracle`:
`VERIFICATION:- SUCCESSFUL` — `evidence/mutation-controls-2026-08-18/11-bigint-reverted-oracle.log`.

## What this establishes, and what it does not

- **Establishes:** for each of the five primitives, at least one real, non-trivial defect class
  (non-minimal acceptance, an off-by-one consumed-count, a wrong-index typo) is caught by the
  harness(es) whose documented job is to catch it, and the same harness passes on the unmutated
  code — the two-directional control Lens 2 asks for. No oracle gap was found; the STOP protocol
  was not exercised.
- **Does not establish:** that *every* possible defect in these five modules would be caught — five
  planted mutations are a sample, not an exhaustive mutation-testing sweep (this crate has no
  automated mutation-testing tool wired in; each mutation here was hand-planted and hand-reverted).
  It also says nothing about the other 27 modules' oracles, which F1 did not scope in.
- **Toolchain, read from the runs themselves:** `Kani Rust Verifier 0.67.0 (cargo plugin)`, `CBMC
  6.8.0 (cbmc-6.8.0)` — matches the pins declared in `PROOF_MANIFEST.md` §2 and observed there on
  2026-08-11.
- **Final state:** all five files (`length.rs`, `tag.rs`, `tlv.rs`, `integer.rs`,
  `big_integer.rs`) are confirmed byte-identical to their pre-mutation content; `git diff` is empty
  for all five at the end of this session.
