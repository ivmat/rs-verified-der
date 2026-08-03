---
type: reference
---

# Two defects in the Lean lid's gates, both watched to fail before and after — 2026-08-03

The task was the first defect only: the drift checks could report a **failed extraction** as a
**source change**. Fixing it meant running the lid green afterwards, and that green run is where the
second defect surfaced — the sorry-gate's warning arm had never matched anything in its life.

Both are in `lean/check_lean.sh`. Neither is a proof failure: no verified property changed, and the
171-harness Kani floor is untouched. What changed is what the gate is *able to tell you*.

## 1. Extraction failure was reported as a source change

`length`, `bigint`, `oid` and `tag` sent charon/aeneas output to `/dev/null` and went straight to
`diff -q`. (`tlv` and `sequence` already had `[ ! -f ]` guards; those two were never affected.)

**Reproduced, not inferred.** Fault injected by a shim `aeneas` that exits 0 and writes nothing —
the real charon still runs, and the toolchain-revision pins still pass, so the script reaches the
drift check exactly as it would in production:

```
== lean lid: re-extract (charon -> aeneas) + drift check ==
diff: /tmp/tmp.KZoykq0oLx/DerLengthExtract.lean: No such file or directory
!! lean lid: FAIL - regenerated model differs from committed DerLengthExtract.lean.
   length.rs changed; re-extract and re-prove before committing.
```

`length.rs` had not changed. — `lid-drift-faults-repro-unfixed.log`

**A second, worse mode was found while fixing it,** not previously recorded: when charon or aeneas
exits *non-zero*, `set -e` aborted the script with the tool's output already discarded. Injecting a
Rust syntax error into `length.rs` and running the **unfixed** script gives `rc=101` and **60 bytes
of output** — the section header and nothing else. A `check.sh` failing with no diagnostic at all.
— `lid-drift-faults-A2-charonfail-unfixed.log`

### After the fix — three distinct verdicts, each observed

| injected fault | verdict | log |
|---|---|---|
| aeneas exits 0, writes no model | `EXTRACTION FAILURE ... aeneas exited 0 but produced no DerLengthExtract.lean` + captured tool output | `lid-drift-faults-A-noextract-fixed.log` |
| charon exits non-zero (syntax error in `length.rs`) | `EXTRACTION FAILURE ... charon exited non-zero` + the full rustc error | `lid-drift-faults-A2-charonfail-fixed.log` |
| **a real source change** (`//!` line added to `length.rs`) | `MODEL DRIFT ... Extraction succeeded, so this is a real difference: length.rs changed` | `lid-drift-faults-B-realchange-fixed.log` |

The real-source-change case is the one that matters for the fix not being a whitewash: the gate had
to stay *able* to report drift, and it does. The `//!`-line fault is the exact mechanism that made
the lid red on 2026-08-03 (Aeneas embeds `Source: … lines N:M` spans in every model).

`length.rs` restored and confirmed byte-identical, sha256
`80ada6f0a9d47ae1fb1d6447073591e639dda3aa3c27078655d67a25f39ec2fc`.

## 2. ⚠ The sorry-gate's warning arm had never matched anything

Found because the green run after fix 1 printed `== lean lid: PASS (sorry-free) ==` while its own
build output contained three ``declaration uses `sorry` `` lines.

The gate matched `declaration uses '?sorry'?` — **ASCII single quotes**. Lean 4 emits **backticks**.
Measured directly against the green log: the gate's own pattern matches **0** lines of it, while the
same pattern matches a hand-written single-quoted line (positive control) and does **not** match the
backticked form Lean actually produces.

So the entire gate rested on its other arm, `sorryAx` in `#print axioms` output — and that arm only
sees declarations that *carry* such a line. They cover a subset: `LengthProofs.lean` has **17**
`#print axioms` disclosures over **42** theorems.

**The hole is real and was demonstrated, not argued:**

| injected `sorry` | `#print axioms`? | unfixed gate | log |
|---|---|---|---|
| `decode_short_form` | yes | **caught** — `sorryAx` in the axiom set, rc=1 | `lid-sorrygate-A-covered-theorem.log` |
| `decode_reserved` | **no** | **`PASS (sorry-free)`, rc=0** — with ``LengthProofs.lean:93:8: declaration uses `sorry` `` in the same output | `lid-sorrygate-B-uncovered-theorem-PASSED-unfixed.log` |

### The fix cannot be "match backticks too"

Aeneas's own Std ships sorries this repo neither owns nor can fix — `Aeneas/Std/Slice.lean` (×2) and
`Aeneas/Std/StringIter.lean`. Matching every sorry warning would pin the lid **permanently red**.
That is very likely why the arm was written loosely in the first place; it was never watched, so the
typo and the design problem both survived.

The warning arm is now scoped to files **outside** the dependency tree (`.lake/`, `Aeneas/`,
`Mathlib/`, `Batteries/`, `Init/`, `Std/`) — exactly the set whose sorry-freedom this lid claims.
Dependency sorries are **disclosed with a count** rather than ignored silently, so the number is
visible and a new one is noticeable:

```
-- lean lid: NOTE - 3 sorry warning(s) in DEPENDENCY
   files (Aeneas/Mathlib Std). Not ours, not failed on, disclosed so the count is visible:
   | Aeneas/Std/Slice.lean:363:4: declaration uses `sorry`
   | Aeneas/Std/Slice.lean:586:8: declaration uses `sorry`
   | Aeneas/Std/StringIter.lean:13:4: declaration uses `sorry`
```

With the fix, the case that previously passed now fails and names the file and line
(`lid-sorrygate-B-uncovered-theorem-fixed.log`):

```
!! lean lid: FAIL - a proof in a file THIS repo owns depends on 'sorry':
   | LengthProofs.lean:93:8: declaration uses `sorry`
   The unbounded proofs must be sorry-free.
```

`LengthProofs.lean` restored and confirmed byte-identical, sha256
`4165c46b1c914c661aafa0dd837a7f88aea5ab330b5e8faf57a6b5c72b14fe5b`.

## 2b. ⚠ A third defect, found by trying to commit the first two: the repo could not accept a
commit touching its own proof-bearing source

Committing the fixes above was **blocked by the pre-commit gate**, on
`test_gen_proof_manifest.py :: test_unchanged_since_head_is_true`.

The cause is today's own currency fix. `31b0994` changed `verified_source_unchanged_since` to
compare a commit against the **working tree** rather than against `HEAD` — correct, and it fixed a
real false claim. But `VERIFIED_PATHS` is `['der-verified/src', 'lean']`, and the self-test still
asserted the pre-change premise, *"HEAD vs HEAD: nothing can have changed"*, while reading the
developer's actual checkout. Under the new semantics that assertion is false whenever anything under
those two paths is uncommitted — which is the state the pre-commit hook runs in, on **every commit
that touches proof-bearing source**.

So from `31b0994` (pushed, public) onward, this repo could not accept a commit modifying
`der-verified/src` or `lean/`. It went unnoticed for one reason only:

```
$ git log --oneline 31b0994..HEAD -- der-verified/src lean
(empty)
```

No commit touched a verified path in between. The next one that did — this one — was stopped by its
own gate, with a self-test failure naming nothing real.

**Fix:** both tests now run against a throwaway git repo with `gen.ROOT` redirected, so they say
nothing about the ambient checkout. And the direction `31b0994` actually bought — *an uncommitted
edit under a verified path must already read as changed* — was covered by nothing, which is why the
mismatch shipped; it now has a test.

**Both were watched to fail,** by mutating `verified_source_unchanged_since`'s return:

| mutation | test that fails | reads |
|---|---|---|
| always `return True` | `test_uncommitted_edit_to_verified_source_reads_as_changed` | `FAILED (failures=1)` |
| always `return False` | `test_unchanged_since_head_is_true` | `FAILED (failures=1)` |

Each mutation kills exactly one test and the correct one. `gen_proof_manifest.py` restored
byte-identical, sha256 `1095a6a92e9f7ac8394466e299587aa56c1b99d1e30c45caed50422cca023514`.

## 3. Green, after both fixes

`rc=0`, `Build completed successfully (1704 jobs)`, `== lean lid: PASS (sorry-free) ==`, with the
three dependency sorries disclosed. — `lid-green-2026-08-03.log`

Run under a **computed** cap (`MemoryMax=20G`, `MemoryHigh=18G`, `MemorySwapMax=0`,
`AVAIL_MB≈22.7 GB`). The lid is not the memory-hungry stage — the ~24 GB figure in `README.md` is
the **Kani** floor's requirement, not this lid's. No Kani run was attempted today; see
`FLOOR-2026-08-03.md` for why the full floor cannot complete on this box with the desktop up.

## 4. What is NOT established

- **That the sorry-gate is now complete.** It is two arms, both now live, and the warning arm is the
  broad one. But it reads `lake build` *output*: a declaration whose warning Lean elides on a fully
  cached rebuild would not be seen. Every run recorded here rebuilt the affected file, because the
  injection forced re-elaboration. **A cold-cache vs warm-cache comparison of the warning set has
  not been done**, and until it is, "no sorry warnings" is a claim about this build, not all builds.
- **That the dependency prefix list is exhaustive.** `.lake/ Aeneas/ Mathlib/ Batteries/ Init/ Std/`
  covers what this toolchain emits today. A new dependency with a different path root would be
  classified as *ours* — which fails safe (a false red, not a false green), but is untested.
- **Anything about the 171-harness Kani floor.** Not run. Unchanged.
- **A second-model review of these two fixes.** Recorded in §5 of the session report; **missing from
  `measurements/review_correlation.jsonl`**.
