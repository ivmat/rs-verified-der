# The proof-manifest self-test no longer depends on tree state — re-verification, and two further holes

**Date:** 2026-08-03, after `75aa03c`. Written by a session that did not write `75aa03c`.
**Subject:** `gates/test_gen_proof_manifest.py::HeadCoverageFact`, and the production predicate
`gen_proof_manifest.verified_source_unchanged_since`.

The tree-state fix itself landed in `75aa03c` ("the third defect"). This file records (1) an
independent re-run of its acceptance criteria, because "mutation-killed" in a commit message is not
itself a check, and (2) **two further defects that re-run then exposed**, both fixed here.

Every injection below was reverted and confirmed byte-identical with `sha256sum -c`. The only files
this work leaves changed are `gates/test_gen_proof_manifest.py` and this record.

## What the defect was

`verified_source_unchanged_since` diffs the **working tree** against the recorded commit (`git diff
<commit> -- <paths>`, deliberately no `..HEAD` — `31b0994`), so an edit to verified source reads as
superseding a recorded run immediately rather than one commit later. That semantics is correct and
load-bearing: it was itself the fix for a false proof-currency claim published to a public repo, and
nothing here changes it.

The self-test, however, asserted the predicate True **against the developer's own checkout**. With
`VERIFIED_PATHS = ['der-verified/src', 'lean']`, that assertion is false whenever a change under those
paths is visible to `git diff` — tracked edits and staged additions — which is the state the
pre-commit hook runs in. (An *untracked* file is not visible to `git diff <commit> -- <paths>`;
measured: with an untracked `der-verified/src/_untracked_probe.rs` present, the predicate still
returns `True`. So the trigger is "a tracked or staged change", not literally "anything uncommitted".)

## 1. The suite passes with the real tree dirty under both VERIFIED_PATHS

```
$ printf '\n// scratch edit\n' >> der-verified/src/lib.rs
$ printf '\n# scratch edit\n'  >> lean/check_lean.sh
$ git status --porcelain -- der-verified/src lean
 M der-verified/src/lib.rs
 M lean/check_lean.sh

$ ./check_fast.sh                      # the whole pre-commit gate, not just the self-test
Ran 29 tests in 1.537s
OK
== check_fast.sh: PASS (Kani + Lean NOT run here — run check.sh at milestones) ==
                                       rc=0
```

**Differential control — the same dirty tree, pre-fix test file** (`git show
75aa03c^:gates/test_gen_proof_manifest.py`), so the two runs differ only in the test:

```
Ran 27 tests in 1.548s
FAIL: test_unchanged_since_head_is_true
  line 297: self.assertTrue(gen.verified_source_unchanged_since(head))
AssertionError: False is not true
FAILED (failures=1)                    rc=1
```

The red is reproducible on demand and the green is not an accident of a clean tree.
Restored: `sha256sum -c` OK on both files.

## 2. The production semantics are enforced — mutants of the FUNCTION, killed by name

Each mutant was applied to `gates/gen_proof_manifest.py`, the full suite run, the file restored
(`sha256sum -c` → OK each time).

| mutant | rc | killed by |
|---|---|---|
| **M1** — revert `31b0994`: diff `commit..HEAD` instead of the working tree | 1 | `test_uncommitted_edit_to_verified_source_reads_as_changed` |
| **M2** — always `True` (after the unrecorded-commit guard) | 1 | `…reads_as_changed` + `…predating_a_committed_source_change…` |
| **M3** — always `False` (after the guard) | 1 | `test_unchanged_since_head_is_true` + `…predating…` |
| **M4** — ignore the recorded commit; ask only "is the tree dirty?" (`git diff HEAD -- paths`) | 1 | `test_commit_predating_a_committed_source_change_reads_as_changed` |

**M3 is what shows the hermetic test is not vacuous.** Moving a test onto a fixture the test builds
clean risks asserting only that a clean thing is clean; M3 shows `test_unchanged_since_head_is_true`
still goes red when the predicate stops answering truthfully. M1 shows the semantics `31b0994` bought
cannot be reverted without a named test noticing.

M2 does not additionally kill `test_unrecorded_commit_is_unknown_not_true`, and should not be read as
if it did: the injection sits *after* the `not commit or commit == 'unrecorded'` guard, so that path
still returns `None`.

### 2a. **M4 was green before this session — a real hole, found by the second model**

Both of `75aa03c`'s tests move the **working tree** and leave the recorded commit at HEAD. A predicate
that ignored its own argument and merely asked *"is the verified tree dirty?"* therefore satisfied
both while answering a different question. Measured before the fix: **`rc=0`, `Ran 28 tests`, `OK`.**

That is the predicate's whole job — *does the run recorded at THIS COMMIT still speak for what is here
now* — so it must read False for an **old commit on a perfectly clean tree**, the ordinary state of a
repo whose proofs have gone stale. `test_commit_predating_a_committed_source_change_reads_as_changed`
now pins it, asserting the fixture is clean first so it cannot pass for the dirty-tree reason, and
asserting the *new* commit still reads True so it is not merely "always False". With it, M4 fails,
killed by that test alone.

## 3. The three MutationKill tests are green AND non-vacuous

Green in the clean run: `test_gutting_the_comparison_is_caught`, `test_reverting_the_fix_is_caught`,
`test_widening_the_advisory_set_is_caught` — all `ok`.

Green is not enough, since each asserts a *subset* relation against a kill-set. Fault-injected
`MutationKill._kills` to return `set()` ("pretend nothing was killed"):

```
FAIL: test_gutting_the_comparison_is_caught
FAIL: test_reverting_the_fix_is_caught
FAIL: test_widening_the_advisory_set_is_caught
Ran 28 tests    FAILED (failures=3)    rc=1
```

All three depend on real kills. Test file restored.

## 4. The fixture was hermetic from the tree but **not from the ambient git environment**

The second defect this re-run exposed. `_throwaway_repo` overrode `user.email`/`user.name` but
inherited everything else, so a contributor with `commit.gpgsign` set and no usable key, or a
`core.hooksPath` pointing at a global hook, or a global init template shipping a `pre-commit`, would
have the **seed commit** fail — reddening the suite for something that is not this gate's business.
That is the same defect class as the one this task was opened for.

None of those settings are set on this machine (`commit.gpgsign`, `core.hooksPath`, `init.templatedir`,
`init.defaultBranch` all unset), which is exactly why they needed pinning rather than assuming.
Simulated with a hostile-but-legitimate contributor environment — `GIT_CONFIG_GLOBAL` setting
`commit.gpgsign=true` with `gpg.program=/bin/false`, plus a `GIT_TEMPLATE_DIR` whose `hooks/pre-commit`
exits 1:

```
committed fixture (75aa03c):   Ran 28 tests   FAILED (errors=2)   rc=1
                               ERROR: test_unchanged_since_head_is_true
                               ERROR: test_uncommitted_edit_to_verified_source_reads_as_changed
hardened fixture (this file):  Ran 29 tests   OK                  rc=0
```

The fixture now overrides signing and hooks per-invocation, scrubs `GIT_*` from the child environment,
and passes an empty `--template=`.

## 5. ⚠ ESCALATION — not fixed here: the manifest tells the reader to run the OLD command

`r_evidence_coverage` renders, for a live run log:

> ``git diff <commit>..HEAD -- der-verified/src lean`` is empty. **Run that command rather than
> trusting this sentence.**

That is the `..HEAD` form `31b0994` deliberately removed from the predicate. The sentence is produced
by one check and audited by a different one, and on a dirty verified tree the two can disagree — the
reader's command can report "empty" where the predicate says superseded. This is the same
over-claiming shape `31b0994` fixed, one layer out.

**Left alone deliberately.** It is production output in a PUBLIC manifest, the dispatch scoped this
work to the test's tree-state dependency and warned specifically against touching this function's
production behaviour, and correcting the prose means regenerating `PROOF_MANIFEST.md`. Owner's call.

## Not verified here

- **The Kani floor was not run.** `./check.sh` was not attempted: `PROOF_MANIFEST.md` records
  `x509_extension::validate_extensions_never_panics` at ~20.5 GiB and `README.md` puts the floor near
  24 GB, against `MemAvailable` ~23 GB with the desktop up — a computed cap of `avail − 2G` lands
  *below* the documented requirement. No proof, harness or verified property is touched by this work,
  but the floor is **unrun**, not green.
- **The Lean lid was not run** — for scope, *not* for memory. `LID-GATE-FAULTS-2026-08-03.md` is
  explicit that the lid is not the memory-hungry stage and the ~24 GB figure is Kani's. `75aa03c` also
  rewrote the lid's sorry gate **and** its extraction-failure/drift handling; **neither is
  re-verified here.**
- **`cargo test` and the gates are the only executed evidence** for this change.
- The second-model review that found §2a and §4 is **absent from
  `measurements/review_correlation.jsonl`** — `review.py` cannot run on this box
  (`ModuleNotFoundError: httpx`), so no linux review reaches that ledger.
- The transient mutation runs are transcribed here rather than kept as raw logs; the final hashes and
  tree state evidence restoration, not every intermediate command.
