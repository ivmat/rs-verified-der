---
type: reference
---

# Oracle-falsifiability controls on the six Lean lids — 2026-08-19

**What this closes.** The crate owned a negative control for the L4 **gate**
(`evidence/lid-sorrygate-*.log`: an injected `sorry` was confirmed to fail `check_lean.sh`, so
sorry-freeness is enforced rather than eyeballed) and mutation controls for five **Kani** oracles
(`evidence/MUTATION-CONTROLS-2026-08-18.md`). It owned **no control of any kind for the Lean
lineage's own oracles**: nothing recorded that a lid would go RED if its theorem said the wrong
thing. A lid's `lake build` PASS was, until this file, an artifact nobody had ever watched fail for
a *statement* reason.

Those two are different claims and this file is deliberate about the difference. The sorry-gate
control attests **the gate** (a proof that cheats is caught). This one attests **the oracle** (a
theorem that says something false does not build). Both are worth having; only the second answers
"is the lid's statement load-bearing?".

**Method.** For each of the six lids: plant **one** mutation — a real defect class, not a no-op —
in the lid's THEOREM-relevant text, run `lake build DerVerified` from `lean/`, observe the build
**FAIL**, revert with `git checkout --`, confirm the file is **byte-identical** to its pre-mutation
sha256, and re-build. Two mutation kinds are used, and each row says which:

- **statement** — a comparison or equality flipped in the headline theorem's own postcondition
  (`length`, `tag`, `tlv`, `sequence`). This asks: does the proof actually depend on the property
  as stated, or would a neighbouring, false statement go through as well?
- **oracle** — a constant flipped inside the *independent predicate* the biconditional is stated
  against (`oid`'s `IsCanonicalOid`, `big_integer`'s `IsMinimalDer`). This asks the same question of
  the de-tautologised specification itself — the part of a biconditional lid that is not the
  production code and is therefore the part most able to drift into agreeing with anything.

The mutations were designed to make the theorem **false**, not merely different: a weaker statement
would still be provable and would prove nothing about the oracle. `lake build` was run directly
rather than through `lean/check_lean.sh`, because the extraction/drift stages that script runs first
are not what is under test here (and a mutated lid file would never reach them). No Kani, no solver
lane, no VM: local Lean only.

**STOP protocol.** If a planted mutation had NOT failed the build, that lid stops there and the
result is recorded as a genuine lid-oracle gap — the mutation is *not* tuned until it goes red.
**The protocol was not triggered: six for six went RED.**

## Summary table

| Lid | Kind | Planted mutation | Build | First error, verbatim |
|---|---|---|---|---|
| `LengthProofs.lean` | statement | `decode_accepts_only_canonical`: re-encoded consumption `relen.val = used.val` → `= used.val + 1` | **FAILED** | `LengthProofs.lean:812:4: unsolved goals` |
| `TagProofs.lean` | statement | `tag_decode_used_bounds`: lower consumption bound `1 ≤ used.val` → `2 ≤ used.val` | **FAILED** | `TagProofs.lean:368:2: Type mismatch` |
| `TlvProofs.lean` | statement | `decode_tlv_structure`: the no-over-read conjunct `used.val ≤ input.val.length` → `<` | **FAILED** | `TlvProofs.lean:500:12: Type mismatch` |
| `SequenceProofs.lean` | statement | `decode_sequence_structure`: exhausted-suffix conjunct `content.val.drop …` → `content.val.take …` | **FAILED** | `SequenceProofs.lean:730:2: Type mismatch` |
| `OidProofs.lean` | oracle | `IsCanonicalOid`: forbidden subidentifier-start octet `≠ 128` → `≠ 129` | **FAILED** | `OidProofs.lean:287:35: Application type mismatch` |
| `BigIntProofs.lean` | oracle | `IsMinimalDer`: the two redundant-padding octets swapped (`0x00` ↔ `0xFF` branches) | **FAILED** | `BigIntProofs.lean:161:8: unsolved goals` |

Every mutated file was restored to a **byte-identical sha256** before the next mutation
(`results.json` records both hashes per lid), and `git diff` over `lean/` is empty at the end.

**Toolchain, read from the tree the runs used:** Lean `leanprover/lean4:v4.30.0-rc2`
(`lean/lean-toolchain`), against the committed `Der*Extract.lean` models and the Aeneas Std library
at the revisions `lean/check_lean.sh` pins. `lake build DerVerified` — 1704 jobs, six of which are
the lids.

**An honest note on the "reverted" builds, because the timings would otherwise flatter them.** The
per-lid revert build (`M*-reverted.log`, ~2-4 s, exit 0) is a *trace check*: the restored file hashes
back to the state whose `.olean` is already cached, so `lake` correctly declares it up to date and
replays the cached messages. That confirms the restore, not the re-elaboration. So the six lids were
then **force re-elaborated from source in one final run** — their `.olean`/`.ilean`/`.trace`
artifacts deleted, `lake build DerVerified` re-run — and all six rebuilt green:

```
ℹ [1698/1704] Built OidProofs (2.6s)
⚠ [1699/1704] Built TlvProofs (3.7s)
⚠ [1700/1704] Built SequenceProofs (3.9s)
⚠ [1701/1704] Built BigIntProofs (3.0s)
⚠ [1702/1704] Built LengthProofs (4.2s)
⚠ [1703/1704] Built TagProofs (4.2s)
```
— `evidence/lid-mutation-controls-2026-08-19/ZZ-forced-reelaboration-all-six-restored.log`, exit 0.
(The `⚠` is the pre-existing `sorry` disclosure from Aeneas's own Std library, which
`check_lean.sh` reports and does not fail on — see its NOTE arm. `OidProofs` carries none.)

---

## 1. `LengthProofs.lean` — off-by-one the re-encoded consumption

```diff
 theorem decode_accepts_only_canonical (s : Slice U8) :
     length.decode_length s ⦃ r => ∀ (v : U32) (used : Usize), r = .Ok (v, used) →
         length.encode_length v ⦃ (re, relen) =>
-          relen.val = used.val ∧ ∀ i, i < used.val → re.val[i]! = s.val[i]! ⦄ ⦄ := by
+          relen.val = used.val + 1 ∧ ∀ i, i < used.val → re.val[i]! = s.val[i]! ⦄ ⦄ := by
```

The headline round-trip canonicality claim, off-by-one'd on the one number that makes it a
canonicality statement: re-encoding must reproduce *exactly* the consumed bytes.

**Observed RED, verbatim** (`M1-length-mutated.log`):

```
error: LengthProofs.lean:812:4: unsolved goals
case h.e'_3
...
this : length.encode_length i ⦃ (re, relen) => ↑relen = 1 ∧ ∀ i < 1, (↑re)[i]! = (↑s)[i]! ⦄
⊢ (uncurry fun re relen => ↑relen = 2 ∧ (↑re)[0] = (↑s)[0]?.getD default) =
    uncurry fun re relen => ↑relen = 1 ∧ (↑re)[0] = (↑s)[0]?.getD default
```

The short-form branch's round-trip lemma proves `relen = 1`; the mutated statement demands `2`. A
second failure follows in the long-form branch (`LengthProofs.lean:865:16`), so both accept paths
independently reject the mutation. Reverted: sha256 `4165c46b…14fe5b`, byte-identical.

## 2. `TagProofs.lean` — raise the consumption lower bound

```diff
 theorem tag_decode_used_bounds (input : Slice U8) (t : tag.Tag) (used : Usize) :
     tag.decode_tag input = ok (core.result.Result.Ok (t, used)) →
-      1 ≤ used.val ∧ used.val ≤ input.val.length := by
+      2 ≤ used.val ∧ used.val ≤ input.val.length := by
```

`2 ≤ used` is false for every low-tag identifier, which consumes exactly one octet — the most
common DER tag there is.

**Observed RED, verbatim** (`M2-tag-mutated.log`):

```
error: TagProofs.lean:368:2: Type mismatch
  hspec t used rfl
has type
  1 ≤ ↑used ∧ ↑used ≤ (↑input).length
but is expected to have type
  2 ≤ ↑used ∧ ↑used ≤ (↑input).length
```

Reverted: sha256 `54d720b1…3f20e8`, byte-identical.

## 3. `TlvProofs.lean` — strengthen no-over-read into a falsehood

```diff
           used.val = t_used.val + l_used.val + len.val ∧
-          used.val ≤ input.val.length ∧
+          used.val < input.val.length ∧
           t.value.val = input.val.slice (t_used.val + l_used.val) used.val ⦄ := by
```

This is the conjunct the lid is prized for — the security-critical no-over-read fact — and `<` is
false for a TLV that exactly fills its input, i.e. every well-formed top-level object.

**Observed RED, verbatim** (`M3-tlv-mutated.log`):

```
error: TlvProofs.lean:500:12: Type mismatch
  hend_le
has type
  ↑used ≤ (↑input).length
but is expected to have type
  ↑used < (↑input).length
```

Worth reading closely: `hend_le` is the hypothesis derived from `decode_tlv`'s **own runtime
guard**, and it is what discharges no-over-read. The mutation shows the theorem's security conjunct
is proved from that guard and cannot be nudged past what the guard gives. (Consistent with
`evidence/AXIOM-AUDIT-2026-08-18.md` §2.7's blast-radius finding: no-over-read comes from the
runtime guard, not from the two unproven `length_decode_used_le` axioms.)

**A second, unplanned observation, recorded because it was not predicted.** The mutated build's
`#print axioms` line for `decode_tlv_structure` lists **`sorryAx`** — Lean's error recovery admits
the failed proof, and the disclosure command then reports it. So `check_lean.sh`'s sorry-gate would
independently fail this mutation even if the build error were somehow tolerated. That is a second
layer nobody designed for this case; it is stated as an observation, not claimed as a designed
defence. Reverted: sha256 `1770fa6c…d9c8c4`, byte-identical.

## 4. `SequenceProofs.lean` — swap `drop` for `take` in the exhausted-suffix conjunct

```diff
       | core.result.Result.Ok _ =>
         ∃ finalRest : Slice U8,
-          finalRest.val = content.val.drop (content.val.length - finalRest.val.length) ∧
+          finalRest.val = content.val.take (content.val.length - finalRest.val.length) ∧
           finalRest.val.length = 0
```

A one-token typo of exactly the kind that would turn the ∀-children exact-tiling claim into
something else while still type-checking and still *looking* like a tiling statement.

**Observed RED, verbatim** (`M4-sequence-mutated.log`):

```
error: SequenceProofs.lean:730:2: Type mismatch
  decode_sequence_loop_spec content h32 0#usize { rest := content, done := false } hsuf hdone hcount
has type
  ... ∃ finalRest, ↑finalRest = List.drop ((↑content).length - (↑finalRest).length) ↑content ∧ (↑finalRest).length = 0 ...
but is expected to have type
  ... ∃ finalRest, ↑finalRest = List.take ((↑content).length - (↑finalRest).length) ↑content ∧ (↑finalRest).length = 0 ...
```

Reverted: sha256 `946d9bf8…8ba7ba`, byte-identical.

## 5. `OidProofs.lean` — wrong constant in the independent canonicality oracle

```diff
 def IsCanonicalOid (xs : List U8) : Prop :=
   xs ≠ [] ∧
-  (∀ p, p < xs.length → IsStart xs p → xs[p]!.val ≠ 128) ∧
+  (∀ p, p < xs.length → IsStart xs p → xs[p]!.val ≠ 129) ∧
   IsTerm xs[xs.length - 1]!
```

`0x80` is *the* forbidden subidentifier-start octet (X.690 §8.19's minimality rule); `0x81` is a
perfectly legal one. This mutates the **specification side** of the biconditional, so the production
code is untouched — precisely the failure a de-tautologised oracle exists to make impossible, and
the one a "the code agrees with the spec" proof cannot catch on its own if the two drift together.

**Observed RED, verbatim** (`M5-oid-mutated.log`):

```
error: OidProofs.lean:287:35: Application type mismatch: The argument
  h2
has type
  ∀ p < (↑content).length, IsStart (↑content) p → ↑(↑content)[p]! ≠ 129
but is expected to have type
  ∀ t < (↑content).length, IsStart (↑content) t → ↑(↑content)[t]! ≠ 128
```

The `128` on the "expected" side comes from the loop invariant, which recomputes the forbidden octet
from the production code's own read — so the mismatch is exactly the oracle-vs-implementation
disagreement the biconditional is supposed to detect. A second error at `:288:37` reports the other
direction of the `↔`. Reverted: sha256 `d9f4544b…1bcb388`, byte-identical.

## 6. `BigIntProofs.lean` — swap the two redundant-padding octets in the minimality oracle

```diff
 def IsMinimalDer (l : List U8) : Prop :=
   match l with
   | [] => False
   | [_] => True
-  | l0 :: l1 :: _ => l0 ≠ (if l1.val < 128 then 0#u8 else 255#u8)
+  | l0 :: l1 :: _ => l0 ≠ (if l1.val < 128 then 255#u8 else 0#u8)
```

The X.690 §8.3.2 rule keyed on the *implied sign-extension byte*: a leading `0x00` is redundant when
the next octet's top bit is clear, a leading `0xFF` when it is set. Swapping the two branches keeps
the shape and inverts the meaning — the same defect class as the F1 Kani campaign's `big_integer`
mutation, but planted on the oracle side instead of the implementation side.

**Observed RED, verbatim** (`M6-bigint-mutated.log`):

```
error: BigIntProofs.lean:161:8: unsolved goals
case pos
...
hc00 : l0 = 0#u8
hi1' : ↑l1 < 128
⊢ False
```

Read the goal: with a leading `0x00` and `l1 < 128` the content **is** non-minimal, the production
code rejects it, and the mutated oracle now calls it minimal — so the proof is asked for `False` and
cannot supply it. Two further branches fail the same way (`:163:8`, `:170:10`). Reverted: sha256
`6becbea1…8e065f`, byte-identical.

---

## What this establishes, and what it does not

- **Establishes:** for each of the six lids, a mutation that makes its headline claim FALSE — in
  four cases the theorem statement, in two the independent oracle predicate — is caught by
  `lake build`, and the restored source builds green under forced re-elaboration. The lids' claims
  are load-bearing: the proofs do not go through for a neighbouring, false statement, and the two
  biconditional lids do not agree with an oracle that has been quietly corrupted.
- **Does not establish:** that *every* wrong statement of these properties would be caught. Six
  planted mutations are a sample, not a mutation-testing sweep, and there is no automated mutation
  tooling for Lean wired into this repository. In particular this says nothing about a mutation that
  makes a theorem **weaker** (those stay provable by construction and are the real drift risk for a
  lid — a statement that quietly says less than a reader assumes), and nothing about the two
  assumptions the axiom audit flags as UNPROVEN (`length_decode_used_le` ×2 — see
  `ASSUMPTIONS.md` A6): an axiom cannot be falsified by a build, which is exactly why it is an axiom.
- **Does not establish** anything about the Aeneas extraction's fidelity (`ASSUMPTIONS.md` A4).
  Every control here is inside the Lean world. A mutation to a `Der*Extract.lean` model would be a
  different and also worthwhile control — it would ask whether the lids catch a wrong
  *implementation* rather than a wrong *statement* — and is not what this file did.
- **Final state:** all six lid files confirmed byte-identical to their pre-mutation content;
  `git diff` over `lean/` empty; raw build logs, per-mutation diffs and the machine-readable
  `results.json` in `evidence/lid-mutation-controls-2026-08-19/`.
