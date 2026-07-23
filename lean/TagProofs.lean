import DerTagExtract

/-!
# Unbounded (∀-length) totality and consumption bound of the DER tag (identifier) codec

This theorem is proved in Lean 4 over the **Aeneas-extracted** model of the *same*
`der-verified/src/tag.rs` that the Kani floor proves — single source of truth: the extraction
crate `#[path]`-includes that file, and `lean/check_lean.sh` re-extracts and diffs on every run to
guard against drift.

## A source refactor was required first (behavior-preserving, mirrors D25)

`decode_tag`'s original high-tag base-128 loop had three `return`s **nested inside its `loop`**
(`return Err(Truncated)` / `return Err(NonMinimal)` / `return Err(TooLarge)`). Aeneas's Lean
backend cannot extract a function body with a `return` nested inside a `loop` ("Breaks to outer
loops are not supported yet"), so `decode_tag` extracted as a **bodyless axiom** — exactly the
shape `oid::validate_oid` hit before D25's refactor, and exactly what `TlvProofs.lean` /
`SequenceProofs.lean` (D27/D28) had to assume about `decode_tag` via `tag_decode_used_bounds` /
`tag_decode_total` because it was opaque to Lean at the time those lids were written.

Fix, applied to the shipped `tag.rs` (single source of truth — the same file the Kani floor
proves): every early `return` inside the loop became a `break` carrying the outcome in an
accumulated `Result<(u32, usize), TagError>` (`state`), matched **once**, after the loop, via `?`.
Behavior is **identical** — proven, not asserted: `cargo test` (295 tests) and all `tag::proofs::*`
Kani harnesses (`roundtrip_all_tags`, `decode_tag_never_panics`, `decode_tag_accepts_only_canonical`,
`high_tag_of_small_number_is_non_minimal`, `leading_zero_high_tag_is_non_minimal`,
`truncated_high_tag_is_classified`, `too_large_tag_is_classified`) re-passed on the refactored code
(re-run by me via real exit codes, `cargo kani -Z stubbing --harness tag`, 16/16 SUCCESSFUL). With
this fix `decode_tag` now extracts **with a body** (`tag.decode_tag_loop` / `.body`, the Aeneas
`loop` combinator — see `DerTagExtract.lean`), unlocking the theorems below.

**`encode_tag` is marked `--opaque`** during this module's own extraction pass (same parameter-
shadowing workaround `TlvProofs.lean`/`SequenceProofs.lean` already use for `tag::encode_tag` /
`tlv::encode_tlv_into`: a Rust parameter named `tag` shadows the `tag` module in Aeneas's Lean
dot-notation resolution, "Invalid field" elaboration errors). `decode_tag` never calls
`encode_tag`, so this loses nothing for this lid's scope (it proves properties of `decode_tag`
only).

## What's proven (sorry-free, ∀-length)

* **`tag_decode_total`** — `decode_tag` always returns `ok (Result.Ok _ | .Err _)`: it never
  `fail`s or `div`erges, for an input of *any* length. The Lean-level restatement of "`decode_tag`
  never panics", now a genuine THEOREM (derived from the extracted body's control flow — every
  arithmetic op on the loop's live path is `lift`ed/checked, never raw) rather than an assumed
  axiom.
* **`tag_decode_used_bounds`** — whenever `decode_tag input` accepts `Ok (t, used)`, `1 ≤ used ≤
  input.length`: an accepted decode never claims zero bytes, and never consumes more than the
  input holds, for an input of *any* length.

Both are proven by a `loop.spec_decr_nat` measure-induction over `tag.decode_tag_loop`'s
`(i, number, count)` state (measure `input.length - i.val`, strictly decreasing on every `cont`
step since the loop's only continuation reads and consumes exactly one more octet, advancing
`i` to `i + 1`), mirroring `LengthProofs.lean`'s `decode_length_loop_spec` / `OidProofs.lean`'s
`validate_oid_loop_spec` — the same idiom this crate has used for every unbounded-loop lid so far.

## Trust surface

The extraction is nearly axiom-free: the *only* opaque primitive this lid's theorems depend on is
`core.slice.Slice.first` (`Option<&T>`'s erased-borrow value form — the exact same assumed spec
`LengthProofs.lean`'s `first_spec` already discloses and justifies, restated here only because
`lean/extract-tag` runs its own independent Charon/Aeneas pass, producing a separate Lean
namespace). `core.slice.Slice.get` (the `input.get(i)` call inside the loop) is a Std-library
`abbrev` (`ok s[i]?`, `@[simp, step_simps]`) — computable and total, not an axiom; likewise every
arithmetic step in the loop body is `lift`ed (`Result.ok`, always succeeds) or a checked `Usize`/
`U32` op the `step` tactic discharges directly. `#print axioms` at the bottom shows both theorems
depend on exactly `first_spec` plus the three standard Lean axioms (`propext`, `Classical.choice`,
`Quot.sound`). No `sorryAx`.
-/

open Aeneas Aeneas.Std Result
open der_tag_extract

namespace DerVerified.Tag

/-- **Assumed spec** for the opaque external `core::slice::<[T]>::first` — restated from
    `LengthProofs.lean`'s `first_spec` (same justification: Aeneas has no builtin for it, so it
    extracts as an axiom with no body; we give it its documented Rust semantics). Restated here
    (not imported) because `lean/extract-tag` runs its own independent Charon/Aeneas pass,
    producing a Lean namespace (`der_tag_extract`) distinct from `der_length_extract`'s. -/
axiom first_spec {T : Type} (s : Slice T) :
    der_tag_extract.core.slice.Slice.first s = ok s.val[0]?

/-! ## The high-tag loop invariant -/

/-- **`decode_tag_loop`'s ∀-length invariant.** From any well-formed entry state `(i, number,
    count)` with `1 ≤ i.val ≤ input.length` (the loop is only ever entered at `i = 1`, right after
    the marker octet, and every `cont` step increments `i` by exactly one after confirming an
    octet is present, so `i` stays in-bounds until the slice is exhausted), the loop — run to
    completion — always reaches `ok r` for SOME `r` (never `fail`/`div`, totality), and whenever it
    accepts (`r = Result.Ok (number', used)`) then `i.val ≤ used.val ∧ used.val ≤
    input.val.length` (progress + no-over-read). Proved by `loop.spec_decr_nat` with measure
    `input.val.length - i1.val`, strictly decreasing on every `cont` (the loop's only
    continuation fires after `input.get(i1) = some _` is confirmed, i.e. `i1.val <
    input.val.length`, and advances to `i1.val + 1`). -/
theorem decode_tag_loop_spec (input : Slice U8) (i : Usize) (number : U32) (count : Usize)
    (hi1 : 1 ≤ i.val) (hile : i.val ≤ input.val.length) (hcle : count.val ≤ i.val) :
    tag.decode_tag_loop i input number count ⦃ r =>
      ∃ r' : core.result.Result (U32 × Usize) tag.TagError, r = r' ∧
        ∀ (number' : U32) (used : Usize),
          r' = core.result.Result.Ok (number', used) →
            i.val ≤ used.val ∧ used.val ≤ input.val.length ⦄ := by
  unfold tag.decode_tag_loop
  apply loop.spec_decr_nat
    (measure := fun (⟨i1, _, _⟩ : Usize × U32 × Usize) => input.val.length - i1.val)
    (inv := fun (⟨i1, _, count1⟩ : Usize × U32 × Usize) =>
      i.val ≤ i1.val ∧ i1.val ≤ input.val.length ∧ count1.val ≤ i1.val)
  · rintro ⟨i1, number1, count1⟩ ⟨hge1, hile1, hcle1⟩
    simp only [tag.decode_tag_loop.body, core.slice.Slice.get, bind_tc_ok]
    match hoeq : input.val[i1.val]? with
    | none =>
      -- off the end of the slice: Truncated. `done`, vacuous bound (not `Result.Ok _`).
      simp only [hoeq, WP.spec_ok]
      exact ⟨_, rfl, fun number' used heq => by injection heq⟩
    | some b =>
      -- an octet is present at i1: i1.val < input.val.length (drives the progress bound).
      have hi1lt : i1.val < input.val.length := by
        by_contra hcon
        push_neg at hcon
        have hnone : input.val[i1.val]? = none := List.getElem?_eq_none (by omega)
        rw [hoeq] at hnone
        exact absurd hnone (by simp)
      have hcmax : count1.val + 1 ≤ Usize.max := by
        have := Slice.length_ineq (s := input); omega
      simp only [hoeq]
      -- Both `count1 = 0` branches take the SAME shape (the leading-zero check only fires under
      -- `count1 = 0`, but the arithmetic tail is identical either way) — a single tactic block
      -- (not a hand-restated term, to stay syntactically identical to the extracted body)
      -- discharges whichever of the two occurrences `simp` leaves in the goal.
      by_cases hzero : count1 = 0#usize
      · by_cases hb128 : b = 128#u8
        · simp only [hzero, ↓reduceIte, hb128, WP.spec_ok]
          exact ⟨_, rfl, fun number' used heq => by injection heq⟩
        · simp only [hzero, ↓reduceIte, hb128]
          step as ⟨i2, hi2⟩        -- i2 = U32.MAX >>> 7
          by_cases htoolarge : number1 > i2
          · simp only [htoolarge, ↓reduceIte, WP.spec_ok]
            exact fun number' used heq => by injection heq
          · simp only [htoolarge, ↓reduceIte]
            step as ⟨i3, hi3⟩        -- i3 = number1 <<< 7
            step as ⟨i4, hi4⟩        -- i4 = b &&& 0x7f
            step as ⟨i5, hi5⟩        -- i5 = i4 as u32
            step as ⟨number1', hn1⟩  -- number1' = i3 ||| i5
            step as ⟨count1', hc1⟩   -- count1' = count1 + 1
            step as ⟨i6, hi6⟩        -- i6 = i1 + 1
            have hi6val : i6.val = i1.val + 1 := by scalar_tac
            step as ⟨i7, hi7⟩        -- i7 = b &&& 0x80
            by_cases hlast : i7 = 0#u8
            · simp only [hlast, ↓reduceIte, WP.spec_ok]
              exact fun number' used heq => by
                  injection heq with heq1
                  have h1 := congrArg Prod.fst heq1
                  have h2 := congrArg Prod.snd heq1
                  simp only at h1 h2
                  subst h1; subst h2
                  exact ⟨by scalar_tac, by rw [hi6val]; omega⟩
            · simp only [hlast, ↓reduceIte, WP.spec_ok]
              refine ⟨by scalar_tac, by rw [hi6val]; omega, by scalar_tac⟩
      · simp only [hzero, ↓reduceIte]
        step as ⟨i2, hi2⟩        -- i2 = U32.MAX >>> 7
        by_cases htoolarge : number1 > i2
        · simp only [htoolarge, ↓reduceIte, WP.spec_ok]
          exact fun number' used heq => by injection heq
        · simp only [htoolarge, ↓reduceIte]
          step as ⟨i3, hi3⟩        -- i3 = number1 <<< 7
          step as ⟨i4, hi4⟩        -- i4 = b &&& 0x7f
          step as ⟨i5, hi5⟩        -- i5 = i4 as u32
          step as ⟨number1', hn1⟩  -- number1' = i3 ||| i5
          step as ⟨count1', hc1⟩   -- count1' = count1 + 1
          step as ⟨i6, hi6⟩        -- i6 = i1 + 1
          have hi6val : i6.val = i1.val + 1 := by scalar_tac
          step as ⟨i7, hi7⟩        -- i7 = b &&& 0x80
          by_cases hlast : i7 = 0#u8
          · simp only [hlast, ↓reduceIte, WP.spec_ok]
            exact fun number' used heq => by
                injection heq with heq1
                have h1 := congrArg Prod.fst heq1
                have h2 := congrArg Prod.snd heq1
                simp only at h1 h2
                subst h1; subst h2
                exact ⟨by scalar_tac, by rw [hi6val]; omega⟩
          · simp only [hlast, ↓reduceIte, WP.spec_ok]
            refine ⟨by scalar_tac, by rw [hi6val]; omega, by scalar_tac⟩
  · exact ⟨le_refl _, hile, hcle⟩

#print axioms decode_tag_loop_spec

/-! ## The headline theorems -/

/-- **Totality of `decode_tag`'s final `number ≤ 30` guard**, GENERIC over the `Tag` fields it
    doesn't touch (`class1 : tag.Class`, `constructed : Bool`) — a trivial `if _ then ok _ else
    ok _` always reaches `ok _`. Factored out (mirrors `used_bounds_tail`'s reason) purely so the
    SAME proof term applies at all four `Class` branches `split` leaves in `tag_decode_total_spec`,
    rather than needing to restate the concrete class literal four times. -/
theorem total_tail_ok {class1 : tag.Class} {constructed : Bool} (number1 : U32) (i3 : Usize) :
    (let (number, i3') := (number1, i3)
     if number ≤ 30#u32 then ok (core.result.Result.Err tag.TagError.NonMinimal)
     else ok (core.result.Result.Ok ({ «class» := class1, constructed, number }, i3'))
     : Result (core.result.Result (tag.Tag × Usize) tag.TagError))
    ⦃ (_ : core.result.Result (tag.Tag × Usize) tag.TagError) => True ⦄ := by
  show (if number1 ≤ 30#u32 then ok (core.result.Result.Err tag.TagError.NonMinimal)
        else ok (core.result.Result.Ok ({ «class» := class1, constructed, number := number1 }, i3))
        : Result (core.result.Result (tag.Tag × Usize) tag.TagError))
      ⦃ (_ : core.result.Result (tag.Tag × Usize) tag.TagError) => True ⦄
  by_cases hle : number1 ≤ 30#u32
  · rw [if_pos hle]; trivial
  · rw [if_neg hle]; trivial

/-- **`decode_tag`'s totality, ∀-length**, in `spec`/postcondition form (the shape the `step`
    tactic and the existential corollary below both need). `decode_tag` never panics/faults: for
    ANY postcondition `True`, the computation reaches `ok r` for some `r` — i.e. it never
    `fail`s/`div`erges, for an input of *any* length. -/
theorem tag_decode_total_spec (input : Slice U8) :
    tag.decode_tag input ⦃ (_ : core.result.Result (tag.Tag × Usize) tag.TagError) => True ⦄ := by
  unfold tag.decode_tag
  rw [first_spec]
  match hfirst : input.val[0]? with
  | none => simp [hfirst]
  | some b =>
    have hb_lt : 1 ≤ input.val.length := by
      obtain ⟨h0, -⟩ := List.getElem?_eq_some_iff.mp hfirst
      omega
    simp only [bind_tc_ok]
    step as ⟨i, hi⟩            -- i = b >>> 6
    -- `class1 ← match i with | 0 => .. | 1 => .. | 2 => .. | _ => ..`: every branch is an
    -- unconditional `ok _`, so `class1`'s concrete value is irrelevant to totality — `split`
    -- case-splits the match and `simp` collapses each branch's trivial `ok _ ← ok _` bind.
    split <;> simp only [bind_tc_ok]
    all_goals
      step as ⟨i1, hi1⟩          -- i1 = b &&& 0x20
      step as ⟨i2, hi2⟩          -- i2 = b &&& 0x1f
      by_cases hlow : (i2 != 31#u8) = true
      · rw [if_pos hlow]
        step as ⟨i3, hi3⟩
        step as ⟨i4, hi4⟩
      · rw [if_neg hlow]
        have hspec := decode_tag_loop_spec input 1#usize 0#u32 0#usize (by scalar_tac) (by
          scalar_tac) (by scalar_tac)
        obtain ⟨y, hy, r', hyr', -⟩ := WP.spec_imp_exists hspec
        rw [hy, hyr']
        rcases r' with ⟨number1, i3⟩ | terr
        · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
          exact total_tail_ok number1 i3
        · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
          trivial

/-- **`decode_tag`'s totality, ∀-length.** `decode_tag` never panics/faults: it always returns
    SOME `ok r` (`r : core.result.Result (Tag × Usize) TagError`, either accept or a well-formed
    reject), never `fail`/`div`, for an input of *any* length. Discharges (as a THEOREM) the fact
    `TlvProofs.lean`/`SequenceProofs.lean` (D27/D28) previously had to assume as the axiom
    `tag_decode_total` about `decode_tag` while it was still opaque to Lean. Existential corollary
    of `tag_decode_total_spec`. -/
theorem tag_decode_total (input : Slice U8) :
    ∃ r : core.result.Result (tag.Tag × Usize) tag.TagError, tag.decode_tag input = ok r := by
  obtain ⟨r, hr, -⟩ := WP.spec_imp_exists (tag_decode_total_spec input)
  exact ⟨r, hr⟩

#print axioms tag_decode_total

/-- **The tail of `decode_tag`, from right after the `Class`-selector match onward, GENERIC over
    `class1 : tag.Class`.** Factored as a standalone top-level lemma (rather than inline in
    `tag_decode_used_bounds_spec`) so the SAME proof term applies uniformly to all four branches
    of that match (`split`-ing the match directly would leave a different concrete `tag.Class`
    literal baked into the goal per branch, which the `show`-based `let`-reduction inside this
    proof can't be restated four times against generically). `used`'s bound never depends on
    which `Class` variant was selected — only on the `i1`/`i2`/high-tag-loop structure below,
    already independent of the class. -/
theorem used_bounds_tail (input : Slice U8) (b : U8) (class1 : tag.Class)
    (hb_lt : 1 ≤ input.val.length) :
    (do
      let i1 ← lift (b &&& 32#u8)
      let i2 ← lift (b &&& 31#u8)
      if i2 != 31#u8
      then do
        let i3 ← lift (b &&& 31#u8)
        let i4 ← lift (UScalar.cast .U32 i3)
        ok (core.result.Result.Ok
          ({ «class» := class1, constructed := (i1 != 0#u8), number := i4 }, 1#usize))
      else do
        let state ← tag.decode_tag_loop 1#usize input 0#u32 0#usize
        let cf ← core.result.Result.Insts.CoreOpsTry.branch state
        match cf with
        | core.ops.control_flow.ControlFlow.Continue val =>
          let (number, i3) := val
          if number ≤ 30#u32 then ok (core.result.Result.Err tag.TagError.NonMinimal)
          else ok (core.result.Result.Ok
            ({ «class» := class1, constructed := (i1 != 0#u8), number }, i3))
        | core.ops.control_flow.ControlFlow.Break residual =>
          core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
            (tag.Tag × Usize) (core.convert.FromSame tag.TagError) residual
      : Result (core.result.Result (tag.Tag × Usize) tag.TagError)) ⦃ r =>
        ∀ (t : tag.Tag) (used : Usize),
          r = core.result.Result.Ok (t, used) → 1 ≤ used.val ∧ used.val ≤ input.val.length ⦄ := by
  step as ⟨i1, hi1⟩
  step as ⟨i2, hi2⟩
  by_cases hlow : (i2 != 31#u8) = true
  · rw [if_pos hlow]
    step as ⟨i3, hi3⟩
    step as ⟨i4, hi4⟩
    intro t used heq
    injection heq with heq1
    have h2 := congrArg Prod.snd heq1
    simp only at h2
    refine ⟨by scalar_tac, ?_⟩
    rw [← h2]; scalar_tac
  · rw [if_neg hlow]
    have hspec := decode_tag_loop_spec input 1#usize 0#u32 0#usize (by scalar_tac) (by
      scalar_tac) (by scalar_tac)
    obtain ⟨y, hy, r', hyr', hbound⟩ := WP.spec_imp_exists hspec
    rw [hy, hyr']
    rcases r' with ⟨number1, i3⟩ | terr
    · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
      show (if number1 ≤ 30#u32 then ok (core.result.Result.Err tag.TagError.NonMinimal)
            else ok (core.result.Result.Ok
              ({ «class» := class1, constructed := i1 != 0#u8, number := number1 }, i3))
            : Result (core.result.Result (tag.Tag × Usize) tag.TagError)) ⦃ r =>
        ∀ (t : tag.Tag) (used : Usize),
          r = core.result.Result.Ok (t, used) → 1 ≤ used.val ∧ used.val ≤ input.val.length ⦄
      by_cases hle : number1 ≤ 30#u32
      · rw [if_pos hle]
        intro t used heq
        exact absurd heq (by simp)
      · rw [if_neg hle]
        intro t used heq
        injection heq with heq1
        have h2 := congrArg Prod.snd heq1
        simp only at h2
        have hb := hbound number1 i3 rfl
        rw [← h2]
        exact ⟨by scalar_tac, hb.2⟩
    · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
      intro t used heq
      exact absurd heq (by simp)

/-- **`decode_tag`'s consumption bound, ∀-length**, in `spec`/postcondition form (the shape
    `step` needs — mirrors `tag_decode_total_spec`'s split from `tag_decode_total`). Whenever
    `decode_tag input` accepts `Ok (t, used)`, `1 ≤ used.val ≤ input.val.length`. -/
theorem tag_decode_used_bounds_spec (input : Slice U8) :
    tag.decode_tag input ⦃ r => ∀ (t : tag.Tag) (used : Usize),
      r = core.result.Result.Ok (t, used) → 1 ≤ used.val ∧ used.val ≤ input.val.length ⦄ := by
  unfold tag.decode_tag
  rw [first_spec]
  match hfirst : input.val[0]? with
  | none => simp [hfirst]
  | some b =>
    have hb_lt : 1 ≤ input.val.length := by
      obtain ⟨h0, -⟩ := List.getElem?_eq_some_iff.mp hfirst
      omega
    simp only [bind_tc_ok]
    step as ⟨i, hi⟩
    -- `used_bounds_tail`, applied identically at each of the four `Class` branches `split`
    -- leaves — its value is irrelevant to `used`'s bound, and `used_bounds_tail` (above) is
    -- already generic over `class1 : tag.Class`, so one lemma instantiation (not four copies of
    -- its proof) covers all branches.
    split <;> simp only [bind_tc_ok] <;> exact used_bounds_tail input b _ hb_lt

/-- **`decode_tag`'s consumption bound, ∀-length.** Whenever `decode_tag input` accepts `Ok (t,
    used)`, `1 ≤ used.val ≤ input.val.length`: an accepted decode never claims zero bytes, and
    never consumes more than the input holds, for an input of *any* length. Discharges (as a
    THEOREM) the fact `TlvProofs.lean`/`SequenceProofs.lean` (D27/D28) previously had to assume as
    the axiom `tag_decode_used_bounds` about `decode_tag` while it was still opaque to Lean.
    Direct corollary of `tag_decode_used_bounds_spec`. -/
theorem tag_decode_used_bounds (input : Slice U8) (t : tag.Tag) (used : Usize) :
    tag.decode_tag input = ok (core.result.Result.Ok (t, used)) →
      1 ≤ used.val ∧ used.val ≤ input.val.length := by
  intro heq
  have hspec := tag_decode_used_bounds_spec input
  rw [heq, WP.spec_ok] at hspec
  exact hspec t used rfl

#print axioms tag_decode_used_bounds

end DerVerified.Tag
