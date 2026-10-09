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
Behavior was **re-validated by the full test suite and all 16 Kani harnesses** (a re-validation,
not an equivalence proof): `cargo test` (295 tests) and all `tag::proofs::*` Kani harnesses
(`roundtrip_all_tags`, `decode_tag_never_panics`, `decode_tag_accepts_only_canonical`,
`high_tag_of_small_number_is_non_minimal`, `leading_zero_high_tag_is_non_minimal`,
`truncated_high_tag_is_classified`, `too_large_tag_is_classified`) passed on the refactored code
when the returns→breaks refactor originally landed — validated VM-side at that time, 16/16
SUCCESSFUL under `cargo kani -Z stubbing --harness tag` (Kani is never run on this box). With
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
* **`tag_decode_identifier_fields`** — whenever `decode_tag input` accepts, its class is the direct
  X.690 four-range interpretation of octet 0's top two bits, its constructed flag is exactly the
  `0x20` bit, and a low-tag-form number is exactly the low five bits.  The three field facts also
  have separately named projection theorems so mutation failures localize.

The first two are proven by a `loop.spec_decr_nat` measure-induction over `tag.decode_tag_loop`'s
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
`U32` op the `step` tactic discharges directly. `#print axioms` at the bottom shows every headline theorem
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

/-! ## Identifier-octet value semantics (X.690 §8.1.2.2)

    The oracle below is deliberately written from the X.690 identifier-octet table, rather than
    through `encode_tag` or any helper from `tag.rs`: octet-0 values `0..63`, `64..127`,
    `128..191`, and `192..255` denote UNIVERSAL, APPLICATION, CONTEXT-SPECIFIC, and PRIVATE,
    respectively.  The constructed flag is the fixed `0x20` bit.  In low-tag form, the number is
    the low five bits.  Thus this theorem detects a decoder and encoder that share the same wrong
    interpretation, which a round trip cannot. -/

/-- The X.690 class table, stated directly as four numeric ranges of identifier octet 0. -/
def x690Class (b : U8) : tag.Class :=
  if b.val < 64 then tag.Class.Universal
  else if b.val < 128 then tag.Class.Application
  else if b.val < 192 then tag.Class.ContextSpecific
  else tag.Class.Private

/-- Turning the top-two-bit value `00` into the first row of the X.690 class table.  Arithmetic is
    discharged before simplifying the constructor-valued `if`, rather than asking `scalar_tac` to
    prove an equality of `Class` constructors. -/
theorem x690Class_shift0 (b : U8) (h : b.val >>> 6 = 0) :
    x690Class b = tag.Class.Universal := by
  simp only [Nat.shiftRight_eq_div_pow] at h
  norm_num at h
  have hb : b.val < 64 := by omega
  simp [x690Class, hb]

/-- Turning top-two-bit value `01` into APPLICATION. -/
theorem x690Class_shift1 (b : U8) (h : b.val >>> 6 = 1) :
    x690Class b = tag.Class.Application := by
  simp only [Nat.shiftRight_eq_div_pow] at h
  norm_num at h
  have hlo : 64 ≤ b.val := by omega
  have hhi : b.val < 128 := by omega
  simp [x690Class, not_lt_of_ge hlo, hhi]

/-- Turning top-two-bit value `10` into CONTEXT-SPECIFIC. -/
theorem x690Class_shift2 (b : U8) (h : b.val >>> 6 = 2) :
    x690Class b = tag.Class.ContextSpecific := by
  simp only [Nat.shiftRight_eq_div_pow] at h
  norm_num at h
  have hlo : 128 ≤ b.val := by omega
  have hhi : b.val < 192 := by omega
  simp [x690Class, not_lt_of_ge (by omega : 64 ≤ b.val), not_lt_of_ge hlo, hhi]

/-- Turning top-two-bit value `11` into PRIVATE. -/
theorem x690Class_shift3 (b : U8) (h : b.val >>> 6 = 3) :
    x690Class b = tag.Class.Private := by
  simp only [Nat.shiftRight_eq_div_pow] at h
  norm_num at h
  have hlo : 192 ≤ b.val := by omega
  simp [x690Class, not_lt_of_ge (by omega : 64 ≤ b.val),
    not_lt_of_ge (by omega : 128 ≤ b.val), not_lt_of_ge hlo]

/-- After class selection, every accepting branch preserves the selected class and derives the
    constructed flag from exactly `0x20`.  The final conjunct additionally pins the low-tag-form
    number to the low five bits; it is vacuous on the high-tag branch. -/
theorem identifier_fields_tail (input : Slice U8) (b : U8) (class1 : tag.Class)
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
        ∀ (t : tag.Tag) (used : Usize), r = core.result.Result.Ok (t, used) →
          t.«class» = class1 ∧
          t.constructed = (b &&& 32#u8 != 0#u8) ∧
          ((b &&& 31#u8 != 31#u8) = true → t.number.val = (b &&& 31#u8).val) ⦄ := by
  step as ⟨i1, hi1⟩
  step as ⟨i2, hi2⟩
  by_cases hlow : (i2 != 31#u8) = true
  · rw [if_pos hlow]
    step as ⟨i3, hi3⟩
    step as ⟨i4, hi4⟩
    intro t used heq
    injection heq with heq1
    cases heq1
    refine ⟨rfl, ?_, ?_⟩
    · have hi1eq : i1 = b &&& 32#u8 := UScalar.eq_of_val_eq hi1
      rw [hi1eq]
    · intro _
      rw [hi4, U8.cast_U32_val_eq, hi3]
  · rw [if_neg hlow]
    have hspec := decode_tag_loop_spec input 1#usize 0#u32 0#usize (by scalar_tac)
      (by scalar_tac) (by scalar_tac)
    obtain ⟨y, hy, r', hyr', -⟩ := WP.spec_imp_exists hspec
    rw [hy, hyr']
    rcases r' with ⟨number1, i3⟩ | terr
    · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
      show (if number1 ≤ 30#u32 then ok (core.result.Result.Err tag.TagError.NonMinimal)
            else ok (core.result.Result.Ok
              ({ «class» := class1, constructed := i1 != 0#u8, number := number1 }, i3))
            : Result (core.result.Result (tag.Tag × Usize) tag.TagError)) ⦃ r =>
        ∀ (t : tag.Tag) (used : Usize), r = core.result.Result.Ok (t, used) →
          t.«class» = class1 ∧
          t.constructed = (b &&& 32#u8 != 0#u8) ∧
          ((b &&& 31#u8 != 31#u8) = true → t.number.val = (b &&& 31#u8).val) ⦄
      by_cases hle : number1 ≤ 30#u32
      · rw [if_pos hle]
        intro t used heq
        exact absurd heq (by simp)
      · rw [if_neg hle]
        intro t used heq
        injection heq with heq1
        cases heq1
        refine ⟨rfl, ?_, ?_⟩
        · have hi1eq : i1 = b &&& 32#u8 := UScalar.eq_of_val_eq hi1
          rw [hi1eq]
        · intro hb
          have hi2eq : i2 = b &&& 31#u8 := UScalar.eq_of_val_eq hi2
          have : (i2 != 31#u8) = true := by rw [hi2eq]; exact hb
          exact absurd this hlow
    · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
      intro t used heq
      exact absurd heq (by simp)

/-- Lift `identifier_fields_tail` from its generic selected class to the independent X.690 class
    oracle once that selected class has been related to the top-two-bit table. -/
theorem identifier_fields_tail_x690 (input : Slice U8) (b : U8) (class1 : tag.Class)
    (hb_lt : 1 ≤ input.val.length) (hclass : class1 = x690Class b) :
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
        ∀ (t : tag.Tag) (used : Usize), r = core.result.Result.Ok (t, used) →
          t.«class» = x690Class b ∧
          t.constructed = (b &&& 32#u8 != 0#u8) ∧
          ((b &&& 31#u8 != 31#u8) = true → t.number.val = (b &&& 31#u8).val) ⦄ := by
  apply WP.spec_mono (identifier_fields_tail input b class1 hb_lt)
  intro r hr t used heq
  have hf := hr t used heq
  exact ⟨hf.1.trans hclass, hf.2⟩

/-- Spec-form accepted identifier semantics.  This follows the same `unfold` / `rw first_spec` /
    `step` / `split` shape as the existing totality, bounds, leading-zero, high-tag, and overflow
    proofs above; keeping it in spec form lets the field theorems below be tiny projections. -/
theorem tag_decode_identifier_fields_spec (input : Slice U8) (b : U8)
    (h0 : input.val[0]? = some b) :
    tag.decode_tag input ⦃ r => ∀ (t : tag.Tag) (used : Usize),
      r = core.result.Result.Ok (t, used) →
        t.«class» = x690Class b ∧
        t.constructed = (b &&& 32#u8 != 0#u8) ∧
        ((b &&& 31#u8 != 31#u8) = true → t.number.val = (b &&& 31#u8).val) ⦄ := by
  unfold tag.decode_tag
  rw [first_spec, h0]
  have hb_lt : 1 ≤ input.val.length := by
    obtain ⟨hindex, -⟩ := List.getElem?_eq_some_iff.mp h0
    omega
  simp only [bind_tc_ok]
  step as ⟨i, hi⟩
  split <;> simp only [bind_tc_ok]
  · have hsel : b.val >>> 6 = 0 := by
      norm_num at hi
      exact hi.symm
    exact identifier_fields_tail_x690 input b tag.Class.Universal hb_lt
      (x690Class_shift0 b hsel).symm
  · have hsel : b.val >>> 6 = 1 := by
      norm_num at hi
      exact hi.symm
    exact identifier_fields_tail_x690 input b tag.Class.Application hb_lt
      (x690Class_shift1 b hsel).symm
  · have hsel : b.val >>> 6 = 2 := by
      norm_num at hi
      exact hi.symm
    exact identifier_fields_tail_x690 input b tag.Class.ContextSpecific hb_lt
      (x690Class_shift2 b hsel).symm
  · rename_i hibv selector hne0 hne1 hne2
    have hi0 : i.val ≠ 0 := by
      intro hval
      apply hne0
      apply UScalar.eq_of_val_eq
      simpa using hval
    have hi1 : i.val ≠ 1 := by
      intro hval
      apply hne1
      apply UScalar.eq_of_val_eq
      simpa using hval
    have hi2 : i.val ≠ 2 := by
      intro hval
      apply hne2
      apply UScalar.eq_of_val_eq
      simpa using hval
    have hiv_le : i.val ≤ 3 := by
      rw [hi, Nat.shiftRight_eq_div_pow]
      norm_num
      have hb : b.val < 256 := by scalar_tac
      omega
    have hiv : i.val = 3 := by omega
    have h3 : b.val >>> 6 = 3 := hi.symm.trans hiv
    exact identifier_fields_tail_x690 input b tag.Class.Private hb_lt
      (x690Class_shift3 b h3).symm

/-- **Class bits, ∀-length.** On every accepted input, the decoded class is the direct X.690
    four-range interpretation of the top two bits of identifier octet 0. -/
theorem tag_decode_class (input : Slice U8) (b : U8) (t : tag.Tag) (used : Usize)
    (h0 : input.val[0]? = some b)
    (hdecode : tag.decode_tag input = ok (core.result.Result.Ok (t, used))) :
    t.«class» = x690Class b := by
  have hspec := tag_decode_identifier_fields_spec input b h0
  rw [hdecode, WP.spec_ok] at hspec
  exact (hspec t used rfl).1

/-- **Constructed bit, ∀-length.** On every accepted input, `constructed` is exactly bit
    `0x20` of identifier octet 0. -/
theorem tag_decode_constructed (input : Slice U8) (b : U8) (t : tag.Tag) (used : Usize)
    (h0 : input.val[0]? = some b)
    (hdecode : tag.decode_tag input = ok (core.result.Result.Ok (t, used))) :
    t.constructed = (b &&& 32#u8 != 0#u8) := by
  have hspec := tag_decode_identifier_fields_spec input b h0
  rw [hdecode, WP.spec_ok] at hspec
  exact (hspec t used rfl).2.1

/-- **Low-tag number, ∀-length.** On every accepted low-tag-form input, the decoded number is
    exactly the low five bits of identifier octet 0. -/
theorem tag_decode_low_tag_number (input : Slice U8) (b : U8) (t : tag.Tag) (used : Usize)
    (h0 : input.val[0]? = some b)
    (hdecode : tag.decode_tag input = ok (core.result.Result.Ok (t, used)))
    (hlow : (b &&& 31#u8 != 31#u8) = true) :
    t.number.val = (b &&& 31#u8).val := by
  have hspec := tag_decode_identifier_fields_spec input b h0
  rw [hdecode, WP.spec_ok] at hspec
  exact (hspec t used rfl).2.2 hlow

/-- **Accepted identifier semantics, ∀-length.** Composition of the three independently named
    field facts above. -/
theorem tag_decode_identifier_fields (input : Slice U8) (b : U8) (t : tag.Tag) (used : Usize)
    (h0 : input.val[0]? = some b)
    (hdecode : tag.decode_tag input = ok (core.result.Result.Ok (t, used))) :
    t.«class» = x690Class b ∧
    t.constructed = (b &&& 32#u8 != 0#u8) ∧
    ((b &&& 31#u8 != 31#u8) = true → t.number.val = (b &&& 31#u8).val) := by
  exact ⟨tag_decode_class input b t used h0 hdecode,
    tag_decode_constructed input b t used h0 hdecode,
    tag_decode_low_tag_number input b t used h0 hdecode⟩

#print axioms tag_decode_class
#print axioms tag_decode_constructed
#print axioms tag_decode_low_tag_number
#print axioms tag_decode_identifier_fields

/-! ## The base-128 value semantics of `decode_tag`'s high-tag loop

    Everything above proves *totality* and *consumption bounds* of `decode_tag` but says nothing
    about the numeric VALUE the high-tag loop accumulates. That gap left three `cargo-mutants`
    survivors alive in the base-128 loop body (`tag.rs:142/145/149`). The theorems below pin the
    value semantics ∀-length (symbolically, never for a fixed byte array), making each mutant
    provably false. They mirror `LengthProofs.lean`'s base-256 development (`beVal`, `beVal_take_succ`,
    `shl8_or_bv`, `decode_length_loop_spec`, `decode_long_form_accept`) almost line-for-line, with
    the radix changed from 256 to 128 and the septet mask `b &&& 0x7f = b.val % 128` in place of a
    whole byte.

    The high-tag loop consumes continuation octets starting at input index 1. For a loop state
    `(i1, number1, count1)` the octets consumed so far are `input.val.drop 1 |>.take count1.val`
    (`count1 = i1 - 1` of them), and `number1` is their base-128 big-endian value `b128`. Each octet
    contributes its low 7 bits (`b &&& 0x7f`, i.e. `b.val % 128`); the high bit `b &&& 0x80` is the
    continuation flag (loop terminates when it is clear). -/

/-- Base-128 big-endian value of a septet list — matches `decode_tag_loop`'s fold
    `number := (number <<< 7) | (b & 0x7f)` (the septet being `b.val % 128`). The base-128 analogue
    of `LengthProofs.beVal`. -/
def b128 : List U8 → Nat := List.foldl (fun acc b => acc * 128 + (b.val % 128)) 0

@[simp] theorem b128_nil : b128 [] = 0 := rfl

/-- One fold step: appending septet `k` multiplies by 128 and adds its low 7 bits. Mirror of
    `LengthProofs.beVal_take_succ`. -/
theorem b128_take_succ (l : List U8) (k : Nat) (hk : k < l.length) :
    b128 (l.take (k + 1)) = b128 (l.take k) * 128 + l[k].val % 128 := by
  have he : l.take (k + 1) = l.take k ++ [l[k]] := by
    rw [List.take_succ, List.getElem?_eq_getElem hk]; rfl
  rw [he]; simp only [b128, List.foldl_append, List.foldl_cons, List.foldl_nil]

/-- `b128` of a prefix is monotone in the prefix length: one more octet can only grow the value
    (multiply by 128, add a septet). This is what makes the pre-shift `≤ 0x01FFFFFF` bound
    genuinely *inductive* over the loop's `cont` states: given `hbound` (the accumulated value at
    the last `cont` octet is `≤ 0x01FFFFFF`), monotonicity yields the same bound at every earlier
    `cont` state, so each `number << 7` step stays in range. The accumulated value only *exceeds*
    `0x01FFFFFF` on the terminal `done` step, where it is returned rather than shifted again — so
    the bound is not violated on any step that reads it. -/
theorem b128_take_succ_ge (l : List U8) (k : Nat) :
    b128 (l.take k) ≤ b128 (l.take (k + 1)) := by
  by_cases hk : k < l.length
  · rw [b128_take_succ l k hk]
    have h1 : b128 (l.take k) ≤ b128 (l.take k) * 128 := by
      have := Nat.le_mul_of_pos_right (b128 (l.take k)) (show 0 < 128 by norm_num); omega
    omega
  · have he : l.take (k + 1) = l.take k := by
      rw [List.take_of_length_le (by omega : l.length ≤ k),
          List.take_of_length_le (by omega : l.length ≤ k + 1)]
    rw [he]

theorem b128_take_mono (l : List U8) {a b : Nat} (h : a ≤ b) :
    b128 (l.take a) ≤ b128 (l.take b) := by
  induction b with
  | zero => simp only [Nat.le_zero] at h; rw [h]
  | succ n ih =>
    rcases Nat.lt_succ_iff_lt_or_eq.mp (Nat.lt_succ_of_le h) with h1 | h1
    · exact le_trans (ih (by omega)) (b128_take_succ_ge l n)
    · rw [h1]

/-- The `(number << 7) | septet` step is exactly `number*128 + septet` when it does not overflow
    (`number ≤ 0x01FFFFFF = U32::MAX >> 7`, so `number << 7` fits in 32 bits, and the septet
    `< 0x80`). Base-128 analogue of `LengthProofs.shl8_or_bv`; the disjoint-bitfield identity that
    makes `tag.rs:148`'s `|` behave as `+` (the EQUIVALENT mutant `|`≡`^`). -/
theorem shl7_or_bv (v w : BitVec 32) (hv : v < 0x2000000#32) (hw : w < 0x80#32) :
    (v <<< (7 : Nat) ||| w) = v * 128#32 + w := by bv_decide

/-- The same, at the `Nat` (`toNat`) level. Mirror of `LengthProofs.shl8_or_toNat`. -/
theorem shl7_or_toNat (v w : BitVec 32) (hv : v < 0x2000000#32) (hw : w < 0x80#32) :
    (v <<< (7 : Nat) ||| w).toNat = v.toNat * 128 + w.toNat := by
  have h1 : v.toNat < 2 ^ 25 := by bv_omega
  have h2 : w.toNat < 128 := by bv_omega
  rw [shl7_or_bv v w hv hw, BitVec.toNat_add, BitVec.toNat_mul, BitVec.toNat_ofNat]
  omega

/-- Bitwise-AND commutes with `.val` on `U8` (both are `BitVec.toNat` of the same `&&&`). Lets the
    continuation-bit test `b &&& 0x80` and the septet mask `b &&& 0x7f` be read numerically. -/
theorem u8_and_val (b c : U8) : (b &&& c).val = b.val &&& c.val := by
  simp only [UScalar.val, UScalar.bv_and, BitVec.toNat_and]

/-- The septet mask `b &&& 0x7f` numerically is `b.val % 128` — the base-128 analogue of the
    `low7_eq_mod` fact used in `LengthProofs.lean`. -/
theorem u8_and_127 (b : U8) : (b &&& 127#u8).val = b.val % 128 := by
  rw [u8_and_val, show (127#u8).val = 127 from by decide]
  have h := Nat.and_two_pow_sub_one_eq_mod b.val 7
  norm_num at h
  exact h

/-- `U32::MAX >> 7 = 0x01FFFFFF = 33554431`: the extracted `TooLarge` threshold constant (the
    largest pre-shift value for which `number << 7` still fits in a `u32`). Load-bearing for the
    `>>`→`<<` mutant of `tag.rs:145` (the mutated constant would be a different number). -/
theorem u32_max_shr7 : (core.num.U32.MAX).val >>> (7#i32).toNat = 33554431 := by
  decide

/-! ## (a) Leading-zero rule ⇒ `NonMinimal` — kills the `tag.rs:142` `==`→`!=` mutant

    `if count == 0 && b == 0x80 { NonMinimal }`: the FIRST continuation octet (`count == 0`, i.e.
    loop index `i = 1`) may not be `0x80` (a leading septet of value 0 with the continuation bit
    set — a non-canonical leading zero). If the `==` on `count` is mutated to `!=`, this check
    never fires on the first octet, so a leading `0x80` is wrongly ACCEPTED as the start of a
    multi-octet number; the theorem below (leading `0x80` ⇒ `NonMinimal`) then becomes false. -/

/-- The high-tag loop, entered fresh at `(1, 0, 0)`, rejects `NonMinimal` as soon as the first
    continuation octet (`input[1]`) is `0x80`. The invariant pins the loop to its entry state:
    the body fires the `count == 0 && b == 0x80` branch immediately, so the `cont` case is never
    reached (vacuous). -/
theorem decode_tag_loop_leading_zero (input : Slice U8) (h1 : input.val[1]? = some 128#u8) :
    tag.decode_tag_loop 1#usize input 0#u32 0#usize
      ⦃ r => r = core.result.Result.Err tag.TagError.NonMinimal ⦄ := by
  unfold tag.decode_tag_loop
  apply loop.spec_decr_nat
    (measure := fun (⟨i1, _, _⟩ : Usize × U32 × Usize) => input.val.length - i1.val)
    (inv := fun (⟨i1, number1, count1⟩ : Usize × U32 × Usize) =>
      i1 = 1#usize ∧ number1 = 0#u32 ∧ count1 = 0#usize)
  · rintro ⟨i1, number1, count1⟩ ⟨hi1, hn1, hc1⟩
    simp only [tag.decode_tag_loop.body, core.slice.Slice.get, bind_tc_ok]
    have hval : i1.val = 1 := by rw [hi1]; scalar_tac
    match hoeq : input.val[i1.val]? with
    | none =>
      have h2 : input.val[i1.val]? = some 128#u8 := by rw [hval]; exact h1
      rw [hoeq] at h2; exact absurd h2 (by simp)
    | some b =>
      have hb : b = 128#u8 := by
        have h2 : input.val[i1.val]? = some 128#u8 := by rw [hval]; exact h1
        rw [hoeq] at h2; injection h2
      subst hb
      simp only [hc1, ↓reduceIte, WP.spec_ok]
  · exact ⟨rfl, rfl, rfl⟩

/-- **(a) ∀-length, spec form.** A high-tag marker whose first continuation octet is `0x80`
    decodes to `NonMinimal` — mirrors `tag_decode_total_spec`'s `step`-driven walk of the pre-loop
    scaffold, then feeds `decode_tag_loop_leading_zero` through the post-loop `?`. -/
theorem tag_decode_leading_zero_spec (input : Slice U8) (b0 : U8)
    (h0 : input.val[0]? = some b0) (hhigh : b0 &&& 31#u8 = 31#u8)
    (h1 : input.val[1]? = some 128#u8) :
    tag.decode_tag input ⦃ r => r = core.result.Result.Err tag.TagError.NonMinimal ⦄ := by
  unfold tag.decode_tag
  rw [first_spec, h0]
  simp only [bind_tc_ok]
  step as ⟨i, hi⟩
  split <;> simp only [bind_tc_ok]
  all_goals
    step as ⟨i1, hi1⟩
    step as ⟨i2, hi2, hi2bv⟩
    rw [hhigh] at hi2
    have hi2eq : i2 = 31#u8 := UScalar.eq_of_val_eq hi2
    have hlow : ¬ ((i2 != 31#u8) = true) := by rw [hi2eq]; simp
    rw [if_neg hlow]
    have hspec := decode_tag_loop_leading_zero input h1
    obtain ⟨y, hy, rfl⟩ := WP.spec_imp_exists hspec
    rw [hy]
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, WP.spec_ok]

/-- **(a) ∀-length: a high-tag whose first continuation octet is `0x80` decodes to `NonMinimal`.**
    Symbolic in the marker octet `b0` (only its low-5-bits-all-ones high-tag form is fixed) and in
    the slice length. Kills `tag.rs:142` (`count == 0 && b == 0x80`, mutant `==`→`!=`). -/
theorem tag_decode_leading_zero (input : Slice U8) (b0 : U8)
    (h0 : input.val[0]? = some b0) (hhigh : b0 &&& 31#u8 = 31#u8)
    (h1 : input.val[1]? = some 128#u8) :
    tag.decode_tag input = ok (core.result.Result.Err tag.TagError.NonMinimal) := by
  have hspec := tag_decode_leading_zero_spec input b0 h0 hhigh h1
  obtain ⟨y, hy, rfl⟩ := WP.spec_imp_exists hspec
  exact hy

#print axioms tag_decode_leading_zero

/-! ## (c) Accept-value semantics — kills the `tag.rs:148/149` mutants

    The high-tag loop, run over a *canonical* continuation window (first octet `≠ 0x80`, every octet
    before the terminator has its continuation bit set, the terminator octet has it clear, and the
    accumulated value stays `≤ 0x01FFFFFF` before the final shift), returns exactly the base-128
    value `b128` of the window, consuming `1 + count` octets. Because the octets are SYMBOLIC and the
    window has arbitrary length `t`, an *interior* `0x80` septet (continuation bit set, low 7 bits 0)
    is admitted — which is precisely what the `count += 1`→`count *= 1` mutant of `tag.rs:149` would
    wrongly reject (that mutant keeps `count == 0` forever, so the leading-zero test fires on every
    octet). The `|`≡`+` value identity (`shl7_or`) is what makes `tag.rs:148`'s `(number<<7)|septet`
    compute `number*128 + septet`. -/

/-- **Accept-path loop invariant, ∀-length.** From the fresh entry `(1, 0, 0)`, given a canonical
    continuation window terminating at index `t`, the loop returns `Ok (number', used)` with
    `number'` the base-128 value of the `t` octets and `used = t + 1`. Proved by `loop.spec_decr_nat`
    carrying `number1 = b128 (window consumed so far)` and `count1 = i1 - 1` through each step. -/
theorem decode_tag_loop_accept_spec (input : Slice U8) (t : Nat)
    (ht : 1 ≤ t) (htlen : t + 1 ≤ input.val.length)
    (hlead : input.val[1]! ≠ 128#u8)
    (hterm : input.val[t]!.val &&& 128 = 0)
    (hcont : ∀ j, 1 ≤ j → j < t → input.val[j]!.val &&& 128 ≠ 0)
    (hbound : b128 ((input.val.drop 1).take (t - 1)) ≤ 33554431) :
    tag.decode_tag_loop 1#usize input 0#u32 0#usize ⦃ r =>
      ∃ (number' : U32) (used : Usize), r = core.result.Result.Ok (number', used) ∧
        number'.val = b128 ((input.val.drop 1).take t) ∧ used.val = t + 1 ⦄ := by
  unfold tag.decode_tag_loop
  apply loop.spec_decr_nat
    (measure := fun (⟨i1, _, _⟩ : Usize × U32 × Usize) => input.val.length - i1.val)
    (inv := fun (⟨i1, number1, count1⟩ : Usize × U32 × Usize) =>
      1 ≤ i1.val ∧ i1.val ≤ t ∧ count1.val = i1.val - 1 ∧
      number1.val = b128 ((input.val.drop 1).take count1.val))
  · rintro ⟨i1, number1, count1⟩ ⟨hge1, hile1, hceq, hveq⟩
    simp only [tag.decode_tag_loop.body, core.slice.Slice.get, bind_tc_ok]
    have hi1lt : i1.val < input.val.length := by omega
    match hoeq : input.val[i1.val]? with
    | none =>
      rw [List.getElem?_eq_none_iff] at hoeq; omega
    | some b =>
      have hbget : input.val[i1.val]'hi1lt = b := by
        have h := List.getElem?_eq_getElem hi1lt; rw [hoeq] at h; exact (Option.some_inj.mp h).symm
      have hbbang : input.val[i1.val]! = b := by
        rw [getElem!_pos input.val i1.val hi1lt]; exact hbget
      have hcmax : count1.val + 1 ≤ Usize.max := by
        have := Slice.length_ineq (s := input); omega
      have hidx_eq : 1 + count1.val = i1.val := by omega
      have hdrlen : count1.val < (input.val.drop 1).length := by
        simp only [List.length_drop]; omega
      have hdrget : (input.val.drop 1)[count1.val]'hdrlen = b := by
        have h := List.getElem?_eq_getElem hdrlen
        rw [List.getElem?_drop, hidx_eq, hoeq] at h; exact (Option.some_inj.mp h).symm
      have hi7pre : b.val &&& 128 = input.val[i1.val]!.val &&& 128 := by rw [hbbang]
      by_cases hzero : count1 = 0#usize
      · -- count = 0 (i1 = 1): the leading-zero check must NOT fire (first octet ≠ 0x80)
        have hi1one : i1.val = 1 := by
          have : count1.val = 0 := by rw [hzero]; rfl
          omega
        have hbne : b ≠ 128#u8 := by
          have hb1 : input.val[1]! = b := by rw [← hi1one]; exact hbbang
          rw [← hb1]; exact hlead
        by_cases hb128 : b = 128#u8
        · exact absurd hb128 hbne
        · simp only [hzero, ↓reduceIte, hb128]
          step as ⟨i2, hi2, hi2bv⟩
          have hi2v : i2.val = 33554431 := by rw [hi2]; exact u32_max_shr7
          have hnb : number1.val ≤ 33554431 := by
            rw [hveq]
            exact le_trans (b128_take_mono (input.val.drop 1) (by omega : count1.val ≤ t - 1)) hbound
          by_cases htoolarge : number1 > i2
          · exact absurd htoolarge (by scalar_tac)
          · simp only [htoolarge, ↓reduceIte]
            step as ⟨i3, hi3, hi3bv⟩
            step as ⟨i4, hi4, hi4bv⟩
            step as ⟨i5, hi5⟩
            step as ⟨number1', hn1, hn1bv⟩
            step as ⟨count1', hc1⟩
            step as ⟨i6, hi6⟩
            have hi6val : i6.val = i1.val + 1 := by scalar_tac
            step as ⟨i7, hi7, hi7bv⟩
            have hi5val : i5.val = b.val % 128 := by rw [hi5, U8.cast_U32_val_eq, hi4]; exact u8_and_127 b
            have hkey : number1'.val = number1.val * 128 + b.val % 128 := by
              have hnbv : number1.bv < 0x2000000#32 := by
                have h : number1.bv.toNat ≤ 33554431 := hnb; bv_omega
              have hi5bv : i5.bv < 0x80#32 := by
                have h : i5.bv.toNat = b.bv.toNat % 128 := hi5val; bv_omega
              simp only [UScalar.val] at *
              rw [hn1bv, hi3bv, shl7_or_toNat number1.bv i5.bv hnbv hi5bv, hi5val]
            have hb128step : b128 ((input.val.drop 1).take (count1.val + 1)) = number1'.val := by
              rw [b128_take_succ (input.val.drop 1) count1.val hdrlen, hdrget, ← hveq, hkey]
            have hi7val : i7.val = b.val &&& 128 := by
              rw [hi7, u8_and_val, show (128#u8).val = 128 from by decide]
            have hc1val : count1'.val = count1.val + 1 := by scalar_tac
            rcases lt_or_eq_of_le hile1 with hlt | heq
            · -- interior octet: continuation bit set ⇒ cont
              have hbit : b.val &&& 128 ≠ 0 := by
                rw [hi7pre]; exact hcont i1.val hge1 hlt
              have hi7ne : i7 ≠ 0#u8 := by
                intro hc; apply hbit; rw [← hi7val, hc]; rfl
              simp only [hi7ne, ↓reduceIte, WP.spec_ok]
              refine ⟨by omega, by omega, by omega, ?_, by omega⟩
              rw [hc1val, hb128step]
            · -- terminator octet: continuation bit clear ⇒ done Ok, value pinned
              have hbit : b.val &&& 128 = 0 := by
                rw [hi7pre, heq]; exact hterm
              have hi7z : i7 = 0#u8 := by
                apply UScalar.eq_of_val_eq; rw [hi7val, hbit]; rfl
              simp only [hi7z, ↓reduceIte, WP.spec_ok]
              refine ⟨number1', i6, rfl, ?_, by rw [hi6val]; omega⟩
              rw [← heq, ← hidx_eq]
              have : 1 + count1.val = count1.val + 1 := by omega
              rw [this, hb128step]
      · -- count ≠ 0 (i1 ≥ 2): no leading-zero check, identical arithmetic tail
        simp only [hzero, ↓reduceIte]
        step as ⟨i2, hi2, hi2bv⟩
        have hi2v : i2.val = 33554431 := by rw [hi2]; exact u32_max_shr7
        have hnb : number1.val ≤ 33554431 := by
          rw [hveq]
          exact le_trans (b128_take_mono (input.val.drop 1) (by omega : count1.val ≤ t - 1)) hbound
        by_cases htoolarge : number1 > i2
        · exact absurd htoolarge (by scalar_tac)
        · simp only [htoolarge, ↓reduceIte]
          step as ⟨i3, hi3, hi3bv⟩
          step as ⟨i4, hi4, hi4bv⟩
          step as ⟨i5, hi5⟩
          step as ⟨number1', hn1, hn1bv⟩
          step as ⟨count1', hc1⟩
          step as ⟨i6, hi6⟩
          have hi6val : i6.val = i1.val + 1 := by scalar_tac
          step as ⟨i7, hi7, hi7bv⟩
          have hi5val : i5.val = b.val % 128 := by rw [hi5, U8.cast_U32_val_eq, hi4]; exact u8_and_127 b
          have hkey : number1'.val = number1.val * 128 + b.val % 128 := by
            have hnbv : number1.bv < 0x2000000#32 := by
              have h : number1.bv.toNat ≤ 33554431 := hnb; bv_omega
            have hi5bv : i5.bv < 0x80#32 := by
              have h : i5.bv.toNat = b.bv.toNat % 128 := hi5val; bv_omega
            simp only [UScalar.val] at *
            rw [hn1bv, hi3bv, shl7_or_toNat number1.bv i5.bv hnbv hi5bv, hi5val]
          have hb128step : b128 ((input.val.drop 1).take (count1.val + 1)) = number1'.val := by
            rw [b128_take_succ (input.val.drop 1) count1.val hdrlen, hdrget, ← hveq, hkey]
          have hi7val : i7.val = b.val &&& 128 := by
            rw [hi7, u8_and_val, show (128#u8).val = 128 from by decide]
          have hc1val : count1'.val = count1.val + 1 := by scalar_tac
          rcases lt_or_eq_of_le hile1 with hlt | heq
          · have hbit : b.val &&& 128 ≠ 0 := by
              rw [hi7pre]; exact hcont i1.val hge1 hlt
            have hi7ne : i7 ≠ 0#u8 := by
              intro hc; apply hbit; rw [← hi7val, hc]; rfl
            simp only [hi7ne, ↓reduceIte, WP.spec_ok]
            refine ⟨by omega, by omega, by omega, ?_, by omega⟩
            rw [hc1val, hb128step]
          · have hbit : b.val &&& 128 = 0 := by
              rw [hi7pre, heq]; exact hterm
            have hi7z : i7 = 0#u8 := by
              apply UScalar.eq_of_val_eq; rw [hi7val, hbit]; rfl
            simp only [hi7z, ↓reduceIte, WP.spec_ok]
            refine ⟨number1', i6, rfl, ?_, by rw [hi6val]; omega⟩
            rw [← heq, ← hidx_eq]
            have : 1 + count1.val = count1.val + 1 := by omega
            rw [this, hb128step]
  · exact ⟨by scalar_tac, ht, by scalar_tac, by simp⟩

/-- **Accept-path tail, GENERIC over the `Tag` fields the loop does not fix** (`class1`,
    `constructed`) — the base-128 analogue of `total_tail_ok`. Given a loop value `number' > 30`
    (so the post-loop `number ≤ 30 ⇒ NonMinimal` guard is not taken), the tail accepts `Ok (tag,
    used)` with `tag.number = number'` and reports `used`. Factored out (like `total_tail_ok`) so the
    SAME proof term applies at all four `Class` branches `split` leaves. -/
theorem accept_tail {class1 : tag.Class} {constructed : Bool} (number' : U32) (used : Usize)
    (bv tp1 : Nat) (hval : number'.val = bv) (husd : used.val = tp1) (h30 : 30 < number'.val) :
    (let (number, i3) := (number', used)
     if number ≤ 30#u32 then ok (core.result.Result.Err tag.TagError.NonMinimal)
     else ok (core.result.Result.Ok ({ «class» := class1, constructed, number }, i3))
     : Result (core.result.Result (tag.Tag × Usize) tag.TagError))
    ⦃ r => ∃ (tg : tag.Tag) (used' : Usize), r = core.result.Result.Ok (tg, used') ∧
        tg.number.val = bv ∧ used'.val = tp1 ⦄ := by
  show (if number' ≤ 30#u32 then ok (core.result.Result.Err tag.TagError.NonMinimal)
        else ok (core.result.Result.Ok ({ «class» := class1, constructed, number := number' }, used))
        : Result (core.result.Result (tag.Tag × Usize) tag.TagError))
      ⦃ r => ∃ (tg : tag.Tag) (used' : Usize), r = core.result.Result.Ok (tg, used') ∧
        tg.number.val = bv ∧ used'.val = tp1 ⦄
  rw [if_neg (show ¬ (number' ≤ 30#u32) by scalar_tac)]
  simp only [WP.spec_ok]
  exact ⟨_, used, rfl, hval, husd⟩

/-- **(c) ∀-length, spec form.** A canonical high-tag (marker `b0 &&& 31 = 31`, canonical
    continuation window of length `t` per `decode_tag_loop_accept_spec`, and a value `> 30` so the
    final `number ≤ 30 ⇒ NonMinimal` guard is *not* taken) accepts `Ok (tag, used)` with
    `tag.number = b128 window` and `used = t + 1`. -/
theorem tag_decode_high_tag_accept_spec (input : Slice U8) (b0 : U8) (t : Nat)
    (h0 : input.val[0]? = some b0) (hhigh : b0 &&& 31#u8 = 31#u8)
    (ht : 1 ≤ t) (htlen : t + 1 ≤ input.val.length)
    (hlead : input.val[1]! ≠ 128#u8)
    (hterm : input.val[t]!.val &&& 128 = 0)
    (hcont : ∀ j, 1 ≤ j → j < t → input.val[j]!.val &&& 128 ≠ 0)
    (hbound : b128 ((input.val.drop 1).take (t - 1)) ≤ 33554431)
    (hgt30 : 30 < b128 ((input.val.drop 1).take t)) :
    tag.decode_tag input ⦃ r => ∃ (tg : tag.Tag) (used : Usize),
      r = core.result.Result.Ok (tg, used) ∧
      tg.number.val = b128 ((input.val.drop 1).take t) ∧ used.val = t + 1 ⦄ := by
  unfold tag.decode_tag
  rw [first_spec, h0]
  simp only [bind_tc_ok]
  step as ⟨i, hi⟩
  split <;> simp only [bind_tc_ok]
  all_goals
    step as ⟨i1, hi1⟩
    step as ⟨i2c, hi2c, hi2cbv⟩
    rw [hhigh] at hi2c
    have hi2eq : i2c = 31#u8 := UScalar.eq_of_val_eq hi2c
    have hlow : ¬ ((i2c != 31#u8) = true) := by rw [hi2eq]; simp
    rw [if_neg hlow]
    obtain ⟨y, hy, number', used, rfl, hval, husd⟩ :=
      WP.spec_imp_exists (decode_tag_loop_accept_spec input t ht htlen hlead hterm hcont hbound)
    have h30 : 30 < number'.val := by rw [hval]; exact hgt30
    rw [hy]
    simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
    exact accept_tail number' used _ _ hval husd h30

/-- **(c) ∀-length: canonical high-tag accept-value semantics.** For a symbolic input whose
    continuation window (length `t`, arbitrary) is canonical — first octet `≠ 0x80`, interior octets
    with the continuation bit set (an interior `0x80` septet IS admitted, which is the `count += 1`
    → `count *= 1` kill for `tag.rs:149`), terminator bit clear, value in range and `> 30` — the
    decoded tag number equals the base-128 value `b128` of the window (the `tag.rs:148`
    `(number<<7)|septet` = `number*128 + septet` kill), consuming `t + 1` octets.

    **Disclosure (scope).** This theorem pins the decoded `number` and the consumed `used`, and
    deliberately does NOT constrain the `class`/`constructed` fields: those are the marker octet's
    high bits, unaffected by the three high-tag-loop mutants (`tag.rs:142/145/148/149`) this lid
    targets, so they are out of scope for THIS theorem. Their correctness is independently proved
    for every accepted input by `tag_decode_identifier_fields` above. -/
theorem tag_decode_high_tag_accept (input : Slice U8) (b0 : U8) (t : Nat)
    (h0 : input.val[0]? = some b0) (hhigh : b0 &&& 31#u8 = 31#u8)
    (ht : 1 ≤ t) (htlen : t + 1 ≤ input.val.length)
    (hlead : input.val[1]! ≠ 128#u8)
    (hterm : input.val[t]!.val &&& 128 = 0)
    (hcont : ∀ j, 1 ≤ j → j < t → input.val[j]!.val &&& 128 ≠ 0)
    (hbound : b128 ((input.val.drop 1).take (t - 1)) ≤ 33554431)
    (hgt30 : 30 < b128 ((input.val.drop 1).take t)) :
    ∃ (tg : tag.Tag) (used : Usize),
      tag.decode_tag input = ok (core.result.Result.Ok (tg, used)) ∧
      tg.number.val = b128 ((input.val.drop 1).take t) ∧ used.val = t + 1 := by
  obtain ⟨v, hv, tg, used, rfl, hnum, husd⟩ :=
    WP.spec_imp_exists (tag_decode_high_tag_accept_spec input b0 t h0 hhigh ht htlen hlead hterm
      hcont hbound hgt30)
  exact ⟨tg, used, hv, hnum, husd⟩

#print axioms tag_decode_high_tag_accept

/-! ## (b) `TooLarge` overflow threshold — kills the `tag.rs:145` `>>`→`<<` mutant

    `if number > (u32::MAX >> 7) { TooLarge }` rejects a high-tag number whose accumulated value has
    grown past `0x01FFFFFF` — the largest value for which the next `number << 7` still fits in a
    `u32`. The extracted threshold constant is `core.num.U32.MAX >>> 7 = 0x01FFFFFF = 33554431`
    (`u32_max_shr7`). Mutating `>>` to `<<` changes the constant to `u32::MAX << 7 = 0xFFFFFF80`
    (wrapping), so values in `(0x01FFFFFF, 0xFFFFFF80]` would no longer be rejected — the theorem
    below (such a value ⇒ `TooLarge`) then becomes false. -/

/-- **`TooLarge` loop spec, ∀-length.** From `(1, 0, 0)`, a window whose octets `1..p-1` all carry
    the continuation bit (first `≠ 0x80`), whose accumulated value stays `≤ 0x01FFFFFF` through entry
    `p-1` but EXCEEDS it at entry `p` (`b128` of the first `p-1` septets), makes the loop reject
    `TooLarge` — the guard fires at entry `p`, before the `<< 7` that would overflow. Same
    `loop.spec_decr_nat` skeleton as `decode_tag_loop_accept_spec`; the terminating body is the
    `number > 0x01FFFFFF` guard instead of the continuation-bit-clear branch. -/
theorem decode_tag_loop_toolarge_spec (input : Slice U8) (p : Nat)
    (hp : 2 ≤ p) (hplen : p < input.val.length)
    (hlead : input.val[1]! ≠ 128#u8)
    (hcont : ∀ j, 1 ≤ j → j < p → input.val[j]!.val &&& 128 ≠ 0)
    (hprev : b128 ((input.val.drop 1).take (p - 2)) ≤ 33554431)
    (hbig : 33554431 < b128 ((input.val.drop 1).take (p - 1))) :
    tag.decode_tag_loop 1#usize input 0#u32 0#usize ⦃ r =>
      r = core.result.Result.Err tag.TagError.TooLarge ⦄ := by
  unfold tag.decode_tag_loop
  apply loop.spec_decr_nat
    (measure := fun (⟨i1, _, _⟩ : Usize × U32 × Usize) => input.val.length - i1.val)
    (inv := fun (⟨i1, number1, count1⟩ : Usize × U32 × Usize) =>
      1 ≤ i1.val ∧ i1.val ≤ p ∧ count1.val = i1.val - 1 ∧
      number1.val = b128 ((input.val.drop 1).take count1.val))
  · rintro ⟨i1, number1, count1⟩ ⟨hge1, hile1, hceq, hveq⟩
    simp only [tag.decode_tag_loop.body, core.slice.Slice.get, bind_tc_ok]
    have hi1lt : i1.val < input.val.length := by omega
    match hoeq : input.val[i1.val]? with
    | none =>
      rw [List.getElem?_eq_none_iff] at hoeq; omega
    | some b =>
      have hbget : input.val[i1.val]'hi1lt = b := by
        have h := List.getElem?_eq_getElem hi1lt; rw [hoeq] at h; exact (Option.some_inj.mp h).symm
      have hbbang : input.val[i1.val]! = b := by
        rw [getElem!_pos input.val i1.val hi1lt]; exact hbget
      have hcmax : count1.val + 1 ≤ Usize.max := by
        have := Slice.length_ineq (s := input); omega
      have hidx_eq : 1 + count1.val = i1.val := by omega
      have hdrlen : count1.val < (input.val.drop 1).length := by
        simp only [List.length_drop]; omega
      have hdrget : (input.val.drop 1)[count1.val]'hdrlen = b := by
        have h := List.getElem?_eq_getElem hdrlen
        rw [List.getElem?_drop, hidx_eq, hoeq] at h; exact (Option.some_inj.mp h).symm
      have hi7pre : b.val &&& 128 = input.val[i1.val]!.val &&& 128 := by rw [hbbang]
      by_cases hzero : count1 = 0#usize
      · -- count = 0 (i1 = 1 < p): leading octet ≠ 0x80, value 0 ≤ threshold, continues
        have hi1one : i1.val = 1 := by
          have : count1.val = 0 := by rw [hzero]; rfl
          omega
        have hbne : b ≠ 128#u8 := by
          have hb1 : input.val[1]! = b := by rw [← hi1one]; exact hbbang
          rw [← hb1]; exact hlead
        by_cases hb128 : b = 128#u8
        · exact absurd hb128 hbne
        · simp only [hzero, ↓reduceIte, hb128]
          step as ⟨i2, hi2, hi2bv⟩
          have hi2v : i2.val = 33554431 := by rw [hi2]; exact u32_max_shr7
          have hc0 : count1.val = 0 := by rw [hzero]; rfl
          have hnb : number1.val ≤ 33554431 := by rw [hveq, hc0]; simp
          by_cases htoolarge : number1 > i2
          · exact absurd htoolarge (by scalar_tac)
          · simp only [htoolarge, ↓reduceIte]
            step as ⟨i3, hi3, hi3bv⟩
            step as ⟨i4, hi4, hi4bv⟩
            step as ⟨i5, hi5⟩
            step as ⟨number1', hn1, hn1bv⟩
            step as ⟨count1', hc1⟩
            step as ⟨i6, hi6⟩
            have hi6val : i6.val = i1.val + 1 := by scalar_tac
            step as ⟨i7, hi7, hi7bv⟩
            have hi5val : i5.val = b.val % 128 := by rw [hi5, U8.cast_U32_val_eq, hi4]; exact u8_and_127 b
            have hkey : number1'.val = number1.val * 128 + b.val % 128 := by
              have hnbv : number1.bv < 0x2000000#32 := by
                have h : number1.bv.toNat ≤ 33554431 := hnb; bv_omega
              have hi5bv : i5.bv < 0x80#32 := by
                have h : i5.bv.toNat = b.bv.toNat % 128 := hi5val; bv_omega
              simp only [UScalar.val] at *
              rw [hn1bv, hi3bv, shl7_or_toNat number1.bv i5.bv hnbv hi5bv, hi5val]
            have hb128step : b128 ((input.val.drop 1).take (count1.val + 1)) = number1'.val := by
              rw [b128_take_succ (input.val.drop 1) count1.val hdrlen, hdrget, ← hveq, hkey]
            have hi7val : i7.val = b.val &&& 128 := by
              rw [hi7, u8_and_val, show (128#u8).val = 128 from by decide]
            have hc1val : count1'.val = count1.val + 1 := by scalar_tac
            have hbit : b.val &&& 128 ≠ 0 := by
              rw [hi7pre]; exact hcont i1.val hge1 (by omega)
            have hi7ne : i7 ≠ 0#u8 := by
              intro hc; apply hbit; rw [← hi7val, hc]; rfl
            simp only [hi7ne, ↓reduceIte, WP.spec_ok]
            refine ⟨by omega, by omega, by omega, ?_, by omega⟩
            rw [hc1val, hb128step]
      · -- count ≠ 0 (i1 ≥ 2): TooLarge fires exactly at i1 = p
        simp only [hzero, ↓reduceIte]
        step as ⟨i2, hi2, hi2bv⟩
        have hi2v : i2.val = 33554431 := by rw [hi2]; exact u32_max_shr7
        by_cases hip : i1.val = p
        · have hbiggt : number1 > i2 := by
            have hcp : count1.val = p - 1 := by omega
            have hnv : number1.val = b128 ((input.val.drop 1).take (p - 1)) := by rw [hveq, hcp]
            scalar_tac
          simp only [hbiggt, ↓reduceIte, WP.spec_ok]
        · have hi1ltp : i1.val < p := by omega
          have hnb : number1.val ≤ 33554431 := by
            rw [hveq]
            exact le_trans (b128_take_mono (input.val.drop 1) (by omega : count1.val ≤ p - 2)) hprev
          by_cases htoolarge : number1 > i2
          · exact absurd htoolarge (by scalar_tac)
          · simp only [htoolarge, ↓reduceIte]
            step as ⟨i3, hi3, hi3bv⟩
            step as ⟨i4, hi4, hi4bv⟩
            step as ⟨i5, hi5⟩
            step as ⟨number1', hn1, hn1bv⟩
            step as ⟨count1', hc1⟩
            step as ⟨i6, hi6⟩
            have hi6val : i6.val = i1.val + 1 := by scalar_tac
            step as ⟨i7, hi7, hi7bv⟩
            have hi5val : i5.val = b.val % 128 := by rw [hi5, U8.cast_U32_val_eq, hi4]; exact u8_and_127 b
            have hkey : number1'.val = number1.val * 128 + b.val % 128 := by
              have hnbv : number1.bv < 0x2000000#32 := by
                have h : number1.bv.toNat ≤ 33554431 := hnb; bv_omega
              have hi5bv : i5.bv < 0x80#32 := by
                have h : i5.bv.toNat = b.bv.toNat % 128 := hi5val; bv_omega
              simp only [UScalar.val] at *
              rw [hn1bv, hi3bv, shl7_or_toNat number1.bv i5.bv hnbv hi5bv, hi5val]
            have hb128step : b128 ((input.val.drop 1).take (count1.val + 1)) = number1'.val := by
              rw [b128_take_succ (input.val.drop 1) count1.val hdrlen, hdrget, ← hveq, hkey]
            have hi7val : i7.val = b.val &&& 128 := by
              rw [hi7, u8_and_val, show (128#u8).val = 128 from by decide]
            have hc1val : count1'.val = count1.val + 1 := by scalar_tac
            have hbit : b.val &&& 128 ≠ 0 := by
              rw [hi7pre]; exact hcont i1.val hge1 hi1ltp
            have hi7ne : i7 ≠ 0#u8 := by
              intro hc; apply hbit; rw [← hi7val, hc]; rfl
            simp only [hi7ne, ↓reduceIte, WP.spec_ok]
            refine ⟨by omega, by omega, by omega, ?_, by omega⟩
            rw [hc1val, hb128step]
  · exact ⟨by scalar_tac, by scalar_tac, by scalar_tac, by simp⟩

/-- **(b) ∀-length, spec form.** A high-tag whose accumulated value exceeds the `u32::MAX >> 7`
    threshold decodes to `TooLarge` — feeds `decode_tag_loop_toolarge_spec` through the post-loop
    `?` (an `Err` residual propagates unchanged). -/
theorem tag_decode_too_large_spec (input : Slice U8) (b0 : U8) (p : Nat)
    (h0 : input.val[0]? = some b0) (hhigh : b0 &&& 31#u8 = 31#u8)
    (hp : 2 ≤ p) (hplen : p < input.val.length)
    (hlead : input.val[1]! ≠ 128#u8)
    (hcont : ∀ j, 1 ≤ j → j < p → input.val[j]!.val &&& 128 ≠ 0)
    (hprev : b128 ((input.val.drop 1).take (p - 2)) ≤ 33554431)
    (hbig : 33554431 < b128 ((input.val.drop 1).take (p - 1))) :
    tag.decode_tag input ⦃ r => r = core.result.Result.Err tag.TagError.TooLarge ⦄ := by
  unfold tag.decode_tag
  rw [first_spec, h0]
  simp only [bind_tc_ok]
  step as ⟨i, hi⟩
  split <;> simp only [bind_tc_ok]
  all_goals
    step as ⟨i1, hi1⟩
    step as ⟨i2c, hi2c, hi2cbv⟩
    rw [hhigh] at hi2c
    have hi2eq : i2c = 31#u8 := UScalar.eq_of_val_eq hi2c
    have hlow : ¬ ((i2c != 31#u8) = true) := by rw [hi2eq]; simp
    rw [if_neg hlow]
    have hspec := decode_tag_loop_toolarge_spec input p hp hplen hlead hcont hprev hbig
    obtain ⟨y, hy, rfl⟩ := WP.spec_imp_exists hspec
    rw [hy]
    simp [core.result.Result.Insts.CoreOpsTry.branch,
      core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual,
      core.convert.FromSame, WP.spec_ok]

/-- **(b) ∀-length: overflow-threshold `TooLarge` classification.** A symbolic high-tag whose
    running base-128 value crosses the `u32::MAX >> 7 = 0x01FFFFFF` boundary at some octet `p`
    decodes to `TooLarge`. Load-bearing on the exact threshold constant, so the `>>`→`<<` mutant of
    `tag.rs:145` (which changes the constant to `0xFFFFFF80`) falsifies it.

    **Disclosure (vacuity of small windows).** The hypotheses are unsatisfiable for `p ∈ {2, 3, 4}`:
    the value at entry `p` is `b128` of `p − 1` septets, at most `7·(p−1) ≤ 21` bits, which cannot
    exceed `2^25 − 1 = 0x01FFFFFF` (the `hbig` hypothesis), so no such input exists. The first
    satisfiable instance is `p = 5` (`7·4 = 28 > 25` bits). This is harmless — the theorem is
    non-vacuous overall (it has genuine models at `p ≥ 5`) and its statement holds trivially where
    the premises cannot be met; it is disclosed so the reader does not read `p ≥ 2` as claiming a
    live `TooLarge` at `p = 2..4`. -/
theorem tag_decode_too_large (input : Slice U8) (b0 : U8) (p : Nat)
    (h0 : input.val[0]? = some b0) (hhigh : b0 &&& 31#u8 = 31#u8)
    (hp : 2 ≤ p) (hplen : p < input.val.length)
    (hlead : input.val[1]! ≠ 128#u8)
    (hcont : ∀ j, 1 ≤ j → j < p → input.val[j]!.val &&& 128 ≠ 0)
    (hprev : b128 ((input.val.drop 1).take (p - 2)) ≤ 33554431)
    (hbig : 33554431 < b128 ((input.val.drop 1).take (p - 1))) :
    tag.decode_tag input = ok (core.result.Result.Err tag.TagError.TooLarge) := by
  have hspec := tag_decode_too_large_spec input b0 p h0 hhigh hp hplen hlead hcont hprev hbig
  obtain ⟨y, hy, rfl⟩ := WP.spec_imp_exists hspec
  exact hy

#print axioms tag_decode_too_large

end DerVerified.Tag
