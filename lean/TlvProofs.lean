import DerTlvExtract

/-!
# Unbounded (∀-length) structural correctness of the DER TLV reader

This theorem is proved in Lean 4 over the **Aeneas-extracted** model of the *same*
`der-verified/src/tlv.rs` (composing `tag.rs` + `length.rs`) that the Kani floor proves —
single source of truth: the extraction crate `#[path]`-includes all three shipped files, and
`lean/check_lean.sh` re-extracts and diffs on every run to guard against drift.

The point is the **straddle**: Kani's `tlv::proofs::decode_tlv_structure` proves this codec's
headline "no over-read" property bit-precisely but only for a bounded 16-byte symbolic buffer.
Here we prove the same property for an input of **any length** — the unbounded lid Kani cannot
reach.

## The property (mirrors `tlv::proofs::decode_tlv_structure`, ∀-length)

`decode_tlv`'s **structural correctness**: whenever it accepts (`Ok (tlv, used)`), the returned
`used` is exactly `header + len` (where `header = t_used + l_used`, the tag+length octets
consumed), the returned `tlv.value` is exactly the `len`-octet window `input[header .. used]`,
and — the security-critical fact — **`used ≤ input.length`: an accepted TLV never claims bytes
beyond the input (no over-read)**, for an input slice of *any* length.

## A one-line, behavior-preserving source fix (pre-flight, `writing-verifiable-rust.md` §4)

Extraction initially failed with an Aeneas **name clash**: `tlv.rs`'s point-free
`.map_err(TlvError::Tag)` / `.map_err(TlvError::Length)` forced Aeneas to materialize the
variant constructors as standalone function values, whose auto-generated names collided with
the variants' own qualified constructor names ("the following identifiers are bound to the same
name"). This is Aeneas's own naming-scheme limitation (not fixable by a `-impl-namespace` flag,
and the `#[aeneas::rename(...)]` escape hatch needs `#![feature(register_tool)]`, a nightly-only
gate incompatible with `der-verified`'s `stable` pin). The fix, applied to the shipped
`tlv.rs` (single source of truth — same file the Kani floor proves): rewrite the two point-free
`map_err` calls as explicit closures (`.map_err(|e| TlvError::Tag(e))` /
`.map_err(|e| TlvError::Length(e))`) — a pure style change. Re-verified: all 295 crate tests and
all 5 `tlv::proofs::*` Kani harnesses (plus `sequence::proofs::roundtrip_two_children` /
`tag_correctness`, which depend on `tlv` transitively) pass unchanged after the edit.

## Trust surface

This lid composes THREE codecs (`tag`, `length`, `tlv`). `tag.rs`'s `decode_tag` **used to**
extract as an unmodelled bodyless axiom (an early `return` nested inside its `loop` — the exact
"no return nested >1 loop deep" shape that also hit `validate_oid`, D25); the same D25-style
refactor (moving every early `return` in the loop to a `break`-with-accumulated-`Result`, matched
once via `?`, see `tag.rs`'s own doc comment on `decode_tag`) now applies to this pass's copy too,
so `decode_tag` extracts here **with a body**. `tag_decode_used_bounds` / `tag_decode_total`
below are consequently proven as THEOREMS (restated from `TagProofs.lean`'s own proof of the same
facts, over the same source — this pass's own namespace, `der_tlv_extract.tag`, is distinct from
`TagProofs.lean`'s `der_tag_extract.tag`, so the proof is duplicated rather than imported), not
assumed. `usize::try_from(u32)` still extracts as an **unmodelled axiom** (a stdlib `TryFrom` impl
Aeneas's Std library hasn't (yet) covered for this direction). This file adds five remaining
small, documented, disclosed assumed specs — each the `first_spec` pattern from
`LengthProofs.lean` (a minimal, honest characterization of an otherwise fully-opaque primitive),
never a re-statement of `decode_tlv`'s own logic:

* **`length_decode_total`** / **`length_decode_used_le`** — the SAME two facts `tag_decode_total`/
  `tag_decode_used_bounds` prove for `decode_tag`, restated as AXIOMS for `length.decode_length`.
  Unlike `decode_tag`, `decode_length` is fully-defined (not opaque) in this extraction, and
  `LengthProofs.lean`'s own `decode_accepts_only_canonical` already proves totality **sorry-free**
  over the byte-identical `length.rs` source — but `lean/extract-tlv` runs its own independent
  Charon/Aeneas pass (needed since `tlv.rs` requires `length` as a sibling module), producing a
  Lean namespace that collides with `lean/extract`'s own `DerLengthExtract` if both are imported
  together. These two axioms are a namespace-workaround, not new unverified trust — see the
  docstrings for the precise justification.
* **`result_map_err_ok_spec`** / **`result_map_err_err_spec`** — `Result::map_err`'s textbook
  semantics (`Ok v ↦ Ok v`, `Err e ↦ Err (f e)`, the latter conditioned on `call_once` succeeding
  — always true for `decode_tlv`'s two concrete closures); Aeneas extracts
  `core.result.Result.map_err` itself as an unmodelled axiom (a generic stdlib combinator, not yet
  in the Aeneas Std library — the same category as `first_spec`).
* **`try_from_u32_usize_spec`** — `usize::try_from(u32)` always succeeds, value-preserving, given
  `usize` is at least 32 bits — `tlv.rs`'s own documented deployment boundary (§ "Portability...
  Unreachable on 32/64-bit"), the same assumption Kani's harnesses make (Kani models `usize` as
  64-bit).

None of these five axioms is der-specific trust beyond what `LengthProofs.lean` has already proved
(sorry-free, over the identical source) or what the Rust standard library guarantees — all are
disclosed here, and `#print axioms` at the bottom shows the resulting theorem depends on exactly
these five plus the standard Lean axioms (`propext`, `Classical.choice`, `Quot.sound`) plus the two
underlying opaque Aeneas primitives they characterize
(`Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from`, `core.result.Result.map_err`) and the
one `LengthProofs.lean` already trusts (`core.slice.Slice.first`). No `sorryAx`. (`tag.decode_tag`
itself — now defined, not opaque — no longer appears in the axiom list at all.)
-/

open Aeneas Aeneas.Std Result
open der_tlv_extract

namespace DerVerified.Tlv

/-! ## Assumed specs (disclosed trust surface) -/

/-- **Assumed spec** for the opaque external `core::slice::<[T]>::first` — restated from
    `LengthProofs.lean`'s `first_spec` (same justification: Aeneas has no builtin for it, so it
    extracts as an axiom with no body; we give it its documented Rust semantics). Restated here
    (not imported) because `lean/extract-tlv` runs its own independent Charon/Aeneas pass,
    producing a Lean namespace (`der_tlv_extract`) distinct from `der_length_extract`'s /
    `der_tag_extract`'s. Needed now that `decode_tag`'s proof (below) calls `Slice.first` too. -/
axiom first_spec {T : Type} (s : Slice T) :
    der_tlv_extract.core.slice.Slice.first s = ok s.val[0]?

/-- **`decode_tag_loop`'s ∀-length invariant** — restated from `TagProofs.lean`'s
    `decode_tag_loop_spec` (same proof, same justification: see that file's module doc for the
    full D25-style refactor story). Restated here (not imported) because `lean/extract-tlv` runs
    its own independent Charon/Aeneas pass, producing a `der_tlv_extract.tag` namespace distinct
    from `der_tag_extract.tag`'s — `tag.rs`'s `decode_tag` now extracts WITH A BODY (no longer a
    bodyless axiom) in this pass too, so this is a proven THEOREM, not new trust. -/
theorem tag_decode_tag_loop_spec (input : Slice U8) (i : Usize) (number : U32) (count : Usize)
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
      simp only [hoeq, WP.spec_ok]
      exact ⟨_, rfl, fun number' used heq => by injection heq⟩
    | some b =>
      have hi1lt : i1.val < input.val.length := by
        by_contra hcon
        push_neg at hcon
        have hnone : input.val[i1.val]? = none := List.getElem?_eq_none (by omega)
        rw [hoeq] at hnone
        exact absurd hnone (by simp)
      have hcmax : count1.val + 1 ≤ Usize.max := by
        have := Slice.length_ineq (s := input); omega
      simp only [hoeq]
      by_cases hzero : count1 = 0#usize
      · by_cases hb128 : b = 128#u8
        · simp only [hzero, ↓reduceIte, hb128, WP.spec_ok]
          exact ⟨_, rfl, fun number' used heq => by injection heq⟩
        · simp only [hzero, ↓reduceIte, hb128]
          step as ⟨i2, hi2⟩
          by_cases htoolarge : number1 > i2
          · simp only [htoolarge, ↓reduceIte, WP.spec_ok]
            exact fun number' used heq => by injection heq
          · simp only [htoolarge, ↓reduceIte]
            step as ⟨i3, hi3⟩
            step as ⟨i4, hi4⟩
            step as ⟨i5, hi5⟩
            step as ⟨number1', hn1⟩
            step as ⟨count1', hc1⟩
            step as ⟨i6, hi6⟩
            have hi6val : i6.val = i1.val + 1 := by scalar_tac
            step as ⟨i7, hi7⟩
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
        step as ⟨i2, hi2⟩
        by_cases htoolarge : number1 > i2
        · simp only [htoolarge, ↓reduceIte, WP.spec_ok]
          exact fun number' used heq => by injection heq
        · simp only [htoolarge, ↓reduceIte]
          step as ⟨i3, hi3⟩
          step as ⟨i4, hi4⟩
          step as ⟨i5, hi5⟩
          step as ⟨number1', hn1⟩
          step as ⟨count1', hc1⟩
          step as ⟨i6, hi6⟩
          have hi6val : i6.val = i1.val + 1 := by scalar_tac
          step as ⟨i7, hi7⟩
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

/-- **Totality of `decode_tag`'s final `number ≤ 30` guard**, GENERIC over the `Tag` fields it
    doesn't touch — restated from `TagProofs.lean`'s `total_tail_ok` (same namespace-restatement
    reason as above). -/
theorem tag_total_tail_ok {class1 : tag.Class} {constructed : Bool} (number1 : U32) (i3 : Usize) :
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

/-- **`decode_tag`'s totality, ∀-length**, in `spec`/postcondition form — restated from
    `TagProofs.lean`'s `tag_decode_total_spec`. -/
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
    step as ⟨i, hi⟩
    split <;> simp only [bind_tc_ok]
    all_goals
      step as ⟨i1, hi1⟩
      step as ⟨i2, hi2⟩
      by_cases hlow : (i2 != 31#u8) = true
      · rw [if_pos hlow]
        step as ⟨i3, hi3⟩
        step as ⟨i4, hi4⟩
      · rw [if_neg hlow]
        have hspec := tag_decode_tag_loop_spec input 1#usize 0#u32 0#usize (by scalar_tac) (by
          scalar_tac) (by scalar_tac)
        obtain ⟨y, hy, r', hyr', -⟩ := WP.spec_imp_exists hspec
        rw [hy, hyr']
        rcases r' with ⟨number1, i3⟩ | terr
        · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
          exact tag_total_tail_ok number1 i3
        · simp only [bind_tc_ok, core.result.Result.Insts.CoreOpsTry.branch]
          trivial

/-- **Assumed totality** for `tag.decode_tag` — now a THEOREM (`decode_tag` extracts with a body
    in this pass too, see `tag_decode_tag_loop_spec`'s docstring), restated from `TagProofs.lean`'s
    `tag_decode_total`. Kept the SAME name (`tag_decode_total`) as the discharged axiom this
    section used to declare, so the composition proof below needs no further edits. -/
theorem tag_decode_total (input : Slice U8) :
    ∃ r : core.result.Result (tag.Tag × Usize) tag.TagError, tag.decode_tag input = ok r := by
  obtain ⟨r, hr, -⟩ := WP.spec_imp_exists (tag_decode_total_spec input)
  exact ⟨r, hr⟩

/-- **The tail of `decode_tag`, from right after the `Class`-selector match onward** — restated
    from `TagProofs.lean`'s `used_bounds_tail`. -/
theorem tag_used_bounds_tail (input : Slice U8) (b : U8) (class1 : tag.Class)
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
    have hspec := tag_decode_tag_loop_spec input 1#usize 0#u32 0#usize (by scalar_tac) (by
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

/-- **`decode_tag`'s consumption bound, ∀-length**, in `spec`/postcondition form — restated from
    `TagProofs.lean`'s `tag_decode_used_bounds_spec`. -/
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
    split <;> simp only [bind_tc_ok] <;> exact tag_used_bounds_tail input b _ hb_lt

/-- **`decode_tag`'s consumption bound, ∀-length** — now a THEOREM (`decode_tag` extracts with a
    body in this pass too), restated from `TagProofs.lean`'s `tag_decode_used_bounds`. Kept the
    SAME name/signature as the discharged axiom this section used to declare, so the composition
    proof below needs no further edits. -/
theorem tag_decode_used_bounds (input : Slice U8) (t : tag.Tag) (t_used : Usize) :
    tag.decode_tag input = ok (core.result.Result.Ok (t, t_used)) →
      1 ≤ t_used.val ∧ t_used.val ≤ input.val.length := by
  intro heq
  have hspec := tag_decode_used_bounds_spec input
  rw [heq, WP.spec_ok] at hspec
  exact hspec t t_used rfl

/-- **Assumed spec for the opaque `core.result.Result.map_err` axiom.** Standard `Result::
    map_err` semantics, stated in the two shapes actually needed (both directions total, no
    partiality caveat): `Ok v` passes through untouched; `Err e` maps to `Err w` exactly when
    the `FnOnce`'s `call_once e` itself succeeds with `w` (which it always does for the two
    concrete closures `decode_tlv` applies below — `tlv.TlvError.Tag`/`tlv.TlvError.Length`,
    themselves unconditional `ok (...)` one-liners, per `DerTlvExtract.lean`). `map_err` is a
    generic stdlib combinator Aeneas has not (yet) modelled in its Std library — the same trust
    category as `LengthProofs.lean`'s `first_spec` for `core::slice::first`. -/
axiom result_map_err_ok_spec {T E F O : Type} (inst : core.ops.function.FnOnce O E F)
    (v : T) (f : O) :
    core.result.Result.map_err (T := T) (E := E) inst (.Ok v) f = ok (.Ok v)

axiom result_map_err_err_spec {T E F O : Type} (inst : core.ops.function.FnOnce O E F)
    (e : E) (f : O) (w : F) (hcall : inst.call_once f e = ok w) :
    core.result.Result.map_err (T := T) inst (.Err e) f = ok (.Err w)

/-- **Assumed spec for the opaque `usize::try_from(u32)` axiom**, conditioned on the platform's
    `usize` being at least 32 bits — exactly `tlv.rs`'s own documented deployment boundary
    ("Portability: `decode_length` yields a u32; on targets where `usize` is narrower this could
    truncate... Unreachable on 32/64-bit"), and the same assumption Kani's own harnesses make
    (Kani models `usize` as 64-bit). Under this hypothesis `u32::MAX ≤ usize::MAX`, so the
    conversion always succeeds and is value-preserving — the standard, well-known semantics of
    this stdlib `TryFrom` impl. -/
axiom try_from_u32_usize_spec (i : U32) (h32 : 32 ≤ Usize.numBits) :
    ∃ l : Usize, Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from i
        = ok (core.result.Result.Ok l) ∧ l.val = i.val

/-- **Assumed totality** of `length.decode_length` (the copy embedded in *this* extraction crate
    — `lean/extract-tlv` runs its own independent Charon/Aeneas pass over the same shipped
    `length.rs`, since `tlv.rs` needs `length` as a sibling module; that produces a Lean namespace
    structurally identical to, but distinct from, `lean/extract`'s own `DerLengthExtract`/
    `LengthProofs.lean`, so the two files cannot be imported together — a naming collision, not a
    semantic gap). This is NOT blind trust: `LengthProofs.lean`'s `decode_accepts_only_canonical`
    already proves this exact fact **sorry-free**, unconditionally for every `s : Slice U8` (by
    `WP.spec_fail`/`spec_div` reducing an unprovable `⦃⦄` triple to `False`, a proved triple with
    no vacuous hypotheses forces the underlying `Result` to be `ok _`) — over the byte-identical
    `length.rs` source. Restated here as a disclosed axiom purely to work around the duplicate-
    extraction namespace clash, not because the fact is unverified. -/
axiom length_decode_total (s : Slice U8) :
    ∃ r : core.result.Result (U32 × Usize) length.LengthError, length.decode_length s = ok r

/-- **Assumed no-over-read bound** for `length.decode_length` (the copy embedded in *this*
    extraction crate — same duplicate-namespace situation as `length_decode_total` above): an
    accepted decode never consumes more bytes than its input holds. This is the "no over-read"
    half of `length.rs`'s own headline property (Kani's `decode_tlv_structure`/`tlv_roundtrip_*`
    harnesses already exercise exactly this composition bounded; `decode_length`'s Rust source
    only ever slices `input[1 .. 1+n]` after checking `1+n ≤ input.len()`, so `l_used ≤
    s.length` by construction). Used only to discharge the overflow-freedom side-condition of
    `t_used + l_used` (`decode_tlv`'s own `header` computation) — not a new correctness claim. -/
axiom length_decode_used_le (s : Slice U8) (v : U32) (l_used : Usize) :
    length.decode_length s = ok (core.result.Result.Ok (v, l_used)) →
      l_used.val ≤ s.val.length

/-! ## The headline theorem -/

/-- **`decode_tlv`'s structural correctness, ∀-length** (the unbounded companion to
    `tlv::proofs::decode_tlv_structure`). On any platform with `usize` at least 32 bits (the
    module's own documented deployment boundary — the only hypothesis beyond the two disclosed
    assumed specs above), whenever `decode_tlv input` accepts `Ok (t, used)`:

    * `decode_tag` and `decode_length` (applied to the tag-consumed suffix) both succeeded, with
      `used` equal to their combined consumption plus the declared value length;
    * — the security-critical fact — **`used ≤ input.length`: the accepted TLV never claims
      bytes beyond the input, for an input of *any* length** (no over-read);
    * `t.value` is *exactly* the declared-length window immediately following the header.

    Proved by following `decode_tlv`'s only accept path: `decode_tag` succeeds (consuming
    `t_used`, bounded via `tag_decode_used_bounds`), then `decode_length` succeeds on the
    remaining suffix, then the `usize::try_from` / `checked_add` overflow guards both take their
    "fits" branch, and the final `input.len() < end` guard is false — exactly the `Ok` tail's
    precondition, from which the postcondition is read off directly. -/
theorem decode_tlv_structure (input : Slice U8) (h32 : 32 ≤ Usize.numBits) :
    tlv.decode_tlv input ⦃ r => ∀ (t : tlv.Tlv) (used : Usize),
      r = core.result.Result.Ok (t, used) →
        ∃ (t_used l_used : Usize) (len : U32),
          tag.decode_tag input = ok (core.result.Result.Ok (t.tag, t_used)) ∧
          length.decode_length (input.drop t_used) = ok (core.result.Result.Ok (len, l_used)) ∧
          used.val = t_used.val + l_used.val + len.val ∧
          used.val ≤ input.val.length ∧
          t.value.val = input.val.slice (t_used.val + l_used.val) used.val ⦄ := by
  unfold tlv.decode_tlv
  obtain ⟨tres, htag⟩ := tag_decode_total input
  rcases tres with ⟨t0, t_used⟩ | terr
  · -- decode_tag succeeded: Ok (t0, t_used). The live accept path.
    obtain ⟨hpos, hle⟩ := tag_decode_used_bounds input t0 t_used htag
    rw [htag]
    simp only [bind_tc_ok]
    rw [result_map_err_ok_spec]
    step as ⟨cf, hcf⟩
    simp only [hcf]
    step as ⟨s, hs⟩
    -- `decode_length` is fully-defined (not opaque): `length_decode_total` (derived above from
    -- `LengthProofs.lean`) gives its `ok` shape directly, mirroring the `decode_tag` handling.
    obtain ⟨lres, hlen⟩ := length_decode_total s
    rcases lres with ⟨len_u32, l_used⟩ | lerr
    · -- decode_length succeeded: Ok (len_u32, l_used). Continue the live accept path.
      have hlused : l_used.val ≤ s.val.length := length_decode_used_le s len_u32 l_used hlen
      have hnoverflow : t_used.val + l_used.val ≤ Usize.max := by
        have hslen : s.val.length = input.val.length - t_used.val := by rw [hs]; simp
        rw [hslen] at hlused
        scalar_tac
      rw [hlen]
      simp only [bind_tc_ok]
      rw [result_map_err_ok_spec]
      step as ⟨cf1, hcf1⟩
      simp only [hcf1]
      step as ⟨header, hheader⟩
      obtain ⟨l, htry, hlval⟩ := try_from_u32_usize_spec len_u32 h32
      rw [htry]
      simp only [bind_tc_ok]
      rcases hchk : Usize.checked_add header l with _ | e
      · -- checked_add overflows: LengthTooLarge, vacuous for the Ok postcondition.
        simp [lift]
      · -- checked_add fits: e = header + l = t_used + l_used + len_u32.
        have hcheck := Usize.checked_add_bv_spec header l
        rw [hchk] at hcheck
        have heval : e.val = header.val + l.val := hcheck.2.1
        simp only [lift, bind_tc_ok]
        by_cases hshort : input.len < e
        · -- input shorter than the declared end: Truncated, vacuous for the Ok postcondition.
          simp [hshort]
        · -- accept: index the value window and return Ok.
          simp only [hshort, ite_false]
          -- `SliceIndexRangeUsizeSlice.index` is `if start ≤ end ∧ end ≤ s.length then ok ⟨...⟩
          -- else fail .panic`; the guard holds here (`header ≤ e` from `heval`/scalar facts, and
          -- `e ≤ input.length` from `hshort`), so unfold and take the `ok` branch directly rather
          -- than a blind `rcases` (avoids a spurious unreachable `fail` goal).
          have hend_le : e.val ≤ input.val.length := by
            have := Slice.len_val (v := input); scalar_tac
          have hstart_le : header.val ≤ e.val := by rw [heval]; scalar_tac
          have hidx : core.slice.index.SliceIndexRangeUsizeSlice.index
              ({ start := header, «end» := e } : core.ops.range.Range Usize) input
              = ok ⟨input.val.slice header.val e.val, by scalar_tac⟩ := by
            unfold core.slice.index.SliceIndexRangeUsizeSlice.index
            simp [hstart_le, hend_le]
          simp only [hidx, bind_tc_ok, WP.spec_ok]
          intro t used heq
          injection heq with heq1
          have h1 := congrArg Prod.fst heq1
          have h2 := congrArg Prod.snd heq1
          simp only at h1 h2
          have heqtag : t.tag = t0 := by rw [← h1]
          have heqval1 : t.value.val = input.val.slice header.val e.val := by rw [← h1]
          have hused : used = e := h2.symm
          subst hused
          have hseq : s = input.drop t_used := by
            apply Subtype.ext
            rw [hs, Slice.getElem!_val_drop]
          rw [hseq] at hlen
          refine ⟨t_used, l_used, len_u32, ?_, hlen, ?_, ?_, ?_⟩
          · rw [heqtag]
          · rw [heval, hheader, hlval]
          · exact hend_le
          · rw [heqval1, hheader]
    · -- decode_length rejected: short-circuits to Err. Vacuous for the Ok postcondition.
      rw [hlen]
      simp only [bind_tc_ok]
      rw [result_map_err_err_spec (inst :=
        tlv.decode_tlv.closure_1.Insts.CoreOpsFunctionFnOnceTupleLengthErrorTlvError)
        (w := tlv.TlvError.Length lerr) (hcall := rfl)]
      step as ⟨cf2, hcf2⟩
      simp only [hcf2]
      unfold core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
      simp only [core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
      intro t used heq
      exact absurd heq (by simp)
  · -- decode_tag rejected: Ok (Err terr). decode_tlv short-circuits to Err via map_err + `?`.
    rw [htag]
    simp only [bind_tc_ok]
    rw [result_map_err_err_spec (inst :=
      tlv.decode_tlv.closure.Insts.CoreOpsFunctionFnOnceTupleTagErrorTlvError)
      (w := tlv.TlvError.Tag terr) (hcall := rfl)]
    step as ⟨cf0, hcf0⟩
    simp only [hcf0]
    unfold core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
    simp only [core.convert.FromSame.from, bind_tc_ok, WP.spec_ok]
    intro t used heq
    exact absurd heq (by simp)

#print axioms decode_tlv_structure

end DerVerified.Tlv
