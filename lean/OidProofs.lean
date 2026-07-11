import DerOidExtract

/-!
# Unbounded (∀-length) properties of the DER OBJECT IDENTIFIER body codec

This theorem is proved in Lean 4 over the **Aeneas-extracted** model of the *same*
`der-verified/src/oid.rs` that the Kani floor proves (single source of truth — the extraction
crate `#[path]`-includes that file).

The straddle mirrors `LengthProofs.lean` / `BigIntProofs.lean`: Kani proves `validate_oid`'s
minimality/canonicality bit-precisely but only for a bounded symbolic buffer (`oid.rs`'s harnesses
run at ≤ 6 octets, "representative, not limiting"); here we prove it for a content octet-string of
**any length** — the unbounded lid Kani cannot reach.

## Trust surface

The extracted model (`DerOidExtract.lean`) leaves **zero** opaque axioms: `is_empty`/`index_usize`/
`len` are Aeneas-modelled (computable, total), and the loop body's `lift (b &&& 128#u8)` goes
through the *owned-value* `&&&` (a genuinely modelled `UScalar` operation), not an opaque reference
op. So the **only** non-standard axiom this file introduces is the single `bv_decide` bit↔value
bridge (`bv8_and_0x80_eq_zero_iff`, mirroring `BigIntProofs.lean`'s `and_0x80_eq_zero_iff`), whose
native certificate axiom shows up explicitly in every `#print axioms` below alongside the standard
`propext` / `Classical.choice` / `Quot.sound`. No `sorryAx`.

"Only non-standard *axiom*" is not "only trust" (review `oid-lid-01`): `term_iff` also
uses the Aeneas scalar-semantics lemmas `UScalar.bv_and` / `UScalar.eq_equiv_bv_eq` / `BitVec.lt_def`.
Those are axiom-free *theorems* (they do not appear in `#print axioms`), but they are part of the
ambient Aeneas-model TCB that the whole extraction already rests on — the same trusted base every lid
in this repo shares, not a new trust injection by this file.

## The de-tautologized spec

`IsCanonicalOid` is a **positional / state-free** characterization of a canonical DER OID body,
deliberately *not* a restatement of the production loop's `at_subid_start` flag-threading
recursion (the D14 de-tautologization requirement):

* `IsTerm b`      — `b` is a subidentifier *terminator* octet (bit 8 clear), stated in **value**
  form (`b.val < 128`), bridged to the production bit-and test by the one `bv_decide` lemma
  `term_iff`.
* `IsStart xs p`  — position `p` begins a new subidentifier: either `p = 0`, or `p` immediately
  follows a terminator octet (`0 < p ≤ xs.length ∧ IsTerm xs[p-1]!`). Note the bound is `p ≤
  xs.length` (not `p < xs.length`): this lets `IsStart xs xs.length` coincide with "the last octet
  terminates", which is exactly the flag value the production loop carries when it falls off the
  end of the slice. **Deviation from the design doc's literal `p < xs.length`** — see the note on
  `IsStart` below. To be precise (review `oid-lid-01`): the widening *does* change
  `IsStart`'s own standalone domain — it is now defined at the one-past-end index `p = xs.length` —
  but it does *not* change the meaning of `IsCanonicalOid`, whose clause 2 only ever consults
  `IsStart` under its own `p < xs.length` guard, where both bounds agree.
* `IsCanonicalOid xs` — `xs` is non-empty, every subidentifier-start octet differs from `0x80`
  (minimality: no subidentifier is padded with a redundant leading `0x80`), and the final octet is
  a terminator (not `Truncated`).

## Headline theorem

`validate_iff_canonical : oid.validate_oid content = ok (core.result.Result.Ok ()) ↔
  IsCanonicalOid content.val`, proved via a loop invariant (`validate_oid_loop_spec`, the
`loop.spec_decr_nat` idiom from `BigIntProofs.lean`'s slice 2 / `LengthProofs.lean`'s
`decode_length_loop_spec`) that accumulates, from the loop's entry position onward, exactly the
"no forbidden subid-start octet seen so far" fact — the recursive bookkeeping the production loop
needs internally, but stated against the independent positional oracle `IsStart`/`IsTerm`, not the
production `at_subid_start` Boolean.
-/

open Aeneas Aeneas.Std Result
open der_oid_extract

namespace DerVerified.Oid

/-! ## Bit-level bridge: testing the terminator bit via `&&& 0x80` -/

/-- Pure `BitVec 8` fact: AND-ing with the top-bit mask `0x80` is zero exactly when the value's
    top bit is clear. The one `bv_decide` call in this file. -/
theorem bv8_and_0x80_eq_zero_iff (x : BitVec 8) : (x &&& 128#8) = 0#8 ↔ x < 128#8 := by
  bv_decide

/-- `U8` form, at the `.val` (`Nat`) level used throughout the codec's control flow:
    `(b &&& 0x80) = 0 ↔ b.val < 128` — i.e. the production AND-with-mask terminator test is
    exactly the "value < 0x80" test. Mirrors `BigIntProofs.lean`'s `and_0x80_eq_zero_iff`. -/
theorem term_iff (b : U8) : (b &&& 128#u8) = 0#u8 ↔ b.val < 128 := by
  rw [UScalar.eq_equiv_bv_eq]
  have h1 : (b &&& 128#u8).bv = b.bv &&& 128#8 := UScalar.bv_and b 128#u8
  rw [h1, show (0#u8 : U8).bv = (0#8 : BitVec 8) from rfl, bv8_and_0x80_eq_zero_iff, BitVec.lt_def]
  rfl

/-! ## The de-tautologized, positional spec -/

/-- A subidentifier *terminator* octet: bit 8 clear, i.e. numeric value `< 0x80`. Stated in value
    form per the design (bridged to the production bit-and via `term_iff`). -/
def IsTerm (b : U8) : Prop := b.val < 128

instance instDecidableIsTerm (b : U8) : Decidable (IsTerm b) := by
  unfold IsTerm; infer_instance

/-- Position `p` (into `xs`, `0 ≤ p ≤ xs.length`) begins a new subidentifier: either the very
    start (`p = 0`), or the position immediately following a terminator octet. The bound
    `p ≤ xs.length` (rather than `p < xs.length`) is deliberate: it lets `p = xs.length` (the
    "one past the end" position the loop reaches when it falls off the slice) coincide exactly
    with "the last octet terminates" — see `IsStart_succ` below. -/
def IsStart (xs : List U8) (p : Nat) : Prop :=
  p = 0 ∨ (0 < p ∧ p ≤ xs.length ∧ IsTerm xs[p - 1]!)

instance instDecidableIsStart (xs : List U8) (p : Nat) : Decidable (IsStart xs p) := by
  unfold IsStart; infer_instance

/-- `IsStart` one step past a terminator: `IsStart xs (j+1) ↔ IsTerm xs[j]!`, given `j+1` is in
    bounds. This is the single structural fact the loop invariant below both consumes (to justify
    the flag update `at_subid_start' = decide (IsTerm b)`) and produces (to close the boundary
    case, `IsStart xs xs.length ↔ IsTerm xs[xs.length - 1]!`). -/
theorem IsStart_succ {xs : List U8} {j : Nat} (hj : j + 1 ≤ xs.length) :
    IsStart xs (j + 1) ↔ IsTerm xs[j]! := by
  unfold IsStart
  constructor
  · rintro (h0 | ⟨_, _, ht⟩)
    · omega
    · simpa using ht
  · intro ht
    exact Or.inr ⟨by omega, hj, by simpa using ht⟩

/-- `IsStart` always holds at position `0` (the empty prefix trivially "starts" a subidentifier). -/
@[simp] theorem IsStart_zero (xs : List U8) : IsStart xs 0 := Or.inl rfl

/-- **The independent canonicality predicate.** Restated in a form *different* from the
    production if-chain / flag recursion (D14's de-tautologization requirement): `xs` is a
    canonical DER OID body iff it is non-empty, every subidentifier-start octet (per the
    positional `IsStart` oracle) differs from `0x80` (no subidentifier carries a redundant
    leading `0x80` padding octet), and its final octet is a terminator (the encoding is not
    truncated mid-subidentifier). -/
def IsCanonicalOid (xs : List U8) : Prop :=
  xs ≠ [] ∧
  (∀ p, p < xs.length → IsStart xs p → xs[p]!.val ≠ 128) ∧
  IsTerm xs[xs.length - 1]!

/-! ## The loop invariant -/

/-- **`validate_oid_loop`'s loop invariant, ∀-length.** From any well-formed entry state — an
    index `i` in bounds (`i.val ≤ xs.length`) whose flag `s` correctly reflects the positional
    oracle (`s = decide (IsStart xs i.val)`) — the loop returns `Ok ()` **iff** no subidentifier
    starting at or after `i` begins with the forbidden `0x80` octet, and the final octet
    terminates. This is the loop-invariant half of the headline theorem: it does not restate the
    production `at_subid_start` recursion (D14) but instead recomputes, from the loop's own
    single read octet `b` each step, membership in the independent oracle `IsStart`/`IsTerm` that
    `IsCanonicalOid` is stated against. Proved by well-founded recursion on `xs.length - i.val`
    (the `loop.spec_decr_nat` idiom, mirroring `BigIntProofs.lean`'s
    `encode_minimal_integer_into_loop_spec` / `LengthProofs.lean`'s `decode_length_loop_spec`). -/
theorem validate_oid_loop_spec (content : Slice U8) (s : Bool) (i : Usize)
    (hne : content.val ≠ [])
    (hi : i.val ≤ content.val.length)
    (hs : s = decide (IsStart content.val i.val)) :
    oid.validate_oid_loop content s i ⦃ r =>
      r = core.result.Result.Ok () ↔
        ((∀ t, i.val ≤ t → t < content.val.length → IsStart content.val t →
            content.val[t]!.val ≠ 128) ∧
         IsTerm content.val[content.val.length - 1]!) ⦄ := by
  unfold oid.validate_oid_loop
  apply loop.spec_decr_nat
    (measure := fun (⟨_, i1⟩ : Bool × Usize) => content.val.length - i1.val)
    (inv := fun (⟨s1, i1⟩ : Bool × Usize) =>
      i.val ≤ i1.val ∧ i1.val ≤ content.val.length ∧
      s1 = decide (IsStart content.val i1.val) ∧
      (∀ t, i.val ≤ t → t < i1.val → IsStart content.val t →
          content.val[t]!.val ≠ 128))
  · rintro ⟨s1, i1⟩ ⟨hge, hile, hseq, hacc⟩
    simp only [oid.validate_oid_loop.body]
    split
    · -- i1 < len: at least one octet remains
      rename_i hlt
      step as ⟨b, hb⟩            -- b = content[i1]
      have hbval : content.val[i1.val]! = b :=
        (getElem!_pos content.val i1.val hlt).trans hb.symm
      by_cases hstart1 : s1 = true
      · -- at_subid_start = true
        subst hstart1
        have hstartt : IsStart content.val i1.val := by simpa using hseq.symm
        by_cases hb128 : b = 128#u8
        · -- b = 0x80: NonMinimalSubid — a forbidden start octet at i1 itself
          simp only [hb128, ↓reduceIte]
          constructor
          · intro hcontra; injection hcontra
          · rintro ⟨hall, _⟩
            exact (hall i1.val hge hlt hstartt (by rw [hbval]; scalar_tac)).elim
        · -- b ≠ 0x80: continue
          simp only [hb128, ↓reduceIte]
          step as ⟨i2, hi2, hi2bv⟩   -- i2 = b &&& 0x80
          have hi2eq : i2 = b &&& 128#u8 := UScalar.eq_of_val_eq hi2
          step as ⟨i3, hi3⟩         -- i3 = i1 + 1
          have hi3val : i3.val = i1.val + 1 := by scalar_tac
          have hflag : (i2 = 0#u8) ↔ IsStart content.val i3.val := by
            rw [hi3val, IsStart_succ (by scalar_tac), hbval, hi2eq]
            exact term_iff b
          refine ⟨by scalar_tac, by scalar_tac, ?_, ?_, by scalar_tac⟩
          · simp only [hflag]
          · intro t ht1 ht2 hstt
            have ht2' : t < i1.val + 1 := by omega
            rcases Nat.lt_or_ge t i1.val with h | h
            · exact hacc t ht1 h hstt
            · have heqt : t = i1.val := by omega
              subst heqt
              rw [hbval]
              exact fun hc => hb128 (UScalar.eq_of_val_eq (by rw [hc]; scalar_tac))
      · -- at_subid_start = false
        have hbfalse : s1 = false := by revert hstart1; cases s1 <;> simp
        subst hbfalse
        rw [if_neg (show ¬ (false = true) by decide)]
        have hnotstart : ¬ IsStart content.val i1.val := by
          have hh : (false : Bool) = decide (IsStart content.val i1.val) := hseq
          simpa using hh.symm
        step as ⟨i2, hi2, hi2bv⟩   -- i2 = b &&& 0x80
        have hi2eq : i2 = b &&& 128#u8 := UScalar.eq_of_val_eq hi2
        step as ⟨i3, hi3⟩         -- i3 = i1 + 1
        have hi3val : i3.val = i1.val + 1 := by scalar_tac
        have hflag : (i2 = 0#u8) ↔ IsStart content.val i3.val := by
          rw [hi3val, IsStart_succ (by scalar_tac), hbval, hi2eq]
          exact term_iff b
        refine ⟨by scalar_tac, by scalar_tac, ?_, ?_, by scalar_tac⟩
        · simp only [hflag]
        · intro t ht1 ht2 hstt
          have ht2' : t < i1.val + 1 := by omega
          rcases Nat.lt_or_ge t i1.val with h | h
          · exact hacc t ht1 h hstt
          · have heqt : t = i1.val := by omega
            subst heqt
            exact absurd hstt hnotstart
    · -- i1 ≥ len (and ≤ len ⇒ = len): done
      rename_i hge2
      have heqlen : i1.val = content.val.length := by scalar_tac
      have hpos : 0 < content.val.length := List.length_pos_of_ne_nil hne
      have hlen_eq : content.val.length - 1 + 1 = content.val.length := by omega
      by_cases hstart1 : s1 = true
      · subst hstart1
        simp only [↓reduceIte]
        constructor
        · intro _
          refine ⟨?_, ?_⟩
          · rw [← heqlen]; exact hacc
          · have hstartt : IsStart content.val i1.val := by simpa using hseq.symm
            rw [heqlen] at hstartt
            have hstartt2 : IsStart content.val (content.val.length - 1 + 1) := by
              rw [hlen_eq]; exact hstartt
            exact (IsStart_succ (by omega)).mp hstartt2
        · intro _; rfl
      · have hbfalse : s1 = false := by revert hstart1; cases s1 <;> simp
        subst hbfalse
        constructor
        · intro hcontra; injection hcontra
        · rintro ⟨_, hterm⟩
          exfalso
          have hnotstart : ¬ IsStart content.val i1.val := by
            have hh : (false : Bool) = decide (IsStart content.val i1.val) := hseq
            simpa using hh.symm
          rw [heqlen] at hnotstart
          apply hnotstart
          have hstartt2 : IsStart content.val (content.val.length - 1 + 1) :=
            (IsStart_succ (by omega)).mpr hterm
          rw [hlen_eq] at hstartt2
          exact hstartt2
  · exact ⟨le_refl _, hi, hs, fun t ht1 ht2 _ => absurd (And.intro ht1 ht2) (by omega)⟩

#print axioms validate_oid_loop_spec

/-! ## The headline theorem -/

/-- **`validate_oid` accepts iff canonical, ∀-length.** The unbounded companion to `oid.rs`'s
    Kani floor: `validate_oid content` returns `Ok ()` exactly when `content` is a canonical DER
    OBJECT IDENTIFIER body, for a content octet-string of *any* length. Composes the empty-input
    short-circuit with the loop invariant `validate_oid_loop_spec` instantiated at the entry state
    `(true, 0)` — `IsStart _ 0` always holds, so the flag is trivially well-formed there. -/
theorem validate_iff_canonical (content : Slice U8) :
    oid.validate_oid content = ok (core.result.Result.Ok ()) ↔ IsCanonicalOid content.val := by
  unfold oid.validate_oid
  simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.length]
  by_cases hempty : content.val.length = 0
  · have hnil : content.val = [] := List.eq_nil_of_length_eq_zero hempty
    simp [hnil, IsCanonicalOid]
  · rw [if_neg (show ¬ (decide (content.val.length = 0) = true) by simp [hempty])]
    have hne : content.val ≠ [] := fun h => hempty (by simp [h])
    have h0 : (0#usize).val ≤ content.val.length := by scalar_tac
    have hz : (0#usize).val = 0 := by scalar_tac
    have hs0 : true = decide (IsStart content.val (0#usize).val) := by
      rw [hz]; simp [IsStart_zero]
    obtain ⟨y, hy, hiff⟩ :=
      (WP.spec_equiv_exists _ _).1 (validate_oid_loop_spec content true 0#usize hne h0 hs0)
    have hcanon_iff : IsCanonicalOid content.val ↔
        ((∀ t, t < content.val.length → IsStart content.val t → content.val[t]!.val ≠ 128) ∧
         IsTerm content.val[content.val.length - 1]!) := by
      unfold IsCanonicalOid
      constructor
      · rintro ⟨_, h2, h3⟩; exact ⟨h2, h3⟩
      · rintro ⟨h2, h3⟩; exact ⟨hne, h2, h3⟩
    rw [hy, hcanon_iff]
    constructor
    · intro heq
      injection heq with hyeq
      have h := hiff.mp hyeq
      exact ⟨fun t ht1 ht2 => h.1 t (Nat.zero_le t) ht1 ht2, h.2⟩
    · intro hcanon
      have hyeq : y = core.result.Result.Ok () :=
        hiff.mpr ⟨fun t _ ht1 ht2 => hcanon.1 t ht1 ht2, hcanon.2⟩
      rw [hyeq]

#print axioms validate_iff_canonical

end DerVerified.Oid
