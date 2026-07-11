import DerBigintExtract

/-!
# Unbounded (∀-length) properties of the DER arbitrary-magnitude INTEGER codec

These theorems are proved in Lean 4 over the **Aeneas-extracted** model of the
*same* `der-verified/src/big_integer.rs` that the Kani floor proves (single source
of truth — the extraction crate `lean/extract-bigint` `#[path]`-includes that file).

The straddle mirrors the `length`-codec lid (`LengthProofs.lean`): Kani proves the
minimality/canonicality properties bit-precisely but only for a bounded symbolic
buffer (`big_integer.rs`'s harnesses run at `N = 20`, "representative, not limiting");
here we prove them for a slice of **any length** — turning `minimality_is_local`'s
informal length-generalization argument into a machine-checked theorem.

**Scope of this file: BOTH slices.** *Slice 1 (validate-only):* `validate_integer_content`
(§8.3.2 minimality) and `is_negative` are loop-free, so their ∀-length lift needs only the trust
base below — no loop invariant. *Slice 2 (encode side, landed):* the strip-loop
(`encode_minimal_integer_into`) with its `loop.spec_decr_nat` invariant, encoder-output minimality,
the round-trip (validator accepts encoder output), and the already-minimal fixed point — all ∀-length,
all sorry-free, and (notably) adding **no new assumed axiom**. See the "Slice 2" section below.

## Trust base
The extracted model (`DerBigintExtract.lean`) leaves three opaque externals that Aeneas
does not model, each requiring one assumed spec (in the style of length's `first_spec`):
`core::slice::first`, the bit-and reference op, and `Option::is_some_and`. Each spec is
one line, is stated below, and shows up explicitly in every theorem's `#print axioms`.

Note: `validate_integer_content` itself is entirely axiom-free — its `c1 &&& 128#u8`
computations go through the *owned-value* `&&&` (a genuinely modelled, computable
`UScalar` operation, not an opaque external), so `validate_iff_minimal` below rests on
no assumed spec at all. The three axioms are needed only for `is_negative`, whose
closure captures the *reference* bit-and op `&u8 & u8` that Aeneas cannot model.
-/

open Aeneas Aeneas.Std Result
open der_bigint_extract

namespace DerVerified.BigInteger

/-- **Assumed spec** for the opaque external `core::slice::<[T]>::first`. Identical in
    spirit to `DerVerified.Length.first_spec` (same Rust function, re-extracted into
    this crate's own opaque axiom) — joins the same trust class. See that file's
    docstring for the two modelling notes (value-vs-reference, totality). -/
axiom first_spec {T : Type} (s : Slice T) :
    der_bigint_extract.core.slice.Slice.first s = ok s.val[0]?

/-- **Assumed spec** for the opaque external
    `core::ops::bit::{impl BitAnd<u8, u8> for &u8}::bitand` (the *reference* bit-and,
    `&byte & 0x80`, used inside `is_negative`'s closure). Aeneas erases the shared
    borrow but cannot give this instance a computable body, so it is extracted as an
    axiom; we give it its documented semantics: identical to the ordinary
    (computable, already-modelled) `UScalar` `&&&` on the dereferenced values. -/
axiom bitand_spec (a b : U8) :
    der_bigint_extract.Shared0U8.Insts.CoreOpsBitBitAndU8U8.bitand a b = ok (a &&& b)

/-- **Assumed spec** for the opaque external `core::option::{Option<T>}::is_some_and`.
    Aeneas extracts the `FnOnce` closure application generically via an instance
    argument rather than inlining it, so this spec states the closure's documented
    Rust semantics (`None` ⇒ `false`; `Some x` ⇒ apply the closure to `x`) in a form
    that lets `inst.call_once env x` reduce via the caller's own closure instance. -/
axiom is_some_and_spec {T T1 : Type}
    (inst : core.ops.function.FnOnce T1 T Bool) (o : Option T) (env : T1) :
    der_bigint_extract.core.option.Option.is_some_and inst o env
      = match o with
        | some x => inst.call_once env x
        | none => ok false

/-! ## Bit-level bridge: testing the sign bit via `&&& 0x80` -/

/-- Pure `BitVec 8` fact: AND-ing with the top-bit mask `0x80` is zero exactly when
    the value's top bit is clear. -/
theorem bv8_and_0x80_eq_zero_iff (x : BitVec 8) : (x &&& 128#8) = 0#8 ↔ x < 128#8 := by
  bv_decide

/-- `U8` form, at the `.val` (`Nat`) level used throughout the codec's control flow:
    `(b &&& 0x80) = 0 ↔ b.val < 128` — i.e. the AND-with-mask test is exactly the
    sign-bit / "value < 0x80" test. -/
theorem and_0x80_eq_zero_iff (b : U8) : (b &&& 128#u8) = 0#u8 ↔ b.val < 128 := by
  rw [UScalar.eq_equiv_bv_eq]
  have h1 : (b &&& 128#u8).bv = b.bv &&& 128#8 := UScalar.bv_and b 128#u8
  rw [h1, show (0#u8 : U8).bv = (0#8 : BitVec 8) from rfl, bv8_and_0x80_eq_zero_iff,
    BitVec.lt_def]
  rfl

/-! ## `is_negative`: characterization by the leading byte's sign bit -/

/-- **`is_negative` ∀-length**: `is_negative content` reports whether the *first*
    octet of `content` has its sign bit set, or `false` for an empty slice. This is
    the ∀-length lift of the Kani harness `is_negative_matches_sign_bit`. -/
theorem is_negative_spec (content : Slice U8) :
    big_integer.is_negative content ⦃ r =>
      r = (content.val[0]?.map (fun b => decide (128 ≤ b.val))).getD false ⦄ := by
  unfold big_integer.is_negative
  simp only [first_spec, bind_tc_ok, is_some_and_spec]
  cases h : content.val[0]? with
  | none => simp
  | some b =>
    simp only [Option.map_some, Option.getD_some]
    unfold big_integer.is_negative.closure.Insts.CoreOpsFunctionFnOnceTupleSharedU8Bool.call_once
    simp only [bind_tc_ok, bitand_spec]
    simp only [WP.spec_ok]
    by_cases hb : 128 ≤ b.val
    · have hne : (b &&& 128#u8) ≠ 0#u8 := by rw [ne_eq, and_0x80_eq_zero_iff]; omega
      simp [hne, hb]
    · have heq : (b &&& 128#u8) = 0#u8 := by rw [and_0x80_eq_zero_iff]; omega
      simp [heq, hb]

/-! ## `validate_integer_content`: minimality (validate-only slice) -/

/-- **The independent minimality predicate.** Restated in a form *different* from
    the production if-chain (D14's de-tautologization requirement): for `l.length ≥ 2`,
    `l` is a minimal DER integer content iff its leading octet `l[0]` differs from the
    *hypothetical sign-extension byte* implied by the second octet `l[1]` — `0x00` if
    `l[1]` is non-negative (`< 0x80`), `0xFF` otherwise. A single octet is always
    minimal (nothing to pad); the empty content is never minimal (rejected `Empty`,
    not a minimality question). This is the Kani oracle's own formulation
    (`minimality_is_local`), lifted here to an unbounded `List U8`. -/
def IsMinimalDer (l : List U8) : Prop :=
  match l with
  | [] => False
  | [_] => True
  | l0 :: l1 :: _ => l0 ≠ (if l1.val < 128 then 0#u8 else 255#u8)

/-- **The headline biconditional (validate-only slice).** `validate_integer_content`
    accepts (`Ok ()`) exactly when the content is minimal per the independent
    predicate `IsMinimalDer`, for a slice of *any* length. Proved by unfolding the
    loop-free if-chain and case-splitting on the leading ≤ 2 octets — no loop
    reasoning, no axiom (`validate_integer_content` never touches the three opaque
    externals). -/
theorem validate_iff_minimal (content : Slice U8) :
    big_integer.validate_integer_content content = ok (core.result.Result.Ok ())
      ↔ IsMinimalDer content.val := by
  unfold big_integer.validate_integer_content
  simp only [core.slice.Slice.is_empty, bind_tc_ok, Slice.length]
  by_cases hempty : content.val.length = 0
  · have hnil : content.val = [] := List.eq_nil_of_length_eq_zero hempty
    simp [hnil, IsMinimalDer]
  · simp only [hempty, ↓reduceIte]
    by_cases h2 : content.len ≥ 2#usize
    · have hlen2 : 2 ≤ content.val.length := by scalar_tac
      simp only [h2, ↓reduceIte]
      obtain ⟨l0, l1, rest, hlrw⟩ :
          ∃ l0 l1 rest, content.val = l0 :: l1 :: rest := by
        rcases hv : content.val with _ | ⟨x0, l⟩
        · rw [hv] at hlen2; simp at hlen2
        · rcases l with _ | ⟨x1, xs⟩
          · rw [hv] at hlen2; simp at hlen2
          · exact ⟨x0, x1, xs, rfl⟩
      have hc0 : Slice.index_usize content 0#usize = ok l0 := by
        unfold Slice.index_usize
        rw [Slice.getElem?_Usize_eq, hlrw]; rfl
      have hc1 : Slice.index_usize content 1#usize = ok l1 := by
        unfold Slice.index_usize
        rw [Slice.getElem?_Usize_eq, hlrw]; rfl
      simp only [bind_tc_ok, lift, hc0, hc1, hlrw, IsMinimalDer]
      by_cases hc00 : l0 = 0#u8
      · simp only [hc00, ↓reduceIte]
        have hstep : (l1 &&& 128#u8) = 0#u8 ↔ l1.val < 128 := and_0x80_eq_zero_iff l1
        by_cases hi1 : (l1 &&& 128#u8) = 0#u8
        · have hi1' : l1.val < 128 := hstep.mp hi1
          simp [hi1, hi1']
        · have hi1' : ¬ l1.val < 128 := fun hc => hi1 (hstep.mpr hc)
          simp [hi1, hi1']
      · simp only [hc00, ↓reduceIte]
        by_cases hc0ff : l0 = 255#u8
        · simp only [hc0ff, ↓reduceIte]
          have hstep : (l1 &&& 128#u8) = 0#u8 ↔ l1.val < 128 := and_0x80_eq_zero_iff l1
          by_cases hi1 : (l1 &&& 128#u8) = 0#u8
          · have hi1' : l1.val < 128 := hstep.mp hi1
            simp [hi1, hi1']
          · have hi1' : ¬ l1.val < 128 := fun hc => hi1 (hstep.mpr hc)
            simp [hi1, hi1']
        · simp only [hc0ff, ↓reduceIte]
          have hne0 : l0 ≠ (if l1.val < 128 then (0#u8 : U8) else 255#u8) := by
            split
            · exact hc00
            · exact hc0ff
          exact ⟨fun _ => hne0, fun _ => rfl⟩
    · have hlen1 : content.val.length < 2 := by scalar_tac
      have hlen1' : content.val.length = 1 := by omega
      obtain ⟨x, hx⟩ := List.length_eq_one_iff.mp hlen1'
      simp only [h2, ↓reduceIte]
      simp [hx, IsMinimalDer]

#print axioms is_negative_spec
#print axioms validate_iff_minimal

/-! ## Slice 2: `encode_minimal_integer_into`, the strip-loop, and the round-trip

    This is the banked follow-on flagged in the module docstring: the strip-loop side of
    the codec (`encode_minimal_integer_into`), lifted to a slice of *any* length, using
    the same `loop.spec_decr_nat` idiom `LengthProofs.lean`'s `decode_length_loop_spec` /
    `encode_length_loop0_spec` / `encode_length_loop1_spec` already exercise.

    No NEW assumed axiom is needed: the loop body's `lift (i3 &&& 128#u8)` goes through the
    same *owned-value* `&&&` (a genuinely modelled, computable `UScalar` operation) that
    `validate_integer_content` itself uses — not the *reference* `&u8 & u8` op that needed
    `bitand_spec` for `is_negative`'s closure. So the strip-loop, `encode_minimal_integer_into`,
    and the round-trip theorem below rest on no axiom beyond the Lean/Aeneas standard ones and
    `bv_decide`'s own certificate axiom (already disclosed above).

    Precise reading of "no new axiom" (review bigint-roundtrip-lid-01): the three
    slice-1 axioms (`first_spec`/`bitand_spec`/`is_some_and_spec`) still exist in this file for
    `is_negative`; the claim is that no slice-2 theorem *depends on* them — machine-backed by the
    `#print axioms` line after each theorem below (each shows only propext/Classical.choice/
    Quot.sound + the one bv_decide axiom). The `copy_from_slice` / `index_mut` / range-from
    `Slice.index` ops the encoder threads through are Aeneas-*modelled* (computable, no opaque
    external), so they need no assumed spec and sit in the same "trust the Aeneas Std model of
    Rust" base as every extracted op; `take_setSlice!_zero` bridges the copy to `List.setSlice!`.

    Reviewed by three independent reviewers (bigint-roundtrip-lid-01): two SOUND, one REVISE-6,
    adjudicated — F2 (loop spec "too weak") REJECTED (`IsMinimalDer (drop r)` *is* the guard-fails
    fixed point; the converse is `..._loop_body_done`/`..._fixed_point`), F1/F4/F6 folded as the
    precision/prose above. Follow-ons (a) exactness + (b) success-witness now LANDED as
    `encode_minimal_integer_into_exact` (`out[..written] = content.drop (len − written)` — the output
    is *the* minimal suffix of the input) and `encode_minimal_integer_into_succeeds` (`content ≠ [] ∧
    len ≤ out.len → some`), both sorry-free / zero new axioms, one independent review (bigint-banked-01)
    SOUND. (c) [from D16] the two-case §8.3.2-form `IsMinimalDer` lemma, `IsMinimalDer_two_case`
    (bottom of file), is now landed — the last banked item. -/

/-- Two convenience lemmas bridging `IsMinimalDer`'s cons-pattern definition to the
    length/leading-two-octet facts the strip-loop proof below naturally produces (mirrors the
    `l0 :: l1 :: rest` decomposition idiom `validate_iff_minimal` already uses, factored out so
    the loop proof's three `done`-branches can each discharge in one line). -/
theorem IsMinimalDer_of_singleton {l : List U8} (h : l.length = 1) : IsMinimalDer l := by
  obtain ⟨x, hx⟩ := List.length_eq_one_iff.mp h
  simp [hx, IsMinimalDer]

/-- The general (≥ 2 octets) case: `l` is minimal whenever its leading octet differs from the
    hypothetical sign-extension byte implied by its second octet — exactly `IsMinimalDer`'s own
    `l0 :: l1 :: _` case, restated so a caller only has to exhibit the two leading octets and the
    length bound, not perform the list case-split itself. Stated with `getElem!` (default-valued,
    no bound-proof bookkeeping) since the loop proof below only ever knows the length bound
    separately from the octet values, and `!`-indexing composes with `drop` (`List.getElem!_drop`)
    with no dependent-proof gymnastics. -/
theorem IsMinimalDer_of_ne {l : List U8} (h2 : 2 ≤ l.length)
    (hne : l[0]! ≠ (if l[1]!.val < 128 then (0#u8 : U8) else 255#u8)) :
    IsMinimalDer l := by
  obtain ⟨l0, l1, rest, hlrw⟩ : ∃ l0 l1 rest, l = l0 :: l1 :: rest := by
    rcases hv : l with _ | ⟨x0, tl⟩
    · rw [hv] at h2; simp at h2
    · rcases tl with _ | ⟨x1, xs⟩
      · rw [hv] at h2; simp at h2
      · exact ⟨x0, x1, xs, rfl⟩
  subst hlrw
  simpa [IsMinimalDer] using hne

/-! ### The core loop lemma -/

/-- **`encode_minimal_integer_into`'s strip-loop, ∀-length.** From any in-bounds `start`, the
    production loop (`big_integer.encode_minimal_integer_into_loop`) returns some `r ≥ start`,
    still in bounds, such that the *independent* predicate `IsMinimalDer` holds of the tail
    `content.val.drop r` — i.e. the loop lands exactly where the redundant-padding guard first
    fails (or one octet remains). This is the loop-invariant half of the round-trip: it does not
    restate the production if-chain (D14) but instead recomputes, from the loop's own two
    `step`-read octets, the same independent oracle `validate_iff_minimal` is stated against. -/
theorem encode_minimal_integer_into_loop_spec (content : Slice U8) (start : Usize)
    (hstart : start.val < content.val.length) :
    big_integer.encode_minimal_integer_into_loop content start ⦃ r =>
      start.val ≤ r.val ∧ r.val < content.val.length ∧
      IsMinimalDer (content.val.drop r.val) ⦄ := by
  unfold big_integer.encode_minimal_integer_into_loop
  apply loop.spec_decr_nat
    (measure := fun cur => content.val.length - cur.val)
    (inv := fun cur => start.val ≤ cur.val ∧ cur.val < content.val.length)
  · rintro cur ⟨hle, hlt⟩
    simp only [big_integer.encode_minimal_integer_into_loop.body, bne_iff_ne]
    step as ⟨i, hi⟩              -- i = cur + 1
    have hival : i.val = cur.val + 1 := by scalar_tac
    split
    · -- i < len(content): at least two octets remain from `cur`
      rename_i hcase
      have hi1len : cur.val + 1 < content.val.length := by scalar_tac
      have hilt : i.val < content.val.length := by scalar_tac
      step as ⟨i2, hi2⟩          -- i2 = content[cur]
      have hc0 : content.val[cur.val]! = i2 :=
        (getElem!_pos content.val cur.val hlt).trans hi2.symm
      have hd0 : (content.val.drop cur.val)[0]! = i2 := by
        rw [List.getElem!_drop]; simpa using hc0
      split
      · -- i2 = 0x00
        rename_i hi2z
        step as ⟨i3, hi3⟩            -- i3 = content[i] = content[cur+1]
        step as ⟨i4, hi4, hi4bv⟩     -- i4 = i3 &&& 0x80  (owned &&&, no axiom)
        have hi4eq : i4 = i3 &&& 128#u8 := UScalar.eq_of_val_eq hi4
        have hc1 : content.val[cur.val + 1]! = i3 := by
          rw [← hival]; exact (getElem!_pos content.val i.val hilt).trans hi3.symm
        have hd1 : (content.val.drop cur.val)[1]! = i3 := by
          rw [List.getElem!_drop]; simpa using hc1
        split
        · -- i4 = 0 -> the leading 0x00 is redundant, keep stripping: cont i
          rename_i hi4z
          refine ⟨?_, ?_, ?_⟩ <;> scalar_tac
        · -- i4 ≠ 0
          rename_i hi4nz
          split
          · -- i2 = 0xFF is impossible here (i2 = 0x00 from hi2z)
            rename_i hi2ff
            exact absurd (hi2z.symm.trans hi2ff) (by decide)
          · -- done cur: l0 = 0x00, l1's sign bit is set (i4 ≠ 0) so the sign-extension byte
            -- implied by l1 is 0xFF ≠ l0 -- already minimal, stop.
            refine ⟨hle, hlt, IsMinimalDer_of_ne (by rw [List.length_drop]; omega) ?_⟩
            have hi3ge : ¬ (i3.val < 128) := by
              rw [← and_0x80_eq_zero_iff, ← hi4eq]; exact hi4nz
            rw [hd0, hd1, hi2z, if_neg hi3ge]; decide
      · -- i2 ≠ 0x00
        rename_i hi2nz
        split
        · -- i2 = 0xFF
          rename_i hi2ff
          step as ⟨i3, hi3⟩            -- i3 = content[i] = content[cur+1]
          step as ⟨i4, hi4, hi4bv⟩     -- i4 = i3 &&& 0x80
          have hi4eq : i4 = i3 &&& 128#u8 := UScalar.eq_of_val_eq hi4
          have hc1 : content.val[cur.val + 1]! = i3 := by
            rw [← hival]; exact (getElem!_pos content.val i.val hilt).trans hi3.symm
          have hd1 : (content.val.drop cur.val)[1]! = i3 := by
            rw [List.getElem!_drop]; simpa using hc1
          split
          · -- i4 ≠ 0 -> the leading 0xFF is redundant, keep stripping: cont i
            rename_i hi4nz
            refine ⟨?_, ?_, ?_⟩ <;> scalar_tac
          · -- i4 = 0 -> l1's sign bit is clear, sign-extension byte is 0x00 ≠ l0 (0xFF): stop
            rename_i hi4z
            simp only [not_not] at hi4z
            refine ⟨hle, hlt, IsMinimalDer_of_ne (by rw [List.length_drop]; omega) ?_⟩
            have hi3lt : i3.val < 128 := (and_0x80_eq_zero_iff i3).mp (hi4eq.symm.trans hi4z)
            rw [hd0, hd1, hi2ff, if_pos hi3lt]; decide
        · -- i2 ∉ {0x00, 0xFF}: trivially minimal regardless of l1, stop
          rename_i hi2nff
          refine ⟨hle, hlt, IsMinimalDer_of_ne (by rw [List.length_drop]; omega) ?_⟩
          rw [hd0]
          split
          · exact hi2nz
          · exact hi2nff
    · -- i ≥ len(content): only one octet remains from `cur` -- trivially minimal, stop
      rename_i hge
      refine ⟨hle, hlt, IsMinimalDer_of_singleton ?_⟩
      rw [List.length_drop]; scalar_tac
  · exact ⟨le_refl _, hstart⟩

#print axioms encode_minimal_integer_into_loop_spec

/-! ### Encode output is minimal -/

/-- Writing `s'` at offset `0` of a list `s` (via `setSlice!`) and then taking back exactly
    `s'.length` octets recovers `s'`, provided `s'` fits (`s'.length ≤ s.length`) — the list-level
    fact behind `Slice::copy_from_slice` into a `[..len]` sub-slice view. -/
theorem take_setSlice!_zero {α} (s s' : List α) (h : s'.length ≤ s.length) :
    (s.setSlice! 0 s').take s'.length = s' := by
  simp only [List.setSlice!, Nat.sub_zero, List.take_zero, List.nil_append,
    Nat.min_eq_left h, List.take_of_length_le (le_refl s'.length), List.take_left]

/-- **`encode_minimal_integer_into`'s output is minimal, ∀-length.** When the encoder succeeds
    (returns `some written`), the first `written` octets it wrote into `out` satisfy the
    independent minimality predicate `IsMinimalDer` — the ∀-length lift of the Kani harness
    `minimizer_output_is_always_minimal`. Composes the strip-loop invariant above with the
    range-index / range-index_mut / `copy_from_slice` step specs that thread the loop's result
    through to the actually-written output. -/
theorem encode_minimal_integer_into_spec (content out : Slice U8) :
    big_integer.encode_minimal_integer_into content out ⦃ r =>
      ∀ written, r.1 = some written → IsMinimalDer (r.2.val.take written.val) ⦄ := by
  unfold big_integer.encode_minimal_integer_into
  step as ⟨b, hb⟩
  split
  · -- content empty: r = (none, out) -- vacuous
    intro written heq; simp at heq
  · -- content nonempty
    rename_i hbF
    have hcpos : 0 < content.val.length := by scalar_tac
    step with encode_minimal_integer_into_loop_spec as ⟨start, hstartle, hstartlt, hmin⟩
    step as ⟨minimal, hminval, hminlen⟩
    split
    · -- out too small: r = (none, out) -- vacuous
      intro written heq; simp at heq
    · -- minimal fits in out
      rename_i hbig
      step as ⟨s, back, hsval, hslen, hback⟩
      step as ⟨s1, hs1⟩
      intro written heq
      have hw : written = Slice.len minimal := by
        simpa using heq.symm
      have hlen_le : minimal.val.length ≤ out.val.length := by scalar_tac
      have houtval : (back s1).val = out.val.setSlice! 0 minimal.val := by
        rw [hs1]; exact hback minimal
      have hwval : written.val = minimal.val.length := by
        rw [hw]; scalar_tac
      rw [hwval, houtval, take_setSlice!_zero out.val minimal.val hlen_le, hminval]
      exact hmin

#print axioms encode_minimal_integer_into_spec

/-! ### Round-trip: decode accepts encode's output -/

/-- **Round-trip: the validator accepts the encoder's output** (∀-length): whenever
    `encode_minimal_integer_into` succeeds, the content it wrote (`out[..written]`, packaged as a
    `Slice`) is accepted by `validate_integer_content`. This is the *recognizer* direction —
    `validate (encode c) = Ok`, i.e. everything the encoder emits is DER-minimal and so passes the
    decoder's minimality check. It is **not** a value-preserving `encode ∘ decode = id` bijection
    (the Rust encoder only strips redundant sign octets; value-preservation is a separate claim not
    made here). Ties together the strip-loop (`encode_minimal_integer_into_spec`) and the
    independent minimality oracle (`validate_iff_minimal`); mirrors `LengthProofs.lean`'s
    `decode_accepts_only_canonical`. -/
theorem encode_minimal_integer_into_roundtrip (content out : Slice U8) :
    big_integer.encode_minimal_integer_into content out ⦃ r =>
      ∀ written, r.1 = some written →
        big_integer.validate_integer_content ⟨r.2.val.take written.val, by scalar_tac⟩
          = ok (core.result.Result.Ok ()) ⦄ := by
  apply WP.spec_mono (encode_minimal_integer_into_spec content out)
  intro r hr written heq
  exact (validate_iff_minimal ⟨r.2.val.take written.val, by scalar_tac⟩).mpr (hr written heq)

#print axioms encode_minimal_integer_into_roundtrip

/-! ### Fixed point: an already-minimal input strips nothing -/

/-- Converse of `IsMinimalDer_of_ne`: if `l` (≥ 2 octets) is minimal, its leading octet differs
    from the sign-extension byte implied by its second octet. -/
theorem IsMinimalDer_elim {l : List U8} (h2 : 2 ≤ l.length) (hmin : IsMinimalDer l) :
    l[0]! ≠ (if l[1]!.val < 128 then (0#u8 : U8) else 255#u8) := by
  obtain ⟨l0, l1, rest, hlrw⟩ : ∃ l0 l1 rest, l = l0 :: l1 :: rest := by
    rcases hv : l with _ | ⟨x0, tl⟩
    · rw [hv] at h2; simp at h2
    · rcases tl with _ | ⟨x1, xs⟩
      · rw [hv] at h2; simp at h2
      · exact ⟨x0, x1, xs, rfl⟩
  subst hlrw
  simpa [IsMinimalDer] using hmin

/-- **The strip-loop's body takes no step from an already-minimal position.** If
    `content.val.drop cur.val` is already `IsMinimalDer`, the production loop body cannot see
    either redundant-padding pattern (`0x00` followed by a non-negative byte, or `0xFF` followed
    by a negative byte) — both would contradict `IsMinimalDer` — so it always reports `done cur`.
    The converse half of `encode_minimal_integer_into_loop_spec`'s case analysis. -/
theorem encode_minimal_integer_into_loop_body_done (content : Slice U8) (cur : Usize)
    (hlt : cur.val < content.val.length) (hmin : IsMinimalDer (content.val.drop cur.val)) :
    big_integer.encode_minimal_integer_into_loop.body content cur
      ⦃ r => r = ControlFlow.done cur ⦄ := by
  simp only [big_integer.encode_minimal_integer_into_loop.body, bne_iff_ne]
  step as ⟨i, hi⟩
  have hival : i.val = cur.val + 1 := by scalar_tac
  split
  · -- i < len(content): at least two octets remain from `cur`
    rename_i hcase
    have hi1len : cur.val + 1 < content.val.length := by scalar_tac
    have hilt : i.val < content.val.length := by scalar_tac
    step as ⟨i2, hi2⟩
    have hc0 : content.val[cur.val]! = i2 := (getElem!_pos content.val cur.val hlt).trans hi2.symm
    have hd0 : (content.val.drop cur.val)[0]! = i2 := by
      rw [List.getElem!_drop]; simpa using hc0
    have h2len : 2 ≤ (content.val.drop cur.val).length := by rw [List.length_drop]; omega
    have hne := IsMinimalDer_elim h2len hmin
    split
    · -- i2 = 0x00
      rename_i hi2z
      step as ⟨i3, hi3⟩
      step as ⟨i4, hi4, hi4bv⟩
      have hi4eq : i4 = i3 &&& 128#u8 := UScalar.eq_of_val_eq hi4
      have hc1 : content.val[cur.val + 1]! = i3 := by
        rw [← hival]; exact (getElem!_pos content.val i.val hilt).trans hi3.symm
      have hd1 : (content.val.drop cur.val)[1]! = i3 := by
        rw [List.getElem!_drop]; simpa using hc1
      rw [hd0, hd1, hi2z] at hne
      split
      · -- i4 = 0 -> l1 < 128 -> the sign-extension byte for l1 is 0x00 = l0: contradicts `hne`
        rename_i hi4z
        have hi3lt : i3.val < 128 := (and_0x80_eq_zero_iff i3).mp (hi4eq.symm.trans hi4z)
        exact (hne (if_pos hi3lt).symm).elim
      · -- i4 ≠ 0: i2 = 0xFF is impossible (i2 = 0x00), forced done
        split
        · rename_i hi2ff; exact absurd (hi2z.symm.trans hi2ff) (by decide)
        · rfl
    · -- i2 ≠ 0x00
      rename_i hi2nz
      split
      · -- i2 = 0xFF
        rename_i hi2ff
        step as ⟨i3, hi3⟩
        step as ⟨i4, hi4, hi4bv⟩
        have hi4eq : i4 = i3 &&& 128#u8 := UScalar.eq_of_val_eq hi4
        have hc1 : content.val[cur.val + 1]! = i3 := by
          rw [← hival]; exact (getElem!_pos content.val i.val hilt).trans hi3.symm
        have hd1 : (content.val.drop cur.val)[1]! = i3 := by
          rw [List.getElem!_drop]; simpa using hc1
        rw [hd0, hd1, hi2ff] at hne
        split
        · -- i4 ≠ 0 -> l1 ≥ 128 -> the sign-extension byte for l1 is 0xFF = l0: contradicts `hne`
          rename_i hi4nz
          have hi3ge : ¬ (i3.val < 128) := by
            rw [← and_0x80_eq_zero_iff, ← hi4eq]; exact hi4nz
          exact (hne (if_neg hi3ge).symm).elim
        · rfl
      · rfl
  · rfl

/-- **Fixed point / round-trip framing** (∀-length): an already-minimal, non-empty `content`
    leaves the strip-loop at `start = 0` — i.e. `encode_minimal_integer_into` is a no-op on
    already-minimal input. The ∀-length lift of the Kani harness
    `accepted_is_fixed_point_of_minimizer`'s core claim (there tied to `validate_integer_content`
    accepting; here stated directly against the independent `IsMinimalDer` oracle, composable with
    `validate_iff_minimal` for the decode-side framing). -/
theorem encode_minimal_integer_into_loop_fixed_point (content : Slice U8)
    (hne : content.val ≠ []) (hmin : IsMinimalDer content.val) :
    big_integer.encode_minimal_integer_into_loop content 0#usize ⦃ r => r = 0#usize ⦄ := by
  have hlt : (0#usize).val < content.val.length := by
    have hpos : 0 < content.val.length := List.length_pos_of_ne_nil hne
    scalar_tac
  unfold big_integer.encode_minimal_integer_into_loop
  apply loop.spec_decr_nat (measure := fun _ : Usize => 0) (inv := fun cur => cur = 0#usize)
  · intro cur hcur
    rw [hcur]
    apply WP.spec_mono
      (encode_minimal_integer_into_loop_body_done content 0#usize hlt (by simpa using hmin))
    rintro r rfl
    rfl
  · rfl

#print axioms encode_minimal_integer_into_loop_fixed_point

/-! ### Banked follow-ons: exactness and a success witness

    Two small strengthenings flagged (but not proved) in the slice-2 section's docstring above,
    both reusing the already-proved machinery with no restructuring: (a) *exactness* — the bytes
    the encoder actually writes are not just "some `IsMinimalDer` list" but the literal suffix of
    `content` that the strip-loop lands on; (b) a *success witness* — a simple sufficient condition
    (`content` non-empty and `out` at least as long as `content`) under which the encoder is
    guaranteed to return `some`, i.e. the `out`-too-small branch provably cannot fire. -/

/-- **Exactness** (∀-length): on success, the `written` octets `encode_minimal_integer_into`
    wrote into `out` are *literally* the trailing `written` octets of `content` — nothing added,
    reordered, or drawn from elsewhere; the encoder only ever strips a leading prefix. Same
    derivation as `encode_minimal_integer_into_spec` (the `take_setSlice!_zero` / `hminval` chain
    already produces `r.2.val.take written.val = content.val.drop start.val` internally; this
    theorem additionally identifies `start.val` with `content.val.length - written.val` via the
    loop result's length bookkeeping (`hminlen`), so the statement below needs no reference to the
    internal `start` at all. Combined with `encode_minimal_integer_into_spec`, this gives full
    exactness: the output is *the* minimal suffix of the input, byte-for-byte. -/
theorem encode_minimal_integer_into_exact (content out : Slice U8) :
    big_integer.encode_minimal_integer_into content out ⦃ r =>
      ∀ written, r.1 = some written →
        r.2.val.take written.val = content.val.drop (content.val.length - written.val) ⦄ := by
  unfold big_integer.encode_minimal_integer_into
  step as ⟨b, hb⟩
  split
  · -- content empty: r = (none, out) -- vacuous
    intro written heq; simp at heq
  · -- content nonempty
    rename_i hbF
    have hcpos : 0 < content.val.length := by scalar_tac
    step with encode_minimal_integer_into_loop_spec as ⟨start, hstartle, hstartlt, hmin⟩
    step as ⟨minimal, hminval, hminlen⟩
    split
    · -- out too small: r = (none, out) -- vacuous
      intro written heq; simp at heq
    · -- minimal fits in out
      rename_i hbig
      step as ⟨s, back, hsval, hslen, hback⟩
      step as ⟨s1, hs1⟩
      intro written heq
      have hw : written = Slice.len minimal := by
        simpa using heq.symm
      have hlen_le : minimal.val.length ≤ out.val.length := by scalar_tac
      have houtval : (back s1).val = out.val.setSlice! 0 minimal.val := by
        rw [hs1]; exact hback minimal
      have hwval : written.val = minimal.val.length := by
        rw [hw]; scalar_tac
      have hstarteq : content.val.length - minimal.val.length = start.val := by
        scalar_tac
      rw [hwval, houtval, take_setSlice!_zero out.val minimal.val hlen_le, hstarteq]
      exact hminval

#print axioms encode_minimal_integer_into_exact

/-- **Success witness** (∀-length): if `content` is non-empty and `out` is at least as long as
    `content`, `encode_minimal_integer_into` is guaranteed to succeed (return `some written`) — the
    `out`-too-small branch cannot fire. Uses `encode_minimal_integer_into_loop_spec` to bound the
    loop result `start < content.len`, so the minimal suffix `minimal = content.drop start` has
    `minimal.len ≤ content.len ≤ out.len`, which is exactly the negation of the encoder's
    `out.len < minimal.len` failure guard. -/
theorem encode_minimal_integer_into_succeeds (content out : Slice U8)
    (hne : content.val ≠ []) (hfits : content.val.length ≤ out.val.length) :
    big_integer.encode_minimal_integer_into content out ⦃ r => ∃ written, r.1 = some written ⦄ := by
  unfold big_integer.encode_minimal_integer_into
  step as ⟨b, hb⟩
  have hcpos : 0 < content.val.length := by
    have hlen0 : content.val.length ≠ 0 := by simpa using hne
    omega
  split
  · -- content empty: contradicts hne / hcpos
    exfalso; scalar_tac
  · rename_i hbF
    step with encode_minimal_integer_into_loop_spec as ⟨start, hstartle, hstartlt, hmin⟩
    step as ⟨minimal, hminval, hminlen⟩
    split
    · -- out too small: impossible given hfits, since minimal.len ≤ content.len ≤ out.len
      rename_i hbig
      exfalso; scalar_tac
    · rename_i hbig
      step as ⟨s, back, hsval, hslen, hback⟩
      step as ⟨s1, hs1⟩
      exact ⟨_, rfl⟩

#print axioms encode_minimal_integer_into_succeeds

/-! ### The explicit §8.3.2 two-case form -/

/-- **The explicit DER §8.3.2 two-case form** (the last banked item, D16/review
    bigint-roundtrip-lid-01): a third, independent restatement of `IsMinimalDer` on a
    ≥ 2-octet list, spelling out the standard's own "two redundant leading-octet
    patterns" wording directly — `l0 :: l1 :: rest` is minimal iff it exhibits
    *neither* of the two forbidden patterns: a leading `0x00` followed by a
    non-negative octet (`l1.val < 128`), or a leading `0xFF` followed by a negative
    octet (`128 ≤ l1.val`). This is definitionally the same fact as the `if`-form in
    `IsMinimalDer`'s own definition (and as `IsMinimalDer_of_ne` / `IsMinimalDer_elim`
    together), but phrased with no `if` at all — a cross-check that the de-tautologized
    predicate really does encode exactly §8.3.2's two-case rule. -/
theorem IsMinimalDer_two_case {l0 l1 : U8} {rest : List U8} :
    IsMinimalDer (l0 :: l1 :: rest)
      ↔ ¬ ((l0 = 0#u8 ∧ l1.val < 128) ∨ (l0 = 255#u8 ∧ 128 ≤ l1.val)) := by
  simp only [IsMinimalDer]
  by_cases h1 : l1.val < 128
  · rw [if_pos h1]
    constructor
    · intro hne hor
      rcases hor with ⟨h0, _⟩ | ⟨_, hge⟩
      · exact hne h0
      · omega
    · intro hnot heq
      exact hnot (Or.inl ⟨heq, h1⟩)
  · rw [if_neg h1]
    have h1' : 128 ≤ l1.val := by omega
    constructor
    · intro hne hor
      rcases hor with ⟨_, hlt⟩ | ⟨h0, _⟩
      · omega
      · exact hne h0
    · intro hnot heq
      exact hnot (Or.inr ⟨heq, h1'⟩)

#print axioms IsMinimalDer_two_case

end DerVerified.BigInteger
