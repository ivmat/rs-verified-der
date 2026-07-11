import DerLengthExtract

/-!
# Unbounded (∀-length) properties of the DER length codec

These theorems are proved in Lean 4 over the **Aeneas-extracted** model of the
*same* `der-verified/src/length.rs` that the Kani floor proves (single source of
truth — the extraction crate `#[path]`-includes that file).

The point is the **straddle**: Kani proves these properties bit-precisely but only
for bounded buffers (the harnesses use an 8-byte symbolic buffer). Here we prove
them for a slice of **any length** — the unbounded lid Kani cannot reach.

Covered here (each unbounds a specific Kani harness in `length.rs`):

  *First-byte branches* —
  * `decode_empty`      ← `rejects_empty_input`
  * `decode_indefinite` ← `indefinite_is_classified`   (0x80)
  * `decode_reserved`   ← `reserved_is_classified`     (0xFF)
  * `decode_short_form` ← the decode half of `short_form_roundtrips` (accept path)

  *Long-form reject family* (the malformed-encoding surface — through the `&0x7f`
  bit-mask, the fallible `1 + n` add, and the range-slice + `index_usize`) —
  * `decode_truncated_long`            ← `truncated_long_form_is_classified`
  * `decode_nonminimal_leading_zero`   ← `leading_zero_is_non_minimal`
  * `decode_toolarge`                  ← `too_large_is_classified`

Together these cover **every reject path that fires *before* the value-decode loop**
(the syntactic malformed-input surface) plus the short-form accept, at any length.

The **value-decode loop invariant** (`decode_length_loop_spec`) is proven: the loop
computes the big-endian value `beVal` of the ≤ 4 octets, with no `u32` truncation (via
`loop.spec_decr_nat` + the `shl8_or_bv` bit-vector identity). It is now **wired through
`decode_length`'s entire long-form tail** — *both* post-loop branches are proven at any
length:

  *Long-form tail* (consuming the loop invariant via `step with`) —
  * `decode_long_form_accept`          — canonical accept ⇒ `Ok(beVal ws, 1+n)`
  * `decode_long_form_nonminimal_value`— `beVal < 0x80` ⇒ `NonMinimal` (e.g. `[0x81, 0x01]`)

With these, every branch of `decode_length` is proven ∀-length. The headline **round-trip
canonicality** (`decode_accepts_only_canonical`, below) — a *different* theorem additionally
needing `encode_length`'s two loops (encode is the inverse direction) — **is also proven**, so
this file machine-checks the length-codec L4 lid **complete end-to-end** (decode branches +
encode↔decode round-trip, at any length). See D7.

Trusted base: the Aeneas Std library specs + the single assumed spec `first_spec`
below (Aeneas emits `core::slice::first` as an opaque axiom). The loop-invariant
lemmas additionally use `bv_decide` for one bit-vector identity (`shl8_or_bv`),
which introduces its LRAT-checked native axiom — a *verified* SAT-certificate
decision procedure, **not** a `sorry`. `#print axioms` at the bottom accounts for
exactly what each theorem depends on; none rest on `sorryAx` (in particular, not on
Aeneas's own internal `sorry`s).
-/

open Aeneas Aeneas.Std Result
open der_length_extract

namespace DerVerified.Length

/-- **Assumed spec** for the opaque external `core::slice::<[T]>::first`.
    Aeneas has no builtin for it, so it is extracted as an axiom with no body.
    We give it its documented Rust semantics: return the head of the slice, or
    `none` iff empty.

    Two modelling notes (raised in independent review `L4-lean-lid-01`):
    * *value vs reference* — Rust's `first` returns `Option<&T>`, but Aeneas erased
      the shared borrow when it chose the extracted type `Slice T → Result (Option T)`;
      this codec consumes the byte by value, so value-equality (`s.val[0]?`) is faithful.
    * *totality* — Aeneas's `Slice T` is `{ val : List T // val.length ≤ Usize.max }`
      (a `List` with a single length-bound invariant, no other structure), so `first`
      is total; modelling it as always-`ok` admits no unreachable state.

    This is the ONLY spec we trust on top of the Aeneas Std library. -/
axiom first_spec {T : Type} (s : Slice T) :
    der_length_extract.core.slice.Slice.first s = ok s.val[0]?

/-- Empty input ⇒ `Truncated`. -/
theorem decode_empty (s : Slice U8) (h : s.val = []) :
    length.decode_length s = ok (.Err length.LengthError.Truncated) := by
  unfold length.decode_length
  simp [first_spec, h]

/-- **Indefinite form** (`0x80`): any slice of ANY length beginning with `0x80`
    is classified `Indefinite`. (Kani proved this only for ≤ 8-byte buffers.) -/
theorem decode_indefinite (s : Slice U8) (h : s.val[0]? = some 128#u8) :
    length.decode_length s = ok (.Err length.LengthError.Indefinite) := by
  unfold length.decode_length
  simp [first_spec, h]

/-- **Reserved octet** (`0xFF`): any slice of ANY length beginning with `0xFF`
    is classified `Reserved`. -/
theorem decode_reserved (s : Slice U8) (h : s.val[0]? = some 255#u8) :
    length.decode_length s = ok (.Err length.LengthError.Reserved) := by
  unfold length.decode_length
  simp [first_spec, h]

/-- **Short form accept path**: any slice of ANY length whose first byte `b` is
    `< 0x80` decodes to *exactly* `b` widened to `u32`, consuming 1 byte. Stated as
    the precise returned value (functional determinism), not merely value-equality
    — strengthened per independent review `L4-lean-lid-01`. -/
theorem decode_short_form (s : Slice U8) (b : U8) (hb : b.val < 128)
    (h : s.val[0]? = some b) :
    length.decode_length s = ok (.Ok (UScalar.cast .U32 b, 1#usize)) := by
  unfold length.decode_length
  simp [first_spec, h, hb, lift]

/-- Corollary in value form: the decoded `u32` equals the first byte numerically. -/
theorem decode_short_form_val (s : Slice U8) (b : U8) (hb : b.val < 128)
    (h : s.val[0]? = some b) :
    ∃ v : U32, v.val = b.val ∧ length.decode_length s = ok (.Ok (v, 1#usize)) :=
  ⟨UScalar.cast .U32 b, by simp, decode_short_form s b hb h⟩

/-- **Long-form `Truncated`** (∀-length): a long-form initial octet `b` (`0x81..0xFE`)
    declares `n = b &&& 0x7f` following octets, but the slice holds only `≤ n` bytes —
    rejected `Truncated` before any octet is read. Unbounds `truncated_long_form_is_classified`. -/
theorem decode_truncated_long (s : Slice U8) (b : U8)
    (hlo : 128 < b.val) (hhi : b.val < 255)
    (h : s.val[0]? = some b)
    (hlen : s.val.length ≤ b.val &&& 127) :
    length.decode_length s ⦃ r => r = .Err length.LengthError.Truncated ⦄ := by
  unfold length.decode_length
  have e1 : ¬ (b.val < 128) := by omega
  have e2 : ¬ (b = 128#u8) := by scalar_tac
  have e3 : ¬ (b = 255#u8) := by scalar_tac
  simp only [first_spec, h]
  simp [e1, e2, e3]
  step as ⟨i, hi⟩        -- i  = b & 0x7f
  step as ⟨n, hn⟩        -- n  = i as usize
  step as ⟨i2, hi2⟩      -- i2 = 1 + n
  have hlt : s.val.length < i2.val := by scalar_tac
  simp [hlt]

/-- **Long-form `NonMinimal` (leading-zero octet)** (∀-length): a long-form length
    with enough octets present but whose first length octet is `0x00` is non-canonical,
    rejected `NonMinimal`. Unbounds `leading_zero_is_non_minimal`. -/
theorem decode_nonminimal_leading_zero (s : Slice U8) (b : U8)
    (hlo : 128 < b.val) (hhi : b.val < 255)
    -- b declares ≥ 1 length-octet. Implied by 0x81..0xFE, but `scalar_tac`/`omega`
    -- cannot derive `1 ≤ b & 0x7f` (no bit-mask reasoning; verified in review
    -- L4-lean-lid-02), so we state it explicitly rather than smuggle a `sorry`.
    (hpos : 1 ≤ b.val &&& 127)
    (h : s.val[0]? = some b)
    (henough : 1 + (b.val &&& 127) ≤ s.val.length)
    (h1 : s.val[1]? = some 0#u8) :
    length.decode_length s ⦃ r => r = .Err length.LengthError.NonMinimal ⦄ := by
  unfold length.decode_length
  have e1 : ¬ (b.val < 128) := by omega
  have e2 : ¬ (b = 128#u8) := by scalar_tac
  have e3 : ¬ (b = 255#u8) := by scalar_tac
  simp only [first_spec, h]
  simp [e1, e2, e3]
  step as ⟨i, hi⟩        -- i  = b & 0x7f
  step as ⟨n, hn⟩        -- n  = i as usize
  step as ⟨i2, hi2⟩      -- i2 = 1 + n
  have hnt : ¬ (s.val.length < i2.val) := by scalar_tac  -- enough octets present
  simp [hnt]
  step as ⟨octets, hoct⟩ -- octets = input[1 .. i2]
  step as ⟨i3, hi3⟩      -- i3 = octets[0]
  have hlen1 : 1 < s.val.length := by scalar_tac
  have hz : i3 = 0#u8 := by simp_lists [hi3, hoct, h1]; grind
  rw [hz]; simp

/-- **Long-form `TooLarge`** (∀-length): a long-form length declaring more than 4
    octets (value `> u32::MAX`) with a non-zero leading octet is rejected `TooLarge`
    (this codec's deliberate `u32` boundary, D2b). Unbounds `too_large_is_classified`. -/
theorem decode_toolarge (s : Slice U8) (b c : U8)
    (hlo : 128 < b.val) (hhi : b.val < 255)
    (hbig : 4 < b.val &&& 127)      -- declares > 4 length-octets ⇒ exceeds u32
    (h : s.val[0]? = some b)
    (henough : 1 + (b.val &&& 127) ≤ s.val.length)
    (h1 : s.val[1]? = some c) (hc : c ≠ 0#u8) :  -- leading octet present and non-zero
    length.decode_length s ⦃ r => r = .Err length.LengthError.TooLarge ⦄ := by
  unfold length.decode_length
  have e1 : ¬ (b.val < 128) := by omega
  have e2 : ¬ (b = 128#u8) := by scalar_tac
  have e3 : ¬ (b = 255#u8) := by scalar_tac
  simp only [first_spec, h]
  simp [e1, e2, e3]
  step as ⟨i, hi⟩
  step as ⟨n, hn⟩
  step as ⟨i2, hi2⟩
  have hnt : ¬ (s.val.length < i2.val) := by scalar_tac
  simp [hnt]
  step as ⟨octets, hoct⟩
  step as ⟨i3, hi3⟩
  have hlen1 : 1 < s.val.length := by scalar_tac
  have hz : i3 = c := by simp_lists [hi3, hoct, h1]; grind
  have hnz : ¬ (i3 = 0#u8) := by rw [hz]; exact hc
  simp [hnz]
  have hgt : 4 < n.val := by scalar_tac
  simp [hgt]

/-! ## The value-decode loop invariant (enabling long-form accept + canonicality) -/

/-- Big-endian value of a byte list — matches `decode_length_loop`'s fold
    `val := val*256 + byte`. -/
def beVal : List U8 → Nat := List.foldl (fun acc b => acc * 256 + b.val) 0

@[simp] theorem beVal_nil : beVal [] = 0 := rfl

/-- Each octet contributes < 256, so the big-endian value fits in `256^length`. -/
theorem beVal_lt (l : List U8) : beVal l < 256 ^ l.length := by
  induction l using List.reverseRecOn with
  | nil => simp [beVal]
  | append_singleton xs x ih =>
    simp only [beVal, List.foldl_append, List.foldl_cons, List.foldl_nil,
      List.length_append, List.length_cons, List.length_nil] at *
    have hx : x.val < 256 := by scalar_tac
    rw [pow_succ]
    omega

/-- One fold step: appending octet `k` multiplies by 256 and adds it. -/
theorem beVal_take_succ (l : List U8) (k : Nat) (hk : k < l.length) :
    beVal (l.take (k + 1)) = beVal (l.take k) * 256 + l[k].val := by
  have he : l.take (k + 1) = l.take k ++ [l[k]] := by
    rw [List.take_succ, List.getElem?_eq_getElem hk]; rfl
  rw [he]; simp only [beVal, List.foldl_append, List.foldl_cons, List.foldl_nil]

/-- The `(val << 8) | byte` step is exactly `val*256 + byte` when it doesn't overflow. -/
theorem shl8_or_bv (v w : BitVec 32) (hv : v < 0x1000000#32) (hw : w < 0x100#32) :
    (v <<< (8 : Nat) ||| w) = v * 256#32 + w := by bv_decide

/-- The same, at the `Nat` (`toNat`) level. -/
theorem shl8_or_toNat (v w : BitVec 32) (hv : v < 0x1000000#32) (hw : w < 0x100#32) :
    (v <<< (8 : Nat) ||| w).toNat = v.toNat * 256 + w.toNat := by
  have h1 : v.toNat < 2 ^ 24 := by bv_omega
  have h2 : w.toNat < 256 := by bv_omega
  rw [shl8_or_bv v w hv hw, BitVec.toNat_add, BitVec.toNat_mul, BitVec.toNat_ofNat]
  omega

/-- **Loop invariant**: `decode_length_loop` from `(0, 0)` computes the big-endian
    value of the `n` octets (given `n ≤ 4`, so the `u32` accumulator never truncates).
    This is the inductive lemma the long-form *accept* and full canonicality rest on. -/
theorem decode_length_loop_spec (n : Usize) (octets : Slice U8)
    (hn : n.val ≤ 4) (hlen : octets.val.length = n.val) :
    length.decode_length_loop n octets 0#u32 0#usize ⦃ v => v.val = beVal octets.val ⦄ := by
  unfold length.decode_length_loop
  apply loop.spec_decr_nat
    (measure := fun vi => n.val - vi.2.val)
    (inv := fun vi =>
      vi.2.val ≤ n.val ∧ vi.1.val = beVal (octets.val.take vi.2.val) ∧ vi.1.val < 256 ^ vi.2.val)
  · -- hBody: the body preserves the invariant and decreases the measure
    rintro ⟨val, i⟩ ⟨hile, hval, hbound⟩
    simp only [length.decode_length_loop.body]
    split
    · -- i < n: one accumulation step
      rename_i hlt
      step as ⟨i1, hi1, hi1bv⟩       -- i1 = val <<< 8
      step as ⟨i2, hi2⟩              -- i2 = octets[i]
      step as ⟨i3, hi3⟩              -- i3 = i2 as u32
      step as ⟨val1, hv1, hv1bv⟩     -- val1 = i1 ||| i3
      step as ⟨i4, hi4⟩             -- i4 = i + 1
      have hi_le3 : i.val ≤ 3 := by scalar_tac
      have hvsmall : val.val < 2 ^ 24 :=
        lt_of_lt_of_le hbound
          (by calc (256 : Nat) ^ i.val ≤ 256 ^ 3 := Nat.pow_le_pow_right (by norm_num) hi_le3
                _ = 2 ^ 24 := by norm_num)
      have hi3lt : i3.val < 256 := by rw [hi3]; scalar_tac
      -- the accumulation value, via the bit-vector identity `shl8_or_bv`
      have hkey : val1.val = val.val * 256 + i2.val := by
        have hi3val : i3.val = i2.val := by rw [hi3]; simp
        simp only [UScalar.val] at *
        rw [hv1bv, hi1bv, shl8_or_toNat val.bv i3.bv (by bv_omega) (by bv_omega), hi3val]
      refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
      · rw [hi4, beVal_take_succ _ _ (by scalar_tac), ← hval, hkey, hi2]
      · rw [hi4]
        have hlen' : octets.val.length = n.val := hlen
        have hi_lt : i.val < n.val := by scalar_tac
        have hl1 : (octets.val.take (i.val + 1)).length = i.val + 1 := by
          rw [List.length_take]; omega
        calc val1.val = beVal (octets.val.take (i.val + 1)) := by
              rw [beVal_take_succ _ _ (by scalar_tac), ← hval, hkey, hi2]
          _ < 256 ^ (octets.val.take (i.val + 1)).length := beVal_lt _
          _ = 256 ^ (i.val + 1) := by rw [hl1]
    · -- i ≥ n and i ≤ n ⇒ i = n: the loop is done, value is the full big-endian
      rename_i hge
      have hin : i.val = n.val := by scalar_tac
      simp only [WP.spec_ok]
      rw [hval, hin, List.take_of_length_le (by omega)]
  · -- hInv: the invariant holds initially at (0, 0)
    refine ⟨by scalar_tac, ?_, ?_⟩ <;> simp [beVal]

/-! ## Wiring the loop invariant through `decode_length`'s long-form tail

    The two theorems below consume `decode_length_loop_spec` (via `step with`) to
    prove the **two post-loop branches** of `decode_length` at *any* length: the
    canonical long-form **accept** (`val ≥ 0x80`) and the **post-loop `NonMinimal`**
    (`val < 0x80`, e.g. `[0x81, 0x01]`). Both reuse the pre-loop `step` scaffold of
    the reject family, then apply the loop invariant and branch on the decoded value.

    `ws` is the window of `n = b&0x7f` length octets following the initial octet
    (`(s.val.drop 1).take n`); the range-slice `input[1 .. 1+n]` the codec reads is
    exactly this window (Aeneas `List.slice 1 (1+n)`). -/

/-- **Long-form accept** (∀-length): a *canonical* long-form length — initial octet
    `b ∈ 0x81..0xFE` declaring `n = b&0x7f ∈ 1..4` octets, all present, leading octet
    non-zero, whose big-endian value `beVal ws ≥ 0x80` — decodes to *exactly*
    `Ok(beVal ws, 1+n)`. This threads `decode_length_loop_spec` through the tail:
    the returned value is the loop's big-endian fold, consuming `1+n` bytes. -/
theorem decode_long_form_accept (s : Slice U8) (b : U8) (ws : List U8)
    (hlo : 128 < b.val) (hhi : b.val < 255)
    -- `hpos` (≥ 1 length-octet) is *implied* by `hge` (a window with `beVal ≥ 0x80`
    -- is non-empty); it is kept explicit for uniformity with the reject family and to
    -- keep the proof's `scalar_tac` obligations bit-mask-free (see `decode_toolarge`).
    (hpos : 1 ≤ b.val &&& 127) (hn4 : b.val &&& 127 ≤ 4)
    (h : s.val[0]? = some b)
    (henough : 1 + (b.val &&& 127) ≤ s.val.length)
    (hws : ws = (s.val.drop 1).take (b.val &&& 127))
    (hnz : ws[0]? ≠ some 0#u8)
    (hge : 128 ≤ beVal ws) :
    length.decode_length s ⦃ r => ∃ v : U32, ∃ used : Usize,
      r = .Ok (v, used) ∧ v.val = beVal ws ∧ used.val = 1 + (b.val &&& 127) ⦄ := by
  unfold length.decode_length
  have e1 : ¬ (b.val < 128) := by omega
  have e2 : ¬ (b = 128#u8) := by scalar_tac
  have e3 : ¬ (b = 255#u8) := by scalar_tac
  simp only [first_spec, h]
  simp [e1, e2, e3]
  step as ⟨i, hi⟩        -- i  = b & 0x7f
  step as ⟨n, hn⟩        -- n  = i as usize
  step as ⟨i2, hi2⟩      -- i2 = 1 + n
  have hnt : ¬ (s.val.length < i2.val) := by scalar_tac
  simp [hnt]
  step as ⟨octets, hoct⟩ -- octets = input[1 .. i2]
  step as ⟨i3, hi3⟩      -- i3 = octets[0]
  -- octet window equals ws, of length n (all present via `henough`)
  have hlen_oct : octets.val.length = n.val := by rw [hoct]; scalar_tac
  have hocpos : 0 < octets.val.length := by scalar_tac
  have hoct_ws : octets.val = ws := by
    rw [hoct, hws]; have hb : i2.val = 1 + (b.val &&& 127) := by scalar_tac
    rw [hb]; simp [List.slice]
  -- leading octet non-zero ⇒ bypass the pre-loop leading-zero NonMinimal
  have hnz3 : i3 ≠ 0#u8 := by
    intro hc; apply hnz
    rw [← hoct_ws, List.getElem?_eq_getElem hocpos, ← hi3, hc]
  simp [hnz3]
  have hn4' : ¬ (n.val > 4) := by scalar_tac   -- bypass TooLarge
  simp [hn4']
  -- apply the loop invariant: val = big-endian value of the octets = beVal ws
  step with decode_length_loop_spec as ⟨val, hval⟩
  rw [hoct_ws] at hval
  have hnlt : ¬ (val.val < 128) := by scalar_tac   -- val = beVal ws ≥ 0x80
  rw [if_neg hnlt]
  step as ⟨i4, hi4⟩      -- i4 = 1 + n
  exact ⟨val, i4, rfl, hval, by scalar_tac⟩

/-- **Post-loop `NonMinimal`** (∀-length): a long-form length whose octets are all
    present with a non-zero leading octet, but whose big-endian value is `< 0x80` —
    a value that *must* use the short form (e.g. `[0x81, 0x01]`). Rejected `NonMinimal`
    *after* the value-decode loop. Completes `decode_length`'s post-loop tail. -/
theorem decode_long_form_nonminimal_value (s : Slice U8) (b : U8) (ws : List U8)
    (hlo : 128 < b.val) (hhi : b.val < 255)
    (hpos : 1 ≤ b.val &&& 127) (hn4 : b.val &&& 127 ≤ 4)
    (h : s.val[0]? = some b)
    (henough : 1 + (b.val &&& 127) ≤ s.val.length)
    (hws : ws = (s.val.drop 1).take (b.val &&& 127))
    (hnz : ws[0]? ≠ some 0#u8)
    (hlt : beVal ws < 128) :
    length.decode_length s ⦃ r => r = .Err length.LengthError.NonMinimal ⦄ := by
  unfold length.decode_length
  have e1 : ¬ (b.val < 128) := by omega
  have e2 : ¬ (b = 128#u8) := by scalar_tac
  have e3 : ¬ (b = 255#u8) := by scalar_tac
  simp only [first_spec, h]
  simp [e1, e2, e3]
  step as ⟨i, hi⟩
  step as ⟨n, hn⟩
  step as ⟨i2, hi2⟩
  have hnt : ¬ (s.val.length < i2.val) := by scalar_tac
  simp [hnt]
  step as ⟨octets, hoct⟩
  step as ⟨i3, hi3⟩
  have hlen_oct : octets.val.length = n.val := by rw [hoct]; scalar_tac
  have hocpos : 0 < octets.val.length := by scalar_tac
  have hoct_ws : octets.val = ws := by
    rw [hoct, hws]; have hb : i2.val = 1 + (b.val &&& 127) := by scalar_tac
    rw [hb]; simp [List.slice]
  have hnz3 : i3 ≠ 0#u8 := by
    intro hc; apply hnz
    rw [← hoct_ws, List.getElem?_eq_getElem hocpos, ← hi3, hc]
  simp [hnz3]
  have hn4' : ¬ (n.val > 4) := by scalar_tac
  simp [hn4']
  step with decode_length_loop_spec as ⟨val, hval⟩
  rw [hoct_ws] at hval
  have hvlt : val.val < 128 := by scalar_tac   -- val = beVal ws < 0x80
  rw [if_pos hvlt]
  simp only [WP.spec_ok]

/-! ## Encode-side loop invariants (toward round-trip canonicality `decode_accepts_only_canonical`)

    `encode_length` (long form) runs two loops: `loop0` scans off the leading zero bytes
    of `len.to_be_bytes()` (⇒ `lead`), and `loop1` copies the `n = 4-lead` significant
    bytes into the output. Their invariants below are the encode-side analogues of
    `decode_length_loop_spec`; composed (next) they give a functional spec of `encode_length`,
    the second half of round-trip canonicality. -/

/-- **loop0 = leading-zero scan.** From any `start` whose preceding octets are already
    known zero, `encode_length_loop0` returns the index `lead` of the first NON-zero octet
    of `be` (capped at 4): every octet before `lead` is zero, and if `lead < 4` then
    `be[lead] ≠ 0`. Instantiated at `start = 0` this characterises the leading-zero count. -/
theorem encode_length_loop0_spec (be : Array U8 4#usize) (start : Usize)
    (hstart : start.val ≤ 4)
    (hpre : ∀ j, j < start.val → be.val[j]! = 0#u8) :
    length.encode_length_loop0 be start ⦃ lead =>
      lead.val ≤ 4 ∧ (∀ j, j < lead.val → be.val[j]! = 0#u8) ∧
      (lead.val < 4 → be.val[lead.val]! ≠ 0#u8) ⦄ := by
  unfold length.encode_length_loop0
  apply loop.spec_decr_nat
    (measure := fun lead => 4 - lead.val)
    (inv := fun lead => lead.val ≤ 4 ∧ (∀ j, j < lead.val → be.val[j]! = 0#u8))
  · rintro lead ⟨hle, hz⟩
    simp only [length.encode_length_loop0.body]
    split
    · -- lead < 4: read be[lead]
      rename_i hlt
      have hltn : lead.val < 4 := by scalar_tac
      step as ⟨bi, hbi⟩
      have hbi! : be.val[lead.val]! = bi := by simp_lists [hbi]
      split
      · -- be[lead] = 0: continue at lead+1
        rename_i hbz
        step as ⟨lead1, hlead1⟩
        refine ⟨by scalar_tac, ?_, by scalar_tac⟩
        intro j hj
        rcases Nat.lt_or_ge j lead.val with h | h
        · exact hz j h
        · have hjeq : j = lead.val := by scalar_tac
          rw [hjeq, hbi!, hbz]
      · -- be[lead] ≠ 0: done
        rename_i hbnz
        exact ⟨hle, hz, fun _ => by rw [hbi!]; exact hbnz⟩
    · -- lead ≥ 4 (and ≤ 4 ⇒ = 4): done
      rename_i hge
      exact ⟨hle, hz, fun h4 => absurd h4 (by scalar_tac)⟩
  · exact ⟨hstart, hpre⟩

/-- **loop1 = copy the significant bytes.** From `(out, 0)`, copies `be[lead + k]` into
    `out[1 + k]` for each `k < n` (given `lead + n ≤ 4` so every read is in bounds),
    leaving octet 0 (and everything from `1+n` on) untouched. -/
theorem encode_length_loop1_spec (be : Array U8 4#usize) (lead n : Usize)
    (out : Array U8 5#usize) (hb : lead.val + n.val ≤ 4) :
    length.encode_length_loop1 out be lead n 0#usize ⦃ out' =>
      (∀ k, k < n.val → out'.val[1 + k]! = be.val[lead.val + k]!) ∧
      (∀ m, (1 + n.val ≤ m ∨ m = 0) → out'.val[m]! = out.val[m]!) ⦄ := by
  unfold length.encode_length_loop1
  apply loop.spec_decr_nat
    (measure := fun s => n.val - s.2.val)
    (inv := fun s =>
      s.2.val ≤ n.val ∧
      (∀ k, k < s.2.val → s.1.val[1 + k]! = be.val[lead.val + k]!) ∧
      (∀ m, (1 + s.2.val ≤ m ∨ m = 0) → s.1.val[m]! = out.val[m]!))
  · rintro ⟨cur, i⟩ ⟨hile, hcopy, hpres⟩
    simp only [length.encode_length_loop1.body]
    split
    · -- i < n: copy be[lead+i] into cur[1+i]
      rename_i hlt
      step as ⟨i1, hi1⟩       -- i1 = lead + i
      step as ⟨i2, hi2⟩       -- i2 = be[i1]
      step as ⟨i3, hi3⟩       -- i3 = 1 + i
      step as ⟨a, ha⟩         -- a  = cur.update i3 i2  (= cur.set i3 i2)
      step as ⟨i4, hi4⟩       -- i4 = i + 1
      refine ⟨by scalar_tac, ?_, ?_, by scalar_tac⟩
      · -- copied on [0, i+1)
        intro k hk
        rcases Nat.lt_or_ge k i.val with h | h
        · -- k < i: unchanged position, use hcopy
          have hne : i3.val ≠ 1 + k := by scalar_tac
          have hc := hcopy k h
          simp_lists [ha, hne] at hc ⊢
          exact hc
        · -- k = i: the just-written position
          have hki : k = i.val := by scalar_tac
          subst hki
          simp_lists [ha, hi1, hi2, hi3]
      · -- preserved: octet 0 and everything from 1+i4 on
        intro m hm
        have hne : i3.val ≠ m := by rcases hm with h | h <;> scalar_tac
        have hm' : 1 + i.val ≤ m ∨ m = 0 := by
          rcases hm with h | h
          · exact Or.inl (by scalar_tac)
          · exact Or.inr h
        have hp := hpres m hm'
        simp_lists [ha, hne] at hp ⊢
        exact hp
    · -- i ≥ n (and ≤ n ⇒ = n): done — the invariant's copied + preserved parts ARE the postcondition
      rename_i hge
      have hin : i.val = n.val := by scalar_tac
      refine ⟨fun k hk => ?_, fun m hm => ?_⟩
      · have hki : k < i.val := by omega
        exact hcopy k hki
      · refine hpres m ?_
        rcases hm with h | h
        · exact Or.inl (by omega)
        · exact Or.inr h
  · exact ⟨by scalar_tac, by simp, by intro m _; rfl⟩

/-! ## The minimal-big-endian bridge (`beVal` ↔ `BitVec.toBEBytes`)

    Round-trip canonicality needs to relate the decode-side big-endian fold `beVal` to the
    encode-side `len.to_be_bytes()`, whose Aeneas model is `BitVec.toBEBytes` (a bit-level
    little-endian peel, then reversed). The bridge (`to_be_bytes_significant`) states the DER
    minimality fact: a value's 4-byte big-endian form is its minimal `n`-byte form padded on
    the left with `4 - n` zero octets.

    It is proved from three self-contained facts: (A) the byte decomposition folds back to the
    value (`beVal_toBEBytes_mk`), (B) `beVal` is injective on equal-length lists (uniqueness,
    `beVal_inj`), and leading-zero invariance (`beVal_replicate_zero_append`). -/

/-- Little-endian value of a byte list — the structural companion used to fold `toLEBytes` back. -/
def leValB : List Byte → Nat
  | [] => 0
  | b :: rest => b.toNat + 256 * leValB rest

/-- The little-endian byte decomposition folds back to the original value (any width). -/
theorem leValB_toLEBytes {w : ℕ} (v : BitVec w) :
    leValB (BitVec.toLEBytes v) = v.toNat := by
  if h1 : w = 0 then
    subst h1
    simp only [BitVec.toLEBytes, gt_iff_lt, lt_self_iff_false, ↓reduceIte, leValB]
    have h := v.isLt
    simp only [pow_zero, Nat.lt_one_iff] at h
    omega
  else
    unfold BitVec.toLEBytes
    have hw : w > 0 := by omega
    simp only [gt_iff_lt, hw, ↓reduceIte, leValB]
    rw [leValB_toLEBytes ((v >>> 8).setWidth (w - 8))]
    rw [BitVec.toNat_setWidth, BitVec.toNat_setWidth, BitVec.toNat_ushiftRight]
    have hlt : v.toNat < 2 ^ w := v.isLt
    have hshift : v.toNat >>> 8 = v.toNat / 256 := by rw [Nat.shiftRight_eq_div_pow]
    have hpow : v.toNat >>> 8 < 2 ^ (w - 8) := by
      rw [hshift]
      rcases Nat.lt_or_ge w 8 with h | h
      · have hw80 : w - 8 = 0 := by omega
        rw [hw80, pow_zero]
        have h2 : (2 : Nat) ^ w ≤ 2 ^ 7 := Nat.pow_le_pow_right (by norm_num) (by omega)
        omega
      · rw [Nat.div_lt_iff_lt_mul (by norm_num : 0 < 256)]
        have heq : (2 : Nat) ^ (w - 8) * 256 = 2 ^ w := by
          rw [show (256 : Nat) = 2 ^ 8 from by norm_num, ← pow_add]; congr 1; omega
        omega
    rw [Nat.mod_eq_of_lt hpow, hshift]
    have h256 : (2 : Nat) ^ 8 = 256 := by norm_num
    rw [h256]; omega

/-- Big-endian value of a byte list (`Byte = BitVec 8`), matching `to_be_bytes` order. -/
def beValB : List Byte → Nat := List.foldl (fun acc b => acc * 256 + b.toNat) 0

theorem beValB_append_singleton (xs : List Byte) (b : Byte) :
    beValB (xs ++ [b]) = beValB xs * 256 + b.toNat := by
  simp only [beValB, List.foldl_append, List.foldl_cons, List.foldl_nil]

theorem beValB_reverse (l : List Byte) : beValB l.reverse = leValB l := by
  induction l with
  | nil => rfl
  | cons b l ih => rw [List.reverse_cons, beValB_append_singleton, ih]; simp only [leValB]; ring

/-- The 4-byte big-endian decomposition folds back to the value (the encode-side round-trip). -/
theorem beValB_toBEBytes {w} (v : BitVec w) : beValB (BitVec.toBEBytes v) = v.toNat := by
  unfold BitVec.toBEBytes; rw [beValB_reverse, leValB_toLEBytes]

/-- Bridge the `Byte`-level fold to the `List U8` `beVal` used in the decode proofs. -/
theorem beVal_map_mk (l : List Byte) :
    beVal (l.map (@UScalar.mk UScalarTy.U8)) = beValB l := by
  simp only [beVal, beValB, List.foldl_map]; rfl

/-- **Lemma A**: the `u32` big-endian bytes fold back to the value (`beVal ∘ to_be_bytes = id`). -/
theorem beVal_toBEBytes_mk (v : BitVec 32) :
    beVal ((BitVec.toBEBytes v).map (@UScalar.mk UScalarTy.U8)) = v.toNat := by
  rw [beVal_map_mk, beValB_toBEBytes]

theorem beVal_cons_zero (rest : List U8) : beVal (0#u8 :: rest) = beVal rest := by
  simp only [beVal, List.foldl_cons]; rfl

/-- Leading zero octets do not change the big-endian value. -/
theorem beVal_replicate_zero_append (m : Nat) (ws : List U8) :
    beVal (List.replicate m 0#u8 ++ ws) = beVal ws := by
  induction m with
  | zero => simp
  | succ k ih => rw [List.replicate_succ, List.cons_append, beVal_cons_zero, ih]

/-- LSB-first value, the structural companion for the uniqueness induction. -/
def leVal : List U8 → Nat
  | [] => 0
  | b :: rest => b.val + 256 * leVal rest

theorem beVal_append_singleton (xs : List U8) (x : U8) :
    beVal (xs ++ [x]) = beVal xs * 256 + x.val := by
  simp only [beVal, List.foldl_append, List.foldl_cons, List.foldl_nil]

theorem beVal_reverse (l : List U8) : beVal l.reverse = leVal l := by
  induction l with
  | nil => rfl
  | cons b l ih => rw [List.reverse_cons, beVal_append_singleton, ih]; simp only [leVal]; ring

theorem leVal_inj : ∀ (xs ys : List U8), leVal xs = leVal ys → xs.length = ys.length → xs = ys
  | [], [], _, _ => rfl
  | [], _ :: _, _, hl => by simp at hl
  | _ :: _, [], _, hl => by simp at hl
  | x :: xs, y :: ys, hv, hl => by
    simp only [leVal] at hv
    have hx : x.val < 256 := by scalar_tac
    have hy : y.val < 256 := by scalar_tac
    have hsplit : x.val = y.val ∧ leVal xs = leVal ys := by omega
    have hxy : x = y := UScalar.eq_of_val_eq hsplit.1
    have hlen : xs.length = ys.length := by simpa using hl
    rw [hxy, leVal_inj xs ys hsplit.2 hlen]

/-- **Lemma B**: big-endian value is injective on equal-length byte lists (uniqueness). -/
theorem beVal_inj (xs ys : List U8) (hv : beVal xs = beVal ys)
    (hl : xs.length = ys.length) : xs = ys := by
  have hxr : leVal xs.reverse = beVal xs := by rw [← beVal_reverse xs.reverse, List.reverse_reverse]
  have hyr : leVal ys.reverse = beVal ys := by rw [← beVal_reverse ys.reverse, List.reverse_reverse]
  have h1 : leVal xs.reverse = leVal ys.reverse := by rw [hxr, hyr]; exact hv
  have h2 : xs.reverse.length = ys.reverse.length := by simp [hl]
  have := leVal_inj xs.reverse ys.reverse h1 h2
  simpa using congrArg List.reverse this

/-- **The minimal-big-endian bridge.** If `ws` (length `n ≤ 4`) is a big-endian byte list whose
    value equals `v`, then `v.to_be_bytes()` is `ws` left-padded with `4 - n` zero octets — the
    DER minimality fact relating the decode `beVal` fold to Aeneas's `BitVec.toBEBytes`. -/
theorem to_be_bytes_significant (v : U32) (ws : List U8) (n : Nat)
    (hlen : ws.length = n) (hn : n ≤ 4) (hbe : beVal ws = v.val) :
    (BitVec.toBEBytes v.bv).map (@UScalar.mk UScalarTy.U8)
      = List.replicate (4 - n) 0#u8 ++ ws := by
  apply beVal_inj
  · rw [beVal_toBEBytes_mk, beVal_replicate_zero_append]; exact hbe.symm
  · have hL : ((BitVec.toBEBytes v.bv).map (@UScalar.mk UScalarTy.U8)).length = 4 := by simp
    rw [hL, List.length_append, List.length_replicate, hlen]; omega

/-! ## Encode functional spec (composing the two encode loops through the bridge)

    `encode_length_long_spec` composes `encode_length_loop0_spec` (leading-zero scan) and
    `encode_length_loop1_spec` (copy) with the surrounding code and the minimal-big-endian
    bridge, giving a functional spec of `encode_length` on the long form: a value `≥ 0x80`
    with minimal `n`-byte big-endian representation `ws` encodes to `[0x80|n] ++ ws`, using
    `1 + n` bytes. `encode_length_short_spec` handles the single-octet short form. -/

/-- Index into the left-padded big-endian form: the leading `4 - n` octets are zero. -/
theorem padded_be_zero (ws : List U8) (n : Nat) (j : Nat) (hj : j < 4 - n) :
    (List.replicate (4 - n) 0#u8 ++ ws)[j]! = 0#u8 := by simp_lists

/-- The first significant octet of the padded form is `ws[0]`. -/
theorem padded_be_first (ws : List U8) (n : Nat) :
    (List.replicate (4 - n) 0#u8 ++ ws)[4 - n]! = ws[0]! := by
  simp_lists [List.length_replicate, Nat.sub_self]

/-- The `k`-th significant octet of the padded form is `ws[k]`. -/
theorem padded_be_sig (ws : List U8) (n : Nat) (k : Nat) (hk : k < n) :
    (List.replicate (4 - n) 0#u8 ++ ws)[(4 - n) + k]! = ws[k]! := by
  simp_lists [List.length_replicate, Nat.add_sub_cancel_left]

/-- `0x80 ||| x = 0x80 + x` for `x < 0x80` (disjoint high bit) — pure `BitVec 8`. -/
theorem bv_or_0x80 (x : BitVec 8) (hx : x < 128#8) : (128#8 ||| x) = 128#8 + x := by bv_decide

theorem bv_add_0x80_toNat (x : BitVec 8) (hx : x < 128#8) :
    (128#8 + x).toNat = 128 + x.toNat := by bv_omega

/-- The long-form leading octet `0x80 ||| n` has value `128 + n` (for `n < 0x80`). -/
theorem or_0x80_val (i : U8) (hi : i.val < 128) : (128#u8 ||| i).val = 128 + i.val := by
  simp only [UScalar.val] at hi ⊢
  have hbv : i.bv < 128#8 := by bv_omega
  have hor : (128#u8 ||| i).bv = 128#8 + i.bv := by
    rw [UScalar.bv_or, show (128#u8).bv = (128#8 : BitVec 8) from rfl]; exact bv_or_0x80 i.bv hbv
  rw [hor]; exact bv_add_0x80_toNat i.bv hbv

/-- A U8 with the high bit set decomposes as `128 + (low 7 bits)`; used to match the decode
    initial octet `b` against the re-encoded `0x80 | n`. -/
theorem u8_high_bit_decomp (b : U8) (h : 128 ≤ b.val) : b.val = 128 + (b.val &&& 127) := by
  have hmod : b.val &&& 127 = b.val % 128 := by
    simp only [UScalar.val]
    rw [show (127 : ℕ) = (127#8).toNat from rfl, ← BitVec.toNat_and]
    have hbd : b.bv &&& 127#8 = b.bv % 128#8 := by bv_decide
    rw [hbd]; simp [BitVec.toNat_umod]
  rw [hmod]
  have hb : b.val < 256 := by scalar_tac
  omega

/-- **Encode functional spec (long form)**: for `len ≥ 0x80` with minimal big-endian
    representation `ws` (`|ws| = n ∈ 1..4`, leading octet non-zero, `beVal ws = len`),
    `encode_length len` writes `out[0] = 0x80 | n`, `out[1+k] = ws[k]`, and reports `1 + n`
    bytes. Composes `encode_length_loop0_spec` + `encode_length_loop1_spec` via the bridge
    (`to_be_bytes_significant` pins `lead = 4 - n`). -/
theorem encode_length_long_spec (len : U32) (ws : List U8) (n : Nat)
    (hge : 128 ≤ len.val) (hn1 : 1 ≤ n) (hn4 : n ≤ 4) (hlen : ws.length = n)
    (hnz : ws[0]! ≠ 0#u8) (hbe : beVal ws = len.val) :
    length.encode_length len ⦃ (out, used) =>
      used.val = 1 + n ∧ out.val[0]!.val = 128 + n ∧
      (∀ k, k < n → out.val[1 + k]! = ws[k]!) ⦄ := by
  unfold length.encode_length
  rw [if_neg (show ¬ (len < 128#u32) by scalar_tac)]
  step as ⟨be, hbev⟩
  have hbe4 : be.val = List.replicate (4 - n) 0#u8 ++ ws := by
    rw [hbev]; exact to_be_bytes_significant len ws n hlen hn4 hbe
  step with encode_length_loop0_spec as ⟨lead, hlead_le, hlead_z, hlead_nz⟩
  have hlead_eq : lead.val = 4 - n := by
    rcases lt_trichotomy lead.val (4 - n) with hlt | heq | hgt
    · exfalso
      have hz := hlead_nz (by omega)
      rw [hbe4] at hz
      exact hz (padded_be_zero ws n lead.val hlt)
    · exact heq
    · exfalso
      have hz := hlead_z (4 - n) hgt
      rw [hbe4, padded_be_first ws n] at hz
      exact hnz hz
  step as ⟨ne, hne⟩
  have hne_n : ne.val = n := by rw [hne, hlead_eq]; omega
  step as ⟨i, hi⟩
  step as ⟨i1, hi1⟩
  step as ⟨a, ha⟩
  step with encode_length_loop1_spec as ⟨out1, hout1_copy, hout1_pres⟩
  step as ⟨i2, hi2⟩
  have hi_val : i.val = n := by
    rw [hi, UScalar.cast_val_eq, hne_n]; simp only [UScalarTy.U8_numBits_eq]; omega
  refine ⟨by rw [hi2, hne_n], ?_, ?_⟩
  · have h0 : out1.val[0]! = i1 := by
      rw [hout1_pres 0 (Or.inr rfl), ha, Array.set_val_eq, Array.repeat_val]
      exact List.set_getElem!_eq _ _ _ _ ⟨by simp, by simp⟩
    rw [h0, hi1, or_0x80_val i (by rw [hi_val]; omega), hi_val]
  · intro k hk
    rw [hout1_copy k (by omega), hlead_eq, hbe4]
    exact padded_be_sig ws n k hk

/-- **Encode functional spec (short form)**: `len < 0x80` encodes to the single octet `len`. -/
theorem encode_length_short_spec (len : U32) (h : len.val < 128) :
    length.encode_length len ⦃ (out, used) =>
      used.val = 1 ∧ out.val[0]!.val = len.val ⦄ := by
  unfold length.encode_length
  rw [if_pos (show len < 128#u32 by scalar_tac)]
  step as ⟨i, hi⟩
  step as ⟨out1, ho⟩
  refine ⟨by scalar_tac, ?_⟩
  have h0 : out1.val[0]! = i := by
    rw [ho, Array.set_val_eq, Array.repeat_val]
    exact List.set_getElem!_eq _ _ _ _ ⟨by simp, by simp⟩
  rw [h0, hi, UScalar.cast_val_eq]; simp only [UScalarTy.U8_numBits_eq]; omega

/-! ## Round-trip canonicality

    The two lemmas below re-encode a *decoded* value and show the encoding reproduces exactly
    the consumed prefix of the input, byte for byte — the encode-inverts-decode direction, per
    accept branch. `decode_accepts_only_canonical` (the headline, matching the Kani harness)
    then walks `decode_length`'s full control flow: every reject branch discharges vacuously,
    and the two accept branches dispatch to `roundtrip_short` / `roundtrip_long`. -/

/-- **Long-form round-trip**: a canonically-decoded long-form value `v = beVal ws` re-encodes
    to a `1 + n`-byte field identical to `s[.. 1 + n]`. -/
theorem roundtrip_long (s : Slice U8) (b : U8) (v : U32) (ws : List U8) (n : Nat)
    (hn : n = b.val &&& 127)
    (hlo : 128 < b.val) (hhi : b.val < 255)
    (hn1 : 1 ≤ n) (hn4 : n ≤ 4)
    (h : s.val[0]? = some b)
    (henough : 1 + n ≤ s.val.length)
    (hws : ws = (s.val.drop 1).take n)
    (hnz : ws[0]! ≠ 0#u8)
    (hv : v.val = beVal ws) (hge : 128 ≤ v.val) :
    length.encode_length v ⦃ (re, relen) =>
      relen.val = 1 + n ∧ ∀ i, i < 1 + n → re.val[i]! = s.val[i]! ⦄ := by
  have hwslen : ws.length = n := by rw [hws, List.length_take, List.length_drop]; omega
  apply WP.exists_imp_spec
  obtain ⟨⟨out, used⟩, henc_eq, hused, hout0, houtk⟩ :=
    WP.spec_imp_exists (encode_length_long_spec v ws n hge hn1 hn4 hwslen hnz hv.symm)
  refine ⟨(out, used), henc_eq, hused, ?_⟩
  have hb0 : s.val[0]! = b := by rw [List.getElem!_eq_getElem?_getD, h]; rfl
  intro i hi
  rcases i with _ | k
  · rw [hb0]; apply UScalar.eq_of_val_eq
    rw [hout0, hn]; exact (u8_high_bit_decomp b (by omega)).symm
  · have hk : k < n := by omega
    rw [Nat.add_comm k 1, houtk k hk, hws,
        List.getElem!_take_of_lt n k (s.val.drop 1) hk, List.getElem!_drop]

/-- **Short-form round-trip**: a short-form decoded value re-encodes to the single octet `b`. -/
theorem roundtrip_short (s : Slice U8) (b : U8) (v : U32)
    (hb : b.val < 128) (h : s.val[0]? = some b) (hv : v.val = b.val) :
    length.encode_length v ⦃ (re, relen) =>
      relen.val = 1 ∧ ∀ i, i < 1 → re.val[i]! = s.val[i]! ⦄ := by
  apply WP.exists_imp_spec
  obtain ⟨⟨out, used⟩, henc_eq, hused, hout0⟩ :=
    WP.spec_imp_exists (encode_length_short_spec v (by omega))
  refine ⟨(out, used), henc_eq, hused, ?_⟩
  intro i hi
  have hi0 : i = 0 := by omega
  subst hi0
  have hb0 : s.val[0]! = b := by rw [List.getElem!_eq_getElem?_getD, h]; rfl
  rw [hb0]; apply UScalar.eq_of_val_eq
  rw [hout0]; exact hv

/-- **Round-trip canonicality** (`decode_accepts_only_canonical`, ∀-length): whenever
    `decode_length s` *accepts* — returns `Ok (v, used)` — re-encoding `v` reproduces exactly
    the `used` consumed bytes of `s`. This is the ∀-length lift of the headline Kani harness
    (`re[..relen] == buf[..used]`, here as the equivalent byte-wise equality on `[0, used)`);
    it rules out the non-canonical-length parser differentials that plague X.509 stacks, for a
    slice of *any* length. Proved by walking every branch of `decode_length`: reject branches
    are vacuous (`.Err ≠ .Ok`), the two accept branches dispatch to the round-trip lemmas. -/
theorem decode_accepts_only_canonical (s : Slice U8) :
    length.decode_length s ⦃ r => ∀ (v : U32) (used : Usize), r = .Ok (v, used) →
        length.encode_length v ⦃ (re, relen) =>
          relen.val = used.val ∧ ∀ i, i < used.val → re.val[i]! = s.val[i]! ⦄ ⦄ := by
  unfold length.decode_length
  simp only [first_spec]
  obtain hb | ⟨b, hb⟩ : s.val[0]? = none ∨ ∃ b, s.val[0]? = some b := by
    cases s.val[0]? <;> simp
  · -- empty ⇒ Truncated: vacuous
    simp only [hb, bind_tc_ok, WP.spec_ok]
    intro v used heq; simp at heq
  · simp only [hb, bind_tc_ok]
    by_cases hlt : b.val < 128
    · -- short-form accept
      rw [if_pos (show b < 128#u8 by scalar_tac)]
      step as ⟨i, hi⟩
      intro v used heq
      obtain ⟨rfl, rfl⟩ : i = v ∧ 1#usize = used := by
        simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at heq; exact heq
      have hv : i.val = b.val := by rw [hi]; exact U8.cast_U32_val_eq b
      have := roundtrip_short s b i hlt hb hv
      convert this using 3 <;> simp
    · rw [if_neg (show ¬ (b < 128#u8) by scalar_tac)]
      by_cases h128 : b = 128#u8
      · rw [if_pos h128]; simp only [WP.spec_ok]; intro v used heq; simp at heq
      · rw [if_neg h128]
        by_cases h255 : b = 255#u8
        · rw [if_pos h255]; simp only [WP.spec_ok]; intro v used heq; simp at heq
        · rw [if_neg h255]
          step as ⟨i, hi⟩
          step as ⟨nn, hnn⟩
          step as ⟨i2, hi2⟩
          have hbrange : 128 < b.val ∧ b.val < 255 := by scalar_tac
          have hnnval : nn.val = b.val &&& 127 := by scalar_tac
          have hnn1 : 1 ≤ nn.val := by
            rw [hnnval]; have hd := u8_high_bit_decomp b (by omega); omega
          by_cases htrunc : s.len < i2
          · rw [if_pos htrunc]
            simp only [WP.spec_ok]; intro v used heq; simp at heq
          · rw [if_neg htrunc]
            have henough : 1 + nn.val ≤ s.val.length := by scalar_tac
            step as ⟨octets, hoct⟩
            step as ⟨i3, hi3⟩
            have hlen_oct : octets.val.length = nn.val := by rw [hoct]; scalar_tac
            have hocpos : 0 < octets.val.length := by omega
            set ws := (s.val.drop 1).take nn.val with hwsdef
            have hoct_ws : octets.val = ws := by
              rw [hoct, hwsdef]
              have hb2 : i2.val = 1 + nn.val := by scalar_tac
              rw [hb2]; simp [List.slice]
            by_cases hz : i3 = 0#u8
            · rw [if_pos hz]; simp only [WP.spec_ok]; intro v used heq; simp at heq
            · rw [if_neg hz]
              have hnz : ws[0]! ≠ 0#u8 := by
                rw [← hoct_ws, List.getElem!_eq_getElem?_getD,
                    List.getElem?_eq_getElem hocpos, ← hi3]
                simpa using hz
              by_cases hn4 : nn.val > 4
              · rw [if_pos (show nn > 4#usize by scalar_tac)]
                simp only [WP.spec_ok]; intro v used heq; simp at heq
              · rw [if_neg (show ¬ (nn > 4#usize) by scalar_tac)]
                step with decode_length_loop_spec as ⟨val, hval⟩
                rw [hoct_ws] at hval
                by_cases hvlt : val.val < 128
                · rw [if_pos (show val < 128#u32 by scalar_tac)]
                  simp only [WP.spec_ok]; intro v used heq; simp at heq
                · rw [if_neg (show ¬ (val < 128#u32) by scalar_tac)]
                  step as ⟨i4, hi4⟩
                  intro v used heq
                  obtain ⟨rfl, rfl⟩ : val = v ∧ i4 = used := by
                    simp only [core.result.Result.Ok.injEq, Prod.mk.injEq] at heq; exact heq
                  have hwslen : ws.length = nn.val := by
                    rw [hwsdef, List.length_take, List.length_drop]; omega
                  have := roundtrip_long s b val ws nn.val hnnval hbrange.1 hbrange.2
                    hnn1 (by omega) hb (by omega) hwsdef hnz hval (by omega)
                  convert this using 3 <;> simp [hi4, hnnval]

#print axioms decode_indefinite
#print axioms decode_short_form
#print axioms decode_truncated_long
#print axioms decode_nonminimal_leading_zero
#print axioms decode_toolarge
#print axioms decode_length_loop_spec
#print axioms decode_long_form_accept
#print axioms decode_long_form_nonminimal_value
#print axioms encode_length_loop0_spec
#print axioms encode_length_loop1_spec
#print axioms to_be_bytes_significant
#print axioms encode_length_long_spec
#print axioms encode_length_short_spec
#print axioms roundtrip_long
#print axioms roundtrip_short
#print axioms decode_accepts_only_canonical

end DerVerified.Length
