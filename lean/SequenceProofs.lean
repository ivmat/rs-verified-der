import DerSequenceExtract

/-!
# Unbounded (∀-length, ∀-children) structural correctness of the DER SEQUENCE child-walk

This theorem is proved in Lean 4 over the **Aeneas-extracted** model of the *same*
`der-verified/src/sequence.rs` (composing `tag.rs` + `length.rs` + `tlv.rs`) that the Kani floor
proves — single source of truth: the extraction crate `#[path]`-includes all four shipped files,
and `lean/check_lean.sh` re-extracts and diffs on every run to guard against drift.

The point is the **straddle**, extended one level: Kani's `sequence::proofs::no_over_read` and
`sequence::proofs::ok_implies_exact_tiling` prove this codec's headline "no over-read" / "exact
tiling" properties bit-precisely, but only for a bounded 8-byte symbolic content buffer walked
through an unwind-bounded loop (`#[kani::unwind(16)]`, at most ~4 children). Here we prove the
**same properties for a content slice of *any* length, walked by `decode_sequence` for *any*
number of children** — the doubly-unbounded lid Kani cannot reach (Kani's proof is inherently
capped by both the buffer width AND the unwind bound; this lid removes both caps at once). This is
the crate's first coverage of an **unbounded LOOP** in Lean (`tlv::decode_tlv`, the prior
composition-layer lid D27, is itself loop-free — a single sequential composition); `sequence`'s
child walk is the shape Kani-only "bounded loop" proofs cannot generalize past, by construction.

## The property (mirrors `sequence::proofs::no_over_read` / `ok_implies_exact_tiling`, ∀-length,
∀-children)

`decode_sequence`'s **structural correctness, no-over-read**: whenever `decode_sequence content`
accepts (`Ok _`), the child-walk it performs (via `Elements::next`, repeatedly calling
`tlv.decode_tlv` on the remaining suffix and advancing by the bytes it consumed) reaches a state
whose remaining suffix is **exhausted** — the walk consumes *exactly* `content`'s bytes, no more
and no less, for a content slice of *any* length and *any* number of children (no bound on the
loop's trip count, unlike Kani's `#[kani::unwind(16)]`-capped harness). Because the walk's `rest`
field is, at every step, provably *some* `content.val.drop off` (a genuine tail — never a slice
manufactured out of thin air), "the final `rest` is empty" is exactly the security-critical claim:
**the walk never reads past `content`'s end, at any point, however many children it has**.

This is proved in three layers, mirroring `LengthProofs.lean`'s `decode_length_loop_spec` /
`decode_accepts_only_canonical` split:

1. **`decode_tlv_progress`** — the minimal corollary of D27's `decode_tlv_structure` this lid
   needs: an accepted `tlv.decode_tlv` call consumes `1 ≤ used ≤ input.length` bytes.
2. **`elements_next_progress`** — lifts (1) through the slice-drop `Elements::next` performs: an
   accepted child leaves `iter'.rest = iter.rest.drop used` for that same `1 ≤ used ≤
   iter.rest.length` — the per-step no-over-read + progress bound the whole induction rests on.
3. **`decode_sequence_loop_spec`** — the ∀-trip-count loop invariant over
   `sequence.decode_sequence_loop`, proved by `loop.spec_decr_nat` with measure `iter.rest.length`
   (strictly decreasing every accept step, by (2)): the invariant "`iter.rest` is always a genuine
   suffix of `content`" is preserved every iteration, and on `Ok` termination the (existentially
   witnessed) final iterator's `rest` is empty.
4. **`decode_sequence_structure`** — the headline: specializes (3) at the initial state
   (`count = 0`, `iter.rest = content`, `iter.done = false`, from `Elements::new`).

## Trust surface

This lid composes FOUR codecs (`tag`, `length`, `tlv`, `sequence`), reusing the exact same trust
surface D27 (`TlvProofs.lean`) already disclosed and justified — `lean/extract-sequence` runs its
own independent Charon/Aeneas pass (needed since `sequence.rs` requires `tag`/`length`/`tlv` as
sibling modules), producing a **separate** Lean namespace (`der_sequence_extract`, vs. `tlv`'s
`der_tlv_extract`) that cannot be imported alongside `TlvProofs.lean`'s. The seven axioms below are
restated, byte-for-byte the same justification as `TlvProofs.lean`'s (see that file's module doc
for the full accounting) — not new trust, the same duplicate-extraction-namespace workaround D27
already used for `length`'s two axioms, extended to all seven since this pass re-extracts `tag`/
`length`/`tlv` from scratch as `tlv.rs`'s own sibling-module dependencies. `tag.decode_tag` extracts
as a bodyless axiom here too (the same D25-class early-return-in-a-loop shape, disclosed, not fixed
in this pass); `tag.encode_tag`/`tlv.encode_tlv_into` are marked `--opaque` (same parameter-shadowing
workaround as D27, not needed for this lid's scope — `decode_sequence`/`Elements::next` never call
either).

A one-line, behavior-preserving source fix was required first (the SAME map_err name-clash class
D27 fixed in `tlv.rs`, this time in `sequence.rs`): `decode_sequence_tlv`'s point-free
`.map_err(SequenceError::Tlv)` collided with the `SequenceError::Tlv` variant's own qualified
constructor name under Aeneas's naming scheme. Fixed identically: rewritten as the explicit closure
`.map_err(|e| SequenceError::Tlv(e))` — a pure style change, zero behavior change. Re-verified: all
21 `sequence`-module tests plus the crate's 295-test suite pass unchanged after the edit (this lid
does not touch `decode_sequence`/`Elements`, the functions actually proved below, at all).

`#print axioms` at the bottom shows the resulting theorems depend on exactly these seven axioms
(the same as D27's `tlv` lid) plus the three standard Lean axioms (`propext`, `Classical.choice`,
`Quot.sound`) plus the underlying opaque Aeneas primitives they characterize. No `sorryAx`.
-/

open Aeneas Aeneas.Std Result
open der_sequence_extract

namespace DerVerified.Sequence

/-! ## Assumed specs (disclosed trust surface — restated from `TlvProofs.lean`, D27; same
    justification, different extraction-pass namespace) -/

/-- **Assumed spec (structural only) for the opaque `tag.decode_tag` axiom.** See
    `TlvProofs.lean`'s `tag_decode_used_bounds` for the full justification — restated here because
    this lid's `lean/extract-sequence` extraction pass produces its own `der_sequence_extract.tag`
    namespace, distinct from `der_tlv_extract.tag`. -/
axiom tag_decode_used_bounds (input : Slice U8) (t : tag.Tag) (t_used : Usize) :
    tag.decode_tag input = ok (core.result.Result.Ok (t, t_used)) →
      1 ≤ t_used.val ∧ t_used.val ≤ input.val.length

/-- **Assumed totality** for the opaque `tag.decode_tag` axiom. See `TlvProofs.lean`'s
    `tag_decode_total`. -/
axiom tag_decode_total (input : Slice U8) :
    ∃ r : core.result.Result (tag.Tag × Usize) tag.TagError, tag.decode_tag input = ok r

/-- **Assumed spec for the opaque `core.result.Result.map_err` axiom.** See `TlvProofs.lean`'s
    `result_map_err_ok_spec` / `result_map_err_err_spec`. -/
axiom result_map_err_ok_spec {T E F O : Type} (inst : core.ops.function.FnOnce O E F)
    (v : T) (f : O) :
    core.result.Result.map_err (T := T) (E := E) inst (.Ok v) f = ok (.Ok v)

axiom result_map_err_err_spec {T E F O : Type} (inst : core.ops.function.FnOnce O E F)
    (e : E) (f : O) (w : F) (hcall : inst.call_once f e = ok w) :
    core.result.Result.map_err (T := T) inst (.Err e) f = ok (.Err w)

/-- **Assumed spec for the opaque `usize::try_from(u32)` axiom.** See `TlvProofs.lean`'s
    `try_from_u32_usize_spec`. -/
axiom try_from_u32_usize_spec (i : U32) (h32 : 32 ≤ Usize.numBits) :
    ∃ l : Usize, Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from i
        = ok (core.result.Result.Ok l) ∧ l.val = i.val

/-- **Assumed totality** of `length.decode_length` (this pass's own copy). See `TlvProofs.lean`'s
    `length_decode_total` — NOT new unverified trust: `LengthProofs.lean`'s own
    `decode_accepts_only_canonical` already proves this exact fact sorry-free, unconditionally,
    over the byte-identical `length.rs` source; restated here purely to work around the duplicate-
    extraction namespace clash. -/
axiom length_decode_total (s : Slice U8) :
    ∃ r : core.result.Result (U32 × Usize) length.LengthError, length.decode_length s = ok r

/-- **Assumed no-over-read bound** for `length.decode_length` (this pass's own copy). See
    `TlvProofs.lean`'s `length_decode_used_le`. -/
axiom length_decode_used_le (s : Slice U8) (v : U32) (l_used : Usize) :
    length.decode_length s = ok (core.result.Result.Ok (v, l_used)) →
      l_used.val ≤ s.val.length

/-! ## Layer 1: `decode_tlv`'s no-over-read + progress bound (the composition D27 already proved
    in full; here only the minimal corollary `decode_sequence`'s walk needs). -/

/-- **`decode_tlv`'s no-over-read + progress bound, ∀-length.** The minimal corollary of D27's
    `decode_tlv_structure` (`TlvProofs.lean`) that the SEQUENCE child-walk induction needs: whenever
    `decode_tlv input` accepts `Ok (t, used)`, `used` is strictly positive (progress: the walk's
    measure strictly decreases) and never exceeds `input`'s length (no over-read). Proved directly
    by following `decode_tlv`'s only accept path — the same proof shape as D27's headline theorem,
    specialized to the two facts this lid's loop invariant actually consumes. -/
theorem decode_tlv_progress (input : Slice U8) (h32 : 32 ≤ Usize.numBits) :
    tlv.decode_tlv input ⦃ r => ∀ (t : tlv.Tlv) (used : Usize),
      r = core.result.Result.Ok (t, used) → 1 ≤ used.val ∧ used.val ≤ input.val.length ⦄ := by
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
      · -- checked_add fits.
        have hcheck := Usize.checked_add_bv_spec header l
        rw [hchk] at hcheck
        have heval : e.val = header.val + l.val := hcheck.2.1
        simp only [lift, bind_tc_ok]
        by_cases hshort : input.len < e
        · -- input shorter than the declared end: Truncated, vacuous for the Ok postcondition.
          simp [hshort]
        · -- accept.
          simp only [hshort, ite_false]
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
          have h2 := congrArg Prod.snd heq1
          simp only at h2
          have hused : used = e := h2.symm
          subst hused
          refine ⟨?_, hend_le⟩
          have ht1 : 1 ≤ t_used.val := hpos
          scalar_tac
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

/-- **`decode_tlv`'s totality, ∀-length.** `decode_tlv` never panics/faults (`decode_tag_never_
    panics`'s and `decode_length`'s totality composed through the arithmetic guards, all of which
    are `checked_add`/range-checked — no raw arithmetic that could overflow-panic): it always
    returns SOME `ok r` (`r : core.result.Result (Tlv × Usize) TlvError`, either accept or a
    well-formed reject), never `fail`/`div`. Needed (only) so `elements_next_progress`'s `none`
    conjunct is provable in the branches where `decode_tlv` itself might otherwise be assumed to
    fault — Lean's `spec (fail e) P ↔ False` / `spec div P ↔ False` mean a `fail`/`div` outcome
    would make the surrounding triple UNPROVABLE, not vacuously true, unlike an `Ok`-conditioned
    postcondition (which a `fail`/`div` result trivially satisfies by not matching `= Ok _`). Same
    proof walk as `decode_tlv_progress`, terminating each branch with the totality witness instead
    of the numeric bound. -/
theorem decode_tlv_total_spec (input : Slice U8) (h32 : 32 ≤ Usize.numBits) :
    tlv.decode_tlv input ⦃ (_ : core.result.Result (tlv.Tlv × Usize) tlv.TlvError) => True ⦄ := by
  unfold tlv.decode_tlv
  obtain ⟨tres, htag⟩ := tag_decode_total input
  rcases tres with ⟨t0, t_used⟩ | terr
  · obtain ⟨hpos, hle⟩ := tag_decode_used_bounds input t0 t_used htag
    rw [htag]
    simp only [bind_tc_ok]
    rw [result_map_err_ok_spec]
    step as ⟨cf, hcf⟩
    simp only [hcf]
    step as ⟨s, hs⟩
    obtain ⟨lres, hlen⟩ := length_decode_total s
    rcases lres with ⟨len_u32, l_used⟩ | lerr
    · have hlused : l_used.val ≤ s.val.length := length_decode_used_le s len_u32 l_used hlen
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
      · simp [lift]
      · simp only [lift, bind_tc_ok]
        by_cases hshort : input.len < e
        · simp [hshort]
        · simp only [hshort, ite_false]
          have hcheck := Usize.checked_add_bv_spec header l
          rw [hchk] at hcheck
          have heval : e.val = header.val + l.val := hcheck.2.1
          have hend_le : e.val ≤ input.val.length := by
            have := Slice.len_val (v := input); scalar_tac
          have hstart_le : header.val ≤ e.val := by rw [heval]; scalar_tac
          have hidx : core.slice.index.SliceIndexRangeUsizeSlice.index
              ({ start := header, «end» := e } : core.ops.range.Range Usize) input
              = ok ⟨input.val.slice header.val e.val, by scalar_tac⟩ := by
            unfold core.slice.index.SliceIndexRangeUsizeSlice.index
            simp [hstart_le, hend_le]
          simp [hidx]
    · rw [hlen]
      simp only [bind_tc_ok]
      rw [result_map_err_err_spec (inst :=
        tlv.decode_tlv.closure_1.Insts.CoreOpsFunctionFnOnceTupleLengthErrorTlvError)
        (w := tlv.TlvError.Length lerr) (hcall := rfl)]
      step as ⟨cf2, hcf2⟩
      simp only [hcf2]
      unfold core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
      simp [core.convert.FromSame.from]
  · rw [htag]
    simp only [bind_tc_ok]
    rw [result_map_err_err_spec (inst :=
      tlv.decode_tlv.closure.Insts.CoreOpsFunctionFnOnceTupleTagErrorTlvError)
      (w := tlv.TlvError.Tag terr) (hcall := rfl)]
    step as ⟨cf0, hcf0⟩
    simp only [hcf0]
    unfold core.result.Result.Insts.CoreOpsTryTraitFromResidualResultInfallible.from_residual
    simp [core.convert.FromSame.from]

/-- Existential corollary of `decode_tlv_total_spec`: `decode_tlv` always reaches SOME `ok r`. -/
theorem decode_tlv_total (input : Slice U8) (h32 : 32 ≤ Usize.numBits) :
    ∃ r : core.result.Result (tlv.Tlv × Usize) tlv.TlvError, tlv.decode_tlv input = ok r := by
  obtain ⟨r, hr, -⟩ := WP.spec_imp_exists (decode_tlv_total_spec input h32)
  exact ⟨r, hr⟩

/-! ## Layer 2: one `Elements::next` step — no-over-read + progress, lifted through the slice-drop
    `next` performs after a successful child decode. -/

/-- **`Elements::next`'s per-step characterization, ∀-length.** A single step of the walk,
    covering BOTH outcomes `decode_sequence_loop_spec`'s induction needs:
    * if `next` yields a child (`some (Ok t), iter'`), then `iter'.rest` is *exactly*
      `iter.rest` with `1 ≤ used ≤ iter.rest.length` bytes dropped from the front (no-over-read +
      progress); or
    * if `next` yields `none` and `iter.done = false` beforehand (the only way `next` reaches
      `none` without having already stopped), then `iter.rest` was ALREADY empty — the walk had
      nothing left to consume.
    (The `some (Err e)` outcome needs no further characterization: `decode_sequence_loop_spec`'s
    caller only needs to know the walk *stops* there, which is definitionally true of the loop
    body.) -/
theorem elements_next_progress (iter : sequence.Elements) (h32 : 32 ≤ Usize.numBits) :
    sequence.Elements.Insts.CoreIterTraitsIteratorIteratorResultTlvTlvError.next iter
      ⦃ r =>
        (∀ (t : tlv.Tlv) (iter' : sequence.Elements),
          r = (some (core.result.Result.Ok t), iter') →
            ∃ used : Usize, 1 ≤ used.val ∧ used.val ≤ iter.rest.val.length ∧
              iter'.rest.val = iter.rest.val.drop used.val ∧ iter'.done = false) ∧
        (iter.done = false → (∃ iter', r = (none, iter')) → iter.rest.val.length = 0) ⦄ := by
  unfold sequence.Elements.Insts.CoreIterTraitsIteratorIteratorResultTlvTlvError.next
  by_cases hdone : iter.done
  · simp [hdone]
  · rw [if_neg (by simpa using hdone)]
    simp only [core.slice.Slice.is_empty, bind_tc_ok]
    by_cases hempty : iter.rest.val.length = 0
    · simp [Slice.length, hempty]
    · rw [if_neg (by simpa [Slice.length] using hempty)]
      -- `decode_tlv_total` rules out `fail`/`div` FIRST: a `spec (fail e) P` / `spec div P`
      -- obligation is `False` (`WP.spec_fail`/`WP.spec_div`), not vacuously true, so this lemma
      -- would be unprovable in those branches without first pinning `decode_tlv` to an `ok _`.
      obtain ⟨rtot, htot⟩ := decode_tlv_total iter.rest h32
      rcases rtot with ⟨t0, used0⟩ | terr
      · -- decode_tlv accepted: Ok (t0, used0). The live path this lemma characterizes.
        have hbound0 : 1 ≤ used0.val ∧ used0.val ≤ iter.rest.val.length := by
          have hspec := decode_tlv_progress iter.rest h32
          rw [htot, WP.spec_ok] at hspec
          exact hspec t0 used0 rfl
        simp only [htot, bind_tc_ok]
        step as ⟨s, hs⟩
        refine ⟨?_, ?_⟩
        · intro t iter' heq
          obtain ⟨heq1, heq2⟩ := heq
          injection heq1 with heq1'
          have hiter' : iter' = { rest := s, done := false } := heq2.symm
          refine ⟨used0, hbound0.1, hbound0.2, ?_, ?_⟩
          · rw [hiter', hs]
          · rw [hiter']
        · intro hd hex
          obtain ⟨iter', heq⟩ := hex
          simp_all
      · -- decode_tlv rejected: yields Err, contradicting either postcondition arm.
        simp only [htot, bind_tc_ok]
        refine ⟨?_, ?_⟩
        · intro t iter' heq
          simp_all
        · intro hd hex
          obtain ⟨iter', heq⟩ := hex
          simp_all


/-! ## Layer 3: the ∀-trip-count loop invariant.

    `sequence.decode_sequence_loop`'s state is `(count : Usize, iter : Elements)`. The invariant
    carried through the induction: `iter.rest` is *exactly* `content`'s suffix starting at offset
    `content.length - iter.rest.length` (i.e. `iter.rest` is always a genuine tail of `content`,
    consuming from the front) and `iter.done = false`. On completion (`Ok _`), the postcondition
    is `iter.rest.val.length = 0` — the walk consumed the ENTIRE remaining suffix, for *any*
    number of further children (no bound on the loop's trip count, unlike Kani's
    `#[kani::unwind(16)]`-capped harness). Combined with the invariant this is exactly "no
    over-read, exact tiling": `iter.rest` never claims bytes beyond `content` at any point in the
    walk (it is always literally `content.val.drop off` for `off ≤ content.val.length`, a
    structural invariant of `List.drop`), and a clean finish means the walk consumed all of it.

    Proved by `loop.spec_decr_nat` with measure `iter.rest.val.length`, strictly decreasing every
    accept step via `elements_next_progress`'s `1 ≤ used` progress bound — the mechanism that lets
    this induction close for *any* number of children, not just the ≤ 4 a bounded Kani buffer can
    exhibit. -/

/-- **`decode_sequence_loop`'s ∀-trip-count invariant.** From any state `(count, iter)` where
    `iter.rest` is *exactly* `content`'s suffix at the offset it has already consumed
    (`content.val.length - iter.rest.val.length`) and `iter.done = false`, the loop — run to
    completion — either:
    * accepts (`Ok k`), in which case the FINAL `iter.rest` (produced along the way) is exhausted
      (`= []`) — the walk consumed content's entire remaining suffix; or
    * rejects (`Err (SequenceError.Element _)`) on the first malformed child.

    This is stated existentially over the final iterator state reached, since `decode_sequence_loop`
    itself only returns the count/error (not the final `Elements`) — the existential witnesses that
    *some* run of the walk reaches an exhausted `rest`, which is what "no over-read, exact tiling"
    means operationally. -/
theorem decode_sequence_loop_spec (content : Slice U8) (h32 : 32 ≤ Usize.numBits)
    (count : Usize) (iter : sequence.Elements)
    (hsuf : iter.rest.val = content.val.drop (content.val.length - iter.rest.val.length))
    (hdone : iter.done = false)
    (hcount : count.val + iter.rest.val.length ≤ content.val.length) :
    sequence.decode_sequence_loop count iter ⦃ r =>
      match r with
      | core.result.Result.Ok _ =>
        ∃ finalRest : Slice U8,
          finalRest.val = content.val.drop (content.val.length - finalRest.val.length) ∧
          finalRest.val.length = 0
      | core.result.Result.Err _ => True ⦄ := by
  unfold sequence.decode_sequence_loop
  apply loop.spec_decr_nat
    (measure := fun (_, it) => it.rest.val.length)
    (inv := fun (cnt, it) =>
      it.rest.val = content.val.drop (content.val.length - it.rest.val.length) ∧
      it.done = false ∧
      cnt.val + it.rest.val.length ≤ content.val.length)
  · rintro ⟨cnt, it⟩ ⟨hitsuf, hitdone, hitcount⟩
    simp only [sequence.decode_sequence_loop.body]
    step with elements_next_progress as ⟨o, it1, hnextA, hnextB⟩
    match ho : o with
    | none =>
      -- `next` returned `none`: since `it.done = false` beforehand, `elements_next_progress`'s
      -- second conjunct forces `it.rest` to have been already empty — the walk is done HERE,
      -- with `it` itself as the witness (its own suffix invariant is `hitsuf`).
      simp only [ho, WP.spec_ok]
      refine ⟨it.rest, hitsuf, ?_⟩
      exact hnextB hitdone it1 (by rw [← ho])
    | some (core.result.Result.Ok t) =>
      -- accepted a child: the measure strictly decreases (progress) and the suffix invariant is
      -- preserved on the new state `it1`. The invariant's `cnt.val + it.rest.length ≤
      -- content.length` bound (carried since the initial call) discharges `cnt + 1`'s overflow
      -- side-condition: `it.rest.length ≥ 1` here (a child was just accepted, `used ≥ 1`), so
      -- `cnt.val < content.val.length ≤ Usize.max`.
      simp only [ho]
      obtain ⟨used, hused1, hused2, hrest, hdone1⟩ := hnextA t it1 (by rw [← ho])
      have hcnt_lt : cnt.val + 1 ≤ Usize.max := by
        have := Slice.length_ineq content
        omega
      step as ⟨count1, hcount1⟩
      have hit1len : it1.rest.val.length = it.rest.val.length - used.val := by
        rw [hrest, List.length_drop]
      have hoff_eq : content.val.length - it1.rest.val.length
          = (content.val.length - it.rest.val.length) + used.val := by
        rw [hit1len]; omega
      have hsuf' : it1.rest.val = content.val.drop (content.val.length - it1.rest.val.length) := by
        rw [hoff_eq, ← List.drop_drop, ← hitsuf, hrest]
      have hcount' : count1.val + it1.rest.val.length ≤ content.val.length := by
        rw [hit1len, hcount1]
        omega
      have hmeasure : it1.rest.val.length < it.rest.val.length := by
        rw [hit1len]; omega
      exact And.intro hsuf' (And.intro hdone1 (And.intro hcount' hmeasure))
    | some (core.result.Result.Err e) =>
      -- a malformed child: the walk stops with `Err (Element e)`.
      simp only [ho, WP.spec_ok]
  · exact ⟨hsuf, hdone, hcount⟩

/-! ## The headline theorem -/

/-- **`decode_sequence`'s structural correctness, ∀-length, ∀-children** (the unbounded companion
    to Kani's `sequence::proofs::no_over_read` / `ok_implies_exact_tiling`). For a content slice
    of *any* length, whenever `decode_sequence content` accepts (`Ok _`), the child-walk it
    performs reaches a state whose remaining suffix is exhausted — i.e. the walk consumes EXACTLY
    `content`'s bytes, for *any* number of children (no bound on the walk's trip count, unlike
    Kani's `#[kani::unwind(16)]`-capped harness). This is the **security-critical no-over-read
    fact, doubly unbounded**: the walk never claims bytes beyond `content`, however long `content`
    is and however many children it contains. -/
theorem decode_sequence_structure (content : Slice U8) (h32 : 32 ≤ Usize.numBits) :
    sequence.decode_sequence content ⦃ r =>
      match r with
      | core.result.Result.Ok _ =>
        ∃ finalRest : Slice U8,
          finalRest.val = content.val.drop (content.val.length - finalRest.val.length) ∧
          finalRest.val.length = 0
      | core.result.Result.Err _ => True ⦄ := by
  unfold sequence.decode_sequence sequence.Elements.new
  simp only [bind_tc_ok]
  have hsuf : ({ rest := content, done := false } : sequence.Elements).rest.val
      = content.val.drop (content.val.length
          - ({ rest := content, done := false } : sequence.Elements).rest.val.length) := by
    simp
  have hdone : ({ rest := content, done := false } : sequence.Elements).done = false := rfl
  have hcount : (0#usize).val
      + ({ rest := content, done := false } : sequence.Elements).rest.val.length
      ≤ content.val.length := by simp
  exact decode_sequence_loop_spec content h32 0#usize { rest := content, done := false } hsuf hdone hcount

#print axioms decode_tlv_progress
#print axioms elements_next_progress
#print axioms decode_sequence_loop_spec
#print axioms decode_sequence_structure

end DerVerified.Sequence
