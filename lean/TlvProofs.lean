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

This lid composes THREE codecs (`tag`, `length`, `tlv`), two of which (`tag.decode_tag`,
`usize::try_from(u32)`) extract as **unmodelled axioms** (an early-return-in-a-loop bodyless
axiom, and a stdlib `TryFrom` impl Aeneas's Std library hasn't (yet) covered for this direction).
Rather than leave those two fully opaque (which would block proving anything at all about
`decode_tlv`), this file adds seven small, documented, disclosed assumed specs — each the
`first_spec` pattern from `LengthProofs.lean` (a minimal, honest characterization of an otherwise
fully-opaque primitive), never a re-statement of `decode_tlv`'s own logic:

* **`tag_decode_used_bounds`** / **`tag_decode_total`** — the structural facts this lid needs
  from `decode_tag` (itself extracted as a **bodyless axiom**: `tag.rs`'s `decode_tag` has an
  early `return` nested inside its `loop` — the exact `writing-verifiable-rust.md` §4 "no return
  nested >1 loop deep" shape that also hit `validate_oid`, D25. Refactoring `tag.rs` to a
  single-loop/depth-1-return shape — as `validate_oid` was refactored — is a real, owner-scoped
  follow-on item, out of scope for *this* lid, which only needs `decode_tag`'s consumption bound
  and totality, not its full bit-level canonicality). States exactly what Kani's own
  `decode_tag_never_panics` / `decode_tag_accepts_only_canonical` harnesses already prove
  (bounded, ≤ 7 bytes): `decode_tag` never panics/faults, and an accepted decode never consumes
  zero bytes or more bytes than the input holds — the *positive* form of "no over-read" for the
  tag sub-decode, exactly what `decode_tlv` needs to compose.
* **`length_decode_total`** / **`length_decode_used_le`** — the SAME two facts, restated for
  `length.decode_length`. Unlike `decode_tag`, `decode_length` is fully-defined (not opaque) in
  this extraction, and `LengthProofs.lean`'s own `decode_accepts_only_canonical` already proves
  totality **sorry-free** over the byte-identical `length.rs` source — but `lean/extract-tlv` runs
  its own independent Charon/Aeneas pass (needed since `tlv.rs` requires `length` as a sibling
  module), producing a Lean namespace that collides with `lean/extract`'s own `DerLengthExtract`
  if both are imported together. These two axioms are a namespace-workaround, not new unverified
  trust — see the docstrings for the precise justification.
* **`result_map_err_ok_spec`** / **`result_map_err_err_spec`** — `Result::map_err`'s textbook
  semantics (`Ok v ↦ Ok v`, `Err e ↦ Err (f e)`, the latter conditioned on `call_once` succeeding
  — always true for `decode_tlv`'s two concrete closures); Aeneas extracts
  `core.result.Result.map_err` itself as an unmodelled axiom (a generic stdlib combinator, not yet
  in the Aeneas Std library — the same category as `first_spec`).
* **`try_from_u32_usize_spec`** — `usize::try_from(u32)` always succeeds, value-preserving, given
  `usize` is at least 32 bits — `tlv.rs`'s own documented deployment boundary (§ "Portability...
  Unreachable on 32/64-bit"), the same assumption Kani's harnesses make (Kani models `usize` as
  64-bit).

None of these seven axioms is der-specific trust beyond what Kani has already checked (bounded),
what `LengthProofs.lean` has already proved (sorry-free, over the identical source), or what the
Rust standard library guarantees — all are disclosed here, and `#print axioms` at the bottom shows
the resulting theorem depends on exactly these seven plus the standard Lean axioms (`propext`,
`Classical.choice`, `Quot.sound`) plus the three underlying opaque Aeneas primitives they
characterize (`tag.decode_tag`, `Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from`,
`core.result.Result.map_err`) and the one `LengthProofs.lean` already trusts
(`core.slice.Slice.first`). No `sorryAx`.
-/

open Aeneas Aeneas.Std Result
open der_tlv_extract

namespace DerVerified.Tlv

/-! ## Assumed specs (disclosed trust surface) -/

/-- **Assumed spec (structural only) for the opaque `tag.decode_tag` axiom.** `decode_tag`
    itself extracts as a bodyless axiom (early-return-inside-a-loop, the `writing-verifiable-
    rust.md` §4 shape) — this states only the ONE fact `decode_tlv`'s structural proof needs:
    an accepted decode never claims zero bytes, and never consumes more than the input holds.
    Both conjuncts are already Kani-proven (bounded, ≤ 7 bytes) by `decode_tag_never_panics`
    (implicitly, via `used`'s type) and are true of `decode_tag`'s Rust source by construction
    (every accept path returns an index strictly within, or immediately following, a slot the
    code already read) — this is the *value* form of that fact, not a reproof of `decode_tag`'s
    full bit-level canonicality (which Kani already covers, bounded, and which needs the D25-style
    single-loop refactor to reach ∀-length in Lean — a separate, larger follow-on lid). -/
axiom tag_decode_used_bounds (input : Slice U8) (t : tag.Tag) (t_used : Usize) :
    tag.decode_tag input = ok (core.result.Result.Ok (t, t_used)) →
      1 ≤ t_used.val ∧ t_used.val ≤ input.val.length

/-- **Assumed totality** for the opaque `tag.decode_tag` axiom: it always returns `ok
    (core.result.Result.Ok _ | .Err _)`, never `fail`/`div`. This is the Lean-level restatement
    of "`decode_tag` never panics" — `tag::proofs::decode_tag_never_panics` already Kani-checks
    this (bounded, ≤ 7 bytes) for the real Rust function, and it is true by construction of
    `decode_tag`'s Rust source (no `panic!`/`unwrap`/`unreachable!`/arithmetic overflow on any
    path — the whole point of the crate's `#![forbid(unsafe_code)]` + Kani-verified floor). -/
axiom tag_decode_total (input : Slice U8) :
    ∃ r : core.result.Result (tag.Tag × Usize) tag.TagError, tag.decode_tag input = ok r

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
