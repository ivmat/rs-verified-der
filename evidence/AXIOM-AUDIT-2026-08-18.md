# Lean lid axiom audit — 2026-08-18

Closes finding **F4** of the external rigor re-review of this crate (2026-08-16), §5:

> "the six lids declare 17 axioms; a declared axiom characterising an Aeneas-Std primitive and a
> bespoke crate-specific assumption are syntactically identical; audit each declared axiom is
> genuinely an upstream-primitive spec, not a smuggled property of this crate's own code."

`PROOF_MANIFEST.md` §3.2 states the same limitation in its own words: *"Nothing in this repository
mechanically distinguishes them — the argument that each is an upstream-primitive spec is made in
the lid docstrings and rests on review, not on a gate."* This file is that review, done once,
against upstream ground truth rather than against the docstrings.

**Method — read-only.** No `lake`, no `lean`, no solver was run for this audit. Ground truth came
from (a) the rustc library sources for the extraction toolchain actually pinned by
`lean/extract*/rust-toolchain.toml` (`nightly-2026-06-01`, `…/lib/rustlib/src/rust/library/core/src`),
(b) the Aeneas Lean Std library the lids build against
(`~/Downloads/verified_rs_tools/aeneas/backends/lean`, the `[[require]]` path in `lean/lakefile.toml`),
and (c) the archived `#print axioms` disclosure in `evidence/lean-lid-ea8dad4.log`.

**Applicability of the archived log.** That log was *added* in `151c826`, the same commit that
regenerated all six `Der*Extract.lean` files. `git diff --stat 151c826 HEAD -- lean/` touches only
`check_lean.sh` and `lid-source-state.txt`; no lid or extract `.lean` file has changed since. The
axiom dependency sets in that log therefore describe HEAD's lid sources exactly.

---

## 1. Census — declared count vs. reality

**17 declared, 17 found. No drift.** (Contrast the aeneas-lean 4-vs-6 case; this count is honest.)

Census taken with `grep -nE '(^|[^a-zA-Z_.])axiom([ \t]|$)'` over the six lid files, discarding
prose matches inside docstrings:

| Lid | manifest says | found | axiom names (in file order) |
|---|---:|---:|---|
| `lean/BigIntProofs.lean` | 3 | **3** | `first_spec` (45), `bitand_spec` (54), `is_some_and_spec` (62) |
| `lean/LengthProofs.lean` | 1 | **1** | `first_spec` (75) |
| `lean/OidProofs.lean` | 0 | **0** | — |
| `lean/SequenceProofs.lean` | 6 | **6** | `first_spec` (95), `result_map_err_ok_spec` (343), `result_map_err_err_spec` (347), `try_from_u32_usize_spec` (353), `length_decode_total` (362), `length_decode_used_le` (367) |
| `lean/TagProofs.lean` | 1 | **1** | `first_spec` (80) |
| `lean/TlvProofs.lean` | 6 | **6** | `first_spec` (98), `result_map_err_ok_spec` (356), `result_map_err_err_spec` (360), `try_from_u32_usize_spec` (371), `length_decode_total` (386), `length_decode_used_le` (397) |
| **total** | **17** | **17** | |

The 43 `#print axioms` commands the manifest mentions also reconcile: 11 + 17 + 4 + 5 + 4 + 2 = 43
(BigInt/Length/Oid/Sequence/Tag/Tlv). They are audit commands, not axioms; no comparison intended.

### 1b. The second axiom surface the manifest column does *not* count

The six `Der*Extract.lean` files declare **25 further axioms**
(BigInt 3, Length 1, Oid 0, Sequence 13, Tag 2, Tlv 6). These are Aeneas-emitted *bodyless
constants* — declarations of a type with no asserted property — so they add no logical strength and
cannot make a proof unsound on their own. They matter to this audit for two reasons:

1. They are the *targets* the 17 lid axioms characterise. An axiom is an upstream-primitive spec
   exactly when its target is one of these bodyless constants **and** that constant carries an
   Aeneas `@[rust_fun "core::…"]` attribute with a `/rustc/library/core/src/…` source docstring.
   This is the mechanical discriminator §3 recommends turning into a gate.
2. Two of them are **this crate's own functions declared opaque** (deliberately, via `--opaque`, a
   parameter-shadowing workaround): `tag.encode_tag` (`DerTagExtract.lean:311`,
   `DerTlvExtract.lean:620`, `DerSequenceExtract.lean:1345`) and `tlv.encode_tlv_into`
   (`DerTlvExtract.lean:1070`, `DerSequenceExtract.lean:1099`). A theorem *mentioning* either would
   prove nothing about the shipped Rust. **Checked: neither name appears in any lid theorem
   statement or proof** — only in prose docstrings (`TagProofs.lean:32-36`, `SequenceProofs.lean:66`).
   No lid claim is hollowed out by them.

---

## 2. Per-axiom audit

Classification key:

* **UPSTREAM-PRIMITIVE-SPEC** — characterises an upstream (rustc `core`) primitive; assertion
  verified faithful against that primitive's actual source at the pinned extraction toolchain.
* **UPSTREAM-PRIMITIVE-SPEC-UNVERIFIABLE** — upstream target, but no accessible ground truth.
* **SMUGGLED** — asserts a property of *this crate's own* translated code.

| # | file:line | axiom | asserts | upstream anchor | class |
|---|---|---|---|---|---|
| 1 | `LengthProofs.lean:75` | `first_spec` | `der_length_extract.core.slice.Slice.first s = ok s.val[0]?` | `core/src/slice/mod.rs:155` | UPSTREAM-PRIMITIVE-SPEC |
| 2 | `BigIntProofs.lean:45` | `first_spec` | same, `der_bigint_extract` namespace | idem | UPSTREAM-PRIMITIVE-SPEC |
| 3 | `TagProofs.lean:80` | `first_spec` | same, `der_tag_extract` namespace | idem | UPSTREAM-PRIMITIVE-SPEC |
| 4 | `TlvProofs.lean:98` | `first_spec` | same, `der_tlv_extract` namespace | idem | UPSTREAM-PRIMITIVE-SPEC |
| 5 | `SequenceProofs.lean:95` | `first_spec` | same, `der_sequence_extract` namespace | idem | UPSTREAM-PRIMITIVE-SPEC |
| 6 | `BigIntProofs.lean:54` | `bitand_spec` | `Shared0U8.…bitand a b = ok (a &&& b)` | `core/src/internal_macros.rs:27` (`forward_ref_binop`) | UPSTREAM-PRIMITIVE-SPEC |
| 7 | `BigIntProofs.lean:62` | `is_some_and_spec` | `none ↦ ok false`; `some x ↦ inst.call_once env x` | `core/src/option.rs:658` | UPSTREAM-PRIMITIVE-SPEC |
| 8 | `TlvProofs.lean:356` | `result_map_err_ok_spec` | `map_err inst (.Ok v) f = ok (.Ok v)` | `core/src/result.rs:962` | UPSTREAM-PRIMITIVE-SPEC |
| 9 | `TlvProofs.lean:360` | `result_map_err_err_spec` | `call_once f e = ok w → map_err inst (.Err e) f = ok (.Err w)` | idem | UPSTREAM-PRIMITIVE-SPEC |
| 10 | `SequenceProofs.lean:343` | `result_map_err_ok_spec` | idem, `der_sequence_extract` | idem | UPSTREAM-PRIMITIVE-SPEC |
| 11 | `SequenceProofs.lean:347` | `result_map_err_err_spec` | idem, `der_sequence_extract` | idem | UPSTREAM-PRIMITIVE-SPEC |
| 12 | `TlvProofs.lean:371` | `try_from_u32_usize_spec` | `32 ≤ Usize.numBits → ∃ l, try_from i = ok (.Ok l) ∧ l.val = i.val` | `core/src/convert/num.rs:258` + instantiation sites 463/488 | UPSTREAM-PRIMITIVE-SPEC |
| 13 | `SequenceProofs.lean:353` | `try_from_u32_usize_spec` | idem, `der_sequence_extract` | idem | UPSTREAM-PRIMITIVE-SPEC |
| 14 | `TlvProofs.lean:386` | `length_decode_total` | `∃ r, length.decode_length s = ok r` | **none — `der-verified/src/length.rs`** | **SMUGGLED** (discharged elsewhere, §2.6) |
| 15 | `SequenceProofs.lean:362` | `length_decode_total` | idem, `der_sequence_extract` | **none — crate code** | **SMUGGLED** (discharged elsewhere, §2.6) |
| 16 | `TlvProofs.lean:397` | `length_decode_used_le` | `decode_length s = ok (.Ok (v,l_used)) → l_used.val ≤ s.val.length` | **none — crate code** | **SMUGGLED** (no Lean proof anywhere, §2.7) |
| 17 | `SequenceProofs.lean:367` | `length_decode_used_le` | idem, `der_sequence_extract` | **none — crate code** | **SMUGGLED** (no Lean proof anywhere, §2.7) |

### 2.1 `first_spec` ×5 — `<[T]>::first`

Upstream, `nightly-2026-06-01`, `library/core/src/slice/mod.rs:155`:

```rust
pub const fn first(&self) -> Option<&T> {
    if let [first, ..] = self { Some(first) } else { None }
}
```

Head-or-`None`, total, cannot panic. Aeneas emits it as a bodyless axiom
`core.slice.Slice.first {T} : Slice T → Result (Option T)` carrying
`@[rust_fun "core::slice::{[@T]}::first"]`; **confirmed the Aeneas Std library genuinely has no
model for it** (`grep -rn 'rust_fun "core::slice…first' Aeneas/` → no hits; `SliceIter.lean` covers
`iter`/`contains` but not `first`), so an assumed spec is unavoidable rather than lazy.

Faithfulness of `ok s.val[0]?`:
* `Slice α := { l : List α // l.length ≤ Usize.max }` (`Aeneas/Std/SliceDef.lean:5`) — a plain
  length-bounded `List`, so `first` is total and `ok` (never `fail`/`div`) admits no unreachable
  state. Verified against the Aeneas source, not assumed.
* `s.val[0]?` is `some head` iff non-empty, `none` iff empty — the exact `if let [first, ..]`
  dichotomy.
* Borrow erasure (`Option<&T>` → `Option T`) is Aeneas's choice in the *extracted type*; the spec
  cannot be stated any other way, and every consumer here is `T = U8` (`Copy`, used by value).

The five copies differ only in the extraction namespace they target
(`der_length_extract` / `der_bigint_extract` / `der_tag_extract` / `der_tlv_extract` /
`der_sequence_extract`) — verified line by line; none targets another pass's constant.

### 2.2 `bitand_spec` — `impl BitAnd<u8> for &u8`

`DerBigintExtract.lean:20-26` records the target as
`core::ops::bit::{core::ops::bit::BitAnd<&'0 u8, u8, u8>}::bitand`,
source `/rustc/library/core/src/internal_macros.rs:27`. That line is inside `forward_ref_binop!`:

```rust
impl const $imp<$u> for &$t {
    fn $method(self, other: $u) -> <$t as $imp<$u>>::Output { $imp::$method(*self, other) }
}
```

i.e. *dereference, then apply the owned operator* — exactly `ok (a &&& b)` where `&&&` is Aeneas's
modelled owned `UScalar` bit-and. `u8 & u8` cannot panic, so `ok` (never `fail`) is right. Aeneas
Std carries only the `core.ops.bit.BitAnd` trait record (`Aeneas/Std/Core/Ops.lean:43`) and no
`&u8` instance, confirming the primitive really is unmodelled. **Faithful.**

### 2.3 `is_some_and_spec` — `Option::is_some_and`

Upstream `library/core/src/option.rs:658`:

```rust
pub const fn is_some_and(self, f: impl FnOnce(T) -> bool) -> bool {
    match self { None => false, Some(x) => f(x) }
}
```

The axiom is that match, verbatim: `none ⇒ ok false` (no closure call — correct, `f` is not invoked
on `None`), `some x ⇒ inst.call_once env x` (delegates, so the closure's own failure/divergence
still propagates rather than being assumed away). Aeneas Std models `unwrap`/`unwrap_or`/`take`/
`is_none`/`is_some`/`expect` but **not** `is_some_and` — confirmed by grep. **Faithful.**

### 2.4 `result_map_err_ok_spec` / `result_map_err_err_spec` ×2 files — `Result::map_err`

Upstream `library/core/src/result.rs:962`:

```rust
pub const fn map_err<F, O>(self, op: O) -> Result<T, F> {
    match self { Ok(t) => Ok(t), Err(e) => Err(op(e)) }
}
```

* `_ok_spec` — `Ok` passes through with no closure call, unconditionally `ok`. Faithful.
* `_err_spec` — **guarded** by the hypothesis `inst.call_once f e = ok w`, so it asserts nothing
  about the case where the closure fails. That is strictly *weaker* than the true semantics, which
  is the safe direction: it cannot overclaim. (The two closures actually applied,
  `TlvError::Tag` / `TlvError::Length`, are unconditional `ok (…)` one-liners in the extract.)

Aeneas Std models `Result::is_ok`/`unwrap`/`expect` but **not** `map_err` — confirmed by grep.
**Faithful.**

### 2.5 `try_from_u32_usize_spec` ×2 — `<usize as TryFrom<u32>>::try_from`

This is the axiom with the most room for an overclaim, and it is the one stated most precisely.

`DerTlvExtract.lean:20-29` records the target as
`core::convert::num::ptr_try_from_impls::{core::convert::TryFrom<usize, u32, TryFromIntError>}::try_from`
with signature `U32 → Result (core.result.Result Usize TryFromIntError)`, source
`/rustc/library/core/src/convert/num.rs:258`. That line is the body of the `impl_try_from_unbounded!`
macro — `fn try_from(value: $source) -> Result<Self, Self::Error> { Ok(value as Self) }` —
infallible and value-preserving.

Which macro is instantiated for `u32 → usize` depends on the pointer width
(`library/core/src/convert/num.rs`, `#[cfg(target_pointer_width …)]` blocks at 427 / 449 / 474):

| width | line | instantiation for `u32 → usize` | fallible? |
|---|---|---|---|
| 16 | 441 | `rev!(impl_try_from_upper_bounded, usize => u32, …)` | **yes** |
| 32 | 463 | `rev!(impl_try_from_unbounded, usize => u32)` | no |
| 64 | 488 | `rev!(impl_try_from_unbounded, usize => u32, u64)` | no |

The axiom's hypothesis `32 ≤ Usize.numBits` is therefore *exactly* the condition under which the
infallible impl is selected — not a convenient approximation. It also matches `tlv.rs`'s own
documented deployment boundary and Kani's 64-bit `usize` model, and `Usize.numBits` resolves to
`System.Platform.numBits` (32 or 64) in Aeneas, so the hypothesis is a real side condition and not
vacuous. Aeneas Std covers only the **opposite** direction
(`Aeneas/Std/Scalar/CoreConvertNum.lean:815`, `Usize → Result (Result U32 …)`), confirming the
"Aeneas hasn't covered this direction" claim. **Faithful, and precisely guarded.**

### 2.6 `length_decode_total` ×2 — SMUGGLED, but discharged elsewhere

`∃ r, length.decode_length s = ok r`. Its target is **not** an upstream primitive: in both
`DerTlvExtract.lean` and `DerSequenceExtract.lean`, `length.decode_length` is a **fully defined**
function extracted from `src/../../../der-verified/src/length.rs`. By the mechanical test in §1b
this is a crate-code assumption, i.e. structurally the very thing F4 asks about. It is also
**load-bearing**: the archived `#print axioms` shows `DerVerified.Tlv.decode_tlv_structure` and all
four `DerVerified.Sequence.*` headline theorems depend on it, and the proofs use it (`TlvProofs.lean:441`,
`SequenceProofs.lean:394`, `:490`) to obtain the `ok` shape of `decode_length` before continuing —
if `decode_length` could `fail` or diverge, those triples would be false.

Why it is nevertheless *not* an unproven hole:

1. `LengthProofs.lean:799 decode_accepts_only_canonical` is stated for **every** `s : Slice U8` with
   no hypotheses, as an Aeneas Hoare triple `length.decode_length s ⦃ … ⦄`.
2. `Aeneas/Std/WP.lean` gives `spec (ok x) p ↔ p x` (:56), `spec (fail e) p ↔ False` (:58),
   `spec div p ↔ False` (:61). So an unhypothesised proved triple **entails** `∃ r, … = ok r` —
   the docstring's claim checks out against the Aeneas source.
3. That theorem is sorry-free and its own axiom set (archived log) is
   `[propext, Classical.choice, Quot.sound, first_spec, core.slice.Slice.first, 3× bv_decide
   certificate]` — nothing circular.
4. The remaining question is whether the `length.decode_length` proved there is the same function as
   the one assumed here, across three independent Charon/Aeneas passes. **Checked mechanically for
   this audit**: all `length.*` declarations were extracted from `DerLengthExtract.lean`,
   `DerTlvExtract.lean`, `DerSequenceExtract.lean`, the namespace token normalised, and diffed.
   `DerLengthExtract` ≡ `DerTlvExtract` **exactly** (19 declarations, byte-identical).
   `DerSequenceExtract` differs by exactly one addition — a bodyless
   `length.LengthError.Insts.CoreCmpPartialEqLengthError.ne` axiom (derive-generated `PartialEq::ne`,
   pulled in because `sequence.rs` compares `LengthError`) and its one-line instance field. **No
   difference touches `decode_length`'s body.** The three extraction crates also
   `#[path]`-include the *same* `der-verified/src/length.rs` (`lean/extract*/src/lib.rs`), so there
   is a single source of truth by construction.

**Residual:** the transfer from `LengthProofs`'s theorem to these two axioms is a *hand* argument
across namespaces. Nothing fails if someone edits one axiom's statement to say more than the
theorem proves. §3's gate closes the drift half of that; a full close needs either Aeneas emitting
one shared `length` namespace or a `--rename`/module-merge so the theorem can be imported.

### 2.7 `length_decode_used_le` ×2 — SMUGGLED, and **not proven in Lean anywhere**

`decode_length s = ok (.Ok (v, l_used)) → l_used.val ≤ s.val.length`. Same crate-code target as
§2.6, same load-bearing status per `#print axioms`. **But unlike `length_decode_total`, this fact
is not a theorem in `LengthProofs.lean`.** Searched all 42 theorem/lemma statements there: none
states a consumption bound for `decode_length`. `decode_accepts_only_canonical`'s postcondition is a
re-encoding equality using `getElem!` (which silently defaults past the end), so it does **not**
imply the bound either. The docstring is candid that its warrant is a source reading plus bounded
Kani, not a Lean proof — and it is correct that the docstring's warrant is sound:

`der-verified/src/length.rs:74-109` has exactly two accept paths —
`Ok((first as u32, 1))` at :80, reachable only after `input.first()` returned `Some` (so
`input.len() ≥ 1`), and `Ok((val, 1 + n))` at :108, reachable only past the guard
`if input.len() < 1 + n { return Err(Truncated) }` at :89. So `l_used ≤ input.len()` holds on both.
The axiom is **true of the shipped source**; it is simply not machine-checked.

It is also derivable inside `LengthProofs.lean` from lemmas that already exist —
`decode_short_form` (:102, pins `used = 1`) and `decode_long_form_accept` (:301, pins
`used = 1 + (b &&& 127)` under the hypothesis `1 + (b &&& 127) ≤ s.val.length`) — plus the branch
walk that `decode_accepts_only_canonical`'s own proof already performs. **This is the single
highest-value follow-up in the whole audit: a `decode_length_used_le` theorem in `LengthProofs.lean`
would move axioms 16 and 17 into the same "discharged elsewhere" class as 14 and 15, at what looks
like modest proof cost.**

**Blast radius, stated precisely (good news).** In both lids this axiom is consumed at exactly one
place: to establish `hnoverflow : t_used.val + l_used.val ≤ Usize.max`, the overflow-freedom side
condition of `decode_tlv`'s own `header` computation (`TlvProofs.lean:444-449`,
`SequenceProofs.lean:397`, `:492`). The **security-critical** conclusion — `used ≤ input.length`,
the no-over-read fact the ∀-length TLV/SEQUENCE headline actually sells — is derived from
`decode_tlv`'s *own runtime guard* (`hend_le` from `hshort : ¬ (input.len < e)`,
`TlvProofs.lean:479-481`), **not** from this axiom. So a hypothetical falsehood here would
invalidate an overflow side condition, not the headline no-over-read claim itself.

---

## 3. Verdict

**Nothing false. Nothing unverifiable. Four of seventeen are not what the manifest column calls them.**

| classification | count |
|---|---:|
| UPSTREAM-PRIMITIVE-SPEC (verified faithful against rustc source) | **13** |
| UPSTREAM-PRIMITIVE-SPEC-UNVERIFIABLE | **0** |
| SMUGGLED — asserts a property of this crate's own translated code | **4** |
| — of those, discharged by a sorry-free proof elsewhere (`length_decode_total` ×2) | 2 |
| — of those, **no Lean proof anywhere** (`length_decode_used_le` ×2) | 2 |

* **Zero axioms are unfaithful.** Every one of the 13 upstream specs was checked against the actual
  rustc `core` source at the pinned extraction nightly, and every one is either exactly the upstream
  body or strictly weaker than it (`result_map_err_err_spec`) or exactly guarded by the upstream
  cfg condition (`try_from_u32_usize_spec`). No upstream target was unverifiable — the rust-src
  component for `nightly-2026-06-01` is present locally.
* **Zero axioms are false.** The four crate-property axioms were each checked against
  `der-verified/src/length.rs` and hold of the shipped source.
* **Four axioms are mis-labelled by `PROOF_MANIFEST.md`.** The generated §3.2 column is headed
  *"Assumed Aeneas-Std specs (`axiom`)"* and the prose calls them *"a small number of Aeneas-Std
  specs"*. For `length_decode_total` ×2 and `length_decode_used_le` ×2 that is inaccurate: they are
  assumptions about **der-verified's own code**, not about Aeneas's Std library. The lid docstrings
  say so plainly; only the manifest's summary flattens the distinction. **Recommend renaming the
  column to "Assumed specs (`axiom`)" and splitting it into upstream vs. crate-property sub-counts
  (13 / 4), driven by the gate in §4.**
* **One real residual:** `length_decode_used_le` ×2 — true, disclosed, narrowly used, but not
  machine-checked. Closing it is a small proof in `LengthProofs.lean` (§2.7).

Concretely, the honest one-line statement of the ∀-length trust base is:
*13 upstream-primitive specs (verified faithful), 2 crate-code facts proved sorry-free in a sibling
lid and re-asserted across an extraction-namespace boundary, and 2 crate-code facts warranted by
source reading and bounded Kani only.*

---

## 4. Recommended mechanical census gate

The 4-vs-6 drift class this audit was asked to guard against is a *count and location* problem; the
smuggling class is a *target* problem. One gate can close both, because Aeneas hands us the
discriminator the manifest says does not exist: every bodyless constant in a `Der*Extract.lean`
carries an `@[rust_fun "…"]` attribute and a `Source:` docstring, and those cleanly separate

* upstream — `@[rust_fun "core::…"]`, `Source: '/rustc/library/core/src/…'`
* crate — `Source: 'src/../../../der-verified/src/*.rs'`

**Proposal: `gates/check_axiom_census.py`, wired into `check_fast.sh`** (pure text, no Lean, so it
runs per-commit like `check_lid_staleness.py`), with a checked-in expectation file
`gates/axiom_census.txt`:

1. **Count + location.** Parse top-level `axiom <name>` declarations out of the six lid files;
   compare the `(lid, name, class)` multiset against `gates/axiom_census.txt`. Fail closed on any
   addition, removal, rename, or move between lids. A pure count check would have missed a swap;
   this checks both, as F4 asks.
2. **Classification, mechanically.** For each lid axiom, resolve the head constant of its
   right-hand side; find its declaration in the sibling `Der*Extract.lean`; read the `@[rust_fun …]`
   pattern and the `Source:` line.
   * pattern rooted at `core::` / `alloc::` / `std::` **and** source under `/rustc/library/…`
     ⇒ `UPSTREAM`;
   * source under `der-verified/src/…` **or** target is a defined (non-axiom) declaration
     ⇒ `CRATE`.
   Fail if the derived class disagrees with the census file. **This is the check that makes a
   newly-smuggled crate-property axiom impossible to add silently** — it turns "rests on review,
   not on a gate" into a gate.
3. **Crate-property axioms must name their discharge.** Every `CRATE` census row carries a required
   `discharge:` field (`LengthProofs.lean:799 decode_accepts_only_canonical`, or the literal
   `UNPROVEN` for `length_decode_used_le`). Fail if a `CRATE` row lacks one; print the `UNPROVEN`
   rows as a WARN line on every run so the residual stays visible instead of decaying into
   background noise.
4. **Census the opaque surface too.** Apply steps 1–2 to the 25 bodyless axioms in the six
   `Der*Extract.lean` files, so a newly-opaque crate function (the `tag.encode_tag` /
   `tlv.encode_tlv_into` class) cannot appear unnoticed after a refactor. Additionally fail if any
   `CRATE`-class opaque constant's name occurs in a lid **theorem statement** — the hollow-claim
   check that §1b currently passes by hand.
5. **Reconcile with the manifest.** Have `gates/gen_proof_manifest.py` read the census file rather
   than re-counting independently, and emit the two sub-counts (upstream / crate-property) instead
   of the single "Assumed Aeneas-Std specs" column. Two independent counters is exactly how a
   4-vs-6 drift survives; one source of truth is how it does not.

Expected initial census: **17 lid axioms (13 UPSTREAM, 4 CRATE — 2 discharged, 2 UNPROVEN) and 25
extract axioms**, per §1 and §2 above.

---

## 5. Files and anchors used

* Lids: `lean/{BigInt,Length,Oid,Sequence,Tag,Tlv}Proofs.lean`
* Extracts: `lean/Der{Bigint,Length,Oid,Sequence,Tag,Tlv}Extract.lean`
* Extraction crates (single-source-of-truth `#[path]` includes): `lean/extract*/src/lib.rs`,
  toolchain pin `lean/extract*/rust-toolchain.toml` → `nightly-2026-06-01`
* Shipped source audited against: `der-verified/src/length.rs:74-109`
* Aeneas Std (`lean/lakefile.toml` `[[require]]` path):
  `Aeneas/Std/WP.lean:56,58,61`, `Aeneas/Std/SliceDef.lean:5`, `Aeneas/Std/Core/Ops.lean:43`,
  `Aeneas/Std/Scalar/CoreConvertNum.lean:815`
* rustc `core` (`nightly-2026-06-01` rust-src): `slice/mod.rs:155`, `option.rs:658`,
  `result.rs:962`, `convert/num.rs:258,427,441,449,463,474,488`, `internal_macros.rs:27`
* Archived disclosure: `evidence/lean-lid-ea8dad4.log` (added in `151c826`; no lid/extract `.lean`
  change since — applicable to HEAD)
* Manifest text audited: `PROOF_MANIFEST.md` §3.2
