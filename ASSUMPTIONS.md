# Assumptions — the trusted base of `der-verified`

**Every machine-checked claim in this crate stands on things that are assumed, not proven. This file
is the list, stated loudly rather than left to be inferred from the corners of other documents.**
`PROOF_MANIFEST.md` says what is proven and over what domain; this file says what has to be true for
any of that to mean what it appears to mean.

Nothing here is a disclaimer in the legal sense. Each entry is a real dependency with a real failure
mode, and each names it:

- **fails-if** — what would falsify the assumption, or at least make us notice. An assumption nobody
  can imagine noticing the failure of is a wish, and is marked as such.
- **load-bearing-for** — what stops being true if the assumption is false. An assumption nothing
  leans on does not belong in a trust base.

**Two rules this file is written under.**

1. **An entry leaves this file by TOMBSTONE (§T), never by deletion.** If an assumption is
   discharged — a proof written, a gate added — it moves to §T with the reason and the artifact that
   closed it. Silent removal is how a trust base shrinks on paper only.
2. **This list is incomplete, and A0 says so inside the list rather than around it.** No claim of
   the form "these are all the assumptions" is made anywhere in this crate.

Two of the entries below (**A6**) are assumptions about *this crate's own code*. Since 2026-08-19
neither is un-discharged — both are entailed by a sorry-free proof in a sibling lid — but the
transfer across Aeneas's per-extraction namespaces is still a **hand argument, not an import**, and
§2 says so in as many words rather than softening it. The pair that really was *proven nowhere*
(`length_decode_used_le` ×2) was discharged by proof on that date and is tombstoned in §T.

---

## 0. The entry that bounds all the others

- **A0 · This list is incomplete.** There are assumptions in this crate that nobody here has
  identified. The apparatus that would find them — review, re-review, adversarial reading — is the
  same apparatus that produced this list, so its blind spots are inherited.
  **fails-if:** never falsifiable; the entry exists to block any "all assumptions are stated"
  reading of this file, including of this file itself.
  **load-bearing-for:** every sentence in this repository of the form "the full trust base is …".

## 1. The tool base — what the machines have to get right

- **A1 · Kani is sound for the properties it decides, at the pinned version.** The L3 floor is
  `cargo kani -Z stubbing` at Kani `0.67.0` (`.github/workflows/ci.yml`). Kani's compilation of Rust
  MIR to CBMC goto-programs, its default checks (panic-freedom, arithmetic overflow, memory safety),
  its `-Z stubbing` substitution and its harness/property bookkeeping are all trusted. A missed
  property, a check silently not emitted, or a stub applied to the wrong callee would make a green
  run mean less than it appears to.
  **fails-if:** an upstream Kani soundness advisory at or below this version; a differential against
  another checker on the same harness; a harness that reports `SUCCESSFUL` while a hand-planted
  defect of the class it exists to catch survives (this is why the mutation controls in
  `evidence/MUTATION-CONTROLS-*.md` exist — they are the cheapest available probe of A1, and they
  sample it rather than establish it).
  **load-bearing-for:** all 191 proof harnesses — i.e. every bounded claim in `PROOF_MANIFEST.md`
  §§3.1, 4, 5, 7.
  *Not enforced by `./check.sh`:* the Kani version is pinned in CI, and a local run with a different
  Kani will not tell you so (`PROOF_MANIFEST.md` §2).

- **A2 · CBMC 6.8.0 and its SAT backend decide the queries correctly.** Underneath Kani sit CBMC's
  symbolic execution, its bit-precise encoding of the verification conditions, and the SAT solver
  that discharges them (CaDiCaL 2.0.0 by default — read from the committed run's own banner in
  `evidence/check-69bbc9f.log`, not assumed). An encoding bug, an unsound simplification, or a
  solver that answers UNSAT where the formula is satisfiable all produce a green run over a false
  property, and no artifact in this repository would show it.
  **fails-if:** an upstream CBMC/CaDiCaL soundness advisory; a re-run under a different solver
  (`--solver kissat`/`cvc5`) disagreeing; a proof that survives a planted defect.
  **load-bearing-for:** the same set as A1 — the entire L3 floor.
  *Independence caveat:* A1 and A2 are not independent of each other in practice. Kani's own test
  suite and this crate's runs exercise the pair, so a bug in either tends to be visible only as
  "the pair agreed on something false".

- **A3 · The Lean 4 kernel is sound, and `bv_decide`'s certificate checking with it.** The L4/L5
  lids are `lake build`-checked Lean developments; a kernel bug, or an unsound bit-blasting
  certificate accepted by `bv_decide`, would let a false theorem elaborate.
  **fails-if:** an upstream Lean/`bv_decide` soundness report at `leanprover/lean4:v4.30.0-rc2`;
  a lid theorem that still builds after its statement is mutated into a false one — measured for all
  six lids in `evidence/LID-MUTATION-CONTROLS-2026-08-19.md` (six for six went RED), which is a probe
  of the *lid's* oracle and only incidentally of the kernel.
  **load-bearing-for:** every ∀-length claim in `PROOF_MANIFEST.md` §3.2 — the six codecs' unbounded
  properties, which are the crate's strongest claims.

- **A4 · The Aeneas extraction is faithful: the Lean the lids prove is a faithful model of the Rust
  that ships.** This is the largest single assumption in the crate, and it is structural rather than
  accidental. The lids do **not** prove Rust. They prove theorems about a Lean model produced by
  Charon (Rust → LLBC) and Aeneas (LLBC → Lean), at the exact revisions
  `lean/check_lean.sh` pins and fails closed on. The Rust → LLBC → Lean translation is not itself
  verified against rustc semantics; this is the standard Aeneas assurance boundary, and it means a
  translation bug can make a lid prove a true theorem about the wrong function.
  What is genuinely nailed down, and is therefore *not* part of this assumption:
  - **same source of truth** — the six extraction shims `#[path]`-include the *shipped*
    `der-verified/src/*.rs` (`lean/extract*/src/lib.rs`), so no separate copy of the codec can drift;
  - **no cfg-split** — `lean/check_lean.sh` fails closed unless each lidded `pub fn` occurs exactly
    once, so a `#[cfg(kani)]` / `#[cfg(not(kani))]` pair cannot let the two lineages prove different
    code;
  - **no stale model** — the gate re-extracts and diffs against the committed `Der*Extract.lean`,
    and `gates/check_lid_staleness.py` is the per-commit tripwire between full runs.
  Those close *drift*. None of them closes *fidelity*, which is what A4 is.
  **fails-if:** an Aeneas/Charon translation bug affecting a construct this crate uses; a lid
  theorem that contradicts a Kani result on the overlapping (bounded) domain — the two lineages
  cross-check each other there, and a disagreement is the loudest signal available;
  a `--opaque` carve-out silently growing to cover a function a lid's theorem *mentions*
  (audited by hand in `evidence/AXIOM-AUDIT-2026-08-18.md` §1b; not gated).
  **load-bearing-for:** every ∀-length claim, and the crate's headline that six codecs are proven
  over inputs of any length.

- **A5 · The toolchain pins name what is actually installed and behave per their semantics.**
  rustc compiles per its reference, `cargo test` runs what it says, and the pins in
  `PROOF_MANIFEST.md` §2 correspond to the binaries used. One of those pins is deliberately weak and
  is called out here rather than only there: **the rustc pin is a floating `stable` channel, not a
  version**, so the compiler that builds and tests this crate is a property of your run, not of this
  crate. The Kani harnesses are insulated (Kani ships its own toolchain) and the lids are insulated
  (exact Aeneas/Charon/Lean pins, gated); `cargo test` is not.
  **fails-if:** a miscompilation report at the versions in use; a `cargo test` result that differs
  across stable toolchains; toolchain supply-chain compromise.
  **load-bearing-for:** the bridge from "the verified model" to "the code you compile"; all 472 unit
  and regression tests; every reproduction of these results on another machine.

## 2. The crate's own assumptions — the ones that are ours, not the tools'

- **A6 · The lids' declared axioms are what they claim to be — and two of them are assumptions about
  this crate's own code, discharged by a proof in a sibling lid rather than by an import.** The six
  lids declare **15** `axiom`s (17 until 2026-08-19; see the tombstone below). They were
  audited once, by hand, against upstream sources
  (`evidence/AXIOM-AUDIT-2026-08-18.md`), with this result:
  - **13 are upstream-primitive specs** — characterisations of rustc `core` functions Aeneas does
    not model (`<[T]>::first`, `Option::is_some_and`, `Result::map_err`,
    `<usize as TryFrom<u32>>::try_from`, `&u8 & u8`), each verified faithful against the actual
    `core` source at the extraction toolchain's pinned nightly.
  - **2 are assumptions about `der-verified`'s own translated code**, not about Aeneas's Std library
    — which is *not* what `PROOF_MANIFEST.md` §3.2's generated column heading says, and the audit
    says so.
    - `length_decode_total` ×2 (`TlvProofs.lean`, `SequenceProofs.lean`) — **discharged elsewhere**:
      entailed by `LengthProofs.lean`'s unhypothesised, sorry-free
      `decode_accepts_only_canonical`, transferred across an extraction-namespace boundary **by a
      hand argument**, not by an import. That transfer is the assumption; the fact itself is proved.
  Blast radius, stated precisely because it is narrow: each is consumed to obtain the `ok` shape of
  `decode_length` before the composition proof continues. A falsehood would make the `tlv`/`sequence`
  ∀-length triples unprovable rather than silently wrong — but it would not be *noticed* by any gate,
  which is why it is an assumption and not a proof.
  **fails-if:** the two extraction passes' `length.decode_length` turn out not to be the same
  function (the audit checked this mechanically, by normalising the namespace token and diffing all
  `length.*` declarations across the three extracts); an audit of a *new* axiom finds a genuinely
  false assertion; the census gate the audit proposes (§4) is built and disagrees with the 13/2 split.
  **load-bearing-for:** the `tlv` and `sequence` ∀-length theorems in full; the honest one-line
  statement of the ∀-length trust base.
  **Named follow-up:** `length_decode_total` ×2 is now discharged the same way its former companion
  was — `LengthProofs.lean`'s `decode_length_used_le_spec` is unhypothesised, so
  `∃ r, decode_length s = ok r` follows from it in three lines *inside each lid's own namespace*,
  which would close the hand-argument transfer as well. Not done here: it was outside the scope of
  the 2026-08-19 change, and it is recorded so the next session does not have to rediscover it.
  *Not gated:* a declared axiom characterising an upstream primitive and a bespoke assumption about
  this crate's code are syntactically identical. Nothing mechanically distinguishes them today —
  the discriminator exists (Aeneas's `@[rust_fun]` attribute and `Source:` docstring) and the gate
  that would use it is designed but not built.

- **A7 · "Bounded" means bounded — a Kani harness says nothing whatsoever about inputs outside its
  domain.** Every L3 property is proven over a fixed-width symbolic buffer with a stated
  `#[kani::unwind]` depth. Inputs wider than the buffer, or needing more loop iterations, are **not
  claimed**: not "probably fine", not "expected to hold", not claimed. This is the manifest's own
  discipline (`PROOF_MANIFEST.md` §§3.1, 6.1, 8.1) and it is repeated here because it is the
  assumption a reader is most likely to make on the crate's behalf without noticing. Two places
  where the gap is explicitly *not* machine-checked away, and instead rests on a compositional
  argument plus one concrete fixture: `x509_certificate` (panic-freedom proven ≤ 12 bytes; a real
  certificate is ~170) and `rsa_private_key` (≤ 20 bytes; a real two-prime key is ~317).
  **fails-if:** a defect found at a size above a harness's bound — which no artifact here would
  catch, by construction. The honest statement is that this assumption fails *silently* unless
  someone widens a bound or writes a lid.
  **load-bearing-for:** every use of this crate on real-world-sized inputs, which is all of them.

- **A8 · The three disclosed-unsatisfiable covers are an arithmetic artifact of a reduced bound, not
  a dead proof.** Three harnesses report `0 of 1 cover properties satisfied` at their bounds —
  `x509_extension::validate_extensions_never_panics`,
  `x509_tbs_certificate::parse_tbs_certificate_never_panics`, and
  `x509_validity::parse_never_panics`. The claim is that the buffer is simply too small for a
  well-formed object to exist inside it (a minimal `Validity` needs ~32 octets against a 16-octet
  buffer, etc.), so what those harnesses prove is panic-freedom over a domain consisting entirely of
  rejecting paths — real, but narrower than the name suggests. The byte-count arguments are
  hand-derived, not machine-checked. Each is paired with a positive-construction witness sibling,
  and for `x509_tbs_certificate` **that witness is itself stub-mediated**, so it evidences the glue
  under stub semantics, not that the real composition accepts anything.
  **fails-if:** the arithmetic is wrong and a well-formed object does fit (then the cover is
  unsatisfiable for a *reason nobody has diagnosed*, which is the interesting case); a widened bound
  leaves the cover unsatisfied.
  **load-bearing-for:** reading those three `never_panics` results as meaningful rather than
  vacuous. `./check.sh` does **not** fail on an unsatisfied cover — this is disclosed, not enforced.

- **A9 · Every stub's assumed postcondition is discharged by a named sibling harness.** Eight
  harnesses are modular proofs: a sub-parser is replaced by a `#[kani::stub]` whose return value is
  constrained by `kani::assume`. Those constraints are the one place in the crate where an
  unjustified `assume` would be an unsound hole rather than a narrowed domain. The claim is that
  each is proven separately (`PROOF_MANIFEST.md` §8.4), and that the stubs otherwise
  over-approximate (returning `Ok` and `Err` nondeterministically, which cannot hide a panic).
  **fails-if:** a stub constraint with no sibling harness proving it; a sibling harness whose proven
  postcondition is weaker than the constraint the stub assumes. Both are review-checked, not gated:
  the manifest's stub table is generated, but the *correspondence* between an assumed postcondition
  and its discharging theorem is a human reading.
  **load-bearing-for:** the `x509_name` / `x509_tbs_certificate` / `x509_certificate` /
  `rsa_private_key` composition proofs.

- **A10 · Every oracle is a human reading of the standard.** The crate's strongest harnesses are
  biconditionals against a hand-written reference predicate. A proof of agreement with an oracle
  that misstates X.690 is a machine-checked proof of the wrong thing, and nothing in this repository
  checks an oracle against the standard. The same applies to the `profile` module's reading of
  RFC 5280 and to every "canonical"/"minimal" judgement in the crate.
  **fails-if:** an interoperability differential against another DER implementation; a standard
  erratum; a reviewer reading the oracle back against the text. The specific hazard is a *shared*
  misreading: an oracle shaped like the implementation would agree with it and both be wrong, which
  is why `big_integer`'s oracle is independently phrased (`PROOF_MANIFEST.md` §8.3).
  **load-bearing-for:** every canonicality, minimality and classification claim — i.e. the
  parser-differential value the crate exists for.

- **A11 · The hand-written half of the documentation is honest and current.** The manifest's
  generated regions are derived and gated; everything outside them — the claims, the scope fence,
  the deviations list, every measured number (peak RAM, wall-clock, byte counts) and every date — is
  a maintainer's assertion. The gate detects *inventory* changes only: it does not notice a weakened
  `assert!`, a deleted `cover` in a harness that keeps its `assert`, a tightened `assume`, or a
  rewritten oracle body. **A green gate is not a statement that the verification did not get
  weaker.**
  **fails-if:** a re-review finding a claim with no artifact behind it — which has happened in this
  crate's own history and is why the mutation-control and axiom-audit evidence files exist; a
  generated region disagreeing with a prose sentence beside it (also observed, and the reason §4.1's
  classification list is checked against §5 rather than trusted).
  **load-bearing-for:** everything in `PROOF_MANIFEST.md`, `README.md` and this file that a gate
  does not re-derive — including this list's own accuracy.

- **A12 · The eleven unharnessed entry points are total by inspection.** Ten delegating wrappers and
  accessors carry no Kani harness of their own (the eleventh, `Charset::tag_number`, is symbolically
  executed inside harnesses that do not name it). For the wrappers the argument is a one-line body
  delegating to a harnessed function — a human argument, recorded as one (`PROOF_MANIFEST.md` §4.1).
  A transposed constant in a wrapper (`decode_ia5_string` delegating with the wrong `Charset`) would
  satisfy every proof cited and is covered by `#[test]` cases only.
  **fails-if:** a defect found in a wrapper by test or by use.
  **load-bearing-for:** any reading of "this crate's public API is proven panic-free" that includes
  those eleven names. The manifest declines that reading explicitly.

## 3. Out of focus — parked, not gone

Assumptions that are almost never the interesting failure, kept in the list because "almost never"
is itself an assumption.

- **A13 · The package registries and toolchain channels deliver the bytes their pins name**
  (crates.io, rustup/elan channels, the Aeneas/Charon revisions cloned by hand).
  **fails-if:** a lockfile/hash mismatch; a registry compromise disclosure.
  **load-bearing-for:** every build and every reproduction of these results.
- **A14 · The machine that produced the committed evidence was uncompromised, and its clock and
  filesystem are honest.** Every `evidence/*.log` is trusted to be the log the run wrote.
  **fails-if:** a sha256 mismatch on re-capture; a timestamp ordering that cannot be true.
  **load-bearing-for:** the entire evidence chain — §3.4's run table and every control campaign.
- **A15 · Git's object integrity holds**, so a commit-pinned claim names the content it appears to.
  **fails-if:** a practical collision attack against the hash in use.
  **load-bearing-for:** every "verified at commit X" statement, including the lid staleness gate.

## §T Tombstones — assumptions that were discharged

- **A6a · `length_decode_used_le` ×2 — the two lid axioms that were assumed and discharged nowhere.**
  *Was:* half of A6. `TlvProofs.lean` and `SequenceProofs.lean` each DECLARED, as an `axiom`, that an
  accepted `length.decode_length` never reports consuming more bytes than its input holds
  (`decode_length s = ok (.Ok (v, l_used)) → l_used.val ≤ s.val.length`). Its warrant was a reading
  of `der-verified/src/length.rs:74-109` plus bounded Kani — true of the shipped code, but not
  machine-checked. `evidence/AXIOM-AUDIT-2026-08-18.md` §2.7 named it the audit's one real residual.
  **Discharged 2026-08-19 by proof.** `LengthProofs.lean`'s `decode_length_used_le` (with
  `decode_length_used_le_spec`, `decode_length_loop_total`, `low7_eq_mod`) proves it as a branch walk
  over `decode_length`; the same proof, character-for-character, now stands in `TlvProofs.lean` and
  `SequenceProofs.lean` in place of the two axioms, because Aeneas's per-pass namespaces make the
  theorem un-importable across lids (the copies are `diff`-checkable, which is what replaces the
  import). The three theorems' disclosed axiom set is
  `[propext, Classical.choice, Quot.sound, first_spec, core.slice.Slice.first]` — no `bv_decide`
  certificate, no `sorryAx`, and no crate-code assumption.
  **Artifacts:** `lean/LengthProofs.lean` (§"The consumption bound"), the corresponding sections of
  `lean/TlvProofs.lean` / `lean/SequenceProofs.lean`; a green `lean/check_lean.sh` (re-extraction +
  drift + sorry-gate); the discharge addendum in `evidence/AXIOM-AUDIT-2026-08-18.md`; and the
  three planted-mutation negative controls in `evidence/LID-MUTATION-CONTROLS-2026-08-19.md`
  (M7–M9), which confirm the new statements are load-bearing rather than vacuous.
  **What did NOT change:** the security-relevant `used ≤ input.length` conclusion the `tlv`/`sequence`
  lids sell still comes from `decode_tlv`'s own runtime guard, exactly as before. This closed an
  assumption, not a gap in a headline.

An entry arrives here only with the artifact that closed it named; that is what makes the
list above shrinkable without making it quietly editable.

---

**Where the rest of the envelope lives:** `PROOF_MANIFEST.md` (what is proven, over what bounds,
with what stubs, and what is *not* proven), `DECISIONS.md` (why the profile is narrowed the way it
is), `evidence/` (the run logs and the control campaigns these entries cite).
