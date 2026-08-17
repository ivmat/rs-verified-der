---
type: decision-memo
status: owner decides — not decided in this session
---

# `no_std` — decision memo (2026-08-17)

## Why this memo exists

`PROOF_MANIFEST.md` claimed the crate is `no_std`. It is not: nothing in `der-verified/src` carries
`#![no_std]`, and `TODO.md:151-174` records this as an open, deliberately-not-landed item ("SCOPED
2026-08-03, deliberately NOT landed"). That is a real claim/reality gap in the crate's own honest
proof envelope — the document whose entire point is to not overclaim — so it is fixed here rather
than left. This memo does **not** decide whether to add `#![no_std]`; it lays out the two options so
the owner can. The *wording* fix (making the manifest's prose match what is actually true right now)
is applied separately and is small enough not to need a decision — see "Immediate fix" below.

## What is actually true today (measured, not re-measured in this session — see `TODO.md:155-166`)

- **Exactly one `std::` path in all of `der-verified/src`**, and it is inside a `#[test]`
  assertion *message*, not library code (`utf8_string.rs:507` per the 2026-08-03 measurement).
- **All `Vec`/`String`/`vec!`/`Box` occurrences are inside `#[cfg(test)]` modules** — test-only
  builders, not reachable from a non-test build.
- Zero runtime dependencies (`der-verified/Cargo.toml`'s `[dependencies]` is empty).
- `#![forbid(unsafe_code)]`, and the decode paths are allocation-free.
- `thumbv7em-none-eabi` was installed on the measuring box on 2026-08-03, so `cargo build --target
  thumbv7em-none-eabi` is available as a mechanical check of the `no_std` claim, the same shape of
  fix the crate's MSRV declaration got when it went from an unchecked number to a gated one.
- The crate's own module docs (`x509_name.rs`, `big_integer.rs`) already argue for a heap-free,
  validate-don't-materialize design — `#![no_std]` would be consistent with, not a departure from,
  the existing design stance.
- **Blocker recorded 2026-08-03, unresolved at this writing:** the L3 Kani proof floor cannot
  currently be run to completion on this box — `evidence/FLOOR-2026-08-03.md` documents an
  OOM-kill under a computed 20 GiB `MemoryMax` cap, below the crate's own documented ~22-24 GiB
  requirement. This session was explicitly told not to start any Kani/CBMC solver runs, so that
  blocker is neither re-confirmed nor re-measured here — it is carried forward as-is from
  `TODO.md`/`evidence/FLOOR-2026-08-03.md`.
- **Unsettled question named in `TODO.md:171-174`:** whether `cargo kani` sets `cfg(test)`. If it
  ever does, a naive `#![cfg_attr(not(test), no_std)]` would silently verify the `std` configuration
  instead of the shipped one — `TODO.md` already prescribes guarding this with a
  `#[cfg(all(kani, test))] compile_error!(...)` rather than resting on the assumption.

## Option A — add `#![no_std]` and gate it

**Shape.** `#![cfg_attr(not(test), no_std)]` (or an explicit `std`/`no_std` Cargo feature, per the
TODO item's phrasing "gated on a `std` feature") on `der-verified/src/lib.rs`, plus:

1. A CI/gate job that builds `--target thumbv7em-none-eabi` (or another `no_std` target) so the
   claim is *mechanically* checked going forward, not just true at the moment it is added — the
   same discipline `rust-version` got when it moved from a hand-typed guess to a measured, gated
   value.
2. The `#[cfg(all(kani, test))] compile_error!(...)` guard `TODO.md` already names, so a future
   Kani-sets-`cfg(test)` toolchain change fails loudly instead of silently verifying the wrong
   configuration.
3. `PROOF_MANIFEST.md`'s inventory prose (the line this memo's companion edit corrects) would flip
   back to asserting `no_std` — truthfully, this time, and backed by (1).
4. A fresh full run of the L3 Kani floor and the L4 Lean lid against the changed source, because
   `#![no_std]` is a `der-verified/src` change and `VERIFIED_PATHS` in
   `gates/gen_proof_manifest.py` treats any such change as invalidating the currently-committed
   proof evidence (`evidence/`'s `covers_head_source` derivation). The manifest would report "no
   run currently speaks for HEAD" until that happens.

**Costs / risks.**

- **Blocked on the memory ceiling, not on the code change itself.** The source edit is small and
  well-scoped (measured above), but landing it *without* a fresh floor run would ship the crate
  with source that has never been proved — weaker evidence than the crate currently has, to buy a
  capability nothing is waiting on. This is exactly the reasoning `TODO.md` already gives for not
  landing it on 2026-08-03, and nothing has changed that reasoning since (this session did not
  attempt to re-run the floor, per its constraints).
- A `std` feature (if chosen over a blanket `cfg_attr`) is itself API-surface-shaped: once
  published, removing or renaming it is a breaking change under semver, same as any other public
  Cargo feature.
- The `cargo kani`/`cfg(test)` question is unsettled; shipping without the guard risks a silent
  soundness gap (proving the wrong configuration) that nothing in this crate would currently catch.
- Ongoing gate cost: a new mechanical `no_std`-target build check to maintain, and a fresh L3/L4
  run to keep current every time `der-verified/src` changes thereafter (this is not new — it's the
  existing `VERIFIED_PATHS` discipline extending to one more claim).

**What it changes in `PROOF_MANIFEST.md`/gates.** The §1 inventory prose reasserts `no_std`
(truthfully); `gates/gen_proof_manifest.py`'s `VERIFIED_PATHS` mechanism already handles staleness
correctly (no script change needed there — it just needs a fresh evidence run to point at); a new
gate script (or CI job) needs to exist for the `no_std`-target build itself, since nothing today
builds this crate against a bare-metal target.

## Option B — drop the claim (what this session already did, minimally)

**Shape.** State plainly that the crate is not `#![no_std]` today, and point at `TODO.md` for the
open item and its status. This is the smallest honest fix and has already been applied to
`PROOF_MANIFEST.md` §1 in this session (see "Immediate fix" below) — it does not require the owner
decision this memo asks for; it is a correction of a currently-false statement, not a design choice.

**Costs / risks.**

- None structurally — it is strictly a truth repair, not a scope change. The crate keeps its
  current, already-`no_std`-*ready* shape (measured above) without committing to the mechanical
  guarantee `#![no_std]` + a gate would provide.
- The differentiator `TODO.md:153-154` names ("a zero-dep, formally-verified DER core usable in
  embedded / bootloader / kernel contexts") stays unclaimed until Option A lands. A `no_std`
  consumer today has to take it on faith (or verify it themselves) rather than have the crate
  assert and gate it.
- Leaves `TODO.md`'s open item exactly where it already was — this is not a regression, just a
  non-decision.

**What it changes in `PROOF_MANIFEST.md`/gates.** Nothing beyond the wording already corrected;
no new gate, no new evidence run required, no proof re-run needed for the 0.1.1 release.

## Immediate fix applied in this session (not a decision — a correction)

`PROOF_MANIFEST.md` §1's hand-written prose (just below the generated inventory table, not inside a
`<!-- BEGIN GENERATED -->` region, so hand-editable directly) previously read:

> Zero runtime dependencies (…), `no_std`, no `alloc` on the decode paths, and
> `#![forbid(unsafe_code)]`.

This asserted an attribute the crate does not carry. It now reads:

> Zero runtime dependencies (…), no `alloc` on the decode paths, and `#![forbid(unsafe_code)]`.
> **Not `#![no_std]` today** — the crate does not carry that attribute, though the source is
> `no_std`-*ready* by measurement (see `TODO.md`'s "`no_std` support" item and this memo for the
> add-vs-drop tradeoff; this line is corrected to say so rather than claim the attribute exists).

This is the smallest change that makes the sentence true. It does not resolve Option A vs. Option
B; it only stops the manifest from asserting the Option-A outcome while the crate is actually in
the Option-B state.

## Recommendation

**Option B for the 0.1.1 release; Option A only once the L3 floor can be run to completion on
available hardware (or budget for a bigger box / a memory-reduced harness split), never landed
without a fresh proof run covering the changed source.** The reasoning:

- The crate's honest-envelope discipline (`PROOF_MANIFEST.md`'s own stated rule: "where a claim
  would be stronger than the evidence, the evidence wins and the claim is narrowed") argues
  directly against landing `#![no_std]` while the floor that would verify it cannot complete here.
- Nothing is currently waiting on the `no_std` capability — `TODO.md` calls it "Low priority; a
  strong differentiator when done", not a blocker for anything scheduled.
- The source-side work is cheap and already scoped (this memo's Option A section), so Option A
  is not being deferred for lack of a plan — only for lack of a machine that can complete the
  floor, or a plan to split/reduce that floor's peak memory.

**Owner decides.** This memo does not choose between A and B; it exists so the owner can, with the
costs of each laid out. If the owner picks Option A, `TODO.md`'s existing scoping (the `cfg(test)`
guard, the `thumbv7em-none-eabi` target, the fresh floor run) is the plan to execute against.
