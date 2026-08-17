---
type: decision-memo
status: owner decides — not decided in this session
---

# `no_std` — decision memo (2026-08-17)

> **Revised same-day, after a release-review pass on the first draft.** The original version
> carried the 2026-08-03 OOM-kill (`evidence/FLOOR-2026-08-03.md`) forward as an *unresolved,
> current* blocker on Option A ("blocked on the memory ceiling"). That review pointed at
> `evidence/check-ffcea81.log:5,12` (committed 2026-08-11, `ca0754f`): a full `./check.sh` run on
> this same box under a *fixed*
> `MemoryMax=22G` cap completed **SUCCESSFULLY**, peaking at **21.0 GB**. That run predates this
> memo's first draft, so citing the 2026-08-03 figures as current was stale, not wrong-when-written
> — but it changes the central claim about Option A from "blocked" to "feasible, costs release
> time." The sections below are corrected accordingly; the 2026-08-03 facts are kept, re-labelled as
> historical/superseded, because they are still true of *that specific run* and explain why the
> then-current cap was too small (it was *computed*, not the fixed 22G the 08-11 run used).

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
- **The 2026-08-03 OOM-kill is HISTORICAL, and superseded.** The first version of this memo
  carried `evidence/FLOOR-2026-08-03.md`'s OOM-kill (under a *computed* 20 GiB `MemoryMax` cap,
  below the crate's ~22 GiB requirement) forward as an unresolved blocker on the same box. It is
  not current: **`evidence/check-ffcea81.log` (committed by `ca0754f`, dated 2026-08-11) records
  a full `./check.sh` run on this same box that completed SUCCESSFULLY** — 191/191 Kani harnesses
  `SUCCESSFUL`, 0 `FAILED`, under a *fixed, documented* `MemoryMax=22G` cap (not the 2026-08-03
  run's computed-and-too-low 20 GiB), peaking at a measured cgroup `memory.peak` of **21.0 GB**
  (line 12 of the log), wall-clock ~63 minutes. So the L3 floor is **not** blocked on this box's
  hardware — the 2026-08-03 finding was a too-small *computed* cap on that particular run, not a
  ceiling this box cannot clear. (This session did not re-run the floor itself — no Kani/CBMC
  solver runs were started here, per this session's constraints. The 21.0 GB figure is read out of
  the already-committed `evidence/check-ffcea81.log`, not freshly measured.)
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

- **FEASIBLE on this box, not blocked on the memory ceiling** — see "the 2026-08-03 OOM-kill is
  historical" above: the 2026-08-11 run already cleared the full floor at 21.0 GB peak under a
  22 GiB cap, on the same hardware. What Option A actually costs is a fresh full `./check.sh` run
  *against the changed source* (source that adds `#![no_std]` is different source than what
  `check-ffcea81.log` verified — `VERIFIED_PATHS` in `gates/gen_proof_manifest.py` is exactly the
  mechanism that says so), plus release time/headroom to run it (~63 minutes wall-clock per the
  08-11 log, plus the L4 Lean lid) and to review its result before publish. That is a real cost —
  it is release-time and reviewer-attention, not a hardware blocker — and it is the reason this
  memo still recommends B *for the 0.1.1 release specifically* below, not because A cannot be done.
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

**What it changes in `PROOF_MANIFEST.md`/gates.** Nothing beyond the wording already corrected; no
new gate, no new evidence run required *by this decision itself*. **Option B itself adds no
proof-run requirement** — but that is not the same as "no run is owed before publish": this
session's other fixes (task #20, item 3 in particular) already touched `der-verified/src`, so a
full `./check.sh` run is owed before `cargo publish` regardless of which `no_std` option is chosen.
Choosing B does not add a *second*, `no_std`-specific reason for one.

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

**Option B for the 0.1.1 release; Option A as a follow-up release, landed together with the fresh
full `./check.sh` run its source change requires.** Revised reasoning (the original draft of this
memo rested on Option A being infeasible on this hardware, which the 2026-08-11 evidence
contradicts — see above; the reasoning below no longer depends on that claim):

- Option A is **feasible, not blocked** — 21.0 GB peak under a 22 GiB cap, on this box, per
  `evidence/check-ffcea81.log`. So the case for B now rests on release SCOPE and TIMING, not on A
  being impossible: a full run is release-time (~63 minutes plus the L4 lid) and reviewer-attention
  cost that 0.1.1 does not currently have scheduled, and a fresh full run is owed before *this*
  release regardless (see "what it changes" under Option B) — adding `#![no_std]` on top would mean
  that same run also has to carry a new, not-yet-reviewed source change into a release that is
  already held on other items.
- Nothing is currently waiting on the `no_std` capability — `TODO.md` calls it "Low priority; a
  strong differentiator when done", not a blocker for anything scheduled, so there is no forcing
  function to bundle it into 0.1.1 specifically.
- The source-side work is cheap and already scoped (this memo's Option A section) — the honest
  reason to defer it is sequencing (land it deliberately, with its own review and its own fresh
  floor run) rather than folding an unplanned scope addition into an already-held release, not any
  infeasibility.
- The crate's honest-envelope discipline (`PROOF_MANIFEST.md`'s own stated rule: "where a claim
  would be stronger than the evidence, the evidence wins and the claim is narrowed") still argues
  against asserting `no_std` before its own gate and floor run exist — that part of the original
  reasoning holds regardless of the memory-ceiling correction above.

**Owner decides.** This memo does not choose between A and B; it exists so the owner can, with the
costs of each laid out. If the owner picks Option A, `TODO.md`'s existing scoping (the `cfg(test)`
guard, the `thumbv7em-none-eabi` target, the fresh floor run) is the plan to execute against — and
per the correction above, that floor run is now known to fit on this hardware.
