# der-verified — remaining verification work (map for the driver)

**Status as of 2026-07-21, after Task A (x509_validity cover-vacuity close, commit `cd4a365`).**
Not committed by this pass (uncommitted map file — driver commits). Sources: `PROOF_MANIFEST.md`,
`docs/verification-cost.md`, `TODO.md`, `METHODS-APPLICATION-ANALYSIS-2026-07-21.md`, and a direct
grep of `der-verified/src/*.rs`.

**UPDATE 2026-07-22: §3's next-valuable-lid item is CLOSED — landed as the 4th L4 lid, on `tlv`
(DECISIONS.md D27, `lean/TlvProofs.lean`, `decode_tlv_structure`).** Priority-1 pick from §3 below:
the first L4 coverage on the crate's structural *composition* layer (not another leaf codec) —
`decode_tlv`'s structural/no-over-read correctness, ∀-length. Required a one-line behavior-
preserving source fix (`tlv.rs`'s point-free `.map_err(TlvError::Tag)` → an explicit closure, to
unblock an Aeneas naming-clash on extraction — a *different* pre-flight issue than §3's flagged
depth-2-return rule, though `decode_tag`'s own early-return-in-a-loop shape was also hit and
disclosed via an assumed spec rather than refactored in this pass). 7 disclosed assumed specs (2
of which restate an already-`sorry`-free-proved `LengthProofs.lean` fact, working around a
duplicate-extraction Lean-namespace collision, not new unverified trust). `check_lean.sh`
extended (drift-guard + cfg-split guard for `tlv.rs`) and confirmed **non-vacuous** via a
sorry-injection test (fails closed, then reverted). Full `sh check_lean.sh`: green, 1700 jobs,
`PASS (sorry-free)`. Der's Lean track is now **4 lids**: `length`, `big_integer`, `oid`, `tlv`.
Next, if pursued: the larger `sequence`/consumer-walk lid (§3's item 1's OTHER half — a genuinely
bigger separate piece, since `sequence` walks an unbounded child count, a loop `decode_tlv` itself
lacks), or a D25-style refactor of `tag.rs` to fully de-opaque `decode_tag` (would leanen `tlv`'s
own trust surface too).

**UPDATE 2026-07-22 (later same day): the `sequence`/consumer-walk lid flagged above is ALSO
CLOSED — landed as the 5th L4/L5 lid (DECISIONS.md D28, `lean/SequenceProofs.lean`,
`decode_sequence_structure`).** The crate's first **unbounded-LOOP** lid: `decode_sequence`'s
structural/no-over-read correctness, ∀-length AND ∀-children (`tlv::decode_tlv`, composed here, is
itself loop-free — Kani's own `#[kani::unwind(16)]`-capped harness is inherently bounded on BOTH
buffer width and trip count; this lid removes both caps). Required the SAME map_err name-clash fix
as D27, this time in `sequence.rs` (`decode_sequence_tlv`'s `.map_err(SequenceError::Tlv)`), plus a
genuinely NEW Aeneas limitation surfaced and worked around: the `Iterator` trait's `step_by`/
`enumerate`/`take` default-method fields are not auto-filled by Aeneas for a hand-written `impl
Iterator` that only defines `next` (as `Elements` does) — a real codegen gap for user-defined
iterators (library iterators get hand-specialized adapters in Aeneas's own Std; a user type gets
none). Fixed by a documented, re-runnable `check_lean.sh` patch step that fills the three fields
with Aeneas's own generic default-method combinators (inert scaffolding — none of the three is ever
called by the functions this lid proves anything about). Reuses the SAME 7 disclosed assumed specs
as `tlv`'s D27 lid (restated for this pass's own extraction namespace, per the established
duplicate-extraction-namespace pattern). Proved via `loop.spec_decr_nat` with measure
`iter.rest.length`, strictly decreasing every accepted child — the mechanism that lets the
induction close for *any* number of children. `check_lean.sh` extended (drift-guard + cfg-split
guard for `sequence.rs` + the Iterator-fields patch step) and confirmed **non-vacuous** via a
sorry-injection test at BOTH the single-file `lake build` level and the full-gate level (fails
closed both times, then reverted). Full `sh check_lean.sh`: green, 1702 jobs, `PASS (sorry-free)`.
Der's Lean track is now **5 lids**: `length`, `big_integer`, `oid`, `tlv`, `sequence`. Next, if
pursued: a D25-style refactor of `tag.rs` to fully de-opaque `decode_tag` (would leanen both `tlv`'s
and `sequence`'s trust surfaces).

**UPDATE 2026-07-21/22 (dedicated 32 GB box, no other worker, 28 GB cgroup cap):** both items in
§2's "Cloud Kani" table below are now CLOSED locally — neither needed a cloud box after all; the
prior OOMs were shared-box working-set pressure, not a genuine >32 GB wall.
`x509_name::validate_rdn_never_panics` converged `VERIFICATION: SUCCESSFUL` (peak RSS ~17.1 GiB,
wall ~851 s / ~14.2 min) — no cover on this harness (by design; the cover lives on its sibling
`validate_never_panics`, itself cheap/green, `1 of 1` satisfied). `x509_extension::validate_extensions_never_panics`
ALSO converged `VERIFICATION: SUCCESSFUL` this time (peak RSS ~20.5 GiB, wall ~602 s / ~10 min) —
but surfaced a genuine, previously-undetermined **cover vacuity** (`0 of 1 cover properties
satisfied`): the module's own doc-comment arithmetic for the 13-octet buffer was wrong (a real
two-`Extension` `Extensions` needs 16 octets, not 13), so the walk's claimed "genuine second
iteration" never co-occurs with a real `Ok` at that buffer size. Closed the same way as the two
prior vacuities (positive-construction witness, no stub needed): new harness
`x509_extension::validate_extensions_ok_path_witnessed` on a concrete, hand-built minimal
two-`Extension` `Extensions` (16 octets) — `VERIFICATION: SUCCESSFUL`, `1 of 1 cover properties
satisfied`, peak RSS ~16.7 GiB, wall ~201 s. A full crate-wide `cargo kani -Z stubbing` re-run
(164 harnesses, sequential, same 28 GB cap) afterwards: **164/164 SUCCESSFUL, 0 failures** — the
only three `0 of 1` (vacuous, unsatisfiable-by-design) covers remaining are the three
already-documented ones (`x509_validity::parse_never_panics`, `x509_tbs_certificate::parse_tbs_certificate_never_panics`,
and now `x509_extension::validate_extensions_never_panics`), each immediately preceded in the run
by its own `1 of 1`-satisfied positive-construction witness sibling. **Der's two remaining heavy
items are now fully closed, local, no cloud needed.**

## 1. Local Kani (cheap, doable on the 32 GB box under the ~12 GB shared-box cap) — anything left?

**No open local-Kani work identified.** The 2026-07-21 cover-retrofit swept every proof module:
23 of 25 source modules with `#[kani::proof]` now also carry `kani::cover` (the 2 without —
`boolean`, `null` — have **no `kani::assume`** narrowing their domain at all: they exhaustively
characterize a 1-byte input space via `assert!` biconditionals, so a cover would be redundant, not
a gap; this is a checked negative, not an oversight). `x509_validity` and `x509_tbs_certificate`
each had one vacuous `Ok`-tail cover (the T6/T2-COROLLARY-A finding); both are now closed by a
positive-construction companion harness (tbs: `d2dc80d`; validity: `cd4a365`, this pass).

One small, genuinely-open, low-priority item surfaced while mapping this (not fixed in this pass,
out of Task A/B's scope): `enumerated::proofs::decode_delegates_to_integer` has an
`assume(n >= 1 && n <= 8)` narrowing the symbolic length, with no `kani::cover` confirming a
representative spread of `n` (or both `Ok`/`Err` outcomes) is actually reachable through the
delegation. Likely benign — `enumerated` is a thin re-tag of `integer`, whose own proofs already
cover this shape — but it is the one remaining `assume`-without-`cover` pattern in the crate found
during this scoping pass. Cheap to check (single small proof, no stubs, sub-second historically for
this module) if the driver wants a genuinely-exhaustive local-Kani close-out.

Everything else in the local-Kani tier is measured fast (sub-second to tens of seconds; the `set_of`
/`sequence`/`utf8_string` family runs 79–256 s but is TIME-heavy, not RAM-heavy, and already green —
see `docs/verification-cost.md`).

## 2. Cloud Kani — RESOLVED, neither needs cloud (both closed locally, 2026-07-21/22)

**Superseded by the 2026-07-21/22 dedicated-box pass (see the UPDATE note at the top of this
file).** Both harnesses previously suspected to need a bigger-than-32GB box turned out to be
shared-box working-set artifacts, not genuine >32 GB walls — on a DEDICATED 32 GB box (28 GB
cgroup cap, no other worker), both converged:

| Harness | Peak RSS (dedicated box) | Wall | Status |
|---|---|---|---|
| `x509_name::proofs::validate_rdn_never_panics` | **~17.1 GiB** | ~851 s (~14.2 min) | `VERIFICATION: SUCCESSFUL`, 0 of 300 failed. No `kani::cover` on this harness itself (by design — the cover lives on sibling `validate_never_panics`, which is cheap: ~5.6 s, `1 of 1 cover properties satisfied`). |
| `x509_extension::proofs::validate_extensions_never_panics` | **~20.5 GiB** | ~602 s (~10 min) | `VERIFICATION: SUCCESSFUL`, 0 of 255 failed — BUT surfaced a genuine, previously-undetermined cover vacuity: `0 of 1 cover properties satisfied`. The module's own "13 octets leaves room for a genuine second iteration" doc-comment claim was arithmetically wrong (two minimal `Extension`s + envelope = 16 octets, not 13). Closed the same way as the `x509_validity`/`x509_tbs_certificate` precedent: a new positive-construction witness harness, `validate_extensions_ok_path_witnessed`, on a concrete hand-built 16-octet two-`Extension` `Extensions` — `VERIFICATION: SUCCESSFUL`, `1 of 1 cover properties satisfied`, ~16.7 GiB peak RSS, ~201 s wall. No stub needed (same shallow-composition pattern as `x509_validity`'s witness). |

Neither needed a code change to converge — same harness, same buffer, same unwind bound as
originally written; just isolation from shared-box memory pressure via a per-harness `systemd-run
--scope -p MemoryMax=28G -p MemorySwapMax=0` cgroup cap. Both solvers (cadical default, kissat via
T7) had previously been tried on the shared box and OOM'd around 16–19 GB; the true peaks (~17.1
and ~20.5 GiB) fit comfortably under a real 28 GB cap. **No cloud run is needed for der.** A
full crate-wide re-run afterwards (164 harnesses, sequential, same cap) confirms **164/164
SUCCESSFUL, 0 failures**, with exactly the three expected (and now all closed-via-witness) vacuous
covers remaining as an honest record — see §4. No other der harness is RAM-walled; the
`set_of`/`sequence` family (79–256 s, ~5 GB) is TIME-heavy but not RAM-walled and was never a cloud
candidate.

## 3. Lean lids (Aeneas/Charon/Lean) — existing coverage + next lid

**5 sorry-free lids exist today** (D27 landed `tlv`, D28 landed `sequence` — both superseding this
section's earlier "3 lids"/"next lid" framing, kept below only for the historical trail), all
gate-enforced (`lean/check_lean.sh` fails closed on any `sorryAx`/"uses 'sorry'"), each
re-extracting from the shipped `.rs` (drift-guarded, not a stale snapshot):

| Codec | Lean file | Property (∀-length, unbounded) |
|---|---|---|
| `length` (§8.1.3) | `lean/LengthProofs.lean` | every branch of `decode_length`; round-trip canonicality (also proves both `encode_length` loops) |
| `big_integer` (§8.3) | `lean/BigIntProofs.lean` | minimality biconditional + encode-side round-trip/canonicality |
| `oid` (§8.19) | `lean/OidProofs.lean` | canonical-form biconditional (validate side) |
| `tlv` (§8.1, composing `tag`+`length`) | `lean/TlvProofs.lean` | `decode_tlv`'s structural/no-over-read correctness, ∀-length (D27) |
| `sequence` (§8.9/§8.10, composing `tag`+`length`+`tlv`) | `lean/SequenceProofs.lean` | `decode_sequence`'s structural/no-over-read correctness, ∀-length AND ∀-children — the crate's first unbounded-LOOP lid (D28) |

**All X.509 structural modules (`x509_*`) are Kani-only — no L4 lid.** Still the crate's one open
*breadth* item (not a defect — a deliberate, disclosed scope boundary per `PROOF_MANIFEST.md`'s L4
section).

**Next valuable lid, if pursued:**
1. A D25-style refactor of `tag.rs` to fully de-opaque `decode_tag` (currently a bodyless Aeneas
   axiom in both `tlv`'s and `sequence`'s lids, the early-return-in-a-loop shape) — would leanen
   both existing composition-layer lids' trust surfaces and unlock a standalone `tag` lid.
2. An X.509 structural-module lid (bigger scope, no consumer-walk precedent yet at that layer).
3. Pre-flight check before either: audit the candidate's control flow for a depth-2-nested `return`
   (the `writing-verifiable-rust.md` §4 rule — Aeneas silently emits a bodyless axiom/sorry-
   equivalent for this shape; `oid`'s own extraction needed exactly this refactor per D25) AND for
   a hand-written `impl Iterator`/similar trait impl relying on default methods (the D28-discovered
   `step_by`/`enumerate`/`take` codegen gap — same disclosed-patch workaround pattern applies).

No Lean work is blocked on Task A/B; this is a clean scoping item for whenever the driver wants to
invest in L4/L5 breadth next.

## 4. Vacuity findings — open?

**None open.** All three `kani::cover`-vacuity findings found across the 2026-07-21 cover-retrofit
and the 2026-07-21/22 dedicated-box heavy-harness pass are now closed:

- `x509_tbs_certificate::parse_tbs_certificate_never_panics`'s `Ok`-tail cover (UNSATISFIABLE at
  `[u8; 10]`) — closed by `parse_tbs_certificate_ok_path_witnessed` (commit `d2dc80d`, prior pass):
  3 `#[kani::stub]`s needed (`validate_name`, `validate_extensions`, `parse_validity`), ~11.3 GB
  peak RSS / ~206 s wall.
- `x509_validity::parse_never_panics`'s `Ok`-tail cover (UNSATISFIABLE at `[u8; 16]`) — closed by
  `parse_validity_ok_path_witnessed` (commit `cd4a365`, **this pass, Task A**): **no stubs needed**
  (shallow call graph — one outer `decode_tlv` + at most two `decode_time_tlv` calls, each a single
  inlined leaf time-decoder), ~0.58 GB peak RSS / ~6 s wall.
- `x509_extension::validate_extensions_never_panics`'s `Ok`-plus-second-iteration cover
  (UNSATISFIABLE at `[u8; 13]`, only DETERMINED on the 2026-07-21/22 dedicated-box run — previously
  the harness OOM'd on the shared box before reaching any verdict at all) — closed by
  `validate_extensions_ok_path_witnessed` (this pass, Task B/dedicated-box pass): **no stub
  needed** (same shallow-composition pattern as `x509_validity`'s witness), concrete 16-octet
  two-`Extension` `Extensions` fixture, ~16.7 GiB peak RSS / ~201 s wall.

Total: exactly **three** cover-vacuity findings have ever existed in this crate, all now closed by
a companion positive-construction witness harness, each left alongside its original (unmodified,
honestly-"0 of 1"-reporting) symbolic harness per the project's stated convention (a cover
reporting non-satisfaction IS the machine-checked evidence of the gap, not a bug to hide).

`x509_certificate::parse_certificate_never_panics` (the third, outermost modular-stub harness in
the DAG, stubbing `parse_tbs_certificate`) was checked directly during the earlier Task B pass:
`cargo kani --harness x509_certificate::proofs::parse_certificate_never_panics` → `VERIFICATION:
SUCCESSFUL`, **`1 of 1 cover properties satisfied`** (~48 s, cheap). **No vacuity gap here** — at
`[u8; 12]` with a symbolic length and ONE stub (`parse_tbs_certificate`, returning a nondet
`Result`), the happy path IS reachable, unlike `x509_tbs_certificate`/`x509_validity`/
`x509_extension`, whose deeper unstubbed compositions pushed the arithmetic floor for a real `Ok`
past their harnesses' buffers.

## Summary for dispatch

- **Local Kani:** done, crate-wide. A full sequential `cargo kani -Z stubbing` re-run of all 164
  harnesses under a 28 GB cgroup cap (2026-07-21/22, dedicated box): **164/164 SUCCESSFUL, 0
  failures.** One optional micro-check remains (`enumerated`'s unguarded `assume`) if the driver
  wants a fully exhaustive close-out — not a real gap.
- **Cloud Kani:** RESOLVED — **neither heavy harness needs a cloud box.** Both
  `x509_name::validate_rdn_never_panics` (~17.1 GiB peak, ~14.2 min) and
  `x509_extension::validate_extensions_never_panics` (~20.5 GiB peak, ~10 min) converge
  `VERIFICATION: SUCCESSFUL` under a dedicated 28 GB cap; the prior OOMs were shared-box working-set
  pressure, not a genuine >32 GB wall. Der's cloud-candidate list is now empty.
- **Lean:** both `tlv` (D27) and `sequence` (D28) consumer-correctness lids are now landed
  (5 sorry-free lids total). Next, if pursued: a D25-style `tag.rs` refactor to fully de-opaque
  `decode_tag` — owner-scoped, not urgent.
- **Vacuity:** closed (tbs, validity, and now extensions); `x509_certificate` checked directly —
  not vacuous (`1 of 1` cover already satisfied). Total: exactly 3 findings ever existed, all now
  closed.
