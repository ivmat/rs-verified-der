# der-verified — remaining verification work (map for the driver)

**Status as of 2026-07-21, after Task A (x509_validity cover-vacuity close, commit `cd4a365`).**
Not committed by this pass (uncommitted map file — driver commits). Sources: `PROOF_MANIFEST.md`,
`docs/verification-cost.md`, `TODO.md`, `METHODS-APPLICATION-ANALYSIS-2026-07-21.md`, and a direct
grep of `der-verified/src/*.rs`.

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

## 2. Cloud Kani (bounded-RAM walls needing a bigger box) — confirmed set

Exactly the two named in the task brief, both re-measured on this Linux 32 GB desktop
(`docs/verification-cost.md`, `METHODS-APPLICATION-ANALYSIS-2026-07-21.md` §"2.6 Cloud"):

| Harness | Measured RSS | Status |
|---|---|---|
| `x509_name::proofs::validate_rdn_never_panics` | **~17 GB peak RSS** | `VERIFICATION: SUCCESSFUL` — SAT/bounded, fits a genuine 32 GB box outright, just not this shared box's ~12 GB working cap. The heavy SET-OF/RDN §11.6 lemma at one-RDN scale; `validate_name` itself is proven cheaply (~0.5 GB) by *stubbing* this lemma's already-proven postcondition (`2 ≤ used ≤ input.len()`). |
| `x509_extension::proofs::validate_extensions_never_panics` | **~19 GB (cadical, default solver) / ~16 GB (kissat)** | Genuine RAM wall, **both solvers OOM at the same post-slicing SSA-encoding stage** (CBMC's own "appears to have run out of memory" verdict) — this one did NOT reach a verdict on the 32 GB box either (unlike `validate_rdn`, which converges SUCCESSFUL). `--slice-formula` (T8) is already Kani's default and did not help; classified RAM-bound, not TIME-bound. |

Both are **cloud-crushable** in the sense the task brief means (256 GB removes the wall trivially
for `validate_rdn` — SAT already, just wants headroom — and very likely for `validate_extensions`
too, though that one has not yet been observed to converge at any RAM size on this box; a cloud run
would be the first data point on whether it's a RAM-wall-with-a-ceiling or something structurally
larger). Neither needs code changes to attempt on cloud — same harness, same buffer, same unwind
bound, just run with more RAM. No other der harness is in this bucket; the `set_of`/`sequence`
family (79–256 s, ~5 GB) is TIME-heavy but not RAM-walled and is NOT a cloud candidate.

## 3. Lean lids (Aeneas/Charon/Lean) — existing coverage + next lid

**3 sorry-free lids exist today**, all gate-enforced (`lean/check_lean.sh` fails closed on any
`sorryAx`/"uses 'sorry'"), each re-extracting from the shipped `.rs` (drift-guarded, not a stale
snapshot):

| Codec | Lean file | Property (∀-length, unbounded) |
|---|---|---|
| `length` (§8.1.3) | `lean/LengthProofs.lean` | every branch of `decode_length`; round-trip canonicality (also proves both `encode_length` loops) |
| `big_integer` (§8.3) | `lean/BigIntProofs.lean` | minimality biconditional + encode-side round-trip/canonicality |
| `oid` (§8.19) | `lean/OidProofs.lean` | canonical-form biconditional (validate side) |

**All X.509 structural modules (`x509_*`) are Kani-only — no L4 lid.** `TODO.md` and the methods
analysis both flag "a 4th L4 lid" as the crate's one open *breadth* item (not a defect — a
deliberate, disclosed scope boundary per `PROOF_MANIFEST.md`'s L4 section).

**Next valuable lid (per the methods analysis, §2.3/§2.5), in priority order:**
1. **A `sequence` or `tlv` round-trip ∀-length correctness lid** — the analysis's top pick: a
   *consumer*-level correctness lid (not just another leaf codec) would be the first L4 coverage on
   the crate's structural composition layer, not just its primitive codecs. Real proof-engineering
   effort (T5 is "research-grade, selective" per the methods KB), not a quick win.
2. A 4th primitive **codec** lid (candidates deliberately excluded: `tag`/`boolean`/`null` are "too
   trivial to be worth a lid" per the analysis — no real ∀-length risk beyond what Kani already
   fully characterizes at 1–3 bytes).
3. Pre-flight check before either: audit the candidate's control flow for a depth-2-nested `return`
   (the `writing-verifiable-rust.md` §4 rule — Aeneas silently emits a bodyless axiom/sorry-
   equivalent for this shape; `oid`'s own extraction needed exactly this refactor per D25).

No Lean work is blocked on Task A/B; this is a clean scoping item for whenever the driver wants to
invest in L4 breadth next.

## 4. Vacuity findings — open?

**None open.** Both `kani::cover`-vacuity findings the 2026-07-21 cover-retrofit surfaced are now
closed:

- `x509_tbs_certificate::parse_tbs_certificate_never_panics`'s `Ok`-tail cover (UNSATISFIABLE at
  `[u8; 10]`) — closed by `parse_tbs_certificate_ok_path_witnessed` (commit `d2dc80d`, prior pass):
  3 `#[kani::stub]`s needed (`validate_name`, `validate_extensions`, `parse_validity`), ~11.3 GB
  peak RSS / ~206 s wall.
- `x509_validity::parse_never_panics`'s `Ok`-tail cover (UNSATISFIABLE at `[u8; 16]`) — closed by
  `parse_validity_ok_path_witnessed` (commit `cd4a365`, **this pass, Task A**): **no stubs needed**
  (shallow call graph — one outer `decode_tlv` + at most two `decode_time_tlv` calls, each a single
  inlined leaf time-decoder), ~0.58 GB peak RSS / ~6 s wall.

Both original vacuous-cover harnesses are left in place, unmodified, as the honest "0 of 1
satisfied" record — per the project's own stated convention (a cover reporting non-satisfaction
IS the machine-checked evidence of the gap, not a bug to hide).

`x509_certificate::parse_certificate_never_panics` (the third, outermost modular-stub harness in
the DAG, stubbing `parse_tbs_certificate`) was checked directly during this Task B pass:
`cargo kani --harness x509_certificate::proofs::parse_certificate_never_panics` → `VERIFICATION:
SUCCESSFUL`, **`1 of 1 cover properties satisfied`** (~48 s, cheap). **No vacuity gap here** — at
`[u8; 12]` with a symbolic length and ONE stub (`parse_tbs_certificate`, returning a nondet
`Result`), the happy path IS reachable, unlike `x509_tbs_certificate`/`x509_validity` whose deeper
unstubbed compositions pushed the arithmetic floor for a real `Ok` past their harnesses' buffers.
Confirms the crate has exactly two (now-closed) vacuity findings, not three.

## Summary for dispatch

- **Local Kani:** essentially done; one optional micro-check (`enumerated`'s unguarded `assume`) if
  the driver wants a fully exhaustive close-out — not a real gap.
- **Cloud Kani:** dispatch `x509_name::validate_rdn_never_panics` (~17 GB, expect SUCCESSFUL) and
  `x509_extension::validate_extensions_never_panics` (~19 GB, currently unresolved/OOM even at
  32 GB — genuinely worth a cloud run to get a first convergent data point) to a 256 GB box.
- **Lean:** next lid is a `sequence`/`tlv` round-trip ∀-length *consumer* correctness lid — real
  effort, owner-scoped, not urgent.
- **Vacuity:** closed (tbs + validity); `x509_certificate` checked directly this pass — not vacuous
  (`1 of 1` cover already satisfied). Total: exactly 2 findings existed, both now closed.
