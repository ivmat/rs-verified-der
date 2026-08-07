# Proof manifest — `der-verified`

This is the **honest proof envelope** for this crate: what is machine-checked, over what domain,
under what assumptions and stubs — and, given equal weight, **what is not**. It exists so that a
reader who is not going to read 171 proof harnesses and 6 Lean developments can still know what
they are being offered, and where the guarantee stops.

> ## The rule this document is written under
>
> **Counts are inventory, not coverage.** "171 Kani harnesses, 6 Lean lids, 320 tests" describes how
> much verification *exists*. It says nothing about how much of the crate's behaviour is covered, and
> a reader who reads it as a coverage figure has been misled by this document, not by themselves. So
> the *claims* below are stated in prose, per property and per bound; the counts sit underneath them
> as evidence, never in place of them. Where a claim would be stronger than the evidence, the
> evidence wins and the claim is narrowed.

## How this document is produced (and why that matters)

Every number **inside a `<!-- BEGIN GENERATED -->` region** is derived from the source tree by a
committed script:

```sh
python3 gates/gen_proof_manifest.py --write     # regenerate the factual regions
python3 gates/gen_proof_manifest.py --check     # gate: fail if manifest and source disagree
python3 gates/gen_proof_manifest.py --json      # the derived facts, machine-readable
```

`--check` runs inside `./check.sh` and `./check_fast.sh`, so a harness added, a bound changed, a
stub introduced or an entry point exposed without a corresponding manifest update **fails the gate**.
It also guards the count-claims in `README.md`, `der-verified/README.md`, `docs/`, the crate docs, and
**this file's own prose** — a stale count in a secondary document is the same overclaim in a quieter
place, and the manifest's own repeated counts are the most-read of all.

Four limits on that guarantee, because the sentence above is the reason you would trust any number
here:

- **Numbers in hand-written prose are not derived.** Measured figures (peak RAM, wall-clock, the
  ~24 GB reproduction requirement, the CI share, byte-count arguments) and dates are
  maintainer-reported. They are not machine-checkable and are not claimed to be. Where one appears,
  it is a measurement someone took, not a fact the gate re-derives.
- **The gate detects *inventory* changes only.** It does not notice a weakened `assert!`, a `cover`
  deleted from a harness that keeps its `assert`, a tightened size/range `assume`, a rewritten oracle
  body, or a changed stub return expression — none of those change any count. Those are protected
  only by re-running the proofs and by review. A green gate is not a statement that the verification
  did not get weaker.
- **The script runs no proofs.** It cannot tell you the proofs pass; §3.4 states separately what run
  evidence exists.
- **One region is advisory, and labels itself as such.** The `pins-observed` region in §2 records
  what the *machine that last ran `--write`* had installed. `--write` regenerates it; `--check`
  deliberately does **not** byte-compare it, because your rustc version — and whether you have Kani
  or Aeneas installed at all — is a property of your run, not of this crate. Comparing it meant
  `./check.sh` failed for every third party whose toolchain differed from ours, before a single
  proof ran. The *declared* pins in the §2 table are read from in-tree files and stay fully
  enforced. `gates/test_gen_proof_manifest.py` gates both halves of that split: an unfamiliar
  toolchain must not fail `--check`, and a drifted count or declared pin must still fail it.

Everything outside a generated region is hand-written judgement — the claims, the scope fence, the
deviations. Read the two differently.

## 1. Inventory

<!-- BEGIN GENERATED:inventory (gates/gen_proof_manifest.py) -->
| Inventory (static, derived from `der-verified/src` + `lean/`) | Count |
|---|---:|
| source modules (excl. `lib.rs`) | 26 |
| …of which carry at least one `#[kani::proof]` | 26 |
| public entry points (free `pub fn`s + public `impl` methods) | 68 |
| …named by at least one Kani harness | 57 |
| …named by **no** Kani harness | **11** |
| `#[kani::proof]` harnesses | 171 |
| `kani::assume` harness preconditions (narrow the proved domain) | 136 |
| `kani::assume` inside stub bodies (constrain a stub's *return*, not an input) | 3 |
| `kani::cover` **statements** (satisfaction is observed at a run, is not gate-enforced, and its currency versus HEAD is derived in §3.4, not asserted here) | 75 |
| …harnesses whose cover is **known-unsatisfiable and disclosed** — i.e. known *non*-witnesses | **3** |
| `#[kani::stub]` applications / harnesses using them | 7 / 4 |
| `#[test]` unit + regression tests | 320 |
| crate-doc examples run as doc-tests | 1 |
| Lean lids (`lean/*Proofs.lean`) | 6 |
| `unsafe` blocks in `der-verified/src` | 0 (crate is `#![forbid(unsafe_code)]`: yes) |
<!-- END GENERATED:inventory -->

Zero runtime dependencies (`der-verified/Cargo.toml` has an empty `[dependencies]`), `no_std`, no
`alloc` on the decode paths, and `#![forbid(unsafe_code)]`. There is therefore **no unsafe-code
assumption and no third-party-crate assumption in the trust base** — an unusually small dependency
surface, and the reason the classes of verification difficulty that come from `unsafe` code and from
third-party crates do not arise here.

Read "trust base" narrowly: it means the *linked* code. It does not extend to `core`, whose internals
are `unsafe` and are trusted, nor to the verification tools themselves (§3.2), nor to allocation —
Kani models allocation as succeeding, and while the decode paths are allocation-free, nothing here is
a claim about behaviour under allocation failure. It says nothing about the other classes of
difficulty either: the model-vs-compiler gap (§3.2), toolchain bugs (§3.2), and specification
correctness (§8.3) all remain.

## 2. Toolchain pins

<!-- BEGIN GENERATED:pins (gates/gen_proof_manifest.py) -->
| Tool | Pin (declared, and where the pin lives) | Enforced by |
|---|---|---|
| rustc | `stable` channel — `rust-toolchain.toml` pins the *channel*, not a version: it floats to whatever stable is installed. Only `cargo test`/`cargo build` use it; Kani bundles its own toolchain. | not enforced (deliberate — see the note below) |
| Kani | `0.67.0` — `.github/workflows/ci.yml` (`kani-version:`) | CI installs exactly this |
| Lean 4 | `leanprover/lean4:v4.30.0-rc2` — `lean/lean-toolchain` | elan, per-project |
| Aeneas | `45061fa1a5b4bad876f17c03d3a5544d818622e6` | `lean/check_lean.sh` fails closed on drift |
| Charon | `40ee060a8df43f4e7e0842d3f05387b0a4426aaf` | `lean/check_lean.sh` fails closed on drift |
| extract shims | `nightly-2026-06-01` (Charon's nightly; `lean/extract*/rust-toolchain.toml`) — drives extraction only, never the shipped build | pinned in-tree |

Because the rustc pin is a floating channel, **the rustc version is a property of the run, not of the crate**: a reader reproducing these results on a different stable will be checking the same source with a different compiler. The Kani harnesses are insulated from this (Kani ships its own toolchain); `cargo test` is not.
<!-- END GENERATED:pins -->

<!-- BEGIN GENERATED:pins-observed (gates/gen_proof_manifest.py) -->
Observed on the machine that last regenerated this section — a provenance note, **not** a gate-enforced pin (your values will differ, and that is fine): rustc `rustc 1.93.1 (01f6ddf75 2026-02-11) (built from a source tarball)`, Kani `cargo-kani 0.67.0`, Aeneas `45061fa1a5b4bad876f17c03d3a5544d818622e6`, Charon `40ee060a8df43f4e7e0842d3f05387b0a4426aaf`.
<!-- END GENERATED:pins-observed -->

Toolchain identity is part of every claim in this document. Two honest qualifications:

- **The rustc pin is a channel, not a version.** `rust-toolchain.toml` says `stable`, so a fresh
  clone builds with whatever stable is installed. The Kani harnesses are insulated (Kani ships its
  own toolchain), and the Lean lids are insulated (they pin exact Aeneas/Charon commits and a
  specific Lean release, and fail closed on drift). `cargo test` is not insulated.
- **Only the Aeneas/Charon/Lean pins are enforced by a gate.** `lean/check_lean.sh` compares the
  installed Aeneas and Charon revisions against the ones the proofs were checked against and fails
  on mismatch. The Kani version is pinned in CI but not asserted by `check.sh`; a local run with a
  different Kani version will not tell you so. Throughout this document "gate" means `./check.sh` /
  `./check_fast.sh` — the checks you run locally — not CI.

## 3. What is proven — the two lineages

### 3.1 L3 floor — Kani (`cargo kani -Z stubbing`) — **bounded**

Kani compiles each `#[kani::proof]` harness to CBMC and discharges it as a bit-precise SAT/SMT
query. Every harness proves, by Kani's default checks, **absence of panics, absence of arithmetic
overflow, and memory safety** on its input domain — plus whatever **functional property** the
harness itself asserts: round-trip, canonicality/minimality biconditionals, and exact rejection
classification of malformed or non-canonical encodings.

**What "bounded" means here, precisely.** Each harness constructs a *fixed-width symbolic input*
(`kani::any()` byte arrays, usually with a symbolic length narrowed by `kani::assume` to `0..=N`),
and unrolls loops to a stated `#[kani::unwind(N)]` depth. The proof is **complete over that bounded
domain and no larger**. It is **not** a statement about longer inputs. Bounds are stated as
per-module buffer-width and unwind ranges in §4's table and as a crate-wide unwind histogram in §8.1;
exact per-harness values live in the harnesses themselves, and the size/range `assume` bounds are
characterised in §8.2 rather than listed (the full list is in `--json`).

Nothing in the L3 layer is a claim about inputs wider than the harness buffer. Where an
unbounded (∀-length) guarantee exists, it comes from an L4 Lean lid, and only for the six codecs
listed next.

### 3.2 L4/L5 reach — Aeneas → Lean — **unbounded, on six codecs**

Six codecs are additionally extracted Rust → Charon → Aeneas → Lean 4, and for each of them
*selected* properties — named per codec below, not all of that codec's properties — are machine-checked
over inputs of **any length** (and, for `sequence`, any number of children). The rejection and
canonicality classifications of these same six remain Kani-bounded; §6.2 says which.

<!-- BEGIN GENERATED:l4 (gates/gen_proof_manifest.py) -->
| Lid | Codec | Theorems + lemmas | Assumed Aeneas-Std specs (`axiom`) |
|---|---|---:|---:|
| `lean/BigIntProofs.lean` | `bigint` | 16 | 3 |
| `lean/LengthProofs.lean` | `length` | 42 | 1 |
| `lean/OidProofs.lean` | `oid` | 5 | 0 |
| `lean/SequenceProofs.lean` | `sequence` | 13 | 6 |
| `lean/TagProofs.lean` | `tag` | 7 | 1 |
| `lean/TlvProofs.lean` | `tlv` | 8 | 6 |

The `axiom` column counts the *assumed Aeneas-Std specs declared in the lid file itself* — the trust surface a reader can audit by opening the file. It excludes Lean's own `propext`/`Classical.choice`/`Quot.sound` and `bv_decide`'s certificate axiom. Separately, the lids carry 43 `#print axioms` commands: that is a count of *audit commands* (roughly one per theorem whose dependency set is disclosed at build time), **not** a count of axioms — do not compare it with the column.

One limitation to name explicitly: a declared `axiom` characterising an Aeneas-Std primitive and a bespoke assumption about this crate's own code are syntactically identical, and the latter would be an unsound hole. Nothing in this repository mechanically distinguishes them — the argument that each is an upstream-primitive spec is made in the lid docstrings and rests on review, not on a gate.
<!-- END GENERATED:l4 -->

What each lid proves, **as summarised by the author** — this table is hand-written interpretation,
not generated: the script counts a lid's theorems and axioms but cannot read Lean. For the exact
machine-checked statement, read the named theorem in the lid source. Where this table and the Lean
file disagree, the Lean file is right.

| Codec | Unbounded property |
|---|---|
| `length` (X.690 §8.1.3) | every branch of `decode_length` ∀-length, and round-trip canonicality — Lean theorem `decode_accepts_only_canonical`, whose proof also covers both loops of `encode_length` (`encode_length_loop0_spec`, `encode_length_loop1_spec`) |
| `big_integer` (X.690 §8.3) | the minimality biconditional on the validate side (`validate_iff_minimal`) and encode-side round-trip/canonicality (`encode_minimal_integer_into_roundtrip`), ∀-length |
| `oid` (X.690 §8.19) | the OID canonical-form biconditional on the validate side (`validate_iff_canonical`), ∀-length |
| `tag` (X.690 §8.1.2) | `decode_tag`'s totality and consumption bound ∀-length (`tag_decode_total`, `tag_decode_used_bounds`): it never fails to terminate, and an accepted decode consumes `1..=input.length` bytes. Required a behaviour-preserving refactor of the high-tag loop (`return`-inside-loop → break-with-`Result`) to make Aeneas extraction produce a body rather than a bodyless axiom |
| `tlv` | `decode_tlv`'s structural correctness ∀-length: an accepted TLV's `used` equals header + declared length, its value is exactly that window, and — the security-relevant fact — `used ≤ input.length` (`decode_tlv_structure`) |
| `sequence` | `decode_sequence`'s structural correctness ∀-length **and ∀-children**: whenever the child-walk accepts, it consumes exactly the content's bytes, for any number of children (`decode_sequence_structure`). the only lid unbounded in the **number of children** as well as in byte length — `tag` and `length` also prove properties of loops ∀-length, but their trip counts are bounded by the input's byte length, whereas a `SEQUENCE`'s child count is not. Kani's corresponding harness is capped at `unwind(16)` on both width and trip count |

**Trust base for L4, stated rather than hidden.** The Lean proofs check the **Aeneas model** of the
Rust code. The Rust → LLBC → Lean translation is not itself formally verified against rustc
semantics; this is the standard Aeneas assurance boundary. On top of that, each lid assumes a small
number of *Aeneas-Std specs* as `axiom`s — the count is in the table above, the full non-standard
axiom set of every proof is disclosed by `#print axioms` in the sources, and each lid's docstring
explains its own trust surface.

All L4 proofs are **`sorry`-free, and that is a gate, not an eyeball check**: `lean/check_lean.sh`
fails closed if `sorryAx` or a `declaration uses 'sorry'` warning appears, and it was negative-tested
by injecting a `sorry` and confirming failure. The lid **re-extracts from the shipped `.rs` and fails
on drift**, so it provably concerns the shipped source rather than a stale snapshot.

**Both lineages trust their tools, and that is an assumption, not a proof.** Every claim in this
document rests on the correctness of the verification stack itself: for L3, Kani's compilation to
CBMC's goto-programs, CBMC's symbolic execution and encoding, and the SAT solver that discharges the
resulting formula (CaDiCaL by default); for L4, Charon's Rust→LLBC front-end, Aeneas's translation to
Lean, and Lean 4's kernel and `bv_decide` certificate checking. A bug in any of them could make a
false property look proven. This is the standard assumption of all machine-checked verification and
is not specific to this crate, but it is part of the envelope and is stated rather than left to be
inferred.

**L4 is guarded, which has an honest downside.** `lean/check_lean.sh` no-ops (exit 0) when the
Aeneas/Lean toolchain is absent, so `./check.sh` still passes on the L3 floor alone. That means **a
green `./check.sh` on a machine without the extraction stack has verified none of the unbounded
claims.** The skip is printed, not silent, but a reader should know that the L4 half of this manifest
is only re-checked on a machine that has Aeneas, Charon and Lean installed at the pinned revisions.

### 3.3 Concrete tests

`cargo test` runs 320 unit and regression tests (plus 27 module and crate-doc examples) over concrete vectors, including
seeded-bad specimens. **These are example-based tests, not property-based and not proofs.** They are
regression road-signs; the assurance claim rests on the harnesses and the lids. For the `profile`
module (§7) they are the *only* evidence that exists.

### 3.4 Run evidence — what has actually been executed, and when

<!-- BEGIN GENERATED:evidence (gates/gen_proof_manifest.py) -->
| Committed log | At commit | `SUCCESSFUL` | `FAILED` | harnesses reporting an unsatisfied cover |
|---|---|---:|---:|---:|
| `evidence/check-28e1429.log` | `28e1429` | 171 | 0 | 3 |
| `evidence/check-461f751.log` | `461f751` | 171 | 0 | 3 |
| `evidence/check-b355f76.log` | `b355f76` | 164 | 0 | 3 |
| `evidence/check-ba40709.log` | `ba40709` | 171 | 0 | 3 |
| `evidence/check-ea8dad4-remainder.log` | `ea8dad4` | 8 | 0 | 2 |
| `evidence/check-ea8dad4.log` | `ea8dad4` | 162 | 0 | 0 |
| `evidence/check_tractable-67c1f80.log` | `67c1f80` | 143 | 0 | 1 |

Every column here is read out of the committed log itself, so this table is reproducible from the tree alone and is gate-enforced. Whether a given run still speaks for HEAD needs `git`, which a tarball or shallow clone may not have — that question is answered separately just below, and is advisory for exactly that reason.
<!-- END GENERATED:evidence -->

<!-- BEGIN GENERATED:evidence-coverage (gates/gen_proof_manifest.py) -->
**`evidence/check-ba40709.log` still speaks for HEAD.** No path it verified has changed since its commit: `git diff ba40709..HEAD -- der-verified/src lean` is empty. Run that command rather than trusting this sentence.
- `evidence/check-28e1429.log` (at `28e1429`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-461f751.log` (at `461f751`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-b355f76.log` (at `b355f76`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-ea8dad4-remainder.log` (at `ea8dad4`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-ea8dad4.log` (at `ea8dad4`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check_tractable-67c1f80.log` (at `67c1f80`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
<!-- END GENERATED:evidence-coverage -->

The precise provenance of the L3 verdict, stated plainly because "the proofs pass" is the one claim
in this document a reader cannot check from the source alone:

- **The verdict is now read off a committed artifact, not transcribed.** The current run is
  **2026-08-07 at commit `ba40709`** (`evidence/check-ba40709.log`) — `171 successfully verified
  harnesses, 0 failures`, `cargo test` green, the L4 Lean gate `PASS (sorry-free)`, and the
  lid-staleness `--strict` gate green in the same pass, 53m37s wall under a `MemoryMax=22G` scope.
  The three unsatisfied covers are again exactly the three §8.2 discloses. The first such run, described
  below, was `./check.sh`
  end-to-end on **2026-07-30** at commit `b355f76` — `cargo kani -Z stubbing` over all 164 harnesses
  **sequentially** (no `-j`; parallel harnesses multiply peak RSS), inside a `MemoryMax=22G`
  cgroup scope, 52 minutes wall — and the log is in this repository. It reports **164
  `VERIFICATION: SUCCESSFUL`, 0 `FAILED`**, and the `cargo test` and **L4 Lean** stages green in the
  same run (`lean lid: PASS (sorry-free)`, 1704 `lake` jobs). Every number in the table above is
  derived from that file by this manifest's generator, not typed.
- **Three harnesses reported `0 of 1 cover properties satisfied`, and they are exactly the three
  §8.2 discloses** (`x509_extension::validate_extensions_never_panics`,
  `x509_tbs_certificate::parse_tbs_certificate_never_panics`, `x509_validity::parse_never_panics`).
  That is the useful part of committing a log: the disclosed-vacuity table is no longer a promise
  about what a re-run would show. Nothing undisclosed appeared, and no disclosed gap had quietly
  become satisfiable. One of the three had previously never been *determined* at all — that harness
  had only ever OOM-ed past the slicing stage, so its cover's SAT/UNSAT status was unknown (see
  `docs/verification-cost.md`); it is now determined, and UNSATISFIED.
- **`evidence/` holds two files per run, deliberately.** `evidence/check-b355f76.log` is a
  distillation — per-harness verdicts, cover satisfaction, timings, stage banners — and
  `evidence/raw/check-b355f76.log.gz` is the *complete* 28 MB raw log, so the distillation is
  checkable rather than trusted. The distilled file's own header states the exact `grep` that
  produced it, the raw log's byte count and its sha256.
- **Which run currently speaks for HEAD is derived, not asserted in prose.** It is stated in the
  advisory region just above §3.4's table, computed as `git diff <run-commit>..HEAD --
  der-verified/src lean` being empty. That is deliberately *advisory*: it needs git history, which a
  tarball or a shallow clone may not have, and making `./check.sh` depend on the reader's environment
  is the exact defect the `pins-observed` split fixed. Every count in the evidence table itself is
  read out of the committed log and stays gate-enforced.
- **Why derived rather than written down:** a sentence saying "the run at X still covers HEAD" rots
  the moment a source commit lands, and it rots toward over-claiming. The earlier version of this
  bullet named two specific commits and had to be rewritten by hand at the next run; this one cannot
  go stale, because nothing states it.
- **What this supersedes.** The previous entry here cited a 2026-07-21/22 run transcribed in
  `DER-REMAINING-WORK.md`, and had to disclose that `der-verified/src/` had changed after it —
  `tag.rs`'s behaviour-preserving high-tag-loop refactor (`0c2948a`) and the additive `profile`
  module (`d65e7f0`, `6bcb8be`) — so that the 164/164 figure was "not a single run at the current
  HEAD" but a full-suite run plus a targeted re-run of the one changed module. That caveat is
  **closed**: the committed run covers `tag.rs` and `profile` as they now stand, in one pass. The
  older, narrower point remains true and worth keeping: no proof of equivalence between the old and
  new `decode_tag` exists — the old body extracted as a bodyless axiom, so there was never an
  ∀-length statement about it to equate against.
- **Reproducing the full L3 floor needs a large machine.** Two harnesses dominate:
  `x509_extension::validate_extensions_never_panics` peaked ~20.5 GiB (~10 min) and
  `x509_name::validate_rdn_never_panics` ~17.1 GiB (~14 min). Below roughly 24 GB of available RAM
  those two will not converge, and `./check.sh` will fail on them rather than on any defect. CI runs
  the memory-tractable share — about 136 of the 171 harnesses (the shard filters are by module, not a
  pinned count, so read the workflow for the exact set), sharded across three 7 GB runners; the
  remainder is a local-milestone check. See `docs/verification-cost.md` for the per-harness numbers.

**The L4 evidence is in better shape than the L3 evidence, which is worth saying because it is the
opposite of what a reader would assume.** The last recorded full `sh lean/check_lean.sh` pass —
`PASS (sorry-free)`, 1704 `lake` jobs — was at commit `0c2948a`. Since then **no source file that any
lid extracts from has changed**: the six extracted codecs are `length`, `big_integer`, `oid`, `tag`,
`tlv` and `sequence`, and the only `der-verified/src` changes since `0c2948a` are `profile.rs`, the
`lib.rs` line declaring it, and this pass's three comment-only registry lines. The extraction shims
`#[path]`-include the individual module files and do not import the crate, so neither `lib.rs` nor
`profile.rs` can affect them. The lid also re-extracts and fails on drift. So the recorded L4 verdict
still concerns the bytes shipped at HEAD. (That the shims are `#[path]`-based is a fact about the
tree; that the last pass was at `0c2948a` is transcribed from that commit's message.)

**Public CI is the one piece of run evidence a third party can inspect without a large machine.**
`.github/workflows/ci.yml` runs `cargo test`, `cargo clippy -D warnings`, and the memory-tractable
Kani share on every push. Its most recent recorded conclusion before this commit was **success at
`bd318e2`** (2026-07-26). Three limits on what that buys you: it covers roughly 136 of the 164
harnesses, not the two heavy ones; a harness reporting an unsatisfied `cover` passes CI exactly as it
passes locally (§6.1); and it never runs the L4 lids. CI is a floor under regressions in the tractable
share, not a substitute for the full gate.

**What is not recorded anywhere, and would be worth recording.** The exact Kani version and flags of
the 2026-07-21/22 full-suite run; whether that run's per-harness `cover` satisfaction was captured
rather than just `SUCCESSFUL`; and whether the post-refactor `tag` re-run recorded cover satisfaction.
Under §6.1 those are different facts, and only the coarse one was written down.

## 4. Entry points — covered, and not covered

Entry points are each module's public API surface: its free `pub fn`s plus the public methods on its
public types. "Named by a harness" is a **syntactic** fact: some harness in that module's `mod proofs`
mentions the function or method by name. It is a lower bound on attention, not evidence
that the function's behaviour is characterised — the per-property statements in §5 and §6 are what
carry that.

<!-- BEGIN GENERATED:per-module (gates/gen_proof_manifest.py) -->
| Module | entry points | named by a harness | Kani | symbolic `[u8; N]` | unwind | `assume` | `cover` | stubs | L4 |
|---|---:|---:|---:|---|---|---:|---:|---:|:--:|
| `big_integer` | 3 | 3 | 13 | 20 | 1..22 | 15 | 4 | 0 | ✅ |
| `bit_string` | 3 | 3 | 8 | 3..6 | 6..8 | 9 | 2 | 0 |  |
| `boolean` | 2 | 2 | 3 | — | — | 0 | 0 | 0 |  |
| `context_tag` | 1 | 1 | 1 | 16 | 20 | 0 | 2 | 0 |  |
| `enumerated` | 2 | 2 | 3 | 9 | 12 | 1 | 10 | 0 |  |
| `generalized_time` | 3 | 2 | 16 | 3..19 | 16..20 | 20 | 3 | 0 |  |
| `integer` | 2 | 2 | 7 | 8..10 | 12 | 4 | 2 | 0 |  |
| `length` | 2 | 2 | 9 | 8 | 10 | 7 | 1 | 0 | ✅ |
| `null` | 1 | 1 | 1 | — | — | 0 | 0 | 0 |  |
| `octet_string` | 2 | 2 | 6 | 3..16 | 16 | 4 | 2 | 0 |  |
| `oid` | 1 | 1 | 5 | 4..6 | 8 | 5 | 2 | 0 | ✅ |
| `profile` | 1 | 1 | 6 | 1..2 | 4 | 2 | 16 | 0 |  |
| `restricted_string` | 14 | 5 | 26 | 3..16 | 6..16 | 30 | 4 | 0 |  |
| `sequence` | 6 | 6 | 7 | 8..16 | 16 | 0 | 2 | 0 | ✅ |
| `set_of` | 5 | 5 | 13 | 3..16 | 16 | 2 | 2 | 0 |  |
| `tag` | 2 | 2 | 7 | 7 | 12 | 5 | 2 | 0 | ✅ |
| `tlv` | 3 | 3 | 5 | 3..16 | 16 | 0 | 3 | 0 | ✅ |
| `utc_time` | 3 | 3 | 14 | 14..17 | 14..18 | 15 | 3 | 0 |  |
| `utf8_string` | 4 | 3 | 9 | 4..16 | 6..16 | 12 | 2 | 0 |  |
| `x509_algorithm_identifier` | 1 | 1 | 1 | 16 | 20 | 0 | 3 | 0 |  |
| `x509_certificate` | 1 | 1 | 1 | 12 | 12 | 1 | 1 | 1 |  |
| `x509_extension` | 2 | 2 | 3 | 13..16 | 12..20 | 1 | 3 | 0 |  |
| `x509_name` | 1 | 1 | 2 | 16 | 10..12 | 2 | 1 | 1 |  |
| `x509_spki` | 1 | 1 | 1 | 16 | 20 | 0 | 1 | 0 |  |
| `x509_tbs_certificate` | 1 | 1 | 2 | 10..135 | 12 | 1 | 2 | 5 |  |
| `x509_validity` | 1 | 1 | 2 | 16..32 | 20 | 0 | 2 | 0 |  |
<!-- END GENERATED:per-module -->

### 4.1 Entry points named by no harness

<!-- BEGIN GENERATED:unharnessed-entry-points (gates/gen_proof_manifest.py) -->
- **`generalized_time`** — `require_no_fraction`
- **`restricted_string`** — `Charset::tag_number`, `decode_printable_string`, `decode_ia5_string`, `decode_numeric_string`, `decode_visible_string`, `encode_printable_string_into`, `encode_ia5_string_into`, `encode_numeric_string_into`, `encode_visible_string_into`
- **`utf8_string`** — `decode_utf8_str`
<!-- END GENERATED:unharnessed-entry-points -->

Entry points include **public methods on public types**, not only free functions — `Charset::contains`
and `Elements::new` are as much part of the API surface as `decode_length` is. An earlier version of
the generator scanned free functions only and silently missed four of them, and a later pass missed
`Iterator::next` on `Elements` as well (a trait-impl method carries no `pub` keyword). The counts in
§1 and in the table above are the corrected ones.

Honest classification of that list — four kinds, only one of which is a real gap:

1. **Eight `restricted_string` per-charset wrappers** (`decode_printable_string`,
   `decode_ia5_string`, `decode_numeric_string`, `decode_visible_string`, and the four
   `encode_*_string_into` counterparts). Each is a single-expression delegation to
   `decode_restricted_string` / `encode_restricted_string_into` with a fixed `Charset` — no
   arithmetic, no branching. Both delegates are harnessed, and `restricted_string`'s charset
   biconditionals are proven per charset. The wrappers' panic-freedom follows from their delegates'
   **by inspection of a one-line body** — which is a human argument, not a machine-checked one, and
   is recorded here as such. **A second, smaller gap sits inside this one:** nothing machine-checks
   that each wrapper passes its *own* `Charset`. A transposed constant — `decode_ia5_string`
   delegating with `Charset::Printable` — would satisfy every proof cited above, because each proof is
   about the delegate given a charset, not about the pairing. The pairing is covered by `#[test]`
   cases only.
2. **`generalized_time::require_no_fraction`** (returns `t.fraction.is_empty()`) and
   **`utf8_string::decode_utf8_str`** (calls the harnessed `decode_utf8_string`, then
   `core::str::from_utf8` on content already validated as UTF-8, returning an `Err` rather than
   panicking on a branch that is unreachable *on the harnessed domain* — beyond it, by inspection).
   Same status: trivially total by inspection, not by proof.
3. **`Charset::tag_number`** — a `pub const fn` returning the charset's UNIVERSAL tag number by
   `match`. No harness *names* it, but it is not unexercised: `Charset::identifier` calls it, and the
   `wrong_tag_is_classified_*` harnesses call `identifier()` for all four charsets, so `tag_number`
   is symbolically executed under Kani in those four harnesses. This is the clearest illustration of
   why "named by a harness" is only a syntactic proxy — here it undercounts.
4. **`profile::validate_profile`** — a genuine gap, and the largest single one in the crate. It has
   no Kani harness and no Lean lid; see §7.

**No entry point in this crate is claimed to be proven where it is not.** If you need a
machine-checked guarantee on one of the eleven above: for the nine delegating wrappers and
accessors, call the harnessed delegate directly; for `profile::validate_profile` there is no delegate
to fall back to, so the only options are to ask for a harness or to treat it as tested-only.

## 5. Properties proven — per module

The harness names *are* the property names; this is the index into them. Read the harness for the
exact statement, including its `assume` preconditions.

<!-- BEGIN GENERATED:properties (gates/gen_proof_manifest.py) -->
- **`big_integer`** (13): `validate_iff_minimal_oracle`, `accepted_is_fixed_point_of_minimizer`, `minimizer_output_is_always_minimal`, `minimality_is_local`, `validate_never_panics`, `encode_never_panics`, `empty_is_empty`, `redundant_positive_padding_is_non_minimal`, `redundant_negative_padding_is_non_minimal`, `redundant_positive_padding_is_non_minimal_at_length`, `redundant_negative_padding_is_non_minimal_at_length`, `is_negative_matches_sign_bit`, `strips_redundant_padding`
- **`bit_string`** (8): `roundtrip_canonical`, `decode_never_panics`, `decode_accepts_only_canonical`, `empty_is_classified`, `unused_too_large_is_classified`, `nonzero_padding_is_classified`, `empty_nonzero_unused_is_classified`, `octet_aligned_iff_unused_zero`
- **`boolean`** (3): `one_octet_is_canonical`, `roundtrip`, `wrong_length_is_bad_length`
- **`context_tag`** (1): `decode_explicit_context_never_panics`
- **`enumerated`** (3): `decode_delegates_to_integer`, `encode_delegates_to_integer`, `roundtrip`
- **`generalized_time`** (16): `roundtrip_all_fields`, `decode_never_panics`, `decode_accepts_only_canonical`, `accepted_iff_canonical_oracle`, `short_length_is_bad_length`, `non_digit_is_classified`, `not_zulu_is_classified`, `month_range_is_classified`, `day_range_is_classified`, `hour_range_is_classified`, `minute_range_is_classified`, `second_range_is_classified`, `bad_fraction_separator_is_classified`, `fraction_empty_is_classified`, `fraction_trailing_zero_is_classified`, `fraction_non_digit_is_classified`
- **`integer`** (7): `roundtrip_all_i64`, `decode_never_panics`, `decode_accepts_only_minimal`, `empty_is_classified`, `redundant_positive_padding_is_non_minimal`, `redundant_negative_padding_is_non_minimal`, `nine_octets_is_too_large`
- **`length`** (9): `roundtrip_all_u32`, `decode_never_panics`, `decode_accepts_only_canonical`, `indefinite_is_classified`, `reserved_is_classified`, `leading_zero_is_non_minimal`, `long_form_of_short_value_is_non_minimal`, `truncated_long_form_is_classified`, `too_large_is_classified`
- **`null`** (1): `only_empty_is_valid`
- **`octet_string`** (6): `roundtrip_small`, `decode_never_panics`, `accepted_content_is_the_tlv_value`, `constructed_form_is_rejected`, `non_octet_string_tag_is_wrong_tag`, `accepted_identifier_is_canonical_0x04`
- **`oid`** (5): `validate_never_panics`, `empty_is_classified`, `leading_0x80_is_non_minimal`, `later_0x80_is_non_minimal`, `unterminated_is_truncated`
- **`profile`** (6): `utc_time_can_never_denote_2050_or_later`, `rule1_mismatch_iff_algorithms_differ`, `rule2_requires_v3_iff_extensions_present_and_not_v3`, `rule3_generalized_too_early_iff_year_le_2049`, `error_precedence_follows_declaration_order`, `validate_profile_never_panics`
- **`restricted_string`** (26): `charset_exactly_matches_oracle_printable`, `charset_exactly_matches_oracle_ia5`, `charset_exactly_matches_oracle_numeric`, `charset_exactly_matches_oracle_visible`, `validate_iff_all_in_charset_printable`, `validate_iff_all_in_charset_ia5`, `validate_iff_all_in_charset_numeric`, `validate_iff_all_in_charset_visible`, `roundtrip_printable`, `roundtrip_ia5`, `roundtrip_numeric`, `roundtrip_visible`, `decode_never_panics`, `constructed_form_is_rejected_printable`, `constructed_form_is_rejected_ia5`, `constructed_form_is_rejected_numeric`, `constructed_form_is_rejected_visible`, `accepted_identifier_is_canonical_printable`, `accepted_identifier_is_canonical_ia5`, `accepted_identifier_is_canonical_numeric`, `accepted_identifier_is_canonical_visible`, `out_of_charset_reports_position`, `wrong_tag_is_classified_printable`, `wrong_tag_is_classified_ia5`, `wrong_tag_is_classified_numeric`, `wrong_tag_is_classified_visible`
- **`sequence`** (7): `iterate_never_panics`, `no_over_read`, `ok_implies_exact_tiling`, `roundtrip_two_children`, `tag_correctness`, `accepted_identifier_is_canonical_0x30`, `strict_rejects_trailing`
- **`set_of`** (13): `iterate_never_panics`, `no_over_read`, `ok_implies_exact_tiling`, `ordering_iff_oracle`, `cmp_padded_matches_oracle`, `unsorted_children_are_rejected`, `unsorted_reports_first_violation_index`, `unsorted_reports_first_violation_index_depth_four`, `duplicate_adjacent_encodings_are_accepted`, `tag_correctness`, `accepted_identifier_is_canonical_0x31`, `strict_rejects_trailing`, `roundtrip_two_sorted_children`
- **`tag`** (7): `roundtrip_all_tags`, `decode_tag_never_panics`, `decode_tag_accepts_only_canonical`, `high_tag_of_small_number_is_non_minimal`, `leading_zero_high_tag_is_non_minimal`, `truncated_high_tag_is_classified`, `too_large_tag_is_classified`
- **`tlv`** (5): `decode_tlv_never_panics`, `decode_tlv_structure`, `tlv_roundtrip_small`, `tlv_truncated_value_is_classified`, `strict_rejects_trailing`
- **`utc_time`** (14): `roundtrip_all_fields`, `decode_never_panics`, `decode_accepts_only_canonical`, `accepted_iff_canonical_oracle`, `wrong_length_is_bad_length`, `non_digit_is_classified`, `not_zulu_is_classified`, `month_range_is_classified`, `day_range_is_classified`, `hour_range_is_classified`, `minute_range_is_classified`, `second_range_is_classified`, `decode_postcondition_fields_in_range`, `full_year_pivot_is_correct`
- **`utf8_string`** (9): `validate_iff_oracle`, `validate_iff_oracle_multi`, `validate_iff_std`, `roundtrip`, `decode_never_panics`, `constructed_form_is_rejected`, `accepted_identifier_is_canonical`, `wrong_tag_is_classified`, `ill_formed_reports_position`
- **`x509_algorithm_identifier`** (1): `parse_algorithm_identifier_never_panics`
- **`x509_certificate`** (1): `parse_certificate_never_panics`
- **`x509_extension`** (3): `parse_extension_never_panics`, `validate_extensions_never_panics`, `validate_extensions_ok_path_witnessed`
- **`x509_name`** (2): `validate_rdn_never_panics`, `validate_never_panics`
- **`x509_spki`** (1): `parse_never_panics`
- **`x509_tbs_certificate`** (2): `parse_tbs_certificate_never_panics`, `parse_tbs_certificate_ok_path_witnessed`
- **`x509_validity`** (2): `parse_never_panics`, `parse_validity_ok_path_witnessed`
<!-- END GENERATED:properties -->

## 6. Properties NOT proven

This is the list that decides whether the rest of the document is worth anything.

### 6.1 Crate-wide

- **No cryptography.** No signature verification, no key or algorithm semantics, no certificate-path
  or trust validation, no clock. `der-verified` is an encoding-layer core and nothing above it.
- **Not unbounded, except six codecs.** Every property outside `length`, `big_integer`, `oid`,
  `tag`, `tlv` and `sequence` is bounded verification over the harness domains in §4's table.
  Inputs wider than those buffers, or requiring more loop iterations than the unwind depth, are
  **not claimed** — not "probably fine", not claimed.
- **No performance, timing or side-channel claim.** Nothing here says anything about constant-time
  behaviour or resistance to timing attacks.
- **The rustc-semantics gap for L4** (§3.2): the Lean proofs check the Aeneas model, not rustc.
- **Tests are not proofs** (§3.3).
- **The gate does not fail on an unsatisfied `cover`.** See §8.2 — Kani reports a harness with an
  unsatisfiable cover as `SUCCESSFUL` with `0 of 1 cover properties satisfied`, so cover
  satisfaction is *disclosed* here, not *enforced* by `check.sh`.

### 6.2 Per module

| Module | Not proven (beyond the crate-wide items above) |
|---|---|
| `tag` | ∀-length totality and consumption bounds are proven in Lean; the *canonicality/minimality* rejection properties are Kani-bounded only |
| `length` | fully lifted to ∀-length in Lean; no known residual beyond the Aeneas trust boundary |
| `tlv` | structural correctness is ∀-length; the strict (anti-trailing-data) variant's rejection classification is Kani-bounded only |
| `context_tag` | bounded only; only the explicit-context form is addressed — implicit tagging is not modelled |
| `boolean` | nothing outstanding: the 1-octet input space is characterised exhaustively |
| `integer` | values are capped at `i64` by design (see §9); `big_integer` is the arbitrary-magnitude complement. Bounded only |
| `big_integer` | validate-side minimality and encode-side round-trip are ∀-length in Lean; the classification of *specific* malformed shapes is Kani-bounded only |
| `null` | nothing outstanding: exhaustive over the 1-octet space |
| `oid` | canonical-form biconditional is ∀-length; **arc values are never materialised** — `validate_oid` validates encoding form and does not decode arcs, so no arithmetic-overflow property about arc values exists to prove |
| `bit_string` | bounded only; no unbounded lid |
| `octet_string` | bounded only; the BER constructed/segmented form is rejected by design (§9), so no property about it is claimed |
| `enumerated` | bounded only; it is a thin re-tag of `integer` and inherits that module's `i64` fence. Its `decode_delegates_to_integer` harness is the crate's one `assume`-narrowed harness whose non-vacuity rests on `integer`'s own proofs rather than on its own witness — see §8.2 |
| `restricted_string` | bounded only; the eight per-charset wrappers are unharnessed (§4.1) |
| `utf8_string` | bounded only; equivalence with `core::str::from_utf8` is proven as a *differential oracle* over the bounded domain, not ∀-length. `decode_utf8_str` is unharnessed (§4.1) |
| `utc_time` | bounded only. Single-field range validation only — **no calendar validity** (day-of-month against month, leap years); leap-second `SS=60` is rejected by design (§9) |
| `generalized_time` | bounded only. Same calendar-validity and leap-second fences; `require_no_fraction` is unharnessed (§4.1) |
| `sequence` | structural child-walk correctness is ∀-length and ∀-children; the strict variants' rejection classification is Kani-bounded only |
| `set_of` | bounded only. `SET OF` member-ordering (§11.6) is validated; **general `SET` (§10.3) is out of scope** (§9) |
| `x509_algorithm_identifier` | bounded, structural only: frames the object; interprets no algorithm semantics and no parameters |
| `x509_spki` | bounded, structural only: no key parsing, no key validity, no algorithm/key agreement check |
| `x509_name` | bounded, structural only. The composition proof is **modular** (`validate_rdn` stubbed — §8.4). No name-constraint semantics, no string canonicalisation/comparison rules |
| `x509_validity` | bounded, structural only: no comparison against a clock. Its `parse_never_panics` cover is **known-unsatisfiable at `[u8; 16]`** and disclosed (§8.2) |
| `x509_extension` | bounded, structural only: extension *contents* are never interpreted, and `critical` is peeked, not acted on. `validate_extensions` is proven at a reduced `[u8; 13]`; its cover is **known-unsatisfiable at that bound** and disclosed (§8.2) |
| `x509_tbs_certificate` | bounded, structural only, and **modular** (two stubs; three in the witness harness — §8.4). Its `never_panics` cover is **known-unsatisfiable at `[u8; 10]`** and disclosed (§8.2). No cross-field RFC 5280 rule is checked here — that is `profile`'s job |
| `x509_certificate` | bounded, structural only, and **modular** (`parse_tbs_certificate` stubbed — §8.4). No signature check, no path building |
| `profile` | bounded, and over symbolic *field values* rather than symbolic DER bytes — it decodes nothing (§7). Each of the three RFC 5280 cross-field rules is proven as a biconditional, plus their precedence and totality. No Lean lid, so no ∀-length statement |

## 7. `profile` — proven, at value level and without a Lean lid

`profile` is a first slice of a typed layer built strictly *on top of* the structural `x509_*`
parsers, checking cross-field RFC 5280 rules the parsers deliberately leave to the caller. It
performs no DER decoding of its own — only comparisons over already-materialised fields of an
already-structurally-valid `Certificate`. It currently enforces three rules, in this order,
returning the first violation:

1. **§4.1.1.2** — the outer `Certificate.signatureAlgorithm` must equal `tbsCertificate.signature`
   (two independently-valid `AlgorithmIdentifier`s that nothing in the ASN.1 grammar ties together).
2. **§4.1.2.1 / §4.1.2.9** — `extensions` is a v3-only field: a certificate carrying `extensions`
   while declaring a non-v3 `version` is rejected.
3. **§4.1.2.5** — `notBefore`/`notAfter` must each use the RFC-mandated encoding for their calendar
   year (UTCTime through 2049, GeneralizedTime from 2050). Only the GeneralizedTime-too-early
   direction needs a runtime check; the UTCTime-too-late direction is impossible by construction
   (`utc_time::full_year_rfc5280`'s codomain is exactly `1950..=2049`).

**What is now proven, and in what form.** Six Kani harnesses cover this module, and the shape of the
statements matters more than the count: each of the three rules is a **biconditional** — the rule
fires *exactly* when the RFC says it should — rather than a one-directional "bad input is rejected"
check that a too-eager implementation would also satisfy. Rule 2's harness ranges over all 256
`version` values, not just `0`/`1`/`2`. A fourth harness pins the **precedence** this section
documents, with all four violations independently symbolic, so the "first violation wins" ordering is
a proved property rather than a comment. A fifth proves totality over every profile-relevant field
combination, and a sixth proves the §4.1.2.5.1 window (`1950..=2049`) that rule 3's
impossible-by-construction half rests on.

**Why this module is cheap where the `x509_*` modules are not.** It decodes nothing, so its harnesses
take a symbolic *value* — an `AlgorithmIdentifier` pair, a `version`, an `Option` of extension bytes,
two `Time` arms and their years — instead of a symbolic DER buffer plus a parse. All six verify in
~0.5 s at ~205 MB peak, the cheapest module in the crate, and they run in CI's `codecs-b` shard rather
than the heavy local-milestone tier.

**Two boundaries this section will not blur.** First, **no Lean lid**: these are bounded proofs over
field values, not ∀-length statements over bytes, so `profile` does not carry the L4/L5 grade the six
lidded codecs do. Second, the proofs are about the *rules as this crate states them* — that
`validate_profile` implements RFC 5280 §4.1.1.2, §4.1.2.1/§4.1.2.9 and §4.1.2.5 **faithfully** is a
reading of the RFC by a human, exactly as §8.3 says of every oracle in this crate.

The structural half of rule 3 also stopped resting on a test in this pass. `full_year_rfc5280`'s
codomain claim needs `year2 <= 99`, and `UtcTime`'s fields are `pub` — a hand-written
`UtcTime { year2: 200, .. }` maps to `2100`, so "a `Time::Utc` can never denote 2050 or later" was
sound only for decoder-produced values, with nothing stating that as a proved property.
`utc_time::decode_postcondition_fields_in_range` now proves the decoder's postcondition over symbolic
content, which discharges the premise `full_year_pivot_is_correct` assumes. The hand-constructed case
remains outside it, by design and now in writing.

Not covered at all: name constraints, key usage, basic constraints, validity-against-clock, path
validation, and every other RFC 5280 cross-field rule beyond the three above. Roadmap:
`DER-REMAINING-WORK.md`, `TODO.md`.

## 8. Bounds, oracles, stubs, assumptions

### 8.1 Harness bounds and unwind limits

A bounded proof that hides its bound is a false claim, so every bound is stated. Per-module symbolic
buffer widths and unwind ranges are in §4's table; the crate-wide distribution:

<!-- BEGIN GENERATED:bounds (gates/gen_proof_manifest.py) -->
| `#[kani::unwind(N)]` | harnesses |
|---:|---:|
| 1 | 6 |
| 4 | 6 |
| 6 | 10 |
| 8 | 9 |
| 10 | 10 |
| 12 | 19 |
| 14 | 12 |
| 16 | 61 |
| 18 | 5 |
| 20 | 12 |
| 21 | 1 |
| 22 | 1 |
| **total bounded** | **152** |

19 harnesses declare no `#[kani::unwind]`, so no unwind bound is imposed on them and CBMC must unroll to completion every loop they reach. For those harnesses the loop depth is therefore *not* a limit on the claim: a loop CBMC could not fully unroll would fail an unwinding assertion rather than pass quietly. Their input domains are still bounded by buffer width like every other harness. Listed so a reader can check each one: `big_integer::empty_is_empty`, `big_integer::redundant_positive_padding_is_non_minimal`, `big_integer::redundant_negative_padding_is_non_minimal`, `bit_string::empty_is_classified`, `bit_string::empty_nonzero_unused_is_classified`, `boolean::one_octet_is_canonical`, `boolean::roundtrip`, `boolean::wrong_length_is_bad_length`, `enumerated::encode_delegates_to_integer`, `integer::empty_is_classified`, `integer::redundant_positive_padding_is_non_minimal`, `integer::redundant_negative_padding_is_non_minimal`, `null::only_empty_is_valid`, `oid::empty_is_classified`, `restricted_string::charset_exactly_matches_oracle_printable`, `restricted_string::charset_exactly_matches_oracle_ia5`, `restricted_string::charset_exactly_matches_oracle_numeric`, `restricted_string::charset_exactly_matches_oracle_visible`, `utc_time::full_year_pivot_is_correct`.
<!-- END GENERATED:bounds -->

Two bounds are deliberate, documented **reductions** rather than natural sizes, and are called out
because their scope cost is real:

- `x509_tbs_certificate::parse_tbs_certificate_never_panics` at `[u8; 10]` — chosen for
  tractability. The reduction is why its `Ok`-tail cover cannot be satisfied (§8.2).
- `x509_extension::validate_extensions_never_panics` at `[u8; 13]` — chosen because the outer
  `SEQUENCE OF` walk inlines a full `parse_extension` per iteration, so CBMC takes the product of
  both loops' maxima and `[u8; 16]`/`unwind(20)` exhausts memory. The residual (longer
  multi-extension inputs) is covered compositionally: `parse_extension` is separately proven at the
  full `[u8; 16]`, and what `validate_extensions` adds is bounded offset arithmetic plus slicing kept
  in-bounds by `decode_tlv`'s proven `used ≤ remaining`. That argument is compositional prose, not a
  single monolithic proof.

### 8.2 Non-vacuity — by what means

An assumption-narrowed harness can be green because it proves something about an empty or trivial
input space. This crate treats that as the default suspicion, and the check is machine-derived:

<!-- BEGIN GENERATED:non-vacuity (gates/gen_proof_manifest.py) -->
| Non-vacuity audit (derived from source) | Count |
|---|---:|
| harnesses | 171 |
| `kani::cover` witnesses | 75, in 24 of the 26 modules that have harnesses |
| harnesses whose ONLY checks are Kani's implicit panic/overflow/memory-safety ones (no `cover`, no `assert`) | **0** |
| harnesses narrowed by `assume` with no `cover` (their `assert` is the post-state witness instead) | 82 |
| harnesses whose `cover` is known-UNSATISFIABLE and disclosed | 3 |

**The row that carries the weight is "implicit checks only", and it is 0.** Every harness in the crate either witnesses a post-state effect with `kani::cover` or asserts a functional outcome with `assert!`; none relies on Kani's implicit checks alone. That much is a static fact this script re-derives on every run, not a claim.

What the remaining 82 `assume`-narrowed-without-a-`cover` harnesses give you is a *different* kind of witness, not automatically a better one. The static, derived fact is that each of them contains an `assert!`. The judgement — that these particular assertions are functional outcomes (a biconditional, a round-trip, an exact `Err` variant) whose passing requires the code to have produced a specific correct result — is per-harness and human; this script cannot grade an assertion's strength. But an assertion is not interchangeable with a cover: `assert!(r.is_err())` can be satisfied by a shallow rejection path while a deeper one is never reached, whereas a cover can pin a specific deep effect. Neither subsumes the other, and this manifest does not claim the assertions make covers unnecessary — only that no harness is left with nothing but Kani's implicit checks. The one case where even that is weaker than it looks is named in the prose below.

**What the 136 harness assumptions actually restrict.** 92 of them are size or range bounds — they relate lengths, indices and integer values with comparisons and `&&`, and nothing else — which narrows *how big* an input may be, not *what it may contain*. The remaining 44 restrict input CONTENT, which is the materially stronger kind of narrowing, so every one is named here rather than folded into a count:

Two things to hold in mind reading it. First, the classifier is deliberately conservative: anything it cannot show is a pure size/range bound is listed, so some entries below *are* range constraints in a shape it does not recognise (a negated range such as `!(mo >= 1 && mo <= 12)`, for instance). It errs toward disclosing. Second, content narrowing is usually the **point** of the harness rather than a weakness in it: a rejection-classification harness exists precisely to pin a malformed shape and assert the exact error it must produce, and it must narrow to that shape to do so. What the list gives you is the ability to check that judgement yourself, harness by harness, instead of taking a count on trust.

- `big_integer::redundant_positive_padding_is_non_minimal_at_length` — `assume(buf[0] == 0x00)`
- `big_integer::redundant_positive_padding_is_non_minimal_at_length` — `assume(buf[1] & 0x80 == 0)`
- `big_integer::redundant_negative_padding_is_non_minimal_at_length` — `assume(buf[0] == 0xFF)`
- `big_integer::redundant_negative_padding_is_non_minimal_at_length` — `assume(buf[1] & 0x80 != 0)`
- `big_integer::strips_redundant_padding` — `assume(buf[1] != 0x00)`
- `generalized_time::roundtrip_all_fields` — `assume(frac[k].is_ascii_digit())`
- `generalized_time::roundtrip_all_fields` — `assume(frac[fl - 1] != b'0')`
- `generalized_time::roundtrip_all_fields` — `assume(fields_in_range(&t))`
- `generalized_time::non_digit_is_classified` — `assume(!bad.is_ascii_digit())`
- `generalized_time::not_zulu_is_classified` — `assume(term != b'Z')`
- `generalized_time::month_range_is_classified` — `assume(mo <= 99 && !(mo >= 1 && mo <= 12))`
- `generalized_time::day_range_is_classified` — `assume(d <= 99 && !(d >= 1 && d <= 31))`
- `generalized_time::bad_fraction_separator_is_classified` — `assume(sep != b'.')`
- `generalized_time::fraction_trailing_zero_is_classified` — `assume(d.is_ascii_digit())`
- `generalized_time::fraction_non_digit_is_classified` — `assume(!bad.is_ascii_digit())`
- `length::indefinite_is_classified` — `assume(buf[0] == 0x80)`
- `length::reserved_is_classified` — `assume(buf[0] == 0xFF)`
- `length::leading_zero_is_non_minimal` — `assume(buf[0] >= 0x81 && buf[0] <= 0x87)`
- `length::leading_zero_is_non_minimal` — `assume(buf[1] == 0x00)`
- `oid::leading_0x80_is_non_minimal` — `assume(buf[0] == 0x80)`
- `oid::later_0x80_is_non_minimal` — `assume(buf[0] < 0x80)`
- `oid::later_0x80_is_non_minimal` — `assume(buf[1] == 0x80)`
- `oid::unterminated_is_truncated` — `assume(buf[0] != 0x80 && buf[0] & 0x80 != 0)`
- `oid::unterminated_is_truncated` — `assume(buf[1] & 0x80 != 0 && buf[2] & 0x80 != 0 && buf[3] & 0x80 != 0)`
- `restricted_string::roundtrip_printable` — `assume((0..n).all(|i| oracle_printable(content[i])))`
- `restricted_string::roundtrip_ia5` — `assume((0..n).all(|i| oracle_ia5(content[i])))`
- `restricted_string::roundtrip_numeric` — `assume((0..n).all(|i| oracle_numeric(content[i])))`
- `restricted_string::roundtrip_visible` — `assume((0..n).all(|i| oracle_visible(content[i])))`
- `restricted_string::out_of_charset_reports_position` — `assume(!(0..n).all(|i| oracle_numeric(buf[i])))`
- `restricted_string::wrong_tag_is_classified_printable` — `assume(id != Charset::Printable.identifier())`
- `restricted_string::wrong_tag_is_classified_printable` — `assume(oracle_printable(v))`
- `restricted_string::wrong_tag_is_classified_ia5` — `assume(id != Charset::Ia5.identifier())`
- `restricted_string::wrong_tag_is_classified_ia5` — `assume(oracle_ia5(v))`
- `restricted_string::wrong_tag_is_classified_numeric` — `assume(id != Charset::Numeric.identifier())`
- `restricted_string::wrong_tag_is_classified_numeric` — `assume(oracle_numeric(v))`
- `restricted_string::wrong_tag_is_classified_visible` — `assume(id != Charset::Visible.identifier())`
- `restricted_string::wrong_tag_is_classified_visible` — `assume(oracle_visible(v))`
- `utc_time::roundtrip_all_fields` — `assume(fields_in_range(&t))`
- `utc_time::non_digit_is_classified` — `assume(!bad.is_ascii_digit())`
- `utc_time::not_zulu_is_classified` — `assume(term != b'Z')`
- `utc_time::month_range_is_classified` — `assume(mo <= 99 && !(mo >= 1 && mo <= 12))`
- `utc_time::day_range_is_classified` — `assume(d <= 99 && !(d >= 1 && d <= 31))`
- `utf8_string::roundtrip` — `assume(oracle_wellformed_utf8(&content[..n]))`
- `utf8_string::ill_formed_reports_position` — `assume(!oracle_wellformed_utf8(&buf[..n]))`
<!-- END GENERATED:non-vacuity -->

The covers are **authored against** a bar: witness a *post-state effect*, never an input predicate.
`cover(len == N)` or `cover(true)` would be satisfiable even if the function body were replaced by a
no-op, and are therefore worthless. The bar is "would this still be satisfiable if the body did
nothing?" — and conformance to it is established by review of 52 hand-written covers, not by any
gate; nothing mechanically rejects a weak cover. — for the stub-bearing composition harnesses that means covering that the
real glue reached its `Ok` tail, and for `x509_extension` that a second walk iteration genuinely
co-occurs with acceptance.

**Two of the 25 harnessed modules carry no `kani::cover`, and both are deliberate:** `boolean` and
`null` have no `kani::assume` at all and characterise a 1-octet input space exhaustively via
`assert!` biconditionals, so a cover would be redundant.

**The `enumerated` module's covers, and why the harness domain was widened.**
`decode_delegates_to_integer` proves an *agreement* — that `decode_enumerated` returns literally what
`crate::integer::decode_integer` returns — and an agreement is the shape that most easily hides
vacuity: it holds just as well if both sides only ever reject, or if only one input width is ever
explored. The harness previously carried no cover at all, so its non-vacuity rested on `integer`'s
proofs rather than on its own witness; that is the residual this section used to flag as open.

It now carries **seven**, and the domain is the wrapper's *whole* reachable input space rather than
`integer`'s: a 9-octet buffer with symbolic length `0..=9`. That widening is the substantive part. An
intermediate version assumed `1 <= n <= 8` — mirroring `integer.rs`'s own buffer choices — and then
explained the two excluded error paths away by pointing at `integer`'s harnesses, which left the
delegation unproven at exactly the two lengths the wrapper can still be handed. A second-model review
called that "stopping one byte short", and it was right. At `0..=9` both `Empty` (needs `n == 0`) and
`TooLarge` (needs `n > 8`) are **reachable and witnessed through the delegation** instead of argued
away in a comment. The seven: accepts at `n == 1`, at an intermediate `2 <= n <= 7`, and at the full
width `n == 8`; a **negative** two's-complement value at `n == 8`; and the exact `Err(NonMinimal)`,
`Err(Empty)` and `Err(TooLarge)` rejections.

`encode_delegates_to_integer` gained three of its own for the same reason — it is the same agreement
shape, un-narrowed — pinning the returned length at both ends of the minimal-encoding range and the
sign octet at full width.

**Read all of them as reachability witnesses, and read the claim precisely.** The agreement itself is
proven symbolically for every length in the domain; nothing is left unproven by the shape of the cover
list. And the covers do *not* individually refute a do-nothing body: a constant `Ok(0)` satisfies the
positive-width witnesses, a constant `Err` satisfies one rejection witness. What no single constant
body satisfies is the *set*; what pins the function to real behaviour at every length is the assert.
The earlier wording here claimed each cover individually met that bar, which was false, and a
second-model review caught it. Two other claims went the same way and are gone: that the `n == 8`
cover shows the accumulator loop runs eight times (it shows an 8-octet slice was *accepted* — trip
count is `integer`'s property, not this harness's), and that a negative value was witnessed at full
width when `[0x80]` at `n == 1` was its cheapest witness — hence the added `&& n == 8` conjunct.

**One residual of this kind remains**, and it is the larger one: `x509_name::validate_rdn_never_panics`
has no cover, and its conditional postcondition is not self-witnessed either — see the correction at
the end of this section. With `encode_delegates_to_integer` now covered, it is the crate's only
harness whose non-vacuity argument points somewhere other than at itself.

**Disclosed non-vacuity gaps.** Three harnesses have a cover that is **known-unsatisfiable at their
bound**. They are left in place rather than deleted, because a cover reporting `0 of 1 satisfied`
is, at each run, the machine-checked *signal* of the gap. As of the committed 2026-07-30 run that
signal **is** read off an artifact rather than only reproduced on demand: all three appear in
`evidence/check-b355f76.log` as `0 of 1 cover properties satisfied`, and no fourth harness does
(§3.4). Each is paired with a companion positive-construction harness on a concrete input:

<!-- BEGIN GENERATED:disclosed-vacuities (gates/gen_proof_manifest.py) -->
| Harness whose `cover` is UNSATISFIABLE at its bound | Companion witness harness | Does the witness itself use `#[kani::stub]`? |
|---|---|---|
| `x509_extension::validate_extensions_never_panics` | `x509_extension::validate_extensions_ok_path_witnessed` | no |
| `x509_tbs_certificate::parse_tbs_certificate_never_panics` | `x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed` | **yes — read it as glue-reachability only** |
| `x509_validity::parse_never_panics` | `x509_validity::parse_validity_ok_path_witnessed` | no |

**The third column is the one that changes what a witness means.** A cover satisfied inside a stub-bearing harness shows that the caller's glue is reachable *given a fabricated `Ok` from the stubbed sub-parser*. It is not evidence that the real sub-parser ever returns `Ok`, and therefore not evidence that the real composition accepts anything.
So for `x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed` the "gap closed" claim is narrower than for the unstubbed rows: what is witnessed is the glue, under stub semantics.
<!-- END GENERATED:disclosed-vacuities -->

In each case the cause is arithmetic, not a cover-authoring error: the reduced buffer is too small
for a well-formed object to exist inside it. A minimal `Validity` needs about 32 octets — two
`Time`s of 15 each plus a 2-octet `SEQUENCE` wrapper — against a 16-octet buffer; two minimal
`Extension`s inside an `Extensions` wrapper need 16 octets, not 13; a minimal TBS body needs far more
than 10. (Those byte counts are hand-derived, not machine-checked — see the note on prose numbers
above.) What each `never_panics` harness proves
is therefore **panic-freedom over its domain including all the rejecting paths**, while the claim
that the deep glue is *exercised* rests on the witness sibling, not on the symbolic harness. Both
halves are stated because either alone would mislead.

**A correction worth stating plainly, because the earlier framing of it was wrong.**
`x509_name::validate_rdn_never_panics` has no cover of its own, and its cheap sibling
`validate_never_panics` does *not* supply one for it: that sibling **stubs** `validate_rdn`, so its
`1 of 1` satisfied cover would still be satisfied if the real `validate_rdn` rejected every input.
It witnesses the RDN-walk glue, not the RDN parser.

So, precisely, for `validate_rdn`: **panic-freedom over its 0..=16-octet domain is proved
unconditionally and is not vacuous** — that is the harness's primary property. Its *postcondition*
(`2 ≤ used ≤ input.len()` on `Ok`) is asserted inside `if let Ok(used) = …`, so it is discharged
conditionally, and **no Kani artifact in this crate witnesses that the real `validate_rdn` ever
returns `Ok`**. That is not unsound — `stub_validate_rdn` returns both `Ok` and `Err`
nondeterministically, over-approximating the real function, and exploring more control-flow outcomes
cannot hide a panic — but it does mean the accept path of the name/TBS/certificate composition is
evidenced by `#[test]` cases, not by proof. Together with the stub-mediated witness row above, that is
the one place in this document where "witness" needs reading carefully, and it is why the table names
which witnesses are stub-mediated.

### 8.3 Oracles — where the *specification* comes from, and what it rests on

A biconditional harness (`validate_iff_minimal_oracle`, `cmp_padded_matches_oracle`,
`charset_exactly_matches_oracle_*`, `accepted_iff_canonical_oracle`, `validate_iff_oracle`) proves
that the production code agrees with a **hand-written reference predicate** — an *oracle*. This is the
crate's strongest class of property and also the one place where a machine-checked proof can be
machine-checked proof *of the wrong thing*: if the oracle misstates X.690, the harness proves faithful
agreement with a mistake. Proofs enforce consistency between implementation and oracle; nothing
enforces the oracle's fidelity to the standard.

The full hand-written helper surface inside `mod proofs`, so a reader can go audit it:

<!-- BEGIN GENERATED:oracles (gates/gen_proof_manifest.py) -->
| Module | Hand-written helpers in `mod proofs` (oracles + stub bodies) | Harnesses that assert an equivalence against one |
|---|---|---|
| `big_integer` | `is_minimal_oracle` | `validate_iff_minimal_oracle` |
| `bit_string` | — | `octet_aligned_iff_unused_zero` |
| `generalized_time` | `is_canonical_der_generalizedtime` | `accepted_iff_canonical_oracle` |
| `profile` | — | `rule1_mismatch_iff_algorithms_differ`, `rule2_requires_v3_iff_extensions_present_and_not_v3`, `rule3_generalized_too_early_iff_year_le_2049` |
| `restricted_string` | `oracle_ia5`, `oracle_numeric`, `oracle_printable`, `oracle_visible` | `charset_exactly_matches_oracle_ia5`, `charset_exactly_matches_oracle_numeric`, `charset_exactly_matches_oracle_printable`, `charset_exactly_matches_oracle_visible`, `validate_iff_all_in_charset_ia5`, `validate_iff_all_in_charset_numeric`, `validate_iff_all_in_charset_printable`, `validate_iff_all_in_charset_visible` |
| `set_of` | `cmp_padded_oracle` | `cmp_padded_matches_oracle`, `ordering_iff_oracle` |
| `tag` | `any_class` | — |
| `tlv` | `any_class` | — |
| `utc_time` | `is_canonical_der_utctime` | `accepted_iff_canonical_oracle` |
| `utf8_string` | `oracle_wellformed_utf8` | `validate_iff_oracle`, `validate_iff_oracle_multi`, `validate_iff_std` |
| `x509_certificate` | `stub_parse_tbs_certificate` | — |
| `x509_name` | `stub_validate_rdn` | — |
| `x509_tbs_certificate` | `stub_parse_validity`, `stub_validate_extensions`, `stub_validate_name` | — |

16 hand-written helper functions in total. Derived by exclusion — every `fn` in a `mod proofs` block that is not itself a harness — so a helper cannot escape this list by being named something unexpected.
<!-- END GENERATED:oracles -->

What mitigates this, and what does not:

- **The oracles are deliberately written in a different shape from the production code**
  ("de-tautologisation" — `DECISIONS.md` D14 and the module docstrings). `big_integer`'s oracle
  reasons about the hypothetical sign-extension byte implied by the first octet rather than replaying
  the production scan; `restricted_string`'s oracles are explicit allow-lists against production
  bit-tests; `utf8_string`'s states Unicode Table 3-7 as byte ranges rather than by code point. A
  single typo therefore cannot hide in both sides. Two of the crate's own review records
  (`DECISIONS.md` D14 addendum, `set_of`) note the counter-argument: this independence is *semantic*,
  not structural, and where both formulations share a step — the msb-of-`l1` test, for instance — a
  shared misreading would survive.
- **`utf8_string` additionally checks against `core::str::from_utf8`**, a genuinely external oracle.
  Note the direction: `from_utf8` is used as a differential *comparison*, never as an input
  constructor — the deliberately sound direction.
- **What does not mitigate it:** nothing gates oracle fidelity, no oracle is derived from the
  standard text mechanically, and the standard itself is not machine-readable. Each oracle's
  justification is prose in its docstring, checked by review against X.690/RFC 5280.

If you are relying on one of these biconditionals, read the oracle, not just the theorem name.

### 8.4 Modular proofs via stubs

Four harnesses are **modular proofs**: they replace an already-independently-proven sub-parser with a
`#[kani::stub]` capturing its proven contract, so CBMC can verify the composition glue tractably.

<!-- BEGIN GENERATED:stubs (gates/gen_proof_manifest.py) -->
| Harness | `#[kani::stub]`-replaced function(s) |
|---|---|
| `x509_certificate::parse_certificate_never_panics` | `crate::x509_tbs_certificate::parse_tbs_certificate` |
| `x509_name::validate_never_panics` | `validate_rdn` |
| `x509_tbs_certificate::parse_tbs_certificate_never_panics` | `validate_name`, `validate_extensions` |
| `x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed` | `validate_name`, `validate_extensions`, `parse_validity` |

Every `kani::assume` inside a **stub body** — each constrains what the stub is allowed to *return*, so each must be discharged by a separate harness or it is an unsound hole:

- `x509_name::stub_validate_rdn` — `assume(2 <= used && used <= input.len())`

For contrast, the other `kani::assume`s outside harness bodies live in input generators and narrow a nondeterministic selector — ordinary harness setup, nothing to discharge:

- `tag::any_class` — `assume(sel < 4)`
- `tlv::any_class` — `assume(sel < 4)`
<!-- END GENERATED:stubs -->

This is sound **because each stubbed function is separately proven at its own harness** — but it is a
compositional argument, not a single monolithic proof, and is disclosed as one. The chain is a DAG:
`x509_certificate` → `x509_tbs_certificate` → {`x509_name` → its `validate_rdn` lemma,
`x509_extension`, and — in the witness harness only — `x509_validity`}, each link a real function
separately proven panic-free. The `parse_validity` edge exists only in
`parse_tbs_certificate_ok_path_witnessed`, which is why the stub table above shows three stubs on
that row and two on the `never_panics` row.

Two properties of the discharge that a reader should check rather than assume:

- **Each stub's contract is discharged over a *symbolic input length* (`0..=N`)**, not just at the
  full `N`-byte buffer. The parsers' control flow is length-dependent and the callers pass suffix
  slices, so a fixed-length discharge would leave the shorter call lengths unproven.
- **Stubs over-approximate.** `stub_validate_rdn` returns both `Ok` and `Err` nondeterministically,
  a superset of the real function's behaviour; exploring more control-flow outcomes cannot hide a
  panic. Where a stub's `Ok` payload is constrained (`2 ≤ used ≤ input.len()`), that constraint is an
  **assumed postcondition discharged by a named sibling harness** (`validate_rdn_never_panics`) —
  never an unproven assumption.

`x509_name`'s harness is modular because the monolithic proof's SET-OF §11.6 ordering over symbolic
content is intractable (>100 GB in CBMC symbolic execution); see `DECISIONS.md` D26.

`cargo kani -Z stubbing` (used by `check.sh`) enables the feature. Harnesses without a
`#[kani::stub]` are unaffected by the flag.

### 8.5 Assumptions

`kani::assume(...)` preconditions constrain the symbolic input — typically bounding a declared length
so a loop stays inside its unwind depth. **An assumption excludes inputs from the proof's domain:**
the properties hold *for inputs satisfying the assumptions*, and inputs outside them are simply not
claimed. Every assumption is inline and visible in its harness.

A small number of `kani::assume`s live in **stub bodies** rather than harnesses (the count is split
out in §1). Those are a different animal: they constrain a stub's *return value* to its proven
postcondition, and each is discharged by a named sibling harness (§8.4). An assumption on a stub's
output that is *not* separately proven would be an unsound hole; there are none.

The six Lean lids remove the length bound entirely for their codecs — that is the point of the L4
layer.

## 9. Documented deviations from full DER/X.509

This crate implements a **strict, deliberately narrowed** profile. Each narrowing is a design
decision recorded in `DECISIONS.md`, not a defect:

- **Range fences on numeric and time fields** — `integer` is capped at `i64`, with `big_integer` as
  the arbitrary-magnitude complement (D2, D14).
- **Leap second `SS=60` is rejected** in both time types (D9).
- **Time types validate single-field ranges, not calendar validity** — day-of-month against month,
  leap years, etc. are not checked (D10).
- **`OCTET STRING` accepts the primitive form only**, rejecting BER constructed/segmented form —
  itself a parser-differential hardening (see the module docs).
- **General `SET` (§10.3) is out of scope**; only `SET OF` (§11.6) member ordering is validated
  (D6, D13).
- **Only explicit context tagging** is addressed (`context_tag`); implicit tagging is not modelled.
- **The `x509_*` modules are structural parsers.** They frame RFC 5280 objects by composing the
  verified codecs and interpret **no** algorithm, key, signature or certificate semantics.
- **`oid` validates encoding form without materialising arc values.**
- **A behaviour-preserving refactor was made for verifiability, not for the runtime:**
  `tag::decode_tag`'s high-tag loop was rewritten from `return`-inside-loop to break-with-`Result`
  so Aeneas would extract a body instead of a bodyless axiom (mirroring the earlier `validate_oid`
  fix, D25). Accept/reject cases, `used` counts and error variants are identical **on the harnessed
  domain**, re-verified there after the change; agreement beyond that domain rests on review of the
  diff, not on a proof.
- **Clippy's `redundant_closure` is silenced, deliberately, in one place.** The
  `map_err(|e| ...)` closures that Aeneas requires are flagged by clippy; the resolution is
  `#[allow]`, **never** reverting to point-free form — the point-free version breaks Lean
  extraction. Do not "fix" this.

**Reviewed 2026-07-30: this deviations list is complete to the best of the maintainer's knowledge,
and non-empty by nature — a narrowed profile is the design.** "Reviewed", not "verified": completeness
of a prose list is not the kind of thing this crate's tools can check.

## 10. Reproduce

```sh
./check.sh          # doc-link gate + manifest gate + cargo test + cargo kani (L3) + Lean lids (L4, guarded)
./check_fast.sh     # fast subset: doc gate + cargo test
```

Read §3.4 first for what a green run does and does not establish on your machine: `./check.sh`
needs roughly 24 GB of available RAM to complete the L3 floor, and skips the entire L4 layer if the
Aeneas/Charon/Lean stack is not installed at the pinned revisions. The skip prints
`== lean lid: SKIP ... ==` — so you can tell from the output whether your green run checked L4 — but
it does not fail, and a reader who does not look will not notice.

See `README.md` for a fresh-clone walkthrough (rustc + Kani install, and the optional Aeneas/Lean
stack), and `docs/verification-cost.md` for per-harness time and memory figures.
