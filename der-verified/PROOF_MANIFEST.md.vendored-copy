# Proof manifest — `der-verified`

This is the **honest proof envelope** for this crate: what is machine-checked, over what domain,
under what assumptions and stubs — and, given equal weight, **what is not**. It exists so that a
reader who is not going to read 298 proof harnesses and 6 Lean developments can still know what
they are being offered, and where the guarantee stops.

Its machine-readable companion is `der-verified/acceptance.toml`. It follows acceptance format
0.3.2 with the Rust verification profile and names its exact validator-closure commit in the
generated header.

> ## The rule this document is written under
>
> **Counts are inventory, not coverage.** "298 Kani harnesses, 6 Lean lids, 539 tests" describes how
> much verification *exists*. It says nothing about how much of the crate's behaviour is covered, and
> a reader who reads it as a coverage figure has been misled by this document, not by themselves. So
> the *claims* below are stated in prose, per property and per bound; the counts sit underneath them
> as evidence, never in place of them. Where a claim would be stronger than the evidence, the
> evidence wins and the claim is narrowed.

> ## What all of this stands on
>
> **`ASSUMPTIONS.md` is this document's companion, and should be read with it.** Everything below
> is machine-checked *given* a trusted base — Kani, CBMC and its SAT backend, the Lean kernel, the
> fidelity of the Aeneas extraction, the toolchain pins, the lids' 13 declared axioms (all of them
> specs for upstream `core` primitives since 2026-08-19 — none is an assumption about this crate's
> own code any more), the meaning of "bounded", the framing layer's named residual (§6.3: a
> well-formed TLV is not a valid DER value encoding; since 2026-08-25 `identifier_form` decides
> that difference, but the framing entry points still do not), and
> the three disclosed-unsatisfiable covers. That base is enumerated in one place, each entry with
> its failure mode and what leans on it, in [`ASSUMPTIONS.md`](ASSUMPTIONS.md). This document says
> what is proven; that one says what has to be true for "proven" to mean what it looks like.

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
| source modules (excl. `lib.rs`) | 33 |
| …of which carry at least one `#[kani::proof]` | 33 |
| public entry points (free `pub fn`s + public `impl` methods) | 84 |
| …named by at least one Kani harness | 83 |
| …named by **no** Kani harness | **1** |
| `#[kani::proof]` harnesses | 298 |
| `kani::assume` harness preconditions, in harness bodies and in the input-generator helpers they call (narrow the proved domain; 29 of the total are in generator helpers) | 293 |
| `kani::assume` inside stub bodies (constrain a stub's *return*, not an input) | 1 |
| `kani::cover` **statements** (satisfaction is observed at a run, is not gate-enforced, and its currency versus HEAD is derived in §3.4, not asserted here) | 504 |
| …harnesses whose cover is **known-unsatisfiable and disclosed** — i.e. known *non*-witnesses | **3** |
| `#[kani::stub]` applications / harnesses using them | 23 / 20 |
| `#[test]` unit + regression tests | 539 |
| crate-doc examples run as doc-tests | 34 |
| Lean lids (`lean/*Proofs.lean`) | 6 |
| `unsafe` blocks in `der-verified/src` | 0 (crate is `#![forbid(unsafe_code)]`: yes) |
<!-- END GENERATED:inventory -->

Zero runtime dependencies (`der-verified/Cargo.toml` has an empty `[dependencies]`), no `alloc` on
the decode paths, and `#![forbid(unsafe_code)]`. **Not `#![no_std]` today** — the crate does not
carry that attribute, though the source is `no_std`-*ready* by measurement (see `TODO.md`'s
"`no_std` support" item, and `DECISIONS.md` D36 for the decision to defer it past 0.1.1 and what
landing it later requires; this line says so rather than claiming the attribute exists). There is
therefore **no
unsafe-code assumption and no third-party-crate assumption in the trust base** — an unusually small
dependency surface, and the reason the classes of verification difficulty that come from `unsafe`
code and from third-party crates do not arise here.

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
| `lean/LengthProofs.lean` | `length` | 46 | 1 |
| `lean/OidProofs.lean` | `oid` | 5 | 0 |
| `lean/SequenceProofs.lean` | `sequence` | 18 | 4 |
| `lean/TagProofs.lean` | `tag` | 36 | 1 |
| `lean/TlvProofs.lean` | `tlv` | 13 | 4 |

The `axiom` column counts the *assumed Aeneas-Std specs declared in the lid file itself* — the trust surface a reader can audit by opening the file. It excludes Lean's own `propext`/`Classical.choice`/`Quot.sound` and `bv_decide`'s certificate axiom. Separately, the lids carry 56 `#print axioms` commands: that is a count of *audit commands* (roughly one per theorem whose dependency set is disclosed at build time), **not** a count of axioms — do not compare it with the column.

One limitation to name explicitly: a declared `axiom` characterising an Aeneas-Std primitive and a bespoke assumption about this crate's own code are syntactically identical, and the latter would be an unsound hole. Nothing in this repository mechanically distinguishes them — the argument that each is an upstream-primitive spec is made in the lid docstrings and rests on review, not on a gate.
<!-- END GENERATED:l4 -->

What each lid proves, **as summarised by the author** — this table is hand-written interpretation,
not generated: the script counts a lid's theorems and axioms but cannot read Lean. For the exact
machine-checked statement, read the named theorem in the lid source. Where this table and the Lean
file disagree, the Lean file is right.

| Codec | Unbounded property |
|---|---|
| `length` (X.690 §8.1.3) | every branch of `decode_length` ∀-length, and round-trip canonicality — Lean theorem `decode_accepts_only_canonical`, whose proof also covers both loops of `encode_length` (`encode_length_loop0_spec`, `encode_length_loop1_spec`); plus the consumption bound `decode_length_used_le` (an accepted decode never reports consuming more bytes than the input holds — added 2026-08-19, and reproduced inside the `tlv`/`sequence` lids' own namespaces, where it replaced two declared axioms — and where a three-line corollary of its triple, `length_decode_total`, replaced the other two on the same date) |
| `big_integer` (X.690 §8.3) | the minimality biconditional on the validate side (`validate_iff_minimal`) and encode-side round-trip/canonicality (`encode_minimal_integer_into_roundtrip`), ∀-length |
| `oid` (X.690 §8.19) | the OID canonical-form biconditional on the validate side (`validate_iff_canonical`), ∀-length |
| `tag` (X.690 §8.1.2) | `decode_tag`'s totality and consumption bound ∀-length (`tag_decode_total`, `tag_decode_used_bounds`); accepted class, constructed-bit, and low-tag-number semantics against a direct X.690 oracle (`tag_decode_identifier_fields`); high-tag base-128 value semantics (`tag_decode_high_tag_accept`); and named non-minimal/overflow classifications. The extraction has a body because the high-tag loop uses break-with-`Result` rather than nested `return` |
| `tlv` | `decode_tlv`'s structural correctness ∀-length: an accepted TLV's `used` equals header + declared length, its value is exactly that window, and — the security-relevant fact — `used ≤ input.length` (`decode_tlv_structure`) |
| `sequence` | `decode_sequence`'s structural correctness ∀-length **and ∀-children**: whenever the child-walk accepts, it consumes exactly the content's bytes, for any number of children (`decode_sequence_structure`). the only lid unbounded in the **number of children** as well as in byte length — `tag` and `length` also prove properties of loops ∀-length, whose trip counts are bounded by the input's byte length; a `SEQUENCE`'s child count likewise grows with the input's length (each child consumes at least one byte), but it has no fixed bound independent of that length, and the lid states the walk for any number of children. Kani's corresponding harness is capped at `unwind(16)` on both width and trip count |

**Trust base for L4, stated rather than hidden.** The Lean proofs check the **Aeneas model** of the
Rust code. The Rust → LLBC → Lean translation is not itself formally verified against rustc
semantics; this is the standard Aeneas assurance boundary. On top of that, each lid assumes a small
number of *Aeneas-Std specs* as `axiom`s — the count is in the table above, the full non-standard
axiom set of every proof is disclosed by `#print axioms` in the sources, and each lid's docstring
explains its own trust surface. **All 13 are specs for upstream `core` primitives Aeneas does not
model** (`<[T]>::first`, `Option::is_some_and`, `Result::map_err`, `<usize as TryFrom<u32>>::try_from`,
`&u8 & u8`), each read against the actual rustc source at the extraction toolchain's pinned nightly
by `evidence/AXIOM-AUDIT-2026-08-18.md`. **No lid declares an axiom about `der-verified`'s own code.**
That was not true until 2026-08-19: four such axioms existed (`length_decode_used_le` ×2,
`length_decode_total` ×2, in the `tlv` and `sequence` lids), and all four were replaced by proofs
that day — see the audit's two discharge addenda, and `ASSUMPTIONS.md` §T for the tombstones. The
syntactic limitation the generated note above states is unchanged: nothing *mechanically* keeps a
crate-code assumption out of a future lid, so the property "13 upstream, 0 crate-code" is a
reviewed fact about today's sources, not a gated one.

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

`cargo test` runs 539 unit and regression tests (plus 34 module and crate-doc examples) over concrete vectors, including
seeded-bad specimens. **These are example-based tests, not property-based and not proofs.** They are
regression road-signs; the assurance claim rests on the harnesses and the lids. For the `profile`
module (§7) they are the *only* evidence that exists.

### 3.4 Run evidence — what has actually been executed, and when

<!-- BEGIN GENERATED:evidence (gates/gen_proof_manifest.py) -->
| Committed log | At commit | `SUCCESSFUL` | `FAILED` | harnesses reporting an unsatisfied cover |
|---|---|---:|---:|---:|
| `evidence/check-0e327b7.log` | `0e327b7` | 191 | 0 | 3 |
| `evidence/check-24ddb69.log` | `24ddb69` | 191 | 0 | 3 |
| `evidence/check-28e1429.log` | `28e1429` | 171 | 0 | 3 |
| `evidence/check-42c8165-heavy-x509_extension-validate_extensions_never_panics.log` | `42c8165` | 1 | 0 | 1 |
| `evidence/check-42c8165-heavy-x509_extension-validate_extensions_ok_path_witnessed.log` | `42c8165` | 1 | 0 | 0 |
| `evidence/check-42c8165-heavy-x509_name-validate_rdn_never_panics.log` | `42c8165` | 1 | 0 | 0 |
| `evidence/check-42c8165.log` | `42c8165` | 294 | 0 | 2 |
| `evidence/check-461f751.log` | `461f751` | 171 | 0 | 3 |
| `evidence/check-69bbc9f.log` | `69bbc9f` | 191 | 0 | 3 |
| `evidence/check-953a1a2.log` | `953a1a2` | 191 | 0 | 3 |
| `evidence/check-b355f76.log` | `b355f76` | 164 | 0 | 3 |
| `evidence/check-ba40709.log` | `ba40709` | 171 | 0 | 3 |
| `evidence/check-bffab69.log` | `bffab69` | 203 | 0 | 3 |
| `evidence/check-d05d3f2.log` | `d05d3f2` | 210 | 0 | 3 |
| `evidence/check-d68eeca-heavy-x509_extension-validate_extensions_never_panics.log` | `d68eeca` | 1 | 0 | 1 |
| `evidence/check-d68eeca-heavy-x509_extension-validate_extensions_ok_path_witnessed.log` | `d68eeca` | 1 | 0 | 0 |
| `evidence/check-d68eeca-heavy-x509_name-validate_rdn_never_panics.log` | `d68eeca` | 1 | 0 | 0 |
| `evidence/check-d68eeca.log` | `d68eeca` | 295 | 0 | 2 |
| `evidence/check-ea8dad4-remainder.log` | `ea8dad4` | 8 | 0 | 2 |
| `evidence/check-ea8dad4.log` | `ea8dad4` | 162 | 0 | 0 |
| `evidence/check-ffcea81.log` | `ffcea81` | 191 | 0 | 3 |
| `evidence/check_tractable-67c1f80.log` | `67c1f80` | 143 | 0 | 1 |

Every column here is read out of the committed log itself, so this table is reproducible from the tree alone and is gate-enforced. Whether a given run still speaks for HEAD needs `git`, which a tarball or shallow clone may not have — that question is answered separately just below, and is advisory for exactly that reason.
<!-- END GENERATED:evidence -->

<!-- BEGIN GENERATED:evidence-coverage (gates/gen_proof_manifest.py) -->
**The run evidence captured at `d68eeca` still speaks for HEAD** (a SPLIT floor of 4 logs, read together: the main half `evidence/check-d68eeca.log` and its 3 heavy-harness companion logs `evidence/check-d68eeca-heavy-x509_extension-validate_extensions_never_panics.log`, `evidence/check-d68eeca-heavy-x509_extension-validate_extensions_ok_path_witnessed.log`, `evidence/check-d68eeca-heavy-x509_name-validate_rdn_never_panics.log`). No build input it depends on has changed since the anchor `d68eeca`: `git diff d68eeca -- check.sh der-verified/src der-verified/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml .cargo der-verified/build.rs lean` is empty.

This is a **sufficient** condition, not an iff. An empty diff over the L3 build inputs (`check.sh der-verified/src der-verified/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml .cargo der-verified/build.rs`) since the anchor, with the §2 toolchain pins unchanged, means the Kani evidence still applies; `lean/` joins that list for the L4 lid. A non-empty diff, or a moved pin, means re-run: it does not by itself show the evidence is wrong. The generator checks the diff only; whether a §2 pin moved is for the reader. Run the command rather than trusting this sentence.

- `evidence/check-0e327b7.log` (at `0e327b7`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-24ddb69.log` (at `24ddb69`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-28e1429.log` (at `28e1429`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-42c8165-heavy-x509_extension-validate_extensions_never_panics.log` (at `42c8165`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-42c8165-heavy-x509_extension-validate_extensions_ok_path_witnessed.log` (at `42c8165`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-42c8165-heavy-x509_name-validate_rdn_never_panics.log` (at `42c8165`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-42c8165.log` (at `42c8165`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-461f751.log` (at `461f751`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-69bbc9f.log` (at `69bbc9f`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-953a1a2.log` (at `953a1a2`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-b355f76.log` (at `b355f76`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-ba40709.log` (at `ba40709`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-bffab69.log` (at `bffab69`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-d05d3f2.log` (at `d05d3f2`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-ea8dad4-remainder.log` (at `ea8dad4`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-ea8dad4.log` (at `ea8dad4`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check-ffcea81.log` (at `ffcea81`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
- `evidence/check_tractable-67c1f80.log` (at `67c1f80`) is superseded: verified source changed after it. It is kept as a dated record, not as a current claim.
<!-- END GENERATED:evidence-coverage -->

The precise provenance of the L3 verdict, stated plainly because "the proofs pass" is the one claim
in this document a reader cannot check from the source alone:

- **The current floor at `d68eeca` (2026-10-10) is a SPLIT floor: there is no single-run 298-harness floor at this commit.**
  `evidence/check-d68eeca.log` is the MAIN half: one capped (`MemoryMax=20G`) `check.sh` pass in which the
  `cargo kani` stage ran **295 harnesses** (a temporary copy of `check.sh` with the kani line restricted
  by `--exact --harness`; `check.sh` itself is unchanged), with the L4 Lean lid and every document gate in the same
  pass — `Complete - 295 successfully verified harnesses, 0 failures, 295 total.` The other **3**
  (`x509_extension::validate_extensions_never_panics`, `x509_extension::validate_extensions_ok_path_witnessed`,
  `x509_name::validate_rdn_never_panics`; kept out of the 20 GiB pass because earlier measurements approached or
  exceeded 20 GiB) ran separately, one at a time, at `MemoryMax=24G`, at the same commit with the same toolchain.
  Their measured peaks under that cap, read from the `peak memory:` header line of each companion log, are **20.1G**,
  **16.5G** and **17.3G** respectively (the `>20 GB peak each` phrase in those headers is the earlier estimate, not
  the measurement). Their logs are `evidence/check-d68eeca-heavy-<module>-<harness>.log`,
  each ending `Complete - 1 successfully verified harnesses, 0 failures, 1 total.` The floor is 295 + 3 = 298, all
  `SUCCESSFUL`. `check.sh`'s own summary line `L3 kani floor: GREEN` refers to the 295-harness restricted stage only.
  The two logs of the extension pair are also the sat-twin evidence of `evidence/planted-twins-2026-10-10/`.
- **The verdict is now read off a committed artifact, not transcribed.** The previous single-pass run was
  **2026-09-18 at commit `d05d3f2`** (`evidence/check-d05d3f2.log`) — `Complete - 210 successfully
  verified harnesses, 0 failures, 210 total.`, `cargo test` green (530 + 34), every document gate
  and the strict lid-staleness gate green in the same pass, `check.sh exit: 0`, 1h14m19s wall
  (peak memory not captured for this run — the header says so rather than inventing a figure). The
  three unsatisfied covers are again exactly the three §8.2 discloses.
  **This run is a single end-to-end pass covering BOTH the L3 Kani floor and the L4 Lean lid** —
  `== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: PASS) ==` with `lean lid: PASS (sorry-free)`
  in the same process — which is the stronger arrangement the earlier 2026-08-19 `24ddb69` VM run
  could not achieve (that clean-room VM had no Aeneas/Charon/Lean stack, so its lid stage `SKIP`ped
  and its L4 came from a separate artifact over the same bytes). It ran on the maintainer's own box
  under the 2026-09-18 relaxation of the estate's box-Kani rule — as a memory-capped detached
  systemd `--user` service — for the same provenance reason `check-bffab69.log` did: this box owns
  the Aeneas/Charon/Lean stack, so a single run covering both floors cannot also be clean-room. The
  earlier single-process run covering both was **2026-08-11 at `ffcea81`** (`evidence/check-ffcea81.log`,
  191/191 with `lean lid: PASS (sorry-free)` in the same pass, ~63m at 21.0 GB under `MemoryMax=22G`). The first such run, described
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
- **Each run has a committed distillation and a local raw log, deliberately.**
  `evidence/check-b355f76.log` is a distillation — per-harness verdicts, cover satisfaction, timings,
  stage banners. The *complete* raw log (`check-b355f76.log.gz` and its siblings) is kept **LOCAL**,
  not committed (owner 2026-09-18: raw gate logs stay out of the repo — `evidence/raw/` is gitignored;
  each raw log is available on request). The distillation stays checkable rather than trusted because
  the distilled file's own header states the exact `grep` that produced it, plus the raw log's byte
  count and sha256 — so a raw log provided on request can be verified byte-for-byte against the header
  it was distilled from. (Historic distilled headers written before 2026-09-18 say the raw was
  "committed alongside"; that was true when written — see `evidence/README.md`.)
- **Which run currently speaks for HEAD is derived, not asserted in prose.** It is stated in the
  advisory region just above §3.4's table, computed as `git diff <anchor> -- <build inputs>` being
  empty. The build inputs are the L3 closure (`check.sh`, `der-verified/src`, `der-verified/Cargo.toml`,
  `Cargo.toml`, `Cargo.lock`, `rust-toolchain.toml`, `.cargo`, `der-verified/build.rs`) plus `lean/` for the
  L4 lid, not the two source trees alone. The anchor is the run's capture commit (`d68eeca` for the split
  floor) or, when that commit is not part of the published history, the published commit with the identical tree. An empty diff with the §2 toolchain pins unchanged is a **sufficient** condition for the
  evidence to still apply, never an iff: anything else means re-run, not that the evidence is wrong. A
  split floor is named as one set (the main log and every companion log together). That region is
  deliberately *advisory*: it needs git history, which a tarball or a shallow clone may not have, and
  making `./check.sh` depend on the reader's environment is the exact defect the `pins-observed` split
  fixed. Every count in the evidence table itself is read out of the committed log and stays
  gate-enforced.
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
  the memory-tractable share — 221 of the 298 harnesses (the shard filters are by module, not a
  pinned count, so read the workflow for the exact set), sharded across three 7 GB runners; the
  remainder is a local-milestone check. See `docs/verification-cost.md` for the per-harness numbers.

**At `d05d3f2`, L3 and L4 were witnessed by the same single run, which removed the separate-artifact drift
argument earlier versions of this bullet had to make. At `d68eeca` the lean-lid stage ran in the same pass as the
295-harness main half of the split floor, and the 3 heavy harnesses ran separately, so there is no single-run L3
floor at that commit (§3.4).** The `d05d3f2` run set `DER_REQUIRE_LEAN=1`,
so the L4 lean-lid stage ran in the same pass as the L3 floor — an absent Aeneas/Charon/Lean stack
would have *failed* it, not skipped — and printed `lean-lid-status: PASS` / `lean lid: PASS
(sorry-free)`. The six extracted codecs are `length`, `big_integer`, `oid`, `tag`, `tlv` and
`sequence`; the lid **re-extracts each from the shipped `.rs` and fails closed on drift**, so its
PASS at `d05d3f2` concerns exactly the bytes shipped at that commit — including the 2026-09 tag-lid
value-semantics rewrite, which this run's lid stage covers. Because the lid re-extracts and
drift-gates on every run, L4 currency is established by the committed run itself and does not rest on
a hand-tracked "last full pass at commit X, nothing changed since" argument (which rots toward
over-claiming the moment a lid source lands — the exact defect the derived HEAD-currency check in
§3.4 replaced).

**Public CI is the one piece of run evidence a third party can inspect without a large machine.**
`.github/workflows/ci.yml` runs `cargo test`, `cargo clippy -D warnings`, and the memory-tractable
Kani share on every push. Its most recent recorded conclusion before this commit was **success at
`bd318e2`** (2026-07-26). Three limits on what that buys you: it covers roughly 136 of the 164
harnesses, not the two heavy ones; a harness reporting an unsatisfied `cover` passes CI exactly as it
passes locally (§6.1); and it never runs the L4 lids. CI is a floor under regressions in the tractable
share, not a substitute for the full gate.

**Negative controls — the evidence that these oracles can go RED at all.** A green run is only as
meaningful as the oracle's ability to fail, and a suite nobody has watched fail is a suite whose
green is unmeasured. Four campaigns are recorded, and each says in its own words what it does *not*
cover: `evidence/MUTATION-CONTROLS-2026-08-18.md` (a planted defect in each of `length`, `tag`,
`tlv`, `integer` and `big_integer`, each caught by the harness whose documented job is to catch it,
each reverted byte-identically and re-run green);
`evidence/MUTATION-CONTROLS-2026-08-19-oid-sequence.md` (the same protocol extended to `oid` and
`sequence` — the two remaining ∀-length-lidded DER base codecs — run on a disposable host from a
fresh clone of the published commit, and carrying two deliberately **predicted-GREEN** runs that
identify which harness in each pair is actually load-bearing);
`evidence/PLANTED-SATISFIED-TWINS-2026-08-18.md`
(for the three disclosed-unsatisfiable covers of §8.2, a twin that *is* satisfiable at the same
bound, so "unsatisfiable" is distinguished from "cover never fires here"); and
`evidence/LID-MUTATION-CONTROLS-2026-08-19.md` (for the L4 lineage: **eleven** mutations across the
six lids — six theorem statements, two independent oracle predicates, and, in that file's two dated
addenda, the three copies of the `decode_length_used_le` consumption bound and the two
`length_decode_total` corollaries that between them replaced the lids' four crate-code axioms —
each confirmed to fail `lake build`, each reverted
byte-identically, with the affected lids force re-elaborated green afterwards). These are
samples, not sweeps: no automated mutation tooling is wired into this repository, in either lineage.

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
Reading the `symbolic [u8; N]` column: it reports syntactically declared array sizes inside harness bodies, including concrete specimens, fully symbolic buffers and small symbolic sub-arrays. The largest entry is therefore not necessarily a symbolic input domain. It does not list a buffer built as `[0u8; N]` or inside a helper function, so a larger backing buffer with symbolic fields is invisible to it. The per-harness input domains and the backing capacities are stated per module in §6.2.

| Module | entry points | named by a harness | Kani | symbolic `[u8; N]` | unwind | `assume` | `cover` | stubs | L4 |
|---|---:|---:|---:|---|---|---:|---:|---:|:--:|
| `big_integer` | 3 | 3 | 13 | 20 | 1..22 | 15 | 4 | 0 | ✅ |
| `bit_string` | 3 | 3 | 12 | 3..8 | 6..10 | 14 | 22 | 0 |  |
| `boolean` | 2 | 2 | 3 | 16 | — | 1 | 3 | 0 |  |
| `context_tag` | 1 | 1 | 3 | 16 | 20 | 3 | 9 | 0 |  |
| `ec_private_key` | 2 | 2 | 4 | 10..121 | 20 | 3 | 21 | 0 |  |
| `ecdsa_sig_value` | 2 | 2 | 4 | 16..71 | 20 | 3 | 19 | 0 |  |
| `encrypted_private_key_info` | 2 | 2 | 4 | 11..16 | 20 | 3 | 13 | 0 |  |
| `enumerated` | 2 | 2 | 3 | 9 | 12 | 1 | 10 | 0 |  |
| `generalized_time` | 3 | 3 | 19 | 3..20 | 16..21 | 25 | 28 | 0 |  |
| `identifier_form` | 4 | 4 | 12 | 6 | 12 | 4 | 7 | 0 |  |
| `integer` | 2 | 2 | 7 | 8..10 | 12 | 4 | 2 | 0 |  |
| `length` | 2 | 2 | 9 | 8 | 10 | 7 | 1 | 0 | ✅ |
| `null` | 1 | 1 | 1 | 16 | — | 1 | 3 | 0 |  |
| `octet_string` | 2 | 2 | 8 | 3..16 | 16..17 | 10 | 11 | 0 |  |
| `oid` | 1 | 1 | 5 | 4..6 | 8 | 5 | 2 | 0 | ✅ |
| `pkcs8` | 2 | 2 | 4 | 16..48 | 20 | 3 | 20 | 0 |  |
| `profile` | 1 | 1 | 8 | 1..4 | 4..6 | 8 | 42 | 0 |  |
| `restricted_string` | 14 | 13 | 42 | 3..16 | 6..16 | 37 | 17 | 0 |  |
| `rsa_private_key` | 2 | 2 | 23 | 16..317 | 5..20 | 21 | 71 | 16 |  |
| `rsa_public_key` | 2 | 2 | 4 | 16..270 | 20 | 3 | 19 | 0 |  |
| `sequence` | 6 | 6 | 7 | 8..16 | 16 | 3 | 4 | 0 | ✅ |
| `set_of` | 5 | 5 | 18 | 3..16 | 7..16 | 11 | 29 | 0 |  |
| `tag` | 2 | 2 | 7 | 7 | 12 | 6 | 2 | 0 | ✅ |
| `tlv` | 3 | 3 | 5 | 3..16 | 16 | 3 | 3 | 0 | ✅ |
| `utc_time` | 3 | 3 | 16 | 14..17 | 14..18 | 16 | 23 | 0 |  |
| `utf8_string` | 4 | 4 | 12 | 4..16 | 6..16 | 17 | 16 | 0 |  |
| `x509_algorithm_identifier` | 1 | 1 | 2 | 16 | 20 | 2 | 4 | 0 |  |
| `x509_certificate` | 1 | 1 | 1 | 12 | 12 | 1 | 1 | 1 |  |
| `x509_extension` | 2 | 2 | 10 | 2..16 | 3..20 | 6 | 32 | 0 |  |
| `x509_name` | 1 | 1 | 16 | 2..20 | 3..12 | 19 | 36 | 1 |  |
| `x509_spki` | 1 | 1 | 2 | 16 | 20 | 2 | 2 | 0 |  |
| `x509_tbs_certificate` | 1 | 1 | 2 | 10..135 | 12 | 1 | 2 | 5 |  |
| `x509_validity` | 1 | 1 | 12 | 3..32 | 20 | 35 | 26 | 0 |  |
<!-- END GENERATED:per-module -->

### 4.1 Entry points named by no harness

<!-- BEGIN GENERATED:unharnessed-entry-points (gates/gen_proof_manifest.py) -->
- **`restricted_string`** — `Charset::tag_number`
<!-- END GENERATED:unharnessed-entry-points -->

Entry points include **public methods on public types**, not only free functions — `Charset::contains`
and `Elements::new` are as much part of the API surface as `decode_length` is. An earlier version of
the generator scanned free functions only and silently missed four of them, and a later pass missed
`Iterator::next` on `Elements` as well (a trait-impl method carries no `pub` keyword). The counts in
§1 and in the table above are the corrected ones.

Honest classification of that list (2026-10-02: ten of the former eleven are now named by harnesses):

1. **The eight `restricted_string` per-charset wrappers** and **`utf8_string::decode_utf8_str`** are
   no longer on the list: each now has an exact-delegation harness (`wrapper_decode_*_delegates`,
   `wrapper_encode_*_delegates`, `decode_str_is_exact_delegation`), so a transposed constant —
   `decode_ia5_string` delegating with `Charset::Printable` — now fails a proof (observed red,
   2026-10-02), where before only `#[test]` cases covered the pairing.
2. **`generalized_time::require_no_fraction`** is no longer on the list either:
   `require_no_fraction_iff_no_fraction_octets` proves its biconditional over decoded times.
3. **`Charset::tag_number`** — a `pub const fn` returning the charset's UNIVERSAL tag number by
   `match`. No harness *names* it, but it is not unexercised: `Charset::identifier` calls it, and the
   `wrong_tag_is_classified_*` harnesses call `identifier()` for all four charsets, so `tag_number`
   is symbolically executed under Kani in those four harnesses. This is the clearest illustration of
   why "named by a harness" is only a syntactic proxy — here it undercounts.
**The correction.** Until this revision a fourth item sat here calling `profile::validate_profile`
"a genuine gap, and the largest single one in the crate ... no Kani harness and no Lean lid". That
stopped being true when the `profile` harnesses landed: §5's generated property list names
`validate_profile_never_panics`, §7 describes six harnesses over that module, and the generated
list above — which is derived from the source, not typed — has never contained `profile`. So the
generated regions agreed with each other and with §1's count of eleven, while the prose beside them
did not. **This is the failure mode this document warns about in its own opening section**: the half
a gate cannot check is exactly where a claim rots, and here it rotted in the *pessimistic* direction
(a gap disclosed that no longer existed), which is the only reason it was survivable. `validate_profile`
still has **no Lean lid** — that residual is real and is stated in §6.2 and §7, where it belongs.

**No entry point in this crate is claimed to be proven where it is not.** The one remaining unnamed
entry point, `Charset::tag_number`, needs nothing further — it is symbolically executed inside the four
`wrong_tag_is_classified_*` harnesses, it is simply not *named* by one.

## 5. Properties proven — per module

The harness names *are* the property names; this is the index into them. Read the harness for the
exact statement, including its `assume` preconditions.

<!-- BEGIN GENERATED:properties (gates/gen_proof_manifest.py) -->
- **`big_integer`** (13): `validate_iff_minimal_oracle`, `accepted_is_fixed_point_of_minimizer`, `minimizer_output_is_always_minimal`, `minimality_is_local`, `validate_never_panics`, `encode_never_panics`, `empty_is_empty`, `redundant_positive_padding_is_non_minimal`, `redundant_negative_padding_is_non_minimal`, `redundant_positive_padding_is_non_minimal_at_length`, `redundant_negative_padding_is_non_minimal_at_length`, `is_negative_matches_sign_bit`, `strips_redundant_padding`
- **`bit_string`** (12): `roundtrip_canonical`, `decode_never_panics`, `decode_accepts_only_canonical`, `accepted_iff_canonical_oracle`, `encode_rejects_exactly_the_non_canonical`, `decode_is_exactly_the_reference`, `empty_is_classified`, `unused_too_large_is_classified`, `nonzero_padding_is_classified`, `empty_nonzero_unused_is_classified`, `octet_aligned_iff_unused_zero`, `require_octet_aligned_exact_on_built_values`
- **`boolean`** (3): `one_octet_is_canonical`, `roundtrip`, `wrong_length_is_bad_length`
- **`context_tag`** (3): `decode_explicit_context_never_panics`, `decode_explicit_context_faithful`, `decode_explicit_context_exact_result`
- **`ec_private_key`** (4): `parse_never_panics`, `parse_faithful`, `parse_strict_never_panics`, `parse_ok_path_witnessed`
- **`ecdsa_sig_value`** (4): `parse_never_panics`, `parse_faithful`, `parse_strict_never_panics`, `parse_strict_ok_path_witnessed_high_bit_r`
- **`encrypted_private_key_info`** (4): `parse_never_panics`, `parse_faithful`, `parse_strict_never_panics`, `parse_ok_path_witnessed`
- **`enumerated`** (3): `decode_delegates_to_integer`, `encode_delegates_to_integer`, `roundtrip`
- **`generalized_time`** (19): `roundtrip_all_fields`, `decode_never_panics`, `decode_accepts_only_canonical`, `accepted_iff_canonical_oracle`, `decode_is_exactly_the_reference`, `require_no_fraction_iff_no_fraction_octets`, `encode_is_total_exact_oracle`, `short_length_is_bad_length`, `non_digit_is_classified`, `not_zulu_is_classified`, `month_range_is_classified`, `day_range_is_classified`, `hour_range_is_classified`, `minute_range_is_classified`, `second_range_is_classified`, `bad_fraction_separator_is_classified`, `fraction_empty_is_classified`, `fraction_trailing_zero_is_classified`, `fraction_non_digit_is_classified`
- **`identifier_form`** (12): `oracle_is_well_formed`, `required_form_matches_oracle_on_all_u32`, `reserved_eoc_rejected_iff_universal_zero`, `constructed_form_rule_matches_oracle_on_all_tags`, `accepts_iff_no_encoded_rule_violated_and_never_rejects_non_universal`, `decode_tlv_form_checked_is_decode_tlv_refined_by_the_rule`, `decode_tlv_form_checked_strict_requires_full_consumption`, `rejects_every_disclosed_illegal_identifier`, `high_tag_universal_types_are_form_checked`, `legal_der_the_comparison_library_rejected_is_still_accepted`, `real_x509_identifiers_are_still_accepted`, `content_errors_are_deliberately_not_caught`
- **`integer`** (7): `roundtrip_all_i64`, `decode_never_panics`, `decode_accepts_only_minimal`, `empty_is_classified`, `redundant_positive_padding_is_non_minimal`, `redundant_negative_padding_is_non_minimal`, `nine_octets_is_too_large`
- **`length`** (9): `roundtrip_all_u32`, `decode_never_panics`, `decode_accepts_only_canonical`, `indefinite_is_classified`, `reserved_is_classified`, `leading_zero_is_non_minimal`, `long_form_of_short_value_is_non_minimal`, `truncated_long_form_is_classified`, `too_large_is_classified`
- **`null`** (1): `only_empty_is_valid`
- **`octet_string`** (8): `roundtrip_small`, `encode_with_symbolic_capacity_is_exact`, `decode_never_panics`, `accepted_content_is_the_tlv_value`, `classification_is_exact`, `constructed_form_is_rejected`, `non_octet_string_tag_is_wrong_tag`, `accepted_identifier_is_canonical_0x04`
- **`oid`** (5): `validate_never_panics`, `empty_is_classified`, `leading_0x80_is_non_minimal`, `later_0x80_is_non_minimal`, `unterminated_is_truncated`
- **`pkcs8`** (4): `parse_never_panics`, `parse_faithful`, `parse_strict_never_panics`, `parse_ok_path_witnessed`
- **`profile`** (8): `utc_time_can_never_denote_2050_or_later`, `rule1_mismatch_iff_algorithms_differ`, `validate_profile_is_exactly_the_documented_precedence`, `rule2_requires_v3_iff_extensions_present_and_not_v3`, `rule3_generalized_too_early_iff_year_le_2049`, `rule4_fraction_iff_generalized_with_fraction`, `error_precedence_follows_declaration_order`, `validate_profile_never_panics`
- **`restricted_string`** (42): `charset_exactly_matches_oracle_printable`, `charset_exactly_matches_oracle_ia5`, `charset_exactly_matches_oracle_numeric`, `charset_exactly_matches_oracle_visible`, `validate_iff_all_in_charset_printable`, `validate_iff_all_in_charset_ia5`, `validate_iff_all_in_charset_numeric`, `validate_iff_all_in_charset_visible`, `roundtrip_printable`, `roundtrip_ia5`, `roundtrip_numeric`, `roundtrip_visible`, `decode_never_panics`, `constructed_form_is_rejected_printable`, `constructed_form_is_rejected_ia5`, `constructed_form_is_rejected_numeric`, `constructed_form_is_rejected_visible`, `accepted_identifier_is_canonical_printable`, `accepted_identifier_is_canonical_ia5`, `accepted_identifier_is_canonical_numeric`, `accepted_identifier_is_canonical_visible`, `out_of_charset_reports_position`, `wrong_tag_is_classified_printable`, `wrong_tag_is_classified_ia5`, `wrong_tag_is_classified_numeric`, `wrong_tag_is_classified_visible`, `decode_is_faithful_printable`, `decode_is_faithful_ia5`, `decode_is_faithful_numeric`, `decode_is_faithful_visible`, `wrapper_decode_printable_delegates`, `wrapper_decode_ia5_delegates`, `wrapper_decode_numeric_delegates`, `wrapper_decode_visible_delegates`, `wrapper_encode_printable_delegates`, `wrapper_encode_ia5_delegates`, `wrapper_encode_numeric_delegates`, `wrapper_encode_visible_delegates`, `encode_is_exact_printable`, `encode_is_exact_ia5`, `encode_is_exact_numeric`, `encode_is_exact_visible`
- **`rsa_private_key`** (23): `parse_never_panics`, `parse_strict_never_panics`, `parse_ok_2prime_witnessed`, `validate_other_prime_infos_never_panics`, `validate_other_prime_info_never_panics`, `parse_faithful_two_prime_s1`, `parse_faithful_two_prime_s2`, `parse_rejects_missing_fields`, `parse_rejects_two_octet_version`, `parse_other_prime_infos_tail_empty`, `parse_other_prime_infos_tail_primitive`, `parse_other_prime_infos_tail_truncated`, `parse_other_prime_infos_tail_trailing`, `parse_other_prime_infos_tail_set`, `parse_multi_prime_faithful`, `parse_rejects_outer_identifier`, `parse_rejects_field_identifier`, `parse_rejects_field_length`, `parse_multi_prime_rejects_member_identifier`, `parse_multi_prime_rejects_member_length`, `parse_multi_prime_rejects_member_field_identifier`, `parse_multi_prime_rejects_member_field_length`, `parse_multi_prime_rejects_member_shape`
- **`rsa_public_key`** (4): `parse_never_panics`, `parse_faithful`, `parse_strict_never_panics`, `parse_strict_ok_path_witnessed_rsa_2048_shaped`
- **`sequence`** (7): `iterate_never_panics`, `no_over_read`, `ok_implies_exact_tiling`, `roundtrip_two_children`, `tag_correctness`, `accepted_identifier_is_canonical_0x30`, `strict_rejects_trailing`
- **`set_of`** (18): `refactored_walk_matches_previous_walk`, `iterate_never_panics`, `no_over_read`, `ok_implies_exact_tiling`, `ordering_iff_oracle`, `cmp_padded_matches_oracle`, `unsorted_children_are_rejected`, `unsorted_reports_first_violation_index`, `unsorted_reports_first_violation_index_depth_four`, `duplicate_adjacent_encodings_are_accepted`, `tag_correctness`, `accepted_identifier_is_canonical_0x31`, `strict_rejects_trailing`, `roundtrip_two_sorted_children`, `ordering_matches_whole_encoding_oracle`, `tlv_entry_enforces_ordering_exactly`, `strict_is_exact_composition`, `encode_is_exact_over_content_and_capacity`
- **`tag`** (7): `roundtrip_all_tags`, `decode_tag_never_panics`, `decode_tag_accepts_only_canonical`, `high_tag_of_small_number_is_non_minimal`, `leading_zero_high_tag_is_non_minimal`, `truncated_high_tag_is_classified`, `too_large_tag_is_classified`
- **`tlv`** (5): `decode_tlv_never_panics`, `decode_tlv_structure`, `tlv_roundtrip_small`, `tlv_truncated_value_is_classified`, `strict_rejects_trailing`
- **`utc_time`** (16): `roundtrip_all_fields`, `decode_never_panics`, `decode_accepts_only_canonical`, `accepted_iff_canonical_oracle`, `decode_is_exactly_the_reference`, `encode_is_total_exact_oracle`, `wrong_length_is_bad_length`, `non_digit_is_classified`, `not_zulu_is_classified`, `month_range_is_classified`, `day_range_is_classified`, `hour_range_is_classified`, `minute_range_is_classified`, `second_range_is_classified`, `decode_postcondition_fields_in_range`, `full_year_pivot_is_correct`
- **`utf8_string`** (12): `validate_iff_oracle`, `validate_iff_oracle_multi`, `validate_iff_std`, `roundtrip`, `decode_never_panics`, `constructed_form_is_rejected`, `accepted_identifier_is_canonical`, `wrong_tag_is_classified`, `ill_formed_reports_position`, `decode_is_faithful`, `decode_str_is_exact_delegation`, `encode_is_exact_over_content_and_capacity`
- **`x509_algorithm_identifier`** (2): `parse_algorithm_identifier_never_panics`, `parse_faithful`
- **`x509_certificate`** (1): `parse_certificate_never_panics`
- **`x509_extension`** (10): `parse_extension_never_panics`, `validate_extensions_never_panics`, `validate_extensions_ok_path_witnessed`, `parse_extension_faithful`, `validate_extensions_structured_empty`, `validate_extensions_structured_one_member`, `validate_extensions_structured_two_members`, `validate_extensions_structured_second_identifier`, `validate_extensions_rejects_child_framing`, `validate_extensions_rejects_outer_envelope`
- **`x509_name`** (16): `validate_rdn_never_panics`, `validate_never_panics`, `validate_name_single_atv_exact`, `validate_name_outer_identifier`, `validate_name_rdn_identifier`, `validate_name_atv_identifier`, `validate_name_oid_identifier`, `validate_name_two_rdns_exact`, `validate_name_empty_rdn`, `validate_name_empty_sequence_accepted`, `validate_name_atv_trailing_exact`, `validate_name_atv_missing_value_exact`, `validate_name_two_atvs_exact`, `validate_name_two_atvs_unsorted`, `validate_name_atv_value_length`, `validate_name_atv_oid_length`
- **`x509_spki`** (2): `parse_never_panics`, `parse_faithful`
- **`x509_tbs_certificate`** (2): `parse_tbs_certificate_never_panics`, `parse_tbs_certificate_ok_path_witnessed`
- **`x509_validity`** (12): `parse_never_panics`, `parse_validity_ok_path_witnessed`, `parse_validity_faithful`, `parse_validity_faithful_uu`, `parse_validity_faithful_ug`, `parse_validity_faithful_gu`, `parse_validity_faithful_gg`, `parse_validity_rejects_outer_identifier`, `parse_validity_rejects_field_identifier`, `parse_validity_rejects_missing_fields`, `parse_validity_rejects_field_content`, `parse_validity_rejects_field_length`
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
| `tag` | ∀-length totality, consumption bounds, accepted identifier-field semantics, and the stated high-tag accept-value semantics are proven in Lean; the *canonicality/minimality* rejection properties are Kani-bounded only, at a **7-byte** symbolic buffer (`decode_tag_accepts_only_canonical`/`high_tag_of_small_number_is_non_minimal` et al., §4's `tag` row) — non-minimal high-tag encodings beyond that bound are not covered by the ∀-length Lean lid |
| `length` | fully lifted to ∀-length in Lean; no known residual beyond the Aeneas trust boundary |
| `tlv` | **no over-read is proven, and this row names it because nothing else in the module's own clause did**: an accepted TLV consumes `used ≤ input.len()` and its value borrow is exactly `input[header..used]` — Kani-bounded at a 16-byte buffer (`decode_tlv_structure`) *and* ∀-length in Lean (§3.2's `tlv` row). Not proven: the strict (anti-trailing-data) variant's rejection classification, which is Kani-bounded only. **Also not proven of `tlv`, deliberately:** any judgement that the parsed identifier is a *legal DER identifier for a value*. Since 2026-08-25 the primitive/constructed form rules and the EOC exclusion ARE decided by `identifier_form`, whose `decode_tlv_form_checked` composes them onto this reader; `decode_tlv` itself keeps its permissive framing-only behaviour by design, so the residual is live for its own callers (§6.3) |
| `context_tag` | bounded-backing evidence (**CONTRACT SURFACE / bounded-backing evidence, not an unrestricted proof**). The three `decode_explicit_context_*` harnesses decide the exact total `Result` over a fully symbolic buffer of **≤ 16 bytes** with a symbolic `len ≤ 16` and a full-range tag number `n`, at `#[kani::unwind(20)]`, with **no stubs**. Only the **explicit**-context form is modelled — implicit tagging is not. Inner-TLV well-formedness and tiling are the caller's: an `Ok` does not require the value octets to be one complete inner TLV (`A0 00` and `A0 01 FF` are accepted). Nothing is claimed beyond 16 bytes |
| `boolean` | bounded only. The one-octet input is characterised exhaustively (all 256 values); every other content length `0..=16` except 1 is covered with fully symbolic content and is rejected as `BadLength`. Content longer than 16 octets is not machine-checked |
| `integer` | values are capped at `i64` by design (see §9); `big_integer` is the arbitrary-magnitude complement. Bounded only |
| `big_integer` | validate-side minimality and encode-side round-trip are ∀-length in Lean; the classification of *specific* malformed shapes is Kani-bounded only |
| `null` | bounded only. Empty content is accepted exactly; every content length `1..=16` with fully symbolic content is rejected as `NonEmpty`. Content longer than 16 octets is not machine-checked |
| `oid` | canonical-form biconditional is ∀-length; **arc values are never materialised** — `validate_oid` validates encoding form and does not decode arcs, so no arithmetic-overflow property about arc values exists to prove |
| `bit_string` | bounded only; no unbounded lid |
| `octet_string` | bounded only; the BER constructed/segmented form is rejected by design (§9), so no property about it is claimed |
| `enumerated` | bounded only; it is a thin re-tag of `integer` and inherits that module's `i64` fence. Its `decode_delegates_to_integer` harness is `assume`-narrowed and carries seven covers, over a 9-octet buffer with a symbolic length `0..=9` — see §8.2 |
| `restricted_string` | bounded only; `Charset::tag_number` is the one entry point no harness names (§4.1) — it is exercised inside the `wrong_tag_is_classified_*` harnesses through `Charset::identifier` |
| `utf8_string` | bounded only; equivalence with `core::str::from_utf8` is proven as a *differential oracle* over the bounded domain, not ∀-length |
| `utc_time` | bounded only. Single-field range validation only — **no calendar validity** (day-of-month against month, leap years); leap-second `SS=60` is rejected by design (§9) |
| `generalized_time` | bounded only. Same calendar-validity and leap-second fences |
| `sequence` | structural child-walk correctness is ∀-length and ∀-children; the strict variants' rejection classification is Kani-bounded only. The walk inherits `tlv`'s residual: it judges each child's *framing*, never whether the child's identifier is a legal DER identifier. `identifier_form` decides that rule but is **not** wired into this walk, and decides one identifier rather than a tree — so a recursive validator must apply it per child itself (§6.3) |
| `set_of` | Lean proves each accepted shared `Elements` step for a remaining slice of any length (`elements_next_progress`), but does not prove exhaustion of the SET OF loop. SET OF's whole-loop exhaustion, raw-span recovery, member-ordering (§11.6), error mapping, and count glue are **CONTRACT SURFACE / bounded-backing evidence**, not unrestricted proofs (cursor `0..=6`; exact-result equivalence/oracle `0..=8`); the equivalence harness checks production's returned results only, and the link between production's call sequence and the harness-owned iterator is by source inspection. **General `SET` (§10.3) is out of scope** (§9) |
| `x509_algorithm_identifier` | bounded, structural only: frames the object; interprets no algorithm semantics and no parameters |
| `ecdsa_sig_value` | bounded, structural only: DER framing and canonicality of `SEQUENCE { r INTEGER, s INTEGER }`. **No curve-order range check** (`1 <= r,s <= n-1` needs a curve identifier this container does not carry), **no low-S policy** (protocol profile, not DER validity), **no cryptographic interpretation** |
| `rsa_private_key` | bounded-backing evidence for the two-prime structure (**CONTRACT SURFACE / bounded-backing evidence, not an unrestricted proof**): the S1/S2 symbolic-content skeletons and the perturbation harnesses decide the exact `Result`, with backing **≤ 44 bytes**. The multi-prime **member walk** is covered for **one member of three 1-octet INTEGERs**. `parse_multi_prime_faithful` has symbolic content for all three member INTEGERs; the `parse_multi_prime_rejects_*` harnesses have concrete member content and one symbolic framing octet or selector (the perturbed octet, field or element count); like `identifier_form`'s fixture harnesses, these are not part of the contract claim beyond that shape. **Not covered: more than one member, multi-octet member INTEGERs, the strict entry point on a multi-prime input.** The payload of `BadOuterSeq` for the outer envelope (the inner `SequenceError::Tlv(_)` detail) is not pinned by the exact-result harnesses. Panic-freedom is proven **≤ 20 bytes** (`parse_never_panics`/`parse_strict_never_panics`); a real two-prime `RSAPrivateKey` is **~317 bytes** — panic-freedom beyond 20 bytes is **not machine-checked**: it rests on an un-machine-checked compositional argument (each field decoder proven panic-free on its own) plus a single concrete 317-byte fixture (`parse_ok_2prime_witnessed`) and `#[cfg(test)]` examples, not a symbolic proof over the real-size domain. No RSA arithmetic (`n = p*q`, CRT-parameter consistency, primality) is checked — every key-material INTEGER is opaque, comparison-only content. `rsa_private_key` is in the **HEAVY** tier (`gates/tiers.txt`): its harnesses are not run by the public CI, only by `./check.sh` on a machine with at least 24 GB of RAM |
| `x509_spki` | bounded, structural only: no key parsing, no key validity, no algorithm/key agreement check |
| `x509_name` | bounded-backing evidence (**CONTRACT SURFACE / bounded-backing evidence, not an unrestricted proof**); no name-constraint semantics, no string canonicalisation/comparison rules. Covered: single-ATV RDNs; two single-ATV RDNs; one RDN with two ATVs of **different** encoded lengths (the ordering is then decided at the length octet — the general comparison is `set_of::cmp_padded`'s claim, not this module's); 1-octet OIDs; zero-length values outside the framing harnesses; OID lengths `0x03`/`0x83` are excluded. **Not covered: two ATVs of equal encoded length (a solver tool limit — the fully symbolic harness exceeds the memory budget under one global unwind bound — disclosed in the harness comments) and RDNs with more than two ATVs.** The payload of `BadOuterSeq` for the outer envelope (the inner `SequenceError::Tlv(_)` detail) is not pinned by the exact-result harnesses. The composition proof `validate_never_panics` is **modular** (`validate_rdn` stubbed — §8.4); the stub is discharged by `validate_rdn_never_panics`, a **heavy** harness (kept out of the 20 GiB-capped main floor because earlier measurements approached or exceeded 20 GiB; run separately in a 24 GiB window, where its measured peak was 16.3G, §3.4) |
| `x509_validity` | bounded-backing evidence (**CONTRACT SURFACE / bounded-backing evidence, not an unrestricted proof**), no comparison against a clock. Three distinct size concepts matter here. The backing buffer of the skeleton harnesses is `[u8; 47]` (**skeletons ≤ 47 bytes**); it is built as `[0u8; 47]` or in a helper, so the §4 column does not list it. The fully symbolic arrays are small: `parse_never_panics` is a fully symbolic `[u8; 16]` with a symbolic length `0..=16`, and `parse_validity_rejects_field_content` has one fully symbolic 13-octet field. The widest `[u8; N]` the §4 row shows (32) is the **concrete** specimen of `parse_validity_ok_path_witnessed`, not a symbolic domain. The per-harness domains of the skeleton harnesses are: concrete TLV framing with symbolic content, identifier or length octets (the `parse_validity_rejects_*` harnesses), each symbolic time field restricted to its literal specification range, and an outer tail of at most 3 octets; inputs are symbolic within that skeleton, not over every 47-byte string. `GeneralizedTime` fractions are covered for 0 to 3 digits with no trailing zero. A `GeneralizedTime` failure inside the validity parse is pinned only at `BadLength`; other `GeneralizedTime` content errors belong to the `generalized_time` module's own proofs and are not re-pinned through the validity mapping (`map_err`). The payload of `BadOuterSeq` for the outer envelope (the inner `SequenceError::Tlv(_)` detail) is not pinned by the exact-result harnesses. The RFC 5280 year-2050 encoding rule is **not enforced**. The `Ok` cover of `parse_never_panics` is **known-unsatisfiable at `[u8; 16]`** and disclosed (§8.2); its companion `parse_validity_ok_path_witnessed` witnesses the same path |
| `x509_extension` | bounded-backing evidence (**CONTRACT SURFACE / bounded-backing evidence, not an unrestricted proof**); extension *contents* are never interpreted (`extnValue` is uninterpreted) and `critical` is peeked, not acted on. `parse_extension` is covered **≤ 16 bytes, fully symbolic**. `validate_extensions` is covered for **at most two members, each with a 1-octet OID and an empty value**, and `validate_extensions_never_panics` runs at a reduced `[u8; 13]`; its `Ok` cover is **known-unsatisfiable at 13 bytes** and disclosed (§8.2), and its companion `validate_extensions_ok_path_witnessed` witnesses the same path. The two `validate_extensions_*` harnesses named here are **heavy**: they are kept out of the 20 GiB-capped main floor because earlier measurements approached or exceeded 20 GiB, and run separately in a 24 GiB window, where their measured peaks were 20G (`validate_extensions_never_panics`) and 16.7G (`validate_extensions_ok_path_witnessed`) (§3.4) |
| `x509_tbs_certificate` | bounded, structural only, and **modular** (two stubs; three in the witness harness — §8.4). Its `never_panics` cover is **known-unsatisfiable at `[u8; 10]`** and disclosed (§8.2). No cross-field RFC 5280 rule is checked here — that is `profile`'s job |
| `x509_certificate` | panic-freedom is proven **≤ 12 bytes** (`parse_certificate_never_panics`, **modular** — `parse_tbs_certificate` stubbed, §8.4); a real certificate is **~170 bytes** (this module's own test fixture) — panic-freedom beyond 12 bytes is **not machine-checked at this composition**: it rests on an un-machine-checked compositional argument (`decode_tlv`'s proven no-over-read contract plus each delegated sub-parser's own separate panic-freedom proof), not a symbolic proof over the real-size domain. No signature check, no path building |
| `profile` | bounded, and over symbolic *field values* rather than symbolic DER bytes — it decodes nothing (§7). Each of the four RFC 5280 cross-field rules is proven as a biconditional, plus their precedence and totality. No Lean lid, so no ∀-length statement |

**Proof-harness comments corrected in this release (wrong in 0.2.0)**

Three groups of comments in `mod proofs` were wrong in 0.2.0 and are corrected in this release. The
bullets below retain the correction record and its effect on the claims:

- The `utc_time::proofs::full_year_pivot_is_correct` comment and the
  `profile::proofs::utc_time_can_never_denote_2050_or_later` comment, and the cover text in
  `full_year_pivot_is_correct` said that a hand-built `year2` of 100 or more maps above 2049. They
  now state that `year2` in `100..=149` maps to `2000..=2049`, and only `year2` in `150..=255` maps
  above 2049. The proved formula is unaffected.
- In `profile::proofs::validate_profile_is_exactly_the_documented_precedence`, the comment used to
  say there were "no per-octet reads of these spans". That holds only for the unread spans and for
  fraction emptiness: the algorithm-identifier bytes are compared octet by octet, so the `0..=4`
  window bounds the proof for them. The comment now says so.
- In `x509_extension`, the shared comment used to label all four structured harnesses CONTRACT SURFACE.
  `validate_extensions_structured_empty` checks one fixed input (`[0x30, 0x00]`), so it is a PROBE
  fixed example, not contract evidence; the corrected comment distinguishes it from the other three.
  The module grade does not change.

### 6.3 Named residual — what the TLV framing accepts that a DER *validator* rejects

**Disposition (updated 2026-08-25): the rules are now DECIDED, in a new module, and the framing
layer is deliberately unchanged.** Classes (a) and (b) below are enforced by
[`identifier_form`](der-verified/src/identifier_form.rs) — `validate_identifier_form` on a decoded
`Tag`, and `decode_tlv_form_checked` / `decode_tlv_form_checked_strict` as the compositions with `tlv`. The module
carries its own harness set (counted per-module in §4); four of those theorems are stated over the
**complete** input domain (a symbolic `u32` tag number and all four classes), not a bounded buffer.

**What that does and does not change, stated exactly:**

- **Decided:** the rules now live in a verified layer of this crate, which is what §6.3 previously
  said they did not.
- **Not changed:** `tag::decode_tag`, `tlv::decode_tlv`, `tlv::decode_tlv_strict` and `sequence`'s
  child walk behave **exactly as before** — they still accept every input in the table below. That
  is deliberate: `decode_tlv` must keep reading any well-formed TLV to drive recursive parsing, and
  a caller must be able to inspect an identifier before deciding what it means. So the residual
  described in the rest of this section is still live *for callers of those entry points*; what has
  changed is that there is now a verified entry point that closes it, instead of only the
  hand-written per-call-site checks.
- **Still open:** whether the check should be wired into `decode_tlv_strict` itself. That is a
  behavioural change to a Lean-lidded shipped function and is a separate decision, deliberately not
  bundled here (the same reasoning D33 applied to the `set_of` refactor).
- **Scope of the new module, and it is narrower than the name suggests:** it decides ONE
  identifier, not a tree — the children of an accepted constructed TLV are unchecked, so a recursive
  DER validator must apply the rule at each level. It decides *form* only, never whether the tag is
  the one a schema expects. And it is **not a DER validator**: it never reads content octets, so
  `decode_tlv_form_checked` accepts `01 01 01` (BOOLEAN `true` must be `0xFF`), `02 02 00 01`
  (non-minimal INTEGER) and `05 01 00` (NULL must be empty). Content canonicality remains the
  per-type codecs' job. Those three specimens are pinned by a harness and a test, so the fence is
  executable rather than only written down.

Differential fuzzing against an independent DER implementation (2026-08) compared this crate's TLV
framing with that library's tag layer over a multi-hour campaign. It found **no defect in what this
crate claims** — no panic, no over-read, no round-trip or canonical-stability failure — and it found
three classes of input where the two implementations disagree because they are answering **different
questions**. Two of those classes are a real residual of this crate's scope and are named here.

**The claim `decode_tlv` makes, stated so the residual is legible.** `tlv::decode_tlv` decides
*structural framing*: the identifier octets are well-formed (`tag::decode_tag`, including the
minimal-high-tag rule), the length is a canonical definite length (`length::decode_length`), and the
declared value is present inside the input (§3.2's ∀-length theorem). It decides **nothing about
whether the tag it just parsed is a legal identifier for a DER value.** It is a framing reader, not
a validator, and "`decode_tlv` returned `Ok`" means "these bytes are a well-formed TLV", **not**
"these bytes are valid DER".

| Class | What our framing does | What a DER validator does | Repro (hex) |
|---|---|---|---|
| **(a) Constructed form of a primitive-only universal type.** X.690 requires the primitive form for these types; bit 6 of the identifier is nevertheless set. | accepts — `decode_tag` reports `constructed: true`, and the framing layer does not judge the combination | rejects at the tag layer | `21 00` (BOOLEAN), `26 01 39` (OBJECT IDENTIFIER), `27 02 04 04` (ObjectDescriptor), `29 00` (REAL), `2A 01 4A` (ENUMERATED), `2C 01 01` (UTF8String), `33 01 00` (PrintableString), `3E 00` (BMPString) |
| **(b) The reserved EOC identifier `0x00`.** Universal 0 is BER's end-of-contents marker for indefinite-length encodings; it is never a legal DER identifier. | accepts — it is a syntactically valid identifier octet with a valid length | rejects | `00 00` |
| **(c) Universal tags the comparison library does not model** (primitive ObjectDescriptor, EXTERNAL). | accepts — correctly: these are legal DER | rejects, for lack of a model | `07 01 4A`, `28 02 01 30` |

**(c) is not a residual of this crate** — it is a capacity limit of the comparison, the same family
as the documented `TagNumber > 255` guard, and it is listed only so the three-way split is not
silently collapsed into "we accept things others reject".

**(a) and (b): where the rules sit, and where they still do not.** Since 2026-08-25 the
primitive/constructed form rules and the EOC exclusion **are** enforced in a verified layer —
`identifier_form` — but they remain enforced in none of the layers listed below, which is what a
caller of those layers experiences:

- `tag::decode_tag` parses the identifier — class, constructed bit, number — and validates the
  *encoding* of the number (minimal high-tag form). It attaches no meaning to the combination.
- `tlv::decode_tlv` and `sequence`'s child walk pass the parsed `Tag` through untouched. Their
  proofs — bounded and ∀-length alike — are about consumption and windowing, not about tag legality.
- Where a **typed** parser exists it does check: `octet_string::decode_octet_string` rejects the
  constructed form explicitly (§9), and the `pkcs8` / `x509_*` parsers check tag identity and, where
  DER requires it, the constructed flag, at every field. Those checks are per-call-site, not a
  property of the framing layer.
- The content-level codecs (`decode_bool`, `decode_integer`, `validate_oid`, the string validators …)
  take **content**, never an identifier octet: the caller has already decided which codec to invoke,
  so a mismatched form cannot be caught there even in principle.

**What a consumer must therefore not do:** treat `decode_tlv`/`decode_sequence` acceptance as a
DER-validity decision for a value of a *known type*. A generic walk over untrusted bytes that
accepts whatever tags it finds will accept the (a) and (b) inputs above. Three supported ways to
reject them, strongest first: use `identifier_form::decode_tlv_form_checked` (or `decode_tlv_form_checked_strict`) in
place of `decode_tlv`; call `identifier_form::validate_identifier_form` on a `Tag` you already have;
or check the `Tag` yourself at each site — `tlv.tag.constructed`, `tlv.tag.number`, `tlv.tag.class`
are all public and exact — or use the typed parser for the type you expect.

**Cross-check kept honest in both directions.** Class (c) below is *legal* DER that the comparison
library rejected only for lack of a model, so it is the set most at risk from a rule that
over-rejects. `identifier_form` accepts both (c) specimens, and a harness
(`legal_der_the_comparison_library_rejected_is_still_accepted`) pins that, alongside one that pins
the real X.509 identifiers. The rule buys its rejections without refusing legal input.

**Evidence class, stated honestly:** this residual was found by *differential fuzzing against an
independent implementation*, which is `ASSUMPTIONS.md` A10's own named falsifier. It is a
disagreement of scope rather than a disagreement about a property either side claims: nothing in
`PROOF_MANIFEST.md` was falsified, and no harness or lid changed as a result. What changed is that
this document now names the gap instead of leaving it to be inferred from the absence of a claim.
`ASSUMPTIONS.md` A16 carries it as a trust-base entry with its failure mode.

## 7. `profile` — proven, at value level and without a Lean lid

`profile` is a first slice of a typed layer built strictly *on top of* the structural `x509_*`
parsers, checking cross-field RFC 5280 rules the parsers deliberately leave to the caller. It
performs no DER decoding of its own — only comparisons over already-materialised fields of a
`Certificate` that is structurally valid when parser-produced (the fields are public, so a hand-built
value is not checked structurally; the proofs below range over such values as well). It currently enforces four rules, in this order,
returning the first violation:

1. **§4.1.1.2** — the outer `Certificate.signatureAlgorithm` must equal `tbsCertificate.signature`
   (two independently-valid `AlgorithmIdentifier`s that nothing in the ASN.1 grammar ties together).
2. **§4.1.2.1 / §4.1.2.9** — `extensions` is a v3-only field: a certificate carrying `extensions`
   while declaring a non-v3 `version` is rejected.
3. **§4.1.2.5** — `notBefore`/`notAfter` must each use the RFC-mandated encoding for their calendar
   year (UTCTime through 2049, GeneralizedTime from 2050). Only the GeneralizedTime-too-early
   direction needs a runtime check; the UTCTime-too-late direction is impossible by construction
   (`utc_time::full_year_rfc5280`'s codomain is exactly `1950..=2049`).
4. **§4.1.2.5.2** — a GeneralizedTime in `validity` must not carry fractional seconds: a
   `Time::Generalized` `notBefore` or `notAfter` with a non-empty fraction is rejected (through
   `generalized_time::require_no_fraction`). Enforced since 0.2.0; a `Time::Utc` has no fraction field.
   Checked after rule 3 for both fields, `notBefore` first. **Bound (disclosed):** the proofs
   enumerate a GeneralizedTime fraction of 0 to 4 octets (a 4-octet symbolic backing, arbitrary octet
   values) per field; fractions longer than 4 octets are covered by unit tests (lengths 3, 4, 5, 9 and
   more, both fields), not by a proof. The code reads emptiness, not length, so this is a window, not
   a claim for arbitrary fraction lengths.

**What is now proven, and in what form.** Eight Kani harnesses cover this module, and the shape of the
statements matters more than the count: each of the four rules is a **biconditional** — the rule
fires *exactly* when the RFC says it should — rather than a one-directional "bad input is rejected"
check that a too-eager implementation would also satisfy. Rule 2's harness ranges over all 256
`version` values, not just `0`/`1`/`2`. A fourth harness pins the **precedence** this section
documents, with all six error cases (four rules, two fields on rules 3 and 4) independently symbolic, so
the "first violation wins" ordering is a proved property rather than a comment. A whole-function exact-result
harness (`validate_profile_is_exactly_the_documented_precedence`) additionally fixes the full result over
every profile-relevant field, including each Time's fraction emptiness. A fifth proves totality over every profile-relevant field
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
validation, and every other RFC 5280 cross-field rule beyond the four above. Roadmap:
`DER-REMAINING-WORK.md`, `TODO.md`.

## 8. Bounds, oracles, stubs, assumptions

### 8.1 Harness bounds and unwind limits

A bounded proof that hides its bound is a false claim, so every bound is stated. Per-module symbolic
buffer widths and unwind ranges are in §4's table; the crate-wide distribution:

<!-- BEGIN GENERATED:bounds (gates/gen_proof_manifest.py) -->
| `#[kani::unwind(N)]` | harnesses |
|---:|---:|
| 1 | 6 |
| 3 | 18 |
| 4 | 6 |
| 5 | 20 |
| 6 | 11 |
| 7 | 1 |
| 8 | 13 |
| 10 | 11 |
| 12 | 27 |
| 14 | 13 |
| 16 | 85 |
| 17 | 2 |
| 18 | 6 |
| 20 | 52 |
| 21 | 2 |
| 22 | 1 |
| **total bounded** | **274** |

24 harnesses declare no `#[kani::unwind]`, so no unwind bound is imposed on them and CBMC must unroll to completion every loop they reach. For those harnesses the loop depth is therefore *not* a limit on the claim: a loop CBMC could not fully unroll would fail an unwinding assertion rather than pass quietly. Their input domains are still bounded by buffer width like every other harness. Listed so a reader can check each one: `big_integer::empty_is_empty`, `big_integer::redundant_positive_padding_is_non_minimal`, `big_integer::redundant_negative_padding_is_non_minimal`, `bit_string::empty_is_classified`, `bit_string::empty_nonzero_unused_is_classified`, `boolean::one_octet_is_canonical`, `boolean::roundtrip`, `boolean::wrong_length_is_bad_length`, `enumerated::encode_delegates_to_integer`, `identifier_form::oracle_is_well_formed`, `identifier_form::required_form_matches_oracle_on_all_u32`, `identifier_form::reserved_eoc_rejected_iff_universal_zero`, `identifier_form::constructed_form_rule_matches_oracle_on_all_tags`, `identifier_form::accepts_iff_no_encoded_rule_violated_and_never_rejects_non_universal`, `integer::empty_is_classified`, `integer::redundant_positive_padding_is_non_minimal`, `integer::redundant_negative_padding_is_non_minimal`, `null::only_empty_is_valid`, `oid::empty_is_classified`, `restricted_string::charset_exactly_matches_oracle_printable`, `restricted_string::charset_exactly_matches_oracle_ia5`, `restricted_string::charset_exactly_matches_oracle_numeric`, `restricted_string::charset_exactly_matches_oracle_visible`, `utc_time::full_year_pivot_is_correct`.
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
| harnesses | 298 |
| `kani::cover` witnesses | 504, in 33 of the 33 modules that have harnesses |
| harnesses whose ONLY checks are Kani's implicit panic/overflow/memory-safety ones (no `cover`, no `assert`) | **1** |
| harnesses narrowed by `assume` with no `cover` (their `assert` is the post-state witness instead) | 84 |
| harnesses whose `cover` is known-UNSATISFIABLE and disclosed | 3 |

Harnesses with implicit checks only — each needs a justification, or a cover:

- `rsa_private_key::parse_strict_never_panics`

What the remaining 84 `assume`-narrowed-without-a-`cover` harnesses give you is **functional assertions (post-state checks), not non-vacuity witnesses**. The static, derived fact is that each of them contains an `assert!`. But an assertion cannot witness that its own assumptions are satisfiable: if the assumptions of such a harness were contradictory, every assertion in it would pass vacuously. So the satisfiability of those assumptions is **not witnessed** by these harnesses, and that gap is kept here, not argued away. The judgement — that these particular assertions are functional outcomes (a biconditional, a round-trip, an exact `Err` variant) which constrain the result on reachable executions — is per-harness and human; this script cannot grade an assertion's strength. Nor is an assertion interchangeable with a cover: `assert!(r.is_err())` can be satisfied by a shallow rejection path while a deeper one is never reached, whereas a cover can pin a specific deep effect. Neither subsumes the other, and this manifest does not claim the assertions make covers unnecessary.

Exactly 1 harness is left with nothing but Kani's implicit checks: `rsa_private_key::parse_strict_never_panics` (also listed above). That is a disclosed exception, not a witnessed property. Where a harness's non-vacuity argument points somewhere other than at itself, the prose below names it.

**The counts in this audit are lexical.** `cover`, `assume` and `assert` counts come from a line scan of each module's `mod proofs`: comment-only lines are excluded, but a `kani::cover` or `kani::assume` token inside a string literal, behind an inline `//` tail or inside a `/* */` block can be counted as if it were code. The scan is checked by a self-test that finds no such token outside code positions in the current source (`gates/test_gen_proof_manifest.py`); that is a statement about today's source, not a guarantee about future edits, and a tokenizing count is a follow-up.

**What the 293 harness assumptions actually restrict.** 237 of them are size or range bounds — they relate lengths, indices and integer values with comparisons and `&&`, and nothing else — which narrows *how big* an input may be, not *what it may contain*. The remaining 56 restrict input CONTENT, which is the materially stronger kind of narrowing, so every one is named here rather than folded into a count:

Two things to hold in mind reading it. First, the classifier is deliberately conservative: anything it cannot show is a pure size/range bound is listed, so some entries below *are* range constraints in a shape it does not recognise (a negated range such as `!(mo >= 1 && mo <= 12)`, for instance). It errs toward disclosing. Second, content narrowing is usually the **point** of the harness rather than a weakness in it: a rejection-classification harness exists precisely to pin a malformed shape and assert the exact error it must produce, and it must narrow to that shape to do so. What the list gives you is the ability to check that judgement yourself, harness by harness, instead of taking a count on trust.

- `big_integer::redundant_positive_padding_is_non_minimal_at_length` — `assume(buf[0] == 0x00)`
- `big_integer::redundant_positive_padding_is_non_minimal_at_length` — `assume(buf[1] & 0x80 == 0)`
- `big_integer::redundant_negative_padding_is_non_minimal_at_length` — `assume(buf[0] == 0xFF)`
- `big_integer::redundant_negative_padding_is_non_minimal_at_length` — `assume(buf[1] & 0x80 != 0)`
- `big_integer::strips_redundant_padding` — `assume(buf[1] != 0x00)`
- `bit_string::nonzero_padding_is_classified` — `assume(last.trailing_zeros() < unused as u32)`
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
- `identifier_form::high_tag_universal_types_are_form_checked` — `assume((31..=36).contains(&n))`
- `length::indefinite_is_classified` — `assume(buf[0] == 0x80)`
- `length::reserved_is_classified` — `assume(buf[0] == 0xFF)`
- `length::leading_zero_is_non_minimal` — `assume(buf[0] >= 0x81 && buf[0] <= 0x87)`
- `length::leading_zero_is_non_minimal` — `assume(buf[1] == 0x00)`
- `oid::leading_0x80_is_non_minimal` — `assume(buf[0] == 0x80)`
- `oid::later_0x80_is_non_minimal` — `assume(buf[0] < 0x80)`
- `oid::later_0x80_is_non_minimal` — `assume(buf[1] == 0x80)`
- `oid::unterminated_is_truncated` — `assume(buf[0] != 0x80 && buf[0] & 0x80 != 0)`
- `oid::unterminated_is_truncated` — `assume(buf[1] & 0x80 != 0 && buf[2] & 0x80 != 0 && buf[3] & 0x80 != 0)`
- `profile::rule4_fraction_iff_generalized_with_fraction` — `assume(!nb_gen || nb_year >= 2050)`
- `profile::rule4_fraction_iff_generalized_with_fraction` — `assume(!na_gen || na_year >= 2050)`
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
- `rsa_private_key::parse_faithful_two_prime_s1` — `assume(buf[29] != 0x10 && buf[29] != 0x30)`
- `rsa_private_key::parse_multi_prime_faithful` — `assume(buf[4] <= 1)`
- `rsa_private_key::parse_rejects_field_length` — `assume(l as usize > 29 - (4 + 3 * s))`
- `rsa_private_key::parse_multi_prime_rejects_member_field_length` — `assume(l as usize > 9 - (3 * k + 2))`
- `utc_time::roundtrip_all_fields` — `assume(fields_in_range(&t))`
- `utc_time::non_digit_is_classified` — `assume(!bad.is_ascii_digit())`
- `utc_time::not_zulu_is_classified` — `assume(term != b'Z')`
- `utc_time::month_range_is_classified` — `assume(mo <= 99 && !(mo >= 1 && mo <= 12))`
- `utc_time::day_range_is_classified` — `assume(d <= 99 && !(d >= 1 && d <= 31))`
- `utf8_string::roundtrip` — `assume(oracle_wellformed_utf8(&content[..n]))`
- `utf8_string::ill_formed_reports_position` — `assume(!oracle_wellformed_utf8(&buf[..n]))`
- `x509_validity::any_gen` — `assume(g.k < 1 || (g.frac[0] >= b'0' && g.frac[0] <= b'9'))`
- `x509_validity::any_gen` — `assume(g.k < 2 || (g.frac[1] >= b'0' && g.frac[1] <= b'9'))`
- `x509_validity::any_gen` — `assume(g.k < 3 || (g.frac[2] >= b'0' && g.frac[2] <= b'9'))`
- `x509_validity::any_gen` — `assume(g.k == 0 || g.frac[g.k - 1] != b'0')`
<!-- END GENERATED:non-vacuity -->

The covers are **authored against** a bar: an outcome witness should demonstrate a *post-state
effect*. `cover(len == N)` or a bare `cover(true)` would be satisfiable even if the function body
were replaced by a no-op, so neither is evidence that the code produced an outcome. The bar is
"would this still be satisfiable if the body did nothing?" **Outcome witnesses are reviewed against
this bar; domain-reachability probes are classified separately below.** No gate mechanically
rejects a weak cover. For the stub-bearing composition harnesses, the bar means covering that the
real glue reached its `Ok` tail; for `x509_extension`, it means that a second walk iteration
genuinely co-occurs with acceptance.

A `cover(true)` that sits inside a branch is different. The branch condition decides whether it is
reached, so it can still witness that branch. The source has 24 covers of this kind, in `identifier_form`,
`octet_string`, `restricted_string`, `set_of` and `utf8_string`. They are not counted in the next paragraph.

**PROBE domain-reachability checks.** The bar is not met by every cover. Reading the harness source
(`der-verified/src/*.rs`, `mod proofs`) finds **51 of the 499 covers** whose predicate reads only
symbolic harness inputs, or a value the harness computes from them by arithmetic or by an oracle
expression. Such a cover never reads a result of the function under proof. It shows that a class of
inputs is reachable in the harness domain. **A satisfied cover witnesses reachability at its
location; it supports assertion non-vacuity where that assertion is reached on the same execution.**
It is **not** an outcome witness and is not evidence that the code produces any result, so this
document labels these 51 as **PROBE domain-reachability checks**. They are, by harness, with the
number of source cover sites in brackets:

- `bit_string`: `accepted_iff_canonical_oracle` (2), `encode_rejects_exactly_the_non_canonical` (5),
  `nonzero_padding_is_classified` (1), `require_octet_aligned_exact_on_built_values` (3, the three
  classes of unused-bit count);
- `boolean`: `wrong_length_is_bad_length` (3, the lengths 0, 2 and 16);
- `null`: `only_empty_is_valid` (3, the lengths 1, 4 and 16);
- `identifier_form`: `high_tag_universal_types_are_form_checked` (2, the tag numbers 31 and 36);
- `profile`: `rule3_generalized_too_early_iff_year_le_2049` (1),
  `rule4_fraction_iff_generalized_with_fraction` (1), `error_precedence_follows_declaration_order` (5);
- `restricted_string`: `check_encode_exact` (4; one shared body, used by four charsets);
- `rsa_private_key`: `parse_rejects_field_length` (2), `parse_multi_prime_rejects_member_length` (2),
  `parse_multi_prime_rejects_member_field_length` (2), `parse_multi_prime_rejects_member_shape` (1);
- `set_of`: `ordering_matches_whole_encoding_oracle` (1), `tlv_entry_enforces_ordering_exactly` (1),
  `encode_is_exact_over_content_and_capacity` (4);
- `utc_time`: `full_year_pivot_is_correct` (2);
- `utf8_string`: `encode_is_exact_over_content_and_capacity` (4);
- `x509_extension`: `validate_extensions_rejects_child_framing` (2).

Six additional reference-derived sites read a value that the harness's own reference computes from the
input (`decode_tlv`, `oracle_set_of`), and not a result of the function under proof:
`set_of::tlv_entry_enforces_ordering_exactly` (2), `restricted_string::check_decode_faithful` (2)
and `utf8_string::decode_is_faithful` (2). Thus the initial inventory was **51 identified sites,
plus six additional reference-derived sites**. Shared helper sites are counted once where they are
written, not multiplied by the charset-specific harnesses that call them.

Two further sites in `x509_validity::parse_validity_rejects_field_identifier` are also
reference-derived probes: `field_err` is a reference result computed only from the symbolic identifier
and the selected field, and the two covers distinguish the `notBefore` and `notAfter` rejection
sides without reading `parse_validity`'s result. Including them brings the disclosed inventory to 59
sites: 51 direct-input sites and eight reference-derived sites. Read all 59 as domain-reachability
checks. The list was compiled by reading the source. No gate checks it, and it can be incomplete.

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

In each of these three cases the cause is arithmetic, not a cover-authoring error: the reduced buffer is too small
for a well-formed object to exist inside it. A minimal `Validity` needs about 32 octets — two
`Time`s of 15 each plus a 2-octet `SEQUENCE` wrapper — against a 16-octet buffer; two minimal
`Extension`s inside an `Extensions` wrapper need 16 octets, not 13; a minimal TBS body needs far more
than 10. (Those byte counts are hand-derived, not machine-checked — see the note on prose numbers
above.) What each `never_panics` harness proves
is therefore **panic-freedom over its domain including all the rejecting paths**, while the claim
that the deep glue is *exercised* rests on the witness sibling, not on the symbolic harness. Both
halves are stated because either alone would mislead.

<!-- BEGIN DISCLOSED:unreachable-checks -->
These are property checks that Kani reports as UNREACHABLE in a harness whose evidence records per-check status: the three heavy harnesses run alone at 24 GiB (`evidence/check-d68eeca-heavy-*.log`). Kani also reports unreachable checks for most other harnesses, as the `(N unreachable)` count on each `** 0 of M failed` line in `evidence/check-d68eeca.log`. That log keeps only the summary lines, so those checks are counted there but not named. An unreachable check is not a failure. It means that harness's inputs never reach that code. The code's safety rests on the harnesses named in the last column; those safety references are themselves bounded harnesses (or the named lid), each with its own declared domain (§4, §8.1), so the reference carries the code over that domain and not beyond it.

| Harness | Check | Kani status | Location | Why the harness does not reach it | Safety of that code is carried by |
|---|---|---|---|---|---|
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `boolean::decode_bool.assertion.1` | `UNREACHABLE` | `boolean.rs:45` | The witness has no `critical` BOOLEAN member (each member is an OID then an OCTET STRING), so `parse_extension` never makes the `decode_bool` call at `x509_extension.rs:236` and the "index out of bounds" check on `content[0]` is never reached. | `boolean::proofs::*` |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `tag::decode_tag.assertion.2` | `UNREACHABLE` | `tag.rs:145` | Every identifier octet of the concrete witness (`30`, `06`, `04`) has low five bits other than `1F`, so `decode_tag` returns in its low-tag form at `tag.rs:118` and the "shift right with overflow" check on `u32::MAX >> 7` in the high-tag accumulation loop is never reached. | `tag` (harnesses + lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `tag::decode_tag.assertion.3` | `UNREACHABLE` | `tag.rs:148` | Every identifier octet of the concrete witness (`30`, `06`, `04`) has low five bits other than `1F`, so `decode_tag` returns in its low-tag form at `tag.rs:118` and the "shift left with overflow" check on `number << 7` in the high-tag accumulation loop is never reached. | `tag` (harnesses + lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `tag::decode_tag.assertion.4` | `UNREACHABLE` | `tag.rs:149` | Every identifier octet of the concrete witness (`30`, `06`, `04`) has low five bits other than `1F`, so `decode_tag` returns in its low-tag form at `tag.rs:118` and the "add with overflow" check on `count += 1` in the high-tag accumulation loop is never reached. | `tag` (harnesses + lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `tag::decode_tag.assertion.5` | `UNREACHABLE` | `tag.rs:150` | Every identifier octet of the concrete witness (`30`, `06`, `04`) has low five bits other than `1F`, so `decode_tag` returns in its low-tag form at `tag.rs:118` and the "add with overflow" check on `i += 1` in the high-tag accumulation loop is never reached. | `tag` (harnesses + lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `length::decode_length.assertion.1` | `UNREACHABLE` | `length.rs:89` | Every length octet of the concrete witness (`0e`, `05`, `01`, `00`) is below `80`, so `decode_length` returns in its short form at `length.rs:79` and the "add with overflow" check on `1 + n` in the long-form length-octet count (`input.len() < 1 + n`) is never reached. | `length` (Kani harnesses + ∀-length Lean lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `length::decode_length.assertion.2` | `UNREACHABLE` | `length.rs:92` | Every length octet of the concrete witness (`0e`, `05`, `01`, `00`) is below `80`, so `decode_length` returns in its short form at `length.rs:79` and the "add with overflow" check on the `1 + n` slice bound of `&input[1..1 + n]` is never reached. | `length` (Kani harnesses + ∀-length Lean lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `length::decode_length.assertion.3` | `UNREACHABLE` | `length.rs:93` | Every length octet of the concrete witness (`0e`, `05`, `01`, `00`) is below `80`, so `decode_length` returns in its short form at `length.rs:79` and the "index out of bounds" check on `octets[0]` is never reached. | `length` (Kani harnesses + ∀-length Lean lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `length::decode_length.assertion.4` | `UNREACHABLE` | `length.rs:102` | Every length octet of the concrete witness (`0e`, `05`, `01`, `00`) is below `80`, so `decode_length` returns in its short form at `length.rs:79` and the "shift left with overflow" check on `val << 8` in the long-form accumulation loop is never reached. | `length` (Kani harnesses + ∀-length Lean lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `length::decode_length.assertion.5` | `UNREACHABLE` | `length.rs:102` | Every length octet of the concrete witness (`0e`, `05`, `01`, `00`) is below `80`, so `decode_length` returns in its short form at `length.rs:79` and the "index out of bounds" check on `octets[i]` in the long-form accumulation loop is never reached. | `length` (Kani harnesses + ∀-length Lean lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `length::decode_length.assertion.6` | `UNREACHABLE` | `length.rs:103` | Every length octet of the concrete witness (`0e`, `05`, `01`, `00`) is below `80`, so `decode_length` returns in its short form at `length.rs:79` and the "add with overflow" check on `i += 1` in the long-form accumulation loop is never reached. | `length` (Kani harnesses + ∀-length Lean lid) |
| `x509_extension::proofs::validate_extensions_ok_path_witnessed` | `length::decode_length.assertion.7` | `UNREACHABLE` | `length.rs:108` | Every length octet of the concrete witness (`0e`, `05`, `01`, `00`) is below `80`, so `decode_length` returns in its short form at `length.rs:79` and the "add with overflow" check on the `1 + n` consumed-byte count of the long-form result is never reached. | `length` (Kani harnesses + ∀-length Lean lid) |
| `x509_name::proofs::validate_rdn_never_panics` | `set_of::cmp_padded.assertion.6` | `UNREACHABLE` | `set_of.rs:124` | The padded tail loop is entered only when one argument is a strict prefix of the other, but `decode_set_of` passes `cmp_padded` two whole `decode_tlv` spans (`set_of.rs:154` to `161`), and a complete TLV span is never a strict prefix of a different one because its own length field fixes where it ends, so the "index out of bounds" check on `longer[j]` is never reached. | `set_of::proofs::cmp_padded_matches_oracle` |
| `x509_name::proofs::validate_rdn_never_panics` | `set_of::cmp_padded.assertion.7` | `UNREACHABLE` | `set_of.rs:128` | The padded tail loop is entered only when one argument is a strict prefix of the other, which two whole `decode_tlv` spans of one SET OF (`set_of.rs:154` to `161`) cannot be, so the "add with overflow" check on `j += 1` is never reached. | `set_of::proofs::cmp_padded_matches_oracle` |
<!-- END DISCLOSED:unreachable-checks -->

**A correction worth stating plainly, because the earlier framing of it was wrong.**
`x509_name::validate_rdn_never_panics` has no cover of its own, and its cheap sibling
`validate_never_panics` does *not* supply one for it: that sibling **stubs** `validate_rdn`, so its
`1 of 1` satisfied cover would still be satisfied if the real `validate_rdn` rejected every input.
It witnesses the RDN-walk glue, not the RDN parser.

So, precisely, for `validate_rdn`: **panic-freedom over its 0..=16-octet domain is proved
unconditionally and is not vacuous** — that is the harness's primary property. Its *postcondition*
(`2 ≤ used ≤ input.len()` on `Ok`) is asserted inside `if let Ok(used) = …`, so it is discharged
conditionally, and **that harness (`validate_rdn_never_panics`) has no cover, and nothing in the
stub-mediated harnesses witnesses the real `validate_rdn` returning `Ok`**. That is not
unsound — `stub_validate_rdn` returns both `Ok` and `Err`
nondeterministically, over-approximating the real function, and exploring more control-flow outcomes
cannot hide a panic.

The name parser's accept path is witnessed by other harnesses, which use no stub.
`x509_name::validate_name_single_atv_exact` (backing `[u8; 11]`) and
`x509_name::validate_name_two_atvs_exact` (backing `[u8; 19]`) call the real `validate_name`, and
through it the real `validate_rdn`. Each has a `kani::cover` of the `Ok` result, and both covers are
satisfied (`3 of 3` cover properties each in `evidence/check-d68eeca.log`). This is bounded-backing
evidence for those two structured shapes, not a proof over every input.

The limitation that remains is for the TBS and certificate compositions. Their witnesses run under
stubs, so they witness the glue only, and the accept path of those compositions is evidenced by
`#[test]` cases, not by proof. Together with the stub-mediated witness row above, that is the one
place in this document where "witness" needs reading carefully, and it is why the table names which
witnesses are stub-mediated.

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
| `bit_string` | `reference_bit_string` | `accepted_iff_canonical_oracle`, `octet_aligned_iff_unused_zero` |
| `generalized_time` | `is_canonical_der_generalizedtime`, `reference_generalized_time` | `accepted_iff_canonical_oracle`, `encode_is_total_exact_oracle`, `require_no_fraction_iff_no_fraction_octets` |
| `identifier_form` | `accepted_exactly_as_framed`, `any_class`, `any_tag`, `oracle_is_constructed_only`, `oracle_is_primitive_only` | `accepts_iff_no_encoded_rule_violated_and_never_rejects_non_universal`, `constructed_form_rule_matches_oracle_on_all_tags`, `oracle_is_well_formed`, `required_form_matches_oracle_on_all_u32`, `reserved_eoc_rejected_iff_universal_zero` |
| `profile` | `raw_bytes_differ`, `window` | `rule1_mismatch_iff_algorithms_differ`, `rule2_requires_v3_iff_extensions_present_and_not_v3`, `rule3_generalized_too_early_iff_year_le_2049`, `rule4_fraction_iff_generalized_with_fraction` |
| `restricted_string` | `check_decode_faithful`, `check_decode_wrapper`, `check_encode_exact`, `check_encode_wrapper`, `oracle_ia5`, `oracle_numeric`, `oracle_of`, `oracle_printable`, `oracle_tag_number`, `oracle_visible` | `charset_exactly_matches_oracle_ia5`, `charset_exactly_matches_oracle_numeric`, `charset_exactly_matches_oracle_printable`, `charset_exactly_matches_oracle_visible`, `validate_iff_all_in_charset_ia5`, `validate_iff_all_in_charset_numeric`, `validate_iff_all_in_charset_printable`, `validate_iff_all_in_charset_visible` |
| `rsa_private_key` | `check_multi`, `expected_skeleton`, `field_at`, `key_at`, `key_is_borrowed_at`, `same_slice`, `sentinel_validate_other_prime_infos`, `slot_error`, `stub_validate_other_prime_info`, `stub_validate_other_prime_infos`, `tail_case` | — |
| `set_of` | `cmp_padded_oracle`, `oracle_encoding_cmp`, `oracle_set_of`, `previous_decode_set_of` | `cmp_padded_matches_oracle`, `ordering_iff_oracle`, `ordering_matches_whole_encoding_oracle` |
| `tag` | `any_class` | — |
| `tlv` | `any_class` | — |
| `utc_time` | `is_canonical_der_utctime`, `reference_utc_time` | `accepted_iff_canonical_oracle`, `encode_is_total_exact_oracle` |
| `utf8_string` | `oracle_wellformed_utf8` | `validate_iff_oracle`, `validate_iff_oracle_multi`, `validate_iff_std` |
| `x509_certificate` | `stub_parse_tbs_certificate` | — |
| `x509_extension` | `expected_member`, `expected_parse_extension` | — |
| `x509_name` | `expected_single`, `single_atv_case`, `stub_validate_rdn` | — |
| `x509_tbs_certificate` | `stub_parse_validity`, `stub_validate_extensions`, `stub_validate_name` | — |
| `x509_validity` | `any_gen`, `any_utc`, `arms_case`, `build_uu`, `check_frac`, `gen_of`, `put_gen`, `put_tlv`, `put_utc` | — |

59 hand-written helper functions in total. Derived by exclusion — every `fn` in a `mod proofs` block that is not itself a harness — so a helper cannot escape this list by being named something unexpected.
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
- **`tlv`'s no-over-read oracle is INLINE, so the generated table above cannot see it — and it is
  the crate's clearest anti-cast-mirroring case.** `decode_tlv_structure` re-derives the header from
  the same bytes and states the consumption and value-length facts against the *declared* length
  widened losslessly to `u64` (`used as u64 == header as u64 + len_u32 as u64`), never re-using the
  implementation's own `as usize` cast. Asserting `== len as usize` would be tautological: a
  truncating `len_u32 as usize` inside `decode_tlv` — a known seeded-defect class — would be mirrored
  by the identical cast in the assertion and stay invisible. `sequence`'s `ok_implies_exact_tiling`
  is the same discipline one level up: an independent *index* walk with no pointer arithmetic, so
  the property cannot be vacuously true under address wraparound. The
  derivation that builds the table finds oracles by looking for hand-written helper `fn`s inside
  `mod proofs`; an oracle written inline in a harness body is invisible to it. That is a limit of the
  table, not of the proof, and it is why this bullet exists.
- **`sequence`/`set_of` `no_over_read`: what DRIVES a proof is a separate question from what
  ORACLES it, and this crate got that wrong until 2026-08-24.** Both harnesses used to run their own
  `decode_tlv` loop from raw offsets, `sequence`'s describing itself as "exactly what
  `Elements::next` does". That equivalence was asserted in a comment and never proven, so what was
  verified was a faithful-looking *copy* of the shipped walk — an external review named it, and it
  was correct. A regression in the real walk could have left both harnesses green while the crate's
  central "no over-read" claim pointed at them. Both now execute shipped code. The oracles stay
  separate, and the two are **not** equally strong — the difference is in the shipped code, not in
  the effort spent:
  - `sequence::no_over_read` drives `Elements` and, per child, pins the shipped cursor's advance
    against a one-step `decode_tlv` oracle taken from an offset the harness carries itself. Pinning
    the *advance* is the load-bearing part: an earlier draft of the fix derived the offset from the
    iterator's own cursor, which a mis-advance can survive whenever a child has an empty value
    (`value == content[off..off]` holds at every offset). That draft was caught in review, not in a
    gate.
  - `set_of::no_over_read` drives a harness-owned `Elements` instance and observes it through the
    same read-only `remaining()` accessor production uses to delimit raw child spans. Per child, a
    fresh `decode_tlv` from the harness's own offset supplies the expected child and advance; the
    yielded `Tlv` must match and the cursor must land on `off + expected_used`. This states the
    cursor fact directly, including for empty-valued children where value equality is ambiguous.
    The cursor check uses symbolic lengths `0..=6`, enough for three minimum-size children. Lean's
    `elements_next_progress` proves one accepted iterator step at any remaining-slice length; it
    does not prove SET OF whole-loop exhaustion. SET OF's whole-loop ordering/error/count glue
    remains bounded. A separate exact-result harness compares the returned `Result` of the production
    decoder with a proof-local copy of the previous shipped offset walk over fully symbolic content of `0..=8` octets; it does not
    observe production's intermediate cursors or calls, so that production drives the iterator and accessor the way the
    harness-owned instance does is a source-inspection statement, not a machine-checked one. (The `set_of.rs` module
    documentation still says only "bounded" for these proofs; that rustdoc bound wording is deferred to the next source change.) Claim-named
    controls observed red for both new pieces: a one-octet-short production cursor-delta span is
    caught by `unsorted_children_are_rejected`, and a one-octet-short `Elements::next` advance is
    caught by `set_of::no_over_read` at the exact-offset assertion.
- **What does not mitigate it:** nothing gates oracle fidelity, no oracle is derived from the
  standard text mechanically, and the standard itself is not machine-readable. Each oracle's
  justification is prose in its docstring, checked by review against X.690/RFC 5280. Nor does
  anything gate the driver/oracle distinction above: no check would have caught either the original
  duplicated walk or the self-referential first fix. Both were found by reading the source.

If you are relying on one of these biconditionals, read the oracle, not just the theorem name.

### 8.4 Modular proofs via stubs

Seventeen harnesses are **modular proofs** in the sense that they replace a sub-parser with a
`#[kani::stub]`. Two kinds: eight replace an already-independently-proven sub-parser with a stub capturing
its proven contract, so CBMC can verify the composition glue tractably; nine (`rsa_private_key`'s
2026-10-02 faithful and exact-rejection harnesses) use a **sentinel** stub for `validate_other_prime_infos`
whose body fails the proof if it is ever reached — it cuts cost on shapes that must not reach the member
walk and supplies no value any oracle relies on (`parse_multi_prime_faithful` runs the real walk, unstubbed).

<!-- BEGIN GENERATED:stubs (gates/gen_proof_manifest.py) -->
| Harness | `#[kani::stub]`-replaced function(s) |
|---|---|
| `rsa_private_key::parse_never_panics` | `validate_other_prime_infos` |
| `rsa_private_key::parse_strict_never_panics` | `validate_other_prime_infos` |
| `rsa_private_key::parse_ok_2prime_witnessed` | `validate_other_prime_infos` |
| `rsa_private_key::validate_other_prime_infos_never_panics` | `validate_other_prime_info` |
| `rsa_private_key::parse_faithful_two_prime_s1` | `validate_other_prime_infos` |
| `rsa_private_key::parse_faithful_two_prime_s2` | `validate_other_prime_infos` |
| `rsa_private_key::parse_rejects_missing_fields` | `validate_other_prime_infos` |
| `rsa_private_key::parse_rejects_two_octet_version` | `validate_other_prime_infos` |
| `rsa_private_key::parse_other_prime_infos_tail_empty` | `validate_other_prime_infos` |
| `rsa_private_key::parse_other_prime_infos_tail_primitive` | `validate_other_prime_infos` |
| `rsa_private_key::parse_other_prime_infos_tail_truncated` | `validate_other_prime_infos` |
| `rsa_private_key::parse_other_prime_infos_tail_trailing` | `validate_other_prime_infos` |
| `rsa_private_key::parse_other_prime_infos_tail_set` | `validate_other_prime_infos` |
| `rsa_private_key::parse_rejects_outer_identifier` | `validate_other_prime_infos` |
| `rsa_private_key::parse_rejects_field_identifier` | `validate_other_prime_infos` |
| `rsa_private_key::parse_rejects_field_length` | `validate_other_prime_infos` |
| `x509_certificate::parse_certificate_never_panics` | `crate::x509_tbs_certificate::parse_tbs_certificate` |
| `x509_name::validate_never_panics` | `validate_rdn` |
| `x509_tbs_certificate::parse_tbs_certificate_never_panics` | `validate_name`, `validate_extensions` |
| `x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed` | `validate_name`, `validate_extensions`, `parse_validity` |

Every `kani::assume` inside a **stub body** — each constrains what the stub is allowed to *return*, so each must be discharged by a separate harness or it is an unsound hole:

- `x509_name::stub_validate_rdn` — `assume(2 <= used && used <= input.len())`

For contrast, the other `kani::assume`s outside harness bodies live in input generators: they narrow the symbolic input of every harness that calls them, so they are counted with the harness-domain assumptions (and listed there when they restrict content), but they constrain no stub, so there is nothing to discharge:

- `identifier_form::any_class` — `assume(sel < 4)`
- `profile::window` — `assume(n <= 2)`
- `profile::any_time` — `assume(flen <= 4)`
- `restricted_string::check_decode_faithful` — `assume(len <= 6)`
- `restricted_string::check_decode_wrapper` — `assume(len <= buf.len())`
- `restricted_string::check_encode_wrapper` — `assume(n <= 4)`
- `restricted_string::check_encode_wrapper` — `assume(cap <= 8)`
- `restricted_string::check_encode_exact` — `assume(n <= 4)`
- `restricted_string::check_encode_exact` — `assume(cap <= 8)`
- `tag::any_class` — `assume(sel < 4)`
- `tlv::any_class` — `assume(sel < 4)`
- `x509_validity::any_utc` — `assume(t.year2 <= 99)`
- `x509_validity::any_utc` — `assume(t.month >= 1 && t.month <= 12)`
- `x509_validity::any_utc` — `assume(t.day >= 1 && t.day <= 31)`
- `x509_validity::any_utc` — `assume(t.hour <= 23)`
- `x509_validity::any_utc` — `assume(t.minute <= 59)`
- `x509_validity::any_utc` — `assume(t.second <= 59)`
- `x509_validity::any_gen` — `assume(g.year <= 9999)`
- `x509_validity::any_gen` — `assume(g.month >= 1 && g.month <= 12)`
- `x509_validity::any_gen` — `assume(g.day >= 1 && g.day <= 31)`
- `x509_validity::any_gen` — `assume(g.hour <= 23)`
- `x509_validity::any_gen` — `assume(g.minute <= 59)`
- `x509_validity::any_gen` — `assume(g.second <= 59)`
- `x509_validity::any_gen` — `assume(g.k <= 3)`
- `x509_validity::any_gen` — `assume(g.k < 1 || (g.frac[0] >= b'0' && g.frac[0] <= b'9'))`
- `x509_validity::any_gen` — `assume(g.k < 2 || (g.frac[1] >= b'0' && g.frac[1] <= b'9'))`
- `x509_validity::any_gen` — `assume(g.k < 3 || (g.frac[2] >= b'0' && g.frac[2] <= b'9'))`
- `x509_validity::any_gen` — `assume(g.k == 0 || g.frac[g.k - 1] != b'0')`
- `x509_validity::arms_case` — `assume(extra_len <= 3)`
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
- **`ecdsa_sig_value` frames `SEQUENCE { r INTEGER, s INTEGER }` only.** No curve-order range check
  (`1 <= r,s <= n-1` needs a curve identifier this container does not carry on its own), no low-S
  policy (a protocol-profile choice, e.g. Bitcoin BIP-62/BIP-66, not a general DER/RFC 3279 validity
  rule), no cryptographic interpretation.
  `r`/`s` are exposed as opaque validated bytes, never materialized as numbers (mirrors
  `big_integer`'s and `x509_tbs_certificate::serial_number`'s stance).
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

**Not on this list, deliberately: the framing layer's named residual (§6.3).** The two rules there —
primitive form for primitive-only universal types, and the EOC exclusion — are not *narrowings* of
DER that this crate chose; they were DER rules that no layer here decided either way, at a layer that
never claimed to. They were recorded as a residual with their repro bytes rather than as a deviation,
because calling them a design decision would have implied a decision was made.

**Since 2026-08-25 a decision HAS been made, and it is a scope choice rather than a deviation.**
`identifier_form` decides both rules; `tag`/`tlv`/`sequence` deliberately keep their permissive
framing-only behaviour, so the rules are enforced where a caller opts in and nowhere else. That is
now a design decision, and it is on the record here: the permissive framing reader is load-bearing
for recursive parsing, and tightening it would be a behavioural change to Lean-lidded shipped
functions. Still not a *narrowing* of DER — no legal encoding is rejected anywhere.

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
