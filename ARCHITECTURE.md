# Architecture — `der-verified`

> **arc42-lite.** This document follows a trimmed [arc42](https://arc42.org) skeleton adapted for a
> formally-verified Rust library. The **section headings are repo-agnostic** (they are the same across
> the verified-Rust repos so a generator can scaffold them and a drift gate can keep them present); the
> **content is specific to this crate**. It complements, and does not duplicate, three existing
> authorities — [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) (what is proven, over what domain),
> [`DECISIONS.md`](DECISIONS.md) (why, decision by decision), and [`README.md`](README.md) (how to use)
> — by giving the one view none of those do: how the pieces fit together. Where this file and any of
> those disagree, **they win** and this file is the stale one. It names stable structure (codecs,
> tiers, decisions) and points to the gated authority (`PROOF_MANIFEST.md`) for any live count — it
> avoids duplicating volatile numbers, so it does not itself need adding to the docs-sync guard.

## 1. Introduction & goals

`der-verified` is a zero-dependency, `#![forbid(unsafe_code)]` decoder for **DER** (Distinguished
Encoding Rules, the canonical subset of ASN.1 X.690) with a machine-checked proof envelope. It exists
to be a *trust base*: a parser whose panic-freedom and DER-canonicality are proven, not merely tested,
so that higher layers (X.509, PKCS, signature containers) can compose it without re-litigating the
transfer syntax.

Top quality goals, in priority order:

1. **Soundness** — no accepted input violates the property a codec claims (canonical DER only; a
   malleable re-encoding of the same value is rejected, not merely one canonical form accepted) —
   *up to the verified length bound at L3, and universally for the codecs with an L4 lid* (§8).
2. **Panic-freedom** — no input within the verified bound, well-formed or hostile, causes a panic or
   UB. Machine-checked (L3, bounded; see §11 for the bounded-vs-unbounded residual).
3. **Honesty** — the guarantee's *boundary* is documented and gated as carefully as the guarantee
   (`PROOF_MANIFEST.md`'s standing rule: *counts are inventory, not coverage*).
4. **Composability** — every codec is a leaf that higher structures reuse without re-proof.

Stakeholders: downstream consumers building X.509/PKI/signature tooling; auditors who need to see the
proof boundary; the maintainer, who needs the invariants gated so they cannot silently rot.

## 2. Constraints

- **Zero runtime dependencies**, by design (a selling point, not a gap). `no_std` is a parked TODO.
- **MSRV `1.80`** (edition 2021) for the library source; proofs/lids need a pinned nightly toolchain.
- **Toolchain pins** (volatile — the live authority is the repo's config, not this list): Kani `0.67`
  + a matching CBMC for L3; a nightly + Aeneas + Charon + Lean for L4. See `README.md` / the pin files.
- **Verification is resource-bounded.** Some proofs are memory-heavy (the heaviest X.509 harness
  approaches ~20 GB CBMC); those are kept off the free-CI path (§7) and must be launched under an
  **operator-applied** `systemd-run` memory scope (the gate scripts do not impose one). This shapes
  the two-tier gate/CI split, not just ops.
- **Provenance discipline.** Committed files carry no internal tooling/agent/model names; the tree is
  a public artifact.

## 3. Context & scope

**In scope:** decoding a byte string into validated, borrowed views of DER values, and proving those
decoders panic-free and canonical. Most primitives also expose a canonical **encoder** (`encode_*`)
with a proven decode/encode round-trip (L3, and unbounded at L4 for the lidded codecs). The proven
surface climbs a ladder: primitive content codecs → structural codecs
(`tag`/`length`/`tlv`/`sequence`/`set_of`) → X.509 container consumers (SPKI, Name, Validity,
Extensions, TBSCertificate, Certificate) → **Band-A** signature/key containers (structural DER framing
only, no cryptographic semantics): `ecdsa_sig_value`, `rsa_public_key`, `pkcs8`.

**Out of scope (deliberate — each is a documented decision, not an omission):**
- **Cryptographic semantics** — no signature verification, curve-point, or subgroup checks. Signature
  scalars and key material are exposed as opaque, comparison-only byte slices (D14).
- **General `SET` (ITU-T X.690 §10.3)** — only `SET OF` (X.690 §11.6) member-ordering is in scope (D6, D13).
- **Value-level policy** — curve-order ranges, low-S, and calendar validity are profile concerns left
  to a caller/`profile` layer (D2, D10, and the Band-A modules' own scope notes). (Note: some
  narrowings that *look* like profile rules are enforced at the codec level instead — e.g. a leap
  second `SS=60` is rejected by the time codecs themselves, D9.)

**Entry-point pattern.** The structural codecs (`tlv`, `sequence`) and the Band-A containers each
expose two entry points — a **composable** parser (ignores trailing bytes, so it nests) and a
**strict** one (must consume the whole input, a load-bearing anti-differential control), mirroring
`decode_sequence_tlv` / `decode_sequence_tlv_strict` (D4). The X.509 container consumers are always
top-level and expose a single strict parser/validator each; `parse_algorithm_identifier` is
composable (it nests inside SPKI/TBS).

## 4. Solution strategy

| Goal | Strategy |
|---|---|
| Panic-freedom & soundness | A **four-layer verification stack (L1–L4)**, §8 — each layer proves a different, stronger property at higher cost (the domains are *not* nested: L1 is all-inputs memory-safety, L3 is bounded symbolic, L4 is selected properties of a few codecs ∀-length). |
| Composability | **Compose verified primitives**; a container never hand-rolls TLV parsing — it calls the proven leaf, so correctness is inherited and only the container's own framing needs proving. (The solver cost of a heavy leaf is not free under bounded model checking; that is what the stubbing row below buys.) |
| Tractability of heavy proofs | **Modular (stubbed) proofs** (D23, D26): prove a heavy inner function once, then stub it with its proven post-condition inside the outer proof. |
| Guarantees that survive edits | **Everything is a gate.** Proof counts, the verification map, tier/CI parity, and Lean-lid source-freshness are all regenerated-and-checked by committed scripts (§7), so drift fails the build instead of rotting silently. |
| Honest boundary | `PROOF_MANIFEST.md` states each claim in prose, per property and per bound, with the counts underneath as evidence. |

## 5. Building-block view

Modules form a **dependency ladder** — leaves depend on nothing in-crate, and no lower tier depends on
a higher one. The ladder is strict *between* tiers; **within** the X.509 tier there is further internal
layering (`x509_certificate` → `x509_tbs_certificate` → {`x509_name`, `x509_spki`, `x509_validity`,
`x509_extension`, `x509_algorithm_identifier`}), so read Tier 3 as a responsibility grouping, not a
flat level.

```
Tier 0  structural core     tag → length → tlv        (identifier / length / TLV framing)
Tier 1  primitive content   boolean · null · integer · big_integer · enumerated · oid ·
                            octet_string · bit_string · utf8_string · restricted_string ·
                            utc_time · generalized_time · context_tag
Tier 2  structural content   sequence · set_of         (compose tlv over children)
Tier 3  X.509 containers     x509_algorithm_identifier · x509_spki · x509_validity · x509_name ·
                            x509_extension · x509_tbs_certificate · x509_certificate
Tier 4  Band-A containers    ecdsa_sig_value · rsa_public_key · pkcs8      (+ profile)
```

- The **L4 Lean lids** (unbounded proofs) span Tiers 0–2 — currently the codecs `length`, `tag`,
  `tlv` (Tier 0), `big_integer`, `oid` (Tier 1), `sequence` (Tier 2). `PROOF_MANIFEST.md` is the gated
  authority for the exact set/count; this document names the codecs, not a number that could drift.
  See `DECISIONS.md` (D7 length, D16/D17 big_integer, D25 oid, D27 tlv, D28 sequence) and `lean/`.
- **Tier 3/4** are L3-bounded compositions; the heavy ones (`x509_name`, `x509_tbs_certificate`) use
  modular stubbed proofs to stay tractable.
- A new container (e.g. `pkcs8`) adds a leaf that *only composes downward* — the reason the third
  Band-A module cost one module + three harnesses, not a re-proof of the stack.

The gated **verification map** in `README.md` (`gen_verification_map.py`) is the always-current picture
of which module sits at which layer and colour; treat it as the live building-block diagram.

## 6. Runtime view

A parse is a single left-to-right walk, no back-tracking, no allocation:

1. **Frame** the outer TLV (`decode_tlv` → tag + length + value slice), rejecting non-canonical length
   (indefinite / non-minimal / over-read) at the framing layer.
2. **Dispatch** on the tag; hand the value slice to the tier-1 content validator, which checks
   canonical minimality (e.g. `validate_integer_content`, `validate_oid`).
3. **Compose** for containers: unwrap the outer SEQUENCE, then decode each field in order against its
   own proven codec, requiring the fields to *exactly tile* the content (no trailing element).
4. **Classify** failures into a layered error taxonomy that names the exact structural cause and wraps
   the sub-codec's error — so a caller (and a proof cover) can distinguish every rejection reason.

The **strict vs composable** choice is made by the caller at the entry point, not inside the walk.

## 7. Deployment & build view

- **Artifact:** a library crate (`der-verified`, released on crates.io), consumed as source.
- **Local gates:** `check_fast.sh` (hygiene + docs-sync gates + tests + doctests; the fast floor) and
  `check.sh` (the full L3 proof floor: also runs Kani and the Lean lids — minutes). `check.sh` invokes
  `cargo kani` directly and imposes **no** memory cap; on a memory-constrained host the operator wraps
  the heavy harnesses in a `systemd-run` scope themselves (§2).
- **Two-tier CI** (a memory constraint made structural): the **LIGHT** harnesses that fit a free
  runner run as sharded matrix jobs; the **HEAVY** harnesses (that exceed a 7 GB runner) are a
  local/milestone check via `check.sh`. `check_tier_parity.py` gates that the CI shard filters and the
  `tiers.txt` classification stay in lockstep — so a new module cannot be silently dropped from CI.
- **Docs-sync gates:** `gen_proof_manifest.py` and `gen_verification_map.py` regenerate the counts and
  the map and fail on drift; `check_lid_staleness.py` fails if a Lean lid's source moved without the
  lid being re-checked (D29). The three generate-and-compare gates (`gen_proof_manifest`,
  `gen_verification_map`, `check_lid_staleness`) each ship with a self-test (`test_*.py`) run
  *before* the gate itself; `check_links` and `check_tier_parity` are simple enough to run directly.

## 8. Crosscutting concepts

**The L1–L4 verification stack** (the crate's defining idea):

| Layer | Proves | Over what domain | Mechanism |
|---|---|---|---|
| **L1** | memory safety, no UB | all inputs | `#![forbid(unsafe_code)]` + the Rust type system |
| **L2** | behaviour on chosen vectors, incl. seeded-bad specimens | concrete inputs | `#[test]` + doctests |
| **L3** | panic-freedom + canonicality | **bounded** symbolic inputs (symbolic buffer *and* length) | Kani + CBMC proof harnesses; non-vacuity witnessed by `kani::cover` |
| **L4** | *selected* per-codec correctness properties (canonicality biconditionals, decode/encode round-trips, or structural/consumption correctness — not the same property for every lidded codec) | **unbounded** (∀-length) | Aeneas → Lean "lids": the Rust source is extracted and the named property proven in Lean with no length bound |

- **Bounded vs unbounded is the honest gap.** L3 proves a claim up to a buffer size (measured, never
  assumed — every cover's satisfaction count is read, per the non-vacuity discipline); L4 lifts a
  *specific* codec to all lengths. The lidded codecs (§5) hold ∀-length; the rest rest on L3's bound.
- **Opaque content stance (D14):** values used only for comparison downstream (bignums, key material,
  signature scalars) are exposed as borrowed `&[u8]`, never materialised — keeping arithmetic and
  cryptographic interpretation out of scope by construction.
- **Modular stubbed proofs (D23, D26):** a heavy inner function is proven once, then stubbed by its
  post-condition in the outer proof — the technique that makes X.509-scale compositions tractable. The
  stub's discharge uses symbolic input length so the outer proof is sound at every suffix length.
- **The Lean-lid mechanism (D7, D8):** proofs are extracted through a nightly-pinned, workspace-excluded
  shim crate (no source copy), and the lid embeds source line-spans — which makes lids *fragile to
  source edits*, gated by `check_lid_staleness.py` (§7, D29).
- **Counts are inventory, not coverage** — the reading rule for every number in the tree.

## 9. Architecture decisions

The authoritative log is [`DECISIONS.md`](DECISIONS.md) (D1–D32, each with a status and a confidence).
The load-bearing ones for *architecture* (as opposed to a single codec's rules):

- **D3** module altitude (content-level vs TLV-level); **D4/D5** composable-vs-strict + framing-not-
  content; **D7/D8** the L4 lid concept + extraction shim; **D14** arbitrary-magnitude INTEGER as a
  separate opaque module; **D22** the context-tagging fork + shared `AlgorithmIdentifier`; **D23/D26**
  modular stubbed proofs + the symbolic-length soundness fix; **D29** the lid-staleness tripwire;
  **D30/D31** the Band-A container pattern (ECDSA-Sig-Value, RSAPublicKey) that `pkcs8` extends.

## 10. Quality requirements

| Quality | Scenario | Where enforced |
|---|---|---|
| Soundness | A BER-but-not-DER re-encoding of a value (non-minimal length, redundant integer padding) is **rejected**. | L3 reject-variant covers + seeded-bad tests. |
| Panic-freedom | Any byte string up to the harness bound completes without panicking; a malformed input returns a classified `Err`, a well-formed one returns `Ok`. | L3 `parse_never_panics` harnesses. |
| Differential-resistance | A trailing byte after a top-level object is rejected by the *strict* entry point. | strict harness + test (D4). |
| Reproducibility | Every published count is regenerated from source and gated. | `gen_*` gates + self-tests. |
| Honesty | The proof boundary is stated per-property, per-bound, with "not covered" given equal weight. | `PROOF_MANIFEST.md`. |

## 11. Risks & technical debt

- **Memory walls (L3).** The heaviest X.509 harnesses need large CBMC memory and stay off free CI;
  a future toolchain regression here would silently push more harnesses into the HEAVY tier. Mitigated
  by tier-parity gating, not eliminated.
- **Toolchain coupling (L4).** Lids embed source line-spans and depend on pinned Aeneas/Charon/Lean;
  even a doc-only source edit can drift a lid. Gated (D29) but inherently brittle.
- **Bounded ≠ unbounded.** Only the lidded codecs (§5) hold ∀-length; every other L3 claim holds only
  up to its measured buffer bound. This is disclosed, not hidden — but it is the crate's principal residual.
- **`no_std` is a parked TODO** — a scope limit for embedded consumers.
- **Docs-sync drift class.** Hand-written counts elsewhere in the tree can lag the gated source; the
  gates catch the ones they guard, and their reach is itself a maintenance surface.

## 12. Glossary

**DER / X.690** — the canonical (one-encoding-per-value) subset of ASN.1 BER. **TLV** — tag-length-value,
the framing unit. **Canonicality** — DER's minimal-encoding requirement (the anti-differential property).
**Harness** — a Kani proof entry point (`#[kani::proof]` / `proof_for_contract`). **Cover** — a
`kani::cover` witness that a proof is non-vacuous (a real post-state is reachable). **Lid** — an
Aeneas→Lean unbounded (∀-length) proof of a specific codec (L4). **Modular / stubbed proof** — proving an
inner function once and replacing it by its post-condition in an outer proof. **Band A / Band B** — the
scoping split for signature/key containers: A = structural DER framing of the container (in scope);
B = value-level cryptographic policy (out of scope). **Composable / strict** — the two entry-point
variants (ignore vs. forbid trailing bytes).
