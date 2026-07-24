# Verification cost & tractability

This note records the **cost profile** of the crate's Kani proof suite — how long each harness takes and
which ones are resource-heavy — so the expensive harnesses are visible up front rather than discovered
by a stalled `./check.sh`. It answers a practical question for contributors: *"I ran `cargo kani` and it's
been going for minutes — is that normal?"*

> **Counts are inventory, not coverage** (see `PROOF_MANIFEST.md`). This note is about *wall-clock and
> memory*, not about what is proven. All harnesses listed verify **SUCCESSFULLY**; nothing here is a
> failure.

## How this was measured

- **Machine:** a 16 GB Apple-silicon laptop (a deliberately modest box — the point is to show what a
  contributor's everyday machine can and cannot do).
- **Tooling:** `cargo-kani 0.67.0` / CBMC 6.8.0, `cargo kani -Z stubbing` (the same invocation
  `./check.sh` uses). Per-harness wall-clock is Kani's own `Verification Time:`; peak RSS was sampled
  from `cbmc`'s process.
- **Caveat:** these are point-in-time numbers on one machine; solver and CBMC versions move them.
  Treat the **tiers** as durable, the exact seconds as indicative. The project's reference CI box
  verifies the full suite (currently 164 harnesses — count re-confirmed by source grep; the
  per-harness timings below are the prior measurement pass and were not re-run for the newer
  harnesses) end-to-end.

## Cost tiers

**The large majority of the 164 harnesses are fast** — sub-second to a few seconds. Typical per-module
worst case: `length` 0.4 s, `integer` 0.5 s, `oid` 0.04 s, `boolean` 0.03 s, `bit_string` 0.4 s,
`tag` 0.5 s, `utc_time` 1.0 s, `big_integer` 0.7 s. Whole modules like `oid`, `boolean`, `null`,
`enumerated`, `tag` finish in well under a second total.

**Moderate (single-digit to tens of seconds):**

| Harness / module | ~time | Note |
|---|---|---|
| `restricted_string` (26 harnesses) | ~21 s total | many small charset harnesses |
| `generalized_time` (16 harnesses) | ~10 s total | fractional-second canonicality |
| `octet_string` (6 harnesses) | ~6 s total | |
| `tlv` (5 harnesses) | ~6 s total | |
| `x509_algorithm_identifier::parse_never_panics` | ~6 s | |
| `x509_certificate::parse_certificate_never_panics` | ~50 s | the full-cert composition (modularly stubbed) |
| `x509_validity::parse_validity_ok_path_witnessed` | ~6 s, ~0.58 GB peak RSS | positive-construction cover-vacuity closer, unstubbed (see below) |

**Heavy (1–5 minutes on this box) — the ones to know about:**

| Harness | ~time | Peak RSS |
|---|---|---|
| `set_of::tag_correctness` | ~256 s | ~5 GB |
| `set_of::ok_implies_exact_tiling` | ~177 s | |
| `set_of::accepted_identifier_is_canonical_0x31` | ~174 s | |
| `set_of::roundtrip_two_sorted_children` | ~125 s | |
| `set_of::iterate_never_panics` | ~110 s | |
| `utf8_string::roundtrip` | ~109 s | |
| `sequence::ok_implies_exact_tiling` | ~79 s | |

The `set_of` family dominates because DER SET-OF validation re-derives the X.690 §11.6 *padded* byte
comparison (`set_of::cmp_padded`) over fully symbolic member content, for every member partition — a
genuinely expensive symbolic computation. If you are iterating on `set_of`, `sequence`, or
`utf8_string`, expect minute-scale harnesses and use `--harness <name>` to run just the one you touched.

**Needs more than a 16 GB laptop — run these on a larger box (the reference CI):**

| Harness | Why |
|---|---|
| `x509_extension::validate_extensions_never_panics` | did not finish within a 5-minute per-harness budget on the 16 GB Mac; a `SEQUENCE OF` walk around an inlined per-element parser (see `DECISIONS.md`, the buffer-reduced `[u8; 13]` harness). **Re-measured on the 32 GB Linux desktop, 2026-07-21: a genuine RAM wall, not a Mac-budget artifact.** Symex completes (~126 s, 33149→22672 VCCs after `--slice-formula`, already default-on), but the SAT-solving phase itself climbs past 19 GB RSS (cadical, default) and past 16 GB (kissat, `#[kani::solver]`/`--solver` probe — CBMC's own verdict: "CBMC appears to have run out of memory", both solvers OOM at the same post-slicing stage). Both the default solver and the T7 kissat lever were tried and measured; neither converges under ~12 GB. Classified RAM-bound (not TIME-bound — the Mac's "didn't finish in 5 min" undersold it; on Linux it's an outright OOM once given enough RAM to climb). No further local lever attempted (T8 `--slice-formula` is already Kani's default and did not help; a smaller bound would narrow proof scope, which the module's own doc already treats as a deliberate, documented reduction floor — see `src/x509_extension.rs`). Needs either a larger-RAM box or is left as a known, honestly-logged residual. |
| `x509_name::validate_rdn_never_panics` | peak memory ~17 GB — exceeds 16 GB physical (swaps). This is the heavy SET-OF/RDN lemma; `validate_name` itself is proven cheaply (~0.5 GB) by *stubbing* this lemma's proven postcondition — see the modular-proof note in `src/x509_name.rs` and `DECISIONS.md`. |
| `x509_tbs_certificate::parse_tbs_certificate_ok_path_witnessed` | ~11.3 GB peak RSS, ~206 s wall (symex ~106 s dominates; SAT solve itself is only ~3.4 s) — see `src/x509_tbs_certificate.rs`'s doc comment for the full investigation. Fits under the ~12 GB local budget, but not by a wide margin: it is the positive-construction companion to `parse_tbs_certificate_never_panics` (closes that harness's cover-vacuity finding — see below), and even fully-concrete-input + 3-way modular stubbing (`validate_name`, `validate_extensions`, `parse_validity`) does not make it cheap; the remaining real composition (`parse_algorithm_identifier` + `parse_subject_public_key_info` + the TBS glue itself) is the residual cost driver. |

## Why the two heaviest are structured the way they are

Both heavy X.509 harnesses are already **modular** on purpose. `x509_name::validate_name` is proven
panic-free by splitting off the expensive SET-OF/RDN layer into `validate_rdn_never_panics` (proven at
one-RDN scale, ~17 GB) and having the outer harness **stub** `validate_rdn` with its proven
postcondition (`2 ≤ used ≤ input.len()`) — so the outer proof reasons only about the RDN-walk glue and
runs in ~0.5 GB. Without that split the monolithic harness exceeds ~100 GB. The same technique makes
`x509_tbs_certificate` and `x509_certificate` tractable. This is why `cargo kani` needs `-Z stubbing`.

## Cover-retrofit follow-ups (2026-07-21)

The 2026-07-21 cover-retrofit pass (`METHODS-APPLICATION-ANALYSIS-2026-07-21.md`) added
`kani::cover`s to the crate's symbolic `never_panics` harnesses to check the manifest's "exercises
the REAL glue" claims were machine-witnessed, not just prose. Two open items from that pass were
closed here:

- **`x509_tbs_certificate::parse_tbs_certificate_never_panics`'s `Ok`-tail cover is UNSATISFIABLE at
  `[u8; 10]`** — reaching a successful parse needs >60 octets of valid structure (serialNumber +
  AlgorithmIdentifier + issuer/subject TLVs + Validity ≥32 B + SubjectPublicKeyInfo ≥11 B), which
  cannot fit in 10 octets no matter what the two stubbed callees return. That harness is **left in
  place, cover and all** — a cover reporting "0 of 1 satisfied" is the honest record of the gap, not
  a bug to hide. The gap is closed by a **new, separate harness**,
  `parse_tbs_certificate_ok_path_witnessed` (see `src/x509_tbs_certificate.rs`), which drives the
  real (mostly-unstubbed) parser with a fully-concrete, hand-constructed valid `TBSCertificate` and
  proves its `Ok`-tail cover IS satisfied. See that harness's doc comment for the full investigation,
  including two measured dead ends (concrete input alone did not avoid the composition-depth cost;
  reusing only the sibling harness's two stubs was still insufficient) before the working design
  (three stubs, chosen because they're the two independently-proven "validate, don't materialize"
  callees plus `parse_validity`, whose materialized value the TBS glue never branches on).
- **`x509_extension::validate_extensions_never_panics`'s cover** (`result.is_ok() &&
  second_child_at_nonzero_offset`, added in the same pass) was re-measured on the 32 GB Linux desktop
  per the heavy-harness table above: it is a genuine >12 GB RAM wall (both `cadical` and `kissat`
  OOM past the slicing/SSA stage), so the cover's SAT/UNSAT status was **not determined** — the run
  never reached a verdict. This is left as an open, honestly-logged item (not claimed SATISFIED),
  pending either a larger-RAM box or a scope-narrowing change to the harness (out of scope for a
  same-day pass; see the heavy-harness table entry above).
- **`x509_validity::parse_never_panics`'s `Ok`-tail cover is UNSATISFIABLE at `[u8; 16]`** —
  `decode_utc_time` requires exactly-13-octet content (minimal `Time` TLV = 15 octets), and a
  `Validity` needs an outer SEQUENCE header plus TWO such `Time` fields — an arithmetic floor of 32
  octets, twice this harness's buffer. That harness is **left in place, cover and all** (an honest
  "0 of 1 satisfied" record). The gap is closed (2026-07-21) by a new, separate harness,
  `parse_validity_ok_path_witnessed` (see `src/x509_validity.rs`), which drives the real, fully
  unstubbed `parse_validity` on a concrete 32-octet `Validity` (copied from the module's own
  `VALIDITY_UTC_UTC` test fixture) and proves its `Ok`-tail cover IS satisfied. Unlike the
  `x509_tbs_certificate` positive harness above, **no stubbing was needed here** —
  `Validity`'s call graph is shallow (one outer `decode_tlv` plus at most two `decode_time_tlv`
  calls, each a single inlined leaf time-decoder), so it does not hit the composition-depth wall
  that forced three stubs on the TBS harness: `VERIFICATION: SUCCESSFUL`, `1 of 1 cover properties
  satisfied`, ~0.58 GB peak RSS, ~6 s wall.

## Solver selection (measured, harness-dependent)

Kani lets you pick the SAT back-end per harness (`#[kani::solver(...)]`) or per run (`--solver`).
On the slowest harness here, `set_of::tag_correctness` (~256 s on the default solver):

| Solver | Time | Peak RSS |
|---|---|---|
| default | ~256 s | |
| `cadical` | ~220 s | ~6.6 GB |
| `kissat` | did not finish in 5 min | ~4.7 GB |

So the gain is **modest and solver-specific** — `cadical` was ~14 % faster, `kissat` was *slower* on
this harness (it uses less memory, though). The lesson: solver choice is worth trying on a slow
harness you're iterating on, but there is no single winner to pin crate-wide — measure the specific
harness. No solver is pinned in the crate today for this reason.

## Reproducing

```sh
# whole suite (needs -Z stubbing):
cargo kani -Z stubbing

# one harness, with a per-harness timeout and an alternate solver:
cargo kani -Z stubbing -Z unstable-options --harness-timeout 300s \
    --solver cadical --harness set_of::proofs::tag_correctness
```
