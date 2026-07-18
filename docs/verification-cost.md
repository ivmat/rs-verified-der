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
  verifies the full suite (all 161 harnesses) end-to-end.

## Cost tiers

**The large majority of the 161 harnesses are fast** — sub-second to a few seconds. Typical per-module
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
| `x509_extension::validate_extensions_never_panics` | did not finish within a 5-minute per-harness budget here; a `SEQUENCE OF` walk around an inlined per-element parser (see `DECISIONS.md`, the buffer-reduced `[u8; 13]` harness) |
| `x509_name::validate_rdn_never_panics` | peak memory ~17 GB — exceeds 16 GB physical (swaps). This is the heavy SET-OF/RDN lemma; `validate_name` itself is proven cheaply (~0.5 GB) by *stubbing* this lemma's proven postcondition — see the modular-proof note in `src/x509_name.rs` and `DECISIONS.md`. |

## Why the two heaviest are structured the way they are

Both heavy X.509 harnesses are already **modular** on purpose. `x509_name::validate_name` is proven
panic-free by splitting off the expensive SET-OF/RDN layer into `validate_rdn_never_panics` (proven at
one-RDN scale, ~17 GB) and having the outer harness **stub** `validate_rdn` with its proven
postcondition (`2 ≤ used ≤ input.len()`) — so the outer proof reasons only about the RDN-walk glue and
runs in ~0.5 GB. Without that split the monolithic harness exceeds ~100 GB. The same technique makes
`x509_tbs_certificate` and `x509_certificate` tractable. This is why `cargo kani` needs `-Z stubbing`.

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
