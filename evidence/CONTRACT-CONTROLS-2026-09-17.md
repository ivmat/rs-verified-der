# Contract-grade promotion + observed-red controls — composed layer (2026-09-17)

Five composed/private-key modules each gained a `*_parse_faithful` `#[kani::proof]` **functional
contract**, promoting them from A1 `never_panics`-only (probe) toward **A3 contract** (functional
oracle + observed-red control). Verified on cloud VMs (Kani 0.67.0, CBMC 6.10.0) — Kani is not run on
the box (project Law 1). Raw logs (gzipped) per module under
[`contract-controls-2026-09-17/<module>/`](contract-controls-2026-09-17/).

## What the contract adds over `never_panics`

Each `*_parse_faithful` harness asserts, on any accepted symbolic input (16-octet backing, symbolic
length `0..=16`), that the parser's output **faithfully and exactly** reflects the input's DER
structure: exact envelope consumption / no over-read, faithful field sub-slices, INTEGER content
minimality where applicable, tag/`[0]`/`[1]` classification, documented value constraints (e.g. the
version octet), and **exact field tiling** of the SEQUENCE content. The oracle re-derives the field
boundaries, tiling, tag constraints and content from the lidded/verified primitives
(`decode_sequence_tlv`, `decode_tlv`, `decode_octet_string`, `validate_integer_content`,
`parse_algorithm_identifier`, `decode_explicit_context`, `decode_bit_string`) rather than the module's
own `parse_fields` chain, so a composition defect (wrong field order, missing tiling check, wrong
constant, mis-classified/mis-sliced field, dropped content-validation) is caught.

**Precision of "faithful", stated exactly (per critical review 2026-09-17):** "sub-slice pointer +
length identity" holds for the directly-decoded content fields (each `privateKey`/`encryptedData`
OCTET STRING, each `r`/`s`/`modulus`/`publicExponent` INTEGER, and ec's `[0]` parameters inner). The
**delegated** fields — pkcs8/epki `AlgorithmIdentifier` and ec `publicKey` `BitString` — are checked
by **value-equality** against an independent re-decode, not pointer identity. And claim 1
(`used == outer_used`) recomputes the same `decode_sequence_tlv` call the impl makes, so it checks
return plumbing while the substantive no-over-read rides on that primitive's own lid (DER-C-SEQ-1).

## Bounds disclosure (Law 6 amendment 2026-09-12 — CONTRACT SURFACE / bounded-backing)

The 16-octet symbolic backing is a harness **tractability bound**, stated here and in the harness doc
comments; the public API carries no bound. Inputs/operands are symbolic throughout the declared
domain. Report as CONTRACT SURFACE / bounded-backing evidence, not an unrestricted proof.

## Observed-red controls (non-vacuity, `of_claim` = the module's `parse_faithful` tiling property)

Protocol per module: baseline `parse_faithful` GREEN → mutate the impl's exact-tiling guard (single,
`if`-anchored, verified exactly one replacement) → `parse_faithful` **FAILED** on the exact tiling
assertion (the observed red) → `parse_never_panics` still **SUCCESSFUL** under the same mutation
(proving the contract adds a property panic-freedom cannot catch) → source restored.

Every module's baseline `parse_faithful` verifies SUCCESSFUL and `parse_never_panics` stays SUCCESSFUL
under each mutation (proving the property is one the contract adds). The strong modules carry **two**
controls — one for the exact-tiling conjunct and one for the conjunct added in the 2026-09-17 critical
review (classification for pkcs8; INTEGER minimality for ecdsa/rsa).

**Control 1 — exact-tiling conjunct:**

| module | mutation (impl guard) | `parse_faithful` | failed assert (the observed red) |
|---|---|---|---|
| pkcs8 | `tlv_used != rest.len()` → `>` | FAILED | `attr_used == after_pk.len()` |
| ecdsa_sig_value | `s_used != rest.len()` → `>` | FAILED | `r_used + s_used == outer_content.len()` |
| rsa_public_key | `exponent_used != rest.len()` → `>` | FAILED | `modulus_used + exponent_used == outer_content.len()` |
| encrypted_private_key_info | `data_used != rest.len()` → `>` | FAILED | `data_used == after_alg.len()` |
| ec_private_key | `!rest.is_empty()` → `false` | FAILED | `final_rest.is_empty()` |
| x509_spki *(Track B)* | `pk_used != outer_rest.len()` → `>` | FAILED | `pk_used == after_algo.len()` |
| x509_algorithm_identifier *(Track B)* | `params_used != rest.len()` → `>` | FAILED | `params_used == rest.len()` |

**Control 2 — review-added conjunct (pkcs8/ecdsa/rsa):**

| module | conjunct | mutation (impl) | `parse_faithful` | failed assert |
|---|---|---|---|---|
| pkcs8 | `[0]`-attributes classification | `\|\| tag.number != 0` → `\|\| false` | FAILED | `attr_tlv.tag.number == 0` |
| ecdsa_sig_value | INTEGER minimality | drop `validate_integer_content(...)?` | FAILED | `validate_integer_content(r_tlv.value).is_ok()` |
| rsa_public_key | INTEGER minimality | drop `validate_integer_content(...)?` | FAILED | `validate_integer_content(modulus_tlv.value).is_ok()` |
| x509_spki *(Track B)* | BIT STRING classification | `\|\| tag.number != BIT_STRING_TAG` → `\|\| false` | FAILED | `pk_tlv.tag.number == BIT_STRING_TAG` |
| x509_algorithm_identifier *(Track B)* | canonical-OID | drop `validate_oid(...)?` | FAILED | `validate_oid(oid_tlv.value).is_ok()` |

epki and ec_private_key carry a single control each: epki has no delegated value constraint beyond the
tiling; ec's version octet, `[0]`/`[1]` classification and both optionals all feed the single final
`final_rest.is_empty()` tiling assert exercised by control 1.

All: baseline green · every listed control observed-red on the named assert · never_panics green under
the same mutation. (The Kani property table names each assert as `assertion failed: <expr>`; 0
`Status: FAILURE` on the baselines, exactly one on each control leg.)

**Baseline non-vacuity confirmed (not just SUCCESSFUL).** Every `parse_faithful` baseline log reports
**`1 of 1 cover properties satisfied`** for its `kani::cover(result.is_ok())` — so the Ok branch (where
all the postcondition asserts live) is reachable at baseline, and the harness is non-vacuous
independently of the observed-red controls. Audited across all 7 modules from the committed baseline logs.

## Track A — x509_certificate outer-framing bound (measured capability, not a contract)

The `x509_certificate::parse_certificate_never_panics` harness (TBS parser stubbed) is a panic-freedom
probe; pushing its bound is a *capability* measurement, not a contract (Law 6), and is recorded as such:
- **N=128 reproduced SUCCESSFUL** (unwind 136, peak 16.9 GB, 41 min) — 10.7× the shipped 12-byte CI floor.
- **N=150 SUCCESSFUL** (unwind 158, peak 21.1 GB, 70 min) — a NEW extension past §6.5's N=128; cost grows
  super-linearly (128→150 ⇒ 41→70 min, 16.9→21.1 GB).
- **N=170 (a real certificate's size) is a solver-agnostic tractability wall:** cadical exceeds a 60-min
  budget AND kissat exceeds a 100-min budget (both timeout, not OOM) — so a stronger SAT solver does NOT
  extend reach here; it is a proof-*tractability* limit, not a tool defect and not a solver-choice artifact.
- Still TBS-STUBBED: this narrows §6.5's outer-framing gap; it does NOT close the inner-structure
  compositional argument. Not banked as a contract row; recorded in `COVERAGE.md` §6.5/§6.6.

## Scope / honest residual

This closes the composed layer's "no functional contract, no mutation control" gap for the five
key-format modules (previously A1 panic-freedom probes — honest under assurance-bands rule 6, but
oracle-free), and adds the **X.509 layer's first two contract rows** (x509_spki, x509_algorithm_identifier
— Track B). The deeper x509 cert-*composition* modules (x509_certificate/tbs/validity/name/extension)
remain A1 panic-freedom (weak/stubbed oracles per the harness inventory) — a separate, harder campaign.
The acceptance-manifest band lift is generated (not hand-edited), so promoting these claims to A3 is a
re-emit of the manifest from imported evidence;
the per-module logs here are the ready inputs for that re-emit.
