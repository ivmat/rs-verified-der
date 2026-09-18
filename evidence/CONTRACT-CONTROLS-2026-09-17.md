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

**Control 2 — review-added conjunct (pkcs8/ecdsa/rsa):**

| module | conjunct | mutation (impl) | `parse_faithful` | failed assert |
|---|---|---|---|---|
| pkcs8 | `[0]`-attributes classification | `\|\| tag.number != 0` → `\|\| false` | FAILED | `attr_tlv.tag.number == 0` |
| ecdsa_sig_value | INTEGER minimality | drop `validate_integer_content(...)?` | FAILED | `validate_integer_content(r_tlv.value).is_ok()` |
| rsa_public_key | INTEGER minimality | drop `validate_integer_content(...)?` | FAILED | `validate_integer_content(modulus_tlv.value).is_ok()` |

epki and ec_private_key carry a single control each: epki has no delegated value constraint beyond the
tiling; ec's version octet, `[0]`/`[1]` classification and both optionals all feed the single final
`final_rest.is_empty()` tiling assert exercised by control 1.

All: baseline green · every listed control observed-red on the named assert · never_panics green under
the same mutation. (The Kani property table names each assert as `assertion failed: <expr>`; 0
`Status: FAILURE` on the baselines, exactly one on each control leg.)

## Scope / honest residual

This closes the composed layer's "no functional contract, no mutation control" gap for these five
modules (previously A1 panic-freedom probes — honest under assurance-bands rule 6, but oracle-free).
The x509_* structural family remains at A1 panic-freedom (weak/stubbed oracles per the harness
inventory) — a separate, harder campaign. The acceptance-manifest band lift is generated (not
hand-edited), so promoting these claims to A3 is a re-emit of the manifest from imported evidence;
the per-module logs here are the ready inputs for that re-emit.
