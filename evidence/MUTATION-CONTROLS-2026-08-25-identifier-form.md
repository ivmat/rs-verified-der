---
type: reference
---

# Mutation controls on `identifier_form` — 2026-08-25

**What this closes.** `identifier_form` is a new module (D34) deciding two X.690 identifier rules
that no verified layer of this crate previously decided. Its four headline theorems are stated over
the *complete* input domain, which makes them exactly the kind of claim that is worth nothing if the
harnesses cannot fail. This campaign is the evidence that they can, and — more usefully — that
**different defects kill different, predictable subsets** of them.

**Method.** Two rounds, run LOCALLY under the R-0009 FV slot, one solver run at a time, each inside
its own detached `systemd-run --user --unit=…` service capped at `MemoryMax=12G` (the module is
LIGHT tier: the full 12-harness set verifies in ~10 s). For each mutation: plant one real defect,
run every harness in the module, record the per-harness verdict, revert, and confirm the source is
byte-identical to its pre-mutation copy (`sha256`). The tree was clean at the end of both rounds.

**Preregistration — stated exactly, not smoothed.**

| round | mutations | predictions written down before the run? |
|---|---|---|
| 1 | M1–M3 | **No.** Predicted in the run's *design* (one mutation per rule), not in an artifact. |
| 2 | M4–M6 | **Yes.** `PREREG-mutations-v2.md`, sha256 `6da2284717…`, locked 2026-08-25T09:35:17Z. |

Round 2 is the preregistered set and is the one to weigh. Round 1 is an honest observed control.

---

## Round 2 — preregistered (M4–M6), against the post-review module

Harness abbreviations: **OWF** `oracle_is_well_formed` · **TBL**
`required_form_matches_oracle_on_all_u32` · **EOC** `reserved_eoc_rejected_iff_universal_zero` ·
**FRM** `constructed_form_rule_matches_oracle_on_all_tags` · **ACC**
`accepts_iff_no_encoded_rule_violated_and_never_rejects_non_universal` · **CMP**/**CMPS** the two
composition harnesses · **SPEC** `rejects_every_disclosed_illegal_identifier` · **HIGH**
`high_tag_universal_types_are_form_checked` · **LEGC**
`legal_der_the_comparison_library_rejected_is_still_accepted` · **X509**
`real_x509_identifiers_are_still_accepted` · **CONT** `content_errors_are_deliberately_not_caught`.

| run | planted defect | predicted RED | observed RED | verdict |
|---|---|---|---|---|
| BASELINE | — | (none) | (none) — 12/12 SUCCESSFUL | **match** |
| **M4** | drop SET (universal 17) from the constructed-only table | TBL, FRM, ACC | TBL, FRM, ACC | **match** |
| **M5** | corrupt the **oracle** (clear mask bit 19, PrintableString) — implementation untouched | OWF, TBL, FRM, ACC | OWF, TBL, FRM, ACC | **match** |
| **M6** | drop the `31..=36` arm (revert the P1.1 fix) | TBL, FRM, ACC, HIGH | TBL, FRM, ACC, HIGH | **match** |

**All four predictions matched harness-for-harness, not merely in count.** No prediction was edited
after observation.

### What each mutation actually buys

- **M4 is the discrimination test.** It breaks one table row and kills exactly the three
  table-and-rule theorems, leaving EOC and OWF green. A harness set that went uniformly red would
  tell us far less.
- **M5 tests the direction the others cannot: can the *oracle* rot silently?** The shipped code is
  unchanged, so every fixture harness — including SPEC's own `33 01 00` PrintableString specimen —
  stays green, and only the oracle-facing theorems fall. `oracle_is_well_formed` catches it, which
  is the entire reason that harness exists. **Note its limit:** OWF checks the masks' *shape*
  (disjointness, coverage of `1..=36` minus 15), never their *content*. It cannot catch a
  primitive/constructed misclassification, and it cannot catch a standards misreading shared with
  `required_form`. That is what the `inspection-argued` label on the table is for.
- **M6 is the load-bearing one, and it documents a real miss.** It reverts the fix for the second review's P1.1
  (X.680 assigns 31..=36 — DATE, TIME-OF-DAY, DATE-TIME, DURATION, OID-IRI, RELATIVE-OID-IRI — all
  primitive under DER). **SPEC survived M6.** Every specimen SPEC pins is a low-tag number ≤ 30, so
  no fixture harness in the pre-review set could reach the high-tag form — which is precisely why
  the gap (`3F 1F 00`, a constructed DATE, was accepted) existed and why `HIGH` had to be added.
  M6 is the proof that `HIGH` is not decorative.

---

## Round 1 — observed (M1–M3), against the pre-review module

Run before the review rework, when the module had 9 harnesses and the table stopped at 30.

| run | planted defect | observed RED | correctly unaffected |
|---|---|---|---|
| **M1** | drop BOOLEAN (universal 1) from the primitive-only table | table-vs-oracle, form-rule, accepts-iff, specimen harness | EOC rule, oracle self-check |
| **M2** | remove the reserved-EOC rejection | EOC rule, accepts-iff, specimen harness | table-vs-oracle, form-rule |
| **M3** | no-op the primitive-form rule (accept constructed primitives) | form-rule, accepts-iff, specimen harness | table-vs-oracle, EOC rule |

**The finding round 1 produced, which is worth more than its three red runs.** The two *composition*
harnesses survived **all three** mutations. That is correct behaviour, not a defect: they are stated
relative to `validate_identifier_form`, so they hold whatever the rule says. But it means they
witness the **composition** — that `decode_tlv_form_checked` is `decode_tlv` refined by the rule,
losing and inventing no framing behaviour — and **nothing about the rule's content**. The module
docstring, D34 and the envelope all label them that way as a direct result of this observation.

---

## Control strength, unevenly

Not all six mutations are equally demanding, and presenting them as uniform would be the same
overclaim this crate keeps catching elsewhere:

- **M5 and M6 are demanding.** M5 attacks the oracle rather than the implementation — a direction
  most control campaigns never test. M6 reverts a defect that the *entire pre-existing fixture set
  provably could not catch*, which is the strongest single statement in this document.
- **M1 and M4 are single-row table edits** — real defect classes, and precise, but a table row is an
  easy target for a biconditional stated over the whole domain.
- **M2 and M3 are branch removals** — coarse kill-switches showing the check is load-bearing at all,
  not that it is precise.

None is a no-op; all six are genuine, logged Kani failures. "Six mutations" should not be read as
"six mutations of equal rigor."

## Artifacts

- Round 1 log: `mutation-controls.log` (scratch, run 2026-08-25)
- Round 2 log: `mutation-controls-v2.log` (scratch, run 2026-08-25), preregistration
  `PREREG-mutations-v2.md` sha256 `6da228471787086095b4ada55d23deb6c91a1b09d2bddf156d622d3aff92873b`
- Both rounds: source restored byte-identical by `sha256`, R-0009 slot released, tree clean.
