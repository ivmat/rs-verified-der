# Coverage ledger — what this crate decides, and what it does not

**What this is.** One table saying, per *encoding rule*, whether this crate decides that rule, how
strongly, and the exact command you run to check the answer yourself. It is the consumer-side view:
you should be able to answer *"is the thing I care about actually verified here?"* without reading a
proof, and without reading the 96 KB [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md).

**What it is not.** Not a badge, not a score, and not a replacement for this crate's other documents —
every row cites them. Where this file and the crate's **generated** documents disagree, the generated
documents are authoritative and this file has a bug: [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) and
[`README.md`](README.md)'s verification map are rebuilt from source by
`gates/gen_proof_manifest.py`, and this file is written by hand.

**Certified at `130de97`.** §7 states exactly what that word covers, as a procedure you can re-run.

---

## 1. Subject identity — what exactly is being certified

| | |
|---|---|
| subject | crate `der-verified` 0.1.1, sources at `der-verified/src/` |
| commit | `130de97` |
| tree state | clean at the certified commit; the run log records `git status --porcelain` sampled clean **at launch and at completion**, not assumed |
| spec axis | **X.690 (2021) DER encoding rules**, per type + framing; **RFC 5280** profile surface. See §3. |
| gate receipt | `./check.sh` exit 0 at `bffab69`, `== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: PASS) ==`, run with `DER_REQUIRE_LEAN=1` |
| proof floor (L3) | **203 of 203 Kani harnesses SUCCESSFUL, 0 FAILED** — `evidence/check-bffab69.log:1149` |
| unbounded lids (L4) | 6 lids in Lean, `lean lid: PASS (sorry-free)`, re-extracted from the shipped `.rs`; `lid-source-state.txt unchanged (hashes identical)` |
| tests | 485 unit and regression tests + 34 doc-tests (no integration-test directory exists) |
| unsafe | 0 `unsafe` blocks; the crate is `#![forbid(unsafe_code)]` |
| toolchain | Kani `0.67.0`, CBMC `6.8.0` (kani-bundled, read from the run's own output), CaDiCaL 2.0.0, rustc `1.97.0`, Lean 4 `v4.30.0-rc2` |
| cost | 1h11m07s wall, peak 20.43 GiB. **That peak is systemd cgroup-wide `MemoryPeak`, sampled every 20 s** — a different measure from the previous run's 20.26 GiB (`/usr/bin/time -v` largest-single-process RSS). Do not read a trend across the two. |
| freshness | the run at `bffab69` speaks for HEAD iff `git diff bffab69..HEAD -- der-verified/src lean` is empty. **Run that command; do not trust this sentence.** |

**Two toolchain caveats stated up front,** because they bound everything below:

- Kani is pinned **by version string, not by commit**. Two Kani builds reporting `0.67.0` can have
  different capabilities. Every row's proof evidence inherits that weakness.
- The certified run was executed on the maintainer's own machine, not a clean-room VM — the run log
  says so in its own header. Two earlier runs *were* clean-room VMs, but had to skip the Lean stage,
  because that machine is the only one carrying the Aeneas/Charon/Lean toolchain. A single run
  covering both the Kani floor and the Lean lid cannot currently also be clean-room. That trade is
  stated rather than hidden.

---

## 2. Weighted rows and admitted rows — read this before reading any row

**Every claim about this crate is admitted to this table, including the ones no machine decides.**
A claim left out of a coverage table is a claim the reader has to infer from silence, which is the
failure this file exists to prevent. But admission is not endorsement. Rows fall into two tiers, and
the tier is visible in the `strength` column:

- **Weighted** — `CONTRACT+L4`, `CONTRACT`, `mechanical`. A *deciding* recipe exists: a command whose
  failure would falsify the row. `DER-F-4`, `DER-C-INT-2` and `DER-P-2` are weighted rows.
- **Admitted** — `PROBE`, `test-only`, `inspection-argued`, `not-covered`, `derived`. These are
  carried at the evidentiary level they actually have, which is usually *"a human asserted it and a
  reviewer checked the assertion"*. `DER-X-BOUND` and `DER-C-OID-2` are admitted rows.

**The split cannot be crossed by writing better prose.** A row becomes weighted when a deciding
recipe is attached to it, and not before.

**Of the 74 rows below: 33 are weighted, 39 are admitted, and 2 are split across both tiers**
(`DER-C-BITS-4` inherits a weighted row's strength at one entry point only; `DER-S-5`'s
`sorry`-freedom half is gate-enforced while its no-crate-code-axiom half is inspection-argued). Two
further weighted rows carry a named admitted *sub-claim* — `DER-F-8`'s table-vs-X.680 agreement and
`DER-C-STR-2`'s fixture-shaped siblings — rather than letting the weighted half cover for the other.

**That more than half the rows are admitted is this table working, not failing.** The crate's own
headline is "203 of 203 harnesses SUCCESSFUL". That is true, and it invites the reading that 203 of
203 *rules* are decided. Compare `DER-F-4` (weighted: a Lean lid over all input lengths) with
`DER-X-BOUND` (admitted: a compositional argument nobody has machine-checked). Both sit under the
same green check. This table's job is to stop them reading alike.

### The strength labels

| label | means |
|---|---|
| **CONTRACT+L4** | the rule is proved of the **shipped** function over **unbounded** input, kernel-checked in Lean via the Aeneas lid, *and* also proved bounded by Kani. The strongest thing this crate has. |
| **CONTRACT** | the rule is asserted as a property of the **shipped** function over a **symbolic** (bounded) input domain, with an oracle **not derived from the state under test**. Bounded: it holds up to the declared buffer/unwind, and says nothing beyond it. |
| **PROBE** | bounded, monomorphic, or fixture-shaped evidence — **or** a *safety* property (panic-freedom) that does not decide the encoding rule at all. A probe never counts as the rule being verified. |
| **test-only** | `#[test]` / doc-test at named concrete inputs. Witnesses points, not sets. |
| **inspection-argued** | a documented human argument with no mechanical oracle. Weakest admissible evidence. |
| **not-covered** | no layer of this crate decides this rule. The row exists so you do not have to infer it from silence. |

> **`CONTRACT` here is NOT Kani's `#[kani::requires]`/`#[kani::ensures]` machinery.** This crate uses
> **zero** function contracts — its 203 Kani harnesses are all plain `#[kani::proof]`, and modular proofs are
> built with `#[kani::stub]` + `-Z stubbing`. `CONTRACT` in this table is the review-lens sense
> (*proves the documented rule, on the real shipped path, with an independent oracle*), which is the
> distinction a consumer actually cares about. Verify with
> `grep -rn 'kani::\(requires\|ensures\|proof_for_contract\)' der-verified/src` → no matches.

---

## 3. The spec axis — and why it is not the module list

The rows below are **X.690 encoding rules and RFC 5280 profile rules**, not source modules. That
choice is the point of this document. [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) is organised per
module and answers *"does `sequence.rs` have harnesses?"*. A consumer asks *"is the constructed-form
rule enforced?"* — a question no module owns, and therefore a question a module-shaped table cannot
have a row for. Three of the most important rows here (`DER-F-8`, `DER-F-9`, `DER-C-OID-2`) exist
**only** on this axis.

Item ids are stable and never reused. Rule references are to X.690 (2021) unless marked RFC 5280.

---

## 4. Self-verify recipes

All commands run from the repository root at `130de97`. `<H>` = a harness path of the form
`<module>::proofs::<fn>`.

| id | recipe | what green means |
|---|---|---|
| **G** | `DER_REQUIRE_LEAN=1 ./check.sh` | Exit 0 + `== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: PASS) ==`. Gates, 485 unit and regression tests, all 203 Kani harnesses. Needs ≥24 GB RAM, ~71 min, harnesses run sequentially. **Set `DER_REQUIRE_LEAN=1`** — without it, an absent Lean toolchain takes a guarded SKIP path and still exits 0. |
| **K** `<H>` | `cargo kani -Z stubbing --manifest-path der-verified/Cargo.toml --harness <H>` | `VERIFICATION:- SUCCESSFUL` for that one harness (note Kani's literal spelling, with the dash). Re-derives the row from source. Six modules are HEAVY (>7 GB peak, up to ~20 GB): `set_of`, `sequence`, `x509_name`, `x509_tbs_certificate`, `x509_certificate`, `x509_extension` — see `gates/tiers.txt`. |
| **R** `<H>` | `awk '/Checking harness <H>/,/^Verification Time/' evidence/check-bffab69.log` | The committed run's own `SUMMARY`, **cover tally**, and `VERIFICATION:- SUCCESSFUL` line for that harness. A bare `grep '<H>'` prints only the `Checking harness …` heading and shows you **neither** — the verdict and cover lines come several lines later. Valid only while the freshness command in §1 returns empty. |
| **N** `<thm>` | `sh lean/check_lean.sh`, then read `<thm>` in `lean/<X>Proofs.lean` | **Require the literal `lean lid: PASS (sorry-free)`.** The lid re-extracts from the shipped `.rs` and fails closed on drift. |
| **T** `<filter>` | `cargo test --manifest-path Cargo.toml <filter>` | `test result: ok`. Point evidence only. |
| **A** `<pattern>` | a grep that **must return nothing**, with its positive control | Used only by `not-covered` rows. A grep-zero is a claim about your pattern, so each A-recipe carries the control input that *would* match. See the warning below. |
| **E** | `sed -n '/^pub enum ProfileError/,/^}/p' der-verified/src/profile.rs \| grep -E '^    [A-Z]'` | **Exactly four variants**, and they are the complete rule surface of the profile layer: `validate_profile` returns `Result<(), ProfileError>`, and the enum's own docstring states that *"every variant names a specific cross-field rule this module enforces"*. The four printed lines — `SignatureAlgorithmMismatch`, `ExtensionsRequireV3`, `NotBeforeGeneralizedTimeYearTooEarly`, `NotAfterGeneralizedTimeYearTooEarly` — map exactly onto `DER-P-1`…`DER-P-4`. Any profile rule **not** on that list is not enforced. |
| **D** `<doc §>` | open the cited section and read the argument | `inspection-argued` rows only. There is nothing to run. |

> ### Why `E` exists, and why absence-greps are the weakest recipe here
>
> A `not-covered` row wants to prove a negative, and the obvious move is a grep that returns nothing.
> That move failed in this very file. Three profile rows (`DER-P-5/6/7`) each promised an
> absence-grep scoped to `der-verified/src/profile.rs`; run today, one of them returns **14 hits**,
> not zero. All 14 are in `profile.rs`'s own `mod tests` — a `basicConstraints` blob used as a
> *generic* extension fixture in the v3-extensions unit tests. The row's conclusion was right (basic-constraints
> validation is genuinely not implemented) but its evidence was not, and a reader who ran the command
> would have had no way to tell which.
>
> **A grep-zero is a claim about your pattern, not about the code.** `E` avoids the class by
> inverting the question: rather than asking whether an absent thing fails to appear, it prints the
> **complete, closed** list of what *is* decided and lets you observe that the row's rule is not on
> it. Positive enumeration beats absence-grepping wherever a closed set exists — a return type, an
> enum, a registry, a manifest. Where no closed set exists, an `A` recipe with its positive control
> is the fallback, and it stays fragile.

**Cover tallies matter, and the gate does not enforce them.** Kani reports a harness whose
`kani::cover` is unsatisfiable as `SUCCESSFUL`, with `0 of 1 cover properties satisfied`. `check.sh`
does **not** fail on that. Exactly 3 harnesses have a cover in that state, and they are disclosed
in §6.3. When recipe **R** shows a `0 of N cover properties satisfied` line, read it. The crate has
186 `kani::cover` statements in total.

---

## 5. The coverage ledger

### 5.1 Framing — identifier, length, TLV (X.690 §8.1, §10.1)

| id | rule | status | strength | verify |
|---|---|---|---|---|
| `DER-F-1` | Identifier octets decode: class, constructed bit, tag number; low- and high-tag forms (§8.1.2) | done | **CONTRACT** (bounded). The tag lid is **not** an L4 row for *this* rule — see note below | `K tag::proofs::decode_tag_accepts_only_canonical` |
| `DER-F-1b` | `decode_tag` terminates on any input and an accepted decode consumes `1..=input.len()` bytes | done | **CONTRACT+L4** | `N tag_decode_total`, `tag_decode_used_bounds` (`lean/TagProofs.lean`, ∀-length) |
| `DER-F-2` | High-tag-number form must be minimal — no leading `0x80` padding (§8.1.2.4.2 c) | done | **CONTRACT** | `K tag::proofs::high_tag_of_small_number_is_non_minimal` · `K tag::proofs::leading_zero_high_tag_is_non_minimal` |
| `DER-F-3` | Tag numbers above the supported width are rejected as `TooLarge`, never misread and never a panic. **Supported range is up to `u32::MAX`** (`tag.rs:9`) — a documented deviation from unlimited DER, safe for X.509 | done | **PROBE** — the harness fixes one overflow encoding and leaves only the first identifier octet symbolic | `K tag::proofs::too_large_tag_is_classified` |
| `DER-F-4` | Length is the **shortest** definite form — short form for <128, no leading zero octets in long form (§10.1) | done | **CONTRACT+L4** | `K length::proofs::decode_accepts_only_canonical` · `K length::proofs::leading_zero_is_non_minimal` · `K length::proofs::long_form_of_short_value_is_non_minimal` · `N decode_accepts_only_canonical` (`lean/LengthProofs.lean`, ∀-length) |
| `DER-F-5` | Indefinite length (`0x80`) and the reserved `0xFF` initial octet are rejected (§8.1.3.6, §10.1) | done | **CONTRACT** | `K length::proofs::indefinite_is_classified` · `K length::proofs::reserved_is_classified` |
| `DER-F-6` | An accepted TLV consumes exactly `header + declared length`, its value is exactly that window, and `used ≤ input.len()` — **no over-read** (§8.1.1) | done | **CONTRACT+L4** | `K tlv::proofs::decode_tlv_structure` · `N decode_tlv_structure` (`lean/TlvProofs.lean`, ∀-length) |
| `DER-F-7` | A top-level DER value is *exactly one* TLV — trailing bytes are rejected (§8.1.1.1) | done | **PROBE** — each harness uses **one fixed valid object plus one symbolic trailing byte**, not a symbolic TLV domain. The Lean lids do not cover the strict variants at all | `K tlv::proofs::strict_rejects_trailing` · `K sequence::proofs::strict_rejects_trailing` · `K set_of::proofs::strict_rejects_trailing` |
| `DER-F-8` | **The constructed form is illegal for primitive-only universal types** (§8.1.2, §10.2) — e.g. `21 00` is not a legal BOOLEAN. Decided across X.680's full assignment range `1..=36`, incl. the high-tag types 31..=36 | done **at the opt-in entry point**; **not-covered at `decode_tlv`** | **CONTRACT** (domain-complete: symbolic `u32` tag number × all 4 classes × both forms — not a bounded buffer). Table-vs-X.680 agreement is **inspection-argued**, see below | `K identifier_form::proofs::constructed_form_rule_matches_oracle_on_all_tags` · `K identifier_form::proofs::rejects_every_disclosed_illegal_identifier` · `K identifier_form::proofs::high_tag_universal_types_are_form_checked` · `K identifier_form::proofs::legal_der_the_comparison_library_rejected_is_still_accepted` |
| `DER-F-9` | **The reserved EOC identifier `00 00` is never a legal DER identifier** — universal 0 is BER's end-of-contents marker (§8.1.5), and DER admits no indefinite-length encoding for it to terminate (§10.1) | done **at the opt-in entry point**; **not-covered at `decode_tlv`** | **CONTRACT** (domain-complete biconditional: rejected iff UNIVERSAL 0, either form) | `K identifier_form::proofs::reserved_eoc_rejected_iff_universal_zero` |

### 5.2 Content codecs — per type

| id | rule | status | strength | verify |
|---|---|---|---|---|
| `DER-C-BOOL` | `TRUE` is encoded as `0xFF` and nothing else; content is exactly one octet (§11.1) | done | **CONTRACT** (exhaustive over the 1-octet domain) | `K boolean::proofs::one_octet_is_canonical` · `K boolean::proofs::wrong_length_is_bad_length` |
| `DER-C-INT-1` | INTEGER content is minimal two's-complement — no redundant `00`/`FF` padding (§8.3) | done | **CONTRACT** | `K integer::proofs::decode_accepts_only_minimal` · `K integer::proofs::redundant_positive_padding_is_non_minimal` · `K integer::proofs::redundant_negative_padding_is_non_minimal` |
| `DER-C-INT-2` | The same minimality rule at **arbitrary magnitude** (big serial numbers), not just `i64` | done | **CONTRACT+L4** | `K big_integer::proofs::validate_iff_minimal_oracle` · `N validate_iff_minimal` (`lean/BigIntProofs.lean`, ∀-length) |
| `DER-C-INT-3` | INTEGER content is never empty (§8.3.1) | done | **CONTRACT** | `K integer::proofs::empty_is_classified` |
| `DER-C-BITS-1` | BIT STRING unused-bits octet is `0..=7` (§11.2.1) | done | **CONTRACT** | `K bit_string::proofs::unused_too_large_is_classified` |
| `DER-C-BITS-2` | Every unused bit is zero (§11.2.2) | done | **CONTRACT** | `K bit_string::proofs::nonzero_padding_is_classified` · `K bit_string::proofs::decode_accepts_only_canonical` |
| `DER-C-BITS-3` | The empty BIT STRING is exactly `[0x00]` (§11.2.2.1) | done | **CONTRACT** | `K bit_string::proofs::empty_is_classified` · `K bit_string::proofs::empty_nonzero_unused_is_classified` |
| `DER-C-BITS-4` | BIT STRING must use the **primitive** form (§10.2) | done at the opt-in entry point; **not-covered** at `decode_bit_string` | inherits `DER-F-8` | inherits `DER-F-8`'s recipes. `decode_bit_string` itself still never sees the identifier; the module docstring used to claim otherwise and **was corrected 2026-08-25** — it now names the typed callers and `identifier_form` |
| `DER-C-BITS-5` | NamedBitList trailing-zero minimality (X.680 §22.7, e.g. `KeyUsage`) | **not-covered** | **out-of-scope** | `D bit_string.rs` module docstring — a property of the ASN.1 *type*, deliberately not applied to a bare BIT STRING |
| `DER-C-OCT-1` | OCTET STRING must use the primitive form; the BER constructed (segmented) form is rejected (§10.2) | done | **CONTRACT** — *at the typed parser, not at the framing layer* | `K octet_string::proofs::constructed_form_is_rejected` · `K octet_string::proofs::accepted_identifier_is_canonical_0x04` |
| `DER-C-OCT-2` | An accepted OCTET STRING's content is exactly the TLV's value window | done | **CONTRACT** | `K octet_string::proofs::accepted_content_is_the_tlv_value` |
| `DER-C-NULL` | NULL content is empty and nothing else (§8.8) | done | **CONTRACT** (exhaustive on its domain) | `K null::proofs::only_empty_is_valid` |
| `DER-C-OID-1` | OID subidentifiers are minimal base-128 — no leading `0x80`, last octet terminates (§8.19) | done | **CONTRACT+L4** | `K oid::proofs::leading_0x80_is_non_minimal` · `K oid::proofs::later_0x80_is_non_minimal` · `K oid::proofs::unterminated_is_truncated` · `N validate_iff_canonical` (`lean/OidProofs.lean`, ∀-length) |
| `DER-C-OID-2` | **Subidentifier width limits and arc materialisation** (`X = min(Z/40,2)`, `Y = Z − 40X`) | **not-covered** | **out-of-scope** | `D oid.rs` docstring, "Scope boundaries (deliberate)": a canonical subidentifier may exceed `u64` and is accepted; *"a downstream arc decoder must enforce its own integer-width limit"*. The crate ships a canonical-form validator, not an arc decoder. |
| `DER-C-ENUM-1` | ENUMERATED **content** follows the INTEGER rules (§8.4) | done | **CONTRACT** (delegation proved over symbolic content; inherits `DER-C-INT-1`) | `K enumerated::proofs::decode_delegates_to_integer` · `K enumerated::proofs::encode_delegates_to_integer` |
| `DER-C-ENUM-2` | ENUMERATED uses identifier UNIVERSAL 10 | done | **test-only** — the tag is a constant checked by a concrete unit test; no harness asserts it | `T enumerated::tests` |
| `DER-C-UTF8` | UTF8String content is well-formed UTF-8; ill-formed input is rejected with its position (§8.23) | done | **CONTRACT** (oracle is `core`'s own `str::from_utf8`) | `K utf8_string::proofs::validate_iff_std` · `K utf8_string::proofs::ill_formed_reports_position` · `K utf8_string::proofs::constructed_form_is_rejected` |
| `DER-C-STR-1` | PrintableString / IA5String / NumericString / VisibleString accept exactly their charset (§8.23, X.680) | done | **CONTRACT** (biconditional against an independent charset oracle, all four types) | `K restricted_string::proofs::validate_iff_all_in_charset_printable` (and `_ia5`, `_numeric`, `_visible`) · `K restricted_string::proofs::charset_exactly_matches_oracle_printable` (×4) |
| `DER-C-STR-2` | Those four types reject the constructed form and require their own tag | done | **CONTRACT** — *at the typed parser*. The label rests on the `accepted_identifier_*` harnesses, which are fully symbolic; the `constructed_form_*` and `wrong_tag_*` harnesses beside them are fixture-shaped and would be PROBE alone | `K restricted_string::proofs::accepted_identifier_is_canonical_printable` (×4 — rules out high-tag forms, wrong class/number **and** the constructed form) · `K restricted_string::proofs::constructed_form_is_rejected_printable` (×4) |
| `DER-C-UTC` | UTCTime is exactly `YYMMDDHHMMSSZ` — 13 octets, mandatory seconds, `Z` terminator, field ranges (§11.8) | done | **CONTRACT** (biconditional against a separate canonical-form oracle) | `K utc_time::proofs::accepted_iff_canonical_oracle` · `K utc_time::proofs::not_zulu_is_classified` · `K utc_time::proofs::full_year_pivot_is_correct` |
| `DER-C-GEN` | GeneralizedTime is `YYYYMMDDHHMMSS[.fff]Z` — mandatory seconds, `Z`, canonical fraction with no trailing zeros (§11.7) | done | **CONTRACT** (biconditional oracle) | `K generalized_time::proofs::accepted_iff_canonical_oracle` · `K generalized_time::proofs::fraction_trailing_zero_is_classified` · `K generalized_time::proofs::bad_fraction_separator_is_classified` |
| `DER-C-SEQ-1` | A SEQUENCE's children tile its content exactly — the walk consumes precisely the content bytes (§8.9) | done | **CONTRACT+L4** (the only lid unbounded in **child count** as well as byte length) | `K sequence::proofs::ok_implies_exact_tiling` · `N decode_sequence_structure` (`lean/SequenceProofs.lean`) |
| `DER-C-SEQ-2` | The shipped SEQUENCE walk never over-reads, and each step advances by exactly the child's own encoded length | done | **CONTRACT** (real-path, independent oracle — rewritten 2026-08-24, see §6.2) | `K sequence::proofs::no_over_read` · `R sequence::proofs::no_over_read` (check its two cover lines are satisfied) |
| `DER-C-SEQ-3` | SEQUENCE is constructed and carries identifier `0x30` | done | **CONTRACT** | `K sequence::proofs::tag_correctness` · `K sequence::proofs::accepted_identifier_is_canonical_0x30` |
| `DER-C-SETOF-1` | SET OF members appear in ascending order of their **encodings** (§11.6) | **partial** | **PROBE** — a biconditional, but only over **two fixed-shape 3-octet children** with symbolic content; the comparator lemma is limited to slices of ≤3 bytes. Not established for arbitrary member encodings or counts | `K set_of::proofs::ordering_iff_oracle` · `K set_of::proofs::cmp_padded_matches_oracle` · `K set_of::proofs::unsorted_children_are_rejected` |
| `DER-C-SETOF-2` | Equal adjacent member encodings are accepted (SET **OF**, not SET) | done | **PROBE** — a wholly concrete 6-byte fixture | `K set_of::proofs::duplicate_adjacent_encodings_are_accepted` |
| `DER-C-SETOF-3` | The shipped SET OF walk never over-reads | **partial** | **PROBE** — bounded no-out-of-bounds-access plus an extensional postcondition; see §6.4 | `K set_of::proofs::no_over_read`. **Does not** show the shipped loop used the same per-child boundaries as the oracle, nor that its cursor never over-advances past the final read |
| `DER-C-SET` | General `SET` (§10.3) — DER ordering of a heterogeneous SET | **not-covered** | **out-of-scope** | `D DECISIONS.md` D13; README scope section. Not implemented, not claimed. |
| `DER-C-CTX` | `[n] EXPLICIT` context tagging (§8.14) | done | **PROBE** (panic-freedom only) | `K context_tag::proofs::decode_explicit_context_never_panics` |
| `DER-C-CTX-IMP` | `[n] IMPLICIT` context tagging | **not-covered** | **out-of-scope** | `D PROOF_MANIFEST.md` §6.2 — *"only the explicit-context form is addressed"*. Consequence: X.509's deprecated `[1]`/`[2]` unique identifiers are **rejected**, not parsed (`DER-X-TBS-2`) |

### 5.3 X.509 / PKCS structural surface

**Read this block before trusting any row in it.** Every module here is proved **panic-free**, not
**conformant**: the harnesses are `*_never_panics`. Panic-freedom is a real and valuable safety
property — this is the layer a malformed certificate attacks — but it does **not** decide whether the
parser accepts exactly the RFC 5280 structures. On the rule axis, that makes these rows `partial`.

| id | structure (RFC 5280 unless noted) | status | strength | verify |
|---|---|---|---|---|
| `DER-X-ALGID` | `AlgorithmIdentifier` §4.1.1.2 — framing | partial | **PROBE** (panic-freedom; Ok-tail covers satisfied) | `K x509_algorithm_identifier::proofs::parse_algorithm_identifier_never_panics` · `R` (3 covers, all satisfied) |
| `DER-X-SPKI` | `SubjectPublicKeyInfo` §4.1.2.7 — framing | partial | **PROBE** (panic-freedom; Ok-tail cover satisfied) | `K x509_spki::proofs::parse_never_panics` |
| `DER-X-NAME` | `Name` / `RDNSequence` §4.1.2.4 — framing | partial | **PROBE**, and see §6.3 | `K x509_name::proofs::validate_never_panics` (stubs `validate_rdn`) · `K x509_name::proofs::validate_rdn_never_panics` (**no cover at all**) |
| `DER-X-VALID` | `Validity` §4.1.2.5 — framing | partial | **PROBE**, **cover UNSATISFIED** — see §6.3 | `R x509_validity::proofs::parse_never_panics` (`0 of 1 cover`) · `K x509_validity::proofs::parse_validity_ok_path_witnessed` (companion witness, no stubs) |
| `DER-X-EXT-1` | `Extension` / `Extensions` §4.1.2.9 — framing | partial | **PROBE**, **cover UNSATISFIED** — see §6.3 | `R x509_extension::proofs::validate_extensions_never_panics` (`0 of 1 cover`) · `K x509_extension::proofs::validate_extensions_ok_path_witnessed` |
| `DER-X-EXT-2` | DER `DEFAULT` omission: a `critical` field encoding `FALSE` must be absent (§11.5) | done | **test-only** — one concrete unit test. `parse_extension_never_panics` calls the parser and covers `Ok`; it never asserts this rule | `T x509_extension::tests::rejects_critical_present_but_false` |
| `DER-X-EXT-3` | **Extension *contents* (basicConstraints, keyUsage, SAN, …)** | **not-covered** | **not-covered** | `D PROOF_MANIFEST.md` §6.2 — *"extension contents are never interpreted, and `critical` is peeked, not acted on."* `extnValue` is an opaque OCTET STRING. |
| `DER-X-TBS-1` | `TBSCertificate` §4.1 — the full field skeleton (version, serial, signature, issuer, validity, subject, SPKI, extensions) | partial | **PROBE**, **cover UNSATISFIED**, **stub-mediated** — see §6.3 | `R x509_tbs_certificate::proofs::parse_tbs_certificate_never_panics` (`0 of 1 cover`, 2 stubs) · `K x509_tbs_certificate::proofs::parse_tbs_certificate_ok_path_witnessed` (**3 stubs** — glue reachability only) |
| `DER-X-TBS-2` | DER `DEFAULT` omission for `version`: a present `[0]` encoding v1 is rejected (§11.5) | done | **test-only** — one concrete unit test; no harness asserts it | `T x509_tbs_certificate::tests` — `TbsCertificateError::VersionMustBeOmitted` |
| `DER-X-CERT` | `Certificate` §4.1 — outermost composition | partial | **PROBE** (panic-freedom, 1 stub, Ok-tail cover **satisfied**) — but see `DER-X-BOUND` | `K x509_certificate::proofs::parse_certificate_never_panics` |
| `DER-X-BOUND` | **Panic-freedom at realistic input sizes** | **partial** | **inspection-argued** · ⚠ **UNWEIGHTED** | `D PROOF_MANIFEST.md` §8.1 — `x509_certificate` panic-freedom is proved at **≤12 bytes**; a real certificate is ~170 bytes. `rsa_private_key` at **≤20 bytes** vs ~317. Real-size panic-freedom *"rests on an un-machine-checked compositional argument"*. |
| `DER-K-PKCS8` | PKCS#8 `PrivateKeyInfo` (RFC 5208 §5) | partial | **PROBE** (panic-freedom + strict variant + an Ok-path witness) | `K pkcs8::proofs::parse_never_panics` · `K pkcs8::proofs::parse_ok_path_witnessed` |
| `DER-K-EPKI` | `EncryptedPrivateKeyInfo` (RFC 5958 §3) | partial | **PROBE** | `K encrypted_private_key_info::proofs::parse_never_panics` |
| `DER-K-RSAPUB` | `RSAPublicKey` (RFC 8017 §A.1.1) | partial | **PROBE** | `K rsa_public_key::proofs::parse_strict_never_panics` |
| `DER-K-RSAPRIV` | `RSAPrivateKey` (RFC 8017 §A.1.2) | partial | **PROBE**, and see `DER-X-BOUND` | `K rsa_private_key::proofs::parse_never_panics` (4 stub applications across its harnesses) |
| `DER-K-ECPRIV` | `ECPrivateKey` (RFC 5915 §3) | partial | **PROBE** | `K ec_private_key::proofs::parse_never_panics` |
| `DER-K-ECDSASIG` | `ECDSA-Sig-Value` (RFC 3279 §2.2.3) | partial | **PROBE** | `K ecdsa_sig_value::proofs::parse_strict_never_panics` |
| `DER-X-L4` | An unbounded (Lean) lid over **any** X.509 structural module | **not-covered** | **not-covered** | `D gates/map_declared.txt` row `x509_structural_lid` → `DER-REMAINING-WORK.md` §3. All seven `x509_*` modules are Kani-only. |

### 5.4 RFC 5280 profile rules

The `profile` module is the crate's only *semantic* layer, and — unusually for this crate — its rules
are proved as **biconditionals**, which is stronger than the structural layer beneath it.

| id | rule | status | strength | verify |
|---|---|---|---|---|
| `DER-P-1` | The inner `signature` and outer `signatureAlgorithm` must be identical (§4.1.1.2) | **partial** | **PROBE** — a biconditional, but **monomorphic in slice length**: the OIDs are always 2 bytes and the parameters 1 byte. Since this rule is *about* the algorithm identifiers, that bound is on the rule itself, not incidental | `K profile::proofs::rule1_mismatch_iff_algorithms_differ` |
| `DER-P-2` | Extensions may appear only in a v3 certificate (§4.1.2.1, §4.1.2.9) | done | **CONTRACT** — biconditional over the rule's **full** domain: symbolic `version: u8` (all 256 values, not just 0/1/2) and symbolic extensions-present | `K profile::proofs::rule2_requires_v3_iff_extensions_present_and_not_v3` |
| `DER-P-3` | Dates through 2049 use UTCTime; 2050 onward use GeneralizedTime (§4.1.2.5) | done | **CONTRACT** (biconditional, plus a proof that UTCTime *cannot* denote ≥2050) | `K profile::proofs::rule3_generalized_too_early_iff_year_le_2049` · `K profile::proofs::utc_time_can_never_denote_2050_or_later` |
| `DER-P-4` | Error precedence follows declaration order (determinism of the reported violation) | done | **CONTRACT** | `K profile::proofs::error_precedence_follows_declaration_order` |
| `DER-P-5` | Basic constraints (§4.2.1.9) | **not-covered** | **not-covered** | `E` (see below) — `BasicConstraints` is not among the four variants. `gates/map_declared.txt` row `basic_constraints`. **The absence-grep this row used to name was unsound; see the warning in §4.** |
| `DER-P-6` | Key usage (§4.2.1.3) | **not-covered** | **not-covered** | `E` — no key-usage variant. `gates/map_declared.txt` row `key_usage`. |
| `DER-P-7` | Name constraints (§4.2.1.10) | **not-covered** | **not-covered** | `E` — no name-constraints variant. `gates/map_declared.txt` row `name_constraints`. |
| `DER-P-8` | Validity against a clock (§4.1.2.5) | **not-covered** | **not-covered** | `gates/map_declared.txt` row `validity_against_clock`. The crate is heap-free and clock-free by design. |
| `DER-P-9` | Certificate-path / trust validation; signature and crypto verification | **not-covered** | **out-of-scope** | `D README.md` scope section — *"Out of scope (not implemented, not proven)"*. `gates/map_declared.txt` rows `path_validation`, `crypto_verification`. |
| `DER-P-10` | String canonicalisation / name-comparison rules; OID semantics | **not-covered** | **out-of-scope** | `D PROOF_MANIFEST.md` §6.2 |

### 5.5 Crate-wide safety and hygiene

| id | claim | status | strength | verify |
|---|---|---|---|---|
| `DER-S-1` | No `unsafe` anywhere | done | **mechanical** (compiler-enforced) | `grep -rn '#!\[forbid(unsafe_code)\]' der-verified/src/lib.rs`; the manifest's inventory derives `0` unsafe blocks |
| `DER-S-2` | No panic on malformed input, at the declared bounds, for every harnessed entry point | done | **PROBE** by this file's own §2 definition — panic-freedom is a safety property, not an encoding rule, and it is bounded. Genuinely valuable; simply not a conformance claim. See `DER-X-BOUND` | `G`, or `R` per harness |
| `DER-S-3` | Every public entry point is named by a harness | **partial** | **mechanical** | 84 public entry points; **73 harnessed, 11 not**. The 11 (`PROOF_MANIFEST.md` §4.1): `generalized_time::require_no_fraction`, `utf8_string::decode_utf8_str`, and nine in `restricted_string` — **eight per-type wrappers** over a harnessed generic core (`decode_`/`encode_..._into` for printable/ia5/numeric/visible) **plus `Charset::tag_number`**, which is not a wrapper. Re-derive with `python3 gates/gen_proof_manifest.py --json`. |
| `DER-S-4` | The documentation's counts match the source | done | **mechanical** | `python3 gates/gen_proof_manifest.py --check` and `python3 gates/gen_verification_map.py --check` — each gate has its own self-test, run first, in `check.sh` |
| `DER-S-5a` | The Lean lids contain no `sorry` | done | **mechanical** | `N` — `check_lean.sh` fails closed on `sorryAx` or a `declaration uses 'sorry'` warning, and was negative-tested by injecting one |
| `DER-S-5b` | The lids assume no axiom about this crate's own code (13 declared axioms, all specs for upstream `core` primitives) | done | **inspection-argued** · ⚠ **UNWEIGHTED** | `D evidence/AXIOM-AUDIT-2026-08-18.md`. Nothing *mechanically* keeps a crate-code assumption out of a future lid — this property is reviewed, not gated, so the format declines to vouch for it |

---

---

## 6. The five things a consumer must not miss

### 6.1 Framing acceptance is **not** DER validity (`DER-F-8`, `DER-F-9`)

`tlv::decode_tlv` returning `Ok` means *"these bytes are a well-formed TLV"*, **not** *"these bytes
are valid DER"*. Two X.690 rules were, until 2026-08-25, enforced in **no verified layer of this
crate**, and are still enforced in none of the *framing* layers:

- constructed encodings of primitive-only universal types were accepted — repro `21 00` (BOOLEAN),
  `26 01 39` (OBJECT IDENTIFIER), `2C 01 01` (UTF8String), `33 01 00` (PrintableString);
- the reserved end-of-contents identifier `00 00` was accepted.

This was found by **differential fuzzing against an independent implementation** and is disclosed at
[`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) §6.3. Nothing in the manifest was falsified by it — it was a
scope gap, not a bug.

**Both rules are now decided — but not where you are about to assume.** A module, `identifier_form`
([`DECISIONS.md`](DECISIONS.md) D34), decides them. `tlv::decode_tlv`, `tlv::decode_tlv_strict`,
`tag::decode_tag` and `sequence`'s child walk are **unchanged** and still accept every input above,
deliberately: a permissive framing reader is load-bearing for recursive parsing. So the rules are
enforced for callers who opt in to `identifier_form::decode_tlv_form_checked` /
`decode_tlv_form_checked_strict`, and for nobody else. Whether to wire the check into
`decode_tlv_strict` is open ([`DER-REMAINING-WORK.md`](DER-REMAINING-WORK.md) R3), as is recursion
into the children of a constructed TLV (R4) — the module decides one identifier, not a tree.

**`decode_tlv_form_checked` is not a DER validator, and it was renamed to stop implying it was.** It
decides framing plus one identifier's *form*; it never reads content octets, so it accepts
`01 01 01` (BOOLEAN `true` must be `0xFF`), `02 02 00 01` (non-minimal INTEGER) and `05 01 00` (NULL
must be empty). Content canonicality stays with the per-type codecs. The first version of this work
shipped as `decode_tlv_der` with documentation saying "the bytes must be valid DER"; review caught it
before publication, and the three counterexamples are now pinned by a harness and a test.

*Self-verify (recipe A).* There is no negative harness to run, so verify the absence — and note that
a bare `grep constructed` on `tag.rs`/`tlv.rs` returns **many** matches (the parsed `constructed`
field itself), so it verifies nothing. Grep for a *rejection decision* instead:

```sh
grep -n 'Constructed' der-verified/src/tag.rs der-verified/src/tlv.rs      # → empty
grep -n 'Constructed' der-verified/src/octet_string.rs                     # positive control → hits
grep -n 'MustBePrimitive' der-verified/src/identifier_form.rs              # → hits (where it IS decided)
```

The framing modules have no `Constructed` error variant at all; `octet_string.rs` defines one and
acts on it. That contrast *is* the residual, and the first grep still returning empty is the point:
the rule now lives in `identifier_form`, and the framing layer still does not decide it.

**Two labelling cautions.** First, the four domain-complete theorems compare the shipped `match`
against a bitmask oracle **written by the same author**: they establish that the two encodings of the
table agree on all 2^32 tag numbers — exactly what a transcription slip would violate — and **not**
that the table agrees with X.680, which stays inspection-argued per-arm and spot-checked by concrete
tests. Second, the two *composition* harnesses are stated relative to the rule and survived every
mutation that broke it; they witness the composition, not the rule's content.

**The harnesses behind these rows are mutation-controlled, and the controls documented a real miss.**
`evidence/MUTATION-CONTROLS-2026-08-25-identifier-form.md` records two rounds. Round 2 was
**preregistered** — predictions hashed and locked before the runs — and every prediction matched
*harness-for-harness*, not merely in count. The load-bearing one is **M6**: reverting the `31..=36`
arm (the high-tag universal types DATE, TIME-OF-DAY, DATE-TIME, DURATION, OID-IRI, RELATIVE-OID-IRI)
turned four harnesses red, but the specimen harness `rejects_every_disclosed_illegal_identifier`
**survived** — every specimen it pins has a tag number ≤ 30, so no fixture harness in the pre-review
set could reach the high-tag form. That is exactly why a constructed DATE (`3F 1F 00`) was accepted
by the first version of the module, and exactly why `high_tag_universal_types_are_form_checked` had
to be added. M6 is the evidence that the added harness is not decorative. A separate mutation, M5,
covers the direction the others cannot — corrupting the *oracle* while leaving the implementation
untouched — and is caught only by `oracle_is_well_formed`, whose own limit is stated there: it checks
the masks' *shape*, never their *content*.

### 6.2 `sequence::no_over_read` was proving a **copy** until 2026-08-24 (`DER-C-SEQ-2`)

Until commit `0e327b7`, both `no_over_read` harnesses ran a *duplicated* `decode_tlv` walk and never
entered the shipped code — a textbook "proving a copy". A structural review caught it; the fix drives
the shipped `Elements` iterator and computes the expectation from a **separate** one-step decode at
an offset the harness carries itself. A first draft of the fix derived that offset from the
iterator's own cursor, which is self-referential and would have let a mis-advance survive; that draft
was caught in review too. Rationale: [`DECISIONS.md`](DECISIONS.md) D33.

**Why this matters to a consumer:** none of this crate's gates would have caught it. The manifest
gate counts harnesses, bounds, stubs and covers — and none of those numbers move when a harness
verifies a copy of the shipped walk. **A green gate is not a claim that the harnesses point at
shipped code.**

### 6.3 Three harnesses cannot witness their own happy path

Three harnesses report `0 of 1 cover properties satisfied`, and `check.sh` does **not** fail on that:

| harness | buffer | why unsatisfiable | companion witness | witness uses stubs? |
|---|---|---|---|---|
| `x509_validity::parse_never_panics` | `[u8; 16]` | a minimal `Validity` needs ~32 octets | `parse_validity_ok_path_witnessed` | no |
| `x509_extension::validate_extensions_never_panics` | `[u8; 13]` | two minimal `Extension`s need 16 | `validate_extensions_ok_path_witnessed` | no |
| `x509_tbs_certificate::parse_tbs_certificate_never_panics` | `[u8; 10]` | a minimal TBS body is far larger | `parse_tbs_certificate_ok_path_witnessed` | **yes — glue reachability only** |

The cause is arithmetic, not a cover-authoring error: the buffer is too small for a well-formed
object to exist inside it. So each of those three panic-freedom proofs ranges over an input space in
which **every input is rejected early**. They are honest proofs of "no panic on garbage"; they are
not evidence that the accept path is safe. The companion witnesses supply reachability at concrete
fixtures — and the `x509_tbs_certificate` one does so with three stubs, so it witnesses the glue, not
the parser. Separately, `x509_name::validate_rdn_never_panics` has **no cover at all**, and its
sibling stubs `validate_rdn`, so nothing witnesses the RDN parser's own accept path.

[`DER-REMAINING-WORK.md`](DER-REMAINING-WORK.md) R2 records a further open residual: seven structural
harnesses were widened to symbolic input length in 2026-08-23; only the two rewritten by D33 got
covers. **The other five have none, so nothing witnesses that their widened loops iterate at all.** A
review asked for those covers before publish; the maintainer disclosed rather than fixed, and
recorded it as a judgement call. The covers are owed.

### 6.4 `set_of::no_over_read` is deliberately weaker than its sibling (`DER-C-SETOF-3`)

The asymmetry is in the *shipped code*, not in effort spent, and the crate states it in the
docstring, in [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) §8.3, and in
[`DER-REMAINING-WORK.md`](DER-REMAINING-WORK.md) R1:

| | drives | gets |
|---|---|---|
| `sequence::no_over_read` | `Elements` — the cursor is an observable field | per-child: the shipped advance is pinned to an independent oracle |
| `set_of::no_over_read` | `decode_set_of` — the cursor is a local, the output is a count | bounded no-out-of-bounds-access **+ an extensional `Ok(k)` tiling postcondition** |

`set_of` does **not** show that the shipped loop used the same per-child boundaries as the oracle's
re-walk, and a terminal over-advance past the final read would neither panic nor change `k`. The fix
requires refactoring shipped code onto `sequence::Elements` — a behavioural change, deliberately not
bundled into a proof-integrity fix.

### 6.5 Bounds versus reality (`DER-X-BOUND`)

The outermost parsers are proved panic-free on buffers **an order of magnitude smaller than a real
input**: `x509_certificate` at ≤12 bytes against a ~170-byte certificate, `rsa_private_key` at ≤20
bytes against a ~317-byte key. Real-size panic-freedom rests on a compositional argument that is
written down and reviewed but **not machine-checked**. This is the single largest gap between what
"203/203 verified" sounds like and what it is.

### 6.6 The strongest and weakest layers are inverted relative to your risk

The framing and codec layers carry the `CONTRACT` and `CONTRACT+L4` rows. The X.509 layer — the part
you actually feed a hostile certificate to — has **no conformance `CONTRACT` row at all**: it is
panic-freedom probes, two concrete rule tests, an inspection argument for realistic sizes, and
uncovered semantics, with three unsatisfied covers and the smallest bounds in the crate.

That is not a defect; it is the honest cost curve — those are the 7–20 GB harnesses, and the crate
says so. It is invisible in "203 of 203", and visible in one glance here.

---

## 7. What "certified at `130de97`" means

The word is only worth something if it names a procedure, so here is the one that ran. It is
deliberately mechanical, because the point is that someone who does not trust the author can re-run
it.

1. **Freshness.** `git diff bffab69..HEAD -- der-verified/src lean` → empty. The commits between the
   receipt and HEAD touch only [`CHANGELOG.md`](CHANGELOG.md),
   [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) and the evidence logs, so the `bffab69` run speaks for
   `130de97`.
2. **Counts re-derived, never re-typed.** Every number in §1 came from
   `python3 gates/gen_proof_manifest.py --json` at HEAD.
3. **Every `K` recipe re-checked, mechanically.** All 82 distinct harness paths named in the `verify`
   column were extracted from this file and checked twice: that the function still exists in the
   module it names at HEAD, and that a `Checking harness <H>...` line for it appears in
   `evidence/check-bffab69.log`. **82 of 82 passed both.** The run those lines belong to closed
   `Complete - 203 successfully verified harnesses, 0 failures, 203 total`, so no cited harness is
   stale, renamed, or unrun.
4. **Every `A` recipe actually executed**, with its positive control. This is the step that found the
   broken profile absence-grep described in §4, and the step that re-*reading* rather than
   re-*running* would have skipped for a second time.
5. **`N`, `T`, `R` recipes spot-checked at HEAD.** The cited Lean theorems were located in the files
   named; the `test-only` rows' tests were located by name; the `R` rows' cover tallies were re-read
   out of the run log — the three disclosed-unsatisfiable covers are still exactly `x509_validity`,
   `x509_extension` and `x509_tbs_certificate` and no others, and `sequence::no_over_read` still
   reports `2 of 2 cover properties satisfied`.

**What this procedure does NOT establish**, stated because a list of green steps invites the opposite
reading: nothing above grades any harness's *oracle*. A harness that verifies the wrong property
appears in the run log exactly like one that verifies the right property, and step 3 would pass on
both. Oracle quality is what the `strength` column asserts, and that column is **reviewed, not
gated**. The run log makes the same disclaimer about itself in its header — and both defects fixed at
`bffab69` were found by review, with every gate green across both.

---

## 8. Provenance and known weaknesses of this file

**Hand-built.** Nothing in this file is generated, which means it can be wrong in ways
[`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) cannot. Three mitigations:

1. **Every row carries a runnable recipe.** A hand-asserted row that names a command is falsifiable
   by you in one step. That is a different risk profile from a hand-asserted row that names only a
   conclusion.
2. **The crate-total counts in this file are gate-enforced.** `COVERAGE.md` is registered in
   `gates/gen_proof_manifest.py`'s `GUARDED_DOCS`, so a stale harness, test, doctest, cover or lid
   count here fails `./check_fast.sh` like a stale count anywhere else in the crate's documentation.
   The *judgement* fields are not gated and cannot be.
3. **Judgement fields are marked as judgement.** Every `strength` cell, and all of §6, is the
   author's assessment, and is wrong if the recipe beside it says otherwise. Where this file and a
   recipe disagree, the recipe wins.

**Known weakness, stated plainly.** The `strength` column is the part most likely to be wrong, and it
is the part no gate can check. The first draft of this ledger overclaimed seven rows — labelling
fixture-shaped or monomorphic evidence as `CONTRACT` — and a review caught them. That a hand-built
coverage table's first draft overclaimed seven rows is itself worth knowing: the labels are what need
review, and the recipes are what make review cheap enough to be worth running.

**Related documents.** [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) — what is machine-checked, per module,
with bounds and stubs. [`ASSUMPTIONS.md`](ASSUMPTIONS.md) — the trusted base everything here stands
on. [`DER-REMAINING-WORK.md`](DER-REMAINING-WORK.md) — open residuals, including the ones cited above.
[`DECISIONS.md`](DECISIONS.md) — why scope boundaries are where they are. [`SECURITY.md`](SECURITY.md)
— reporting scope.
