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

**Certified at `d68eeca`** (the integration head: the commit on which the proof run executed, with a clean tree. The evidence and documents of this directory are added in later commits that change none of the build inputs of the proof run (§1 names them), and the freshness command in §1 says how to check that). §7 states exactly what that word covers, as a procedure you can re-run.

---

## 1. Subject identity — what exactly is being certified

| | |
|---|---|
| subject | crate `der-verified` 0.2.0, sources at `der-verified/src/` |
| commit | `d68eeca` (the commit the proof run executed on; the evidence and documents of this directory were added on top of it) |
| tree state | clean at the certified commit; the run log records `git status --porcelain` sampled clean **at launch** (`dirty-tracked-paths-at-launch: 0`), not assumed. This run samples at launch only — earlier runs also sampled at completion; this one does not, and the header says so rather than implying a completion sample it did not take. |
| spec axis | **X.690 (2021) DER encoding rules**, per type + framing; **RFC 5280** profile surface. See §3. |
| gate receipt | `check.sh(split)` exit 0 at `d68eeca` — the main half ran a temporary split copy of `check.sh` (its Kani line restricted to 295 harnesses; `check.sh` itself unchanged), **not a literal `./check.sh` run**. Its summary line reads `== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: PASS) ==`, where `L3 kani floor: GREEN` refers to the 295-harness stage only. Run with `DER_REQUIRE_LEAN=1`. The 3 heavy harnesses ran separately; see the proof-floor row |
| proof floor (L3) | **298/298 SUCCESSFUL, 0 FAILED at `d68eeca` — SPLIT: 295 in one capped (20G) `check.sh` pass incl. the Lean lid + 3 heavy harnesses in separate 24G runs.** Evidence: `evidence/check-d68eeca.log` (the 295-harness main half; its own trailer reads `Complete - 295 successfully verified harnesses, 0 failures, 295 total.`) and the three companion logs `evidence/check-d68eeca-heavy-x509_extension-validate_extensions_never_panics.log`, `evidence/check-d68eeca-heavy-x509_extension-validate_extensions_ok_path_witnessed.log` and `evidence/check-d68eeca-heavy-x509_name-validate_rdn_never_panics.log` (each ends `Complete - 1 successfully verified harnesses, 0 failures, 1 total.`). **There is no single-run 298-harness floor at this commit**: the `L3 kani floor: GREEN` in `check.sh`'s summary line refers to the 295-harness restricted stage only. The previous floor was the split 297/297 at `42c8165` (`evidence/check-42c8165.log` and its companions; superseded, because the verified source changed after it), and the previous single-run floor was 210/210 at `d05d3f2` (`evidence/check-d05d3f2.log`) |
| unbounded lids (L4) | 6 lids in Lean, `lean lid: PASS (sorry-free)`, re-extracted from the shipped `.rs`; `lid-source-state.txt unchanged (hashes identical)` |
| tests | 539 unit and regression tests + 34 doc-tests (no integration-test directory exists) |
| unsafe | 0 `unsafe` blocks; the crate is `#![forbid(unsafe_code)]` |
| toolchain | Kani `0.67.0`, CBMC `6.8.0` (kani-bundled, read from the run's own output), CaDiCaL 2.0.0, rustc `1.97.0`, Lean 4 `v4.30.0-rc2` |
| cost | Main half (295 harnesses plus the Lean lid): 2h31m55s wall (10:49:16Z → 13:21:11Z), peak 17G (systemd service memory peak read from the journal, 20G cap), harnesses run sequentially (no `-j`). Each of the 3 heavy harnesses ran alone under a 24G cap: `validate_extensions_never_panics` 8m07s wall, peak 20.1G; `validate_extensions_ok_path_witnessed` 3m16s wall, peak 16.5G; `validate_rdn_never_panics` 14m48s wall, peak 17.3G (peaks as systemd service memory peaks read from the journal; the wall times are the journal's unit run times, run back to back in the window 2026-10-10 14:08Z-14:36Z). The ≥24 GiB RAM floor in the `G` recipe (§4) still bounds a full run. |
| freshness | **A sufficient condition, not an iff.** The split floor's evidence (the main log and its 3 companion logs, read together) still applies to HEAD if `git diff d68eeca -- check.sh der-verified/src der-verified/Cargo.toml Cargo.toml Cargo.lock rust-toolchain.toml .cargo der-verified/build.rs lean` is empty and the toolchain pins in `PROOF_MANIFEST.md` §2 are unchanged. The L3 build inputs are the list without `lean`; `lean/` is added for the L4 lid. `d68eeca` is the anchor because it is the commit the run was captured on. A non-empty diff or a moved pin means re-run; it does not by itself show the evidence is wrong. **Run that command; do not trust this sentence.** |
| acceptance-record timestamps | `produced_at` in an acceptance record is the time the record was produced (imported into the evidence store), not the time the verifier ran. When a run executed, and at which commit, is stated in the header and the start/end lines of its own evidence log. |

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

**Every claim on the declared spec axis is admitted to this table, including the ones no machine decides.**
A claim left out of a coverage table is a claim the reader has to infer from silence, which is the
failure this file exists to prevent. But admission is not endorsement. Rows fall into two tiers, and
the tier is visible beside the `strength` column.

**Weight is not a rank of the strength label, and this block used to read as if it were.** Until
2026-08-27 it listed "Weighted — `CONTRACT+L4`, `CONTRACT`, `mechanical`" against "Admitted —
`PROBE`, `test-only`, `inspection-argued`, `not-covered`, `derived`" — i.e. weight presented as the
top rungs of the strength ladder. That is wrong: **weight is orthogonal to strength, not a grade
above it.** Strength answers *"how good is the evidence, if it decides anything?"*. Weight answers a
narrower and different question: *"does a deciding recipe actually exist for this specific row — a
command whose failure would falsify it?"* A row can carry a strong label and still lack that recipe,
and a weak label does not, in principle, bar a row from having one (a `PROBE` can be an honest,
well-controlled proof of something narrower than the row's item — that narrowness is exactly why it
is a probe, not a defect in its recipe). This crate's rows do not currently exercise that
combination, which is a fact about today's rows, not a rule about the tiers.

- **Weighted** — a *deciding* recipe exists: a command whose failure would falsify the row. Every row
  that meets that bar today happens to carry `CONTRACT+L4`, `CONTRACT`, or `mechanical` — `DER-F-4`,
  `DER-C-INT-2` and `DER-P-2` are weighted rows — but that correlation describes which rows have a
  recipe today, not a definition of the tier by label.
- **Admitted** — `PROBE`, `test-only`, `inspection-argued`, `not-covered`, `derived`. These are
  carried at the evidentiary level they actually have, which is usually *"a human asserted it and a
  reviewer checked the assertion"*, or — for `inspection-argued` specifically — a label for which no
  deciding recipe can exist by definition. `DER-X-BOUND` and `DER-C-OID-2` are admitted rows.

**The split cannot be crossed by writing better prose.** A row becomes weighted when a deciding
recipe is attached to it, and not before.

**Of the 75 rows below, 36 are weighted and 39 are admitted**, with one (`DER-C-STR-2`) resting on
symbolic harnesses while naming the fixture-shaped ones beside it that would be a probe alone.

**One row, one claim.** Where a single item genuinely carried two strengths, it is **split into two
rows** rather than given a two-grade cell. There are two such splits, and both are load-bearing:

- `DER-F-8` (the shipped rule agrees with the crate's own primitive-only table — **contract**, over
  a complete input domain) and `DER-F-8b` (that table is a faithful transcription of X.680 —
  **inspection-argued, unweighted**). The machine decides the first. Nothing decides the second, and
  a shared misreading of the standard would pass every harness behind the first.
- `DER-S-5a` (the lids contain no `sorry` — **mechanical**, negative-tested by injecting one) and
  `DER-S-5b` (the lids assume no axiom about this crate's own code — **inspection-argued**).

A cell reading *"proved; and also argued"* lets a reader take whichever half they prefer, which is
precisely the failure this format exists to prevent. **The `DER-F-8` split was not in this file's
first draft** — the row carried both grades at once until a checker refused it.

**That more than half the rows are admitted is this table working, not failing.** The crate's own
headline is "210 of 210 harnesses SUCCESSFUL". That is true, and it invites the reading that every
*rule* is decided. Compare `DER-F-4` (weighted: a Lean lid over all input lengths) with
`DER-X-BOUND` (admitted: a compositional argument nobody has machine-checked). Both sit under the
same green check. This table's job is to stop them reading alike.

### The strength labels

| label | means |
|---|---|
| **CONTRACT+L4** | the rule is proved of the **shipped** function over **unbounded** input, kernel-checked in Lean via the Aeneas lid, *and* also proved bounded by Kani. The strongest thing this crate has. |
| **CONTRACT** | **the row's stated item** is asserted as a property of the **shipped** function over a **symbolic** (bounded) input domain. Where the item is a semantic equivalence, the oracle must be **independent of the state under test**; where the item is a direct safety property (e.g. panic-freedom), the assertion decides it directly and no separate oracle applies. Bounded: it holds up to the declared buffer/unwind, and says nothing beyond it. |
| **PROBE** | bounded, monomorphic, or fixture-shaped evidence — **or** evidence offered for an item it does not decide, the commonest case being a panic-freedom harness cited for a *conformance* item. A probe never counts as the row's item being verified. |
| **test-only** | `#[test]` / doc-test at named concrete inputs. Witnesses points, not sets. |
| **inspection-argued** | a documented human argument with no mechanical oracle. Weakest admissible evidence. |
| **not-covered** | no layer of this crate decides this rule, though it is in scope. The row exists so you do not have to infer it from silence. |
| **out-of-scope** | the rule is deliberately outside what this crate sets out to do, and that boundary is declared in the crate's own documents. Not a gap; a fence. |

> **`CONTRACT` here is NOT Kani's `#[kani::requires]`/`#[kani::ensures]` machinery.** This crate uses
> **zero** function contracts — its 298 Kani harnesses are all plain `#[kani::proof]`, and modular proofs are
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

All commands run from the repository root at `d68eeca` (or at any later commit for which the freshness command in §1 is empty). `<H>` = a harness path of the form
`<module>::proofs::<fn>`.

| id | recipe | what green means |
|---|---|---|
| **G** | `DER_REQUIRE_LEAN=1 ./check.sh` | Exit 0 + `== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: PASS) ==`. Gates, 539 unit and regression tests, all 298 Kani harnesses. **This exact command was not run as one pass at `d68eeca`: the floor there is SPLIT** — a 295-harness pass with the Lean lid (~2h32m at the 20G cap) plus 3 heavy harnesses in separate 24G runs, and there is no single-run 298-harness floor. Needs ≥24 GB RAM; harnesses run sequentially. **Set `DER_REQUIRE_LEAN=1`** — without it, an absent Lean toolchain takes a guarded SKIP path and still exits 0. |
| **K** `<H>` | `cargo kani -Z stubbing --manifest-path der-verified/Cargo.toml --harness <H>` | `VERIFICATION:- SUCCESSFUL` for that one harness (note Kani's literal spelling, with the dash). Re-derives the row from source. Seven modules are HEAVY (>7 GB peak, up to ~20 GB): `set_of`, `sequence`, `x509_name`, `x509_tbs_certificate`, `x509_certificate`, `x509_extension`, `rsa_private_key` — see `gates/tiers.txt`. |
| **R** `<H>` | `awk '/Checking harness <H>/,/^Verification Time/' evidence/check-d68eeca.log` (for the 3 heavy harnesses, use their own `evidence/check-d68eeca-heavy-<module>-<name>.log` instead — they are not in the main log) | The committed run's own `SUMMARY`, **cover tally**, and `VERIFICATION:- SUCCESSFUL` line for that harness. A bare `grep '<H>'` prints only the `Checking harness …` heading and shows you **neither** — the verdict and cover lines come several lines later. Valid only while the freshness command in §1 returns empty. |
| **N** `<thm>` | `sh lean/check_lean.sh`, then read `<thm>` in `lean/<X>Proofs.lean` | **Require the literal `lean lid: PASS (sorry-free)`.** The lid re-extracts from the shipped `.rs` and fails closed on drift. |
| **T** `<filter>` | `cargo test --manifest-path Cargo.toml <filter>` | `test result: ok`. Point evidence only. |
| **A** `<pattern>` | a grep that **must return nothing**, with its positive control | Used only by `not-covered` rows. A grep-zero is a claim about your pattern, so each A-recipe carries the control input that *would* match. See the warning below. |
| **E** `<pattern>` | an absence check **scoped to the implementation region**, with two positive controls: `sed -n '1,/^mod tests/p' der-verified/src/profile.rs \| grep -Eic '<pattern>'` | **0**, where the same pattern class finds a rule that *is* enforced (control 1) and the unscoped file does not return 0 (control 2). See the warning below for why both controls are needed. |
| **D** `<doc §>` | open the cited section and read the argument | `inspection-argued` rows only. There is nothing to run. |

> ### Absence checks are the weakest recipe here, and this file got one wrong twice
>
> A `not-covered` row wants to prove a negative, and the obvious move is a grep that returns nothing.
> That move failed in this very file, **twice, in two different ways** — both worth stating, because
> they are the two independent ways a grep-zero lies.
>
> **Failure 1 — wrong scope.** Three profile rows (`DER-P-5/6/7`) each promised an absence-grep
> scoped to `der-verified/src/profile.rs`. Run against the file, one returns **14 hits**, not zero.
> All 14 are inside `profile.rs`'s own `mod tests` — a `basicConstraints` blob used as a *generic*
> extension fixture in the v3-extensions unit tests. **A Rust module's unit tests live in the same
> file, so scoping a grep to one file does not exclude fixtures.** The rows' conclusions were right;
> their evidence was not.
>
> **Failure 2 — wrong pattern.** While repairing the above, the replacement control was first written
> as `grep -c 'basic_constraints\|BasicConstraints'` and returned **0 on the whole file** — appearing
> to show the fixtures had vanished. They had not: they are named `EXT_BASIC_CONSTRAINTS_DEFAULT`,
> upper-snake, which neither alternative matches case-sensitively. **The control that was supposed to
> catch a lying grep was itself a lying grep.**
>
> So `E` is an absence check with **two** positive controls, and both are load-bearing:
>
> ```sh
> # the claim: scoped to the implementation region, above `mod tests`
> sed -n '1,/^mod tests/p' der-verified/src/profile.rs | grep -Eic 'basic_?constraints'   # -> 0
> # control 1 -- the same scoping and pattern class DO find a rule that is enforced
> sed -n '1,/^mod tests/p' der-verified/src/profile.rs | grep -ic  'ExtensionsRequireV3'  # -> 6
> # control 2 -- the scoping is doing real work; unscoped, the fixtures are still there
> grep -Eic 'basic_?constraints' der-verified/src/profile.rs                              # -> 14
> ```
>
> Control 1 proves the pattern can find something. Control 2 proves the *scope* is what produced the
> zero. A single control catches only one of the two failures above.
>
> **A supporting inspection, not a substitute.** `ProfileError`'s six variants are worth reading
> alongside these rows — `validate_profile` returns `Result<(), ProfileError>`, and the enum's
> docstring says every variant names a rule the module enforces:
>
> ```sh
> sed -n '/^pub enum ProfileError/,/^}/p' der-verified/src/profile.rs | grep -E '^    [A-Z]'
> ```
>
> **But this does not decide a `not-covered` row, and an earlier draft of this file wrongly said it
> did.** The docstring gives one direction only: *variant ⇒ enforced rule*. It does not give the
> converse, so an enumeration of the enum cannot establish that an absent rule is unenforced — a rule
> could be enforced by returning an existing variant, or by returning `Ok` on a path that silently
> accepts. **`DER-P-4` is the standing counterexample inside this very crate**: error precedence is
> an enforced, `contract`-graded rule with no variant of its own. So the variants do *not* map
> one-to-one onto `DER-P-1`…`DER-P-4`, and any recipe built on assuming they did was unsound.
> Positive enumeration beats absence-grepping only where the set is genuinely **closed in the
> direction you need**; an error enum is closed for "what can be reported", not for "what is
> checked".

**Cover tallies matter, and the gate does not enforce them.** Kani reports a harness whose
`kani::cover` is unsatisfiable as `SUCCESSFUL`, with `0 of 1 cover properties satisfied`. `check.sh`
does **not** fail on that. Exactly 3 harnesses have a cover in that state, and they are disclosed
in §6.3. When recipe **R** shows a `0 of N cover properties satisfied` line, read it. The crate has
504 `kani::cover` statements in total.

---

## 5. The coverage ledger

### 5.1 Framing — identifier, length, TLV (X.690 §8.1, §10.1)

| id | rule | status | strength | verify |
|---|---|---|---|---|
| `DER-F-1` | Identifier octets decode: **class + constructed bit** interpretation; low- and high-tag forms (§8.1.2) | done | **CONTRACT+L4** (∀-length) — for every accepted decode of any input length, the class is proved against a direct transcription of the four X.690 top-two-bit ranges, the constructed flag against the fixed `0x20` bit, and the low-tag-form number against the low five bits. This oracle does not use `encode_tag`; the bounded Kani round-trip remains the bounded canonicality evidence | `N tag_decode_identifier_fields` (`lean/TagProofs.lean`, ∀-length) · `K tag::proofs::decode_tag_accepts_only_canonical` |
| `DER-F-1b` | `decode_tag` terminates on any input and an accepted decode consumes `1..=input.len()` bytes | done | **CONTRACT+L4** | `N tag_decode_total`, `tag_decode_used_bounds` (`lean/TagProofs.lean`, ∀-length) |
| `DER-F-1c` | High-tag `decode_tag`: an accepted high-tag number equals the base-128 big-endian value of its continuation octets (§8.1.2.4.2) | done | **CONTRACT+L4** (∀-length) — proven against the Aeneas-extracted model, **not** a round-trip oracle, so it genuinely decides that the tag-number bits are read correctly | `N tag_decode_high_tag_accept` (`lean/TagProofs.lean`, ∀-length; pins `number` and `used`; `DER-F-1` independently pins class/constructed for every accepted form) |
| `DER-F-2` | High-tag-number form must be minimal — no leading `0x80` padding (§8.1.2.4.2 c) | done | **CONTRACT+L4** (∀-length) for the leading-`0x80` case; the high-tag-of-small-number (`≤30`) case stays **CONTRACT** (bounded Kani) | `N tag_decode_leading_zero` (∀-length) · `K tag::proofs::high_tag_of_small_number_is_non_minimal` · `K tag::proofs::leading_zero_high_tag_is_non_minimal` |
| `DER-F-3` | Tag numbers above the supported width are rejected as `TooLarge`, never misread and never a panic. **Supported range is up to `u32::MAX`** (`tag.rs:9`) — a documented deviation from unlimited DER, safe for X.509 | done | **CONTRACT+L4** (∀-length) — the `TooLarge` reject on crossing the `u32::MAX >> 7` threshold is now proven for inputs of any length (was a single-encoding bounded probe) | `N tag_decode_too_large` (`lean/TagProofs.lean`, ∀-length) · `K tag::proofs::too_large_tag_is_classified` |
| `DER-F-4` | Length is the **shortest** definite form — short form for <128, no leading zero octets in long form (§10.1) | done | **CONTRACT+L4** | `K length::proofs::decode_accepts_only_canonical` · `K length::proofs::leading_zero_is_non_minimal` · `K length::proofs::long_form_of_short_value_is_non_minimal` · `N decode_accepts_only_canonical` (`lean/LengthProofs.lean`, ∀-length) |
| `DER-F-5` | Indefinite length (`0x80`) and the reserved `0xFF` initial octet are rejected (§8.1.3.6, §10.1) | done | **CONTRACT** (bounded) | `K length::proofs::indefinite_is_classified` · `K length::proofs::reserved_is_classified` |
| `DER-F-6` | An accepted TLV consumes exactly `header + declared length`, its value is exactly that window, and `used ≤ input.len()` — **no over-read** (§8.1.1) | done | **CONTRACT+L4** | `K tlv::proofs::decode_tlv_structure` · `N decode_tlv_structure` (`lean/TlvProofs.lean`, ∀-length) |
| `DER-F-7` | A top-level DER value is *exactly one* TLV — trailing bytes are rejected (§8.1.1.1) | done | **PROBE** (bounded) — each harness uses **one fixed valid object plus one symbolic trailing byte**, not a symbolic TLV domain. The Lean lids do not cover the strict variants at all | `K tlv::proofs::strict_rejects_trailing` · `K sequence::proofs::strict_rejects_trailing` · `K set_of::proofs::strict_rejects_trailing` |
| `DER-F-8` | **The shipped form rule agrees with the crate's primitive-only table** for every identifier — e.g. `21 00` is rejected as a BOOLEAN. Decided across X.680's full assignment range `1..=36`, incl. the high-tag types 31..=36 | done **at the opt-in entry point**; **not-covered at `decode_tlv`** | **CONTRACT** (domain-complete: symbolic `u32` tag number × all 4 classes × both forms — a complete input domain, not a bounded buffer) | `K identifier_form::proofs::constructed_form_rule_matches_oracle_on_all_tags` · `K identifier_form::proofs::rejects_every_disclosed_illegal_identifier` · `K identifier_form::proofs::high_tag_universal_types_are_form_checked` · `K identifier_form::proofs::legal_der_the_comparison_library_rejected_is_still_accepted` |
| `DER-F-8b` | **That table itself is a faithful transcription of X.680** — i.e. that the types it marks primitive-only really are primitive-only | **partial** | **inspection-argued** · ⚠ **UNWEIGHTED** — the four domain-complete theorems compare the shipped `match` against a bitmask oracle **written by the same author**. They establish the two encodings agree on all 2^32 tag numbers, which is what a transcription slip would violate; they cannot establish agreement with the standard. Spot-checked per-arm by concrete tests | `D` — read the per-arm citations in `identifier_form.rs`, whose own source says the same-author mask cannot establish standards correctness. **A shared misreading of X.680 passes every harness in `DER-F-8`.** |
| `DER-F-9` | **The reserved EOC identifier `00 00` is never a legal DER identifier** — universal 0 is BER's end-of-contents marker (§8.1.5), and DER admits no indefinite-length encoding for it to terminate (§10.1) | done **at the opt-in entry point**; **not-covered at `decode_tlv`** | **CONTRACT** (bounded) (domain-complete biconditional: rejected iff UNIVERSAL 0, either form) | `K identifier_form::proofs::reserved_eoc_rejected_iff_universal_zero` |

### 5.2 Content codecs — per type

| id | rule | status | strength | verify |
|---|---|---|---|---|
| `DER-C-BOOL` | `TRUE` is encoded as `0xFF` and nothing else; content is exactly one octet (§11.1) | done | **CONTRACT** (bounded) (exhaustive over the 1-octet domain) | `K boolean::proofs::one_octet_is_canonical` · `K boolean::proofs::wrong_length_is_bad_length` |
| `DER-C-INT-1` | INTEGER content is minimal two's-complement — no redundant `00`/`FF` padding (§8.3) | done | **CONTRACT** (bounded) | `K integer::proofs::decode_accepts_only_minimal` · `K integer::proofs::redundant_positive_padding_is_non_minimal` · `K integer::proofs::redundant_negative_padding_is_non_minimal` |
| `DER-C-INT-2` | The same minimality rule at **arbitrary magnitude** (big serial numbers), not just `i64` | done | **CONTRACT+L4** | `K big_integer::proofs::validate_iff_minimal_oracle` · `N validate_iff_minimal` (`lean/BigIntProofs.lean`, ∀-length) |
| `DER-C-INT-3` | INTEGER content is never empty (§8.3.1) | done | **CONTRACT** (bounded) | `K integer::proofs::empty_is_classified` |
| `DER-C-BITS-1` | BIT STRING unused-bits octet is `0..=7` (§11.2.1) | done | **CONTRACT** (bounded) | `K bit_string::proofs::unused_too_large_is_classified` |
| `DER-C-BITS-2` | Every unused bit is zero (§11.2.2) | done | **CONTRACT** (bounded) | `K bit_string::proofs::nonzero_padding_is_classified` · `K bit_string::proofs::decode_accepts_only_canonical` |
| `DER-C-BITS-3` | The empty BIT STRING is exactly `[0x00]` (§11.2.2.1) | done | **CONTRACT** (bounded) | `K bit_string::proofs::empty_is_classified` · `K bit_string::proofs::empty_nonzero_unused_is_classified` |
| `DER-C-BITS-4` | BIT STRING must use the **primitive** form (§10.2) | done at the opt-in entry point; **not-covered** at `decode_bit_string` | **CONTRACT** (bounded — inherits `DER-F-8`: BIT STRING is UNIVERSAL 3, inside the decided range), **and inherits `DER-F-8b`'s unweighted caveat with it** | inherits `DER-F-8`'s recipes. `decode_bit_string` itself still never sees the identifier; the module docstring used to claim otherwise and **was corrected 2026-08-25** — it now names the typed callers and `identifier_form` |
| `DER-C-BITS-5` | NamedBitList trailing-zero minimality (X.680 §22.7, e.g. `KeyUsage`) | **not-covered** | **out-of-scope** | `D bit_string.rs` module docstring — a property of the ASN.1 *type*, deliberately not applied to a bare BIT STRING |
| `DER-C-OCT-1` | OCTET STRING must use the primitive form; the BER constructed (segmented) form is rejected (§10.2) | done | **CONTRACT** (bounded) — *at the typed parser, not at the framing layer* | `K octet_string::proofs::constructed_form_is_rejected` · `K octet_string::proofs::accepted_identifier_is_canonical_0x04` |
| `DER-C-OCT-2` | An accepted OCTET STRING's content is exactly the TLV's value window | done | **CONTRACT** (bounded) | `K octet_string::proofs::accepted_content_is_the_tlv_value` |
| `DER-C-NULL` | NULL content is empty and nothing else (§8.8) | done | **CONTRACT** (bounded) (exhaustive on its domain) | `K null::proofs::only_empty_is_valid` |
| `DER-C-OID-1` | OID subidentifiers are minimal base-128 — no leading `0x80`, last octet terminates (§8.19) | done | **CONTRACT+L4** | `K oid::proofs::leading_0x80_is_non_minimal` · `K oid::proofs::later_0x80_is_non_minimal` · `K oid::proofs::unterminated_is_truncated` · `N validate_iff_canonical` (`lean/OidProofs.lean`, ∀-length) |
| `DER-C-OID-2` | **Subidentifier width limits and arc materialisation** (`X = min(Z/40,2)`, `Y = Z − 40X`) | **not-covered** | **out-of-scope** | `D oid.rs` docstring, "Scope boundaries (deliberate)": a canonical subidentifier may exceed `u64` and is accepted; *"a downstream arc decoder must enforce its own integer-width limit"*. The crate ships a canonical-form validator, not an arc decoder. |
| `DER-C-ENUM-1` | ENUMERATED **content** follows the INTEGER rules (§8.4) | done | **CONTRACT** (bounded) (delegation proved over symbolic content; inherits `DER-C-INT-1`) | `K enumerated::proofs::decode_delegates_to_integer` · `K enumerated::proofs::encode_delegates_to_integer` |
| `DER-C-ENUM-2` | ENUMERATED uses identifier UNIVERSAL 10 | done | **test-only** — the tag is a constant checked by a concrete unit test; no harness asserts it | `T enumerated::tests` |
| `DER-C-UTF8` | UTF8String content is well-formed UTF-8; ill-formed input is rejected with its position (§8.23) | done | **CONTRACT** (bounded) (oracle is `core`'s own `str::from_utf8`) | `K utf8_string::proofs::validate_iff_std` · `K utf8_string::proofs::ill_formed_reports_position` · `K utf8_string::proofs::constructed_form_is_rejected` |
| `DER-C-STR-1` | PrintableString / IA5String / NumericString / VisibleString accept exactly their charset (§8.23, X.680) | done | **CONTRACT** (bounded) (biconditional against an independent charset oracle, all four types) | `K restricted_string::proofs::validate_iff_all_in_charset_printable` (and `_ia5`, `_numeric`, `_visible`) · `K restricted_string::proofs::charset_exactly_matches_oracle_printable` (×4) |
| `DER-C-STR-2` | Those four types reject the constructed form and require their own tag | done | **CONTRACT** (bounded) — *at the typed parser*. The label rests on the `accepted_identifier_*` harnesses, which are fully symbolic; the `constructed_form_*` and `wrong_tag_*` harnesses beside them are fixture-shaped and would be PROBE alone | `K restricted_string::proofs::accepted_identifier_is_canonical_printable` (×4 — rules out high-tag forms, wrong class/number **and** the constructed form) · `K restricted_string::proofs::constructed_form_is_rejected_printable` (×4) |
| `DER-C-UTC` | UTCTime is exactly `YYMMDDHHMMSSZ` — 13 octets, mandatory seconds, `Z` terminator, field ranges (§11.8) | done | **CONTRACT** (bounded) (biconditional against a separate canonical-form oracle) | `K utc_time::proofs::accepted_iff_canonical_oracle` · `K utc_time::proofs::not_zulu_is_classified` · `K utc_time::proofs::full_year_pivot_is_correct` |
| `DER-C-GEN` | GeneralizedTime is `YYYYMMDDHHMMSS[.fff]Z` — mandatory seconds, `Z`, canonical fraction with no trailing zeros (§11.7) | done | **CONTRACT** (bounded) (biconditional oracle) | `K generalized_time::proofs::accepted_iff_canonical_oracle` · `K generalized_time::proofs::fraction_trailing_zero_is_classified` · `K generalized_time::proofs::bad_fraction_separator_is_classified` |
| `DER-C-SEQ-1` | A SEQUENCE's children tile its content exactly — the walk consumes precisely the content bytes (§8.9) | done | **CONTRACT+L4** (the only lid unbounded in **child count** as well as byte length) | `K sequence::proofs::ok_implies_exact_tiling` · `N decode_sequence_structure` (`lean/SequenceProofs.lean`) |
| `DER-C-SEQ-2` | The shipped SEQUENCE walk never over-reads, and each step advances by exactly the child's own encoded length | done | **CONTRACT** (bounded) (real-path, independent oracle — rewritten 2026-08-24, see §6.2) | `K sequence::proofs::no_over_read` · `R sequence::proofs::no_over_read` (check its two cover lines are satisfied) |
| `DER-C-SEQ-3` | SEQUENCE is constructed and carries identifier `0x30` | done | **CONTRACT** (bounded) | `K sequence::proofs::tag_correctness` · `K sequence::proofs::accepted_identifier_is_canonical_0x30` |
| `DER-C-SETOF-1` | SET OF members appear in ascending order of their **encodings** (§11.6) | **partial** | **CONTRACT** (bounded-backing, symbolic content `0..=8` octets) — exact `Result` against an independent two-phase whole-encoding oracle (`ordering_matches_whole_encoding_oracle`, and the TLV entry point over a symbolic 9-octet buffer in `tlv_entry_enforces_ordering_exactly`): children may differ in identifier octet, length octets and value, and `Unsorted { index }` names the first descending pair. The fixture-shaped harnesses (`ordering_iff_oracle`, `cmp_padded_matches_oracle`, `unsorted_children_are_rejected`) remain narrower than this label. Not established for content above 8 octets | `K set_of::proofs::ordering_iff_oracle` · `K set_of::proofs::cmp_padded_matches_oracle` · `K set_of::proofs::unsorted_children_are_rejected` · `K set_of::proofs::ordering_matches_whole_encoding_oracle` · `K set_of::proofs::tlv_entry_enforces_ordering_exactly`. **Added after the `d05d3f2` row text was written (full floor now at `d68eeca`):** symbolic content of 0..=8 octets (children may differ in identifier octet, length octets and value; the TLV entry point over a symbolic 9-octet buffer), decided exactly against an independent whole-encoding oracle. Still bounded; disclosures: PROOF_MANIFEST.md §6.2 |
| `DER-C-SETOF-2` | Equal adjacent member encodings are accepted (SET **OF**, not SET) | done | **CONTRACT** (bounded-backing, `0..=8` octets) — equal adjacent encodings are non-descending under the whole-encoding oracle and are accepted (`ordering_matches_whole_encoding_oracle`); the concrete 6-byte fixture `duplicate_adjacent_encodings_are_accepted` is kept as a witness | `K set_of::proofs::duplicate_adjacent_encodings_are_accepted`. At `d68eeca` the symbolic whole-encoding oracle `K set_of::proofs::ordering_matches_whole_encoding_oracle` also decides this over 0..=8 octets (equal adjacent encodings are non-descending, so accepted); the fixture above is no longer the only evidence |
| `DER-C-SETOF-3` | The shipped SET OF walk never over-reads, and each step advances by exactly the child's own encoded length | done | **CONTRACT** — **bounded-backing evidence** checks a harness-owned instance of SET OF's shared `Elements` walk per child against an independent oracle over `0..=6` octets; exact-result equivalence over `0..=8` pins production to that call pattern. Lean proves one accepted `Elements` step at any remaining-slice length, not exhaustion of the SET OF loop. This is the disclosed contract surface, not an unrestricted proof of SET OF-specific glue; see §6.4 | `N elements_next_progress` (`lean/SequenceProofs.lean`) · `K set_of::proofs::no_over_read` · `K set_of::proofs::refactored_walk_matches_previous_walk` |
| `DER-C-SET` | General `SET` (§10.3) — DER ordering of a heterogeneous SET | **not-covered** | **out-of-scope** | `D DECISIONS.md` D13; README scope section. Not implemented, not claimed. |
| `DER-C-CTX` | `[n] EXPLICIT` context tagging (§8.14) | done | **CONTRACT** (bounded-backing, `≤16` octets, symbolic `len` and full-range tag number, `unwind(20)`, no stubs) — exact total `Result` for the explicit form only (`decode_explicit_context_exact_result`, `decode_explicit_context_faithful`); an `Ok` does not require the value octets to be one complete inner TLV (inner well-formedness and tiling are the caller's) | `K context_tag::proofs::decode_explicit_context_never_panics` · `K context_tag::proofs::decode_explicit_context_faithful` · `K context_tag::proofs::decode_explicit_context_exact_result`. **Added after the `d05d3f2` row text was written (full floor now at `d68eeca`):** the exact total `Result` over a fully symbolic buffer of ≤16 bytes and a full-range tag number, `unwind(20)`, no stubs; explicit form only; inner-TLV well-formedness and tiling are the caller's. Disclosures: PROOF_MANIFEST.md §6.2 |
| `DER-C-CTX-IMP` | `[n] IMPLICIT` context tagging | **not-covered** | **out-of-scope** | `D PROOF_MANIFEST.md` §6.2 — *"only the explicit-context form is addressed"*. Consequence: X.509's deprecated `[1]`/`[2]` unique identifiers are **rejected**, not parsed (`DER-X-TBS-2`) |

### 5.3 X.509 / PKCS structural surface

**Read this block before trusting any row in it.** The `x509_*` structural rows (`DER-X-*`) are proved
**panic-free**, not **conformant**: their harnesses are `*_never_panics`. Panic-freedom is a real and
valuable safety property — this is the layer a malformed certificate attacks — but it does **not**
decide whether the parser accepts exactly the RFC 5280 structures. On the rule axis, that keeps those
rows `partial`. **The key-format rows (`DER-K-*`: pkcs8, epki, rsa_public_key, ec_private_key,
ecdsa_sig_value) additionally carry a `*_parse_faithful` functional contract (2026-09-17):** on any
accepted symbolic input it proves the decode is *faithful* — exact envelope consumption, field
sub-slice identity, and exact field tiling — with an observed-red control (see
[`evidence/CONTRACT-CONTROLS-2026-09-17.md`](evidence/CONTRACT-CONTROLS-2026-09-17.md)). That lifts
their strength to `CONTRACT` (bounded-backing, `0..=16` octets) for structural faithfulness; they stay
`partial` on the rule axis because full *value* conformance (e.g. that an OID names a known algorithm,
or a modulus is a valid key) is still not decided. **Two `x509_*` framing sub-modules now also carry a
`*_parse_faithful` contract** (`DER-X-ALGID`, `DER-X-SPKI` — 2026-09-17 Track B), **and three more carry bounded-backing exact-result
rows** (`DER-X-NAME`, `DER-X-VALID`, `DER-X-EXT-1`, at `d68eeca`; each row states its own bounds and exclusions). Two
cert-*composition* modules (`x509_certificate`, `x509_tbs_certificate`) remain panic-freedom probes — see §6.6.

| id | structure (RFC 5280 unless noted) | status | strength | verify |
|---|---|---|---|---|
| `DER-X-ALGID` | `AlgorithmIdentifier` §4.1.1.2 — framing | partial | **CONTRACT** (bounded-backing `0..=16`B) — faithful decode: OID sub-slice identity + **canonical-OID conformance** (`validate_oid`) + parameters raw-TLV identity/classification + exact tiling; 2 observed-red controls (tiling + canonicality). Rule-axis `partial`, but the canonical-OID value property IS proven | `K x509_algorithm_identifier::proofs::parse_faithful` · `K …::parse_algorithm_identifier_never_panics` · `D evidence/contract-controls-2026-09-17/x509algid/` |
| `DER-X-SPKI` | `SubjectPublicKeyInfo` §4.1.2.7 — framing | partial | **CONTRACT** (bounded-backing `0..=16`B) — faithful decode: BIT STRING classification + value identity + exact tiling; 2 observed-red controls (tiling + classification). Delegated `algorithm` field is plumbing-checked here, its correctness riding on `DER-X-ALGID`'s contract | `K x509_spki::proofs::parse_faithful` · `K x509_spki::proofs::parse_never_panics` · `D evidence/contract-controls-2026-09-17/x509spki/` |
| `DER-X-NAME` | `Name` / `RDNSequence` §4.1.2.4 — framing | partial | **CONTRACT** (bounded-backing) — exact `Result` and exact error payload for single-ATV RDNs, two single-ATV RDNs and one RDN with two ATVs of different encoded lengths (1-octet OIDs), **except** the inner payload of `BadOuterSeq` for the outer envelope (the inner `SequenceError::Tlv(_)` detail), which is not pinned; equal-length ATV pairs (solver tool limit) and RDNs with more than two ATVs are **not covered**; the composition harness is modular (stubs `validate_rdn`) and is discharged by the heavy `validate_rdn_never_panics`, which has no cover of its own. See §6.3 | `K x509_name::proofs::validate_never_panics` (stubs `validate_rdn`) · `K x509_name::proofs::validate_rdn_never_panics` (**no cover at all**) · `K x509_name::proofs::validate_name_single_atv_exact` · `K x509_name::proofs::validate_name_two_rdns_exact` · `K x509_name::proofs::validate_name_two_atvs_exact` · `K x509_name::proofs::validate_name_two_atvs_unsorted`. **Added after the `d05d3f2` row text was written (full floor now at `d68eeca`):** exact-result and exact-error harnesses with no stubs, for single-ATV RDNs, two single-ATV RDNs and one RDN with two ATVs of different encoded lengths, with the same `BadOuterSeq` inner-payload exception (14 `validate_name_*` harnesses in all, see PROOF_MANIFEST.md §5). **Not covered:** two ATVs of equal encoded length (solver tool limit) and RDNs with more than two ATVs. `validate_rdn_never_panics` is a heavy harness (kept out of the 20 GiB pass because earlier measurements approached or exceeded 20 GiB; measured peak 17.3G in its 24G run) with its own companion log in the split floor; disclosures: PROOF_MANIFEST.md §6.2 |
| `DER-X-VALID` | `Validity` §4.1.2.5 — framing | partial | **CONTRACT** (bounded-backing, skeletons `≤47` octets) — exact `Result` and exact error payload for both field encodings and `GeneralizedTime` fractions of 0 to 3 digits; a `GeneralizedTime` failure is pinned only at `BadLength`, the outer-envelope `BadOuterSeq` payload is not pinned, the year-2050 rule is not enforced; **cover UNSATISFIED** for `parse_never_panics` at `[u8; 16]` (disclosed, witnessed by `parse_validity_ok_path_witnessed`) — see §6.3 | `R x509_validity::proofs::parse_never_panics` (`0 of 1 cover`) · `K x509_validity::proofs::parse_validity_ok_path_witnessed` (companion witness, no stubs) · `K x509_validity::proofs::parse_validity_faithful` (and `_uu`/`_ug`/`_gu`/`_gg`) · `K x509_validity::proofs::parse_validity_rejects_field_content`. **Added after the `d05d3f2` row text was written (full floor now at `d68eeca`):** 10 exact-result harnesses (skeletons ≤47 bytes, `GeneralizedTime` fractions 0 to 3 digits). The `parse_never_panics` cover is still `0 of 1` at `d68eeca` (disclosed, witnessed by the companion above); disclosures: PROOF_MANIFEST.md §6.2 |
| `DER-X-EXT-1` | `Extension` / `Extensions` §4.1.2.9 — framing | partial | **CONTRACT** (bounded-backing) — `parse_extension` exact over `≤16` octets fully symbolic; `validate_extensions` over at most two members with 1-octet OIDs and empty values (`extnValue` uninterpreted); the `Ok` cover of `validate_extensions_never_panics` is **UNSATISFIED** at 13 octets (disclosed, witnessed by `validate_extensions_ok_path_witnessed`); both heavy harnesses ran at 24G in the split floor — see §6.3 | `R x509_extension::proofs::validate_extensions_never_panics` (`0 of 1 cover`) · `K x509_extension::proofs::validate_extensions_ok_path_witnessed` · `K x509_extension::proofs::parse_extension_faithful` · `K x509_extension::proofs::validate_extensions_structured_two_members` · `K x509_extension::proofs::validate_extensions_rejects_outer_envelope`. **Added after the `d05d3f2` row text was written (full floor now at `d68eeca`):** `parse_extension` ≤16 bytes fully symbolic; `validate_extensions` at most two members with 1-octet OIDs and empty values; `extnValue` uninterpreted. The two `validate_extensions_*` harnesses cited above as `R`/`K` are heavy (kept out of the 20 GiB pass because earlier measurements approached or exceeded 20 GiB; measured peaks 20.1G and 16.5G in their 24G runs) and have companion logs at `d68eeca` (split floor); disclosures: PROOF_MANIFEST.md §6.2 |
| `DER-X-EXT-2` | DER `DEFAULT` omission: a `critical` field encoding `FALSE` must be absent (§11.5) | done | **test-only** — one concrete unit test. `parse_extension_never_panics` calls the parser and covers `Ok`; it never asserts this rule | `T x509_extension::tests::rejects_critical_present_but_false` |
| `DER-X-EXT-3` | **Extension *contents* (basicConstraints, keyUsage, SAN, …)** | **not-covered** | **not-covered** | `D PROOF_MANIFEST.md` §6.2 — *"extension contents are never interpreted, and `critical` is peeked, not acted on."* `extnValue` is an opaque OCTET STRING. |
| `DER-X-TBS-1` | `TBSCertificate` §4.1 — the full field skeleton (version, serial, signature, issuer, validity, subject, SPKI, extensions) | partial | **PROBE** (bounded), **cover UNSATISFIED**, **stub-mediated** — see §6.3 | `R x509_tbs_certificate::proofs::parse_tbs_certificate_never_panics` (`0 of 1 cover`, 2 stubs) · `K x509_tbs_certificate::proofs::parse_tbs_certificate_ok_path_witnessed` (**3 stubs** — glue reachability only) |
| `DER-X-TBS-2` | DER `DEFAULT` omission for `version`: a present `[0]` encoding v1 is rejected (§11.5) | done | **test-only** — one concrete unit test; no harness asserts it | `T x509_tbs_certificate::tests` — `TbsCertificateError::VersionMustBeOmitted` |
| `DER-X-CERT` | `Certificate` §4.1 — outermost composition | partial | **PROBE** (bounded) (panic-freedom, 1 stub, Ok-tail cover **satisfied**) — but see `DER-X-BOUND` | `K x509_certificate::proofs::parse_certificate_never_panics` |
| `DER-X-BOUND` | **Panic-freedom at realistic input sizes** | **partial** | **inspection-argued** · ⚠ **UNWEIGHTED** | `D PROOF_MANIFEST.md` §8.1 — `x509_certificate` panic-freedom is proved at **≤12 bytes**; a real certificate is ~170 bytes. `rsa_private_key` at **≤20 bytes** vs ~317. Real-size panic-freedom *"rests on an un-machine-checked compositional argument"*. |
| `DER-K-PKCS8` | PKCS#8 `PrivateKeyInfo` (RFC 5208 §5) | partial | **CONTRACT** (bounded-backing `0..=16`B) — faithful decode: exact consumption + sub-slice identity + exact field tiling; + observed-red control (rule-axis `partial`: structural faithfulness, not full value conformance) | `K pkcs8::proofs::parse_faithful` · `K pkcs8::proofs::parse_never_panics` · `K pkcs8::proofs::parse_ok_path_witnessed` · `D evidence/contract-controls-2026-09-17/pkcs8/` |
| `DER-K-EPKI` | `EncryptedPrivateKeyInfo` (RFC 5958 §3) | partial | **CONTRACT** (bounded-backing `0..=16`B) — faithful decode + observed-red control (rule-axis `partial`) | `K encrypted_private_key_info::proofs::parse_faithful` · `K encrypted_private_key_info::proofs::parse_never_panics` · `D evidence/contract-controls-2026-09-17/epki/` |
| `DER-K-RSAPUB` | `RSAPublicKey` (RFC 8017 §A.1.1) | partial | **CONTRACT** (bounded-backing `0..=16`B) — faithful decode + observed-red control (rule-axis `partial`) | `K rsa_public_key::proofs::parse_faithful` · `K rsa_public_key::proofs::parse_strict_never_panics` · `D evidence/contract-controls-2026-09-17/rsa/` |
| `DER-K-RSAPRIV` | `RSAPrivateKey` (RFC 8017 §A.1.2) | partial | **CONTRACT** (bounded-backing, backing `≤44` octets) for the two-prime structure — exact `Result` from the symbolic-content skeletons plus perturbation harnesses; the multi-prime member walk covers one member of three 1-octet INTEGERs with concrete member content only; behaviour at real size (~317 octets) is not machine-checked (compositional argument, see `DER-X-BOUND`); `BadOuterSeq` payload not pinned; no RSA arithmetic | `K rsa_private_key::proofs::parse_never_panics` (4 stub applications across its harnesses) · `K rsa_private_key::proofs::parse_faithful_two_prime_s1` · `K rsa_private_key::proofs::parse_faithful_two_prime_s2` · `K rsa_private_key::proofs::parse_multi_prime_faithful`. **Added after the `d05d3f2` row text was written (full floor now at `d68eeca`):** exact `Result` for the two-prime structure (backing ≤44 bytes) and a multi-prime member walk over one member of three 1-octet INTEGERs with concrete member content; not covered: more than one member, multi-octet member INTEGERs, the strict entry point on a multi-prime input. Real-size (~317 bytes) panic-freedom is still the un-machine-checked compositional argument; disclosures: PROOF_MANIFEST.md §6.2 |
| `DER-K-ECPRIV` | `ECPrivateKey` (RFC 5915 §3) | partial | **CONTRACT** (bounded-backing `0..=16`B) — faithful decode incl. both `[0]`/`[1]` optionals + observed-red control (rule-axis `partial`) | `K ec_private_key::proofs::parse_faithful` · `K ec_private_key::proofs::parse_never_panics` · `D evidence/contract-controls-2026-09-17/ec/` |
| `DER-K-ECDSASIG` | `ECDSA-Sig-Value` (RFC 3279 §2.2.3) | partial | **CONTRACT** (bounded-backing `0..=16`B) — faithful decode + observed-red control (rule-axis `partial`) | `K ecdsa_sig_value::proofs::parse_faithful` · `K ecdsa_sig_value::proofs::parse_strict_never_panics` · `D evidence/contract-controls-2026-09-17/ecdsa/` |
| `DER-X-L4` | An unbounded (Lean) lid over **any** X.509 structural module | **not-covered** | **not-covered** | `D gates/map_declared.txt` row `x509_structural_lid` → `DER-REMAINING-WORK.md` §3. All seven `x509_*` modules are Kani-only. |

**Disclosed exclusions of the exact-result harnesses (`x509_validity`, `rsa_private_key`, `x509_name`).** These are stated
limits of the evidence, not exhaustive mapping proofs. (1) In `x509_validity`, a `GeneralizedTime` failure is pinned only at
`BadLength`; other `GeneralizedTime` content errors are covered by the `generalized_time` module's own proofs and are not
re-pinned through the validity `map_err`. (2) In `x509_validity`, `rsa_private_key` and `x509_name`, the payload of the
`BadOuterSeq` outer-envelope error (the inner `SequenceError::Tlv(_)` detail) is not pinned by the exact-result harnesses.
No other claim in this document is widened by these statements. See also `PROOF_MANIFEST.md` §6.2.

### 5.4 RFC 5280 profile rules

The `profile` module is the crate's only *semantic* layer, and — unusually for this crate — its rules
are proved as **biconditionals**, which is stronger than the structural layer beneath it.

| id | rule | status | strength | verify |
|---|---|---|---|---|
| `DER-P-1` | The inner `signature` and outer `signatureAlgorithm` must be identical (§4.1.1.2) | **partial** | **PROBE** (bounded) — a biconditional, but **monomorphic in slice length**: the OIDs are always 2 bytes and the parameters 1 byte. Since this rule is *about* the algorithm identifiers, that bound is on the rule itself, not incidental | `K profile::proofs::rule1_mismatch_iff_algorithms_differ` |
| `DER-P-2` | Extensions may appear only in a v3 certificate (§4.1.2.1, §4.1.2.9) | done | **CONTRACT** (bounded) — biconditional over the rule's **full** domain: symbolic `version: u8` (all 256 values, not just 0/1/2) and symbolic extensions-present | `K profile::proofs::rule2_requires_v3_iff_extensions_present_and_not_v3` |
| `DER-P-3` | Dates through 2049 use UTCTime; 2050 onward use GeneralizedTime (§4.1.2.5) | done | **CONTRACT** (bounded) (biconditional, plus a proof that UTCTime *cannot* denote ≥2050) | `K profile::proofs::rule3_generalized_too_early_iff_year_le_2049` · `K profile::proofs::utc_time_can_never_denote_2050_or_later` |
| `DER-P-4` | Error precedence follows declaration order (determinism of the reported violation) | done | **CONTRACT** (bounded) | `K profile::proofs::error_precedence_follows_declaration_order` |
| `DER-P-5` | Basic constraints (§4.2.1.9) | **not-covered** | **not-covered** | `E 'basic_?constraints'` → 0 in the implementation region; controls 6 and 14 as shown in §4. `gates/map_declared.txt` row `basic_constraints`. **The absence-grep this row used to name was unsound; see §4.** |
| `DER-P-6` | Key usage (§4.2.1.3) | **not-covered** | **not-covered** | `E 'key_usage'` → 0 in the implementation region, **sharing only control 1** (`ExtensionsRequireV3`, scoped → 6) with `DER-P-5`. **Control 2 does not apply here**: `key_usage` also returns 0 unscoped (`grep -ic 'key_usage' der-verified/src/profile.rs` → 0) — profile.rs's `mod tests` carries no key-usage fixture at all (unlike `EXT_BASIC_CONSTRAINTS_DEFAULT`, reused generically across `DER-P-5`'s tests), so there is no fixture-shaped false positive for a second control to rule out, and scoping is not what produced this zero. `gates/map_declared.txt` row `key_usage`. |
| `DER-P-7` | Name constraints (§4.2.1.10) | **not-covered** | **not-covered** | `E 'name_constraint'` → 0 in the implementation region, **sharing only control 1** (`ExtensionsRequireV3`, scoped → 6) with `DER-P-5`. **Control 2 does not apply here**: `name_constraint` also returns 0 unscoped (`grep -ic 'name_constraint' der-verified/src/profile.rs` → 0) — profile.rs's `mod tests` carries no name-constraints fixture at all, so there is no fixture-shaped false positive for a second control to rule out, and scoping is not what produced this zero. `gates/map_declared.txt` row `name_constraints`. |
| `DER-P-8` | Validity against a clock (§4.1.2.5) | **not-covered** | **not-covered** | `A '::now('` over `der-verified/src/` → **0** (likewise `SystemTime` and `Instant`, run separately): the crate never acquires a current time, so it cannot compare one. **Positive control:** `grep -c 'Time' der-verified/src/x509_validity.rs` → 115 — the crate has UTCTime/GeneralizedTime *values* in abundance and no *clock*, and that is exactly the distinction this row records. `gates/map_declared.txt` row `validity_against_clock`. |
| `DER-P-9` | Certificate-path / trust validation; signature and crypto verification | **not-covered** | **out-of-scope** | `D README.md` scope section — *"Out of scope (not implemented, not proven)"*. `gates/map_declared.txt` rows `path_validation`, `crypto_verification`. |
| `DER-P-10` | String canonicalisation / name-comparison rules; OID semantics | **not-covered** | **out-of-scope** | `D PROOF_MANIFEST.md` §6.2 |
| `DER-P-11` | A GeneralizedTime in `validity` must not carry fractional seconds (§4.1.2.5.2) — enforced by `validate_profile` since 0.2.0 | done | **CONTRACT** (bounded) — per-field biconditional (reference computed from the fraction window length, not from `require_no_fraction`); the fraction is a symbolic 0..=4-octet window (a 4-octet backing; lengths above 4 are covered by unit tests, not proved) and the rule reads emptiness only. Precedence relative to rules 1–3 is pinned by `DER-P-4` | `K profile::proofs::rule4_fraction_iff_generalized_with_fraction` · `K profile::proofs::validate_profile_is_exactly_the_documented_precedence` |

### 5.5 Crate-wide safety and hygiene

| id | claim | status | strength | verify |
|---|---|---|---|---|
| `DER-S-1` | No `unsafe` anywhere | done | **mechanical** (compiler-enforced) | `grep -rn '#!\[forbid(unsafe_code)\]' der-verified/src/lib.rs`; the manifest's inventory derives `0` unsafe blocks |
| `DER-S-2` | **No harness triggers a panic within that harness's own symbolic domain, assumptions, stubs and unwind bound** | done | **CONTRACT** (bounded) — the item here *is* panic-freedom, and the harnesses decide it directly over symbolic input, so the grade is relative to this item rather than to the encoding rules elsewhere in this table. **It is not a conformance claim, and it does not extend past each harness's declared bound** — see `DER-X-BOUND` for what that costs at realistic input sizes | `G`, or `R` per harness |
| `DER-S-3` | Every public entry point is named by a harness | **partial** | **mechanical** | 84 public entry points; **83 harnessed, 1 not**: `Charset::tag_number` (symbolically executed inside the four `wrong_tag_is_classified_*` harnesses, not named by one). The ten wrappers/helpers listed here before 2026-10-02 now have exact-delegation / biconditional harnesses (`PROOF_MANIFEST.md` §4.1). Re-derive with `python3 gates/gen_proof_manifest.py --json`. |
| `DER-S-4` | The documentation's counts match the source | done | **mechanical** | `python3 gates/gen_proof_manifest.py --check` and `python3 gates/gen_verification_map.py --check` — each gate has its own self-test, run first, in `check.sh` |
| `DER-S-5a` | The Lean lids contain no `sorry` | done | **mechanical** | `N` — `check_lean.sh` fails closed on `sorryAx` or a `declaration uses 'sorry'` warning, and was negative-tested by injecting one |
| `DER-S-5b` | The lids assume no axiom about this crate's own code (13 declared axioms, all specs for upstream `core` primitives) | done | **inspection-argued** · ⚠ **UNWEIGHTED** | `D evidence/AXIOM-AUDIT-2026-08-18.md`. Nothing *mechanically* keeps a crate-code assumption out of a future lid — this property is reviewed, not gated, so the format declines to vouch for it |

---

---

## 6. The six things a consumer must not miss

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
sibling `validate_never_panics` stubs `validate_rdn`, so neither of those two harnesses witnesses the
RDN parser's own accept path. Two other harnesses do, and they use no stub:
`x509_name::validate_name_single_atv_exact` (backing `[u8; 11]`) and
`x509_name::validate_name_two_atvs_exact` (backing `[u8; 19]`) each carry a satisfied `Ok` cover
through the real `validate_rdn` (bounded-backing evidence for those two shapes). The limitation that
remains is for the TBS and certificate compositions, whose witnesses run under stubs and cover the
glue only; their accept path is evidenced by `#[test]` cases.

[`DER-REMAINING-WORK.md`](DER-REMAINING-WORK.md) R2 records a further open residual: seven structural
harnesses were widened to symbolic input length in 2026-08-23; only the two rewritten by D33 got
covers. **The other five have none, so nothing witnesses that their widened loops iterate at all.** A
review asked for those covers before publish; the maintainer disclosed rather than fixed, and
recorded it as a judgement call. The covers are owed.

### 6.4 `set_of::no_over_read` now observes the shared child-walk cursor (`DER-C-SETOF-3`)

`decode_set_of` now drives the same `sequence::Elements` walk as SEQUENCE. Its read-only
`remaining()` view is used both by production, to delimit the whole raw child encoding for §11.6,
and by the proof, on a harness-owned instance, to observe the cursor before and after each child.
Production's use of the same call pattern is pinned by the exact-result equivalence harness:

| | drives | gets |
|---|---|---|
| `sequence::no_over_read` | `Elements` — the cursor is an observable field | per-child: the shipped advance is pinned to an independent oracle |
| `set_of::no_over_read` | a harness-owned `Elements` instance through the same `remaining()` accessor production uses | per-child: the harness-owned advance and raw ordering span are pinned to an independent oracle; production is tied to the pattern by exact equivalence |

The oracle carries its own offset and performs a fresh one-step `decode_tlv`; the iterator cursor
must land on `off + expected_used`. That assertion remains decisive for empty-valued children, where
comparing yielded value bytes cannot identify a boundary. The cursor harness covers symbolic
lengths `0..=6`, enough for three minimum-size children and repeated empty-value advances, while
avoiding the unrelated `cmp_padded` loops. Lean's `elements_next_progress` theorem covers one
accepted `Elements` step for a remaining slice of any length; it does not establish that the SET OF
loop exhausts arbitrary-length content. A separate exact-result harness checks SET OF's raw-span,
ordering, error-mapping, count, variants, and precedence against a proof-local copy of the previous
shipped walk over `0..=8` octets.

The old `no_over_read` harness also carried two claims that are no longer part of this cursor-only
harness. Its symbolic-length exact-tiling/count leg is carried by
`ordering_matches_whole_encoding_oracle` over `0..=8` octets (with the fixed-eight-byte
`ok_implies_exact_tiling` sibling retained). Its explicit value-at-child-tail byte comparison
remains in `sequence::no_over_read`; SET OF now checks the yielded `Tlv` against the independent
one-step decode but does not separately claim an unbounded value-at-tail theorem.

The new glue and cursor claim were each watched fail under a claim-named control: shortening
production's before/after cursor-delta span by one octet makes
`unsorted_children_are_rejected` fail, and shortening `Elements::next`'s advance by one octet makes
`set_of::no_over_read` fail at `new_off == off + expected_used`. Both edits were transient and the
base bytes were restored before the ordinary test suite.

### 6.5 Bounds versus reality (`DER-X-BOUND`)

The outermost parsers are proved panic-free on buffers **an order of magnitude smaller than a real
input**: `x509_certificate` at ≤12 bytes against a ~170-byte certificate, `rsa_private_key` at ≤20
bytes against a ~317-byte key. Real-size panic-freedom rests on a compositional argument that is
written down and reviewed but **not machine-checked**. This is the single largest gap between what
"210/210 verified" sounds like and what it is.

**The ≤12-byte bound is a CI-time floor, not a capability ceiling (measured 2026-09-17).** The same
`x509_certificate` outer-framing harness (TBS parser stubbed) was re-run at increasing buffer/unwind
bounds on a 62 GB host: it verifies panic-free at **N = 128** (≈28 min, ~15.5 GB) — 10.7× the shipped
12-byte bound — and N = 170 (a real certificate's size) did **not** exhaust memory, it exceeded a
1-hour solver budget. So the shipped bound of 12 is chosen for CI tractability (≈28 min per harness
blows CI's ~10-min cap), and a much larger bound is a reproducible capability, not a wall. Two honest
caveats keep this from being oversold: (1) the climb **stubs the TBS parser**, so the ≥128 result is
about the outer TLV framing, not a full-size certificate — the compositional argument above still
stands unchecked for the inner structure; and (2) the growth is super-linear, so N = 170 unstubbed is
a proof-*tractability* limit (the model checker self-diagnoses the state-space growth), not a tool
defect — it is not a solver/codegen bug.

**Frontier re-measured 2026-09-18.** The N=128 point was reproduced (unwind 136, ~16.9 GB, ~41 min)
and the bound was pushed further: **N=150 verifies panic-free** (unwind 158, ~21.1 GB,
~70 min) — a real extension past N=128, with cost growing super-linearly. **N=170 (real-certificate size)
is a solver-agnostic wall:** both cadical (>60 min) and kissat (>100 min) exceed budget without a verdict
(timeout, not OOM), so a stronger SAT solver does not extend reach — the limit is proof state-space, not
solver choice. All of this remains **TBS-stubbed outer framing**; it narrows the outer gap and does not
touch the inner-structure compositional argument. A bounded panic-freedom probe at a larger N is still a
probe (Law 6), recorded as a measured capability, never banked as a contract row. The N=128/150/170
climb logs are transient and kept local (available on request), not committed; the committed floor
artifacts are `evidence/check-d68eeca.log` and its three heavy companion logs (see §1).

### 6.6 The strongest and weakest layers are inverted relative to your risk

The framing and codec layers carry the `CONTRACT` and `CONTRACT+L4` rows. The X.509 layer — the part
you actually feed a hostile certificate to — is far weaker: its two framing sub-modules (`DER-X-ALGID`,
`DER-X-SPKI`) gained faithful-decode `CONTRACT` rows in 2026-09-17 Track B, and `x509_validity`, `x509_name` and
`x509_extension` carry bounded-backing exact-result `CONTRACT` rows at `d68eeca` (small bounds, stated per row). But the **cert-composition
modules you actually parse a certificate through** (`x509_certificate`, `x509_tbs_certificate`) still have **no conformance `CONTRACT` row**:
they are panic-freedom probes, two concrete rule tests, an inspection argument for realistic sizes, and
uncovered semantics, and three covers are still unsatisfied (§6.3), with the smallest bounds in the crate. (`DER-X-BOUND`,
§6.5: the `x509_certificate` outer-framing harness verifies panic-free at N=128 — reproduced 2026-09-17,
~41 min/16.9 GB — but N=170, a real certificate's size, exceeds a 1-hour solver budget; still
TBS-stubbed, so the inner-structure compositional gap stays open.)

That is not a defect; it is the honest cost curve — those are the 7–20 GB harnesses, and the crate
says so. It is invisible in "210 of 210", and visible in one glance here.

---

## 7. What "certified at `d68eeca`" means

The word is only worth something if it names a procedure, so here is the one that ran. It is
deliberately mechanical, because the point is that someone who does not trust the author can re-run
it.

1. **Freshness.** `git diff d68eeca -- check.sh der-verified/src der-verified/Cargo.toml Cargo.toml
   Cargo.lock rust-toolchain.toml .cargo der-verified/build.rs lean` → empty, with the toolchain pins in
   `PROOF_MANIFEST.md` §2 unchanged (the same command as §1; `lean/` matters for the L4 lid only).
   **That scoped command is a sufficient condition, not an iff** — no build input of the proof run has
   moved since the receipt, so the `d68eeca` evidence still applies to HEAD; if it is not empty, or a pin
   moved, the evidence is to be re-run, which is not the same as the evidence being wrong. The unscoped diff is *not* empty and is not supposed to be: it carries
   [`CHANGELOG.md`](CHANGELOG.md), [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md), the evidence logs, and
   this file and the gate change that introduced it. **A document is part of the tree it describes,
   so adding it necessarily makes the tree differ from the one the receipt was minted on.** That is
   why the freshness condition is scoped to the build inputs of the proof run rather than to the whole
   tree — and why a *push* receipt still needs a fresh full-gate run even though nothing here can
   change a proof.
2. **Counts re-derived, never re-typed.** Every *source-derived* number in §1 — harnesses, tests,
   doc-tests, lids, covers, entry points — came from `python3 gates/gen_proof_manifest.py --json` at
   HEAD. The receipt-specific figures beside them (tool versions, wall-clock, peak memory) are read
   out of the run log's own header instead, because they are properties of a run and not of the
   source; they are not re-derivable and are not claimed to be.
3. **Every `K` recipe re-checked, mechanically.** All 107 distinct harness paths named in the `verify`
   column were extracted from this file and checked twice: that the function still exists in the
   module it names at HEAD, and that a `Checking harness <H>...` line for it appears in
   `evidence/check-d68eeca.log` or in one of the three `evidence/check-d68eeca-heavy-*.log` companion
   logs (the 3 heavy harnesses appear only there). 105 of the 107 have the function and a line in the main log, which
   closed `Complete - 295 successfully verified harnesses, 0 failures, 295 total`; the remaining 2 are heavy
   harnesses (the third heavy harness is not named in a `K` recipe), and each of them has the function and its own `Checking harness <H>...` line in its companion log, which closes `Complete - 1 successfully verified harnesses, 0 failures, 1 total`. **107 of 107 passed both.**
4. **Every `A` recipe actually executed**, with its positive control. This is the step that found the
   broken profile absence-grep described in §4, and the step that re-*reading* rather than
   re-*running* would have skipped for a second time.
5. **`N`, `T`, `R` recipes spot-checked at HEAD.** The cited Lean theorems were located in the files
   named; the `test-only` rows' tests were located by name; the `R` rows' cover tallies were re-read
   out of the run logs — the three disclosed-unsatisfiable covers are still exactly `x509_validity`,
   `x509_extension` and `x509_tbs_certificate` and no others (`x509_validity::parse_never_panics` and
   `x509_tbs_certificate::parse_tbs_certificate_never_panics` read `0 of 1 cover properties satisfied` in
   the main log; `x509_extension::validate_extensions_never_panics` reads `0 of 1 cover properties satisfied` in its companion log), and `sequence::no_over_read` still
   reports `2 of 2 cover properties satisfied`.
6. **Split floor stated, not smoothed over.** The floor at `d68eeca` is 295 harnesses in one capped pass
   (with the Lean lid) plus 3 heavy harnesses in separate runs, 298 in all. There is no single-run
   298-harness floor, and nothing in this file claims one.

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

1. **Every row names either a runnable command or an explicitly-flagged inspection argument.** Most
   rows carry a command, and a hand-asserted row that names a command is falsifiable by you in one
   step. The rest carry recipe `D`, which says in as many words that **there is nothing to run** —
   those rows are arguments, and they are marked as arguments rather than dressed as checks. The
   distinction is the honest half of the promise: this file does not claim every row is mechanically
   checkable, it claims every row tells you which kind it is.
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

**cargo-mutants survivor disposition (2026-09-17).** A `cargo-mutants` run over the crate left 38
production-code survivors after filtering `proofs::` mutants (which `cargo test` cannot reach — a
`#[kani::proof]` line decides them, not a unit test). Most were closed by new `#[test]` fixtures
(the test count above moved accordingly). The rest are dispositioned here, not left silent:

- **Equivalent mutants — no test can distinguish them from the original:**
  - `length.rs` `|`→`^` in `encode_length` (`0x80 | n`, `n ∈ 1..=4`) and `decode_length`
    (`(val << 8) | octet`): the operands share no set bits, so `|` ≡ `^`. And `length.rs` `lead < 4`
    → `lead <= 4`: unreachable-guard equivalence — this line is reached only after the `len < 0x80`
    early return, so `be` is never all-zero and the loop always stops at `lead <= 3`; the `< 4` guard
    never has to prevent a `be[4]` read.
  - `set_of.rs:118` `cmp_padded` `>`→`>=`: reached only after the `a.len() == b.len()` branch already
    returned, so lengths are always unequal here and `>` ≡ `>=` for every reachable input. (The plan's
    hint that "≥4-byte slices expose it" does not hold — verified against the guarding code.)
  - `integer.rs:87`, `utf8_string.rs:150`, `tag.rs:148` — the same disjoint-bitfield `|` ≡ `^`
    pattern (annotated inline at those sites).
  - `identifier_form.rs` arm-15 deletion — falls through to the identical `_ => Unspecified`.
- **Disclosed residual — not equivalent, but no fast unit test distinguishes it:** `tlv.rs:110`
  `value.len() > u32::MAX as usize` is distinguishable from `>=`/`==` only by a `value` slice of
  length exactly `u32::MAX` (~4 GiB), impractical in a fast test. A Kani harness or a VM-run property
  test is the appropriate closer (see [`DER-REMAINING-WORK.md`](DER-REMAINING-WORK.md)).

The equivalent-mutant rationale for the **lid-covered** modules (`length`, `tlv`) is recorded here
rather than inline: a comment inside an Aeneas-extracted function shifts the extracted model's
embedded source spans and would (correctly) trip the Lean-lid drift gate.

**Related documents.** [`PROOF_MANIFEST.md`](PROOF_MANIFEST.md) — what is machine-checked, per module,
with bounds and stubs. [`ASSUMPTIONS.md`](ASSUMPTIONS.md) — the trusted base everything here stands
on. [`DER-REMAINING-WORK.md`](DER-REMAINING-WORK.md) — open residuals, including the ones cited above.
[`DECISIONS.md`](DECISIONS.md) — why scope boundaries are where they are. [`SECURITY.md`](SECURITY.md)
— reporting scope.
