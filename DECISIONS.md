# der-verified — contestable decisions ledger

A complete list of the **non-obvious / could-go-both-ways** design and adjudication calls in this
repo — the ones a competent reviewer might dispute. Each entry records the call, the tension, the
evidence (with online consensus where researched), a verdict, and a confidence. Policy: **where an
external consensus exists, we accept it** and carry a code note pointing here.

Related: per-module reviews in `reviews/`.

---

## D1 — Generic BIT STRING: trailing zero *bits* are PRESERVED, not stripped  ·  CONFIRMED (high)

**Call.** `bit_string::decode_bit_string` **accepts** a generic BIT STRING whose trailing *value* bits
are zero — e.g. `04 12 00` is the canonical encoding of the distinct **12-bit** value `0001_0010_0000`,
*not* a non-canonical form of the 8-bit `00 12`. It still **rejects** a non-zero *padding* bit in the
final octet (`NonZeroPadding`), and encodes the empty bit string as exactly `[00]`.

**Tension (why it can go both ways).** X.690 §11.2.2 bundles **two different rules** in adjacent
sentences, and they are routinely conflated:
1. *"Each unused bit in the final octet … shall be set to zero"* — the **padding** bits. Applies to
   **every** BIT STRING. (We enforce it.)
2. *"Where ITU-T Rec. X.680 …, [22.7], applies, the bitstring shall have all trailing 0 bits removed
   before it is encoded"* — strips trailing zero **bits**. The clause **"Where …22.7 applies"** means
   this holds **only for a `NamedBitList`** type (e.g. `KeyUsage`), *not* a plain BIT STRING.

One independent reviewer (rated HIGH) invoked rule 2 against a generic BIT STRING and
proposed a `NonCanonical` variant that would **reject `04 12 00`** — which would drop valid, distinct
values. The other reviewers did **not** make this error.

**Evidence / online consensus (researched 2026-07-03).** Unambiguous, and it is a *known* confusion:
- **IETF PKIX** thread *"DER encoding of BITSTRING"*: a PKIX participant made the identical error, was
  corrected — *"NamedBitLists have trailing zeros removed in DER, whereas plain BIT STRINGs don't"*;
  *"The DER-Encoding of a 'NamedBitString' implies that the trailing bits which are 0 must NOT be
  coded."* **No expert disagreement.**
  <https://mailarchive.ietf.org/arch/msg/pkix/PIgQp9CTvy88NLFeL5j31X9daLc/>
- **OSS Nokalva** (ASN.1 vendor) DER quick-reference: *"Unused bits in last octet are set to 0"*;
  *"Trailing 0s are not encoded for a named bit list"* (only); empty ⇒ one `00` octet.
  <https://www.oss.com/asn1/resources/asn1-made-simple/asn1-quick-reference/distinguished-encoding-rules.html>
- **mbed-TLS #1610** — the real-world "unused bits" bug was specifically about the **NamedBitList**
  write-path, reinforcing that trailing-zero-stripping is a named-bit-list concern.
  <https://github.com/Mbed-TLS/mbedtls/issues/1610>
- Let's Encrypt *"A Warm Welcome to ASN.1 and DER"* (padding-bits-zero, uniform intro).

**Verdict.** **ACCEPT** trailing zero bits for the generic codec (code is correct as shipped). NamedBitList
minimality (§22.7) and octet-alignment (e.g. `SubjectPublicKeyInfo.subjectPublicKey`) are **schema-layer**
constraints the caller applies — see the `require_octet_aligned` helper and the module docs. A prominent
warning lives at `decode_bit_string` pointing here (it is a commonly-mis-read point).

**Revisit if.** We ever add a typed/`NamedBitList` layer — that layer *must* enforce §22.7 minimality
(the opposite default), and this D1 boundary is exactly where the two meet.

---

## D2 — Deliberate range boundaries (documented deviations from full DER)  ·  settled (high)

These reject rather than panic, and are safe for X.509 (whose values sit far inside the bounds). A
strict-DER purist could dispute each; we accept the boundary and document it in-module.

| # | Module | Boundary | Rationale |
|---|--------|----------|-----------|
| D2a | `integer` | values must fit `i64` (≤8 content octets); longer minimal ints → `TooLarge` | X.509 versions/key-sizes/small serials fit i64; big serials need a future bigint type. |
| D2b | `length` | length value capped at `u32::MAX` (≤4 length octets); larger → `TooLarge` | X.509 objects are ≪4 GiB; avoids unbounded length arithmetic. |
| D2c | `tag` | tag number capped at `u32::MAX`; larger high-tag form → `TooLarge` | No real identifier approaches this; keeps decoding total. |

## D3 — Module altitude: content-level vs TLV-level  ·  settled (medium)

- `boolean`/`integer`/`null`/`oid`/`bit_string` validate **content** octets (tag/length already
  stripped by `tlv`) — they carry genuine *content* canonicality.
- `octet_string` composes **`tlv`** at the identifier level, because its only DER rule is *structural*
  (primitive-only, reject BER constructed `0x24`); it has no content canonicality.
- Contestable: one could argue for a uniform altitude. We chose "altitude follows where the constraint
  lives," and each module documents it.

## D4 — `decode_tlv` ignores trailing bytes (strict variant is separate)  ·  settled (high)

`decode_tlv` reads one TLV and returns bytes-consumed so it can drive recursive parsing;
`decode_tlv_strict` is the whole-blob-is-one-TLV variant. A top-level caller **must** use the strict
form (or check the returned length) or an attacker can append ignored data. Documented on both.
`sequence` follows the same pattern: `decode_sequence_tlv` (composable, ignores trailing) +
`decode_sequence_tlv_strict` (top-level, rejects trailing).

## D5 — SEQUENCE reader validates TLV *framing*, not per-child *content* canonicality  ·  settled (high)

**Call.** `sequence::decode_sequence` / `Elements` validate that the content is a concatenation of
well-formed child TLVs whose **framing** (identifier + length) is DER-canonical — that much is
inherited and *proven* by the `tag` and `length` codecs (non-minimal length `30 81 00`, high-tag
form `1F 02`, indefinite length are all rejected). They do **not** validate each child's **content**
canonicality (e.g. BOOLEAN TRUE must be `0xFF`, INTEGER must be minimal) — that is the job of the
typed content decoders (`boolean`, `integer`, …) the caller applies per child.

**Tension.** Reviewers flagged that a caller could misread
`decode_sequence` as "this SEQUENCE body is fully DER-valid" and then process children *without*
content-canonicality checks, letting a non-canonical child (e.g. `01 01 01` = a non-canonical
BOOLEAN TRUE) slip through. NB: their *length/tag*-canonicality examples (`30 81 00`, `02 81 01 07`,
`1F 02`) are **already rejected** — only *content* canonicality is deferred.

**Verdict.** KEEP the split (a shallow structural reader vs. typed content decoders — the natural
altitude, see D3). It is now **documented prominently** on `decode_sequence`, and a test
(`accepts_framing_but_not_content_canonicality`) memorializes that `01 01 01` passes framing while
`boolean::decode_bool` rejects it. **Confidence high** (clear design; the fix was documentation).

## D6 — SET is recognized but not decoded; §11.6 member-ordering NOT enforced  ·  settled (medium)

**Call.** The module exports `SET_TAG = 17` for tag checks and its `Elements`/`decode_sequence`
walk works on any constructed content, but it does **not** decode SET or enforce DER's §11.6
requirement that SET-OF members be sorted by their encoding. `decode_sequence_tlv` rejects a SET
identifier (`0x31`) as `WrongTag`.

**Tension.** Reviewers flagged that exporting `SET_TAG` + a generic
`Elements` over-advertises SET support and invites a caller to iterate SET content without the
ordering check — a real canonicality/malleability gap for SET.

**Verdict.** SET decoding + §11.6 ordering is **out of scope** for this SEQUENCE module; a future
`decode_set` with an ordering proof is its proper home. Reduced the over-advertising (SET_TAG kept
but clearly marked recognize-only; docs are SEQUENCE-focused). A test
(`unsorted_set_content_is_currently_accepted`) captures the gap explicitly. **Revisit when** a SET
decoder is added — it MUST enforce §11.6. **Confidence medium.**

---

## D7 — L4 "Lean lid": Aeneas-extracted *unbounded* proofs on the length codec  ·  COMPLETE (high)

**Call.** We added an independent **L4** verification lineage on top of the L3 Kani floor: the
`length` codec (§8.1.3) is extracted Rust → Charon → Aeneas → **Lean 4** and **ten** functional
properties (plus the loop invariant) are machine-checked in Lean **over inputs of *any* length** — the unbounded lid that Kani
(bounded to an 8-byte symbolic buffer) cannot reach. Artefacts live under `lean/`; the gate is
`lean/check_lean.sh` (wired into `check.sh`, guarded — see D8/README). Proven (`lean/LengthProofs.lean`),
each the ∀-length version of a specific Kani harness: *first-byte branches* — `decode_empty`,
`decode_indefinite` (0x80), `decode_reserved` (0xFF), `decode_short_form` (<0x80 accept); and the
**long-form *pre-loop* reject paths** — `decode_truncated_long`, `decode_nonminimal_leading_zero`,
`decode_toolarge` (proven via the WP-form `step` idiom through the `&0x7f` mask, the fallible `1 + n`
add, and the range-slice + `index_usize`). Additionally proven: the **value-decode loop invariant**
`decode_length_loop_spec` — the loop computes the big-endian value (`beVal`) of the ≤ 4 octets with no
`u32` truncation (via `loop.spec_decr_nat` + the `shl8_or_bv` bit-vector identity, `bv_decide`-checked).

**Tension (why it's contestable).**
1. **Assumed spec.** Aeneas emits `core::slice::<[T]>::first` as an *opaque axiom* (no builtin), so we
   add one trusted spec, `first_spec : first s = ok s.val[0]?` (its documented Rust semantics). A
   reviewer can rightly ask whether that spec is faithful — it is the single non-Std assumption, stated
   in one line, and every theorem's `#print axioms` lists it explicitly.
2. **Bounded floor vs unbounded lid.** These four properties are *also* Kani-proven (bit-precisely,
   ≤8 bytes). The L4 value is the **unbounded quantifier**, matching the prior-art position that
   Kani is bounded and the differentiator is the proof-assistant lineage. It is an honest *addition*,
   not a replacement — both lineages run in the gate (a cross-lineage divergence signal).
3. **Scope.** Every reject path that fires **before the value-decode loop** (the *syntactic*
   malformed-input surface) plus the short-form accept are proven ∀-length, the value-decode loop
   invariant is proven (`decode_length_loop_spec`), **and that invariant is now wired through
   `decode_length`'s *entire* long-form tail** (Round 4, below): `decode_long_form_accept`
   (canonical accept ⇒ `Ok(beVal ws, 1+n)`) and `decode_long_form_nonminimal_value`
   (`beVal < 0x80 ⇒ NonMinimal`, e.g. `[0x81, 0x01]`) — the two post-loop branches, each consuming
   the loop invariant via `step with decode_length_loop_spec`. **Every branch of `decode_length` is
   therefore now proven ∀-length.** The headline **round-trip canonicality**
   (`decode_accepts_only_canonical`) — a *different* theorem, additionally needing `encode_length`'s
   two loops (the inverse direction) — **is now also proven** (commit `3df98d8`; see the Round-6/7
   note and the Verdict below), so the length-codec L4 lid is **complete end-to-end**. The long-form
   reject theorems and `decode_long_form_*` carry an
   explicit `1 ≤ b&0x7f` (or `> 4`) precondition — honest: it is implied by the octet range (and, in
   the accept case, also by `beVal ws ≥ 0x80`) but stated to keep the proof's `scalar_tac` obligations
   bit-mask-free. (Two of the three cross-family reviewers independently caught the earlier "complete
   surface" overstatement — corrected in the header.)

**Trust accounting.** Every theorem's `#print axioms` shows `[propext, Classical.choice, Quot.sound,
first_spec, core.slice.Slice.first]` — the standard Lean/mathlib axioms + our one assumed spec + the
opaque external. The loop-invariant lemmas additionally show a **`bv_decide` native axiom**
(`shl8_or_bv._native.bv_decide.ax_*`) — the LRAT-checked SAT certificate for the one bit-vector
identity; a *verified* decision procedure, **not** a `sorry`. Crucially **no `sorryAx`** anywhere:
although Aeneas's *own* Std library carries a few `sorry`s (e.g. `Aeneas/Std/Slice.lean`), our proofs
do not depend on them. `first_spec` is the only spec we own.

**Verdict.** **KEEP** as a **complete** demonstration of the Kani-floor + Lean-lid **straddle** end-to-end
on one module — the crystal-grounding / differentiator the project is after. Round-trip canonicality
(`decode_accepts_only_canonical`) landed at commit `3df98d8` (re-verified from a clean re-extraction +
`lake build`, sorry-free), so **every branch of `decode_length` and the encode↔decode round-trip are
machine-checked at any length**, subsuming the corresponding L3 harnesses end-to-end. **Confidence high**
(the pipeline and all proofs — including the headline canonicality theorem — are solid and gated).

**Review** (`L4-lean-lid-01`, cross-family independent reviewers): unanimous "sound"; **no soundness defect**
found. One reviewer: no issues. Another: 1 low (a comment implied a full roundtrip where only the decode
half is proven — **fixed**). A third: flagged a `first_spec` by-reference concern at *high* that is a
leaf-context over-severity (Aeneas itself erased the shared borrow to `Option T`; value-equality is
faithful for this byte codec — now **documented**), and usefully asked to strengthen `decode_short_form`
from `∃v, v.val=b.val` to the exact returned value — **applied** (it now states `= ok (.Ok (UScalar.cast
.U32 b, 1))`, with a value-form corollary kept). Adjudicated; not auto-applied. Consistent with the
corpus pattern: convergent leaf-context severity inflation, small real signal.

Rounds 2–3 (`L4-lean-lid-02/03`, same reviewers), both **unanimous sound**: (2, long-form reject family)
most of the panel caught a real "complete surface" overstatement (fixed → "pre-loop"); a reviewer-unique
cfg-split drift-guard was **added**; the reviewers' "derive `hpos` via omega" fix was verified **infeasible**
(`scalar_tac`/omega lack bit-and) so the precondition stays explicit. (3, loop invariant) two reviewers
found **zero issues** (`beVal` faithful, the `n≤4 ⇒ no u32 truncation` argument correct); the third was
sound + suggested a semantic-drift hardening — the **Aeneas/Charon revision pin** was **added** to
`check_lean.sh`.

Round 4 (`L4-lean-lid-04`, long-form **tail** — `decode_long_form_accept` +
`decode_long_form_nonminimal_value`): **one independent reviewer this round** (the others' access was
unavailable, so *no* cross-reviewer correlation datum). The review: **verdict Sound, ZERO findings**
across all seven scope areas — statement faithfulness of
`Ok(beVal ws, 1+n)`; the `ws = (drop 1).take n` ↔ `List.slice 1 (1+n)` bridge (no off-by-one, `henough`
prevents truncation); non-vacuity (independently produced the same `[0x81,0x80]` / `[0x81,0x01]` witnesses
the author used); `if_neg`/`if_pos` branch selection; the `step with decode_length_loop_spec` trust base
(no new axiom/vacuity); honest canonicality scoping (behavior-not-biconditional); and the `hpos`
redundancy (benign, documented, load-bearing).

Round 5 (`L4-lean-lid-05`, **encode-side** loop invariants — first building blocks toward round-trip
canonicality): `encode_length_loop0_spec` (leading-zero scan ⇒ `lead` uniquely = leading-zero count)
and `encode_length_loop1_spec` (copies `be[lead+k] → out[1+k]` for `k<n`, preserves the rest). Both via
`loop.spec_decr_nat`; **trust base = `[propext, Classical.choice, Quot.sound]` only** (no `first_spec`,
no `bv_decide`). One independent reviewer (again the only reviewer available): **1 real finding (LOW)** —
`loop1`'s postcondition exposed only octet-0 preservation while the invariant already proved the *full*
`≥1+n` preservation; **APPLIED** (strengthened the postcondition to the full preserved-outside form, free +
matches the docstring). loop0 and the rest (faithfulness/non-vacuity/bounds/trust) unanimously sound;
adjudicated.

Round 6/7 (`3df98d8`, **round-trip canonicality — the final length-codec L4 milestone, now landed**):
the encode *functional* spec (`encode_length_long/short_spec`, composing the two loop invariants) + the
`to_be_bytes ↔ beVal` arithmetic bridge (`to_be_bytes_significant`, built from `leValB_toLEBytes` +
`beVal_inj` — the research-grade part) + the roundtrip composition (`roundtrip_long/short`) + the headline
`decode_accepts_only_canonical` (a full forward-WP walk of decode's CFG dispatching to the roundtrips).
Sorry-free; trust base adds three LRAT-checked `bv_decide` native axioms (`bv_or_0x80` / `shl8_or_bv` /
`u8_high_bit_decomp`) — no `sorryAx`. First full 3-reviewer pass on a lean-lid: two reviewers SOUND(0),
the third's one unique finding **verified a false positive** (a speculative `leValB_toLEBytes` `w<8`
concern, refuted by machine-check + majority agreement). **The length-codec L4 lid is now complete.**

**Revisit if.** Aeneas gains a builtin for `slice::first` (drop `first_spec`). The length-codec L4
milestones are otherwise all met: every decode branch, the long-form tail, and round-trip canonicality
are proven ∀-length (the lid subsumes the corresponding L3 harnesses end-to-end). The next L4 *breadth*
step is a second module's lid (see the reassessment note / a future D-entry), not further work on `length`.

---

## D8 — Extraction via a nightly-pinned, workspace-excluded shim crate (no source copy)  ·  settled (high)

**Call.** Charon needs its own pinned nightly (`nightly-2026-06-01`) to drive extraction, but
`der-verified` pins `stable` and its Kani gate must stay pristine. Rather than copy `length.rs` (drift
risk) or repoint der-verified's toolchain (gate risk), we added `lean/extract/` — a tiny crate that
`#[path]`-includes the *same* `../../../der-verified/src/length.rs`, carries its own
`rust-toolchain.toml = nightly-2026-06-01`, and is **excluded** from the root Cargo workspace.

**Tension.** A reviewer could argue the shim is indirection, or that `#[path]`-including a file across
crates is unusual. The alternative (a copy) is worse: it would let the proven Lean model silently
diverge from the shipped, Kani-proven source.

**Verdict.** **KEEP.** Single source of truth (one `length.rs`), so the L4 lid provably concerns the
exact bytes the L3 floor proves; the workspace exclude + separate pin keep `cargo test`/`cargo kani`
on stable and untouched. `check_lean.sh` re-extracts on every run and **fails on drift** vs the
committed `DerLengthExtract.lean`, closing the loop (extraction verified deterministic). **Confidence high.**

---

## D9 — Time types: leap second `SS=60` is REJECTED (a deliberate profile narrowing)  ·  settled (medium)

**Call.** `utc_time::decode_utc_time` (§11.8) and `generalized_time::decode_generalized_time` (§11.7)
reject a seconds field of `60`, returning `SecondRange`. The accepted second range is `00..=59`.

**Tension (why it can go both ways).** The X.680 base type for both `UTCTime` and `GeneralizedTime`
follows ISO 8601 and **permits `60`** in the seconds position to denote a positive **leap second**
(`23:59:60Z`). X.690 §11.7/§11.8 add DER canonicality rules (seconds-present, `Z`-terminated,
no-trailing-zero fractions) but do **not** further restrict the second's value range. So a strict
reading of "DER canonical form" would *accept* `SS=60`, and rejecting it is a deviation from the
unrestricted base type — not a raw DER rule. (The task brief that seeded this module described `60`
as something "DER forbids"; verification against X.680 showed that is imprecise — hence this entry.)

**Evidence / consensus.** RFC 5280 §4.1.2.5 requires seconds present and `Z`, and is **silent on leap
seconds**; real-world X.509 `notBefore`/`notAfter` values never carry one, and mainstream validators
parse the field into a normal time type (`00..=59`), so `...60Z` is a value a strict signer never emits
and a lax parser might accept — the classic parser-differential shape this library exists to close.

**Verdict.** **REJECT `SS=60`** for the X.509 anti-differential profile (owner-confirmed, 2026-07-05).
The proof oracle (`is_canonical_der_*`) encodes this narrowing, and its docstring was **sharpened** to
say so after reviewers correctly flagged that an earlier "straight from
X.690 §11.8 + X.680" claim over-stated fidelity to the *unrestricted* base type (the biconditional
proves `accepted == this-profile-canonical`, not `== raw-X.680`). A dedicated harness
(`second_range_is_classified`) and a seeded test (`rejects_leap_second_60`) memorialize it.
**Confidence medium** (clear design; "medium" reflects that a purist could keep `60` and defer leap-second
handling downstream — the contestable half we own here).

**Revisit if.** A consumer needs to ingest a non-X.509 GeneralizedTime that legitimately carries leap
seconds; that caller would need a `60`-permitting variant (and a downstream leap-second policy).

---

## D10 — Time types: content-level altitude; single-field ranges IN, calendar validity + profile rules OUT  ·  settled (high)

**Call.** The time codecs validate the **content** octets of a UNIVERSAL-23/24 TLV (the tag identity
and primitive/definite form are inherited and *proven* by `tag`/`tlv`, per D3), and enforce:
- the DER **canonical string form** — `YYMMDDHHMMSSZ` (UTCTime) / `YYYYMMDDHHMMSS[.fff]Z`
  (GeneralizedTime): `Z`-terminated (no local time, no offset), seconds mandatory, and for
  GeneralizedTime a **canonical fraction** (point separator not comma; ≥1 digit; no trailing zeros;
  an all-zero fraction and its `.` omitted entirely; a *leading* zero is significant, so `.01` is
  canonical and `.10` is not);
- **single-field ranges** — month `01..=12`, day `01..=31`, hour `00..=23` (so `24`, the forbidden
  "midnight at end of day", is rejected), minute `00..=59`, second `00..=59` (see D9).

They deliberately do **not** enforce, all as **out-of-scope date-semantics / profile** concerns:
- **cross-field calendar validity** — `day` is uniformly `01..=31`; `990231235959Z` (Feb-31) is
  accepted at this layer. Leap-year / per-month-length checks are a calendar concern above the encoding.
- **RFC 5280 no-fractional-seconds** (§4.1.2.5.2) for X.509 — generic DER *permits* a canonical
  fraction, so `decode` accepts one; the profile rule is a **caller-applied** check,
  `generalized_time::require_no_fraction` (the same generic-syntax-vs-profile split as `bit_string`'s
  `require_octet_aligned`, D1).
- **the RFC 5280 century mapping** (`YY < 50 ⇒ 20YY`) — a profile interpretation, exposed as
  `utc_time::full_year_rfc5280`, not folded into `decode` (which returns the raw `year2`).

**Tension.** One could argue field-range checks are already "semantics" and should also be deferred, or
conversely that calendar validity belongs here. We draw the line at **single-field syntactic ranges IN,
cross-field/calendar/profile OUT**: the former are what distinguish a well-formed time *string* from
garbage (and include the §11.8 midnight rule via `hour ≤ 23`); the latter depend on a calendar or an
X.509 profile the transfer-syntax codec should not assume.

**Verdict.** **KEEP** the split; documented in both module headers and here. The canonicality oracle is
proven to equal exactly this accepted set (`accepted_iff_canonical_oracle`), de-tautologized against an
independent §11.7/§11.8 predicate. **Confidence high.**

**Revisit if.** A typed X.509 date layer is added — it would apply `require_no_fraction`,
`full_year_rfc5280`, and calendar validity on top of these codecs, and this D10 boundary is where the
two meet.

---

## D11 — Restricted strings: one shared module closing BOTH the charset and constructed-form differentials  ·  settled (high)

**Call.** `restricted_string` covers all four ASCII-restricted X.509 string types —
`PrintableString` (UNIVERSAL 19), `IA5String` (UNIVERSAL 22), `NumericString` (UNIVERSAL 18),
`VisibleString` (UNIVERSAL 26) — as **one** generic module: a `Charset` enum carrying each type's tag
number/identifier/character-set predicate, plus a single `validate_content` / `decode_restricted_string`
/ `encode_restricted_string_into` core parameterized over it, rather than four near-duplicate modules.
The module operates at the **TLV level** (like `octet_string`, D3) so it closes *two* differentials at
once in one place: the **content-level** rule (every octet must be in the type's X.680 character set)
and the **structural** rule (DER forbids the BER constructed/segmented string form — the same
parser-differential vector `octet_string` closes for `0x24`; here the four constructed identifiers are
`0x33`/`0x36`/`0x32`/`0x3A`).

**Boundary.** In scope: **charset-validity only** — for these types the octets *are* the value (no
"minimal encoding" concept, unlike integers/lengths), so charset-membership is the sole content-level
DER rule. **Empty content (zero octets) is accepted** (vacuously charset-valid). Out of scope, as a
caller-applied X.509 **profile** layer (the same altitude split as the time types, D10): `SIZE`/length
constraints, and the `DirectoryString` CHOICE rule (which of these types, plus `TeletexString`/
`UTF8String`/`BMPString`, an attribute may use). Those are policy decisions above the transfer syntax,
not encoding rules.

**The four character sets (verified first-hand against ITU-T X.680, not folklore):**
- **PrintableString** — *exactly* 74 bytes: `A`-`Z`, `a`-`z`, `0`-`9`, SPACE, and only the 11 marks
  `' ( ) + , - . / : = ?`. **Trap:** it excludes `@ * _ & !` and every other ASCII punctuation/symbol —
  an implementation that widens the set (e.g. by using a generic "printable ASCII" range) admits a
  parser differential a strict signer never produced.
- **IA5String** — the full 7-bit set, `0x00..=0x7F` (control characters included); `>= 0x80` invalid.
- **NumericString** — digits `0x30..=0x39` and SPACE (`0x20`) **only**. **Trap:** it excludes hyphen
  `-` and colon `:`, which a lax parser modeling this as "digits plus common date/number punctuation"
  would wrongly admit.
- **VisibleString** (ISO646String) — the graphic subset `0x20..=0x7E` (SPACE through `~`); excludes
  control characters and DEL (`0x7F`).

**Tension.** One could instead give each type its own module (matching `utc_time`/`generalized_time`
being separate despite sharing structure) — that would make each module's doc comment fully
self-contained at the cost of four-fold duplication of the TLV-composition logic and the constructed-
form rejection, and four chances to typo a charset independently rather than one shared, single
`contains` per variant that the Kani oracle proofs pin down exactly. We chose the shared module because
the *only* thing that varies across the four is the tag number and the charset predicate — everything
else (TLV composition, the constructed-form rule, the error shape) is identical, so factoring it once
is "altitude follows where the constraint lives" (D3) applied to a family, not a single type.

**Evidence.** The charset boundaries were checked directly against ITU-T X.680 (clause 41 basic types)
rather than taken from secondary sources, specifically to catch the two known traps above (an early
mental draft of this task brief itself mis-stated the trap bytes before verification). The Kani proof
suite includes, per charset, a `charset_exactly_matches_oracle_*` harness whose oracle is written in a
*syntactically different* shape from the production `Charset::contains` (e.g. PrintableString: an
explicit 74-way byte disjunction vs. production's ASCII-class-helper + punctuation `matches!`; IA5:
`b <= 0x7F` vs. production's `b & 0x80 == 0`; Numeric: `matches!(b, b'0'..=b'9') || b == 0x20` vs.
production's `is_ascii_digit`; Visible: a range `contains` vs. production's explicit `>=`/`<=`) — so a
typo in either formulation cannot hide behind the other, machine-checked over all 256 byte values.

**Verdict.** **KEEP** the shared-module design and the charset sets exactly as stated (no widening).
Confidence **high**: the four charsets are directly checked against the standard text, and the
de-tautologized oracle proofs (`charset_exactly_matches_oracle_{printable,ia5,numeric,visible}`) close
the "trusted the parser's own predicate" gap the same way the time-type oracles do (D10).

**Revisit if.** A `DirectoryString`/attribute-profile layer is added on top — it would apply the
`SIZE` constraint and the CHOICE-of-string-type rule using these codecs as its primitives, the same way
an X.509 date layer would sit on top of `utc_time`/`generalized_time` (D10's "Revisit if").

---

## D12 — UTF8String: its own module (multi-byte well-formedness, not a `Charset` variant)  ·  settled (high)

**Call.** `utf8_string` covers DER UTF8String (UNIVERSAL 12) as a **separate** module from
`restricted_string`, even though both are TLV-wrapped byte-string types that reject the BER
constructed form. The reason is altitude, not convenience: `restricted_string`'s four charsets are
each a **per-byte** membership predicate (`contains(b: u8) -> bool`, checked independently at every
position), whereas UTF-8 well-formedness (RFC 3629 / Unicode §3.9, Table 3-7) is a **multi-byte
structural** property — a lead byte commits to a sequence length, and the *valid range of the very
next byte* depends on which lead byte started the sequence (the `E0`/`ED`/`F0`/`F4` narrowed second-
byte rows). That does not fit the `Charset` enum's per-byte shape, so it gets its own module and
validator rather than a fifth `Charset` variant.

**Boundary.** In scope: content-level UTF-8 well-formedness, plus the same structural rule as
`octet_string`/`restricted_string` — DER forbids the BER constructed/segmented form (identifier
`0x2C`). **Empty content is accepted** (the empty string is well-formed UTF-8, vacuously). Out of
scope, as caller-applied **profile** concerns (the same altitude split as D10/D11): Unicode
**normalization** (NFC/NFKC — a PKIX name-*comparison* rule per RFC 5280/6125, not a DER encoding
rule), `SIZE`/length limits, and the `DirectoryString` CHOICE (which of `UTF8String`/
`PrintableString`/... an attribute may use). Unlike a "shortest form" question layered on top of an
already-valid encoding (e.g. DER integers), **well-formed UTF-8 has exactly one valid byte sequence
per code point** — an overlong form is *invalid*, not a non-canonical alternate spelling of a valid
one — so well-formedness itself already *is* the canonicality property; there is no separate
canonical-form check to add on top.

**The rules (verified against RFC 3629 / Unicode Table 3-7, not folklore), and the differential
classes closed:**
- **Overlong encodings** — `E0 80..9F ..` / `F0 80..8F .. ..` (and lead bytes `C0`, `C1`, which are
  *always* overlong 2-byte forms) would re-encode a code point representable in fewer bytes. Closed
  by narrowing `E0`'s second byte to `A0..BF` and `F0`'s to `90..BF`, and rejecting `C0`/`C1` as leads
  outright.
- **UTF-8-encoded surrogates** — `ED A0..BF ..` would encode `U+D800..U+DFFF`, which are not scalar
  values (they exist only as UTF-16 surrogate halves). Closed by narrowing `ED`'s second byte to
  `80..9F`, and independently by the production decoder's explicit `0xD800..=0xDFFF` code-point check.
- **Beyond `U+10FFFF`** — `F4 90..BF .. ..` would exceed the Unicode range, and lead bytes `F5..FF`
  are always beyond it. Closed by narrowing `F4`'s second byte to `80..8F`, rejecting `F5..FF` as
  leads, and independently by the production decoder's `cp > 0x10FFFF` check.
- **Lone/truncated continuation bytes** — a `10xxxxxx` byte as a *lead* (stray continuation), or a
  multi-byte sequence whose continuation bytes run past the end of the content. Closed by
  `sequence_len` returning `None` for the former and an explicit length check before consuming
  continuation bytes for the latter.

**De-tautologization.** Production `validate_utf8` and the Kani oracle `oracle_wellformed_utf8` are
written in **deliberately different representation spaces**, so a bug in one cannot hide behind the
same bug in the other:
- **Production** is a **value-space decoder**: read the lead byte, derive the sequence length from
  its bit pattern (`0xxxxxxx`/`110xxxxx`/`1110xxxx`/`11110xxx`), require that many continuation bytes
  present and in `0x80..=0xBF`, **compute the code point** by the standard bit-shifts, then check the
  *code point* against shortest-form/surrogate/max-range conditions.
- **The Kani oracle** states Table 3-7 directly as **byte-range matching** — no code-point
  arithmetic, no bit-shifts at all — consuming 1/2/3/4 bytes per the matched row.
- A **third, independent lineage** reinforces both: every concrete seeded-bad specimen in the test
  suite additionally asserts agreement with `core::str::from_utf8` (the standard library's own RFC
  3629 validator, a wholly different code path — internally fast-path/table-driven rather than either
  of the above). This cross-check is a plain `#[test]`, not merely the optional Kani harness, so it
  holds even if the Kani formulation were ever dropped.

**Evidence.** Table 3-7 was reproduced directly from the Unicode Standard / RFC 3629 text (not
secondary summaries), specifically checking the four narrowed-second-byte rows (`E0`, `ED`, `F0`,
`F4`) since those are exactly where the differential classes above live and where a naive
"lead-byte-pattern + `0x80..=0xBF` continuation-byte range for every non-first byte" implementation
would silently admit overlong/surrogate/beyond-max encodings. The Kani proof suite includes
`validate_iff_oracle` (single code point, `[u8;4]`, de-tautologized against Table 3-7),
`validate_iff_oracle_multi` (`[u8;6]`, catches state-reset bugs across sequences), and
`validate_iff_std` (agreement with `core::str::from_utf8` — kept because it verified cleanly, ~5s, no
unwind-bound trouble with std's internals), plus round-trip, never-panics, constructed-form-rejected,
identifier-canonicality, wrong-tag, and error-position-correctness harnesses.

**Verdict.** **KEEP** the separate module and the rules exactly as stated (no widening/narrowing).
Confidence **high**: Table 3-7 was checked directly against the standard, the production/oracle
formulations are genuinely different shapes (decoder vs. byte-range table), and a third independent
lineage (`core::str::from_utf8`) cross-checks every concrete specimen.

**Revisit if.** A `DirectoryString`/attribute-profile layer is added on top — it would apply
normalization, the `SIZE` constraint, and the CHOICE-of-string-type rule using `utf8_string` and
`restricted_string` as its primitives, the same way an X.509 date layer would sit on top of
`utc_time`/`generalized_time` (D10/D11's "Revisit if").

---

## D13 — SET OF (§11.6) gets its own module; general SET (§10.3) stays out of scope  ·  settled (high)

**Call.** `set_of` implements X.690 §11.6 — DER/CER's requirement that a **SET OF**'s child
encodings appear in a specific padded-comparison order — closing the gap `DECISIONS.md` D6 flagged
and deliberately left open when `sequence` was built. It is a new module, not an extension of
`sequence`, because the ordering check needs each child's **raw whole-TLV byte span** (identifier +
length + value), whereas `sequence::Elements` only ever yields the decoded `Tlv { tag, value }` —
a different walk, not just a different predicate layered on the same one.

**Boundary — SET OF (§11.6) is IN scope; general SET (§10.3) is OUT, same boundary class as
D10/D11/D12.** X.690 has *two* member-ordering rules that are easy to conflate:
- **§10.3** (general SET, DER/CER): components are ordered by the **tag** that the ASN.1 module's
  schema assigns to each field (a heterogeneous, per-field-type order). This crate is schema-free —
  it never sees the ASN.1 module — so it structurally *cannot* implement §10.3.
- **§11.6** (SET OF, DER/CER): a **homogeneous** repetition of one component type, ordered by
  **encoding** — comparing the raw bytes with no schema needed. This is implementable schema-free,
  and is exactly what this module does.

  Because both share the same wire tag (UNIVERSAL 17, identifier `0x31`/`0x11`), it would be easy
  for a caller to assume "SET support" covers both. Everything in this module is named around "SET
  OF" specifically (`decode_set_of`, `SetOfError`, …) rather than bare "SET", precisely to avoid
  the over-advertising trap D6 already flagged once for `sequence`'s `SET_TAG` export. Per-child
  **content** canonicality remains out of scope too (the D5 boundary, extended): `decode_set_of`
  validates child TLV *framing* and inter-child *ordering*, not each child's own canonical form.

**The rule, quoted verbatim (X.690 §11.6, "Set-of components"):**
> "The encodings of the component values of a set-of value shall appear in ascending order, the
> encodings being compared as octet strings with the shorter components being padded at their
> trailing end with 0-octets. NOTE – The padding octets are for comparison purposes only and do not
> appear in the encodings."

"The encodings of the component values" = the **complete TLV bytes** of each child (identifier +
length + value), per clause 8's use of "encoding" throughout (e.g. 8.9.2 for SEQUENCE) — not just
each child's value/content octets. **Why `slice::cmp`/`Ord` on `&[u8]` is wrong here:** Rust's
default byte-slice comparison treats a strict prefix as *less than* the longer string, with no
padding — e.g. `[0xAA].cmp(&[0xAA, 0x00])` is `Less` under `slice::cmp`. Under §11.6's padded rule
the same pair is `Equal` (see below). Using `slice::cmp` directly would therefore silently accept
some genuinely misordered SET OF values (or reject some correctly-ordered ones) whenever a
shorter/longer pair's shared prefix matches but the longer one's tail happens to be zero. `cmp_padded`
implements the padded rule explicitly: compare the shared prefix byte-by-byte; if it's all equal and
the lengths differ, treat the longer operand's extra tail as being compared against implicit
zero-padding on the shorter one (never against "nothing").

**Non-strict ("ascending", not "strictly ascending").** Nothing in X.690 forbids two distinct SET OF
*members* from having byte-identical DER encodings (e.g. two INTEGER members both encoding the value
5 — the SET OF's element type doesn't have to be unique-valued). An ordering check that rejected
adjacent equal encodings would therefore incorrectly reject valid SET OF values that happen to
contain duplicates. `decode_set_of` accepts ties: for every adjacent pair,
`cmp_padded(child[i], child[i+1]) != Greater` (both `Less` and `Equal` pass).

**A documented spec quirk, not a defect.** Because the padding is virtual and zero-filled, the
padded rule can make two byte-for-byte **different** encodings compare **equal**: if the shorter
encoding is an exact prefix of the longer one, and every byte in the longer one's non-shared tail is
`0x00`, they compare equal under §11.6 even though their raw bytes differ. Concretely,
`cmp_padded(&[0xAA, 0x00], &[0xAA]) == Equal` (tested explicitly in `set_of::tests`). This is an
accepted property of the spec's own comparison rule, not a bug to "fix" — a stricter comparator that
refused to consider these equal would be **implementing something other than §11.6**.

**De-tautologization.** Production `cmp_padded` and the Kani oracle are written in deliberately
different representation spaces:
- **Production** (`cmp_padded`) is **incremental**: walk the shared prefix index-by-index looking for
  the first differing byte; if none differs and the lengths differ, walk only the longer operand's
  extra tail checking each byte against literal `0`.
- **The oracle** (`cmp_padded_oracle`, Kani-only) **materializes** both operands into fixed-size
  zero-initialized arrays first (copying each operand's actual bytes in, leaving the rest as the
  zero-init default — i.e. the padding is *physically present* in the array rather than checked
  branch-by-branch), then compares the two same-length padded arrays with a single index-by-index
  scan.

  These are genuinely different code shapes — one branches on "did the lengths differ", the other
  never does (it always compares two arrays of the same fixed size) — so an off-by-one in
  production's tail-zero check, or a flipped `Greater`/`Less` return, would not be mirrored by an
  identical bug in the oracle. `cmp_padded_matches_oracle` is the direct biconditional proof (Kani,
  symbolic lengths `0..=3` each); `ordering_iff_oracle` is the same idea lifted to the full decode
  path — `decode_set_of` on two concatenated symbolic-content NULL TLVs accepts iff the oracle says
  the pair is not (padded-)greater — so a bug in either `cmp_padded` or in how `decode_set_of` wires
  it into the adjacent-pair walk would be caught.

**Maximality of `Unsorted { index }`.** The same lesson `utf8_string`'s `IllFormed { position }`
already encodes (see D12's proof, `ill_formed_reports_position`): an index/position field in an
error is not fully specified by "some index that's within bounds" — a lazy implementation that
always reported `index: 0` on any violation would satisfy a weaker "there exists a violation at or
before this index" clause. Applied proactively here:
`unsorted_reports_first_violation_index` uses three children where the first adjacent pair is
properly ordered and only the *second* pair (index 1) violates §11.6, and asserts the reported
index is exactly `1` — not just "some `Err`".

**Evidence.** §11.6 was read directly from the X.690 text (quoted verbatim above), cross-referenced
against §8.9–8.12 (constructed-type encoding) and §10.3 (the general-SET tag-ordering rule it is
*not* implementing) to confirm the altitude split. Kani harnesses: `iterate_never_panics`,
`no_over_read`, `ok_implies_exact_tiling` (mirroring `sequence.rs`'s three structural proofs
verbatim, adapted to `SetOfError`); `ordering_iff_oracle` and `cmp_padded_matches_oracle` (the
de-tautologized security property); `unsorted_children_are_rejected`,
`unsorted_reports_first_violation_index` (maximality), `duplicate_adjacent_encodings_are_accepted`
(the non-strict design), `tag_correctness`, `accepted_identifier_is_canonical_0x31`,
`strict_rejects_trailing`, `roundtrip_two_sorted_children`. All pass; zero warnings.

**Verdict.** **KEEP** as a dedicated module scoped strictly to §11.6. Confidence **high**: the text
was checked directly (not folklore), the non-naive padded comparator is implemented and proven
against an independently-shaped oracle, the non-strict/tie-permitting interpretation is required by
the spec's own silence on duplicate members (not a convenience relaxation), and the maximality gap
class (from this session's own reviewer feedback on a different module) was applied proactively
rather than waiting to be caught.

**Revisit if.** A general (non-SET-OF) SET decoder is ever wanted — it would need the ASN.1 schema's
per-field tag assignment (§10.3) as an *input*, which is a different API shape entirely (this crate
would need to accept a schema, not just bytes) and does not belong in this schema-free module.

**Addendum (post-adjudication) — `cmp_padded`'s tail-padding branch is real but likely
unreachable via `decode_set_of` on genuine canonical children.** Both external reviewers (and,
independently, this addendum's author) probed whether `decode_set_of`'s end-to-end proof suite
should exercise a case where §11.6's zero-*padding* logic (as opposed to the ordinary equal-length
shared-prefix comparison) actually decides an acceptance — e.g. two children whose encodings are
`[0xAA]` and `[0xAA, 0x00]`, which compare `Equal` under `cmp_padded` (already unit-tested at the
function level). One reviewer proposed a concrete two-child example to test this at the
`decode_set_of` level; **that example is wrong** — `[0x04, 0x01, 0x41]` and `[0x04, 0x02, 0x41, 0x00]`
do *not* stand in a "prefix + zero tail" relationship (their length octets, `0x01` vs `0x02`, differ
at byte offset 1, so `cmp_padded` returns `Less`, not `Equal` — verified by hand-tracing the
algorithm, not merely by inspection).

Investigating *why* the proposed construction fails surfaces a genuine, previously-undocumented
structural fact: **DER's canonical (minimal) tag + length encoding is effectively a *prefix-free*
code.** For any two complete, canonically-encoded TLV byte-spans of *different total length*, their
shared-prefix comparison always diverges no later than the length field:
- Short-form lengths (`0x00`–`0x7F`) encode the length *value* directly as the byte itself, so two
  different length values are, by construction, different bytes at that position.
- Long-form vs. short-form (or long-form vs. long-form with a different octet-count) diverge at the
  very first length octet, since DER's minimality rule forbids a non-minimal long form (`0x81 0x01`
  is rejected — length 1 *must* be the short form `0x01`), so the number of length octets is
  determined solely by the length value, and the leading long-form octet (`0x80 | n`) directly
  encodes that count.
- A parallel argument holds for the identifier octets: high-tag-number continuation octets always
  set bit 8 except on the *terminal* octet, while a genuine single-octet low-tag identifier's low 5
  bits are never the `11111` escape pattern — so a low-tag identifier can never be a byte-prefix of
  a high-tag one either.

Consequently, two children of different total byte-length always diverge strictly *within* their
shared tag+length header — i.e. within the `n = min(len)` window `cmp_padded`'s shared-prefix loop
already scans — so the tail-padding branch (comparing the longer operand's extra bytes against
implicit zero) is **never reached** when both operands are genuine `decode_tlv`-derived children.
This was checked against several concrete constructions (varying content length within short-form,
crossing the short/long-form boundary, and varying high-tag continuation depth) — no counterexample
found.

This does **not** mean the tail-padding branch is unnecessary: `cmp_padded` is a general-purpose
`pub fn` over *arbitrary* byte slices, not gated to valid TLV spans, and §11.6's own text describes a
general octet-string comparison procedure — the branch is required for `cmp_padded`'s correctness as
a standalone function, and is properly tested exactly there (`cmp_padded_equates_prefix_with_zero_tail`,
`cmp_padded_matches_oracle`, `cmp_padded_oracle`), independent of whether real TLV children ever reach
it. It means the `decode_set_of`-level "security property" proof (`ordering_iff_oracle`) legitimately
covers only the equal-total-length case *not* because of a proof gap, but because that is structurally
the only case reachable through real canonical children — the interesting padding logic is correctly
proven one layer down, at the comparator itself. **No code change; this is a documentation-only
addendum recording a verified, non-obvious fact so it is not mistakenly re-opened as a coverage gap.**

---

## D14 — Arbitrary-magnitude INTEGER (`big_integer`): a separate module, not a widened `integer` cap  ·  settled (high)

**Call.** `big_integer` validates DER INTEGER content (§8.3, same UNIVERSAL 2 tag as `crate::integer`)
at **any** magnitude — no 8-octet cap — closing the D2a "future bigint type" gap for real X.509
serial numbers (RFC 5280 §4.1.2.2 practice keeps these within ~20 octets; the DER encoding rule
itself has no upper bound at all). It is a **new module**, not a widened `integer::TooLarge` cap,
because the two serve genuinely different use cases with different natural output shapes:
`integer` materializes a value into `i64` for small numeric fields that are actually computed on
(protocol versions, key sizes); serial numbers are **opaque, comparison-only identifiers** — nothing
in X.509 ever adds, subtracts, or otherwise arithmetic-operates on a serial number — so materializing
one into a numeric type is the wrong shape as well as unnecessary. `big_integer` instead validates
minimality and hands back the validated content bytes themselves (for storage/equality/ordering)
plus a cheap sign check, never a bignum value. **`integer`'s `i64` cap stays exactly as it was** —
this is an addition alongside it, not a replacement (the D2a table row is superseded only in the
sense that "big serials need a future bigint type" is now delivered, not in the sense that the `i64`
module's own boundary was wrong).

**The locality insight this module is built on.** DER INTEGER minimality (§8.3.2 — the leading octet
and bit 8 of the second octet must not be all-zero or all-one) is a **local** property of only the
*leading one or two octets* of the content — the check never inspects anything from index 2 onward.
`crate::integer::decode_integer`'s existing minimality check is already exactly this local rule,
completely unmodified by its subsequent `i64` cap; only `content.len() > 8 -> TooLarge` and the
i64-materialization are what bound *that* module to small integers. `big_integer` keeps the identical
minimality rule verbatim and simply drops the cap — any content length is structurally valid DER.
This is machine-checked directly, not merely asserted: `minimality_is_local` constructs two symbolic
buffers that agree on their leading two octets but differ arbitrarily from index 2 on, and proves
`validate_integer_content` returns the *same* verdict for both — the tail is provably irrelevant.

**The Kani bound `N = 20` is representative, not limiting.** Every proof in this module is either a
claim about the leading one-or-two octets specifically (which `minimality_is_local` shows generalizes
to any length) or an explicit statement that everything past index 1 is free — so raising `N` further
would enlarge the state space Kani explores without changing what property is established; the
proofs characterize *the rule*, not *this specific buffer size*. `N = 20` was chosen to match RFC
5280's practical serial-number width, giving the test/proof suite a directly X.509-relevant scale
(the concrete tests include a 20-octet serial `crate::integer::decode_integer` would reject as
`TooLarge`, and its 21-octet non-minimal-padded counterpart) while staying comparable to the widths
already used by this crate's other symbolic-content proofs (13–19 octets for the time types) — the
same "bounded floor, length-uniform logic" argument `sequence.rs`'s buffer-sizing comment makes for
its own coverage envelope.

**The canonicality proof, without a materialized value.** Since no numeric type is produced, "decode
accepts only the minimal encoding" is restated as: **accepted content is a fixed point of an
independently-implemented minimizer.** `encode_minimal_integer_into` normalizes *any* two's-complement
byte string (e.g. from a bignum library or a raw serial-number generator that may not itself be
DER-minimal) down to the minimal form by stripping redundant leading padding — `crate::integer::
encode_integer`'s stripping loop, generalized from a fixed 8-byte array to a slice of any length.
`accepted_is_fixed_point_of_minimizer` proves: whatever `validate_integer_content` accepts,
`encode_minimal_integer_into` leaves byte-for-byte unchanged. The de-tautologized biconditional
(`validate_iff_minimal_oracle`) checks production against an **independently-shaped** oracle:
production enumerates the two redundancy cases directly (`(0x00, bit-clear)` / `(0xFF, bit-set)`);
the oracle instead computes what the *hypothetical sign-extension byte implied by octet 1* would be
(`0x00` if its top bit is clear, `0xFF` if set) and asks whether octet 0 equals that value —
redundancy restated as an equality against an independently-derived byte rather than an enumerated
disjunction, so a `==`/`!=` or `&`/`|` slip in one formulation would not be mirrored by the same slip
in the other.

**Evidence.** 12 Kani harnesses: the de-tautologized biconditional, the fixed-point/round-trip
framing, the locality proof, never-panics (both validate and encode), empty-content classification,
redundant-padding rejection at both the 2-octet scale (anchoring `crate::integer`'s existing cases)
and the `N`-octet scale (making the length-generalization concrete, not just asserted), sign-bit
correctness, and exact-one-byte-stripped minimization. Concrete tests include the differentiating
X.509-scale case (`crate::integer::decode_integer` would reject as `TooLarge`; this module accepts)
and its non-minimal 21-octet counterpart, a positive value needing the leading-zero sign guard at
17 octets, a 20-octet negative value, and a redundant-padding round-trip through the minimizer.

**Verdict.** **KEEP** as a separate module alongside `integer`, scoped strictly to arbitrary-magnitude
*validation* (never materialization). Confidence **high**: the locality claim is machine-checked, not
assumed; the de-tautologized oracle and the fixed-point framing both close the "restating the
parser's own control flow" trap this crate consistently avoids elsewhere.

**Revisit if.** A caller ever needs actual bignum *arithmetic* on a DER INTEGER (not just storage/
comparison) — that would need a real arbitrary-precision integer type as a dependency, a materially
different (and much larger) undertaking than this module, and does not belong here.

**Addendum (post-adjudication) — the encoder's general post-condition, proven.** Independent reviewers,
an adversarial reviewer, and this module's own author independently converged on the same
real gap: `strips_redundant_padding` deliberately restricts `buf[1] != 0x00` to isolate a single-strip
case, so no harness had proven the property that actually matters — that `encode_minimal_integer_into`'s
output is *always* minimal, however many leading bytes needed stripping (e.g. `[0x00, 0x00, 0x01]`, a
plausible naive bignum-library export, cascades correctly to `[0x01]`, but this was previously only
verified by hand-tracing, not machine-checked). **Applied**: `minimizer_output_is_always_minimal`
(a reviewer's proposed harness, adopted near-verbatim after independent verification) proves this
generally; `minimality_is_local` was also widened to drop its `n >= 2` restriction (the `n < 2` cases
are vacuously local — empty is always `Empty`, one byte is always minimal — but the proof now states
the claim at every length, not just where it's non-trivial). Concrete tests added: two multi-byte-
redundant cases (one small, one at X.509 scale with four redundant leading bytes) and the
sign-flip-boundary specimen `[0xFF, 0x7F]` / `[0xFF, 0xFF, 0x7F]` (confirms the stripper correctly
stops *before* a strip would flip the value's sign). Also **tightened `encode_minimal_integer_into`'s
doc contract** (per reviewer feedback): the function only *strips* redundant sign-extension bytes, it never *adds* a
positivity guard byte — `content` must already be a correct two's-complement encoding of the caller's
intended value (not sign-and-magnitude or another convention), or the output is DER-minimal for
whatever value those bytes actually represent, not necessarily what the caller meant. **Rejected**
(matter of degree, a recurring "oracle independence overstated" critique):
the suggestion that `is_minimal_oracle` and production share too much conceptual overlap to count as
independent — both must, by necessity, encode the same correct reading of §8.3.2, and the two
formulations remain structurally different enough that single-token mutations in one do not survive
in the other (verified by an adversarial reviewer via direct mutation testing).

---

## D15 — ENUMERATED: a thin re-tagging of `integer`, not a re-proof  ·  settled (high)

**Call.** X.690 §8.4 states plainly: "The encoding of an enumerated value shall be that of the
integer value with which it is associated." Verified against the standard text directly — there is
no additional DER rule for ENUMERATED beyond INTEGER's two's-complement minimal-content encoding
(§8.3.2); only the tag differs (UNIVERSAL 10 / `0x0A`, vs. INTEGER's UNIVERSAL 2). `enumerated`
therefore does not reimplement or re-derive that content rule; `decode_enumerated`/`encode_enumerated`
delegate entirely to `crate::integer::decode_integer`/`encode_integer`, reusing its `IntError`
classification unchanged. This follows D11's precedent against building near-duplicate modules for a
single shared content rule (there restricted-strings; here a single delegating pair).

**Proof strategy, deliberately light.** Because the content logic is not reimplemented, there is
nothing new to re-prove about minimality/canonicality — that is `crate::integer`'s proof obligation,
already discharged. The three Kani harnesses instead pin the *delegation contract* itself:
`decode_delegates_to_integer` / `encode_delegates_to_integer` assert literal result-equality with the
`crate::integer` functions for symbolic input (catching a future refactor that accidentally diverges
the two), and `roundtrip` restates the round-trip property directly on `enumerated`'s own public API
(implied by the two delegation proofs, but worth anchoring since it's what a caller actually relies
on). No `redundant_positive_padding_is_non_minimal`-style harness is duplicated here — that
`IntError::NonMinimal` classification is `crate::integer`'s to prove, and it transfers for free via
the delegation proofs.

**Verdict.** **KEEP** as a minimal delegating module. Confidence **high**: the standard's identical-
encoding rule is unambiguous and cited directly; delegation is machine-checked (not just asserted by
naming), so any accidental divergence between the two modules would be caught.

**Revisit if.** ENUMERATED ever needs a distinct range/semantics from plain INTEGER (it does not, per
§8.4) — no such case is anticipated.

---

## D16 — `big_integer` L4 Lean lid (validate-only slice): the ∀-length minimality biconditional  ·  landed slice (high)

**Call.** A **second** Aeneas→Lean L4 lid — on `big_integer` (arbitrary-magnitude DER INTEGER, §8.3) —
proving the minimality/canonicality property over inputs of **any length**, the unbounded companion to
`big_integer.rs`'s Kani floor (whose harnesses run at `N = 20`, "representative, not limiting", D14). This
first slice covers the **validate side**; the strip-loop / round-trip side landed as **slice 2** (D17 below).
Extracted from the *same* `big_integer.rs` the Kani floor proves, via a **separate** workspace-excluded shim
crate `lean/extract-bigint` (D8's single-source-of-truth discipline, applied per-module so each lid's model +
drift-check stay independent).

**What's proven (sorry-free, ∀-length, `lean/BigIntProofs.lean`).**
- **`validate_iff_minimal`** — `validate_integer_content content = Ok(()) ↔ IsMinimalDer content.val`. The
  headline: `validate` accepts a content octet-string **iff** it is DER-minimal, for a slice of any length.
  This turns `minimality_is_local`'s informal "N=20 generalizes" argument into a machine-checked theorem.
- **`is_negative_spec`** — `is_negative` reports exactly the leading octet's sign bit (∀-length lift of the
  Kani harness `is_negative_matches_sign_bit`).

**De-tautologization (D14's rule, applied at L4).** `IsMinimalDer` is stated in the Kani oracle's
*derived-byte* shape — for `len ≥ 2`, minimal ⇔ `l0 ≠ (if l1 < 0x80 then 0x00 else 0xFF)` (the hypothetical
sign-extension byte implied by octet 1) — a genuinely different algorithm from production
`validate_integer_content`'s *enumerated two-case disjunction* (`(l0=0x00 ∧ msb(l1)=0) ∨ (l0=0xFF ∧
msb(l1)=1)`). Verified faithful to §8.3.2 (redundant iff the leading octet equals that sign-extension byte);
`len = 1` is always minimal, `len = 0` never (validate returns `Err(Empty)`).

**Trust base — the headline biconditional rests on NO assumed spec.** `validate_integer_content`'s `& 0x80`
goes through the *owned-value*, computable `UScalar` `&&&`, so `validate_iff_minimal`'s `#print axioms` is
exactly `[propext, Classical.choice, Quot.sound]` + one LRAT-checked `bv_decide` native axiom (the sign-bit
bridge `and_0x80_eq_zero_iff`) — no `sorryAx`, no owned assumed spec. An extraction spike
confirmed the module's only three Aeneas opaques are `slice::first`, the *reference* bit-and, and
`Option::is_some_and`; these get three one-line assumed specs (`first_spec` — identical to length's;
`bitand_spec`; `is_some_and_spec` — same trust class), needed **only** by `is_negative_spec`. Every other
slice op `big_integer` uses already has an Aeneas `@[step]` lemma in the shipped Std library.

**Gate.** `check_lean.sh` extended with a `big_integer.rs` cfg-split guard (its three `pub fn`s) + a bigint
re-extract/drift-check; the sorry-gate (added this session) enforces sorry-free; the full lid gate re-runs
green (both drift-checks + both proof files), verified via the real exit code. `check.sh` (the L3 Kani floor)
is untouched. (This session also fixed a latent `set -e` bug in `check_lean.sh` that swallowed a failing
`lake build`'s diagnostics — a false-green risk, now closed.)

**Review (`bigint-validate-lid-01`, a full 3-reviewer pass; independence across reviewer families now
measurable):** **unanimous SOUND, zero
defects.** All three independently confirmed the statements faithful to §8.3.2 + the Rust source, the
de-tautologization real+structural, the three specs honest/appropriately-weak, and the biconditional strong
(soundness + completeness) + non-vacuous. One reviewer (the standing highest-recall unique-finder) uniquely raised a
**medium caveat** — the oracle's independence is *semantic*: both formulations share the msb-of-`l1` test, so
the biconditional cannot catch a bug in that shared notion itself. **Documented, not a defect** — that shared
test is exactly the part that is *not* trusted (`and_0x80_eq_zero_iff`, `bv_decide`-proved), and it is the
recurring "oracle independence overstated" critique (cf. D14 addendum, set_of). The same reviewer also proposed an
**optional** hardening (a lemma equating `IsMinimalDer` to the literal two-case §8.3.2 form) — a genuine free
strengthening, **banked** below. Adjudicated verify-not-auto-apply.

**Verdict.** **KEEP** as the first slice of the `big_integer` L4 lid. Confidence **high** (loop-free; the
biconditional is de-tautologized, faithful to §8.3.2, unanimously reviewed SOUND, and rests on no owned
assumed spec).

---

## D17 — `big_integer` L4 Lean lid (slice 2, encode side): the ∀-length round-trip / canonicality proof  ·  landed slice (high)

**Call.** The banked follow-on to D16: the **encode side** of `big_integer` — `encode_minimal_integer_into`
and its redundant-sign-octet **strip-loop** (`big_integer.rs:97`) — lifted to a slice of **any length**, the
unbounded companion to the Kani harnesses (`N = 20`). No new scaffolding was needed: the Aeneas extraction
already covered the whole module (the loop is present as `encode_minimal_integer_into_loop` / a
`@[rust_loop_body]`), and `check_lean.sh` already cfg-guards + drift-checks `encode_minimal_integer_into`.

**What's proven (sorry-free, ∀-length, `lean/BigIntProofs.lean` slice 2).**
- **`encode_minimal_integer_into_loop_spec`** — the strip-loop invariant via `loop.spec_decr_nat` (measure
  `len − cur`): from any in-bounds `start`, the loop lands at `r` with `IsMinimalDer (content.drop r)` — i.e.
  exactly where the redundant-padding guard first fails (or one octet remains).
- **`encode_minimal_integer_into_spec`** — on success (`some written`), the bytes written
  (`out[..written]`) satisfy `IsMinimalDer`.
- **`encode_minimal_integer_into_roundtrip`** — composes the above with D16's `validate_iff_minimal`:
  `validate_integer_content` **accepts** the encoder's output (the recognizer direction — *not* a
  value-preserving `encode∘decode=id` bijection; the encoder only strips).
- **`encode_minimal_integer_into_loop_fixed_point`** (+ converse `..._loop_body_done`) — an already-minimal
  input strips nothing (loop returns `0`): idempotence.

**Trust base — stronger than slice 1: ZERO new assumed axioms.** The whole encode side rests only on the
standard Lean/Aeneas axioms + the one `bv_decide` certificate — not even D16's `first_spec`. The strip-loop's
`i3 &&& 0x80` uses the *owned-value*, computable `&&&` (the same op `validate_integer_content` uses), and
`copy_from_slice` / `index_mut` / range-from `Slice.index` are Aeneas-*modelled* (no opaque external), so they
need no spec (`take_setSlice!_zero` bridges the copy to `List.setSlice!`). Machine-backed by the `#print
axioms` line after each theorem. **De-tautologization (D14):** the loop proof recomputes `IsMinimalDer` from
the loop's own two `step`-read octets in each `done` branch — it does not restate the production if-chain.

**Method.** Implementation with independent adjudication (the `lake build` +
sorry-gate is the oracle, so a broken/sorry proof cannot land). Adjudicated verify-not-auto-apply —
re-ran `check_lean.sh` via the **real** exit code (not piped), read every theorem for non-vacuity + de-taut,
confirmed isolation (only `BigIntProofs.lean` touched, no git ops). Gate re-runs green (1696 jobs, sorry-free).

**Review (`bigint-roundtrip-lid-01`, a 3-reviewer pass):** **independent reviewers: two SOUND, one
REVISE-6, adjudicated NO soundness defect.**
The dissenting reviewer's sole High soundness claim — F2 "loop spec too weak, doesn't state maximal strip" — **adjudicated a
false_positive**: `IsMinimalDer (drop r)` *is* the guard-fails fixed point (definitionally), and the "can't
stop early" converse is proven by `..._loop_body_done`/`..._fixed_point`; the other two reviewers did not raise it.
F1 (axiom-claim wording) + F4 (roundtrip-not-a-bijection prose) + F6 (Aeneas-model trust of copy_from_slice)
= **documented**, folded as docstring precision.

**Banked follow-ons.** (a) **exactness** + (b) **success witness** — now **LANDED** (same session):
`encode_minimal_integer_into_exact` (`out[..written] = content.drop (len − written)`, i.e. the output is
*the* minimal suffix of the input, byte-for-byte) and `encode_minimal_integer_into_succeeds`
(`content ≠ [] ∧ len ≤ out.len → some`), both sorry-free / zero new axioms, one independent review
(`bigint-banked-01`, proportionate to two additive corollaries on an already-SOUND proof) **SOUND,
0 findings**. (c) [carried from D16] the two-case §8.3.2-form lemma — now **LANDED too**:
`IsMinimalDer_two_case` (`IsMinimalDer` on a ≥2-octet list ⇔ the negation of §8.3.2's two forbidden
leading-octet patterns — `0x00`+non-negative or `0xFF`+negative), sorry-free with the file's **leanest
trust class** (`[propext, Classical.choice, Quot.sound]` only — no `bv_decide`, no assumed spec); a third
independent restatement, cross-checking that the de-tautologized `IsMinimalDer` encodes exactly §8.3.2.
One independent review (`bigint-twocase-01`, proportionate) **SOUND, 0 findings**. **All `big_integer` lid
banks are now closed — the lid is COMPLETE** (validate ⇔ minimal; encode ⇒ minimal ⇒ validate-accepts,
exact + idempotent; and the explicit §8.3.2 two-case cross-check).

**Verdict.** **KEEP.** The `big_integer` L4 lid is now **both-sided** (validate ⇔ minimal, and encode ⇒
minimal ⇒ validate-accepts, + idempotent). Confidence **high** (de-tautologized loop invariant, zero owned
assumed specs, 2/3 reviewers SOUND with the lone REVISE adjudicated defect-free).

**Revisit if / follow-ons (from the D16 validate slice).**
1. ~~Strip-loop / round-trip full canonicality~~ — **DONE: landed as D17** (both slices + the two banked
   exactness/success-witness strengthenings), via the `loop.spec_decr_nat` idiom as anticipated.
2. ~~The optional two-case-form lemma~~ — **DONE: `IsMinimalDer_two_case`** (see the Banked-follow-ons
   note above). **No `big_integer` lid banks remain — the lid is complete.**

---

## D18 — `SubjectPublicKeyInfo` consumer slice: the verified core composes into X.509  ·  landed (medium)

**Call.** A first **downstream consumer** of the verified DER primitives: a **structural** X.509
`SubjectPublicKeyInfo` parser (RFC 5280 §4.1.2.7) — `der-verified/src/x509_spki.rs`. Demonstrates the
crate is *usable*, not just internally proven — the credibility artifact for the OSS/grant lane
(milestone M3). Framing only:
composes SEQUENCE + OID + BIT STRING; **no** algorithm/key/certificate semantics (stays inside the crate
scope fence; `parameters` ANY returned raw).

**What's built.** `parse_subject_public_key_info(&[u8]) -> Result<SubjectPublicKeyInfo, SpkiError>` +
a 14-variant structural error taxonomy. Strict at all three levels (outer SEQUENCE consumes whole input;
AlgorithmIdentifier's OID + optional ANY tile its content; the two top-level fields tile the outer content)
— reusing `decode_sequence_tlv(_strict)` / `decode_tlv` / `validate_oid` / `decode_bit_string` **verbatim**,
no re-rolled TLV parsing.

**Verification & tests.** Kani harness `parse_never_panics` (symbolic `[u8; 16]`, `unwind(20)`) — **PASS,
223/223, re-verified by me** (not just the worker). 17 unit tests: real Ed25519 (RFC 8410) + P-256 positive
vectors, RSA-shaped NULL-params accept, and 13 reject cases covering every parser-differential (constructed
OID/BIT STRING, non-canonical length, non-minimal OID, non-zero BIT STRING padding, trailing data at each
level, wrong tags, truncation, missing key).

**Method & review.** Authored, then independently adjudicated (re-ran cargo test → 203 green, re-ran Kani,
confirmed isolation + scope). One independent review (`spki-01`, proportionate): **SOUND on RFC-5280
correctness, scope-faithfulness, and parser-differential security**; its lone REVISE was reject-suite
*completeness* (3 code-handled error paths — `TrailingBytes`/`OidConstructed`/`PublicKeyConstructed` —
untested) → **adjudicated real, fixed** (3 tests added).

**Verdict.** **KEEP** as the crate's first composition demo. Confidence **medium** (structural only; correctness
is test- + Kani-panic-freedom-backed, not a Lean lid — appropriate for a demo, not a proof obligation).

**Follow-ons (owner-gated / banked).** X.509 breadth (Certificate/TBS structure, extensions subset) = the
grant's M3 growth path, **not** started (scope discipline; don't over-invest depth before packaging).
A Kani/Lean *correctness* lid on the SPKI framing is possible later but out of scope for a composition demo.

---

## D19 — X.509 `Name` / `RDNSequence` consumer slice: the SET OF §11.6 proof composes  ·  landed (medium)

**Call.** The second downstream consumer (after D18's SPKI): a **structural** X.509 `Name` validator —
`der-verified/src/x509_name.rs` — the Subject/Issuer half of a certificate. Where SPKI exercised
SEQUENCE + OID + BIT STRING, `Name` exercises **SET OF (with its §11.6 encoding-order proof, D13)** +
SEQUENCE OF + OID + the `ANY` pattern — a broader composition, and the first consumer to put `set_of`'s
ordering guarantee to work in a real X.509 shape. Framing only; no attribute-value-type / DirectoryString
semantics (each ATV `value` `ANY` is left raw).

**Structure & the validate-not-materialize call.**
```
Name ::= RDNSequence ::= SEQUENCE OF RelativeDistinguishedName
RelativeDistinguishedName ::= SET OF AttributeTypeAndValue   -- SIZE(1..MAX), §11.6-ordered
AttributeTypeAndValue ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }
```
`validate_name(&[u8]) -> Result<(), NameError>` is a **validator**, not a materializing parser (unlike
SPKI's returned struct): a `Name` is variable-count (`SEQUENCE OF … SET OF …`) and the crate is heap-free,
so materializing a tree would need `alloc`. Same "validate, don't materialize" stance as `big_integer`
(D14). A 14-variant `NameError` taxonomy wraps the primitives' errors.

**Composition (verbatim reuse — no re-rolled TLV parsing).** Outer: `decode_sequence_tlv_strict`
(SEQUENCE OF; whole-input, no trailing) + an offset walk of each RDN (SEQUENCE OF order is significant —
**no §11.6 sort at this level**). Each RDN: `decode_set_of_tlv` (SET tag + framing + §11.6 ascending
encoding-order, in one call) + an explicit **empty-RDN reject** (`EmptyRdn`; RFC 5280 §4.1.2.4
`SIZE(1..MAX)` — a check `set_of` deliberately does not make, since a bare empty SET OF is vacuously
ordered). Each ATV: a SEQUENCE of exactly `type` (validated OID) + one raw `value` TLV, strict-tiled (no
third field). Trailing bytes rejected at all three nesting levels.

**Boundary calls.** (a) An **empty `RDNSequence`** (`30 00`, zero RDNs) is ACCEPTED — structurally
well-formed ASN.1; the non-empty-issuer / may-be-empty-subject distinction is an RFC 5280 *profile* rule
above the transfer syntax (same altitude split as the time/string profiles, D10/D11). (b) RDN
`SIZE(1..MAX)` IS enforced — it's an explicit ASN.1 constraint on the SET OF itself. (c) `value` `ANY`
left uninterpreted (no DirectoryString CHOICE).

**Verification & tests.** Kani `validate_never_panics` (symbolic `[u8; 16]`, `unwind(20)`) —
**VERIFIED (`0 of 29` / `0 of 19` failed), re-run by me** (the worker's report left the Kani run in
flight; I confirmed it directly, per the standing "verify Kani myself" discipline). 19 unit tests
(cargo test **222 green**): 3 real DN positives (multi-RDN `C=US`/`O=Example Inc`/`CN=Example CA` with
PrintableString + UTF8String; single-RDN; a §11.6-sorted multi-ATV RDN) + 16 rejects, each asserting the
exact error path.

**Method & review.** Authored, then independently adjudicated (read the whole module for scope/soundness,
re-ran cargo test + cargo kani via **real exit codes**, confirmed isolation — only `x509_name.rs` +
`lib.rs`, no git). One independent review (`x509-name-01`, proportionate — matching D18's SPKI review; a
composition demo, correctness = test + Kani-panic-freedom-backed, not a Lean lid): **SOUND** on RFC 5280
correctness, scope-faithfulness, and parser-differential security; its lone REVISE was one
test-completeness gap (`NameError::AtvNotConstructed` — a *primitive-form* SEQUENCE ATV, tag `0x10` — was
implemented + reachable but untested; `rejects_atv_wrong_tag` uses a SET tag, tripping the tag-*number*
check first) → **adjudicated real, fixed** (`rejects_atv_primitive_form` added).

**Verdict.** **KEEP** as the crate's second composition demo (the Subject/Issuer half). Confidence
**medium** (structural only; correctness is test- + Kani-panic-freedom-backed — appropriate for a demo, not
a proof obligation). With D18 the crate now structurally frames both a certificate's SPKI and its DNs.

**Follow-ons (owner-gated).** A full `TBSCertificate` / `Certificate` structural slice needs
**context-specific tagging** (`[0] version EXPLICIT`, `[3] extensions`, implicit-tagged optionals) — the
genuine design fork flagged since session 12 (explicit vs implicit tagging, schema-dependency), to be
scoped **with the owner**, not autonomously. Otherwise X.509 breadth = the grant M3 growth path; scope
discipline cautions against a third Lean lid before packaging/consumer work.

---

## D20 — X.509 `Validity` consumer slice: the crate's first ASN.1 CHOICE composes  ·  landed (medium)

**Call.** The third downstream consumer (after D18's SPKI + D19's Name): a **structural** X.509
`Validity` parser — `der-verified/src/x509_validity.rs` — the certificate's validity window. Its
distinguishing feature is that it is the crate's **first ASN.1 `CHOICE`**: where SPKI and Name are
fixed sequences of typed fields, `Time` is a field whose *identifier octet itself* selects between two
independently-verified content decoders.

```text
Validity ::= SEQUENCE { notBefore Time, notAfter Time }
Time     ::= CHOICE  { utcTime UTCTime, generalTime GeneralizedTime }
```

**Materialize (like SPKI), not validate-only (like Name).** `Validity` is a fixed two-field schema
with no unbounded child count, so `parse_validity(&[u8]) -> Result<Validity, ValidityError>` returns a
`Validity<'a>` with `not_before`/`not_after: Time<'a>` — a two-arm enum (`Utc(UtcTime)` /
`Generalized(GeneralizedTime<'a>)`). Returning `()` would discard the one thing a CHOICE exists to
expose: *which arm was taken*. The `'a` rides only on the `GeneralizedTime` arm (it borrows its
fraction digits); `UtcTime` is owned/`Copy`.

**The CHOICE dispatch (`decode_time_tlv`).** One `decode_tlv`, then: reject non-`UNIVERSAL` class
(`WrongTag`); dispatch tag number 23 → UTCTime, 24 → GeneralizedTime (any other number → `WrongTag`);
reject the constructed form of either (`Constructed` — both times are always primitive in DER); delegate
content canonicality to `utc_time`/`generalized_time` verbatim (`BadUtc`/`BadGeneralized`). A reusable
`TimeError` is wrapped per field (`NotBefore(..)`/`NotAfter(..)`) — cleaner than SPKI's flat variants,
and appropriate because `Time` is a genuine sub-type. Strict tiling: the two fields must exactly fill the
outer SEQUENCE content (`na_used != rest.len()` → `TrailingBytes`; empty/short → `MissingNotBefore`/
`MissingNotAfter`), and the outer SEQUENCE consumes the whole input (`decode_sequence_tlv_strict`).

**Boundary call — the RFC 5280 §4.1.2.5 profile rule is NOT enforced here.** RFC 5280 additionally
requires validity dates **through 2049** be encoded as UTCTime and dates **2050+** as GeneralizedTime.
That is a *profile* constraint layered **above** the ASN.1 transfer syntax (which permits either `Time`
spelling wherever a `Time` is allowed). The slice therefore **accepts either arm for either field**, in
any combination (UTC/UTC, GT/GT, or the mixed UTC-then-GT spelling RFC 5280 actually mandates for
long-lived certs) — the same generic-syntax-vs-profile split `utc_time::full_year_rfc5280` /
`generalized_time::require_no_fraction` already draw (cf. the time/string profile decisions D10/D11 and
D19's empty-`RDNSequence`-accepted call). A caller enforcing the profile checks the returned `Time`
variant + (for UTCTime) the raw two-digit year. **An independent reviewer (below) adjudicated this the
correct altitude call.**

**Verification & tests.** Kani `parse_never_panics` (symbolic `[u8; 16]`, `unwind(20)`) — **VERIFIED
(`0 of 260` failed), re-run by me** via the real exit code (not the worker's report — the standing
"confirm Kani myself" discipline; the unwinding-assertion checks 258–260 pass, so the bound is
sufficient). 17 unit tests (cargo test **239 green**): 4 positives (UTC/UTC, GT/GT, and both mixed
permutations) + 13 rejects, each asserting the exact error path (wrong outer tag, trailing after/inside,
non-canonical outer length, truncation, empty, missing notAfter, both wrong-tag *and* wrong-*class*
guards, constructed Time, bad UTC content, bad GT fraction).

**Method & review.** Authored, then independently adjudicated (read the whole module for
scope/soundness/tiling, re-ran cargo test + cargo kani via **real exit codes**, confirmed isolation —
only `x509_validity.rs` + `lib.rs`, no git ops by the worker). One independent review (`x509-validity-01`,
proportionate — matching D18/D19; a composition demo, correctness = test + Kani-panic-freedom-backed, not
a Lean lid): **SOUND** on X.690/RFC-5280 correctness, CHOICE-dispatch completeness, the profile-boundary
altitude call, scope-faithfulness, and parser-differential security; its lone finding was a LOW
test-**completeness** gap — the tag-*class* guard (`class != Universal`) was reachable but untested
(`rejects_not_before_wrong_tag` uses a UNIVERSAL INTEGER, which trips the tag-*number* branch first),
plus two symmetry additions → **adjudicated real, fixed** (`rejects_not_before_wrong_class` via a
CONTEXT-SPECIFIC-23 tag `0x97`, `parses_mixed_generalized_then_utc`, `rejects_not_after_wrong_tag`).

**Verdict.** **KEEP** as the crate's third composition demo and its first CHOICE. Confidence **medium**
(structural only; correctness is test- + Kani-panic-freedom-backed, not a Lean lid — appropriate for a
demo). With D18/D19/D20 the crate now structurally frames a certificate's public key, its DNs, and its
validity window — three of the core `TBSCertificate` fields.

**Follow-ons (owner-gated).** The remaining no-fork consumer breadth is `Extension`/`Extensions`
(oid + boolean + octet_string). The full `TBSCertificate`/`Certificate` slice still needs
context-specific tagging — the design fork to scope **with the owner** (D19 follow-on). Scope discipline still
cautions against a third Lean lid before packaging/consumer work; NGI grant packaging (Oct 1) remains the
only hard-deadline lane.

---

## D21 — X.509 `Extension`/`Extensions` consumer slice: DER §11.5 DEFAULT-omission enforced  ·  landed (medium)

**Call.** The fourth downstream consumer (after SPKI D18, Name D19, Validity D20): a **structural**
X.509 `Extension`/`Extensions` parser+validator — `der-verified/src/x509_extension.rs`. Its
distinguishing feature is the crate's **first optional field with a DER `DEFAULT`**, which brings in a
genuinely new canonicality rule — X.690 **§11.5 (a component equal to its `DEFAULT` must be absent)**.

```text
Extension  ::= SEQUENCE { extnID OBJECT IDENTIFIER, critical BOOLEAN DEFAULT FALSE, extnValue OCTET STRING }
Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
```

**The notable verified property — §11.5 DEFAULT-FALSE-omission.** `critical` is `BOOLEAN DEFAULT
FALSE`. Because §11.5 requires a component equal to its default to be **omitted**, a canonical DER
`Extension` either omits `critical` (⇒ `false`) or encodes it **present-and-TRUE**. A *present*
BOOLEAN encoding `FALSE` (`01 01 00`) is therefore **invalid DER** — even though
`boolean::decode_bool` decodes `0x00` as a perfectly canonical `false` *in isolation*. The violation
is only visible at this schema-aware altitude, where "was the field present" carries meaning the
content decoder cannot see. `parse_extension` enforces it (`CriticalMustBeTrue`) — a real
anti-differential a lax parser misses. `decode_time_tlv`-style dispatch: peek the post-extnID TLV; if
UNIVERSAL 1 (BOOLEAN), it must be primitive + `decode_bool`-canonical + `TRUE`; any non-BOOLEAN /
framing-failed peek is treated as "critical absent" and falls through to the mandatory `extnValue`
decode (sound — no bytes are skipped, any real framing error resurfaces there).

**Materialize a single `Extension` (like SPKI), validate-only `Extensions` (like Name).** A single
`Extension` is a fixed schema → `parse_extension` returns an `Extension<'a>` (`extn_id`, `critical:
bool`, raw `extn_value`). `Extensions` is a variable-count `SEQUENCE OF` → `validate_extensions`
walks it heap-free (`Result<(), ExtensionsError>`), enforcing RFC 5280 §4.1 `SIZE(1..MAX)`
(`EmptyExtensions`, mirroring D19's `EmptyRdn`). The offset walk uses `decode_tlv` to find each
child's span and `parse_extension` (strict) to validate it; a child-framing `decode_tlv` failure is
surfaced as `BadExtension(BadSeq(Tlv(_)))` (faithful — the same shape `parse_extension`'s own envelope
decode would produce). `extnValue`'s inner DER is left raw/uninterpreted (like SPKI's `ANY`
parameters); no per-extension semantics or profile rules (BasicConstraints/KeyUsage/etc.) — the same
altitude split as the other slices.

**Verification & tests.** Two Kani harnesses, both **re-run by me** via real exit codes (not the
worker's report):
- `parse_extension_never_panics` (`[u8; 16]`, `unwind(20)`) — **VERIFIED `0 of 222`**.
- `validate_extensions_never_panics` — **VERIFIED `0 of 249`**, but at a **reduced `[u8; 13]`,
  `unwind(12)`** buffer. This is a deliberate, documented reduction (cf. `big_integer`'s Kani N, D14
  "representative, not limiting"): at the sibling `[u8; 16]`/`unwind(20)`, CBMC **runs out of memory**
  (~1.6e5 VCCs → CaDiCaL OOM) — *not* a defect, a tractability wall — because `validate_extensions`
  nests the outer `SEQUENCE OF` walk *around a full `parse_extension` inlined per iteration*, and the
  single global unwind forces CBMC to take the product of both loops' maxima. 13 octets is the
  smallest buffer that still holds a *complete* valid single Extension inside an Extensions wrapper
  (the minimal valid `Extensions` is 9 octets) **and** leaves enough trailing content for the walk to
  take a genuine *second* iteration — so the walk-specific logic (offset advance, the
  `&outer[off..off+used]` slice, the count/empty check) is fully exercised. What the reduction gives
  up (longer multi-Extension inputs) is covered **compositionally**: `parse_extension`'s panic-freedom
  is separately proven at the full `[u8; 16]`, and everything `validate_extensions` adds is bounded
  offset arithmetic + slicing that `decode_tlv`'s no-over-read contract (`used ≤ remaining`) keeps
  in-bounds. The reduction + rationale is documented in-module on the harness. cargo test **260 green**
  (21 new).

**Method & review.** Authored, then independently adjudicated (read the whole module for
scope/soundness — esp. the §11.5 logic and the offset-walk's no-over-read/termination/trailing
rejection; re-ran cargo test + **both** Kani harnesses via real exit codes; diagnosed the
`validate_extensions` OOM myself and chose+documented the `[u8; 13]` reduction; confirmed isolation —
only `x509_extension.rs` + `lib.rs`, no worker git ops). The worker left `validate_extensions` Kani
*unconfirmed* (timed out) and reported the *other* harness as done — the standing "confirm Kani myself"
discipline caught both the unconfirmed one and (via the explicit `VALIDATE_EXIT=$?`, not a piped tail)
the initial OOM `FAILED` that a wrapper subshell's exit code had masked as `0`. One independent review
(`x509-extension-01`, proportionate — matching D18/D19/D20): **SOUND**, zero bugs; explicitly confirmed
the §11.5 enforcement "correct and complete" and the offset-walk "sound, safe, robust". Its lone LOW
finding was a test-completeness gap (an explicit peek-fallthrough test) → **adjudicated real, fixed**
(`rejects_spurious_field_before_extn_value`; note the reviewer's own suggested byte specimen had inconsistent
length octets — corrected on adoption).

**Verdict.** **KEEP** as the crate's fourth composition demo and its first `DEFAULT`-bearing field.
Confidence **medium** (structural only; correctness is test- + Kani-panic-freedom-backed, not a Lean
lid). With D18–D21 the crate now structurally frames a certificate's public key, DNs, validity window,
and extension list — four core `TBSCertificate` fields, all of the non-context-tagged ones.

**Follow-ons (owner-gated).** The no-fork consumer breadth is now essentially exhausted (SPKI, Name,
Validity, Extensions done). What remains for a full `TBSCertificate`/`Certificate` slice is
**context-specific tagging** (`[0] version EXPLICIT`, serialNumber (big_integer), signature
(AlgorithmIdentifier), `[3] extensions EXPLICIT`, implicit-tagged optionals) — the genuine design fork
(explicit vs implicit tagging; schema-dependency vs the crate's schema-free stance) flagged since
session 12, to be scoped **with the owner**, not autonomously. Otherwise: a 3rd Lean lid (deprioritized
before packaging/consumer work) or NGI grant packaging (Oct 1, the only hard deadline).

---

## D22 — Context-tagging fork resolved (owner call) + Stage 1 primitives: EXPLICIT-only helper + shared AlgorithmIdentifier  ·  landed (medium)

**The fork (owner-decided).** The full `TBSCertificate`/`Certificate` slice needs context-specific
tagging — the design fork flagged since session 12 (explicit vs implicit; schema-dependency vs the
crate's schema-free stance). Scoped **with the owner**, who chose **Option A**: an **EXPLICIT-only**
context-tag helper + a `TBSCertificate` consumer slice that **rejects the deprecated `[1]`/`[2]`
IMPLICIT uniqueIDs**. Rationale: EXPLICIT decoding is purely *structural* (peel the `[n]` wrapper,
hand the inner content to an existing decoder) — it stays inside the schema-free fence; IMPLICIT
decoding *replaces* the underlying tag and so requires knowing the underlying type (a schema
dependency the crate avoids), and the only IMPLICIT fields in `TBSCertificate` (`[1]`/`[2]`
issuer/subjectUniqueID) are the deprecated v2 uniqueIDs that a real v3 cert omits. This keeps the
schema baked into the consumer slice (consistent with SPKI/Name/Validity/Extension), not into the
primitives. This entry records **Stage 1** (the two foundational primitives); the TBS slice is D23,
the Certificate wrapper D24.

**`context_tag.rs` — the EXPLICIT `[n]` helper (X.690 §8.14.2).**
`decode_explicit_context(n, input)` decodes a context-specific, **constructed** TLV of tag-number `n`
and returns its **inner content** (the wrapped TLV's own bytes, undecoded) + total bytes consumed —
the caller applies the inner type's decoder + checks tiling. Rejects wrong class (`WrongClass`), wrong
number (`WrongNumber`), and the **primitive form** (`NotConstructed` — EXPLICIT is always constructed;
a primitive `[n]` would be IMPLICIT, out of scope). Canonicality (tag-number + length minimality) is
inherited via `decode_tlv`, not re-proven. IMPLICIT is deliberately *not* provided — documented as
schema-dependent (the crate's fence). Kani `decode_explicit_context_never_panics` (`[u8; 16]`,
`unwind(20)`) **VERIFIED `0 of 115`** (re-run by me).

**`x509_algorithm_identifier.rs` — the shared `AlgorithmIdentifier` parser (extracted).**
`AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters ANY OPTIONAL }` is used identically by
`SubjectPublicKeyInfo.algorithm`, `TBSCertificate.signature`, and `Certificate.signatureAlgorithm`.
The parse previously lived inline in `x509_spki`; it is now a single verified `parse_algorithm_
identifier(input) -> (AlgorithmIdentifier, used)` — **composable** (non-strict, returns `used`, ignores
trailing — correct for a field inside a larger SEQUENCE), OID validated, `parameters` raw, exact
two-field tiling (`TrailingElements`). Kani `parse_algorithm_identifier_never_panics` **VERIFIED
`0 of 171`** (re-run by me).

**`x509_spki` refactored to delegate — public API byte-identical.** `parse_subject_public_key_info`
now calls `parse_algorithm_identifier` for its algorithm field and maps `AlgIdError → SpkiError` via a
private `map_algid_error` (lossless: `BadSeq→BadAlgorithmId`, `TrailingElements→AlgorithmTrailing
Elements`, the rest 1:1). `SubjectPublicKeyInfo`/`SpkiError` unchanged; **all 17 D18 SPKI tests pass
unchanged**; `x509_spki::parse_never_panics` **re-VERIFIED `0 of 244`** post-refactor (re-run by me).

**Method & review.** Authored, then independently adjudicated (read both new modules for soundness,
verified the SPKI diff changes no public type + maps errors exactly, re-ran all three Kani harnesses +
277 tests via real exit codes, confirmed isolation). One independent review
(`tbs-stage1-context-algid-01`, proportionate — two small structural primitives + an extraction of
already-reviewed SPKI code + a behavior-preserving refactor): **SOUND, zero findings** —
explicitly confirmed the EXPLICIT decode "textbook-correct", the EXPLICIT-only scope "the correct
architectural choice", and the refactor "flawlessly behavior-preserving" with a "lossless" error map.
cargo test **277 green** (17 new).

**Verdict.** **KEEP.** Confidence **medium** (structural; test- + Kani-panic-freedom-backed). The two
missing primitives for a full certificate are now in place; **D23** wires them (+ the four done field
slices + big_integer serial) into `TBSCertificate`, **D24** into `Certificate`.

---

## D23 — `TBSCertificate` consumer slice: the crate's largest composition + Kani modular (stubbed) proof  ·  landed (medium)

**Call.** Stage 2 of the certificate arc (after D22's primitives): `der-verified/src/x509_tbs_certificate.rs`
— a **structural** RFC 5280 §4.1 `TBSCertificate` parser, the crate's **largest composition**. It wires
the outer SEQUENCE walk to every field parser built so far: `[0] EXPLICIT version` (context_tag +
integer), serial (big_integer), signature (AlgorithmIdentifier, D22), issuer/subject (x509_name D19),
validity (x509_validity D20), subjectPublicKeyInfo (x509_spki D18), `[3] EXPLICIT extensions`
(context_tag + x509_extension D21). **Materializes** the fixed fields (version/serial/signature/
validity/spki) into a `TbsCertificate<'a>` struct; **holds validated raw spans** for the variable-count
issuer/subject/extensions (heap-free, x509_name's stance).

**Two enforced structural rules of note.** (1) **§11.5 on `version`** (mirrors D21's `critical`):
`version [0] EXPLICIT DEFAULT v1` ⇒ a *present* `[0]` wrapper must encode v2/v3, never v1 — a
present-and-v1 is `VersionMustBeOmitted`; a present value ∉{1,2} is `UnsupportedVersion`. (2) **The
deprecated `[1]`/`[2]` IMPLICIT uniqueIDs are REJECTED** (`UnsupportedUniqueId`) — the "Option A"
owner call from D22 (EXPLICIT-only context tags; IMPLICIT is schema-dependent and only these deprecated
v2 fields need it, which a v3 cert omits). Strict tiling: each field's span is extracted with a real
`decode_tlv` (so `used ≤ remaining` keeps `&content[off..off+used]` in-bounds) then validated by the
owning module's strict parser; `off != content.len()` after the last field ⇒ `TrailingInTbs`.

**Verification & tests.** cargo test **287 green** (10 new, incl. a full 155-byte v3 certificate
positive that parses + whose issuer/subject spans independently re-validate, + a v1-minimal positive +
8 reject differentials). One independent review (`tbs-certificate-01`, proportionate — a structural
composition of already-verified+reviewed parts; adversarial pass requested on the novel glue):
**SOUND, zero findings** — confirmed the §11.5 rule "correct, complete, robustly handles adversarial
cases", the offset-walk tiling exact/in-order with no gaps/overlap/over-read, the `[1]`/`[2]` rejection
secure, and RFC 5280 structural fidelity; error taxonomy "exemplary".

**Kani: a MODULAR (stubbed) never-panics proof — the honest tractability story.** A monolithic
`parse_tbs_certificate` never-panics harness is **intractable** for CBMC: it inlines the entire
~8-parser call graph and reasons about the *product* of their branch structures, so the cost is
composition *depth*, not buffer size. Measured: buffers `[u8; 12/8/5/4]` **all time out** (the D21
`validate_extensions` OOM at 16 was the same wall one level shallower); shrinking the buffer prunes
paths but not the inlined program. **Fix = Kani STUBBING** (`-Z stubbing`, now wired into `check.sh`
line 12): the two heaviest sub-parsers — `validate_name` (a `SEQUENCE OF … SET OF …` walk, called
twice) and `validate_extensions` (a `SEQUENCE OF` walk) — are replaced *for this harness* by
nondeterministic `Result` stubs. **Sound**: each is INDEPENDENTLY proven panic-free at its own harness,
and the TBS glue only branches on their returned `Result` (never inspects a materialized value) and
advances `off` by its OWN real `decode_tlv` length, never the callee's — so an over-approximating
Ok/Err stub cannot hide a panic. With those two bodies removed from the inlined program, **`[u8; 10]`,
`unwind(12)` converges: `VERIFICATION: SUCCESSFUL`, 0 of 554 checks** (re-run by me via real exit code).
This harness thereby exercises the REAL TBS-specific glue: the outer walk, the `[0]` version §11.5
handling, both INTEGER decodes, the real AlgId/Validity/SPKI parses, the `[1]`/`[2]`/`[3]` context-tag
peeks, and all field-boundary offset arithmetic + slicing. The residual (the two stubbed parsers'
internals + inputs > 10 octets) is covered COMPOSITIONALLY (each sub-parser proven + `decode_tlv`'s
no-over-read contract). Confirmed `-Z stubbing` does not affect non-stubbed harnesses (sanity: context_tag
harness still `0 of 115` under the flag). The `[u8; 10]` reduction is documented in-module (cf. D14/D21
"representative, not limiting").

> **New capability — Kani stubbing / modular verification (this session).** `-Z stubbing` is now part of
> the milestone gate. This is the crate's first use of modular verification and the general answer to
> the composition-depth wall: any future composition that inlines too large a call graph can stub its
> already-proven callees (soundly, when the caller only uses their `Result` and drives offsets from its
> own `decode_tlv`) to keep CBMC tractable. Directly unblocks D24 (Certificate wraps TBS — even deeper).

**Verdict.** **KEEP** as the crate's flagship composition: it structurally frames a complete X.509
certificate body from independently-verified parts, with the composition glue itself Kani-proven
panic-free (modularly) and the §11.5/context-tag rules enforced. Confidence **medium** (structural
framing; correctness = test- + Kani-panic-freedom-backed, not a Lean lid). **D24** wraps it in the outer
`Certificate` SEQUENCE (tbs + signatureAlgorithm + signatureValue) — a thin final compose.

---

## D24 — `Certificate` outer wrapper: full X.509 certificate parsing complete  ·  landed (medium)

**Call.** Stage 3, the final piece: `der-verified/src/x509_certificate.rs` — a **structural** RFC 5280
§4.1 `Certificate` parser, the crate's outermost composition. It wraps D23's TBS body with its outer
signature into a complete, structurally-validated X.509 certificate.

```text
Certificate ::= SEQUENCE { tbsCertificate TBSCertificate, signatureAlgorithm AlgorithmIdentifier, signatureValue BIT STRING }
```

`parse_certificate` walks the outer SEQUENCE: `tbsCertificate` (span-extract + `parse_tbs_certificate`),
`signatureAlgorithm` (`parse_algorithm_identifier`), `signatureValue` (`decode_tlv` + UNIVERSAL-3-primitive
check + `decode_bit_string`), strict tiling. **Materializes all three** into a `Certificate<'a>` struct
(fixed 3-field schema, like SPKI/Validity).

**Boundary call — §4.1.1.2 `signatureAlgorithm` == `tbsCertificate.signature` is NOT enforced.** RFC 5280
requires the outer `signatureAlgorithm` to equal the inner `TBSCertificate.signature` (a mismatch is a
classic signature-substitution vector), but it is a **cross-field PROFILE rule** above the transfer
syntax — both fields independently decode as valid, independently-canonical `AlgorithmIdentifier`s, and
the ASN.1 grammar doesn't constrain one by the other. Same altitude split as D20 (Validity year-2050),
D21 (critical). The module **materializes both** `AlgorithmIdentifier`s (`cert.signature_algorithm` and
`cert.tbs_certificate.signature`), which derive `PartialEq`, so the caller enforces the profile check
with a single `==`. An independent reviewer adjudicated this the correct call for a structural transfer-syntax parser.

**Verification & review.** cargo test **294 green** (7 new, incl. a full 170-byte `Certificate` positive
that parses). Kani `parse_certificate_never_panics` (`[u8; 12]`, `unwind(12)`) — **VERIFIED `0 of 257`,
re-run by me** — using the **same modular-stubbing technique as D23**: `parse_tbs_certificate` (itself
proven modularly) is stubbed to a nondeterministic `Result` (a dummy `TbsCertificate` on Ok), since
wrapping the whole TBS call graph under another SEQUENCE is even more intractable monolithically. Sound —
the wrapper glue only branches on the tbs parser's `Result` and advances `off` by its own real
`decode_tlv` length. The `-Z stubbing` `#[kani::stub(...)]` resolves an *external-module* function path
cleanly (a useful confirmation of the technique's reach). One independent review (`x509-certificate-01`,
proportionate): **SOUND, zero findings** — tiling "unimpeachable", strict tbs-span extraction sound, BIT
STRING handling correct, the §4.1.1.2 deferral the correct altitude call, error taxonomy "excellent".

**Verdict.** **KEEP.** With D18–D24 the crate now parses a **complete X.509 certificate** end-to-end,
structurally: outer `Certificate` → `TBSCertificate` (version, serial, signature, issuer, validity,
subject, SPKI, extensions) → every leaf field, each field-parser Kani-proven panic-free and the whole
composition proven panic-free (modularly, via stubbing). Confidence **medium** (structural framing;
test- + Kani-panic-freedom-backed, not a Lean lid — the appropriate bar for a composition demo). **The
"parse a real X.509 certificate at L3" milestone flagged since session 12 is reached.** Next options are
owner-gated: a 3rd Lean L4 lid (deprioritized) · a correctness lid on one of the consumer slices
· NGI grant packaging (Oct 1, owner-deprioritized this session) · profile-layer work (the cross-field
rules deliberately left out here) if a typed/profile API is ever in scope.

---

## D25 — 3rd L4 Lean lid on `oid`: the ∀-length OID canonical-form biconditional (validate-only) + a source refactor to unblock Aeneas  ·  landed (high)

**Call.** The owner chose a **3rd Aeneas→Lean L4 lid** (over a consumer-slice correctness lid / a profile
API layer / NGI packaging, which is deprioritized "for later"), and — from the three candidate modules
(`oid` / `set_of` / `bit_string`) — chose **`oid`** (OBJECT IDENTIFIER canonical-form), **validate-only**
depth (mirroring the D16 `big_integer` validate slice; no encoder exists to round-trip). Rationale: `oid`
is the highest-security-value target (OID confusion is a named X.509 attack surface), genuinely unbounded
(∀ number of subidentifiers × ∀ length each), and — unlike `tag`, which an earlier review flagged as
needing from-scratch base-128 *digit arithmetic* — `validate_oid`'s canonicality is purely **structural**
(continuation-bit pattern + no-leading-`0x80`), so the lid needs no digit theory.

**A source refactor was required first (owner-approved), and it cured a second, larger problem.** Aeneas's
Lean backend rejects a `return` nested two loop-levels deep ("Breaks to outer loops are not supported
yet") — and the original `validate_oid` had exactly that (a `return Err(Truncated)` inside its inner
`while`), so extraction degraded the function to a bodyless `axiom` (useless as a lid). Fix:
`validate_oid` was rewritten as a **single loop** with an explicit `at_subid_start` state, moving every
early `return` to loop-depth 1. Behaviour is **identical** — proven, not asserted: the module's 5 Kani
harnesses (`validate_never_panics`, `empty_is_classified`, `leading_0x80_is_non_minimal`,
`later_0x80_is_non_minimal`, `unterminated_is_truncated`) + all 294 crate tests re-passed on the
refactored code (re-run by me via real exit codes), and single-source-of-truth holds (the extraction
`#[path]`-includes the very file the Kani floor proves). **Kani side effect (measured, honestly bounded):**
the nested loop made the 5 `oid` harnesses themselves slow, and the single-loop form makes them **instant**;
it also removed `oid` as a cost contributor when inlined into the OID-consuming x509 harnesses (which all
verify green — see the L3-floor note below). It did **not**, however, make the full `check.sh` complete: the
gate still walls at `x509_name::validate_never_panics`, but on `set_of::cmp_padded`, a *separate* pre-existing
intractability (in the *pre*-refactor status run the wall's trace was `oid::validate_oid`; post-refactor the
same harness walls one layer down, in `set_of`). So the refactor is a real speedup of the oid path, not a fix
for the `x509_name`/`set_of` gate wall (that is called out and left as a separate item below).

**Extraction — a cleaner trust surface than any prior lid.** New workspace-excluded shim crate
`lean/extract-oid` (per-module isolation, like `extract-bigint`; committed model `lean/DerOidExtract.lean`).
`validate_oid` extracts as `validate_oid` → `validate_oid_loop` (Aeneas `loop` combinator) →
`validate_oid_loop.body`. **The extraction leaves ZERO opaque axioms** — the refactored code uses only
Aeneas-modelled ops (`is_empty` / `index_usize` / `len` / owned-value `&&&`), so — unlike the `big_integer`
lid, which needed three assumed specs (`slice::first`, the reference bit-and, `is_some_and`) — the OID lid
needs **no** assumed opaque spec at all.

**What's proven (sorry-free, ∀-length, `lean/OidProofs.lean`).**
- **`validate_iff_canonical`** — `validate_oid content = ok (Result.Ok ()) ↔ IsCanonicalOid content.val`,
  for a content octet-string of **any** length: `validate_oid` accepts **iff** the content is a canonical
  DER OID body. A genuine soundness+completeness biconditional (rejects ⇔ ¬canonical); totality is baked in
  (the loop invariant is a `loop.spec_decr_nat` WP triple, so termination is proven).
- **De-tautologized spec (D14 rule).** `IsCanonicalOid` is a **positional / state-free** predicate over
  octet indices — non-empty; every subidentifier-start octet ≠ `0x80` (minimality); the final octet is a
  terminator (not truncated) — via `IsStart`/`IsTerm`, deliberately **not** a restatement of the production
  loop's `at_subid_start` flag recursion. `IsTerm` is stated in **value** form (`b.val < 128`) and bridged
  to the production bit-and by the file's single non-standard axiom, the `bv_decide` lemma
  `term_iff : (b &&& 0x80 = 0) ↔ b.val < 128` (mirroring `BigIntProofs.lean`'s `and_0x80_eq_zero_iff`).
- **`validate_oid_loop_spec`** — the loop invariant (measure `len − i`), relating the loop's `(flag, i)`
  state to the positional oracle and accumulating "no forbidden subid-start octet seen so far".

**Trust base.** `#print axioms validate_iff_canonical` = `[propext, Classical.choice, Quot.sound,
bv8_and_0x80_eq_zero_iff._native.bv_decide.ax]` — the 3 standard Lean axioms + one LRAT-checked `bv_decide`
certificate, **no `sorryAx`, no assumed opaque spec** (the leanest trust surface of the three lids).

**Documented deviation (verified sound, independently confirmed).** `IsStart`'s internal bound was widened from
the design's literal `p < xs.length` to `p ≤ xs.length`, so `IsStart xs xs.length` coincides with "the
last octet terminates" (the flag value the loop carries when it falls off the slice). This does **not**
change the meaning of `IsCanonicalOid` — clause 2 only ever consults `IsStart` under its own
`p < xs.length` guard, where both bounds agree — it only extends `IsStart`'s standalone domain to the
one-past-end index. Verified by me and independently confirmed by all three reviewers.

**Gate.** `check_lean.sh` extended with an `oid.rs` cfg-split guard (`pub fn validate_oid` count == 1) + a
third re-extract/drift-check (regenerate `DerOidExtract.lean` from the shipped `oid.rs` and fail on drift);
the sorry-gate enforces sorry-free. Full `sh check_lean.sh` re-runs green (real exit code, 1698 jobs), and
`check_fast.sh` (the per-commit hook) green.

**L3 Kani floor — green EXCEPT one pre-existing-intractable harness (documented, not a regression).** On
the refactored tree every module's harnesses verify SUCCESSFUL — all 5 `oid` harnesses, and, importantly,
every OID-consumer (`x509_algorithm_identifier`, `x509_extension`, `x509_spki` all pass with the refactored
`validate_oid` inlined) plus the stubbed `x509_tbs_certificate` / `x509_certificate` — **except**
`x509_name::validate_never_panics`, which CBMC cannot discharge in practical time here: it inlines
`set_of::cmp_padded` (the RDN SET-OF padded-byte comparison) and blows up in the SAT solver (40k+ unwind
states, no verdict after tens of minutes). This is a **pre-existing** `set_of`/`x509_name` CBMC wall, NOT an
oid regression: (1) it is unrelated to the change (the trace is `set_of::cmp_padded`, not `oid`); (2) it hung
identically in the *pre*-refactor status run; (3) it is stubbed away in the TBS/Certificate harnesses (which
therefore pass); (4) `x509_name` verified green in a prior session (D19, 0-of-29), so it is verifiable, just
environment-sensitively slow. The refactor did not cause it and provably does not affect it (`set_of` is
untouched; every harness that DOES inline the refactored `validate_oid` passes). Flagged as a separate
`check.sh`-runtime item (candidate fix: the same documented buffer/unwind reduction D21 applied to
`validate_extensions`, with the residual covered compositionally) — NOT part of this lid.

**Review (`oid-lid-01`, a full 3-reviewer pass; proportionate to a substantive new lid, not a single
review):** **UNANIMOUS SOUND, zero soundness
defects.** All three independently confirmed faithfulness to X.690 §8.19 (with concrete accept/reject
byte-strings), the genuine (non-vacuous, non-circular) biconditional, the real de-tautologization, the
refactor's behavioural equivalence + faithful extraction, and the `IsStart` bound-widening as
meaning-preserving. One reviewer (the standing highest-recall unique-finder) raised **two honest-framing
documentation nits** — (a) the widening *does* change `IsStart`'s standalone domain (not
`IsCanonicalOid`'s meaning); (b) "only non-standard *axiom*" is not "only trust" — `term_iff` also rests on
the axiom-free Aeneas `UScalar`/`BitVec` semantics lemmas, part of the ambient TCB every lid shares.
**Both adjudicated documented-not-defect and folded as docstring precision** (no proof change; the pattern
matches the "independence is semantic" caveat raised on the bigint lid, D16).

**Method.** Implementation with independent adjudication (an extraction/scaffolding spike, then a
proof-engineering pass) — the `lake build` + sorry-gate is the oracle, so a broken or `sorry` proof cannot
land. verify-not-auto-apply throughout: I re-ran every Kani harness + the full lid gate
myself via real exit codes, read the whole proof for non-vacuity / de-tautologization / the flagged
deviation, and adjudicated every reviewer finding.

**Verdict.** **KEEP.** The **third** complete L4 Lean lid (after `length` D7 and `big_integer` D16/D17): the
DER OBJECT IDENTIFIER canonical-form property proven over inputs of any length, on the leanest trust surface
of the three, unanimously reviewed SOUND. Confidence **high** (loop-invariant de-tautologized, faithful to
§8.19, zero assumed opaque specs, refactor behaviour-preservation Kani- + test-proven).

## D26 — `x509_name` made tractable via a modular (stubbed) proof + a repo-wide symbolic-length soundness fix  ·  landed (high)

**Problem (the wall D25 flagged).** `x509_name::validate_never_panics` (monolithic, `[u8;16]`/unwind 20) was
intractable: CBMC's **symbolic-execution formula construction** — not the SAT solve — exceeds **~100 GB**
(measured: killed still climbing past ~34 GB on a 29 GB box; even `[u8;13]`/unwind 8 exceeds ~34 GB). Root
cause (identified in review, empirically confirmed): a depth-3 loop nest (RDN walk × [SET-OF §11.6 ordering walk +
`Elements` ATV walk] × per-child `validate_oid`/`decode_tlv`) under one global unwind makes CBMC build the
**product** of the loops' unrolled copies, dominated by `set_of::cmp_padded` re-derived over symbolic content
per member-partition. Unwind depth and buffer size barely move it (both tested); it is a proof-structuring
problem, not an inherent cost.

**Fix (mirrors D23's TBS modular proof).** Split into (a) `validate_rdn_never_panics` — the full SET-OF §11.6
+ ATV proof at **one-RDN** scale, which fits (**~16.6 GB**, verified green); and (b) `validate_never_panics`,
which **`#[kani::stub]`s `validate_rdn`** with a nondeterministic `Result<usize,_>` carrying the lemma's proven
postcondition `2 <= used <= input.len()` (needed for the RDN walk's progress + in-bounds slicing), leaving CBMC
only the real outer `RDNSequence` envelope + walk glue (**~510 MB**, verified green). Same theorem as before
(never-panics on all inputs up to 16 octets), now compositional. `x509_name` is now verifiable on a normal
machine for the first time (161/161 harnesses pass locally); the `validate_rdn` lemma stays in the
heavy/local CI tier, the stub glue is cheap.

**A pre-existing soundness gap, found in review and fixed repo-wide (the important part).** The modular idiom
(D23) discharged each stub's contract at a **fixed** input length (`validate_name` at exactly 16, etc.) while
the *composition* calls the stubbed function on **shorter suffix slices**. Because the parsers' control flow is
length-dependent (every truncation check reads `input.len()`) with no embedding argument, a hypothetical defect
reachable only at an intermediate length would pass both harnesses yet panic in the real composition — i.e. the
contract was discharged at a length no call site uses. Fix: every discharging lemma now takes a **symbolic input
length** (`let len = kani::any(); assume(len <= buf.len()); f(&buf[..len])`), applied to `validate_rdn_never_panics`,
`validate_never_panics`, **and the pre-existing `x509_extension`/`x509_tbs_certificate`/`x509_certificate`
harnesses**. Cheap (strict prunings of the fixed-length case) and it makes the "up to N octets" prose actually
true. Also corrected a cost-model comment (the widest single loop is 10 — `cmp_padded`'s virtual-padding tail —
not 8; lemma unwind raised 10→12 accordingly) and softened `validate_name`'s "never panics on any input" doc to
"…up to 16 octets".

**Assurance.** Design + soundness independently reviewed: verdict SOUND after the symbolic-length
and unwind fixes (over-approximation valid, assumed postcondition = lemma's asserted postcondition and true of
the real `validate_rdn` per `decode_set_of_tlv`'s `used <= input.len()` contract, DAG chain no circularity,
unwind bounds fail-loud). All five affected harnesses re-verified green (0 failures) inside a desktop-safe
`systemd-run` memory-capped cgroup. PROOF_MANIFEST (4 stubs / 3 harnesses; 161 count) + check.sh updated.


---

## D27 — 4th L4 Lean lid on `tlv`: the ∀-length TLV structural/no-over-read correctness lid, the first on the composition layer  ·  landed (high)

**Call.** Per `DER-REMAINING-WORK.md`'s dispatch note, the next L4 lid — highest priority per the
methods analysis — is a `sequence`/`tlv` round-trip/consumer-correctness lid: the first coverage on
the crate's **structural composition layer** (composing `tag` + `length`), not just another leaf
codec. Scoped to `tlv` (not the larger `sequence`, which walks a whole content buffer and would be
substantially more effort per the analysis's own "research-grade, selective" framing): `decode_tlv`
is itself **loop-free** (a single sequential composition of `decode_tag` then `decode_length` then
overflow-checked arithmetic), so the lid's job is composing already-extracted facts rather than
proving a new loop invariant from scratch — well-scoped for one session, and still the crate's
first composition-layer L4 coverage (the headline ask).

**Property proven: `decode_tlv`'s structural correctness, ∀-length (`decode_tlv_structure`,
`lean/TlvProofs.lean`).** The unbounded companion to Kani's `tlv::proofs::decode_tlv_structure`
(bounded, 16-byte buffer): whenever `decode_tlv input` accepts `Ok (t, used)`, both sub-decodes
succeeded with `used` equal to their combined consumption plus the declared value length, the
returned value is exactly that window, and — the security-critical fact — **`used ≤ input.length`:
an accepted TLV never claims bytes beyond the input, for an input of *any* length** (the crate's
own module doc names this "the security-critical property proven here"). Conditioned on one honest
hypothesis, `32 ≤ Usize.numBits` — `tlv.rs`'s own documented deployment boundary (32/64-bit
targets; the module already documents 16-bit as out of scope) and the same assumption Kani's
harnesses make (Kani models `usize` as 64-bit).

**A one-line, behavior-preserving source fix was required first (mirrors D25's `oid` refactor,
smaller in scope).** Extraction initially failed with a genuine Aeneas naming-scheme bug (not the
D25 early-return-in-loop shape): `tlv.rs`'s point-free `.map_err(TlvError::Tag)` /
`.map_err(TlvError::Length)` forced Aeneas to materialize the variant constructors as standalone
function values, whose auto-generated names collided with the variants' own qualified constructor
names ("name clash... the generated code will be incorrect"). Neither `-impl-namespace` (a
different collision class) nor `#[aeneas::rename(...)]` (needs `#![feature(register_tool)]`, a
nightly-only gate incompatible with `der-verified`'s `stable` pin) fixed it. Fix: rewrote the two
point-free `map_err` calls as explicit closures (`.map_err(|e| TlvError::Tag(e))` /
`.map_err(|e| TlvError::Length(e))`) in the shipped `tlv.rs` — a pure style change, zero behavior
change. Re-verified: all 295 crate tests, all 5 `tlv::proofs::*` Kani harnesses, and (since they
depend on `tlv` transitively) `sequence::proofs::roundtrip_two_children` /
`sequence::proofs::tag_correctness` — all pass unchanged after the edit.

**A second, independent Aeneas naming issue surfaced and was worked around, not fixed in source.**
`tag::encode_tag` and `tlv::encode_tlv_into` both have a Rust parameter literally named `tag`
(`tag: Tag`), which shadows the `tag` **module** in Aeneas's Lean dot-notation resolution — Aeneas
emits `tag.class_bits tag.«class»` intending "the `class_bits` function from the `tag` namespace,
applied to the `tag` parameter's `.class` field", but Lean's elaborator resolves `tag.class_bits`
as dot-notation on the parameter, failing ("Invalid field `class_bits`... environment does not
contain `Tag.class_bits`"). Neither function is needed for `decode_tlv_structure` (the lid never
calls `encode_tag`/`encode_tlv_into`), so `--opaque der_tlv_extract::tag::encode_tag --opaque
der_tlv_extract::tlv::encode_tlv_into` on the Charon extraction turns both into clean bodyless
axioms instead — honest (they were never going to be used) and avoids a second source change in
one pass. `lean/check_lean.sh` was updated to pass the same `--opaque` flags on re-extraction, with
`set -e` OFF around that one step (mirroring the `lake build` pattern) because `aeneas` itself
EXPECTEDLY exits non-zero here (the disclosed `decode_tag` early-return-in-loop bodyless-axiom
"error" — a pre-existing Aeneas limitation, not a regression) even when the file it emits is
correct; the drift-check right after (`diff` against the committed `DerTlvExtract.lean`) is what
actually gates.

**Extraction.** New workspace-excluded shim crate `lean/extract-tlv` (per-module isolation, like
`extract-oid`/`extract-bigint`; committed model `lean/DerTlvExtract.lean`, 1020 lines). Re-exposes
all three shipped files (`tag.rs`, `length.rs`, `tlv.rs`) as sibling modules under the same crate
root, matching der-verified's own module layout so `tlv.rs`'s internal `crate::tag`/`crate::length`
paths resolve unchanged. `tlv.decode_tlv`, `tlv.decode_tlv_strict` extract as fully transparent
(proof-eligible) definitions; `tag.decode_tag` extracts as a bodyless axiom (the pre-existing D25-
class early-return-in-a-loop shape, disclosed, not fixed in this pass — a real, larger, owner-scoped
follow-on if full ∀-length `decode_tag` canonicality is ever wanted); `tag.encode_tag` and
`tlv.encode_tlv_into` extract as bodyless axioms via `--opaque` (the parameter-shadowing issue
above, not needed for this lid's scope).

**Trust base — 7 disclosed assumed specs (the `first_spec` pattern), not the leanest lid but each
individually minimal and justified.** `#print axioms decode_tlv_structure` = `[propext,
Classical.choice, Quot.sound, length_decode_total, length_decode_used_le, result_map_err_err_spec,
result_map_err_ok_spec, tag_decode_total, tag_decode_used_bounds, try_from_u32_usize_spec,
tag.decode_tag, Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from,
core.result.Result.map_err, core.slice.Slice.first]` — the 3 standard Lean axioms, the 7 assumed
specs (see `TlvProofs.lean`'s module doc for the full justification of each), and the 4 underlying
opaque Aeneas primitives they characterize. Two of the seven (`length_decode_total`,
`length_decode_used_le`) are NOT new unverified trust: `LengthProofs.lean`'s own
`decode_accepts_only_canonical` already proves totality **sorry-free**, unconditionally, over the
byte-identical `length.rs` source — but `lean/extract-tlv` runs its own independent Charon/Aeneas
pass (needed since `tlv.rs` requires `length` as a sibling module), producing a Lean namespace that
collides with `lean/extract`'s own `DerLengthExtract` if both are imported into the same file (a
genuine Lean-level limitation of this duplicate-extraction structure, not a semantic gap); these two
axioms restate an already-proved fact to work around that collision. The other five are honest,
minimal, `first_spec`-style characterizations of genuinely opaque primitives (`decode_tag`'s
consumption bounds + totality; `map_err`'s textbook semantics; `usize::try_from(u32)`'s totality
under the 32-bit-usize hypothesis).

**Gate.** `check_lean.sh` extended with a `tlv.rs` cfg-split guard (`pub fn decode_tlv` /
`decode_tlv_strict` / `encode_tlv_into`, each count == 1) + a fourth re-extract/drift-check
(regenerate `DerTlvExtract.lean` from the shipped sources and fail on drift, with the `--opaque`
flags and the `set -e`-off carve-out above). Full `sh check_lean.sh` re-runs green (1700 jobs,
`PASS (sorry-free)`). Verified non-vacuous: injecting a `sorry` into `decode_tlv_structure`'s proof
makes `check_lean.sh` FAIL closed (`sorryAx` appears in the axiom dump, `lake build` reports the
error, the script exits 1) — confirmed, then the injection was reverted and the gate re-confirmed
green.

**L3 Kani floor.** Unaffected by the `tlv.rs` closure-style edit: re-ran all 5 `tlv::proofs::*`
harnesses plus 2 `sequence::proofs::*` harnesses that depend on `tlv` transitively — all `VERIFICATION:
SUCCESSFUL`, 0 failures, identical cover-satisfaction to before the edit. `cargo test` (295 tests,
crate-wide) green.

**Der's Lean track is now 4 lids: `length`, `big_integer`, `oid`, `tlv`.** Next, if pursued: either
the D25-style refactor to unblock full ∀-length `decode_tag` canonicality (unlocking a leaner `tlv`
trust surface and a standalone `tag` lid), or the larger `sequence`/consumer-walk lid the methods
analysis originally flagged as the *other* half of this dispatch item (a genuinely bigger, separate
piece of work — `sequence` walks an unbounded number of children per content buffer, a loop
`decode_tlv` itself does not have).

**Method.** Implementation with iterative Lean-goal-driven proof construction (no blind large tactic
scripts — each step verified against the real elaborator goal state via `lake build`'s error
output before proceeding). verify-not-auto-apply throughout: every extraction step, the source
refactor's Kani/test re-verification, and the sorry-gate's non-vacuity were confirmed via real exit
codes, not assumed.

## D28 — 5th L4/L5 Lean lid: the `sequence` consumer-walk ∀-length, ∀-children correctness lid — the crate's first unbounded-LOOP lid  ·  landed (high)

**Call.** Per D27's own dispatch note, the `sequence`/consumer-walk lid — the larger, deferred half
of the original dispatch item — is the next L4/L5 target: `sequence.rs`'s child-walk iterates an
UNBOUNDED number of children per content buffer, a loop `tlv::decode_tlv` itself does not have
(that function is a single sequential composition, loop-free). This makes `sequence` the crate's
first coverage of an unbounded LOOP in Lean, not just an unbounded input length — the property
Kani's own `#[kani::unwind(16)]`-capped harnesses (`sequence::proofs::no_over_read` /
`ok_implies_exact_tiling`) are inherently unable to reach past a fixed trip count.

**Property proven: `decode_sequence`'s structural correctness, ∀-length AND ∀-children
(`decode_sequence_structure`, `lean/SequenceProofs.lean`).** The unbounded companion to Kani's
`sequence::proofs::no_over_read` / `ok_implies_exact_tiling` (bounded, 8-byte content buffer, ≤ 4
children): whenever `decode_sequence content` accepts (`Ok _`), the child-walk it performs (via
`Elements::next`, repeatedly calling `tlv.decode_tlv` on the remaining suffix and advancing by the
bytes it consumed) reaches a state whose remaining suffix is **exhausted** — the walk consumes
*exactly* `content`'s bytes, for a content slice of *any* length and *any* number of children (no
bound on the walk's trip count). Because the walk's `rest` field is, at every step, provably *some*
`content.drop(off)` (a genuine tail, never a slice manufactured out of thin air — an invariant
threaded through the induction, not assumed), "the final `rest` is empty" is exactly the
security-critical "no over-read" claim, doubly unbounded.

**Proved in three layers** (mirroring `LengthProofs.lean`'s loop-invariant / headline-theorem
split): (1) `decode_tlv_progress` — the minimal corollary of D27's `decode_tlv_structure` this lid
needs (an accepted `decode_tlv` call consumes `1 ≤ used ≤ input.length`); (2) `elements_next_progress`
— lifts (1) through the slice-drop `Elements::next` performs, PLUS a companion fact for the `none`
(walk-exhausted) outcome; (3) `decode_sequence_loop_spec` — the ∀-trip-count loop invariant over
`sequence.decode_sequence_loop`, proved by `loop.spec_decr_nat` with measure `iter.rest.length`
(strictly decreasing every accepted child, by (2)) — the mechanism that lets the induction close
for *any* number of children, not just the ≤ 4 an 8-byte Kani buffer can exhibit. `decode_sequence_
structure` (4) specializes (3) at the initial state from `Elements::new`. A genuine totality lemma
(`decode_tlv_total`/`decode_tlv_total_spec`) was also needed beyond D27's own accept-conditioned
theorem: Lean's `spec (fail e) P ↔ False` means a proof step where `decode_tlv` might fault is
UNPROVABLE (not vacuously true) unless `decode_tlv` is first pinned to an `ok _` result — the
`none`-outcome half of `elements_next_progress`'s postcondition needed this.

**The SAME map_err name-clash fix as D27, this time in `sequence.rs`.** Extraction failed
identically to D27's `tlv.rs` case: `decode_sequence_tlv`'s point-free `.map_err(SequenceError::
Tlv)` collided with the `SequenceError::Tlv` variant's own qualified constructor name under
Aeneas's naming scheme. Fixed identically: rewritten as the explicit closure `.map_err(|e| SequenceError::Tlv(e))`
— a pure style change, zero behavior change. Re-verified: all 21 `sequence`-module tests plus the
crate's 295-test suite pass unchanged (this function, `decode_sequence_tlv`, is not itself one of
the functions this lid proves anything about — `decode_sequence`/`Elements::next` are — so the fix
is purely a pre-flight unblock).

**A genuinely NEW Aeneas limitation surfaced, worked around via a documented `check_lean.sh` patch
step (not a source change).** Aeneas's Lean codegen does not fill in the `Iterator` trait's other
three fields (`step_by`, `enumerate`, `take`) for a hand-written `impl Iterator` that only defines
`next` — relying on Rust's own trait *default* methods for the rest, exactly as `sequence.rs`'s
`Elements` does. This is a genuine codegen gap specific to *user-defined* iterators: library
iterators (`Vec`'s, slice's, …) get hand-specialized adapter instances in Aeneas's own Std library
(`VecIter.lean`, `SliceIter.lean`, …), but a user's own `Elements` type gets none, so the generated
`Iterator` instance is missing three required fields and fails to typecheck as-is. Neither a
`--translate-all-methods` Charon flag (translates every default `Iterator` method crate-wide,
including several that don't extract cleanly — `try_fold`, lifetime-constrained adapters, …) nor
marking the three methods `--opaque` on the Charon call changed the generated instance's shape (the
gap is in how Aeneas BUILDS the trait dictionary for a partial impl, not in what it chooses to
translate). Removing `impl Iterator for Elements` from the source was rejected as too invasive:
`sequence.rs`'s own `for` loop AND `x509_name.rs`'s consumer both rely on the trait (not just
tests), so the change would ripple into the crate's public API for a published crate — out of
scope for an extraction-shim-only fix. The fix actually applied: `check_lean.sh`'s re-extraction
step now applies a small, documented, deterministic post-extraction patch (embedded in the gate
script itself, applied identically on every run) that fills the three missing fields using Aeneas's
own GENERIC default-method combinators (`core.iter.traits.iterator.Iterator.{step_by,enumerate,
take}.default`) — the exact Lean model of what `rustc` itself synthesizes for any `impl Iterator`
that doesn't override them. None of the three is ever called by `decode_sequence`/`Elements::next`
(the only functions this lid proves anything about), so this is inert scaffolding needed only to
make the trait dictionary's structure well-typed — not new trust, not a behavior change, and fully
reproducible (the gate re-derives and re-diffs it on every run, same "provably concerns the exact
bytes the Kani floor proves" contract as every other lid).

**Extraction.** New workspace-excluded shim crate `lean/extract-sequence` (per-module isolation,
like `extract-tlv`/`extract-oid`/`extract-bigint`; committed model `lean/DerSequenceExtract.lean`,
~1395 lines, mechanical Aeneas output — the Iterator-fields patch is applied only inside
`check_lean.sh`'s re-extraction/diff step, not baked into the committed file's own docstrings, to
keep the committed model provably mechanical). Re-exposes all four shipped files (`tag.rs`,
`length.rs`, `tlv.rs`, `sequence.rs`) as sibling modules under the same crate root. `sequence.
decode_sequence`, `Elements::new`, `Elements::next` (as the `Iterator` impl's `next` method) extract
as fully transparent (proof-eligible) definitions; `tag.decode_tag` extracts as a bodyless axiom
(same D25-class shape as D27, disclosed, not fixed in this pass); `tag.encode_tag` and `tlv.
encode_tlv_into` extract as bodyless axioms via `--opaque` (same parameter-shadowing workaround as
D27, not needed for this lid's scope).

**Trust base — the SAME 7 disclosed assumed specs as D27's `tlv` lid**, restated in this pass's own
`der_sequence_extract` namespace (the same duplicate-extraction-namespace workaround D27 itself
used for 2 of its 7). `#print axioms decode_sequence_structure` = `[propext, Classical.choice,
Quot.sound, length_decode_total, length_decode_used_le, result_map_err_err_spec,
result_map_err_ok_spec, tag_decode_total, tag_decode_used_bounds, try_from_u32_usize_spec,
tag.decode_tag, Usize.Insts.CoreConvertTryFromU32TryFromIntError.try_from,
core.result.Result.map_err, core.slice.Slice.first]` — the 3 standard Lean axioms, the 7 assumed
specs (same justification as `TlvProofs.lean`'s, see `SequenceProofs.lean`'s module doc for the
restatement), and the 4 underlying opaque Aeneas primitives they characterize. No new trust beyond
what D27 already disclosed.

**Gate.** `check_lean.sh` extended with a `sequence.rs` cfg-split guard (`pub fn decode_sequence` /
`decode_sequence_tlv` / `decode_sequence_tlv_strict` / `encode_sequence_into`, each count == 1) + a
fifth re-extract/drift-check (regenerate `DerSequenceExtract.lean` from the shipped sources, apply
the Iterator-fields patch, and fail on drift — with the same `--opaque` flags and `set -e`-off
carve-out as D27's `tlv` step). Full `sh check_lean.sh` re-runs green (1702 jobs, `PASS
(sorry-free)`). Verified non-vacuous TWICE: injecting a `sorry` into `decode_sequence_loop_spec`'s
proof makes both a direct `lake build SequenceProofs` AND the full `sh check_lean.sh` FAIL closed
(`sorryAx` appears in the axiom dump of both `decode_sequence_loop_spec` and its dependent
`decode_sequence_structure`; the gate script's own sorry-grep fires and exits 1) — confirmed at
both levels, then the injection was reverted and both re-confirmed green.

**L3 Kani floor.** Unaffected by the `sequence.rs` closure-style edit: re-ran all 7
`sequence::proofs::*` harnesses (0 of 322 checks failed, 2 of 2 cover properties satisfied) and all
5 `tlv::proofs::*` harnesses (0 of 96 checks failed, 3 of 3 cover properties satisfied) — both
`VERIFICATION: SUCCESSFUL`, identical to before the edit. `cargo test` (295 tests, crate-wide)
green.

**Der's Lean track is now 5 lids: `length`, `big_integer`, `oid`, `tlv`, `sequence`.** Next, if
pursued: the D25-style refactor of `tag.rs` to fully de-opaque `decode_tag` — would leanen both
`tlv`'s and `sequence`'s trust surfaces (both currently carry it as a disclosed bodyless-axiom
dependency) and unlock a standalone `tag` lid.

**Method.** Implementation with iterative Lean-goal-driven proof construction (no blind large
tactic scripts — each step verified against the real elaborator goal state via `lake build`'s error
output before proceeding, including several genuine dead-ends on the loop-invariant's exact
anonymous-constructor nesting that were diagnosed via the elaborator's own displayed goal rather
than guessed). verify-not-auto-apply throughout: every extraction step, the source refactor's
Kani/test re-verification, the Iterator-fields patch's reproducibility, and the sorry-gate's
non-vacuity (at both the file and full-gate level) were confirmed via real exit codes, not assumed.
