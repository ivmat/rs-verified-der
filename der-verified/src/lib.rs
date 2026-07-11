//! `der-verified` — a formally verified DER (X.690) encoding/decoding core.
//!
//! **Scope (target #1):** the DER *encoding layer* — the identifier (tag) and definite-length
//! fields, where real X.509 parser differentials live (non-canonical encodings accepted by lax
//! parsers). Out of scope: X.509 semantics, signature/crypto verification. The [`x509_spki`] module
//! is an exception *only* in name: a **structural** `SubjectPublicKeyInfo` parser that composes the
//! verified codecs to frame a real X.509 object, interpreting no algorithm/key/certificate semantics
//! — a downstream-composition demo that stays inside this fence.
//!
//! **Modules:**
//! - [`tag`] — DER identifier octet(s) (X.690 §8.1.2): class, primitive/constructed, tag number.
//! - [`length`] — DER definite-length field (X.690 §8.1.3, §10.1).
//! - [`tlv`] — the tag-length-value reader composing the two (the X.690 structural unit).
//! - [`context_tag`] — the ASN.1 `[n] EXPLICIT` context-tag wrapper (X.690 §8.14.2): peels one
//!   context-specific constructed TLV, structurally, to expose the nested inner TLV's bytes to a
//!   caller-chosen inner decoder. EXPLICIT only, deliberately (IMPLICIT tagging is schema-dependent
//!   — see the module docs).
//! - [`boolean`], [`integer`], [`null`], [`oid`] — canonical DER content decoders/validators.
//! - [`bit_string`] — DER BIT STRING (§8.6): unused-bits count `0..=7` with zero padding bits
//!   (§11.2.2), the empty bit string as `[0x00]` (§11.2.2.1).
//! - [`big_integer`] — DER INTEGER content (§8.3) at arbitrary magnitude: the big-serial-number
//!   complement to [`integer`]'s `i64` cap (`DECISIONS.md` D2a/D14) — validates minimality only,
//!   exposing opaque comparison-only bytes rather than materializing a numeric value.
//! - [`octet_string`] — DER OCTET STRING (§8.7): primitive-form only, rejecting the BER
//!   constructed/segmented form (a parser-differential vector).
//! - [`enumerated`] — DER ENUMERATED (§8.4): a thin re-tagging of [`integer`]'s content codec
//!   (UNIVERSAL 10 instead of UNIVERSAL 2) — the standard defines its encoding to be identical to
//!   INTEGER's, so this module delegates rather than duplicating the minimality/round-trip proofs.
//! - [`restricted_string`] — DER ASCII-restricted string types (`PrintableString`/`IA5String`/
//!   `NumericString`/`VisibleString`): a shared charset validator plus the primitive-only TLV rule.
//! - [`sequence`] — DER SEQUENCE / constructed-content reader (§8.9, §8.10): shallow iteration and
//!   exact-tiling validation of the immediate child TLVs; constructed UNIVERSAL 16 only.
//! - [`set_of`] — DER SET OF member-ordering canonicality (§11.6): validates that child TLVs'
//!   encodings appear in the padded-comparison ascending order the spec requires; schema-free, so
//!   it covers SET OF only — general SET (§10.3, ordered by the ASN.1 schema's per-field tag) is
//!   explicitly out of scope.
//! - [`utc_time`] — DER UTCTime (§11.8): the canonical `YYMMDDHHMMSSZ` form (UNIVERSAL 23).
//! - [`generalized_time`] — DER GeneralizedTime (§11.7): `YYYYMMDDHHMMSS[.fff]Z`, canonical
//!   fractional seconds (UNIVERSAL 24).
//! - [`utf8_string`] — DER UTF8String (UNIVERSAL 12): RFC 3629 / Unicode Table 3-7 well-formed
//!   UTF-8 content, plus the primitive-only TLV rule.
//! - [`x509_algorithm_identifier`] — a **structural** `AlgorithmIdentifier` (RFC 5280 §4.1.1.2)
//!   parser (SEQUENCE + OID + optional ANY parameters), factored out of [`x509_spki`] so it is
//!   shared by every RFC 5280 field with this exact shape (`subjectPublicKeyInfo.algorithm`,
//!   `TBSCertificate.signature`, `Certificate.signatureAlgorithm`). Composable (like
//!   [`sequence::decode_sequence_tlv`]): does not require its input consumed exactly.
//! - [`x509_certificate`] — a **structural** `Certificate` (RFC 5280 §4.1) parser, the crate's
//!   outermost composition: the thin wrapper tying [`x509_tbs_certificate`]'s signed body together
//!   with its outer `signatureAlgorithm`/`signatureValue` into a complete X.509 certificate.
//!   Materializes all three fields (a fixed schema, like [`x509_spki`]). No signature verification;
//!   the RFC 5280 §4.1.1.2 `signatureAlgorithm`/`tbsCertificate.signature` equality is a cross-field
//!   profile rule left to the caller.
//! - [`x509_spki`] — a **structural** `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7) parser that
//!   *composes* the primitives above (SEQUENCE + [`x509_algorithm_identifier`] + BIT STRING) into a
//!   real X.509 building block — a demonstration that the verified core is usable downstream.
//!   Framing only: no algorithm/key/certificate semantics (the ANY `parameters` field is returned
//!   raw and uninterpreted).
//! - [`x509_extension`] — a **structural** `Extension`/`Extensions` (RFC 5280 §4.1.2.9, §4.1)
//!   parser/validator that composes SEQUENCE + OID + BOOLEAN + OCTET STRING into a certificate's
//!   extension list, enforcing DER §11.5's DEFAULT-FALSE-omission rule for `critical` (a present
//!   `critical` must encode `TRUE`). `Extension` materializes (fixed schema, like `x509_spki`);
//!   `Extensions` validates (variable count, heap-free, like `x509_name`); `extnValue`'s inner DER
//!   is left raw and uninterpreted.
//! - [`x509_name`] — a **structural** `Name`/`RDNSequence` (RFC 5280 §4.1.2.4) *validator* that
//!   composes SEQUENCE + SET OF (incl. its §11.6 ordering proof) + OID into the other half of a
//!   certificate's Subject/Issuer field. Variable-count (`SEQUENCE OF … SET OF …`), so — unlike
//!   `x509_spki` — it validates rather than materializes (no heap, matching [`big_integer`]'s
//!   stance); each ATV's `value` (ANY) is left raw and uninterpreted.
//! - [`x509_tbs_certificate`] — a **structural** `TBSCertificate` (RFC 5280 §4.1, §4.1.2) parser,
//!   the crate's largest composition: wires together every field-parser above (six field types plus
//!   two `[n]` context-tag wrappers) into a certificate's signed body. Materializes the fixed
//!   fields; holds validated raw spans for the variable-count `issuer`/`subject`/`extensions`.
//!   Enforces DER §11.5 on `version` (a present `[0]` wrapper must not encode `v1`, the DEFAULT) and
//!   deliberately rejects the deprecated `[1]`/`[2]` IMPLICIT unique identifiers (EXPLICIT-only
//!   context tags, per [`context_tag`]'s scope). No signature/crypto/path/profile semantics.
//! - [`x509_validity`] — a **structural** `Validity` (RFC 5280 §4.1.2.5) parser and the crate's
//!   first ASN.1 `CHOICE`: composes SEQUENCE + the `Time` CHOICE (UTCTime | GeneralizedTime) into a
//!   certificate's validity window, materializing which arm each field took. Framing only: the
//!   §4.1.2.5 UTCTime/GeneralizedTime year-2050 *profile* rule is left to the caller (accepts either
//!   spelling for either field), consistent with the generic-syntax-vs-profile split elsewhere.
//!
//! **Verification:** each module carries Kani proof harnesses in a `#[cfg(kani)]` block, so an
//! ordinary `cargo build` / `cargo test` neither sees nor depends on Kani. Run the proofs with
//! `cargo kani` (or `./check.sh`). Each codec is proven, over its harness's bounded input domain,
//! to (1) round-trip, (2) never panic, and (3) be **canonical** — decode accepts a byte string only
//! if it is the unique canonical encoding of the decoded value — plus per-variant error-class
//! correctness. Three codecs (`length`, `big_integer`, `oid`) are additionally proven ∀-length via
//! an Aeneas→Lean lid. The bounds, assumptions, and stubs behind each claim — and what is *not*
//! proven — are the honest envelope in `PROOF_MANIFEST.md`; read it before relying on any of this.

#![forbid(unsafe_code)]
// This crate deliberately favours explicit, verification-legible control flow over some of clippy's
// idiomatic rewrites. Explicit range comparisons (kept over `RangeInclusive::contains`) and explicit
// byte comparisons keep each Kani harness's reasoning and each X.690 spec-rule mapping one-to-one with
// the source; a spec rule sometimes yields two structurally-identical branches on purpose; and
// `assert_eq!(x, <bool>)` in tests reads as the exact asserted equality. These are style lints, not
// correctness lints — the correctness claims are the Kani/Lean proofs, not clippy's idiom set.
#![allow(clippy::manual_range_contains)]
#![allow(clippy::bool_assert_comparison)]
#![allow(clippy::byte_char_slices)]
#![allow(clippy::if_same_then_else)]

pub mod big_integer;
pub mod bit_string;
pub mod boolean;
pub mod context_tag;
pub mod enumerated;
pub mod generalized_time;
pub mod integer;
pub mod length;
pub mod null;
pub mod octet_string;
pub mod oid;
pub mod restricted_string;
pub mod sequence;
pub mod set_of;
pub mod tag;
pub mod tlv;
pub mod utc_time;
pub mod utf8_string;
pub mod x509_algorithm_identifier;
pub mod x509_certificate;
pub mod x509_extension;
pub mod x509_name;
pub mod x509_spki;
pub mod x509_tbs_certificate;
pub mod x509_validity;
