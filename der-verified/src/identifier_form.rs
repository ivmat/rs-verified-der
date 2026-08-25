//! The two X.690 identifier rules that no *other* module of this crate decides:
//! **primitive/constructed form for UNIVERSAL types** (§8.1.2, §10.2) and the **reserved
//! end-of-contents identifier** (§8.1.5, §10.1).
//!
//! # Why this module exists
//!
//! [`crate::tlv::decode_tlv`] returning `Ok` means *"these bytes are a well-formed TLV"*, **not**
//! *"these bytes are valid DER"*. [`crate::tag::decode_tag`] decodes the class, the
//! primitive/constructed bit and the tag number, and deliberately *attaches no meaning to the
//! combination*; [`crate::tlv`] passes the parsed [`Tag`] through untouched. Neither has so much as
//! a rejection for a constructed BOOLEAN. So before this module existed, a generic walk over
//! untrusted bytes accepted all of these, every one of which is illegal DER:
//!
//! | bytes | why it is illegal |
//! |---|---|
//! | `21 00` | BOOLEAN (UNIVERSAL 1) encoded **constructed** — §8.1.2/§10.2 |
//! | `26 01 39` | OBJECT IDENTIFIER (UNIVERSAL 6) encoded **constructed** |
//! | `2C 01 01` | UTF8String (UNIVERSAL 12) encoded **constructed** — DER §10.2 forbids the BER segmented form |
//! | `33 01 00` | PrintableString (UNIVERSAL 19) encoded **constructed** — same rule |
//! | `3F 1F 00` | DATE (UNIVERSAL 31, high-tag form) encoded **constructed** |
//! | `00 00` | the reserved **EOC** identifier (UNIVERSAL 0) — §8.1.5 |
//!
//! Most of those were found by differential fuzzing against an independent implementation. This
//! module turns them from a disclosed scope gap into a decided rule, and
//! `rejects_every_disclosed_illegal_identifier` proves each specimen is now rejected — **while
//! `decode_tlv` still accepts them**, which is the whole point of the split described next.
//!
//! # ⚠ What this module decides, and the two much larger things it does NOT
//!
//! **1. It is not a DER validator.** It decides *framing* (via [`crate::tlv`]) plus the *form and
//! legality of one identifier*. It does **not** look at content octets at all, so
//! [`decode_tlv_form_checked`] accepts every one of these, all of which are ill-formed DER:
//!
//! | bytes | what is wrong with it | which module would catch it |
//! |---|---|---|
//! | `01 01 01` | BOOLEAN `true` must be `0xFF`, not `0x01` | [`crate::boolean`] |
//! | `02 02 00 01` | INTEGER with redundant leading `00` — not minimal | [`crate::integer`] |
//! | `05 01 00` | NULL content must be empty | [`crate::null`] |
//!
//! Content canonicality is the per-type codecs' job, and this module does not compose them in.
//! The name says `form_checked`, not `der_valid`, for exactly this reason.
//!
//! **2. It decides ONE identifier, not a tree.** [`decode_tlv_form_checked`] checks the identifier
//! of the *one* TLV it decodes. The children of an accepted constructed TLV are **unchecked**. A
//! recursive DER validator must apply this rule at every level itself.
//!
//! # What this module changes, and what it deliberately does not
//!
//! This module is **additive**. It does not alter [`crate::tag`] or [`crate::tlv`], whose permissive
//! behaviour is load-bearing: `decode_tlv` must keep reading *any* well-formed TLV so it can drive
//! recursive parsing and so a caller can inspect an identifier before deciding what it means.
//! Instead the rules are decided here, and offered in two forms:
//!
//! - [`validate_identifier_form`] — the pure decision on an already-decoded [`Tag`];
//! - [`decode_tlv_form_checked`] / [`decode_tlv_form_checked_strict`] — the composition with
//!   [`crate::tlv`], for a caller who wants the framing reader *and* this rule in one call.
//!
//! **The permissive entry points remain the default, so this rule is enforced only where a caller
//! opts in.** Wiring the check into `decode_tlv_strict` itself would be a behavioural change to a
//! shipped, Lean-lidded function; that is a separate decision, deliberately not bundled into this
//! one (the same reasoning `DECISIONS.md` D33 applies to the `set_of` refactor).
//!
//! # Scope fence — read this before relying on it
//!
//! - **Form, never identity.** This module decides whether an identifier's *form* is legal for the
//!   UNIVERSAL type its number names. It has no idea which tag *you* expected: it accepts a
//!   primitive INTEGER identifier exactly as readily as a primitive BIT STRING one. Checking that
//!   the tag is the one your schema requires remains the typed caller's job, and always was.
//! - **UNIVERSAL only.** For APPLICATION, CONTEXT-SPECIFIC and PRIVATE classes the required form is
//!   a property of the *schema*, not of the identifier, and is unknowable from the bytes alone.
//!   This module accepts all of them ([`RequiredForm::Unspecified`]) rather than guessing.
//! - **Tag number 15, and everything `>= 37`,** are likewise [`RequiredForm::Unspecified`]: 15 is
//!   reserved by X.680 and unassigned, and X.680 assigns no UNIVERSAL type above 36. Accepting them
//!   is the conservative choice. Only tag number **0** is rejected outright, because it is not
//!   merely unassigned but *reserved for a marker DER cannot contain*.
//! - **Accepting more than the standard allows is the direction this errs in.** Every `Unspecified`
//!   arm makes the accepted set a strict **over-approximation of the legal set** (equivalently:
//!   under-enforcement). That is deliberate — it can fail to reject an illegal encoding, and it can
//!   never reject a legal one.
//!
//! # Examples
//!
//! ```
//! use der_verified::identifier_form::{decode_tlv_form_checked, CheckedTlvError, FormError};
//! use der_verified::tlv::decode_tlv;
//!
//! // A constructed BOOLEAN is a well-formed TLV but its identifier is not legal DER.
//! assert!(decode_tlv(&[0x21, 0x00]).is_ok());
//! assert_eq!(
//!     decode_tlv_form_checked(&[0x21, 0x00]),
//!     Err(CheckedTlvError::Form(FormError::MustBePrimitive)),
//! );
//!
//! // The reserved end-of-contents identifier is likewise accepted as a TLV, rejected here.
//! assert_eq!(
//!     decode_tlv_form_checked(&[0x00, 0x00]),
//!     Err(CheckedTlvError::Form(FormError::ReservedIdentifier)),
//! );
//!
//! // A primitive BOOLEAN passes -- note this says nothing about its CONTENT being canonical.
//! let (tlv, used) = decode_tlv_form_checked(&[0x01, 0x01, 0xFF]).unwrap();
//! assert_eq!(used, 3);
//! assert_eq!(tlv.value, &[0xFF]);
//! ```

use crate::tag::{Class, Tag};
use crate::tlv::{decode_tlv, Tlv, TlvError};

/// The encoding form X.690 requires for a UNIVERSAL type, given its tag number.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RequiredForm {
    /// The type must be encoded with the **primitive** form under DER.
    ///
    /// For the string types (BIT STRING, OCTET STRING, UTF8String, the restricted strings) this is
    /// specifically a *DER* restriction: BER also permits a constructed, segmented encoding, and
    /// X.690 §10.2 removes that choice.
    Primitive,
    /// The type must be encoded with the **constructed** form (SEQUENCE, SET, and the other
    /// types whose values are themselves sequences of components).
    Constructed,
    /// This crate's table does not decide a form for this tag number — either the number is
    /// unassigned/reserved by X.680 (15, and everything `>= 37`), or the class is not UNIVERSAL so
    /// the form is a property of the schema rather than of the identifier.
    ///
    /// An `Unspecified` identifier is **accepted**. See the module docs' scope fence.
    Unspecified,
}

/// Why an identifier is not a legal DER identifier.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum FormError {
    /// UNIVERSAL 0 — the reserved end-of-contents identifier (X.690 §8.1.5). It exists only to
    /// terminate a BER indefinite-length encoding, and DER admits no indefinite length for it to
    /// terminate (§10.1), so it is never a legal DER identifier in any position.
    ReservedIdentifier,
    /// A UNIVERSAL type that X.690 requires to be primitive was encoded constructed (§8.1.2,
    /// §10.2) — e.g. `21 00` for BOOLEAN, or the BER segmented form of a string type.
    MustBePrimitive,
    /// A UNIVERSAL type that X.690 requires to be constructed was encoded primitive — e.g. a
    /// SEQUENCE with identifier `0x10` instead of `0x30`.
    MustBeConstructed,
}

/// Why a TLV failed the framing-plus-identifier-form check.
///
/// **Not** "why it is not valid DER" — content is never examined. See the module docs.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CheckedTlvError {
    /// The tag/length/value framing itself was rejected by [`crate::tlv::decode_tlv`].
    Tlv(TlvError),
    /// The framing was well-formed but the identifier's form is not legal.
    Form(FormError),
}

/// The form X.690 requires for UNIVERSAL tag `number`.
///
/// This is the crate's table of the X.680 UNIVERSAL type assignments, read through X.690 §10.2
/// (which removes BER's constructed option for the string types). Tag number 0 is reserved and has
/// no form — [`validate_identifier_form`] rejects it outright rather than asking this function.
///
/// Total and panic-free over the whole `u32` domain.
pub fn required_form(number: u32) -> RequiredForm {
    match number {
        // 0 — reserved (end-of-contents marker); handled by validate_identifier_form, not here.
        // 1 BOOLEAN, 2 INTEGER (§8.2, §8.3) — simple types, primitive.
        1 | 2 => RequiredForm::Primitive,
        // 3 BIT STRING, 4 OCTET STRING (§8.6, §8.7) — DER §10.2 forbids BER's segmented form.
        3 | 4 => RequiredForm::Primitive,
        // 5 NULL, 6 OBJECT IDENTIFIER, 7 ObjectDescriptor (§8.8, §8.19; 7 is a string type).
        5..=7 => RequiredForm::Primitive,
        // 8 EXTERNAL (§8.18) — an associated-type SEQUENCE.
        8 => RequiredForm::Constructed,
        // 9 REAL, 10 ENUMERATED (§8.5, §8.4) — simple types.
        9 | 10 => RequiredForm::Primitive,
        // 11 EMBEDDED PDV (§8.20) — an associated-type SEQUENCE.
        11 => RequiredForm::Constructed,
        // 12 UTF8String (a string type, DER §10.2), 13 RELATIVE-OID (§8.21), 14 TIME (§8.26).
        // NOTE on 14: X.680 (2008 and later, incl. the 2021 edition this crate targets) assigns
        // UNIVERSAL 14 to TIME. Pre-2008 tables show 14 as reserved; a reviewer working from such a
        // table will flag this arm. The same revision that assigns 14 assigns 31..=36 below, so the
        // two are one question. Behavioural stake is small either way: if 14 were unassigned there
        // would be no legal universal-14 value for this arm to over-reject.
        12..=14 => RequiredForm::Primitive,
        // 15 — reserved by X.680, unassigned. Not decided; see the module docs.
        15 => RequiredForm::Unspecified,
        // 16 SEQUENCE / SEQUENCE OF, 17 SET / SET OF (§8.9, §8.11, §8.12) — constructed by
        // definition; this is the rule that makes 0x30/0x31 the only legal spellings.
        16 | 17 => RequiredForm::Constructed,
        // 18..=22 NumericString, PrintableString, T61String, VideotexString, IA5String;
        // 23 UTCTime, 24 GeneralizedTime (§11.8, §11.7);
        // 25..=28 GraphicString, VisibleString, GeneralString, UniversalString.
        // All string or time types: primitive under DER §10.2.
        18..=28 => RequiredForm::Primitive,
        // 29 CHARACTER STRING (unrestricted) — an associated-type SEQUENCE, constructed.
        29 => RequiredForm::Constructed,
        // 30 BMPString — a string type, primitive under DER §10.2.
        30 => RequiredForm::Primitive,
        // 31 DATE, 32 TIME-OF-DAY, 33 DATE-TIME, 34 DURATION (§8.26 time types),
        // 35 OID-IRI (§8.21), 36 RELATIVE-OID-IRI (§8.22). All simple types, primitive under DER.
        // These all require the HIGH-TAG form (`1F`-prefixed), since the low-tag form stops at 30 —
        // so `3F 1F 00` is a constructed DATE, and is rejected.
        31..=36 => RequiredForm::Primitive,
        // 0, and every number >= 37: no assigned UNIVERSAL type.
        _ => RequiredForm::Unspecified,
    }
}

/// Decide whether `tag`'s **form** is legal for the UNIVERSAL type its number names (X.690 §8.1.2,
/// §8.1.5, §10.2).
///
/// Enforces exactly two rules, and nothing else:
/// 1. the reserved end-of-contents identifier (UNIVERSAL 0) is rejected in any position;
/// 2. a UNIVERSAL type is encoded in the form X.690 requires for it.
///
/// It does **not** decide whether the tag is the one you expected — see the module docs' scope
/// fence. Non-UNIVERSAL classes and unassigned UNIVERSAL numbers are accepted. Total and
/// panic-free; makes no allocation and reads no input.
pub fn validate_identifier_form(tag: Tag) -> Result<(), FormError> {
    if tag.class != Class::Universal {
        // The required form of an APPLICATION/CONTEXT/PRIVATE type is schema-dependent and is not
        // recoverable from the identifier octets. Accept rather than guess.
        return Ok(());
    }
    if tag.number == 0 {
        // §8.1.5: universal 0 is the end-of-contents marker, which DER can never contain — not a
        // form error but an identifier that has no legal DER meaning at all.
        return Err(FormError::ReservedIdentifier);
    }
    match required_form(tag.number) {
        RequiredForm::Primitive => {
            if tag.constructed {
                return Err(FormError::MustBePrimitive);
            }
            Ok(())
        }
        RequiredForm::Constructed => {
            if !tag.constructed {
                return Err(FormError::MustBeConstructed);
            }
            Ok(())
        }
        RequiredForm::Unspecified => Ok(()),
    }
}

/// Decode one TLV from the front of `input`, **also** requiring its identifier's form to be legal
/// ([`validate_identifier_form`]).
///
/// This is [`crate::tlv::decode_tlv`] plus the two rules this module owns — **framing and one
/// identifier, never content**. `Ok` here does not mean "valid DER": see the module docs for three
/// ill-formed encodings this function accepts.
///
/// Like `decode_tlv` it reads exactly one TLV and **ignores trailing bytes**, so it can drive a
/// recursive parser; use [`decode_tlv_form_checked_strict`] where the whole input must be one
/// object. **It does not recurse** — the children of an accepted constructed TLV are not checked.
pub fn decode_tlv_form_checked(input: &[u8]) -> Result<(Tlv<'_>, usize), CheckedTlvError> {
    let (tlv, used) = match decode_tlv(input) {
        Ok(v) => v,
        Err(e) => return Err(CheckedTlvError::Tlv(e)),
    };
    match validate_identifier_form(tlv.tag) {
        Ok(()) => Ok((tlv, used)),
        Err(e) => Err(CheckedTlvError::Form(e)),
    }
}

/// [`decode_tlv_form_checked`], additionally requiring the TLV to consume the *entire* `input`.
///
/// The composition of [`crate::tlv::decode_tlv_strict`]'s no-trailing-data rule with this module's
/// identifier-form rules — for "this whole blob must be exactly one TLV, whose identifier is
/// well-formed". Still content-blind, and still does not recurse into a constructed value.
pub fn decode_tlv_form_checked_strict(input: &[u8]) -> Result<Tlv<'_>, CheckedTlvError> {
    let (tlv, used) = decode_tlv_form_checked(input)?;
    if used != input.len() {
        return Err(CheckedTlvError::Tlv(TlvError::TrailingData));
    }
    Ok(tlv)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_class() -> Class {
        let sel: u8 = kani::any();
        kani::assume(sel < 4);
        match sel {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        }
    }

    fn any_tag() -> Tag {
        Tag { class: any_class(), constructed: kani::any(), number: kani::any() }
    }

    // -- The oracle. -------------------------------------------------------
    //
    // A membership test over two bitmasks — a deliberately DIFFERENT formulation from
    // `required_form`'s range-`match`, so the biconditionals below compare two independently
    // written encodings of the table rather than a function against itself. Bit `n` is set iff
    // UNIVERSAL tag number `n` requires that form. Bit 0 is clear in both (reserved), as is bit
    // 15 (unassigned); no bit above 36 is set. `u64`, because X.680 assigns through 36.
    //
    // ⚠ HONEST LIMIT OF THIS ORACLE. It establishes that the shipped `match` and this mask agree
    // on all 2^32 tag numbers — a real and complete result, and exactly the property a
    // transcription slip in a 37-arm `match` would violate. It does NOT establish that either one
    // is what X.680 says: the two encodings share an author, so a shared misreading of the
    // standard survives both. The table's agreement with the standard is INSPECTION-ARGUED,
    // per-arm, in `required_form`'s own comments, and spot-checked against real encodings by the
    // concrete tests below. Do not read these theorems as "conformant to X.680"; read them as
    // "the table is the table, everywhere".
    const PRIMITIVE_ONLY_MASK: u64 = 0x0000_001F_DFFC_76FE;
    const CONSTRUCTED_ONLY_MASK: u64 = 0x0000_0000_2003_0900;
    /// Highest UNIVERSAL tag number X.680 assigns (36 = RELATIVE-OID-IRI).
    const MAX_ASSIGNED: u32 = 36;

    fn oracle_is_primitive_only(number: u32) -> bool {
        number <= MAX_ASSIGNED && (PRIMITIVE_ONLY_MASK >> number) & 1 == 1
    }

    fn oracle_is_constructed_only(number: u32) -> bool {
        number <= MAX_ASSIGNED && (CONSTRUCTED_ONLY_MASK >> number) & 1 == 1
    }

    /// The two masks are disjoint, neither claims tag number 0 or 15, and together they cover
    /// exactly `1..=36` minus 15 — a self-check on the oracle itself, so a typo in a mask constant
    /// cannot silently weaken every theorem below.
    ///
    /// Honest limit: this checks *shape*, not *content*. It cannot catch a primitive/constructed
    /// misclassification, nor a standards mistake shared with `required_form`.
    #[kani::proof]
    fn oracle_is_well_formed() {
        assert!(PRIMITIVE_ONLY_MASK & CONSTRUCTED_ONLY_MASK == 0);
        assert!(PRIMITIVE_ONLY_MASK & 1 == 0);
        assert!(CONSTRUCTED_ONLY_MASK & 1 == 0);
        assert!((PRIMITIVE_ONLY_MASK >> 15) & 1 == 0);
        assert!((CONSTRUCTED_ONLY_MASK >> 15) & 1 == 0);
        // Nothing above the highest assigned number.
        assert!((PRIMITIVE_ONLY_MASK | CONSTRUCTED_ONLY_MASK) >> (MAX_ASSIGNED + 1) == 0);
        // Exactly 1..=36, minus the reserved 15.
        let full = ((1u64 << (MAX_ASSIGNED + 1)) - 1) & !1u64 & !(1u64 << 15);
        assert!(PRIMITIVE_ONLY_MASK | CONSTRUCTED_ONLY_MASK == full);
    }

    /// `required_form` matches the independent mask oracle for **every** `u32` tag number.
    ///
    /// Exhaustive over the complete input domain — not a bounded-buffer proof. There is no
    /// unwinding here and no bound to exceed: the domain *is* `u32`, and CBMC decides it
    /// symbolically.
    #[kani::proof]
    fn required_form_matches_oracle_on_all_u32() {
        let n: u32 = kani::any();
        let got = required_form(n);
        assert!((got == RequiredForm::Primitive) == oracle_is_primitive_only(n));
        assert!((got == RequiredForm::Constructed) == oracle_is_constructed_only(n));
        assert!(
            (got == RequiredForm::Unspecified)
                == (!oracle_is_primitive_only(n) && !oracle_is_constructed_only(n))
        );
    }

    /// **`DER-F-9`, over the complete domain.** `validate_identifier_form` rejects the reserved
    /// end-of-contents identifier, and rejects it *only* there: for every tag, the verdict is
    /// `ReservedIdentifier` iff the tag is UNIVERSAL 0 — regardless of the constructed bit.
    #[kani::proof]
    fn reserved_eoc_rejected_iff_universal_zero() {
        let tag = any_tag();
        let got = validate_identifier_form(tag);
        let is_eoc = tag.class == Class::Universal && tag.number == 0;
        assert!((got == Err(FormError::ReservedIdentifier)) == is_eoc);
    }

    /// **`DER-F-8`, over the complete domain.** For every tag, `validate_identifier_form` returns
    /// `MustBePrimitive` iff the tag is a UNIVERSAL primitive-only type encoded constructed, and
    /// `MustBeConstructed` iff it is a UNIVERSAL constructed-only type encoded primitive — both
    /// stated against the independent mask oracle.
    #[kani::proof]
    fn constructed_form_rule_matches_oracle_on_all_tags() {
        let tag = any_tag();
        let got = validate_identifier_form(tag);
        let universal = tag.class == Class::Universal;
        assert!(
            (got == Err(FormError::MustBePrimitive))
                == (universal && tag.constructed && oracle_is_primitive_only(tag.number))
        );
        assert!(
            (got == Err(FormError::MustBeConstructed))
                == (universal && !tag.constructed && oracle_is_constructed_only(tag.number))
        );
    }

    /// Totality, plus the property that bounds this module's blast radius: an identifier is
    /// accepted iff it violates no rule **as the oracle encodes them**, and **every**
    /// non-UNIVERSAL identifier is accepted unconditionally.
    ///
    /// Read the qualifier: this is "no rejection outside the encoded rule", **not** "no legal DER
    /// encoding is ever rejected". The latter would be a statement about X.680, which no theorem
    /// here makes. What it does guarantee outright is that a schema-dependent APPLICATION /
    /// CONTEXT / PRIVATE tag can never be rejected by this module.
    #[kani::proof]
    fn accepts_iff_no_encoded_rule_violated_and_never_rejects_non_universal() {
        let tag = any_tag();
        let got = validate_identifier_form(tag);
        if tag.class != Class::Universal {
            assert!(got == Ok(()));
        }
        let violates = tag.class == Class::Universal
            && (tag.number == 0
                || (tag.constructed && oracle_is_primitive_only(tag.number))
                || (!tag.constructed && oracle_is_constructed_only(tag.number)));
        assert!(got.is_ok() == !violates);
    }

    /// Composition, over a symbolic buffer: `decode_tlv_form_checked` accepts exactly when the
    /// framing layer accepts **and** the identifier's form is legal, and when it accepts it returns
    /// precisely what `decode_tlv` returned. So this entry point is `decode_tlv` refined by the
    /// rule — it neither loses nor invents any framing behaviour.
    ///
    /// **Bounded at `[u8; 6]`**, unlike the four domain-complete theorems above: this one reaches
    /// the framing decoder's loops, so it is a statement about six-byte inputs, not all inputs.
    ///
    /// Cover: witnesses that both outcomes are live in the symbolic domain — that the `Ok` tail is
    /// reachable, and that a form rejection is genuinely reachable from raw bytes rather than only
    /// from a hand-built `Tag`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_tlv_form_checked_is_decode_tlv_refined_by_the_rule() {
        let buf: [u8; 6] = kani::any();
        let base = decode_tlv(&buf);
        let refined = decode_tlv_form_checked(&buf);
        match base {
            Ok((tlv, used)) => match validate_identifier_form(tlv.tag) {
                Ok(()) => {
                    assert!(refined == Ok((tlv, used)));
                    kani::cover(true, "a legal identifier reaches the Ok tail");
                }
                Err(e) => {
                    assert!(refined == Err(CheckedTlvError::Form(e)));
                    kani::cover(true, "a well-formed TLV is rejected by the identifier rule");
                }
            },
            Err(e) => assert!(refined == Err(CheckedTlvError::Tlv(e))),
        }
    }

    /// `decode_tlv_form_checked_strict` accepts iff `decode_tlv_form_checked` accepts *and* the TLV
    /// spans the whole input — the trailing-data rule composed with the identifier-form rules.
    /// **Bounded at `[u8; 6]`**, for the same reason as the harness above.
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_tlv_form_checked_strict_requires_full_consumption() {
        let buf: [u8; 6] = kani::any();
        let strict = decode_tlv_form_checked_strict(&buf);
        match decode_tlv_form_checked(&buf) {
            Ok((tlv, used)) => {
                if used == buf.len() {
                    assert!(strict == Ok(tlv));
                } else {
                    assert!(strict == Err(CheckedTlvError::Tlv(TlvError::TrailingData)));
                }
            }
            Err(e) => assert!(strict == Err(e)),
        }
    }

    /// **Every illegal identifier this crate has ever disclosed, as a regression proof.** The nine
    /// specimens are `PROOF_MANIFEST.md` §6.3's class (a) and (b) — eight constructed encodings of
    /// primitive-only universal types, plus the reserved EOC — and each is *accepted* by the
    /// framing layer and *rejected* here, so the harness proves both halves at once: that the gap
    /// was real, and that this entry point closes it.
    ///
    /// Fixture-shaped by construction, so this harness is a PROBE. The unbounded statements are the
    /// four theorems above; this one pins the exact specimens a future refactor must never start
    /// accepting again.
    #[kani::proof]
    #[kani::unwind(12)]
    fn rejects_every_disclosed_illegal_identifier() {
        // Class (a): constructed encodings of primitive-only universal types.
        // Low-tag form.
        assert!(decode_tlv(&[0x21, 0x00]).is_ok()); // BOOLEAN (1)
        assert!(
            decode_tlv_form_checked(&[0x21, 0x00])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        );
        assert!(decode_tlv(&[0x26, 0x01, 0x39]).is_ok()); // OBJECT IDENTIFIER (6)
        assert!(
            decode_tlv_form_checked(&[0x26, 0x01, 0x39])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        );
        assert!(decode_tlv(&[0x2C, 0x01, 0x01]).is_ok()); // UTF8String (12)
        assert!(
            decode_tlv_form_checked(&[0x2C, 0x01, 0x01])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        );
        assert!(decode_tlv(&[0x33, 0x01, 0x00]).is_ok()); // PrintableString (19)
        assert!(
            decode_tlv_form_checked(&[0x33, 0x01, 0x00])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        );
        assert!(
            decode_tlv_form_checked(&[0x27, 0x02, 0x04, 0x04])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        ); // ObjectDescriptor (7)
        assert!(
            decode_tlv_form_checked(&[0x29, 0x00])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        ); // REAL (9)
        assert!(
            decode_tlv_form_checked(&[0x2A, 0x01, 0x4A])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        ); // ENUMERATED (10)
        assert!(
            decode_tlv_form_checked(&[0x3E, 0x00])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        ); // BMPString (30)

        // Class (b): the reserved end-of-contents identifier.
        assert!(decode_tlv(&[0x00, 0x00]).is_ok());
        assert!(
            decode_tlv_form_checked(&[0x00, 0x00])
                == Err(CheckedTlvError::Form(FormError::ReservedIdentifier))
        );
    }

    /// **The HIGH-TAG-FORM arm, which the low-tag specimens above cannot reach.** X.680's
    /// assignments 31..=36 all require the high-tag form, so a table that stopped at 30 would
    /// accept a constructed DATE and no fixture above would notice. `3F 1F 00` is exactly that
    /// input; `1F 1F 00` is its legal primitive counterpart and must still be accepted.
    #[kani::proof]
    #[kani::unwind(12)]
    fn high_tag_universal_types_are_form_checked() {
        assert!(decode_tlv(&[0x3F, 0x1F, 0x00]).is_ok()); // framing accepts a constructed DATE
        assert!(
            decode_tlv_form_checked(&[0x3F, 0x1F, 0x00])
                == Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        );
        assert!(decode_tlv_form_checked(&[0x1F, 0x1F, 0x00]).is_ok()); // primitive DATE (31)
        assert!(decode_tlv_form_checked(&[0x1F, 0x24, 0x00]).is_ok()); // primitive RELATIVE-OID-IRI (36)
        // 37 is unassigned, so BOTH forms are accepted (the conservative arm).
        assert!(decode_tlv_form_checked(&[0x1F, 0x25, 0x00]).is_ok());
        assert!(decode_tlv_form_checked(&[0x3F, 0x25, 0x00]).is_ok());
    }

    /// **Class (c) of `PROOF_MANIFEST.md` §6.3 must keep being accepted.** Those two encodings are
    /// *legal* DER that the fuzzing campaign's comparison library rejected only for lack of a
    /// model — so they are the specimens most at risk from a table that over-rejects. A rule that
    /// bought its rejections by also refusing legal input would be caught here.
    #[kani::proof]
    #[kani::unwind(12)]
    fn legal_der_the_comparison_library_rejected_is_still_accepted() {
        assert!(decode_tlv_form_checked(&[0x07, 0x01, 0x4A]).is_ok()); // primitive ObjectDescriptor
        assert!(decode_tlv_form_checked(&[0x28, 0x02, 0x01, 0x30]).is_ok()); // constructed EXTERNAL
    }

    /// The rule does not break the encodings this crate's own X.509 surface depends on: a
    /// primitive INTEGER, a constructed SEQUENCE, a constructed SET, a primitive BIT STRING, a
    /// primitive UTCTime, and both context-specific forms are all still accepted.
    /// A rule that rejected these would be caught here rather than by a distant integration test.
    #[kani::proof]
    #[kani::unwind(12)]
    fn real_x509_identifiers_are_still_accepted() {
        assert!(decode_tlv_form_checked(&[0x02, 0x01, 0x07]).is_ok()); // INTEGER 7
        assert!(decode_tlv_form_checked(&[0x30, 0x00]).is_ok()); // SEQUENCE {}
        assert!(decode_tlv_form_checked(&[0x31, 0x00]).is_ok()); // SET {}
        assert!(decode_tlv_form_checked(&[0x03, 0x01, 0x00]).is_ok()); // BIT STRING, empty
        assert!(decode_tlv_form_checked(&[0x05, 0x00]).is_ok()); // NULL
        assert!(decode_tlv_form_checked(&[0xA0, 0x00]).is_ok()); // [0] EXPLICIT, constructed
        assert!(decode_tlv_form_checked(&[0x80, 0x00]).is_ok()); // [0] IMPLICIT, primitive
    }

    /// **The scope fence, as a proof: this is NOT a DER validator.** Each of these is ill-formed
    /// DER that this module deliberately accepts, because it never looks at content. If a future
    /// change made any of them fail, the docs promising content-blindness would be wrong — and the
    /// docs are what a consumer relies on to know they still need the typed codecs.
    #[kani::proof]
    #[kani::unwind(12)]
    fn content_errors_are_deliberately_not_caught() {
        assert!(decode_tlv_form_checked(&[0x01, 0x01, 0x01]).is_ok()); // BOOLEAN true must be 0xFF
        assert!(decode_tlv_form_checked(&[0x02, 0x02, 0x00, 0x01]).is_ok()); // non-minimal INTEGER
        assert!(decode_tlv_form_checked(&[0x05, 0x01, 0x00]).is_ok()); // NULL must be empty
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. the seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    fn universal(number: u32, constructed: bool) -> Tag {
        Tag { class: Class::Universal, constructed, number }
    }

    #[test]
    fn eoc_identifier_is_rejected_in_both_forms() {
        assert_eq!(
            validate_identifier_form(universal(0, false)),
            Err(FormError::ReservedIdentifier)
        );
        assert_eq!(
            validate_identifier_form(universal(0, true)),
            Err(FormError::ReservedIdentifier)
        );
        assert_eq!(
            decode_tlv_form_checked(&[0x00, 0x00]),
            Err(CheckedTlvError::Form(FormError::ReservedIdentifier))
        );
    }

    #[test]
    fn constructed_primitive_only_types_are_rejected() {
        for number in [1u32, 2, 3, 4, 5, 6, 10, 12, 19, 23, 24, 31, 34, 36] {
            assert_eq!(
                validate_identifier_form(universal(number, true)),
                Err(FormError::MustBePrimitive),
                "universal {number} constructed should be rejected"
            );
            assert_eq!(validate_identifier_form(universal(number, false)), Ok(()));
        }
    }

    #[test]
    fn primitive_constructed_only_types_are_rejected() {
        for number in [8u32, 11, 16, 17, 29] {
            assert_eq!(
                validate_identifier_form(universal(number, false)),
                Err(FormError::MustBeConstructed),
                "universal {number} primitive should be rejected"
            );
            assert_eq!(validate_identifier_form(universal(number, true)), Ok(()));
        }
    }

    /// The identifiers of real X.509 objects, spelled as the standard spells them. This is the
    /// spot-check that the table is the *standard's* table and not merely self-consistent.
    #[test]
    fn real_world_identifier_octets_are_accepted() {
        for (b, what) in [
            (0x30u8, "SEQUENCE"),
            (0x31, "SET"),
            (0x02, "INTEGER (serial number)"),
            (0x03, "BIT STRING (signature value)"),
            (0x04, "OCTET STRING (extnValue)"),
            (0x05, "NULL (algorithm parameters)"),
            (0x06, "OBJECT IDENTIFIER (algorithm)"),
            (0x0C, "UTF8String"),
            (0x13, "PrintableString (common name)"),
            (0x16, "IA5String (dNSName)"),
            (0x17, "UTCTime (notBefore)"),
            (0x18, "GeneralizedTime (notAfter)"),
            (0x01, "BOOLEAN (critical)"),
        ] {
            let (tag, _) = crate::tag::decode_tag(&[b]).unwrap();
            assert_eq!(validate_identifier_form(tag), Ok(()), "{what} ({b:#04x}) must be accepted");
        }
    }

    /// The BER spellings a DER parser must refuse — the constructed/segmented forms.
    #[test]
    fn ber_constructed_string_forms_are_rejected() {
        for (b, what) in [
            (0x23u8, "constructed BIT STRING"),
            (0x24, "constructed OCTET STRING"),
            (0x2C, "constructed UTF8String"),
            (0x33, "constructed PrintableString"),
            (0x36, "constructed IA5String"),
        ] {
            let (tag, _) = crate::tag::decode_tag(&[b]).unwrap();
            assert_eq!(
                validate_identifier_form(tag),
                Err(FormError::MustBePrimitive),
                "{what} ({b:#04x}) must be rejected"
            );
        }
    }

    /// X.680's high-tag assignments (31..=36). A table that stopped at 30 would accept every
    /// constructed spelling here.
    #[test]
    fn high_tag_assignments_are_decided() {
        for (number, what) in [
            (31u32, "DATE"),
            (32, "TIME-OF-DAY"),
            (33, "DATE-TIME"),
            (34, "DURATION"),
            (35, "OID-IRI"),
            (36, "RELATIVE-OID-IRI"),
        ] {
            assert_eq!(required_form(number), RequiredForm::Primitive, "{what}");
            assert_eq!(validate_identifier_form(universal(number, false)), Ok(()), "{what}");
            assert_eq!(
                validate_identifier_form(universal(number, true)),
                Err(FormError::MustBePrimitive),
                "constructed {what} must be rejected"
            );
        }
        // The wire form: `3F 1F 00` is a constructed DATE.
        assert_eq!(
            decode_tlv_form_checked(&[0x3F, 0x1F, 0x00]),
            Err(CheckedTlvError::Form(FormError::MustBePrimitive))
        );
        assert!(decode_tlv_form_checked(&[0x1F, 0x1F, 0x00]).is_ok());
    }

    /// A primitive SEQUENCE identifier (`0x10` instead of `0x30`) is rejected.
    #[test]
    fn primitive_sequence_identifier_is_rejected() {
        assert_eq!(
            decode_tlv_form_checked(&[0x10, 0x00]),
            Err(CheckedTlvError::Form(FormError::MustBeConstructed))
        );
    }

    #[test]
    fn non_universal_classes_are_never_rejected() {
        for class in [Class::Application, Class::ContextSpecific, Class::Private] {
            for constructed in [true, false] {
                for number in [0u32, 1, 4, 16, 29, 30, 31, 36, 37, 1000, u32::MAX] {
                    assert_eq!(
                        validate_identifier_form(Tag { class, constructed, number }),
                        Ok(()),
                        "{class:?} {number} constructed={constructed} must be accepted"
                    );
                }
            }
        }
    }

    #[test]
    fn unassigned_universal_numbers_are_accepted() {
        for number in [15u32, 37, 38, 100, u32::MAX] {
            assert_eq!(required_form(number), RequiredForm::Unspecified);
            assert_eq!(validate_identifier_form(universal(number, false)), Ok(()));
            assert_eq!(validate_identifier_form(universal(number, true)), Ok(()));
        }
    }

    #[test]
    fn framing_errors_pass_through_unchanged() {
        assert_eq!(
            decode_tlv_form_checked(&[0x02, 0x05, 0x01]),
            Err(CheckedTlvError::Tlv(TlvError::Truncated))
        );
        assert!(matches!(
            decode_tlv_form_checked(&[0x30, 0x80]),
            Err(CheckedTlvError::Tlv(TlvError::Length(_)))
        ));
    }

    #[test]
    fn strict_rejects_trailing_bytes() {
        assert_eq!(
            decode_tlv_form_checked_strict(&[0x02, 0x01, 0x07, 0xFF]),
            Err(CheckedTlvError::Tlv(TlvError::TrailingData))
        );
        assert!(decode_tlv_form_checked_strict(&[0x02, 0x01, 0x07]).is_ok());
    }

    /// **This module is not a DER validator, and this test is that promise in executable form.**
    /// Each input is ill-formed DER that is deliberately accepted, because content is never read.
    #[test]
    fn content_errors_are_deliberately_not_caught() {
        for (bytes, what) in [
            (&[0x01u8, 0x01, 0x01][..], "BOOLEAN true must be encoded 0xFF"),
            (&[0x02, 0x02, 0x00, 0x01][..], "INTEGER with redundant leading zero"),
            (&[0x05, 0x01, 0x00][..], "NULL with non-empty content"),
        ] {
            assert!(
                decode_tlv_form_checked(bytes).is_ok(),
                "content-blind by design, so this must still be accepted: {what}"
            );
        }
    }

    /// `decode_tlv` must keep its permissive behaviour — this module is additive, and a change
    /// that tightened the framing layer instead would be caught here.
    #[test]
    fn framing_layer_remains_permissive() {
        for bytes in [
            &[0x21u8, 0x00][..],
            &[0x26, 0x01, 0x39][..],
            &[0x2C, 0x01, 0x01][..],
            &[0x33, 0x01, 0x00][..],
            &[0x3F, 0x1F, 0x00][..],
            &[0x00, 0x00][..],
        ] {
            assert!(
                decode_tlv(bytes).is_ok(),
                "decode_tlv is deliberately permissive and must stay so: {bytes:02x?}"
            );
        }
    }
}
