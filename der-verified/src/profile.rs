//! X.509 **profile** rules (RFC 5280) — the first slice of a typed validation layer built *on top
//! of* this crate's structural parsers, not inside them.
//!
//! Every `x509_*` module in this crate deliberately stops at the transfer-syntax boundary: it
//! validates that a byte string is a well-formed, DER-canonical instance of its ASN.1 type, and
//! nothing more. Several RFC 5280 rules, though, are **cross-field profile constraints** layered
//! *above* that syntax — both sides of the constraint independently decode as perfectly valid,
//! independently-canonical values, and nothing in the ASN.1 grammar itself ties one to the other
//! (see [`crate::x509_certificate`]'s and [`crate::x509_tbs_certificate`]'s module docs, which name
//! this exact split and explicitly leave such rules "to the caller"). This module is that caller,
//! for the first seven such rules:
//!
//! 1. **RFC 5280 §4.1.1.2**: the outer `Certificate.signatureAlgorithm` MUST be identical to the
//!    `signature` field inside the signed `TBSCertificate`. A mismatch is a classic
//!    signature-substitution vector: the signature is computed and verified over
//!    `tbsCertificate.signature`, so an attacker who can get a relying party to instead trust the
//!    outer `signatureAlgorithm` (e.g. to downgrade to a weaker algorithm) needs this equality to
//!    NOT be checked.
//! 2. **RFC 5280 §4.1.2.1 / §4.1.2.9**: `extensions` is a v3-only field (`[3] EXPLICIT Extensions
//!    OPTIONAL` — "v3" in the ASN.1 comment in [`crate::x509_tbs_certificate`]'s module docs) — a
//!    certificate that carries extensions but declares `version` other than v3 is not a conforming
//!    RFC 5280 certificate, even though both fields independently decode without error.
//!
//! 3. **RFC 5280 §4.1.2.5 / §4.1.2.5.1 / §4.1.2.5.2**: `tbsCertificate.validity`'s two `Time`
//!    CHOICE fields (`notBefore`, `notAfter`) must each use the encoding the RFC mandates for their
//!    calendar year: **UTCTime for years through 2049, GeneralizedTime for years 2050 and later**.
//!    [`crate::x509_validity`]'s own module docs name this exact rule and explicitly decline to
//!    enforce it (`parse_validity` accepts either `Time` spelling for either field, in any
//!    combination) — this module is that rule's caller-side home. Unlike rules 1 and 2, this rule
//!    is **one-directional at runtime**: §4.1.2.5.1 *defines* UTCTime's year range as exactly
//!    1950–2049 (implemented by [`crate::utc_time::full_year_rfc5280`]'s `year2 < 50 ⇒ 20YY`,
//!    `year2 ≥ 50 ⇒ 19YY` mapping), so a `Time::Utc` value can *never* denote a year `>= 2050` —
//!    that half of the rule holds **structurally, by construction**, not by a check that could ever
//!    fire. The only direction a runtime check can (and must) catch is a `Time::Generalized` value
//!    whose year is `<= 2049`, which §4.1.2.5.2 forbids (GeneralizedTime is reserved for
//!    2050-and-later). See `check_time_encoding_year`'s doc comment (private) for the same point at
//!    the call site, and `proofs::utc_time_can_never_denote_2050_or_later` for the machine-checked
//!    proof of the structural half this module relies on (whose own premise, `year2 <= 99`, is
//!    discharged for decoder output by `crate::utc_time`'s `decode_postcondition_fields_in_range`).
//! 4. **RFC 5280 §4.1.2.5.2**: a `GeneralizedTime` used in `validity` MUST NOT include fractional
//!    seconds ("YYYYMMDDHHMMSSZ"). X.690 DER itself permits a canonical fraction, and
//!    [`crate::generalized_time`] accepts one, so a certificate whose `notBefore` or `notAfter` is a
//!    GeneralizedTime with a fraction decodes without error and is rejected only here, through
//!    [`crate::generalized_time::require_no_fraction`]. The rule applies to the `Time::Generalized`
//!    arm only: a `Time::Utc` value has no fraction field at all, so that arm is structurally
//!    compliant. Rule 4 is independent of rule 3's year check (a 2050-or-later GeneralizedTime with
//!    a fraction passes rule 3 and fails rule 4), and it is checked after rule 3 for both fields (see
//!    [`validate_profile`] for the exact order).
//! 5. **RFC 5280 §4.2** (profile row `PROF-P-12`): a certificate MUST NOT include more than one
//!    instance of a particular extension. [`crate::x509_extension::validate_extensions`] accepts two
//!    `Extension`s with the same `extnID` (each is a valid `Extension` on its own), so the
//!    duplicate check lives here: [`ProfileError::DuplicateExtension`]. The `extnID`s are compared
//!    as canonical OID **content octets**, so two spellings of one extension that differ in
//!    `critical` or `extnValue` still count as the same extension. A caller that uses
//!    `validate_extensions` alone does not get this check.
//! 6. **RFC 5280 §4.1.2.4** (profile row `PROF-P-13`): the `issuer` field MUST contain a non-empty
//!    distinguished name. [`crate::x509_name::validate_name`] accepts the empty `Name` (`30 00`) by
//!    design, because an empty `subject` is legal, so only the `issuer` is checked here, as
//!    [`ProfileError::EmptyIssuer`]. An empty `subject` is not a violation.
//! 7. **X.501 §9.3** (profile row `PROF-P-14`): a `RelativeDistinguishedName` holds at most one
//!    value for each attribute type. [`crate::x509_name::validate_name`] and
//!    [`crate::set_of::decode_set_of`] accept two `AttributeTypeAndValue`s with the same `type`
//!    in one RDN, so the check lives here, for the `issuer` ([`ProfileError::IssuerDuplicateAttributeType`])
//!    and the `subject` ([`ProfileError::SubjectDuplicateAttributeType`]). The attribute types are
//!    compared as canonical OID content octets. The same type in two different RDNs of one Name is
//!    legal.
//!
//! **Scope.** For a *parser-produced* `Certificate` (the output of
//! [`crate::x509_certificate::parse_certificate`]), both `Certificate` and `TbsCertificate` are
//! already fully structurally parsed by the time [`validate_profile`] runs — this module inspects
//! already-materialized fields (`AlgorithmIdentifier` values, the `version` `u8`, the `extensions`
//! `Option`, the `Validity`'s two `Time` CHOICE arms, their year fields, and the emptiness of a
//! GeneralizedTime's fraction). Rules 1 to 4 perform no byte-level decoding of their own. Rules 5
//! to 7 re-walk the already-validated `extensions`, `issuer` and `subject` byte spans with
//! [`crate::sequence::Elements`], [`crate::sequence::decode_sequence_tlv_strict`] and
//! [`crate::tlv::decode_tlv`] (read-only framing walks; they validate nothing that the parsers did
//! not). On a hand-built span that does not walk (a truncated or mis-tagged element), the walk
//! stops at the first element it cannot frame and reports no violation for the rest: rules 5 to 7
//! are decided on the elements they can read. The structural claims in
//! these docs hold for parser-produced values only: the fields of `Certificate` and its parts are
//! public, so a caller can also build a value by hand that no parser would produce, and
//! `validate_profile` reads such a value's fields exactly as it reads any other. It
//! establishes the pattern the rest of the profile layer (key usage, basic constraints, name
//! constraints, path validation, …) is expected to follow: a separate module, downstream of the
//! structural parsers, that never modifies their logic.
//!
//! # Examples
//!
//! ```
//! use der_verified::profile::validate_profile;
//! use der_verified::x509_certificate::parse_certificate;
//!
//! // A complete v3 Ed25519 certificate whose outer signatureAlgorithm matches
//! // tbsCertificate.signature, and whose UTCTime validity dates are both pre-2050.
//! #[rustfmt::skip]
//! const CERT_DER: [u8; 170] = [
//!     0x30, 0x81, 0xa7, 0x30, 0x81, 0x98, 0xa0, 0x03,
//!     0x02, 0x01, 0x02, 0x02, 0x01, 0x01, 0x30, 0x05,
//!     0x06, 0x03, 0x2b, 0x65, 0x70, 0x30, 0x15, 0x31,
//!     0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03,
//!     0x0c, 0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c,
//!     0x65, 0x20, 0x43, 0x41, 0x30, 0x1e, 0x17, 0x0d,
//!     0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30,
//!     0x30, 0x30, 0x30, 0x30, 0x5a, 0x17, 0x0d, 0x39,
//!     0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35,
//!     0x39, 0x35, 0x39, 0x5a, 0x30, 0x15, 0x31, 0x13,
//!     0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c,
//!     0x0a, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
//!     0x20, 0x43, 0x41, 0x30, 0x2a, 0x30, 0x05, 0x06,
//!     0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00, 0x01,
//!     0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
//!     0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11,
//!     0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19,
//!     0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0xa3,
//!     0x0d, 0x30, 0x0b, 0x30, 0x09, 0x06, 0x03, 0x55,
//!     0x1d, 0x13, 0x04, 0x02, 0x30, 0x00, 0x30, 0x05,
//!     0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x03, 0x00,
//!     0xaa, 0xbb,
//! ];
//!
//! let cert = parse_certificate(&CERT_DER).unwrap();
//! assert_eq!(validate_profile(&cert), Ok(()));
//! ```

use crate::generalized_time::require_no_fraction;
use crate::oid::TAG as OID_TAG;
use crate::sequence::{decode_sequence_tlv_strict, Elements, SET_TAG, TAG as SEQUENCE_TAG};
use crate::tag::Class;
use crate::tlv::{decode_tlv, Tlv};
use crate::x509_certificate::Certificate;
use crate::x509_validity::Time;

/// Why a structurally-valid [`Certificate`] failed an RFC 5280 profile check. Every variant names
/// a specific cross-field rule this module enforces (see the module docs), citing the RFC clause,
/// distinct from the structural [`crate::x509_certificate::CertificateError`] /
/// [`crate::x509_tbs_certificate::TbsCertificateError`] that bytes already had to pass for the
/// parsers to produce a [`Certificate`] at all (a value built by hand from the public fields skips
/// those checks).
///
/// This enum is `#[non_exhaustive]`: later releases may add error variants, so a `match` over it
/// outside this crate needs a wildcard arm. The attribute only protects `match` expressions from
/// breaking on a new variant; stricter validation can still change behaviour incompatibly.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
pub enum ProfileError {
    /// RFC 5280 §4.1.1.2: `Certificate.signatureAlgorithm` MUST equal
    /// `Certificate.tbsCertificate.signature`. Both are structurally valid `AlgorithmIdentifier`s
    /// individually, but their `algorithm_oid` and/or `parameters` differ.
    SignatureAlgorithmMismatch,
    /// RFC 5280 §4.1.2.1 / §4.1.2.9: `extensions` is present in `tbsCertificate`, but `version` is
    /// not v3 (integer value `2`). Extensions are a v3-only field.
    ExtensionsRequireV3,
    /// RFC 5280 §4.1.2.5.2: `tbsCertificate.validity.notBefore` is encoded as GeneralizedTime, but
    /// its year is `<= 2049` — years through 2049 MUST use UTCTime, not GeneralizedTime.
    NotBeforeGeneralizedTimeYearTooEarly,
    /// RFC 5280 §4.1.2.5.2: `tbsCertificate.validity.notAfter` is encoded as GeneralizedTime, but
    /// its year is `<= 2049` — years through 2049 MUST use UTCTime, not GeneralizedTime.
    NotAfterGeneralizedTimeYearTooEarly,
    /// RFC 5280 §4.1.2.5.2: `tbsCertificate.validity.notBefore` is encoded as GeneralizedTime and
    /// carries fractional seconds — a GeneralizedTime in `validity` MUST NOT include them.
    NotBeforeGeneralizedTimeHasFraction,
    /// RFC 5280 §4.1.2.5.2: `tbsCertificate.validity.notAfter` is encoded as GeneralizedTime and
    /// carries fractional seconds — a GeneralizedTime in `validity` MUST NOT include them.
    NotAfterGeneralizedTimeHasFraction,
    /// RFC 5280 §4.2 (profile rule P-12): `tbsCertificate.extensions` contains two `Extension`s
    /// with the same `extnID` — a certificate MUST NOT include more than one instance of a
    /// particular extension. The `extnID`s are compared as canonical OID content octets.
    DuplicateExtension,
    /// RFC 5280 §4.1.2.4 (profile rule P-13): `tbsCertificate.issuer` is the empty `Name`
    /// (an `RDNSequence` with zero RDNs, `30 00`) — the issuer field MUST contain a non-empty
    /// distinguished name. An empty `subject` is legal and is not reported.
    EmptyIssuer,
    /// X.501 §9.3 (profile rule P-14): a `RelativeDistinguishedName` of `tbsCertificate.issuer`
    /// holds two `AttributeTypeAndValue`s with the same attribute type. The types are compared as
    /// canonical OID content octets.
    IssuerDuplicateAttributeType,
    /// X.501 §9.3 (profile rule P-14): a `RelativeDistinguishedName` of `tbsCertificate.subject`
    /// holds two `AttributeTypeAndValue`s with the same attribute type. The types are compared as
    /// canonical OID content octets.
    SubjectDuplicateAttributeType,
}

/// RFC 5280 §4.1.2.5 / §4.1.2.5.1 / §4.1.2.5.2: check one already-decoded `Time` CHOICE value
/// against the year-2050 encoding-choice rule (UTCTime through 2049, GeneralizedTime from 2050 on).
///
/// **Only one direction of the rule needs a runtime check.** §4.1.2.5.1 *defines* UTCTime to encode
/// exactly the years 1950–2049 — [`crate::utc_time::full_year_rfc5280`] (`year2 < 50 ⇒ 20YY`,
/// `year2 ≥ 50 ⇒ 19YY`) implements that window exactly, so its codomain is `1950..=2049` and a
/// `Time::Utc` value can *never* denote a year `>= 2050`. "UTCTime used for a year `>= 2050`" is
/// therefore impossible **by construction** — a stronger guarantee than a runtime check that could
/// never fire, so no such check (and no corresponding `ProfileError` variant) exists. The
/// `Time::Generalized` arm is the only reachable violation: §4.1.2.5.2 reserves GeneralizedTime for
/// years 2050 and later, so a `Time::Generalized` value with `year <= 2049` violates the rule.
///
/// `on_generalized_too_early` lets the caller report which of `notBefore` / `notAfter` was the
/// offending field, via its own dedicated [`ProfileError`] variant. See
/// `proofs::utc_time_can_never_denote_2050_or_later` for the machine-checked proof of the structural
/// half described above, and `crate::utc_time`'s `decode_postcondition_fields_in_range` for the
/// decoder postcondition (`year2 <= 99`) that proof's premise needs.
fn check_time_encoding_year(
    time: &Time<'_>,
    on_generalized_too_early: ProfileError,
) -> Result<(), ProfileError> {
    if let Time::Generalized(t) = time {
        if t.year <= 2049 {
            return Err(on_generalized_too_early);
        }
    }
    Ok(())
}

/// RFC 5280 §4.1.2.5.2: check one already-decoded `Time` CHOICE value against the no-fractional-
/// seconds rule. Only the `Time::Generalized` arm can violate it (`Time::Utc` carries no fraction
/// field); the decision is [`crate::generalized_time::require_no_fraction`], whose biconditional
/// with "the input carried no fraction octets" is proved in `crate::generalized_time`.
/// `on_fraction` lets the caller report which of `notBefore` / `notAfter` was the offending field.
fn check_time_no_fraction(time: &Time<'_>, on_fraction: ProfileError) -> Result<(), ProfileError> {
    if let Time::Generalized(t) = time {
        if !require_no_fraction(t) {
            return Err(on_fraction);
        }
    }
    Ok(())
}

/// The `extnID` / attribute-type OID **content octets** of one element of a SEQUENCE OF
/// `Extension` or of a SET OF `AttributeTypeAndValue`: `element` must be a constructed UNIVERSAL 16
/// SEQUENCE whose first child is a primitive UNIVERSAL 6 OBJECT IDENTIFIER. Returns `None` for any
/// element that does not frame that way (only a hand-built span can contain one: the parsers
/// reject it).
fn leading_oid<'a>(element: &Tlv<'a>) -> Option<&'a [u8]> {
    if element.tag.class != Class::Universal || element.tag.number != SEQUENCE_TAG || !element.tag.constructed {
        return None;
    }
    match decode_tlv(element.value) {
        Ok((id, _))
            if id.tag.class == Class::Universal && id.tag.number == OID_TAG && !id.tag.constructed =>
        {
            Some(id.value)
        }
        _ => None,
    }
}

/// `true` iff two elements of `content` (a concatenation of `Extension`s or of
/// `AttributeTypeAndValue`s) have the same [`leading_oid`] content octets. Compares every element
/// with each later one (quadratic in the element count, allocation-free). Elements whose
/// [`leading_oid`] is `None` take no part, and the walk stops at the first element that does not
/// frame.
fn has_repeated_leading_oid(content: &[u8]) -> bool {
    let mut outer = Elements::new(content);
    while let Some(Ok(first)) = outer.next() {
        if let Some(id) = leading_oid(&first) {
            let mut later = outer.clone();
            while let Some(Ok(other)) = later.next() {
                if leading_oid(&other) == Some(id) {
                    return true;
                }
            }
        }
    }
    false
}

/// P-12 (RFC 5280 §4.2): `true` iff `extensions` (the inner `Extensions` SEQUENCE TLV) holds two
/// `Extension`s with the same `extnID` content octets.
fn extensions_repeat_an_id(extensions: &[u8]) -> bool {
    match decode_sequence_tlv_strict(extensions) {
        Ok(content) => has_repeated_leading_oid(content),
        Err(_) => false,
    }
}

/// P-13 (RFC 5280 §4.1.2.4): `true` iff `name` is exactly the empty `RDNSequence`, `30 00`.
fn name_is_empty(name: &[u8]) -> bool {
    matches!(decode_sequence_tlv_strict(name), Ok(content) if content.is_empty())
}

/// P-14 (X.501 §9.3): `true` iff some `RelativeDistinguishedName` of `name` (a whole `Name` TLV)
/// holds two `AttributeTypeAndValue`s with the same `type` content octets. The walk stops at the
/// first RDN that does not frame as a constructed UNIVERSAL 17 SET.
fn name_has_repeated_attribute_type(name: &[u8]) -> bool {
    let rdns = match decode_sequence_tlv_strict(name) {
        Ok(content) => content,
        Err(_) => return false,
    };
    for rdn in Elements::new(rdns) {
        match rdn {
            Ok(rdn) => {
                if rdn.tag.class != Class::Universal || rdn.tag.number != SET_TAG || !rdn.tag.constructed {
                    return false;
                }
                if has_repeated_leading_oid(rdn.value) {
                    return true;
                }
            }
            Err(_) => return false,
        }
    }
    false
}

/// Check `cert` against this module's RFC 5280 / X.501 profile rules (see the module docs for
/// exactly which seven).
///
/// `cert` is expected to be a structurally-valid [`Certificate`] (i.e. the output of
/// [`crate::x509_certificate::parse_certificate`]; the public fields also allow a hand-built value,
/// which is not checked structurally) — rules 1 to 4 perform no DER decoding of their own, only
/// comparisons over already-materialized fields, and rules 5 to 7 only re-walk the already-validated
/// `extensions`, `issuer` and `subject` spans (see the module docs). Returns `Ok(())` if all rules
/// hold, else the first violated rule's [`ProfileError`] (checked in the order the variants are
/// declared: signature-algorithm equality, then the extensions/version rule, then `notBefore`'s
/// encoding-choice year rule, then `notAfter`'s, then `notBefore`'s no-fractional-seconds rule, then
/// `notAfter`'s, then the duplicate-extension rule (P-12), then the empty-issuer rule (P-13), then the
/// repeated-attribute-type rule for the issuer and then for the subject (P-14)). Rule 4 is checked
/// after both rule 3 fields, and rules 5 to 7 after rule 4, so that the errors reported for
/// certificates that were already rejected before those rules existed are unchanged.
pub fn validate_profile(cert: &Certificate<'_>) -> Result<(), ProfileError> {
    // Rule 1 (§4.1.1.2): outer signatureAlgorithm == tbsCertificate.signature. `AlgorithmIdentifier`
    // derives `PartialEq`/`Eq`, comparing both `algorithm_oid` (byte slice) and `parameters`
    // (`Option<&[u8]>`) — exactly the "algorithm_oid bytes AND parameters" the rule requires.
    if cert.signature_algorithm != cert.tbs_certificate.signature {
        return Err(ProfileError::SignatureAlgorithmMismatch);
    }

    // Rule 2 (§4.1.2.1 / §4.1.2.9): extensions present => version must be v3 (2).
    if cert.tbs_certificate.extensions.is_some() && cert.tbs_certificate.version != 2 {
        return Err(ProfileError::ExtensionsRequireV3);
    }

    // Rule 3 (§4.1.2.5 / §4.1.2.5.1 / §4.1.2.5.2): notBefore/notAfter must each use the RFC-mandated
    // encoding for their calendar year (UTCTime through 2049, GeneralizedTime from 2050 on). Only
    // the GeneralizedTime-too-early direction needs a runtime check -- see
    // `check_time_encoding_year`'s doc comment for why the UTCTime-too-late direction is
    // structurally impossible (§4.1.2.5.1's 1950-2049 window), not merely unchecked.
    let validity = &cert.tbs_certificate.validity;
    check_time_encoding_year(&validity.not_before, ProfileError::NotBeforeGeneralizedTimeYearTooEarly)?;
    check_time_encoding_year(&validity.not_after, ProfileError::NotAfterGeneralizedTimeYearTooEarly)?;

    // Rule 4 (§4.1.2.5.2): a GeneralizedTime in validity MUST NOT include fractional seconds.
    // `Time::Utc` has no fraction field, so only the Generalized arm is checked. Checked after both
    // rule-3 fields (declaration order), notBefore first.
    check_time_no_fraction(&validity.not_before, ProfileError::NotBeforeGeneralizedTimeHasFraction)?;
    check_time_no_fraction(&validity.not_after, ProfileError::NotAfterGeneralizedTimeHasFraction)?;

    // Rule 5 (P-12, RFC 5280 §4.2): no extension appears twice (compared by extnID content octets).
    if let Some(extensions) = cert.tbs_certificate.extensions {
        if extensions_repeat_an_id(extensions) {
            return Err(ProfileError::DuplicateExtension);
        }
    }

    // Rule 6 (P-13, RFC 5280 §4.1.2.4): the issuer Name is not empty. The subject may be empty.
    if name_is_empty(cert.tbs_certificate.issuer) {
        return Err(ProfileError::EmptyIssuer);
    }

    // Rule 7 (P-14, X.501 §9.3): no RDN repeats an attribute type; issuer first, then subject.
    if name_has_repeated_attribute_type(cert.tbs_certificate.issuer) {
        return Err(ProfileError::IssuerDuplicateAttributeType);
    }
    if name_has_repeated_attribute_type(cert.tbs_certificate.subject) {
        return Err(ProfileError::SubjectDuplicateAttributeType);
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::bit_string::BitString;
    use crate::generalized_time::GeneralizedTime;
    use crate::utc_time::{full_year_rfc5280, UtcTime};
    use crate::tag::Tag;
    use crate::x509_algorithm_identifier::AlgorithmIdentifier;
    use crate::x509_spki::SubjectPublicKeyInfo;
    use crate::x509_tbs_certificate::TbsCertificate;
    use crate::x509_validity::Validity;

    /// Build a `Certificate` whose *profile-relevant* fields are symbolic and whose
    /// profile-irrelevant fields are fixed.
    ///
    /// This is the whole reason `profile` is cheap to verify where the `x509_*` modules are not: rules
    /// 1 to 4 perform **no byte-level decoding** (the module docs say so), so a harness does not
    /// need a symbolic DER buffer and a parse -- it needs a symbolic *value*. The opaque byte-span
    /// fields (`serial_number`, `issuer`, `subject`, key material) are not read by rules 1 to 4, so
    /// fixing them to an empty slice loses no generality for the harnesses that isolate those rules;
    /// what stays symbolic is exactly what rules 1 to 4 inspect.
    ///
    /// The empty `issuer` and `subject` do not frame as a `Name`, so rules 6 and 7 cannot fire on them,
    /// and the callers pass either no `extensions` or the empty `Extensions` list `30 00`, which holds no
    /// element, so rule 5 cannot fire either. The harnesses that use this builder therefore replace the
    /// three rule 5 to 7 helpers by `stub_rule_never_fires` (they cost CBMC a symbolic element walk and
    /// a `memcmp` unwinding each); that replacement is sound because the unit test
    /// `tests::rules_5_to_7_helpers_return_false_on_the_isolation_inputs` shows the real helpers return
    /// `false` on exactly these inputs (concrete inputs, so a test decides it as well as Kani does).
    /// The harnesses for rules 5 to 7 build their spans themselves with `symbolic_cert_names`.
    fn symbolic_cert<'a>(
        sig_alg: AlgorithmIdentifier<'a>,
        tbs_sig: AlgorithmIdentifier<'a>,
        version: u8,
        extensions: Option<&'a [u8]>,
        validity: Validity<'a>,
    ) -> Certificate<'a> {
        const EMPTY: &[u8] = &[];
        symbolic_cert_names(sig_alg, tbs_sig, version, extensions, validity, EMPTY, EMPTY)
    }

    /// `symbolic_cert` with caller-chosen `issuer` and `subject` spans, for the harnesses that
    /// exercise rules 5 to 7 (P-12 to P-14) or that must hold them satisfied through stubs.
    /// `symbolic_cert` passes the empty slice for both.
    fn symbolic_cert_names<'a>(
        sig_alg: AlgorithmIdentifier<'a>,
        tbs_sig: AlgorithmIdentifier<'a>,
        version: u8,
        extensions: Option<&'a [u8]>,
        validity: Validity<'a>,
        issuer: &'a [u8],
        subject: &'a [u8],
    ) -> Certificate<'a> {
        const EMPTY: &[u8] = &[];
        Certificate {
            tbs_certificate: TbsCertificate {
                version,
                serial_number: EMPTY,
                signature: tbs_sig,
                issuer,
                validity,
                subject,
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm_oid: EMPTY,
                    parameters: None,
                    subject_public_key: BitString { data: EMPTY, unused: 0 },
                },
                extensions,
            },
            signature_algorithm: sig_alg,
            signature_value: BitString { data: EMPTY, unused: 0 },
        }
    }

    // ---- Stubs for the rule 5 to 7 helpers (modular proof, DECISIONS.md D26 style) ----
    //
    // Rules 5 to 7 re-walk three byte spans with `Elements` and `decode_tlv`, and compare object
    // identifiers with slice equality. Left inline in a harness about rules 1 to 4, that walk
    // multiplies with the symbolic algorithm identifiers (their `memcmp`) and with the symbolic times,
    // and the harness grew from well under 1 GB to an out-of-memory kill at the 20 GB cap
    // (`rule1_mismatch_iff_algorithms_differ`, 11 min 42 s, last log lines unwinding `memcmp` and
    // `leading_oid`; its code had not changed). Every `validate_profile` harness therefore replaces the
    // helpers by one of the stubs below. A stub is sound only when its obligation is discharged. Two are
    // discharged; for one helper the obligation of the nondeterministic and steered stubs is NOT yet
    // discharged by Kani (S5):
    //
    // * `stub_rule_never_fires` returns `false`. It is used where the harness holds rules 5 to 7
    //   satisfied by construction (no `extensions` or the empty list `30 00`; empty `issuer` and
    //   `subject`). Obligation: the real helpers return `false` on those inputs. Discharged by the unit
    //   test `tests::rules_5_to_7_helpers_return_false_on_the_isolation_inputs` (concrete inputs: an
    //   evaluation, so a test decides it as well as Kani does; the Kani version of it ran out of memory at
    //   20 GB, as the symbolic helper harnesses did, see `docs/proof-work/s5-profile-helper-harnesses.md`).
    // * `stub_any_outcome` returns a nondeterministic `bool`. It is used by the totality harness,
    //   which asserts nothing about the outcome. Obligation: the real helpers are total (return a
    //   `bool` and never panic) on every span the harness could pass. DISCHARGED for `name_is_empty`
    //   (`name_is_empty_iff_exactly_30_00`, spans of 0 to 6 octets) and for the envelope and the RDN walk
    //   of the other two helpers up to their inner call (`extensions_repeat_an_id_decides_on_the_envelope`,
    //   `name_has_repeated_attribute_type_decides_on_the_walk`, both with the inner call stubbed); NOT
    //   discharged for `has_repeated_leading_oid` itself (its totality harnesses ran out of memory and are
    //   parked in `docs/proof-work/s5-profile-helper-harnesses.md`). `validate_profile_never_panics`
    //   therefore proves the glue panic-free for every helper outcome, conditional on that one obligation.
    // * `stub_steered_by_bit0` / `stub_steered_by_bit1` return a `bool` read from the first octet of
    //   the span, so the harness (which owns that octet symbolically) can both reach every outcome and
    //   compute the exact expected result from the same octet. A bare `kani::any()` could not be
    //   mirrored by an exact reference. Each stub is a deterministic function of its span, and the
    //   harness spans are independent symbolic windows, so every combination of the rule 5, 6, 7
    //   (issuer) and 7 (subject) outcomes is reachable; that makes the stub an over-approximation of any
    //   total helper (the same one undischarged obligation: `has_repeated_leading_oid` is total). The same span reaching two different helpers (the issuer reaches rule 6 and rule
    //   7) uses different bits, and the issuer and subject are different spans, so a call that read the
    //   wrong field or the wrong helper changes the result and the exact assertion fails.
    //
    // (rustc's dead-code lint does not see the `#[kani::stub]` references as uses.)

    /// Stub for the three helpers where rules 5 to 7 cannot fire (see the block comment above).
    #[allow(dead_code)]
    fn stub_rule_never_fires(_span: &[u8]) -> bool {
        false
    }

    /// Stub for the three helpers where the harness asserts nothing about the outcome.
    #[allow(dead_code)]
    fn stub_any_outcome(_span: &[u8]) -> bool {
        kani::any()
    }

    /// The outcome a steered stub reads from `span`: `true` iff the first octet exists and has a bit
    /// of `mask` set. Used by the stubs and, independently, by the references of the harnesses.
    fn steer(span: &[u8], mask: u8) -> bool {
        span.len() >= 1 && span[0] & mask != 0
    }

    /// Stub steered by bit 0 of the span's first octet (rule 5 on `extensions`, rule 6 on `issuer`).
    #[allow(dead_code)]
    fn stub_steered_by_bit0(span: &[u8]) -> bool {
        steer(span, 1)
    }

    /// Stub steered by bit 1 of the span's first octet (rule 7 on `issuer` and on `subject`).
    #[allow(dead_code)]
    fn stub_steered_by_bit1(span: &[u8]) -> bool {
        steer(span, 2)
    }

    /// A symbolic `AlgorithmIdentifier` over a caller-owned 2-octet OID buffer and an optional
    /// 1-octet parameters buffer. Both are what rule 1's `PartialEq` actually compares.
    fn symbolic_alg<'a>(oid: &'a [u8; 2], params: &'a [u8; 1], has_params: bool) -> AlgorithmIdentifier<'a> {
        AlgorithmIdentifier {
            algorithm_oid: oid,
            parameters: if has_params { Some(params) } else { None },
        }
    }

    /// A symbolic `Time`: either arm, with a symbolic year on each.
    fn symbolic_time<'a>(is_generalized: bool, gen_year: u16, year2: u8, frac: &'a [u8; 1], has_frac: bool) -> Time<'a> {
        if is_generalized {
            Time::Generalized(GeneralizedTime {
                year: gen_year,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                fraction: if has_frac { frac } else { &[] },
            })
        } else {
            Time::Utc(UtcTime { year2, month: 1, day: 1, hour: 0, minute: 0, second: 0 })
        }
    }

    /// A symbolic window `&b[..n]` with `n` symbolic over `0..=2` (the whole backing).
    fn window(b: &[u8; 2]) -> &[u8] {
        let n: usize = kani::any();
        kani::assume(n <= 2);
        &b[..n]
    }

    /// A `Time` with EVERY field symbolic, for the whole-function oracle: which arm; for the
    /// UTCTime arm every `UtcTime` field over its full `u8` range (no `year2 <= 99` assumption: the
    /// fields are `pub` and `validate_profile` does not read them); for the GeneralizedTime arm every
    /// field symbolic (`year: u16`, `month`/`day`/`hour`/`minute`/`second: u8`, and a fraction that is
    /// a symbolic window of `0..=4` octets over `frac_back`, i.e. empty or 1 to 4 arbitrary octets, not
    /// restricted to canonical digits). Returns the time and the three facts the reference needs (the
    /// arm, the Generalized year, and the fraction's length in octets, 0 for the UTCTime arm; the
    /// reference reads nothing else, per the module docs). The fraction length is taken from the
    /// window's own `n`, not from `require_no_fraction` or `slice::is_empty` on the built value.
    fn any_time<'a>(frac_back: &'a [u8; 4]) -> (Time<'a>, bool, u16, usize) {
        let is_gen: bool = kani::any();
        let year: u16 = kani::any();
        if is_gen {
            let flen: usize = kani::any();
            kani::assume(flen <= 4);
            let t = GeneralizedTime {
                year,
                month: kani::any(),
                day: kani::any(),
                hour: kani::any(),
                minute: kani::any(),
                second: kani::any(),
                fraction: &frac_back[..flen],
            };
            (Time::Generalized(t), true, year, flen)
        } else {
            let u = UtcTime {
                year2: kani::any(),
                month: kani::any(),
                day: kani::any(),
                hour: kani::any(),
                minute: kani::any(),
                second: kani::any(),
            };
            (Time::Utc(u), false, year, 0)
        }
    }

    // ---- P2: the structural half `profile` leans on ----

    /// RFC 5280 §4.1.2.5.1's window, as a proof rather than a loop-over-100-cases test: for every
    /// two-digit year a decoder can produce, the profile year is in `1950..=2049` — so a `Time::Utc`
    /// **can never denote 2050 or later** and the missing "UTCTime used past 2049" check is
    /// impossible-by-construction rather than merely absent.
    ///
    /// The `y <= 99` premise is not an assumption about the world: it is
    /// `utc_time::decode_postcondition_fields_in_range`'s conclusion, proven over symbolic content.
    /// The one case it does NOT cover is a hand-written `UtcTime { year2: 100.. }` struct literal
    /// (the fields are `pub`). `full_year_rfc5280` maps `100..=149` to `2000..=2049` and only
    /// `150..=255` above 2049; see the disclosure in this module's docs.
    #[kani::proof]
    #[kani::unwind(4)]
    fn utc_time_can_never_denote_2050_or_later() {
        let year2: u8 = kani::any();
        kani::assume(year2 <= 99);
        let full = full_year_rfc5280(&UtcTime { year2, month: 1, day: 1, hour: 0, minute: 0, second: 0 });
        assert!(full >= 1950 && full <= 2049);
        assert!(full < 2050);
        kani::cover(full == 2049, "the upper edge of the UTCTime window is reachable");
        kani::cover(full == 1950, "the lower edge of the UTCTime window is reachable");
    }

    // ---- P3: rule 1, as a biconditional ----

    /// Raw byte-by-byte inequality of two slices with an explicit length check -- the oracle's own
    /// equality, deliberately *not* the derived `PartialEq` the implementation relies on.
    fn raw_bytes_differ(x: &[u8], y: &[u8]) -> bool {
        if x.len() != y.len() {
            return true;
        }
        let mut i = 0;
        while i < x.len() {
            if x[i] != y[i] {
                return true;
            }
            i += 1;
        }
        false
    }

    /// Rule 1 (§4.1.1.2), **exactly**: `validate_profile` rejects with `SignatureAlgorithmMismatch`
    /// if and only if the outer `signatureAlgorithm` differs from `tbsCertificate.signature` --
    /// the OID octets differ (by length or by a byte), or exactly one side carries `parameters`,
    /// or both do and their octets differ. The oracle is computed from the raw OID / parameter
    /// bytes with `raw_bytes_differ`, not with `AlgorithmIdentifier`'s derived `PartialEq`. The
    /// OIDs and parameters are symbolic over a 4-octet backing with symbolic lengths `0..=4` (so
    /// unequal-length comparison is exercised), and `parameters` is symbolically present/absent on
    /// both sides. The assertion pins the EXACT result (`Err(SignatureAlgorithmMismatch)` when the
    /// identifiers differ, `Ok(())` when they are equal -- rules 2 and 3 are held satisfied), so
    /// neither an over-eager nor a missing check, nor a different error for an equal pair, can pass.
    ///
    /// Rules 5 to 7 are stubbed out (`stub_rule_never_fires`): the certificate carries the empty
    /// `Extensions` list `30 00` and an empty `issuer` and `subject`, on which the real helpers return
    /// `false` (discharged by the unit test `tests::rules_5_to_7_helpers_return_false_on_the_isolation_inputs`). Unwind 6
    /// is the value this harness had before rules 5 to 7 existed (when it verified in well under
    /// 1 GB); with the stubs, the loops left in its path are the same ones as then (the 4-octet OID and
    /// parameter comparisons and `raw_bytes_differ`), so the bound is unchanged.
    #[kani::proof]
    #[kani::stub(extensions_repeat_an_id, stub_rule_never_fires)]
    #[kani::stub(name_is_empty, stub_rule_never_fires)]
    #[kani::stub(name_has_repeated_attribute_type, stub_rule_never_fires)]
    #[kani::unwind(6)]
    fn rule1_mismatch_iff_algorithms_differ() {
        let oid_a: [u8; 4] = kani::any();
        let oid_b: [u8; 4] = kani::any();
        let par_a: [u8; 4] = kani::any();
        let par_b: [u8; 4] = kani::any();
        let la: usize = kani::any();
        let lb: usize = kani::any();
        let lpa: usize = kani::any();
        let lpb: usize = kani::any();
        kani::assume(la <= 4 && lb <= 4 && lpa <= 4 && lpb <= 4);
        let has_a: bool = kani::any();
        let has_b: bool = kani::any();
        let a = AlgorithmIdentifier {
            algorithm_oid: &oid_a[..la],
            parameters: if has_a { Some(&par_a[..lpa]) } else { None },
        };
        let b = AlgorithmIdentifier {
            algorithm_oid: &oid_b[..lb],
            parameters: if has_b { Some(&par_b[..lpb]) } else { None },
        };
        // Hold rules 2 and 3 satisfied so the result isolates rule 1: v3 with extensions present,
        // and both Times a UTCTime (never a rule-3 violation, by P2).
        let t = Time::Utc(UtcTime { year2: 24, month: 1, day: 1, hour: 0, minute: 0, second: 0 });
        const EXT: &[u8] = &[0x30, 0x00];
        let cert = symbolic_cert(a, b, 2, Some(EXT), Validity { not_before: t, not_after: t });
        let r = validate_profile(&cert);
        // Independent oracle: raw OID bytes, then parameter presence, then raw parameter bytes.
        let differ = raw_bytes_differ(&oid_a[..la], &oid_b[..lb])
            || has_a != has_b
            || (has_a && raw_bytes_differ(&par_a[..lpa], &par_b[..lpb]));
        // Rules 2 and 3 cannot fire here (v3 with extensions; both Times UTCTime), so the exact
        // result is the mismatch error when the identifiers differ and `Ok(())` otherwise -- any
        // OTHER error for an equal pair is caught too, not only a missing mismatch.
        assert!(
            r == if differ {
                Err(ProfileError::SignatureAlgorithmMismatch)
            } else {
                Ok(())
            }
        );
        kani::cover(r.is_ok(), "an equal algorithm pair reaches validate_profile's Ok tail");
        kani::cover(
            r == Err(ProfileError::SignatureAlgorithmMismatch)
                && la == lb
                && !raw_bytes_differ(&oid_a[..la], &oid_b[..lb])
                && has_a
                && has_b,
            "a mismatch is detected on `parameters` alone, not only on the OID",
        );
        kani::cover(
            r == Err(ProfileError::SignatureAlgorithmMismatch) && la != lb && oid_a[..la.min(lb)] == oid_b[..la.min(lb)],
            "a mismatch is detected on OID length alone (one OID a strict prefix of the other)",
        );
        kani::cover(
            r == Err(ProfileError::SignatureAlgorithmMismatch)
                && has_a != has_b
                && !raw_bytes_differ(&oid_a[..la], &oid_b[..lb]),
            "a mismatch is detected on `parameters` presence alone (the OID octets are equal)",
        );
        kani::cover(r.is_ok() && has_a && has_b && lpa > 0, "equal non-empty parameters are accepted");
    }

    /// **Whole-function exact-result reference.** Over
    /// symbolic algorithm identifiers (4-octet OID and parameter backings with symbolic lengths
    /// `0..=4` and symbolic parameter presence on each side), a symbolic `version` (all 256 values),
    /// symbolic `extensions` presence, and both `Time`s with EVERY field symbolic (`any_time`: the
    /// UTCTime arm over all `u8` field values, no `year2 <= 99` assumption; the GeneralizedTime arm
    /// with a symbolic `u16` year -- which includes the 2049/2050 boundary -- symbolic
    /// month/day/hour/minute/second and a symbolic 0..=4-octet fraction), `validate_profile(cert)`
    /// equals `expected(..)` EXACTLY. The profile-irrelevant certificate fields are symbolic too:
    /// `serial_number`, the SPKI (OID, optional parameters, key window, unused count) and
    /// `signature_value` are each a symbolic 0..=2-octet window over a 2-octet symbolic backing
    /// (`unused` is any `u8`), so no "never read" argument by inspection is needed: the reference below
    /// depends only on what the module docs say is inspected (algorithm identifiers, `version`,
    /// extensions PRESENCE, each Time's arm, year and fraction emptiness, and the three rule 5 to 7
    /// outcomes), and the assertion proves nothing else changes the result.
    ///
    /// **Rules 5 to 7 are stubbed (modular proof).** The three helpers are replaced by
    /// `stub_steered_by_bit0` (rule 5 on `extensions`, rule 6 on `issuer`) and `stub_steered_by_bit1`
    /// (rule 7 on `issuer` and on `subject`). Each reads its outcome from the first octet of the span it
    /// is given; the `extensions`, `issuer` and `subject` spans are independent symbolic windows of 0 to
    /// 2 octets, so every combination of the four helper outcomes is reachable, and the reference reads
    /// the outcomes from the same octets (`steer`). What this harness proves about rules 5 to 7 is the
    /// glue only: rule 5 runs on the `extensions` span and only when it is present, rule 6 on the
    /// `issuer`, rule 7 on the `issuer` and then on the `subject`, each reports its own variant, and the
    /// whole sits after rule 4 in the documented order. What each helper decides on real DER is shown
    /// in part by the helper harnesses at the end of this module (`name_is_empty_iff_exactly_30_00`,
    /// `leading_oid_is_exact`, and the envelope and RDN-walk harnesses
    /// `extensions_repeat_an_id_decides_on_the_envelope` and
    /// `name_has_repeated_attribute_type_decides_on_the_walk`, whose inner id comparison is stubbed), and
    /// the glue with the real helpers on concrete DER by the unit test
    /// `tests::rules_5_to_7_end_to_end_on_specimens`. The id comparison (`has_repeated_leading_oid`) has
    /// no Kani proof at present: its harnesses ran out of memory and are parked for S5
    /// (`docs/proof-work/s5-profile-helper-harnesses.md`). The PROF rows for rules 5 to 7 are therefore
    /// decided by unit tests on concrete inputs, with Kani proving the glue, the order and the framing
    /// walks only.
    ///
    /// `expected` is an independent total reference written from the documented rule precedence (the
    /// `validate_profile` doc comment and the `ProfileError` declaration order: signature-algorithm,
    /// then extensions/version, then `notBefore`'s year rule, then `notAfter`'s, then `notBefore`'s
    /// no-fraction rule, then `notAfter`'s, then P-12, P-13, P-14 issuer, P-14 subject): algorithm equality is computed from the raw bytes with
    /// `raw_bytes_differ` (not the derived `PartialEq`), the extensions and year rules are spelled
    /// from their RFC statements, and the no-fraction rule (§4.1.2.5.2) is spelled as "a
    /// GeneralizedTime whose fraction window is non-empty" from the window length, not from
    /// `require_no_fraction`. So the rules interact here, not only each in isolation: in particular
    /// rule 1 must win over rules 2 to 4 for every combination of parameter presence, rule 3 (both
    /// fields) must win over rule 4, and `notBefore`'s variant must win over `notAfter`'s within each
    /// rule.
    ///
    /// Bounds (disclosed): 4-octet backings and lengths `0..=4` for the identifier bytes (the same
    /// domain as `rule1_mismatch_iff_algorithms_differ`); 2-octet backings, lengths `0..=2`, for the
    /// irrelevant spans and for the `extensions`, `issuer` and `subject` windows (whose first octet
    /// steers the stubs); a 4-octet backing, length `0..=4`, for each Generalized fraction. Slices
    /// longer than that are not enumerated (for the fraction: lengths above 4 are covered by unit tests
    /// only, and the code reads emptiness, not length). The profile-irrelevant spans and fractions
    /// are inspected only for presence or emptiness, so their windows are representative. The two
    /// algorithm identifiers are compared octet by octet, however, so their `0..=4` windows bound
    /// the proof rather than establishing the result for arbitrary identifier lengths.
    ///
    /// Unwind 6, the value before rules 5 to 7 existed: the widest loops left are the 4-octet
    /// comparisons; the stubs contain none. (The unwind 8 of the monolithic version is no longer
    /// needed: it covered the element walks of rules 5 to 7, which are now outside this harness.)
    #[kani::proof]
    #[kani::stub(extensions_repeat_an_id, stub_steered_by_bit0)]
    #[kani::stub(name_is_empty, stub_steered_by_bit0)]
    #[kani::stub(name_has_repeated_attribute_type, stub_steered_by_bit1)]
    #[kani::unwind(6)]
    fn validate_profile_is_exactly_the_documented_precedence() {
        let oid_a: [u8; 4] = kani::any();
        let oid_b: [u8; 4] = kani::any();
        let par_a: [u8; 4] = kani::any();
        let par_b: [u8; 4] = kani::any();
        let la: usize = kani::any();
        let lb: usize = kani::any();
        let lpa: usize = kani::any();
        let lpb: usize = kani::any();
        kani::assume(la <= 4 && lb <= 4 && lpa <= 4 && lpb <= 4);
        let has_a: bool = kani::any();
        let has_b: bool = kani::any();
        let a = AlgorithmIdentifier {
            algorithm_oid: &oid_a[..la],
            parameters: if has_a { Some(&par_a[..lpa]) } else { None },
        };
        let b = AlgorithmIdentifier {
            algorithm_oid: &oid_b[..lb],
            parameters: if has_b { Some(&par_b[..lpb]) } else { None },
        };
        let version: u8 = kani::any();
        let has_ext: bool = kani::any();
        let frac_nb: [u8; 4] = kani::any();
        let frac_na: [u8; 4] = kani::any();
        let (nb, nb_gen, nb_year, nb_flen) = any_time(&frac_nb);
        let (na, na_gen, na_year, na_flen) = any_time(&frac_na);
        // Profile-irrelevant spans: symbolic windows over symbolic backings.
        let serial: [u8; 2] = kani::any();
        let issuer: [u8; 2] = kani::any();
        let subject: [u8; 2] = kani::any();
        let spki_oid: [u8; 2] = kani::any();
        let spki_par: [u8; 2] = kani::any();
        let spki_key: [u8; 2] = kani::any();
        let sig_val: [u8; 2] = kani::any();
        let ext_back: [u8; 2] = kani::any();
        let spki_has_par: bool = kani::any();
        // The spans rules 5 to 7 are given; the first octet of each steers a stub.
        let ext_span = window(&ext_back);
        let issuer_span = window(&issuer);
        let subject_span = window(&subject);
        let cert = Certificate {
            tbs_certificate: TbsCertificate {
                version,
                serial_number: window(&serial),
                signature: b,
                issuer: issuer_span,
                validity: Validity { not_before: nb, not_after: na },
                subject: subject_span,
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm_oid: window(&spki_oid),
                    parameters: if spki_has_par { Some(window(&spki_par)) } else { None },
                    subject_public_key: BitString { data: window(&spki_key), unused: kani::any() },
                },
                extensions: if has_ext { Some(ext_span) } else { None },
            },
            signature_algorithm: a,
            signature_value: BitString { data: window(&sig_val), unused: kani::any() },
        };
        let r = validate_profile(&cert);

        // Independent total reference, documented precedence.
        let alg_differ = raw_bytes_differ(&oid_a[..la], &oid_b[..lb])
            || has_a != has_b
            || (has_a && raw_bytes_differ(&par_a[..lpa], &par_b[..lpb]));
        let ext_bad = has_ext && version != 2;
        let nb_bad = nb_gen && nb_year <= 2049;
        let na_bad = na_gen && na_year <= 2049;
        let nb_frac = nb_gen && nb_flen > 0;
        let na_frac = na_gen && na_flen > 0;
        // The rule 5 to 7 outcomes the stubs return: the extensions only when present.
        let ext_dup = has_ext && steer(ext_span, 1);
        let issuer_empty = steer(issuer_span, 1);
        let issuer_dup = steer(issuer_span, 2);
        let subject_dup = steer(subject_span, 2);
        let expected = if alg_differ {
            Err(ProfileError::SignatureAlgorithmMismatch)
        } else if ext_bad {
            Err(ProfileError::ExtensionsRequireV3)
        } else if nb_bad {
            Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly)
        } else if na_bad {
            Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly)
        } else if nb_frac {
            Err(ProfileError::NotBeforeGeneralizedTimeHasFraction)
        } else if na_frac {
            Err(ProfileError::NotAfterGeneralizedTimeHasFraction)
        } else if ext_dup {
            Err(ProfileError::DuplicateExtension)
        } else if issuer_empty {
            Err(ProfileError::EmptyIssuer)
        } else if issuer_dup {
            Err(ProfileError::IssuerDuplicateAttributeType)
        } else if subject_dup {
            Err(ProfileError::SubjectDuplicateAttributeType)
        } else {
            Ok(())
        };
        assert!(r == expected);

        kani::cover(
            r == Err(ProfileError::SignatureAlgorithmMismatch) && has_a && has_b && ext_bad,
            "a mismatch with parameters on both sides wins over an extensions/version violation",
        );
        kani::cover(
            r == Err(ProfileError::SignatureAlgorithmMismatch) && (has_a || has_b) && ext_bad && (nb_bad || na_bad),
            "a mismatch with parameters present wins over BOTH an extensions and a time violation",
        );
        kani::cover(
            r == Err(ProfileError::ExtensionsRequireV3) && has_a && has_b && !alg_differ && (nb_bad || na_bad),
            "equal identifiers with parameters present: rule 2 wins over rule 3",
        );
        kani::cover(
            r == Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly) && nb_year == 2049 && has_a && has_b,
            "the 2049 boundary year is rejected with parameters present",
        );
        kani::cover(
            r == Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly) && na_year == 2049,
            "notAfter's variant at the 2049 boundary year",
        );
        kani::cover(r.is_ok() && nb_gen && nb_year == 2050 && has_a && has_b, "the 2050 boundary year is accepted");
        kani::cover(r.is_ok() && has_ext && version == 2 && has_a && has_b && lpa > 0, "a fully conforming certificate with parameters is accepted");
        kani::cover(
            r == Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly)
                && matches!(nb, Time::Generalized(g) if !g.fraction.is_empty()),
            "a too-early GeneralizedTime WITH a non-empty fraction is a year error",
        );
        kani::cover(
            r == Err(ProfileError::NotBeforeGeneralizedTimeHasFraction) && nb_year == 2050 && has_a && has_b,
            "a 2050 notBefore GeneralizedTime WITH a fraction is rejected by rule 4 (the year rule passes it)",
        );
        kani::cover(
            r == Err(ProfileError::NotAfterGeneralizedTimeHasFraction) && na_year >= 2050 && !nb_frac,
            "notAfter's own fraction variant is reachable (notBefore clean)",
        );
        kani::cover(
            r == Err(ProfileError::NotBeforeGeneralizedTimeHasFraction) && na_frac,
            "both fields carry a fraction -- notBefore's variant is the one reported",
        );
        kani::cover(
            r == Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly) && nb_frac,
            "a notBefore fraction does not pre-empt notAfter's year error (rule 3 wins over rule 4)",
        );
        kani::cover(
            r.is_ok() && matches!(nb, Time::Generalized(g) if g.fraction.is_empty()) && nb_year >= 2050,
            "an accepted (2050+) GeneralizedTime with an EMPTY fraction",
        );
        kani::cover(
            r.is_ok() && matches!(nb, Time::Utc(u) if u.year2 > 99),
            "an accepted UTCTime whose hand-built year2 is outside 00..=99",
        );
        kani::cover(
            r.is_ok() && has_ext && matches!(cert.tbs_certificate.extensions, Some(e) if e.is_empty()),
            "an accepted certificate with present-but-empty extensions content",
        );
        kani::cover(
            r == Err(ProfileError::DuplicateExtension) && !nb_frac && !na_frac && has_a && has_b,
            "P-12 is reported once rules 1 to 4 pass (parameters present on both identifiers)",
        );
        kani::cover(
            r == Err(ProfileError::NotAfterGeneralizedTimeHasFraction) && ext_dup && issuer_empty && subject_dup,
            "rule 4 wins over P-12, P-13 and P-14 all violated",
        );
        kani::cover(
            r == Err(ProfileError::DuplicateExtension) && issuer_empty && subject_dup,
            "P-12 wins over P-13 and P-14",
        );
        kani::cover(
            r == Err(ProfileError::EmptyIssuer) && issuer_dup && subject_dup,
            "P-13 wins over both P-14 outcomes",
        );
        kani::cover(
            r == Err(ProfileError::IssuerDuplicateAttributeType) && subject_dup,
            "P-14 reports the issuer before the subject",
        );
        kani::cover(
            r == Err(ProfileError::SubjectDuplicateAttributeType) && !ext_dup && !issuer_empty && !issuer_dup,
            "P-14 reports the subject alone",
        );
        kani::cover(
            r.is_ok() && has_ext && version == 2 && !ext_dup && !issuer_empty && !issuer_dup && !subject_dup,
            "all three of rules 5 to 7 are satisfied and the certificate is accepted",
        );
        kani::cover(
            r.is_ok() && !has_ext && steer(ext_span, 1),
            "rule 5 does not run when extensions are absent, whatever the extensions span would say",
        );
    }

    // ---- P4: rule 2, as a biconditional ----

    /// Rule 2 (§4.1.2.1 / §4.1.2.9), **exactly**: with rule 1 satisfied, `validate_profile` rejects
    /// with `ExtensionsRequireV3` iff `extensions` is present and `version != 2` — over a fully
    /// symbolic `version: u8` (all 256 values, not just 0/1/2) and a symbolic present/absent
    /// `extensions`. Rules 5 to 7 are stubbed out (`stub_rule_never_fires`; the extensions are absent or
    /// the empty list `30 00`, the names empty; see `symbolic_cert`). Unwind 4 is the pre-rules-5-to-7
    /// value: the only loop left is the 2-octet OID comparison.
    #[kani::proof]
    #[kani::stub(extensions_repeat_an_id, stub_rule_never_fires)]
    #[kani::stub(name_is_empty, stub_rule_never_fires)]
    #[kani::stub(name_has_repeated_attribute_type, stub_rule_never_fires)]
    #[kani::unwind(4)]
    fn rule2_requires_v3_iff_extensions_present_and_not_v3() {
        let version: u8 = kani::any();
        let has_ext: bool = kani::any();
        let oid: [u8; 2] = kani::any();
        let alg = symbolic_alg(&oid, &[0], false);
        let t = Time::Utc(UtcTime { year2: 24, month: 1, day: 1, hour: 0, minute: 0, second: 0 });
        const EXT: &[u8] = &[0x30, 0x00];
        let cert = symbolic_cert(alg, alg, version, if has_ext { Some(EXT) } else { None },
                                 Validity { not_before: t, not_after: t });
        let r = validate_profile(&cert);
        assert!((r == Err(ProfileError::ExtensionsRequireV3)) == (has_ext && version != 2));
        kani::cover(r.is_ok() && has_ext, "a v3 certificate WITH extensions is accepted");
        kani::cover(r.is_ok() && !has_ext, "a certificate without extensions is accepted at any version");
        kani::cover(
            r == Err(ProfileError::ExtensionsRequireV3) && version > 2,
            "the rule fires for a version ABOVE v3, not just below it",
        );
    }

    // ---- P5: rule 3, as a biconditional, per field ----

    /// Rule 3 (§4.1.2.5.2), **exactly**, and with the two fields' precedence pinned: with rules 1–2
    /// satisfied (and rule 4 satisfied: every GeneralizedTime here has an empty fraction), `validate_profile` rejects iff at least one of `notBefore` / `notAfter` is a
    /// GeneralizedTime with year `<= 2049`, and it reports `notBefore`'s variant when both are bad —
    /// the order `validate_profile`'s doc comment promises. The certificate has no `extensions` and empty
    /// names, so rules 5 to 7 are stubbed out (`stub_rule_never_fires`; see `symbolic_cert`). Unwind 4 is
    /// the pre-rules-5-to-7 value: the only loop left is the 2-octet OID comparison.
    #[kani::proof]
    #[kani::stub(extensions_repeat_an_id, stub_rule_never_fires)]
    #[kani::stub(name_is_empty, stub_rule_never_fires)]
    #[kani::stub(name_has_repeated_attribute_type, stub_rule_never_fires)]
    #[kani::unwind(4)]
    fn rule3_generalized_too_early_iff_year_le_2049() {
        let nb_gen: bool = kani::any();
        let na_gen: bool = kani::any();
        let nb_year: u16 = kani::any();
        let na_year: u16 = kani::any();
        let nb_y2: u8 = kani::any();
        let na_y2: u8 = kani::any();
        kani::assume(nb_y2 <= 99 && na_y2 <= 99); // the decoder postcondition, see P2
        let frac: [u8; 1] = kani::any();
        let nb = symbolic_time(nb_gen, nb_year, nb_y2, &frac, false);
        let na = symbolic_time(na_gen, na_year, na_y2, &frac, false);
        let oid: [u8; 2] = kani::any();
        let alg = symbolic_alg(&oid, &[0], false);
        let cert = symbolic_cert(alg, alg, 2, None, Validity { not_before: nb, not_after: na });
        let r = validate_profile(&cert);

        let nb_bad = nb_gen && nb_year <= 2049;
        let na_bad = na_gen && na_year <= 2049;
        if nb_bad {
            assert!(r == Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly));
        } else if na_bad {
            assert!(r == Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly));
        } else {
            assert!(r == Ok(()));
        }
        kani::cover(nb_bad && na_bad, "both fields bad -- notBefore's variant is the one reported");
        kani::cover(r.is_ok() && nb_gen && na_gen, "two GeneralizedTimes from 2050 on are accepted");
        kani::cover(r.is_ok() && !nb_gen && !na_gen, "two UTCTimes are accepted");
        kani::cover(
            r == Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly),
            "notAfter's own variant is reachable (notBefore good, notAfter bad)",
        );
    }

    // ---- P5b: rule 4, as a biconditional, per field ----

    /// Rule 4 (§4.1.2.5.2), **exactly**, per field: with rules 1-3 satisfied (equal algorithm
    /// identifiers; a v3 certificate with extensions present; every GeneralizedTime a year `>= 2050`,
    /// every UTCTime unconstrained), `validate_profile` returns `NotBeforeGeneralizedTimeHasFraction`
    /// iff `notBefore` is a GeneralizedTime whose fraction window is non-empty; otherwise
    /// `NotAfterGeneralizedTimeHasFraction` iff `notAfter` is one; otherwise `Ok(())`. The fraction
    /// is a symbolic window of `0..=4` arbitrary octets (the rule inspects emptiness only; lengths above 4
    /// are covered by unit tests, not by this proof) and the
    /// reference is computed from the window length, not from `require_no_fraction`. A UTCTime on
    /// either side (which has no fraction field) is never rejected by this rule. The certificate has the
    /// empty `Extensions` list and empty names, so rules 5 to 7 are stubbed out (`stub_rule_never_fires`;
    /// see `symbolic_cert`). Unwind 4 is the pre-rules-5-to-7 value: the loops left are the 2-octet OID
    /// comparison and the fraction window (at most 4 octets, read only for emptiness).
    #[kani::proof]
    #[kani::stub(extensions_repeat_an_id, stub_rule_never_fires)]
    #[kani::stub(name_is_empty, stub_rule_never_fires)]
    #[kani::stub(name_has_repeated_attribute_type, stub_rule_never_fires)]
    #[kani::unwind(4)]
    fn rule4_fraction_iff_generalized_with_fraction() {
        let frac_nb: [u8; 4] = kani::any();
        let frac_na: [u8; 4] = kani::any();
        let (nb, nb_gen, nb_year, nb_flen) = any_time(&frac_nb);
        let (na, na_gen, na_year, na_flen) = any_time(&frac_na);
        kani::assume(!nb_gen || nb_year >= 2050); // rule 3 satisfied
        kani::assume(!na_gen || na_year >= 2050);
        let oid: [u8; 2] = kani::any();
        let alg = symbolic_alg(&oid, &[0], false);
        const EXT: &[u8] = &[0x30, 0x00];
        let cert = symbolic_cert(alg, alg, 2, Some(EXT), Validity { not_before: nb, not_after: na });
        let r = validate_profile(&cert);

        let nb_frac = nb_gen && nb_flen > 0;
        let na_frac = na_gen && na_flen > 0;
        let expected = if nb_frac {
            Err(ProfileError::NotBeforeGeneralizedTimeHasFraction)
        } else if na_frac {
            Err(ProfileError::NotAfterGeneralizedTimeHasFraction)
        } else {
            Ok(())
        };
        assert!(r == expected);
        kani::cover(nb_frac && na_frac, "both fields carry a fraction -- notBefore's variant is reported");
        kani::cover(
            r == Err(ProfileError::NotAfterGeneralizedTimeHasFraction) && nb_gen && nb_flen == 0,
            "notAfter's own variant is reachable with a clean GeneralizedTime notBefore",
        );
        kani::cover(
            r == Err(ProfileError::NotBeforeGeneralizedTimeHasFraction) && !na_gen,
            "notBefore's variant with a UTCTime notAfter",
        );
        kani::cover(r.is_ok() && nb_gen && na_gen, "two fraction-free GeneralizedTimes (2050+) are accepted");
        kani::cover(r.is_ok() && !nb_gen && !na_gen, "two UTCTimes are accepted");
    }

    // ---- P6: precedence across all seven rules ----

    /// The declared rule ORDER is part of the contract (`validate_profile`'s doc comment states it):
    /// signature-algorithm, then extensions/version, then `notBefore`'s year rule, then `notAfter`'s,
    /// then `notBefore`'s no-fraction rule, then `notAfter`'s, then the duplicate-extension rule (P-12),
    /// then the empty-issuer rule (P-13), then the issuer's and then the subject's repeated-attribute-type
    /// rule (P-14). With every rule independently violable, the reported error is always the first
    /// violated one.
    ///
    /// Rules 5 to 7 are stubbed with the steered stubs (`stub_steered_by_bit0` for rule 5 on
    /// `extensions` and rule 6 on `issuer`, `stub_steered_by_bit1` for rule 7 on `issuer` and `subject`;
    /// see the block comment before `stub_rule_never_fires`). The `extensions`, `issuer` and `subject`
    /// spans are independent symbolic windows of 0 to 2 octets, so every combination of the four helper
    /// outcomes is reachable together with every combination of the rule 1 to 4 outcomes, and the
    /// reference reads each outcome from the same octet (`steer`). The precedence is therefore proven
    /// for ANY outcome of the helpers; the helpers are proven separately (end of this module).
    ///
    /// Unwind 4, the value before rules 5 to 7 existed: the loops left are the 2-octet OID comparison.
    #[kani::proof]
    #[kani::stub(extensions_repeat_an_id, stub_steered_by_bit0)]
    #[kani::stub(name_is_empty, stub_steered_by_bit0)]
    #[kani::stub(name_has_repeated_attribute_type, stub_steered_by_bit1)]
    #[kani::unwind(4)]
    fn error_precedence_follows_declaration_order() {
        let oid_a: [u8; 2] = kani::any();
        let oid_b: [u8; 2] = kani::any();
        let version: u8 = kani::any();
        let has_ext: bool = kani::any();
        let nb_gen: bool = kani::any();
        let na_gen: bool = kani::any();
        let nb_year: u16 = kani::any();
        let na_year: u16 = kani::any();
        let nb_has_frac: bool = kani::any();
        let na_has_frac: bool = kani::any();
        let ext_back: [u8; 2] = kani::any();
        let issuer_back: [u8; 2] = kani::any();
        let subject_back: [u8; 2] = kani::any();
        let a = symbolic_alg(&oid_a, &[0], false);
        let b = symbolic_alg(&oid_b, &[0], false);
        let frac: [u8; 1] = [0];
        let nb = symbolic_time(nb_gen, nb_year, 24, &frac, nb_has_frac);
        let na = symbolic_time(na_gen, na_year, 24, &frac, na_has_frac);
        let ext = window(&ext_back);
        let issuer = window(&issuer_back);
        let subject = window(&subject_back);
        let cert = symbolic_cert_names(
            a,
            b,
            version,
            if has_ext { Some(ext) } else { None },
            Validity { not_before: nb, not_after: na },
            issuer,
            subject,
        );
        let r = validate_profile(&cert);

        let bad1 = a != b;
        let bad2 = has_ext && version != 2;
        let bad3 = nb_gen && nb_year <= 2049;
        let bad4 = na_gen && na_year <= 2049;
        let bad5 = nb_gen && nb_has_frac;
        let bad6 = na_gen && na_has_frac;
        // Rules 5 to 7: the outcome each steered stub returns for the span it is given.
        let bad7 = has_ext && steer(ext, 1);
        let bad8 = steer(issuer, 1);
        let bad9 = steer(issuer, 2);
        let bad10 = steer(subject, 2);
        let expected = if bad1 {
            Err(ProfileError::SignatureAlgorithmMismatch)
        } else if bad2 {
            Err(ProfileError::ExtensionsRequireV3)
        } else if bad3 {
            Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly)
        } else if bad4 {
            Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly)
        } else if bad5 {
            Err(ProfileError::NotBeforeGeneralizedTimeHasFraction)
        } else if bad6 {
            Err(ProfileError::NotAfterGeneralizedTimeHasFraction)
        } else if bad7 {
            Err(ProfileError::DuplicateExtension)
        } else if bad8 {
            Err(ProfileError::EmptyIssuer)
        } else if bad9 {
            Err(ProfileError::IssuerDuplicateAttributeType)
        } else if bad10 {
            Err(ProfileError::SubjectDuplicateAttributeType)
        } else {
            Ok(())
        };
        assert!(r == expected);
        kani::cover(
            bad1 && bad2 && bad3 && bad4 && bad5 && bad6 && bad7 && bad8 && bad9 && bad10,
            "all violations at once -- rule 1 still wins",
        );
        kani::cover(!bad1 && bad2 && bad3, "rule 2 wins over rule 3");
        kani::cover(!bad1 && !bad2 && !bad3 && bad4 && bad5, "notAfter's year error wins over notBefore's fraction error");
        kani::cover(!bad1 && !bad2 && !bad3 && !bad4 && bad5 && bad6, "notBefore's fraction error wins over notAfter's");
        kani::cover(!bad1 && !bad2 && !bad3 && !bad4 && !bad5 && bad6, "notAfter's fraction error is reachable alone");
        kani::cover(
            !bad1 && !bad2 && !bad3 && !bad4 && !bad5 && !bad6 && bad7 && bad8 && bad10,
            "P-12 wins over P-13 and P-14 (the fraction rules are satisfied)",
        );
        kani::cover(
            r == Err(ProfileError::DuplicateExtension) && !bad5 && !bad6 && !bad8 && !bad9 && !bad10,
            "the duplicate-extension error is reachable alone",
        );
        kani::cover(!bad7 && bad8 && bad9 && bad10, "P-13 wins over both P-14 outcomes");
        kani::cover(
            r == Err(ProfileError::EmptyIssuer) && !bad9 && !bad10,
            "the empty-issuer error is reachable alone",
        );
        kani::cover(!bad7 && !bad8 && bad9 && bad10, "the issuer's repeated type wins over the subject's");
        kani::cover(
            r == Err(ProfileError::SubjectDuplicateAttributeType) && !bad7 && !bad8 && !bad9,
            "the subject's repeated-type error is reachable alone",
        );
        kani::cover(
            !has_ext && steer(ext, 1) && r.is_ok(),
            "rule 5 does not run when extensions are absent, whatever the extensions span would say",
        );
        kani::cover(r.is_ok(), "a fully conforming certificate is accepted");
    }

    // ---- P7: totality ----

    /// `validate_profile` is total on symbolic profile-relevant fields: no panic, no arithmetic
    /// overflow, for any combination of the fields the seven rules inspect and for ANY outcome of the
    /// three rule 5 to 7 helpers. The helpers are stubbed by `stub_any_outcome` (a nondeterministic
    /// `bool`). **This proof is conditional.** The helpers' own totality is shown for `name_is_empty` on
    /// spans of 0 to 6 octets (`name_is_empty_iff_exactly_30_00`) and for the envelope and the RDN walk
    /// of the other two helpers with their inner call stubbed
    /// (`extensions_repeat_an_id_decides_on_the_envelope`,
    /// `name_has_repeated_attribute_type_decides_on_the_walk`). It is NOT shown by Kani for the real
    /// `has_repeated_leading_oid`: its totality harnesses ran out of memory at 20 GB and are parked for S5
    /// in `docs/proof-work/s5-profile-helper-harnesses.md`. The unit test
    /// `tests::rules_5_to_7_ignore_spans_that_do_not_frame` runs the real helpers on ten hand-built spans
    /// that do not walk; that is a test, not a proof. `validate_profile` passes the helpers nothing but the
    /// three spans, and the stubs return a `bool`, the only thing the glue uses. The spans this harness
    /// passes are empty (the glue does not read them).
    ///
    /// **Every harness in this module carries an explicit `#[kani::unwind]`, and that is load-bearing
    /// rather than stylistic.** Rule 1 compares two `AlgorithmIdentifier`s, whose `parameters` field
    /// is an `Option<&[u8]>`; with the presence of that `Option` left symbolic, an unbounded harness
    /// sends CBMC into `memcmp` unwinding that does not converge — observed at ~18,000 iterations
    /// before the run was OOM-killed inside its 14 GB cgroup. A finite bound makes it converge, and
    /// CBMC's own unwinding assertion (checked, not assumed) confirms the bound suffices, so the bound
    /// costs no generality. The bound is 4 (the value before rules 5 to 7 existed; the 2-octet OIDs
    /// are the widest loop). Read an OOM on one of these as a missing bound, or as a rule 5 to 7
    /// helper left unstubbed, before reading it as an intractable harness.
    #[kani::proof]
    #[kani::stub(extensions_repeat_an_id, stub_any_outcome)]
    #[kani::stub(name_is_empty, stub_any_outcome)]
    #[kani::stub(name_has_repeated_attribute_type, stub_any_outcome)]
    #[kani::unwind(4)]
    fn validate_profile_never_panics() {
        let oid_a: [u8; 2] = kani::any();
        let oid_b: [u8; 2] = kani::any();
        let par: [u8; 1] = kani::any();
        let has_a: bool = kani::any();
        let has_b: bool = kani::any();
        let version: u8 = kani::any();
        let has_ext: bool = kani::any();
        let nb_gen: bool = kani::any();
        let na_gen: bool = kani::any();
        let nb_year: u16 = kani::any();
        let na_year: u16 = kani::any();
        let y2: u8 = kani::any();
        let frac: [u8; 1] = kani::any();
        let has_frac: bool = kani::any();
        const NO_SPAN: &[u8] = &[];
        let a = symbolic_alg(&oid_a, &par, has_a);
        let b = symbolic_alg(&oid_b, &par, has_b);
        let nb = symbolic_time(nb_gen, nb_year, y2, &frac, has_frac);
        let na = symbolic_time(na_gen, na_year, y2, &frac, has_frac);
        let cert = symbolic_cert_names(
            a,
            b,
            version,
            if has_ext { Some(NO_SPAN) } else { None },
            Validity { not_before: nb, not_after: na },
            NO_SPAN,
            NO_SPAN,
        );
        let r = validate_profile(&cert);
        // A totality harness has no functional `assert!` by construction, so without these it would
        // be the crate's only harness whose sole checks are Kani's implicit panic/overflow/memory
        // ones -- the row PROOF_MANIFEST section 8.2 keeps at 0 and treats as load-bearing. Both are
        // post-state effects of the widest symbolic instance in this module.
        kani::cover(r.is_ok(), "a conforming certificate is accepted at the fully-symbolic bound");
        kani::cover(r.is_err(), "a violating certificate is rejected at the fully-symbolic bound");
        kani::cover(
            r == Err(ProfileError::EmptyIssuer),
            "rule 6 fires on a stubbed helper outcome (the empty-issuer error is reachable)",
        );
        kani::cover(
            r == Err(ProfileError::SubjectDuplicateAttributeType),
            "rule 7 fires on the subject for a stubbed helper outcome (the last rule is reachable)",
        );
    }

    // ---- P8: the rule 5 to 7 helpers, the small proofs that fit ----
    //
    // The `validate_profile` harnesses above replace the three rule 5 to 7 helpers by stubs. These harnesses
    // decide the helpers themselves, each on a symbolic and explicitly bounded input, with an exact
    // assertion against a reference written here (never the helper's own code), and a `kani::cover` for
    // both outcomes: `leading_oid_is_exact`, `name_is_empty_iff_exactly_30_00`, and the two envelope/walk
    // harnesses that stub the inner `has_repeated_leading_oid`. The harnesses that decide
    // `has_repeated_leading_oid` itself (two symbolic totality proofs and the exact proof on three
    // elements) are NOT here: they ran out of memory at the 20 GB cap, because the nested `Elements` walks
    // unwind `decode_length`, `decode_tag` and `memcmp` (about 73,000 verification conditions). They are
    // parked, with their source, the measurement and the S5 plan, in
    // `docs/proof-work/s5-profile-helper-harnesses.md`. Concrete-input facts about the helpers (the
    // stub-discharge facts and the end-to-end specimen matrix) are unit tests in `mod tests`.
    //
    // Unwind 7 where the input is a raw or partly symbolic span: `decode_tag`'s high-tag-number loop
    // reads up to 6 octets of a 6-octet span (6 executions, one more for the exit check), the widest
    // loop on these paths (`decode_length`'s loop runs at most 4 times). The unwinding assertion is
    // checked by CBMC, so a too-low bound fails loud.

    /// `true` iff the two optional OID content slices are both absent, or both present and equal octet
    /// by octet (`raw_bytes_differ`, not slice equality).
    fn same_oid(x: Option<&[u8]>, y: Option<&[u8]>) -> bool {
        match (x, y) {
            (Some(p), Some(q)) => !raw_bytes_differ(p, q),
            (None, None) => true,
            _ => false,
        }
    }

    /// `leading_oid` is exact: for every element whose class, constructed flag and tag number are
    /// symbolic (all four classes, both flags, every `u32` number) and whose value is a symbolic window
    /// of `0..=6` octets, it returns `Some(content octets)` iff the element is UNIVERSAL 16 constructed
    /// and its value starts with a TLV `06 k <k octets>` that lies wholly inside the value, and `None`
    /// otherwise. The reference reads the raw octets (`06`, a length octet that fits, then the content),
    /// not `decode_tlv`. No octet is assumed anything; a long-form length (`>= 0x80`) cannot fit in six
    /// octets and the reference gives `None` for it, matching the decoder's truncation. The proof is
    /// also a totality proof for `leading_oid` on every such value.
    ///
    /// Bounds: value window `0..=6` octets; the element is not nested deeper than its first child.
    #[kani::proof]
    #[kani::unwind(7)]
    fn leading_oid_is_exact() {
        let back: [u8; 6] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 6);
        let class_sel: u8 = kani::any();
        kani::assume(class_sel <= 3);
        let class = if class_sel == 0 {
            Class::Universal
        } else if class_sel == 1 {
            Class::Application
        } else if class_sel == 2 {
            Class::ContextSpecific
        } else {
            Class::Private
        };
        let constructed: bool = kani::any();
        let number: u32 = kani::any();
        let element = Tlv { tag: Tag { class, constructed, number }, value: &back[..len] };
        let got = leading_oid(&element);
        let frames = class_sel == 0 && number == 16 && constructed;
        let oid_child = len >= 2 && back[0] == 0x06 && (back[1] as usize) + 2 <= len;
        let expected: Option<&[u8]> = if frames && oid_child { Some(&back[2..2 + back[1] as usize]) } else { None };
        assert!(same_oid(got, expected));
        kani::cover(matches!(got, Some(o) if o.is_empty()), "an empty OID content octet string is still an id");
        kani::cover(matches!(got, Some(o) if o.len() == 4), "the widest id (4 content octets) is returned");
        kani::cover(!frames && oid_child, "a well-framed OID child inside an element of another tag gives None");
        kani::cover(frames && len >= 2 && back[0] == 0x06 && (back[1] as usize) + 2 > len, "a truncated OID child gives None");
        kani::cover(frames && len >= 2 && back[0] != 0x06, "a first child that is not an OID gives None");
    }

    /// `extensions_repeat_an_id` decides on the envelope: with `has_repeated_leading_oid` stubbed by
    /// `stub_steered_by_bit0` (the stub reads its outcome from the first octet of the content it is
    /// given), the result is `true` iff the span is exactly one UNIVERSAL 16 constructed TLV `30 n <n
    /// octets>` (the reference: first octet `30`, length octet equal to the remaining octet count, no
    /// trailing octet) AND the content it passed on makes the stub answer `true`. So the helper strips
    /// exactly the envelope, passes exactly the content octets, and answers `false` for a span that does
    /// not frame (trailing octets, a length that does not match, a long-form or indefinite length, a
    /// wrong or high-tag-number identifier). RAW window shape, no octet restricted, `0..=6` octets
    /// (so the length octet is always short form when the span frames).
    ///
    /// The stub is sound here when the real inner helper is a total function of the content, and the only
    /// thing the helper does with the inner result is return it. The totality of the real inner helper
    /// is NOT proven by Kani at present (parked for S5, `docs/proof-work/s5-profile-helper-harnesses.md`); the
    /// id comparison it does is decided on concrete inputs by the unit tests only.
    ///
    /// Bounds: span window `0..=6` octets. Unwind 7: see the P8 block comment.
    #[kani::proof]
    #[kani::stub(has_repeated_leading_oid, stub_steered_by_bit0)]
    #[kani::unwind(7)]
    fn extensions_repeat_an_id_decides_on_the_envelope() {
        let back: [u8; 6] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 6);
        let r = extensions_repeat_an_id(&back[..len]);
        let framed = len >= 2 && back[0] == 0x30 && back[1] as usize == len - 2;
        let expected = framed && steer(&back[2..len], 1);
        assert!(r == expected);
        kani::cover(r, "an Extensions envelope whose content the inner helper flags is reported");
        kani::cover(framed && !r && len > 2, "a framed envelope whose content the inner helper does not flag is not reported");
        kani::cover(
            !framed && len >= 3 && back[0] == 0x30 && steer(&back[2..len], 1),
            "a span that does not frame is not reported even when its octets would be flagged",
        );
    }

    /// `name_is_empty` is exact: for any octets and any length `0..=6` it returns `true` iff the span
    /// is exactly `30 00`, the empty `RDNSequence` (a longer `Name`, trailing octets, a truncated or
    /// wrong-tag span, `30 80`, `30 81 00` and every other span give `false`). RAW window shape; also
    /// the totality proof for this helper at that bound.
    ///
    /// Bounds: span window `0..=6` octets. Unwind 7: see the P8 block comment.
    #[kani::proof]
    #[kani::unwind(7)]
    fn name_is_empty_iff_exactly_30_00() {
        let back: [u8; 6] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 6);
        let r = name_is_empty(&back[..len]);
        assert!(r == (len == 2 && back[0] == 0x30 && back[1] == 0x00));
        kani::cover(r, "the empty Name 30 00 is empty");
        kani::cover(!r && len == 2 && back[0] == 0x30 && back[1] != 0x00, "30 followed by a non-zero length is not the empty Name");
        kani::cover(!r && len == 3 && back[0] == 0x30 && back[1] == 0x00, "30 00 plus a trailing octet is not the empty Name");
        kani::cover(!r && len == 0, "the empty span is not the empty Name");
    }

    /// `name_has_repeated_attribute_type` decides on the walk: with `has_repeated_leading_oid` stubbed by
    /// `stub_steered_by_bit0`, over a `Name` of the shape `30 L | 31-or-other 02 f x | [r2 02 f2 x2] |
    /// [stray]` with every identifier octet, flag octet and filler octet symbolic, one or two RDNs
    /// (`two`), and an optional stray trailing octet (`extra`): the result is `true` iff the envelope
    /// is `30` and has no trailing octet, the first RDN is tagged `31` (UNIVERSAL 17 constructed) and
    /// either its content makes the stub answer `true`, or the second RDN exists, is tagged `31`
    /// and its content makes the stub answer `true`. So the walk visits the RDNs in order, hands each
    /// RDN's content octets (not the RDN TLV) to the id comparison, stops at the first RDN that is not
    /// a SET (a repeat in a later RDN is then not reported), and answers `false` for an envelope that
    /// is not exactly one SEQUENCE. A repeat is decided inside one RDN, never across two (each
    /// stub call sees one RDN's content).
    ///
    /// Bounds: at most 2 RDNs, each with a 2-octet content; the envelope length octet is 4 or 8 (short
    /// form). A third RDN, longer contents and a long-form envelope length are not enumerated. The
    /// inner id comparison is NOT decided here (stubbed; parked for S5,
    /// `docs/proof-work/s5-profile-helper-harnesses.md`); the unit tests decide it on concrete inputs.
    /// Unwind 4: the RDN
    /// walk runs at most 2 times (3 loop-condition evaluations); every length octet here is a short form
    /// constant, so `decode_length`'s loop and `decode_tag`'s high-tag loop (which stops at its first
    /// octet, the length octet) are not reached for more than one iteration. One unit of margin over the
    /// count is kept because this bound is derived by reading, not measured.
    #[kani::proof]
    #[kani::stub(has_repeated_leading_oid, stub_steered_by_bit0)]
    #[kani::unwind(4)]
    fn name_has_repeated_attribute_type_decides_on_the_walk() {
        let nt: u8 = kani::any();
        let r1t: u8 = kani::any();
        let f1: u8 = kani::any();
        let x1: u8 = kani::any();
        let r2t: u8 = kani::any();
        let f2: u8 = kani::any();
        let x2: u8 = kani::any();
        let two: bool = kani::any();
        let extra: bool = kani::any();
        let mut buf = [0u8; 11];
        buf[0] = nt;
        buf[1] = if two { 8 } else { 4 };
        buf[2] = r1t;
        buf[3] = 2;
        buf[4] = f1;
        buf[5] = x1;
        buf[6] = r2t;
        buf[7] = 2;
        buf[8] = f2;
        buf[9] = x2;
        let total = if two { 10 } else { 6 };
        buf[total] = 0x00; // the stray octet, used only when `extra`
        let len = if extra { total + 1 } else { total };
        let r = name_has_repeated_attribute_type(&buf[..len]);
        let framed = nt == 0x30 && !extra;
        let first = r1t == 0x31 && f1 & 1 != 0;
        let second = two && r2t == 0x31 && f2 & 1 != 0;
        let expected = framed && r1t == 0x31 && (first || second);
        assert!(r == expected);
        kani::cover(r && first, "a repeat in the first RDN is reported");
        kani::cover(r && !first && second, "a repeat in the second RDN is reported when the first is clean");
        kani::cover(
            !r && framed && r1t != 0x31 && two && r2t == 0x31 && f2 & 1 != 0,
            "the walk stops at a first RDN that is not a SET: a repeat in the second RDN is not reported",
        );
        kani::cover(!r && !framed && f1 & 1 != 0 && r1t == 0x31, "an envelope that is not exactly one SEQUENCE is not reported");
        kani::cover(!r && framed && r1t == 0x31 && f1 & 1 == 0 && two && f2 & 1 == 0, "two clean RDNs are not reported");
    }

}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::utc_time::{full_year_rfc5280, UtcTime};
    use crate::x509_certificate::parse_certificate;

    // --- test-only DER assembly helpers (not part of the crate's verified surface: these build
    //     fixtures for the validator under test) — copied from `x509_certificate.rs`'s /
    //     `x509_tbs_certificate.rs`'s own test modules, per this crate's fixture-reuse convention.

    /// Encode a canonical DER length field for `n` content octets: short form for `n < 128`,
    /// otherwise the long form with the fewest length-of-length octets needed.
    fn der_length(n: usize) -> Vec<u8> {
        if n < 0x80 {
            vec![n as u8]
        } else if n < 0x100 {
            vec![0x81, n as u8]
        } else if n < 0x1_0000 {
            vec![0x82, (n >> 8) as u8, n as u8]
        } else {
            panic!("test fixture too large for this helper");
        }
    }

    /// Wrap `content` in a TLV with the given identifier octet and a canonically-minimal length.
    fn wrap(tag: u8, content: &[u8]) -> Vec<u8> {
        let mut out = vec![tag];
        out.extend(der_length(content.len()));
        out.extend_from_slice(content);
        out
    }

    // --- known-good field specimens, copied verbatim from `x509_tbs_certificate.rs`'s /
    //     `x509_certificate.rs`'s own tests. ---

    /// `[0] EXPLICIT INTEGER 2` — version v3.
    const VERSION_V3: [u8; 5] = [0xA0, 0x03, 0x02, 0x01, 0x02];

    /// `serialNumber` = 1.
    const SERIAL_1: [u8; 3] = [0x02, 0x01, 0x01];

    /// `signature` / `signatureAlgorithm` — Ed25519 AlgorithmIdentifier.
    #[rustfmt::skip]
    const SIGNATURE_ED25519: [u8; 7] = [
        0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x70,
    ];

    /// A second, DIFFERENT `AlgorithmIdentifier` (RSA-with-SHA256, `1.2.840.113549.1.1.11`, with an
    /// explicit ASN.1 NULL `parameters`) — used to seed a §4.1.1.2 mismatch: structurally valid on
    /// its own, but a different OID (and different `parameters`, `None` vs `Some`) than
    /// `SIGNATURE_ED25519`.
    #[rustfmt::skip]
    const SIGNATURE_RSA_SHA256: [u8; 15] = [
        0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
            0x05, 0x00,
    ];

    /// A minimal valid `Name`: `CN=Example CA`. Reused for both `issuer` and `subject`.
    #[rustfmt::skip]
    const NAME_CN_EXAMPLE_CA: [u8; 23] = [
        0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41,
    ];

    /// `Validity`: both fields UTCTime.
    #[rustfmt::skip]
    const VALIDITY_UTC_UTC: [u8; 32] = [
        0x30, 0x1e,
            0x17, 0x0d,
                0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x17, 0x0d,
                0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    ];

    /// A real Ed25519 `SubjectPublicKeyInfo`.
    #[rustfmt::skip]
    const SPKI_ED25519: [u8; 44] = [
        0x30, 0x2a,
            0x30, 0x05,
                0x06, 0x03, 0x2b, 0x65, 0x70,
            0x03, 0x21, 0x00,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    /// A single `basicConstraints` `Extension`, `critical` absent.
    #[rustfmt::skip]
    const EXT_BASIC_CONSTRAINTS_DEFAULT: [u8; 11] = [
        0x30, 0x09,
            0x06, 0x03, 0x55, 0x1d, 0x13,
            0x04, 0x02, 0x30, 0x00,
    ];

    /// `signatureValue` — a minimal BIT STRING: 0 unused bits, 2 data octets.
    const SIGNATURE_VALUE: [u8; 5] = [0x03, 0x03, 0x00, 0xAA, 0xBB];

    /// `Validity` with both fields GeneralizedTime: `notBefore` = 2050-01-01, `notAfter` =
    /// 2099-12-31 — both years `>= 2050`, the RFC-mandated GeneralizedTime range. Byte-for-byte
    /// identical to `x509_validity::tests::VALIDITY_GENERALIZED_GENERALIZED` (fixture reuse
    /// convention, per this module's docs).
    #[rustfmt::skip]
    const VALIDITY_GENERALIZED_GENERALIZED: [u8; 36] = [
        0x30, 0x22,
            0x18, 0x0f,
                0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x18, 0x0f,
                0x32, 0x30, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    ];

    /// `Validity` with `notBefore` UTCTime year `99` (-> 1999, valid) but `notAfter` UTCTime year
    /// `49` (-> full year 2049 under `full_year_rfc5280`'s `< 50 => 20YY` mapping — still within the
    /// UTCTime-permitted range, i.e. this is a VALID boundary specimen, not a violation).
    #[rustfmt::skip]
    const VALIDITY_NOT_AFTER_UTC_YEAR_2049: [u8; 32] = [
        0x30, 0x1e,
            0x17, 0x0d,
                0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x17, 0x0d,
                0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    ];

    /// `Validity` with `notBefore` UTCTime year `50` (-> full year 1950, valid) but `notAfter`
    /// UTCTime year `00` (-> full year 2000 under `full_year_rfc5280`'s `< 50 => 20YY` mapping —
    /// still valid; both fields legitimately UTCTime-encoded, just spanning the century boundary).
    #[rustfmt::skip]
    const VALIDITY_UTC_STRADDLING_CENTURY: [u8; 32] = [
        0x30, 0x1e,
            0x17, 0x0d,
                0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x17, 0x0d,
                0x30, 0x30, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    ];

    /// **Proves the structural invariant `check_time_encoding_year` relies on to omit a
    /// UTCTime-too-late runtime check entirely**: for every possible two-digit `year2` (`0..=99`),
    /// [`full_year_rfc5280`]'s RFC 5280 §4.1.2.5.1 century mapping (`year2 < 50 ⇒ 20YY`, `year2 ⇒
    /// 19YY` otherwise) never produces a full year outside `1950..=2049` -- in particular, never
    /// `>= 2050`. This is exhaustive over `UtcTime::year2`'s entire domain (a `u8` value `0..=99`;
    /// values `>= 100` are not representable in a two-digit field), so it is a proof, not a sample:
    /// no `Time::Utc` value this crate can ever construct can violate the "UTCTime `<= 2049`" half
    /// of the §4.1.2.5 rule, which is exactly why [`ProfileError`] has no
    /// `*UtcTimeYearTooLate`-shaped variant and `check_time_encoding_year` has no corresponding
    /// runtime check -- the guarantee is structural, not merely untested.
    #[test]
    fn full_year_rfc5280_never_reaches_2050() {
        for year2 in 0..=99u8 {
            let t = UtcTime { year2, month: 1, day: 1, hour: 0, minute: 0, second: 0 };
            let full = full_year_rfc5280(&t);
            assert!(
                (1950..=2049).contains(&full),
                "year2={year2} mapped to full year {full}, outside 1950..=2049"
            );
        }
    }

    /// `Validity` with `notBefore` GeneralizedTime year `2049` (<= 2049, a violation -- 2049 and
    /// earlier MUST be UTCTime) and a valid `notAfter` (GeneralizedTime 2099).
    #[rustfmt::skip]
    const VALIDITY_NOT_BEFORE_GENERALIZED_YEAR_2049: [u8; 36] = [
        0x30, 0x22,
            0x18, 0x0f,
                0x32, 0x30, 0x34, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x18, 0x0f,
                0x32, 0x30, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    ];

    /// `Validity` with a valid `notBefore` (UTCTime 1999) and `notAfter` **wrongly** encoded as
    /// GeneralizedTime year `2049` (<= 2049, a violation).
    #[rustfmt::skip]
    const VALIDITY_NOT_AFTER_GENERALIZED_YEAR_2049: [u8; 34] = [
        0x30, 0x20,
            0x17, 0x0d,
                0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x18, 0x0f,
                0x32, 0x30, 0x34, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    ];

    /// Assemble a `TBSCertificate` with the given `version` field bytes (pass `&[]` to omit the
    /// `[0]` wrapper entirely, i.e. DEFAULT v1) and, optionally, an `extensions` field. Uses
    /// `VALIDITY_UTC_UTC` (see `build_tbs_with_validity` to vary `Validity`).
    fn build_tbs(version_bytes: &[u8], extensions: Option<&[u8]>) -> Vec<u8> {
        build_tbs_with_validity(version_bytes, extensions, &VALIDITY_UTC_UTC)
    }

    /// Same as `build_tbs`, but with a caller-chosen `Validity` span — lets tests seed a §4.1.2.5
    /// encoding-choice violation without duplicating the rest of the `TBSCertificate` assembly.
    fn build_tbs_with_validity(
        version_bytes: &[u8],
        extensions: Option<&[u8]>,
        validity: &[u8],
    ) -> Vec<u8> {
        build_tbs_full(version_bytes, extensions, validity, &NAME_CN_EXAMPLE_CA, &NAME_CN_EXAMPLE_CA)
    }

    /// Same as `build_tbs_with_validity`, but with caller-chosen `issuer` and `subject` `Name` spans
    /// too — lets tests seed the name rules (P-13, P-14) without duplicating the assembly.
    fn build_tbs_full(
        version_bytes: &[u8],
        extensions: Option<&[u8]>,
        validity: &[u8],
        issuer: &[u8],
        subject: &[u8],
    ) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(version_bytes);
        content.extend_from_slice(&SERIAL_1);
        content.extend_from_slice(&SIGNATURE_ED25519);
        content.extend_from_slice(issuer);
        content.extend_from_slice(validity);
        content.extend_from_slice(subject);
        content.extend_from_slice(&SPKI_ED25519);
        if let Some(ext) = extensions {
            let extensions_seq = wrap(0x30, ext); // Extensions SEQUENCE
            let extensions_wrapped = wrap(0xA3, &extensions_seq); // [3] EXPLICIT
            content.extend_from_slice(&extensions_wrapped);
        }
        wrap(0x30, &content)
    }

    /// Assemble a complete `Certificate` from a `tbsCertificate` span plus a chosen
    /// `signatureAlgorithm` (letting tests choose whether it matches `tbsCertificate.signature`).
    fn build_certificate(tbs: &[u8], signature_algorithm: &[u8]) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(tbs);
        content.extend_from_slice(signature_algorithm);
        content.extend_from_slice(&SIGNATURE_VALUE);
        wrap(0x30, &content)
    }

    /// A complete, valid v3 certificate: extensions present, version v3, `signatureAlgorithm`
    /// matches `tbsCertificate.signature`.
    fn valid_v3_certificate_bytes() -> Vec<u8> {
        let tbs = build_tbs(&VERSION_V3, Some(&EXT_BASIC_CONSTRAINTS_DEFAULT));
        build_certificate(&tbs, &SIGNATURE_ED25519)
    }

    /// A complete, valid v1 certificate: no extensions, no `[0]` version wrapper (DEFAULT v1),
    /// `signatureAlgorithm` matches `tbsCertificate.signature`.
    fn valid_v1_certificate_bytes() -> Vec<u8> {
        let tbs = build_tbs(&[], None);
        build_certificate(&tbs, &SIGNATURE_ED25519)
    }

    #[test]
    fn valid_v3_certificate_passes() {
        let bytes = valid_v3_certificate_bytes();
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(validate_profile(&cert), Ok(()));
    }

    #[test]
    fn valid_v1_certificate_without_extensions_passes() {
        let bytes = valid_v1_certificate_bytes();
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(validate_profile(&cert), Ok(()));
    }

    #[test]
    fn rejects_signature_algorithm_mismatch() {
        // tbsCertificate.signature is Ed25519, but the outer signatureAlgorithm is RSA-SHA256:
        // both independently valid AlgorithmIdentifiers, but they differ.
        let tbs = build_tbs(&VERSION_V3, Some(&EXT_BASIC_CONSTRAINTS_DEFAULT));
        let bytes = build_certificate(&tbs, &SIGNATURE_RSA_SHA256);
        let cert = parse_certificate(&bytes).unwrap();
        // Sanity: both fields decoded, and they are indeed unequal (the precondition under test).
        assert_ne!(cert.signature_algorithm, cert.tbs_certificate.signature);
        assert_eq!(validate_profile(&cert), Err(ProfileError::SignatureAlgorithmMismatch));
    }

    #[test]
    fn rejects_extensions_present_with_version_v1() {
        // A v1-shaped TBSCertificate (no [0] wrapper, DEFAULT v1) that nonetheless carries
        // extensions: extensions are v3-only. Both `parse_tbs_certificate` and `parse_certificate`
        // accept this structurally (extensions/version are independently validated fields with no
        // cross-field ASN.1 constraint), so this is exactly the case this module's rule 2 exists
        // to catch.
        let tbs = build_tbs(&[], Some(&EXT_BASIC_CONSTRAINTS_DEFAULT));
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        // Sanity: the precondition under test actually holds after structural parsing.
        assert_eq!(cert.tbs_certificate.version, 0);
        assert!(cert.tbs_certificate.extensions.is_some());
        assert_eq!(validate_profile(&cert), Err(ProfileError::ExtensionsRequireV3));
    }

    #[test]
    fn rejects_extensions_present_with_version_v2() {
        // Same rule, seeded via v2 (integer value 1) instead of v1 -- extensions require
        // specifically v3 (2), not merely "not v1".
        const VERSION_V2: [u8; 5] = [0xA0, 0x03, 0x02, 0x01, 0x01];
        let tbs = build_tbs(&VERSION_V2, Some(&EXT_BASIC_CONSTRAINTS_DEFAULT));
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(cert.tbs_certificate.version, 1);
        assert!(cert.tbs_certificate.extensions.is_some());
        assert_eq!(validate_profile(&cert), Err(ProfileError::ExtensionsRequireV3));
    }

    #[test]
    fn signature_mismatch_checked_before_extensions_rule() {
        // Both rules are violated at once (mismatched signatureAlgorithm AND extensions-with-v1);
        // validate_profile must report the first rule in declaration order (rule 1).
        let tbs = build_tbs(&[], Some(&EXT_BASIC_CONSTRAINTS_DEFAULT));
        let bytes = build_certificate(&tbs, &SIGNATURE_RSA_SHA256);
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(validate_profile(&cert), Err(ProfileError::SignatureAlgorithmMismatch));
    }

    // --- Rule 3 (§4.1.2.5 / §4.1.2.5.1 / §4.1.2.5.2): notBefore/notAfter encoding-choice year rule.

    #[test]
    fn valid_v3_certificate_with_both_times_generalized_passes() {
        // Both notBefore (2050) and notAfter (2099) are >= 2050 and correctly GeneralizedTime-encoded
        // -- a valid, if unusual, RFC 5280 spelling (a long-lived certificate entirely past 2050).
        let tbs = build_tbs_with_validity(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_GENERALIZED_GENERALIZED,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        // Sanity: both fields really did decode as the Generalized arm, both years >= 2050.
        match (cert.tbs_certificate.validity.not_before, cert.tbs_certificate.validity.not_after) {
            (crate::x509_validity::Time::Generalized(nb), crate::x509_validity::Time::Generalized(na)) => {
                assert!(nb.year >= 2050);
                assert!(na.year >= 2050);
            }
            other => panic!("expected both fields Generalized, got {other:?}"),
        }
        assert_eq!(validate_profile(&cert), Ok(()));
    }

    #[test]
    fn valid_v3_certificate_with_not_after_utc_year_2049_boundary_passes() {
        // notAfter is UTCTime with year2 = 49 -> full year 2049 (the exact boundary): still valid,
        // since the rule is "UTCTime THROUGH 2049", not "before 2049".
        let tbs = build_tbs_with_validity(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_NOT_AFTER_UTC_YEAR_2049,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        // Sanity: the boundary year really is exactly 2049 under this crate's own mapping function.
        match cert.tbs_certificate.validity.not_after {
            Time::Utc(t) => assert_eq!(full_year_rfc5280(&t), 2049),
            other => panic!("expected notAfter Utc, got {other:?}"),
        }
        assert_eq!(validate_profile(&cert), Ok(()));
    }

    #[test]
    fn valid_v3_certificate_with_both_utc_straddling_century_boundary_passes() {
        // notBefore year2=50 (-> full year 1950) and notAfter year2=00 (-> full year 2000): both
        // legitimately map into the UTCTime-permitted 1950..=2049 range despite crossing the raw
        // two-digit rollover, so both are valid UTCTime encodings.
        let tbs = build_tbs_with_validity(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_UTC_STRADDLING_CENTURY,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        match (cert.tbs_certificate.validity.not_before, cert.tbs_certificate.validity.not_after) {
            (Time::Utc(nb), Time::Utc(na)) => {
                assert_eq!(full_year_rfc5280(&nb), 1950);
                assert_eq!(full_year_rfc5280(&na), 2000);
            }
            other => panic!("expected both fields Utc, got {other:?}"),
        }
        assert_eq!(validate_profile(&cert), Ok(()));
    }

    #[test]
    fn rejects_not_before_generalized_time_year_2049() {
        // notBefore is GeneralizedTime year 2049 (<= 2049): must be UTCTime, not GeneralizedTime.
        let tbs = build_tbs_with_validity(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_NOT_BEFORE_GENERALIZED_YEAR_2049,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        // Sanity: the precondition under test actually holds after structural parsing.
        match cert.tbs_certificate.validity.not_before {
            Time::Generalized(t) => assert_eq!(t.year, 2049),
            other => panic!("expected notBefore Generalized, got {other:?}"),
        }
        assert_eq!(
            validate_profile(&cert),
            Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly)
        );
    }

    #[test]
    fn rejects_not_after_generalized_time_year_2049() {
        // Symmetric to the notBefore case: notAfter is GeneralizedTime year 2049 (<= 2049).
        let tbs = build_tbs_with_validity(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_NOT_AFTER_GENERALIZED_YEAR_2049,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        match cert.tbs_certificate.validity.not_after {
            Time::Generalized(t) => assert_eq!(t.year, 2049),
            other => panic!("expected notAfter Generalized, got {other:?}"),
        }
        assert_eq!(validate_profile(&cert), Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly));
    }

    #[test]
    fn not_before_time_rule_checked_before_not_after_time_rule() {
        // Both notBefore AND notAfter are seeded as GeneralizedTime year 2049 (both violations at
        // once); validate_profile must report notBefore's variant first (declaration order).
        #[rustfmt::skip]
        const VALIDITY_BOTH_GENERALIZED_YEAR_2049: [u8; 36] = [
            0x30, 0x22,
                0x18, 0x0f,
                    0x32, 0x30, 0x34, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
                0x18, 0x0f,
                    0x32, 0x30, 0x34, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
        ];
        let tbs = build_tbs_with_validity(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_BOTH_GENERALIZED_YEAR_2049,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(
            validate_profile(&cert),
            Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly)
        );
    }

    #[test]
    fn extensions_rule_checked_before_time_encoding_rule() {
        // Extensions-with-v1 (rule 2) AND a notBefore GeneralizedTime-year-2049 violation (rule 3)
        // are both present; validate_profile must report rule 2 first (declaration order).
        let tbs = build_tbs_with_validity(
            &[], // DEFAULT v1
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_NOT_BEFORE_GENERALIZED_YEAR_2049,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(validate_profile(&cert), Err(ProfileError::ExtensionsRequireV3));
    }

    // --- Rule 4 (§4.1.2.5.2): a GeneralizedTime in validity MUST NOT include fractional seconds.

    /// A `Time` TLV: UTCTime (tag 0x17) when `generalized` is false, GeneralizedTime (0x18) otherwise.
    fn time_tlv(generalized: bool, ascii: &[u8]) -> Vec<u8> {
        wrap(if generalized { 0x18 } else { 0x17 }, ascii)
    }

    /// A `Validity` SEQUENCE over two already-encoded `Time` TLVs.
    fn validity_of(not_before: &[u8], not_after: &[u8]) -> Vec<u8> {
        let mut content = not_before.to_vec();
        content.extend_from_slice(not_after);
        wrap(0x30, &content)
    }

    /// Parse a v3 certificate carrying `validity` and return `validate_profile`'s result, after
    /// checking that the fixture really parsed (so a rejection can only come from the profile rules).
    fn profile_result_for_validity(validity: &[u8]) -> Result<(), ProfileError> {
        let tbs = build_tbs_with_validity(&VERSION_V3, Some(&EXT_BASIC_CONSTRAINTS_DEFAULT), validity);
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).expect("fixture must be structurally valid");
        validate_profile(&cert)
    }

    #[test]
    fn rejects_not_before_generalized_time_with_fraction() {
        // notBefore 2050-01-01T00:00:00.5Z: year rule satisfied, fraction present.
        let v = validity_of(
            &time_tlv(true, b"20500101000000.5Z"),
            &time_tlv(true, b"20991231235959Z"),
        );
        assert_eq!(
            profile_result_for_validity(&v),
            Err(ProfileError::NotBeforeGeneralizedTimeHasFraction)
        );
    }

    #[test]
    fn rejects_not_after_generalized_time_with_fraction() {
        // The documented example: notAfter 2099-12-31T23:59:59.5Z.
        let v = validity_of(
            &time_tlv(false, b"990101000000Z"),
            &time_tlv(true, b"20991231235959.5Z"),
        );
        assert_eq!(
            profile_result_for_validity(&v),
            Err(ProfileError::NotAfterGeneralizedTimeHasFraction)
        );
    }

    #[test]
    fn rejects_fraction_of_any_length_and_value() {
        for frac in [&b".1"[..], b".123456789", b".99"] {
            let mut na = b"20991231235959".to_vec();
            na.extend_from_slice(frac);
            na.push(b'Z');
            let v = validity_of(&time_tlv(false, b"990101000000Z"), &time_tlv(true, &na));
            assert_eq!(
                profile_result_for_validity(&v),
                Err(ProfileError::NotAfterGeneralizedTimeHasFraction),
                "fraction {frac:?}"
            );
        }
    }

    /// Fraction lengths 3 and 4 (and a few neighbours) on BOTH fields. The proofs cover fraction
    /// lengths up to their stated bound; these tests pin the lengths around it by exact result, so a
    /// check that is skipped for one particular length cannot pass.
    #[test]
    fn rejects_fractions_of_length_three_and_four_on_both_fields() {
        for frac in [&b".123"[..], b".1234", b".001", b".9999", b".12345", b".5"] {
            let mut gen = b"20500101000000".to_vec();
            gen.extend_from_slice(frac);
            gen.push(b'Z');
            let clean = b"20991231235959Z";
            let v = validity_of(&time_tlv(true, &gen), &time_tlv(true, clean));
            assert_eq!(
                profile_result_for_validity(&v),
                Err(ProfileError::NotBeforeGeneralizedTimeHasFraction),
                "notBefore fraction {frac:?}"
            );
            let v = validity_of(&time_tlv(false, b"990101000000Z"), &time_tlv(true, &gen));
            assert_eq!(
                profile_result_for_validity(&v),
                Err(ProfileError::NotAfterGeneralizedTimeHasFraction),
                "notAfter fraction {frac:?}"
            );
            // Both fields fractional with different lengths: notBefore's variant is reported.
            let v = validity_of(&time_tlv(true, &gen), &time_tlv(true, &gen));
            assert_eq!(
                profile_result_for_validity(&v),
                Err(ProfileError::NotBeforeGeneralizedTimeHasFraction),
                "both fields fraction {frac:?}"
            );
        }
    }

    #[test]
    fn accepts_generalized_times_from_2050_without_fraction() {
        // Both fields GeneralizedTime, years >= 2050, no fraction: the compliant spelling.
        let v = validity_of(
            &time_tlv(true, b"20500101000000Z"),
            &time_tlv(true, b"20991231235959Z"),
        );
        assert_eq!(profile_result_for_validity(&v), Ok(()));
        // Mixed: UTCTime notBefore, GeneralizedTime 2050+ notAfter without fraction.
        let v = validity_of(
            &time_tlv(false, b"490101000000Z"),
            &time_tlv(true, b"20500101000000Z"),
        );
        assert_eq!(profile_result_for_validity(&v), Ok(()));
    }

    #[test]
    fn rule4_not_before_fraction_wins_over_not_after_fraction() {
        let v = validity_of(
            &time_tlv(true, b"20500101000000.5Z"),
            &time_tlv(true, b"20991231235959.5Z"),
        );
        assert_eq!(
            profile_result_for_validity(&v),
            Err(ProfileError::NotBeforeGeneralizedTimeHasFraction)
        );
    }

    #[test]
    fn rule3_year_error_is_reported_before_rule4_fraction_error() {
        // notBefore: GeneralizedTime 2049 WITH a fraction -> the year rule (rule 3) fires first.
        let v = validity_of(
            &time_tlv(true, b"20490101000000.5Z"),
            &time_tlv(true, b"20991231235959Z"),
        );
        assert_eq!(
            profile_result_for_validity(&v),
            Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly)
        );
        // notBefore: valid 2050 with a fraction, notAfter: GeneralizedTime 2049 -> notAfter's year
        // error (rule 3, both fields) is still reported before notBefore's fraction error.
        let v = validity_of(
            &time_tlv(true, b"20500101000000.5Z"),
            &time_tlv(true, b"20491231235959Z"),
        );
        assert_eq!(
            profile_result_for_validity(&v),
            Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly)
        );
    }

    #[test]
    fn extensions_rule_checked_before_fraction_rule() {
        // Extensions with DEFAULT v1 (rule 2) AND a fractional notAfter (rule 4): rule 2 first.
        let v = validity_of(
            &time_tlv(false, b"990101000000Z"),
            &time_tlv(true, b"20991231235959.5Z"),
        );
        let tbs = build_tbs_with_validity(&[], Some(&EXT_BASIC_CONSTRAINTS_DEFAULT), &v);
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(validate_profile(&cert), Err(ProfileError::ExtensionsRequireV3));
    }

    #[test]
    fn signature_mismatch_checked_before_fraction_rule() {
        let v = validity_of(
            &time_tlv(false, b"990101000000Z"),
            &time_tlv(true, b"20991231235959.5Z"),
        );
        let tbs = build_tbs_with_validity(&VERSION_V3, Some(&EXT_BASIC_CONSTRAINTS_DEFAULT), &v);
        let bytes = build_certificate(&tbs, &SIGNATURE_RSA_SHA256);
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(validate_profile(&cert), Err(ProfileError::SignatureAlgorithmMismatch));
    }

    // --- Rules 5 to 7 (S4b batch B1): P-12 duplicate extension, P-13 empty issuer, P-14 repeated
    //     attribute type. Fixtures are built from the small encoders below.

    const OID_CN: [u8; 3] = [0x55, 0x04, 0x03];
    const OID_ORG: [u8; 3] = [0x55, 0x04, 0x0a];
    const OID_BASIC_CONSTRAINTS: [u8; 3] = [0x55, 0x1d, 0x13];
    const OID_KEY_USAGE: [u8; 3] = [0x55, 0x1d, 0x0f];
    /// An empty `Name` (`RDNSequence` with zero RDNs).
    const NAME_EMPTY: [u8; 2] = [0x30, 0x00];

    /// `Extension ::= SEQUENCE { extnID, critical (only when true), extnValue }`.
    fn extension(oid: &[u8], critical: bool, value: &[u8]) -> Vec<u8> {
        let mut content = wrap(0x06, oid);
        if critical {
            content.extend_from_slice(&[0x01, 0x01, 0xff]);
        }
        content.extend(wrap(0x04, value));
        wrap(0x30, &content)
    }

    /// `AttributeTypeAndValue ::= SEQUENCE { type OID, value UTF8String }`.
    fn atv(oid: &[u8], text: &[u8]) -> Vec<u8> {
        let mut content = wrap(0x06, oid);
        content.extend(wrap(0x0c, text));
        wrap(0x30, &content)
    }

    /// `RelativeDistinguishedName`: the SET OF the given encoded ATVs, in the order given (the
    /// caller keeps them in §11.6 ascending order).
    fn rdn(atvs: &[Vec<u8>]) -> Vec<u8> {
        wrap(0x31, &atvs.concat())
    }

    /// `Name`: the `RDNSequence` of the given encoded RDNs.
    fn name(rdns: &[Vec<u8>]) -> Vec<u8> {
        wrap(0x30, &rdns.concat())
    }

    /// Parse a v3 certificate with `extensions` content, `issuer` and `subject`, check that the fixture
    /// really parsed, and return `validate_profile`'s result.
    fn profile_result_for(extensions: &[u8], issuer: &[u8], subject: &[u8]) -> Result<(), ProfileError> {
        let tbs = build_tbs_full(&VERSION_V3, Some(extensions), &VALIDITY_UTC_UTC, issuer, subject);
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).expect("fixture must be structurally valid");
        validate_profile(&cert)
    }

    /// P-12 accept: three extensions whose `extnID`s are all different pass, including an OID
    /// that has another extension's OID as a prefix (the whole content octets are compared).
    #[test]
    fn accepts_distinct_extension_ids() {
        let longer_oid = [0x55, 0x1d, 0x13, 0x01];
        let exts = [
            extension(&OID_BASIC_CONSTRAINTS, false, &[0x30, 0x00]),
            extension(&OID_KEY_USAGE, true, &[0x03, 0x02, 0x05, 0xa0]),
            extension(&longer_oid, false, &[0x30, 0x00]),
        ]
        .concat();
        assert_eq!(profile_result_for(&exts, &NAME_CN_EXAMPLE_CA, &NAME_CN_EXAMPLE_CA), Ok(()));
    }

    /// P-12 reject: the same `extnID` twice is rejected even when `critical` and `extnValue`
    /// differ, so the `extnID` alone decides.
    #[test]
    fn rejects_duplicate_extension_id() {
        let exts = [
            extension(&OID_BASIC_CONSTRAINTS, false, &[0x30, 0x00]),
            extension(&OID_BASIC_CONSTRAINTS, true, &[0x30, 0x03, 0x01, 0x01, 0xff]),
        ]
        .concat();
        assert_eq!(
            profile_result_for(&exts, &NAME_CN_EXAMPLE_CA, &NAME_CN_EXAMPLE_CA),
            Err(ProfileError::DuplicateExtension)
        );
    }

    /// P-12 reject: the repeated `extnID` need not be adjacent (first and third of three).
    #[test]
    fn rejects_duplicate_extension_id_that_is_not_adjacent() {
        let exts = [
            extension(&OID_BASIC_CONSTRAINTS, false, &[0x30, 0x00]),
            extension(&OID_KEY_USAGE, true, &[0x03, 0x02, 0x05, 0xa0]),
            extension(&OID_BASIC_CONSTRAINTS, false, &[0x30, 0x00]),
        ]
        .concat();
        assert_eq!(
            profile_result_for(&exts, &NAME_CN_EXAMPLE_CA, &NAME_CN_EXAMPLE_CA),
            Err(ProfileError::DuplicateExtension)
        );
    }

    /// P-13 reject: an empty issuer `Name` (`30 00`) is rejected.
    #[test]
    fn rejects_empty_issuer() {
        let tbs = build_tbs_full(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_UTC_UTC,
            &NAME_EMPTY,
            &NAME_CN_EXAMPLE_CA,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).expect("fixture must be structurally valid");
        // Sanity: the parsers accept the empty issuer, so only this rule can reject it.
        assert_eq!(cert.tbs_certificate.issuer, &NAME_EMPTY[..]);
        assert_eq!(validate_profile(&cert), Err(ProfileError::EmptyIssuer));
    }

    /// P-13 accept: an empty subject is legal (RFC 5280 §4.1.2.6 allows it), so only the issuer is
    /// checked.
    #[test]
    fn accepts_empty_subject() {
        let tbs = build_tbs_full(
            &VERSION_V3,
            Some(&EXT_BASIC_CONSTRAINTS_DEFAULT),
            &VALIDITY_UTC_UTC,
            &NAME_CN_EXAMPLE_CA,
            &NAME_EMPTY,
        );
        let bytes = build_certificate(&tbs, &SIGNATURE_ED25519);
        let cert = parse_certificate(&bytes).expect("fixture must be structurally valid");
        assert_eq!(cert.tbs_certificate.subject, &NAME_EMPTY[..]);
        assert_eq!(validate_profile(&cert), Ok(()));
    }

    /// P-14 reject: an issuer RDN that holds `CN=A` and `CN=B` (the same attribute type twice, in
    /// §11.6 order) is rejected with the issuer variant.
    #[test]
    fn rejects_issuer_rdn_with_repeated_attribute_type() {
        let issuer = name(&[rdn(&[atv(&OID_CN, b"A"), atv(&OID_CN, b"B")])]);
        assert_eq!(
            profile_result_for(&EXT_BASIC_CONSTRAINTS_DEFAULT, &issuer, &NAME_CN_EXAMPLE_CA),
            Err(ProfileError::IssuerDuplicateAttributeType)
        );
    }

    /// P-14 reject: the same defect in the subject gives the subject variant. The repeated type is
    /// in the second RDN, after a clean first RDN.
    #[test]
    fn rejects_subject_rdn_with_repeated_attribute_type() {
        let subject = name(&[
            rdn(&[atv(&OID_ORG, b"Org")]),
            rdn(&[atv(&OID_CN, b"A"), atv(&OID_CN, b"B")]),
        ]);
        assert_eq!(
            profile_result_for(&EXT_BASIC_CONSTRAINTS_DEFAULT, &NAME_CN_EXAMPLE_CA, &subject),
            Err(ProfileError::SubjectDuplicateAttributeType)
        );
    }

    /// P-14 accept: the same attribute type in DIFFERENT RDNs of one Name is legal, in both the issuer
    /// and the subject.
    #[test]
    fn accepts_same_attribute_type_in_different_rdns() {
        let n = name(&[rdn(&[atv(&OID_CN, b"A")]), rdn(&[atv(&OID_CN, b"B")])]);
        assert_eq!(profile_result_for(&EXT_BASIC_CONSTRAINTS_DEFAULT, &n, &n), Ok(()));
    }

    /// P-14 accept: a multi-valued RDN with different attribute types is legal, including a type whose
    /// OID has the other type's OID as a prefix (the whole content octets are compared).
    #[test]
    fn accepts_multi_valued_rdn_with_distinct_attribute_types() {
        let longer_oid = [0x55, 0x04, 0x03, 0x01];
        let n = name(&[rdn(&[
            atv(&OID_CN, b"A"),
            atv(&OID_ORG, b"A"),
            atv(&longer_oid, b"A"),
        ])]);
        assert_eq!(profile_result_for(&EXT_BASIC_CONSTRAINTS_DEFAULT, &n, &n), Ok(()));
    }

    /// P-14 precedence: the issuer's repeated attribute type is reported before the subject's.
    #[test]
    fn issuer_repeated_attribute_type_checked_before_subject() {
        let dup = name(&[rdn(&[atv(&OID_CN, b"A"), atv(&OID_CN, b"B")])]);
        assert_eq!(
            profile_result_for(&EXT_BASIC_CONSTRAINTS_DEFAULT, &dup, &dup),
            Err(ProfileError::IssuerDuplicateAttributeType)
        );
    }

    /// Rules 5 to 7 read hand-built spans that do not walk (empty, truncated, mis-tagged elements)
    /// without panicking and report no violation for what they cannot frame.
    #[test]
    fn rules_5_to_7_ignore_spans_that_do_not_frame() {
        let bytes = valid_v3_certificate_bytes();
        let base = parse_certificate(&bytes).unwrap();
        let spans: [&[u8]; 10] = [
            &[],
            &[0x30],
            &[0x30, 0x05, 0x30],
            &[0x30, 0x02, 0x30, 0x00],
            &[0x30, 0x04, 0x02, 0x02, 0x06, 0x00],
            &[0x31, 0x00],
            &[0x30, 0x04, 0x31, 0x02, 0x30, 0x00],
            &[0x30, 0x06, 0x31, 0x04, 0x30, 0x02, 0x04, 0x00],
            // Two INTEGER elements whose content starts with the same `06 00`: not Extensions.
            &[0x30, 0x08, 0x02, 0x02, 0x06, 0x00, 0x02, 0x02, 0x06, 0x00],
            // A SEQUENCE where the RDN SET belongs, holding two ATV-shaped elements with one type.
            &[0x30, 0x0e, 0x30, 0x0c, 0x30, 0x04, 0x06, 0x00, 0x05, 0x00, 0x30, 0x04, 0x06, 0x00, 0x05, 0x00],
        ];
        for span in spans {
            let mut cert = base;
            cert.tbs_certificate.extensions = Some(span);
            cert.tbs_certificate.subject = span;
            assert_eq!(validate_profile(&cert), Ok(()), "span {span:?}");
        }
    }

    // --- Rules 5 to 7 on concrete specimens (were Kani harnesses until the S4b cost fix: concrete inputs
    //     make the proof an evaluation, and the unwinding of the nested element walks ran out of memory
    //     at 20 GB; see `docs/proof-work/s5-profile-helper-harnesses.md`). ---

    /// Discharges the obligation of the Kani stub `proofs::stub_rule_never_fires`: on the inputs the rule
    /// 1 to 4 harnesses build (`symbolic_cert`: no `extensions` or the empty `Extensions` list `30 00`,
    /// and the empty `issuer` and `subject`), the three real helpers return `false`. The inputs are
    /// concrete, so this test decides the fact as well as a proof would. `30 00` is also pinned as the
    /// one span that IS an empty `Name` (so `name_is_empty` is `true` there), to show the `false` answers
    /// on the empty span are not an artefact of a helper that always answers `false`.
    #[test]
    fn rules_5_to_7_helpers_return_false_on_the_isolation_inputs() {
        const EMPTY_LIST: &[u8] = &[0x30, 0x00];
        const NO_SPAN: &[u8] = &[];
        assert!(!extensions_repeat_an_id(EMPTY_LIST));
        assert!(!extensions_repeat_an_id(NO_SPAN));
        assert!(!name_is_empty(NO_SPAN));
        assert!(!name_has_repeated_attribute_type(NO_SPAN));
        assert!(!name_has_repeated_attribute_type(EMPTY_LIST));
        assert!(name_is_empty(EMPTY_LIST));
        // The empty list frames as an empty SEQUENCE (rule 5 walks zero elements); the empty span does
        // not frame (rules 6 and 7 stop at the envelope).
        assert!(matches!(decode_sequence_tlv_strict(EMPTY_LIST), Ok(c) if c.is_empty()));
        assert!(decode_sequence_tlv_strict(NO_SPAN).is_err());
    }

    /// `Extensions` holding two `Extension`s with different `extnID`s (`2a`, `2b`). No violation.
    const EXT_TWO_DISTINCT: [u8; 16] = [
        0x30, 0x0e, 0x30, 0x05, 0x06, 0x01, 0x2a, 0x04, 0x00, 0x30, 0x05, 0x06, 0x01, 0x2b, 0x04, 0x00,
    ];
    /// `Extensions` holding two `Extension`s with the same `extnID` (`2a`). Rule 5 (P-12).
    const EXT_TWO_SAME: [u8; 16] = [
        0x30, 0x0e, 0x30, 0x05, 0x06, 0x01, 0x2a, 0x04, 0x00, 0x30, 0x05, 0x06, 0x01, 0x2a, 0x04, 0x00,
    ];
    /// A `Name` of one RDN holding two ATVs with different types (`55`, `56`). No violation.
    const NAME_ONE_RDN_TWO_TYPES: [u8; 18] = [
        0x30, 0x10, 0x31, 0x0e, 0x30, 0x05, 0x06, 0x01, 0x55, 0x05, 0x00, 0x30, 0x05, 0x06, 0x01, 0x56,
        0x05, 0x00,
    ];
    /// A `Name` of one RDN holding two ATVs with the same type (`55`). Rule 7 (P-14).
    const NAME_ONE_RDN_SAME_TYPE: [u8; 18] = [
        0x30, 0x10, 0x31, 0x0e, 0x30, 0x05, 0x06, 0x01, 0x55, 0x05, 0x00, 0x30, 0x05, 0x06, 0x01, 0x55,
        0x05, 0x00,
    ];
    /// A `Name` of two RDNs, each holding one ATV of the same type (`55`). Legal: no violation.
    const NAME_TWO_RDNS_SAME_TYPE: [u8; 20] = [
        0x30, 0x12, 0x31, 0x07, 0x30, 0x05, 0x06, 0x01, 0x55, 0x05, 0x00, 0x31, 0x07, 0x30, 0x05, 0x06,
        0x01, 0x55, 0x05, 0x00,
    ];

    /// Glue plus the REAL helpers on concrete DER, nothing stubbed: with equal algorithm identifiers,
    /// version v3 and a UTCTime pair (rules 1 to 4 satisfied), `validate_profile` returns the exact
    /// expected result for EVERY combination of `extensions` (absent, or one of the empty list, two
    /// different ids, two equal ids), `issuer` and `subject` (the empty Name `30 00`, one RDN with two
    /// types, one RDN with the same type twice, two RDNs each with the same type). 2 x 3 x 4 x 4 = 96
    /// certificates; the expected result is written per kind from the specimens' meaning (kind 2 repeats
    /// an id or an attribute type, kind 0 of the issuer is the empty Name), not from the code. The
    /// certificates are built as struct literals (the same inputs the Kani harness used), so the specimens
    /// reach the helpers exactly as written.
    #[test]
    fn rules_5_to_7_end_to_end_on_specimens() {
        use crate::bit_string::BitString;
        use crate::x509_algorithm_identifier::AlgorithmIdentifier;
        use crate::x509_spki::SubjectPublicKeyInfo;
        use crate::x509_tbs_certificate::TbsCertificate;
        use crate::x509_validity::Validity;

        const EMPTY: &[u8] = &[];
        let oid = [0x2a_u8, 0x2b];
        let alg = AlgorithmIdentifier { algorithm_oid: &oid, parameters: None };
        let t = Time::Utc(UtcTime { year2: 24, month: 1, day: 1, hour: 0, minute: 0, second: 0 });
        let names: [&[u8]; 4] = [&NAME_EMPTY, &NAME_ONE_RDN_TWO_TYPES, &NAME_ONE_RDN_SAME_TYPE, &NAME_TWO_RDNS_SAME_TYPE];
        let exts: [&[u8]; 3] = [&[0x30, 0x00], &EXT_TWO_DISTINCT, &EXT_TWO_SAME];
        let mut seen = [0usize; 5];
        for has_ext in [false, true] {
            for (ext_kind, ext) in exts.iter().enumerate() {
                for (issuer_kind, issuer) in names.iter().enumerate() {
                    for (subject_kind, subject) in names.iter().enumerate() {
                        let cert = Certificate {
                            tbs_certificate: TbsCertificate {
                                version: 2,
                                serial_number: EMPTY,
                                signature: alg,
                                issuer,
                                validity: Validity { not_before: t, not_after: t },
                                subject,
                                subject_public_key_info: SubjectPublicKeyInfo {
                                    algorithm_oid: EMPTY,
                                    parameters: None,
                                    subject_public_key: BitString { data: EMPTY, unused: 0 },
                                },
                                extensions: if has_ext { Some(*ext) } else { None },
                            },
                            signature_algorithm: alg,
                            signature_value: BitString { data: EMPTY, unused: 0 },
                        };
                        let expected = if has_ext && ext_kind == 2 {
                            seen[0] += 1;
                            Err(ProfileError::DuplicateExtension)
                        } else if issuer_kind == 0 {
                            seen[1] += 1;
                            Err(ProfileError::EmptyIssuer)
                        } else if issuer_kind == 2 {
                            seen[2] += 1;
                            Err(ProfileError::IssuerDuplicateAttributeType)
                        } else if subject_kind == 2 {
                            seen[3] += 1;
                            Err(ProfileError::SubjectDuplicateAttributeType)
                        } else {
                            seen[4] += 1;
                            Ok(())
                        };
                        assert_eq!(
                            validate_profile(&cert),
                            expected,
                            "has_ext {has_ext}, ext {ext_kind}, issuer {issuer_kind}, subject {subject_kind}"
                        );
                    }
                }
            }
        }
        // Every outcome is reached, so no branch of the matrix is vacuous. P-12: extensions present and
        // kind 2 (4 x 4 issuer/subject pairs); of the other 80, a quarter each have the empty issuer
        // (P-13), the repeated-type issuer (P-14), and then a repeated-type subject (P-14) among the
        // 40 whose issuer is legal (one RDN with two types, or two RDNs); the rest are accepted. The
        // matrix therefore also covers the precedence P-12 over P-13 over P-14, issuer before subject:
        // each non-first violation is present in the certificates that report an earlier one.
        assert_eq!(seen, [16, 20, 20, 10, 30]);
    }

    // --- S4a group 4: the precedence ladder ---

    /// One stage of the precedence ladder: every input the profile reads, and the expected result.
    struct Stage {
        sig_alg: &'static [u8],
        version: &'static [u8],
        not_before: Vec<u8>,
        not_after: Vec<u8>,
        extensions: Vec<u8>,
        issuer: Vec<u8>,
        subject: Vec<u8>,
        expected: Result<(), ProfileError>,
    }

    /// PROF-P-4: with every rule violated at once, repairing the reported violation moves the report
    /// to the next rule in declaration order (rules 1 to 4, then P-12, P-13, and P-14 for the issuer
    /// and then the subject); the fully repaired certificate is accepted.
    #[test]
    fn repairing_violations_in_declaration_order_ends_in_acceptance() {
        let nb_gen_2049_frac = time_tlv(true, b"20490101000000.5Z");
        let na_gen_2049_frac = time_tlv(true, b"20491231235959.5Z");
        let nb_gen_2050_frac = time_tlv(true, b"20500101000000.5Z");
        let na_gen_2060_frac = time_tlv(true, b"20601231235959.5Z");
        let nb_gen_2050 = time_tlv(true, b"20500101000000Z");
        let na_gen_2060 = time_tlv(true, b"20601231235959Z");
        let nb_utc = time_tlv(false, b"490101000000Z");
        let ext_dup = [
            extension(&OID_BASIC_CONSTRAINTS, false, &[0x30, 0x00]),
            extension(&OID_BASIC_CONSTRAINTS, false, &[0x30, 0x00]),
        ]
        .concat();
        let ext_ok = EXT_BASIC_CONSTRAINTS_DEFAULT.to_vec();
        let dup_name = name(&[rdn(&[atv(&OID_CN, b"A"), atv(&OID_CN, b"B")])]);
        let ok_name = NAME_CN_EXAMPLE_CA.to_vec();
        let empty = NAME_EMPTY.to_vec();
        // Each stage repairs the violation the previous stage reported. Extensions are always
        // present, so a DEFAULT v1 certificate violates rule 2. The issuer goes empty (P-13), then
        // repeated-attribute (P-14), then clean; the subject stays repeated-attribute until the end.
        let stage = |sig_alg: &'static [u8],
                     version: &'static [u8],
                     nb: &Vec<u8>,
                     na: &Vec<u8>,
                     ext: &Vec<u8>,
                     issuer: &Vec<u8>,
                     subject: &Vec<u8>,
                     expected: Result<(), ProfileError>| Stage {
            sig_alg,
            version,
            not_before: nb.clone(),
            not_after: na.clone(),
            extensions: ext.clone(),
            issuer: issuer.clone(),
            subject: subject.clone(),
            expected,
        };
        let stages = [
            stage(&SIGNATURE_RSA_SHA256, &[], &nb_gen_2049_frac, &na_gen_2049_frac, &ext_dup, &empty, &dup_name, Err(ProfileError::SignatureAlgorithmMismatch)),
            stage(&SIGNATURE_ED25519, &[], &nb_gen_2049_frac, &na_gen_2049_frac, &ext_dup, &empty, &dup_name, Err(ProfileError::ExtensionsRequireV3)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2049_frac, &na_gen_2049_frac, &ext_dup, &empty, &dup_name, Err(ProfileError::NotBeforeGeneralizedTimeYearTooEarly)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_utc, &na_gen_2049_frac, &ext_dup, &empty, &dup_name, Err(ProfileError::NotAfterGeneralizedTimeYearTooEarly)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2050_frac, &na_gen_2060_frac, &ext_dup, &empty, &dup_name, Err(ProfileError::NotBeforeGeneralizedTimeHasFraction)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2050, &na_gen_2060_frac, &ext_dup, &empty, &dup_name, Err(ProfileError::NotAfterGeneralizedTimeHasFraction)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2050, &na_gen_2060, &ext_dup, &empty, &dup_name, Err(ProfileError::DuplicateExtension)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2050, &na_gen_2060, &ext_ok, &empty, &dup_name, Err(ProfileError::EmptyIssuer)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2050, &na_gen_2060, &ext_ok, &dup_name, &dup_name, Err(ProfileError::IssuerDuplicateAttributeType)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2050, &na_gen_2060, &ext_ok, &ok_name, &dup_name, Err(ProfileError::SubjectDuplicateAttributeType)),
            stage(&SIGNATURE_ED25519, &VERSION_V3, &nb_gen_2050, &na_gen_2060, &ext_ok, &ok_name, &ok_name, Ok(())),
        ];
        for (index, st) in stages.iter().enumerate() {
            let v = validity_of(&st.not_before, &st.not_after);
            let tbs = build_tbs_full(st.version, Some(&st.extensions), &v, &st.issuer, &st.subject);
            let bytes = build_certificate(&tbs, st.sig_alg);
            let cert = parse_certificate(&bytes).expect("fixture must be structurally valid");
            assert_eq!(validate_profile(&cert), st.expected, "stage {index}");
        }
    }
}
