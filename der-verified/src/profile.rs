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
//! for the first four such rules:
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
//!
//! **Scope.** For a *parser-produced* `Certificate` (the output of
//! [`crate::x509_certificate::parse_certificate`]), both `Certificate` and `TbsCertificate` are
//! already fully structurally parsed by the time [`validate_profile`] runs — this module inspects
//! already-materialized fields (`AlgorithmIdentifier` values, the `version` `u8`, the `extensions`
//! `Option`, the `Validity`'s two `Time` CHOICE arms, their year fields, and the emptiness of a
//! GeneralizedTime's fraction) and performs no byte-level decoding of its own. The structural claims in
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

/// Check `cert` against this module's RFC 5280 profile rules (see the module docs for exactly
/// which four).
///
/// `cert` is expected to be a structurally-valid [`Certificate`] (i.e. the output of
/// [`crate::x509_certificate::parse_certificate`]; the public fields also allow a hand-built value,
/// which is not checked structurally) — this function performs no DER decoding of its own, only
/// comparisons over already-materialized fields. Returns `Ok(())` if all rules hold, else
/// the first violated rule's [`ProfileError`] (checked in the order the variants are declared:
/// signature-algorithm equality, then the extensions/version rule, then `notBefore`'s
/// encoding-choice year rule, then `notAfter`'s, then `notBefore`'s no-fractional-seconds rule, then
/// `notAfter`'s). Rule 4 is checked after both rule 3 fields so that the errors reported for
/// certificates that were already rejected before rule 4 existed are unchanged.
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
    use crate::x509_algorithm_identifier::AlgorithmIdentifier;
    use crate::x509_spki::SubjectPublicKeyInfo;
    use crate::x509_tbs_certificate::TbsCertificate;
    use crate::x509_validity::Validity;

    /// Build a `Certificate` whose *profile-relevant* fields are symbolic and whose
    /// profile-irrelevant fields are fixed.
    ///
    /// This is the whole reason `profile` is cheap to verify where the `x509_*` modules are not: this
    /// module performs **no byte-level decoding** (its own module docs say so), so a harness does not
    /// need a symbolic DER buffer and a parse — it needs a symbolic *value*. The opaque byte-span
    /// fields (`serial_number`, `issuer`, `subject`, key material) are never read by
    /// `validate_profile`, so fixing them to an empty slice loses no generality; what stays symbolic
    /// is exactly what the four rules inspect.
    fn symbolic_cert<'a>(
        sig_alg: AlgorithmIdentifier<'a>,
        tbs_sig: AlgorithmIdentifier<'a>,
        version: u8,
        extensions: Option<&'a [u8]>,
        validity: Validity<'a>,
    ) -> Certificate<'a> {
        const EMPTY: &[u8] = &[];
        Certificate {
            tbs_certificate: TbsCertificate {
                version,
                serial_number: EMPTY,
                signature: tbs_sig,
                issuer: EMPTY,
                validity,
                subject: EMPTY,
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
    #[kani::proof]
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

    /// **Whole-function exact-result oracle.** Over
    /// symbolic algorithm identifiers (4-octet OID and parameter backings with symbolic lengths
    /// `0..=4` and symbolic parameter presence on each side), a symbolic `version` (all 256 values),
    /// symbolic `extensions` presence, and both `Time`s with EVERY field symbolic (`any_time`: the
    /// UTCTime arm over all `u8` field values, no `year2 <= 99` assumption; the GeneralizedTime arm
    /// with a symbolic `u16` year -- which includes the 2049/2050 boundary -- symbolic
    /// month/day/hour/minute/second and a symbolic 0..=4-octet fraction), `validate_profile(cert)`
    /// equals `expected(..)` EXACTLY. The profile-irrelevant certificate fields are symbolic too:
    /// `serial_number`, `issuer`, `subject`, the SPKI (OID, optional parameters, key window, unused
    /// count), `signature_value`, and the `extensions` content are each a symbolic 0..=2-octet window
    /// over a 2-octet symbolic backing (`unused` is any `u8`), so no "never read" argument by
    /// inspection is needed: the reference below depends only on what the module docs say is
    /// inspected (algorithm identifiers, `version`, extensions PRESENCE, each Time's arm, year and
    /// fraction emptiness), and the assertion proves nothing else changes the result.
    /// `expected` is an independent total reference written from the documented rule precedence (the
    /// `validate_profile` doc comment and the `ProfileError` declaration order: signature-algorithm,
    /// then extensions/version, then `notBefore`'s year rule, then `notAfter`'s, then `notBefore`'s
    /// no-fraction rule, then `notAfter`'s): algorithm equality is computed from the raw bytes with
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
    /// irrelevant spans; a 4-octet backing, length `0..=4`, for each Generalized fraction. Slices
    /// longer than that are not enumerated (for the fraction: lengths above 4 are covered by unit tests
    /// only, and the code reads emptiness, not length). The profile-irrelevant spans and fractions
    /// are inspected only for presence or emptiness, so their windows are representative. The two
    /// algorithm identifiers are compared octet by octet, however, so their `0..=4` windows bound
    /// the proof rather than establishing the result for arbitrary identifier lengths.
    #[kani::proof]
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
        let cert = Certificate {
            tbs_certificate: TbsCertificate {
                version,
                serial_number: window(&serial),
                signature: b,
                issuer: window(&issuer),
                validity: Validity { not_before: nb, not_after: na },
                subject: window(&subject),
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm_oid: window(&spki_oid),
                    parameters: if spki_has_par { Some(window(&spki_par)) } else { None },
                    subject_public_key: BitString { data: window(&spki_key), unused: kani::any() },
                },
                extensions: if has_ext { Some(window(&ext_back)) } else { None },
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
    }

    // ---- P4: rule 2, as a biconditional ----

    /// Rule 2 (§4.1.2.1 / §4.1.2.9), **exactly**: with rule 1 satisfied, `validate_profile` rejects
    /// with `ExtensionsRequireV3` iff `extensions` is present and `version != 2` — over a fully
    /// symbolic `version: u8` (all 256 values, not just 0/1/2) and a symbolic present/absent
    /// `extensions`.
    #[kani::proof]
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
    /// the order `validate_profile`'s doc comment promises.
    #[kani::proof]
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
    /// either side (which has no fraction field) is never rejected by this rule.
    #[kani::proof]
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

    // ---- P6: precedence across all four rules ----

    /// The declared rule ORDER is part of the contract (`validate_profile`'s doc comment states it):
    /// signature-algorithm, then extensions/version, then `notBefore`'s year rule, then `notAfter`'s,
    /// then `notBefore`'s no-fraction rule, then `notAfter`'s. With every rule independently
    /// violable, the reported error is always the first violated one.
    #[kani::proof]
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
        let a = symbolic_alg(&oid_a, &[0], false);
        let b = symbolic_alg(&oid_b, &[0], false);
        let frac: [u8; 1] = [0];
        let nb = symbolic_time(nb_gen, nb_year, 24, &frac, nb_has_frac);
        let na = symbolic_time(na_gen, na_year, 24, &frac, na_has_frac);
        const EXT: &[u8] = &[0x30, 0x00];
        let cert = symbolic_cert(a, b, version, if has_ext { Some(EXT) } else { None },
                                 Validity { not_before: nb, not_after: na });
        let r = validate_profile(&cert);

        let bad1 = a != b;
        let bad2 = has_ext && version != 2;
        let bad3 = nb_gen && nb_year <= 2049;
        let bad4 = na_gen && na_year <= 2049;
        let bad5 = nb_gen && nb_has_frac;
        let bad6 = na_gen && na_has_frac;
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
        } else {
            Ok(())
        };
        assert!(r == expected);
        kani::cover(
            bad1 && bad2 && bad3 && bad4 && bad5 && bad6,
            "all six violations at once -- rule 1 still wins",
        );
        kani::cover(!bad1 && bad2 && bad3, "rule 2 wins over rule 3");
        kani::cover(!bad1 && !bad2 && !bad3 && bad4 && bad5, "notAfter's year error wins over notBefore's fraction error");
        kani::cover(!bad1 && !bad2 && !bad3 && !bad4 && bad5 && bad6, "notBefore's fraction error wins over notAfter's");
        kani::cover(!bad1 && !bad2 && !bad3 && !bad4 && !bad5 && bad6, "notAfter's fraction error is reachable alone");
        kani::cover(r.is_ok(), "a fully conforming certificate is accepted");
    }

    // ---- P7: totality ----

    /// `validate_profile` is total on symbolic profile-relevant fields: no panic, no arithmetic
    /// overflow, for any combination of the fields the four rules inspect.
    ///
    /// **Every harness in this module carries an explicit `#[kani::unwind]`, and that is load-bearing
    /// rather than stylistic.** Rule 1 compares two `AlgorithmIdentifier`s, whose `parameters` field
    /// is an `Option<&[u8]>`; with the presence of that `Option` left symbolic, an unbounded harness
    /// sends CBMC into `memcmp` unwinding that does not converge — observed at ~18,000 iterations
    /// before the run was OOM-killed inside its 14 GB cgroup. The bound of 4 makes it converge in
    /// under a minute, and CBMC's own unwinding assertion (checked, not assumed) confirms 4
    /// iterations suffice, so the bound costs no generality. Read an OOM on one of these as a
    /// missing bound before reading it as an intractable harness.
    #[kani::proof]
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
        let a = symbolic_alg(&oid_a, &par, has_a);
        let b = symbolic_alg(&oid_b, &par, has_b);
        let nb = symbolic_time(nb_gen, nb_year, y2, &frac, has_frac);
        let na = symbolic_time(na_gen, na_year, y2, &frac, has_frac);
        const EXT: &[u8] = &[0x30, 0x00];
        let cert = symbolic_cert(a, b, version, if has_ext { Some(EXT) } else { None },
                                 Validity { not_before: nb, not_after: na });
        let r = validate_profile(&cert);
        // A totality harness has no functional `assert!` by construction, so without these it would
        // be the crate's only harness whose sole checks are Kani's implicit panic/overflow/memory
        // ones -- the row PROOF_MANIFEST section 8.2 keeps at 0 and treats as load-bearing. Both are
        // post-state effects of the widest symbolic instance in this module.
        kani::cover(r.is_ok(), "a conforming certificate is accepted at the fully-symbolic bound");
        kani::cover(r.is_err(), "a violating certificate is rejected at the fully-symbolic bound");
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
        let mut content = Vec::new();
        content.extend_from_slice(version_bytes);
        content.extend_from_slice(&SERIAL_1);
        content.extend_from_slice(&SIGNATURE_ED25519);
        content.extend_from_slice(&NAME_CN_EXAMPLE_CA); // issuer
        content.extend_from_slice(validity);
        content.extend_from_slice(&NAME_CN_EXAMPLE_CA); // subject
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
}
