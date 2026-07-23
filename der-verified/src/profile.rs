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
//! for the first three such rules:
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
//!    2050-and-later). See [`check_time_encoding_year`]'s doc comment for the same point stated at
//!    the call site, and `tests::full_year_rfc5280_never_reaches_2050` for the machine-checked proof
//!    of the structural half this module relies on.
//!
//! **Scope.** Both `Certificate` and `TbsCertificate` are already fully structurally parsed by the
//! time [`validate_profile`] runs — this module inspects already-materialized fields
//! (`AlgorithmIdentifier` values, the `version` `u8`, the `extensions` `Option`, the `Validity`'s two
//! `Time` CHOICE arms and their year fields) and performs no byte-level decoding of its own. It
//! establishes the pattern the rest of the profile layer (key usage, basic constraints, name
//! constraints, path validation, …) is expected to follow: a separate module, downstream of the
//! structural parsers, that never modifies their logic.

use crate::x509_certificate::Certificate;
use crate::x509_validity::Time;

/// Why a structurally-valid [`Certificate`] failed an RFC 5280 profile check. Every variant names
/// a specific cross-field rule this module enforces (see the module docs), citing the RFC clause,
/// distinct from the structural [`crate::x509_certificate::CertificateError`] /
/// [`crate::x509_tbs_certificate::TbsCertificateError`] the certificate already had to pass to be
/// representable as a [`Certificate`] at all.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
/// `tests::full_year_rfc5280_never_reaches_2050` for the machine-checked proof of the structural
/// half described above.
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

/// Check `cert` against this module's RFC 5280 profile rules (see the module docs for exactly
/// which three).
///
/// `cert` must already be a structurally-valid [`Certificate`] (i.e. the output of
/// [`crate::x509_certificate::parse_certificate`]) — this function performs no DER decoding of its
/// own, only comparisons over already-materialized fields. Returns `Ok(())` if all rules hold, else
/// the first violated rule's [`ProfileError`] (checked in the order the variants are declared:
/// signature-algorithm equality, then the extensions/version rule, then `notBefore`'s
/// encoding-choice year rule, then `notAfter`'s).
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

    Ok(())
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
}
