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
//! for the first two such rules:
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
//! **Scope.** Both `Certificate` and `TbsCertificate` are already fully structurally parsed by the
//! time [`validate_profile`] runs — this module inspects already-materialized fields
//! (`AlgorithmIdentifier` values, the `version` `u8`, the `extensions` `Option`) and performs no
//! byte-level decoding of its own. It establishes the pattern the rest of the profile layer (key
//! usage, basic constraints, name constraints, path validation, …) is expected to follow: a
//! separate module, downstream of the structural parsers, that never modifies their logic.

use crate::x509_certificate::Certificate;

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
}

/// Check `cert` against this module's RFC 5280 profile rules (see the module docs for exactly
/// which two).
///
/// `cert` must already be a structurally-valid [`Certificate`] (i.e. the output of
/// [`crate::x509_certificate::parse_certificate`]) — this function performs no DER decoding of its
/// own, only comparisons over already-materialized fields. Returns `Ok(())` if both rules hold,
/// else the first violated rule's [`ProfileError`] (checked in the order the variants are
/// declared: signature-algorithm equality, then the extensions/version rule).
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

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
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

    /// Assemble a `TBSCertificate` with the given `version` field bytes (pass `&[]` to omit the
    /// `[0]` wrapper entirely, i.e. DEFAULT v1) and, optionally, an `extensions` field.
    fn build_tbs(version_bytes: &[u8], extensions: Option<&[u8]>) -> Vec<u8> {
        let mut content = Vec::new();
        content.extend_from_slice(version_bytes);
        content.extend_from_slice(&SERIAL_1);
        content.extend_from_slice(&SIGNATURE_ED25519);
        content.extend_from_slice(&NAME_CN_EXAMPLE_CA); // issuer
        content.extend_from_slice(&VALIDITY_UTC_UTC);
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
}
