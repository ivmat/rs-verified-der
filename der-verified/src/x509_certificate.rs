//! X.509 `Certificate` (RFC 5280 §4.1) — the crate's outermost composition: the thin wrapper that
//! ties [`crate::x509_tbs_certificate`]'s signed body together with its outer signature into a
//! complete, structurally-validated X.509 certificate.
//!
//! ```text
//! Certificate ::= SEQUENCE {
//!     tbsCertificate       TBSCertificate,
//!     signatureAlgorithm   AlgorithmIdentifier,
//!     signatureValue       BIT STRING }
//! ```
//!
//! This module is the sibling of [`crate::x509_tbs_certificate`]: a **demonstration of
//! composition**, not an expansion of the crate's DER-layer scope (see the crate-level docs). It
//! frames the outer SEQUENCE with [`crate::sequence`] and delegates every field to the module that
//! already owns its shape — [`crate::x509_tbs_certificate`] for `tbsCertificate`,
//! [`crate::x509_algorithm_identifier`] for `signatureAlgorithm`, and [`crate::bit_string`] for
//! `signatureValue` — it hand-rolls no tag/length/TLV parsing of its own beyond the outer SEQUENCE
//! walk and the two inner field-span extractions.
//!
//! **Materializes all three fields.** Unlike [`crate::x509_tbs_certificate`]'s "validate, don't
//! materialize" stance for its variable-count `issuer`/`subject`/`extensions`, `Certificate` is a
//! fixed three-field schema, so [`parse_certificate`] materializes `tbsCertificate`,
//! `signatureAlgorithm`, and `signatureValue` straight into [`Certificate`]'s fields — mirroring
//! [`crate::x509_spki`]'s and [`crate::x509_validity`]'s stance for their own fixed-shape fields.
//!
//! **Scope boundaries (deliberate):**
//! - *Structural framing only.* [`parse_certificate`] validates that the byte string is a
//!   well-formed, DER-canonical `Certificate` with the exact field tiling the ASN.1 schema
//!   requires. It does **not** verify the `signatureValue` against `tbsCertificate` (no
//!   cryptographic operation of any kind lives in this crate), does not build or validate a
//!   certificate chain/path, and does not check the certificate against any profile.
//! - **RFC 5280 §4.1.1.2's `signatureAlgorithm` == `tbsCertificate.signature` equality is NOT
//!   enforced here.** The RFC requires the outer `signatureAlgorithm` field to be identical to the
//!   `signature` field inside the signed `TBSCertificate` — a real, security-relevant rule (a
//!   mismatch is a classic signature-substitution vector). But it is a **cross-field PROFILE rule**
//!   layered *above* the transfer syntax: both fields independently decode as perfectly valid,
//!   independently-canonical `AlgorithmIdentifier`s, and nothing in the ASN.1 `Certificate` grammar
//!   itself constrains one by the other. This is the exact same altitude split this crate draws
//!   everywhere else (e.g. [`crate::x509_extension`]'s `critical`, [`crate::x509_validity`]'s
//!   UTCTime/GeneralizedTime year-2050 rule): this module frames the syntax, a caller applies the
//!   profile check by comparing `cert.tbs_certificate.signature` against
//!   `cert.signature_algorithm` itself (both are already materialized `AlgorithmIdentifier`s,
//!   directly comparable with `==` since the type derives `PartialEq`).
//! - *Strict, top-to-bottom.* The outer SEQUENCE must consume the entire `input` (no trailing bytes
//!   after the whole `Certificate`); the three fields must exactly tile the outer content in the
//!   fixed RFC 5280 order — the classic parser-differential vector this crate's other modules guard
//!   against (`decode_tlv_strict` / `decode_sequence_tlv_strict`).

use crate::bit_string::{decode_bit_string, BitString, BitStringError};
use crate::bit_string::TAG as BIT_STRING_TAG;
use crate::sequence::{decode_sequence_tlv_strict, SequenceError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};
use crate::x509_algorithm_identifier::{parse_algorithm_identifier, AlgIdError, AlgorithmIdentifier};
use crate::x509_tbs_certificate::{parse_tbs_certificate, TbsCertificate, TbsCertificateError};

/// A structurally-parsed `Certificate`, borrowing from the input it was parsed from.
///
/// See the module docs for what "parsed" means here: all three fields are materialized; no
/// signature verification is performed, and the `signatureAlgorithm`/`tbsCertificate.signature`
/// equality RFC 5280 §4.1.1.2 requires is left to the caller.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Certificate<'a> {
    /// `tbsCertificate`: the certificate's signed body, delegated whole to
    /// [`crate::x509_tbs_certificate::parse_tbs_certificate`].
    pub tbs_certificate: TbsCertificate<'a>,
    /// `signatureAlgorithm`: the algorithm used to compute `signatureValue`, delegated whole to
    /// [`crate::x509_algorithm_identifier::parse_algorithm_identifier`]. RFC 5280 §4.1.1.2 requires
    /// this to equal `tbs_certificate.signature` — a profile rule this module does not enforce (see
    /// the module docs).
    pub signature_algorithm: AlgorithmIdentifier<'a>,
    /// `signatureValue`: the CA's signature over the DER encoding of `tbsCertificate`, decoded to
    /// its value octets + unused-bit count. Neither the signature nor the encoding it was computed
    /// over is verified by this crate.
    pub signature_value: BitString<'a>,
}

/// Why a `Certificate` was rejected. Every variant names a specific structural cause, wrapping the
/// underlying primitive's/sub-module's error where one exists (mirrors
/// [`crate::x509_tbs_certificate::TbsCertificateError`]'s wrapping style).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CertificateError {
    /// The outer `Certificate` SEQUENCE envelope was malformed: bad identifier/length, the
    /// primitive (non-constructed) form, or trailing bytes after the whole structure (this is a
    /// top-level object, decoded with [`decode_sequence_tlv_strict`]).
    BadOuterSeq(SequenceError),
    /// No `tbsCertificate` is present — the outer SEQUENCE's content is empty.
    MissingTbs,
    /// The `tbsCertificate` field's own TLV framing (tag/length octets) — used to find its byte
    /// span — was malformed.
    BadTbsTlv(TlvError),
    /// The `tbsCertificate` span's own content failed
    /// [`crate::x509_tbs_certificate::parse_tbs_certificate`].
    BadTbs(TbsCertificateError),
    /// No `signatureAlgorithm` is present — the outer SEQUENCE's content ended after
    /// `tbsCertificate`.
    MissingSignatureAlgorithm,
    /// The `signatureAlgorithm` `AlgorithmIdentifier` failed to decode.
    BadSignatureAlgorithm(AlgIdError),
    /// No `signatureValue` is present — the outer SEQUENCE's content ended after
    /// `signatureAlgorithm`.
    MissingSignatureValue,
    /// The `signatureValue` TLV's framing (tag/length octets) was malformed.
    BadSignatureValueTlv(TlvError),
    /// The `signatureValue` field's identifier was well-framed but not a UNIVERSAL 3 (BIT STRING)
    /// primitive.
    SignatureValueWrongTag,
    /// The `signatureValue` BIT STRING's content failed canonical-DER validation.
    BadSignatureValue(BitStringError),
    /// Bytes remain in the outer SEQUENCE's content after all three fields (`tbsCertificate`,
    /// `signatureAlgorithm`, `signatureValue`) were consumed — more than the three permitted
    /// top-level fields.
    TrailingInCertificate,
}

/// Parse a complete DER `Certificate` from `input`.
///
/// **Strict, top level**: `input` must be *exactly* one `Certificate` — no trailing bytes are
/// tolerated after the whole structure, and the three fields must exactly tile the outer SEQUENCE's
/// content in RFC 5280's fixed order.
///
/// Walks the outer SEQUENCE's content by byte offset, delegating each field to the module that
/// already owns its shape (see the module docs): `tbsCertificate`'s own TLV span is first extracted
/// with [`decode_tlv`], then [`parse_tbs_certificate`] is called on exactly that span;
/// `signatureAlgorithm` is delegated whole to [`parse_algorithm_identifier`] (which itself returns
/// the bytes it consumed); `signatureValue`'s TLV is decoded, tag-checked, and its content handed to
/// [`decode_bit_string`] — mirroring [`crate::x509_tbs_certificate::parse_tbs_certificate`]'s
/// offset-walk idiom.
///
/// Never panics on any input (proven, for a small representative buffer, by the
/// `parse_certificate_never_panics` Kani harness below — see its comment for the modular-stubbing
/// rationale); returns a classified [`CertificateError`] on any structural deviation.
pub fn parse_certificate(input: &[u8]) -> Result<Certificate<'_>, CertificateError> {
    // 1. Outer SEQUENCE: must consume the whole input (top-level anti-trailing-data).
    let content = decode_sequence_tlv_strict(input).map_err(CertificateError::BadOuterSeq)?;
    let mut off = 0usize;

    // 2. tbsCertificate — extract the TLV span, then hand exactly that span to the TBS parser.
    if content[off..].is_empty() {
        return Err(CertificateError::MissingTbs);
    }
    let (_tbs_tlv, tbs_used) =
        decode_tlv(&content[off..]).map_err(CertificateError::BadTbsTlv)?;
    let tbs_span = &content[off..off + tbs_used];
    let tbs_certificate = parse_tbs_certificate(tbs_span).map_err(CertificateError::BadTbs)?;
    off += tbs_used;

    // 3. signatureAlgorithm (AlgorithmIdentifier) — composable, returns its own `used`.
    if content[off..].is_empty() {
        return Err(CertificateError::MissingSignatureAlgorithm);
    }
    let (signature_algorithm, sig_alg_used) = parse_algorithm_identifier(&content[off..])
        .map_err(CertificateError::BadSignatureAlgorithm)?;
    off += sig_alg_used;

    // 4. signatureValue (BIT STRING).
    if content[off..].is_empty() {
        return Err(CertificateError::MissingSignatureValue);
    }
    let (sig_tlv, sig_used) =
        decode_tlv(&content[off..]).map_err(CertificateError::BadSignatureValueTlv)?;
    if sig_tlv.tag.class != Class::Universal
        || sig_tlv.tag.number != BIT_STRING_TAG
        || sig_tlv.tag.constructed
    {
        return Err(CertificateError::SignatureValueWrongTag);
    }
    let signature_value =
        decode_bit_string(sig_tlv.value).map_err(CertificateError::BadSignatureValue)?;
    off += sig_used;

    // 5. Strict tiling: nothing may remain after signatureValue.
    if off != content.len() {
        return Err(CertificateError::TrailingInCertificate);
    }

    Ok(Certificate { tbs_certificate, signature_algorithm, signature_value })
}

// ---------------------------------------------------------------------------
// Kani proof harness — MODULAR STUBBING.
// ---------------------------------------------------------------------------
//
// Why: `parse_certificate` wraps `parse_tbs_certificate`, itself the crate's largest composition
// (see that module's own Kani comment) — inlining its full call graph a second time, underneath yet
// another SEQUENCE walk, is even more intractable than the TBS-level monolithic harness that already
// times out. The fix is the same standard MODULAR-verification technique: Kani STUBBING
// (`-Z stubbing`, wired into `check.sh`). `parse_tbs_certificate` is replaced for THIS harness by a
// nondeterministic `Result` stub (see `mod proofs`). This is SOUND: `parse_tbs_certificate` is
// INDEPENDENTLY proven panic-free (modularly) at its own harness
// (`x509_tbs_certificate::proofs::parse_tbs_certificate_never_panics`), and this composition's
// panic-freedom does not depend on its internals — the Certificate glue only branches on its
// returned `Result` (never inspects a materialized value) and advances `off` by the length from its
// OWN real `decode_tlv` on the tbs span, never from the callee. A stub returning both `Ok` and `Err`
// OVER-approximates the real parser (which returns `Ok` on a strict subset of inputs), and exploring
// more control-flow outcomes cannot hide a panic. With `parse_tbs_certificate`'s body removed from
// the inlined program, a `[u8; 12]` buffer converges.
//
// What this harness therefore verifies is the REAL Certificate-specific glue: the outer-SEQUENCE
// walk, the tbs-span extraction (`decode_tlv` + slicing), the REAL `signatureAlgorithm`
// (`AlgorithmIdentifier`) and `signatureValue` (BIT STRING) parses, and the strict tiling. The
// residual (`parse_tbs_certificate`'s internals, and inputs longer than 12 octets) is covered
// COMPOSITIONALLY: `decode_tlv`'s own no-over-read contract (`used <= remaining`, proven in
// `tlv.rs`) keeps `tbs_span`'s slice in-bounds regardless of how large `content` is, and
// `parse_tbs_certificate` is proven panic-free on its own (modularly). The `[u8; 12]` buffer is a
// DELIBERATE, DOCUMENTED reduction, in the same spirit as `x509_tbs_certificate`'s 10-octet harness.
//
// `#[kani::unwind(12)]` covers a maximal-header `decode_tlv` (~11, per `tlv.rs`) plus the loops
// reachable in 12 octets (the AlgorithmIdentifier OID walk) with margin. If Kani reports an
// unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::x509_spki::SubjectPublicKeyInfo;
    use crate::x509_validity::{Time, Validity};
    use crate::utc_time::UtcTime;

    // Modular stub: parse_tbs_certificate is independently proven panic-free (modularly) at its own
    // harness; the Certificate glue only branches on its returned Result and advances `off` by its OWN
    // real decode_tlv length, never the callee's — so a nondeterministic Ok/Err stub is SOUND for this
    // composition's panic-freedom (over-approximation cannot hide a panic). This removes the huge
    // inlined TBS call graph from CBMC's program, keeping the Certificate harness tractable. See
    // x509_tbs_certificate's Kani comment for the full rationale.
    #[allow(dead_code)]
    fn stub_parse_tbs_certificate(_input: &[u8]) -> Result<TbsCertificate<'_>, TbsCertificateError> {
        if kani::any() {
            Ok(TbsCertificate {
                version: 0,
                serial_number: &[],
                signature: AlgorithmIdentifier { algorithm_oid: &[], parameters: None },
                issuer: &[],
                validity: Validity {
                    not_before: Time::Utc(UtcTime { year2: 0, month: 1, day: 1, hour: 0, minute: 0, second: 0 }),
                    not_after: Time::Utc(UtcTime { year2: 0, month: 1, day: 1, hour: 0, minute: 0, second: 0 }),
                },
                subject: &[],
                subject_public_key_info: SubjectPublicKeyInfo {
                    algorithm_oid: &[], parameters: None,
                    subject_public_key: BitString { data: &[], unused: 0 },
                },
                extensions: None,
            })
        } else {
            Err(TbsCertificateError::MissingSerial)
        }
    }

    /// Robustness: `parse_certificate` never panics on any input up to 12 octets, with
    /// `parse_tbs_certificate` MODULARLY STUBBED (see above). Exercises the real Certificate glue:
    /// the outer SEQUENCE walk, the tbs-span extraction, the real signatureAlgorithm
    /// (AlgorithmIdentifier) + signatureValue (BIT STRING) parses, and the strict tiling.
    ///
    /// Cover (T6 primary rule + T2-COROLLARY-A): this harness stacks a `[u8; 12]` bound AND a
    /// `parse_tbs_certificate` stub -- per the corollary, the intersection must be checked for
    /// vacuity. The module doc claims this harness "verifies the REAL Certificate-specific glue:
    /// the outer-SEQUENCE walk, the tbs-span extraction ..., the REAL `signatureAlgorithm` ... and
    /// `signatureValue` ... parses, and the strict tiling." Reaching `Ok` is the deepest available
    /// post-state witness through the opaque `Result` that all of that real glue ran to completion
    /// (tbs-span extraction, both real field parses, strict tiling), not just that an early field
    /// rejected the input. Would NOT be SAT if `parse_certificate`'s body were a no-op always
    /// returning `Err`.
    #[kani::proof]
    #[kani::stub(crate::x509_tbs_certificate::parse_tbs_certificate, stub_parse_tbs_certificate)]
    #[kani::unwind(12)]
    fn parse_certificate_never_panics() {
        let buf: [u8; 12] = kani::any();
        // Symbolic input length so the "up to 12 octets" claim holds at every length its own callers
        // (and the anti-trailing-data envelope) can produce, not just the full buffer.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let result = parse_certificate(&buf[..len]);
        kani::cover(
            result.is_ok(),
            "parse_certificate reaches its Ok tail: the real outer-SEQUENCE walk, tbs-span \
             extraction, real signatureAlgorithm + signatureValue parses, and strict tiling all \
             ran to completion over the stubbed parse_tbs_certificate's Ok outcome",
        );
        let _ = result;
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509_tbs_certificate::TbsCertificateError;

    // --- test-only DER assembly helpers (not part of the crate's verified surface: these build
    //     fixtures for the parser under test, they are not what is being verified) — copied from
    //     `x509_tbs_certificate`'s own test module, per this crate's fixture-reuse convention. ---

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

    // --- known-good field specimens, copied verbatim from `x509_tbs_certificate.rs`'s own tests
    //     (per the task spec: reuse known-good encodings rather than inventing new ones). ---

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

    /// Assemble a complete, valid v3 `TBSCertificate` (all fields present, including
    /// `extensions`) — byte-for-byte the same fixture as
    /// `x509_tbs_certificate::tests::build_v3_tbs_with_extensions`. Field byte counts: version 5,
    /// serial 3, signature 7, issuer 23, validity 32, subject 23, spki 44, extensions-wrapped 15 =>
    /// outer content = 152 octets (needs the long-form length `81 98`); total fixture length 155
    /// octets. Both figures are asserted immediately below.
    fn build_v3_tbs_with_extensions() -> Vec<u8> {
        let extensions_seq = wrap(0x30, &EXT_BASIC_CONSTRAINTS_DEFAULT); // Extensions SEQUENCE
        let extensions_wrapped = wrap(0xA3, &extensions_seq); // [3] EXPLICIT
        assert_eq!(extensions_wrapped.len(), 15);

        let mut content = Vec::new();
        content.extend_from_slice(&VERSION_V3);
        content.extend_from_slice(&SERIAL_1);
        content.extend_from_slice(&SIGNATURE_ED25519);
        content.extend_from_slice(&NAME_CN_EXAMPLE_CA); // issuer
        content.extend_from_slice(&VALIDITY_UTC_UTC);
        content.extend_from_slice(&NAME_CN_EXAMPLE_CA); // subject
        content.extend_from_slice(&SPKI_ED25519);
        content.extend_from_slice(&extensions_wrapped);
        assert_eq!(content.len(), 152);

        let full = wrap(0x30, &content);
        assert_eq!(full.len(), 155);
        full
    }

    /// Byte offset, within `build_v3_tbs_with_extensions()`'s own output, of the `[0]` wrapper's
    /// inner INTEGER's value octet (outer header is 3 octets: `30 81 98`) — copied from
    /// `x509_tbs_certificate::tests::OFF_VERSION_VALUE`.
    const TBS_OFF_VERSION_VALUE: usize = 3 + 4;

    /// Assemble a complete, valid `Certificate`: `tbsCertificate` (the v3-with-extensions fixture
    /// above) + `signatureAlgorithm` (Ed25519) + `signatureValue` (a minimal BIT STRING), wrapped in
    /// the outer SEQUENCE.
    ///
    /// Field byte counts: tbsCertificate 155, signatureAlgorithm 7, signatureValue 5 => outer
    /// content = 167 octets (needs the long-form length `81 a7`); total fixture length 170 octets.
    /// Both figures are asserted immediately below.
    fn build_certificate() -> Vec<u8> {
        let tbs = build_v3_tbs_with_extensions();
        let mut content = Vec::new();
        content.extend_from_slice(&tbs);
        content.extend_from_slice(&SIGNATURE_ED25519);
        content.extend_from_slice(&SIGNATURE_VALUE);
        assert_eq!(content.len(), 167);

        let full = wrap(0x30, &content);
        assert_eq!(full.len(), 170);
        full
    }

    #[test]
    fn parses_complete_certificate() {
        let bytes = build_certificate();
        let cert = parse_certificate(&bytes).unwrap();
        assert_eq!(cert.tbs_certificate.version, 2);
        assert_eq!(cert.signature_algorithm.algorithm_oid, &[0x2b, 0x65, 0x70]);
        assert_eq!(cert.signature_algorithm.parameters, None);
        assert_eq!(cert.signature_value.unused, 0);
        assert_eq!(cert.signature_value.data, &[0xAA, 0xBB]);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = build_certificate();
        bytes[0] = 0x31;
        assert_eq!(
            parse_certificate(&bytes),
            Err(CertificateError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_malformed_tbs() {
        // Corrupt the tbsCertificate span's own `[0]` version wrapper's inner INTEGER value byte,
        // 02 -> 00 (v1's value): present-but-DEFAULT, rejected by parse_tbs_certificate itself. The
        // tbsCertificate's own outer SEQUENCE framing is untouched, so the Certificate-level span
        // extraction still finds the correct 155-byte tbs TLV; parse_tbs_certificate then rejects
        // its content.
        let mut tbs = build_v3_tbs_with_extensions();
        tbs[TBS_OFF_VERSION_VALUE] = 0x00;

        let mut content = Vec::new();
        content.extend_from_slice(&tbs);
        content.extend_from_slice(&SIGNATURE_ED25519);
        content.extend_from_slice(&SIGNATURE_VALUE);
        let bytes = wrap(0x30, &content);

        assert_eq!(
            parse_certificate(&bytes),
            Err(CertificateError::BadTbs(TbsCertificateError::VersionMustBeOmitted))
        );
    }

    #[test]
    fn rejects_signature_value_wrong_tag() {
        // signatureValue uses OCTET STRING (0x04) instead of BIT STRING (0x03). Its TLV begins
        // right after tbsCertificate (155) + signatureAlgorithm (7) = outer content offset 162, plus
        // the outer header (3 octets: `30 81 a7`) = absolute offset 165.
        let mut bytes = build_certificate();
        const SIG_VALUE_TAG_OFFSET: usize = 3 + 155 + 7;
        assert_eq!(bytes[SIG_VALUE_TAG_OFFSET], 0x03); // sanity: this is indeed the BIT STRING tag
        bytes[SIG_VALUE_TAG_OFFSET] = 0x04;
        assert_eq!(parse_certificate(&bytes), Err(CertificateError::SignatureValueWrongTag));
    }

    #[test]
    fn rejects_trailing_in_certificate() {
        // Bump the outer SEQUENCE's declared content length by one (167 -> 168, `a7` -> `a8`) and
        // append one extra content octet. The outer envelope itself still consumes exactly the
        // (now 171-byte) input, so BadOuterSeq is not triggered -- but the field walk only ever
        // consumes 167 of the 168 declared content bytes, leaving one over.
        let mut bytes = build_certificate();
        bytes[2] = 0xA8; // the `a7` low length-byte of `30 81 a7`
        bytes.push(0xAA);
        assert_eq!(bytes.len(), 171);
        assert_eq!(parse_certificate(&bytes), Err(CertificateError::TrailingInCertificate));
    }

    #[test]
    fn rejects_truncated_input() {
        // Drop the last 10 bytes: the outer SEQUENCE declares more content than is present.
        let bytes = build_certificate();
        let truncated = &bytes[..bytes.len() - 10];
        assert_eq!(
            parse_certificate(truncated),
            Err(CertificateError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_missing_signature_value() {
        // A Certificate with only tbsCertificate + signatureAlgorithm, nothing after.
        let tbs = build_v3_tbs_with_extensions();
        let mut content = Vec::new();
        content.extend_from_slice(&tbs);
        content.extend_from_slice(&SIGNATURE_ED25519);
        assert_eq!(content.len(), 162);
        let bytes = wrap(0x30, &content);

        assert_eq!(parse_certificate(&bytes), Err(CertificateError::MissingSignatureValue));
    }
}
