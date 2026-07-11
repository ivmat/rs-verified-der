//! X.509 `AlgorithmIdentifier` (RFC 5280 §4.1.1.2) — a bounded, **structural** consumer that
//! composes this crate's verified primitives.
//!
//! ```text
//! AlgorithmIdentifier ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY DEFINED BY algorithm OPTIONAL }
//! ```
//!
//! This module is the sibling of [`crate::x509_spki`]: a **demonstration of composition**, not an
//! expansion of the crate's DER-layer scope (see the crate-level docs). It frames the SEQUENCE and
//! the OBJECT IDENTIFIER field using [`crate::sequence`], [`crate::tlv`], and [`crate::oid`]
//! verbatim — it does not hand-roll any tag/length/TLV parsing of its own.
//!
//! **Why this is its own module.** `AlgorithmIdentifier` is not unique to `SubjectPublicKeyInfo`:
//! RFC 5280 uses the identical `SEQUENCE { OID, ANY OPTIONAL }` shape for `subjectPublicKeyInfo.
//! algorithm`, `TBSCertificate.signature`, and `Certificate.signatureAlgorithm` alike. This module
//! extracts the parsing logic that previously lived inline inside [`crate::x509_spki`] so all three
//! call sites — and any future one — share a single verified parser rather than three copies of the
//! same TLV walk.
//!
//! **Scope boundaries (deliberate):**
//! - *Structural framing only.* [`parse_algorithm_identifier`] validates that the byte string is a
//!   well-formed, DER-canonical `AlgorithmIdentifier` with the exact field tiling the ASN.1 schema
//!   requires (algorithm OID, then an optional ANY, nothing more, nothing less). It does **not**
//!   interpret *which* algorithm the OID names.
//! - *`parameters` stays raw.* The second field is ASN.1 `ANY` — its DER encoding (tag + length +
//!   value) is returned unparsed and uninterpreted; this module does not know or care whether it
//!   holds an OID (as for EC), is absent (as for Ed25519, RFC 8410 §3), or is a NULL (as for classic
//!   RSA).
//! - *Strict tiling, not strict top-level.* The two fields must exactly tile the SEQUENCE's content
//!   (rejecting a third field), but [`parse_algorithm_identifier`] itself does **not** require its
//!   `input` to be consumed exactly — it composes inside a larger structure (e.g. `Certificate` has
//!   more fields after `signatureAlgorithm`), mirroring [`crate::sequence::decode_sequence_tlv`]'s
//!   non-strict, composable stance. A top-level caller checks the returned length against
//!   `input.len()` itself, exactly as [`crate::x509_spki::parse_subject_public_key_info`] does for
//!   its own outer SEQUENCE.

use crate::oid::{validate_oid, OidError};
use crate::oid::TAG as OID_TAG;
use crate::sequence::{decode_sequence_tlv, SequenceError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};

/// A structurally-parsed `AlgorithmIdentifier`, borrowing from the input it was parsed from.
///
/// See the module docs for the scope of what "parsed" means here: framing only, no algorithm
/// interpretation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct AlgorithmIdentifier<'a> {
    /// `algorithm`: the canonically-validated OBJECT IDENTIFIER **content** octets (not the TLV
    /// header) — see [`crate::oid::validate_oid`]. This module does not decode which arcs the OID
    /// names; a caller that needs that materializes/compares the arcs itself.
    pub algorithm_oid: &'a [u8],
    /// `parameters` (`ANY OPTIONAL`): the raw DER encoding of the parameters TLV — its own tag,
    /// length, and value octets, verbatim — when present. `None` when the AlgorithmIdentifier has
    /// exactly one field (e.g. Ed25519's, RFC 8410 §3). Completely uninterpreted.
    pub parameters: Option<&'a [u8]>,
}

/// Why an `AlgorithmIdentifier` was rejected. Every variant names a specific structural cause,
/// wrapping the underlying primitive's error where one exists.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum AlgIdError {
    /// The `AlgorithmIdentifier` SEQUENCE envelope was malformed: bad identifier/length, or the
    /// primitive (non-constructed) form.
    BadSeq(SequenceError),
    /// The `algorithm` OID's TLV framing (tag/length octets) was malformed.
    BadOidTlv(TlvError),
    /// The `algorithm` field's identifier was well-framed but not UNIVERSAL 6 (OBJECT IDENTIFIER).
    OidWrongTag,
    /// The `algorithm` field's identifier was UNIVERSAL 6 but in the constructed form — OBJECT
    /// IDENTIFIER content is always primitive.
    OidConstructed,
    /// The `algorithm` OID's content failed canonical-DER validation.
    BadOid(OidError),
    /// The optional `parameters` TLV's framing (tag/length octets) was malformed.
    BadParametersTlv(TlvError),
    /// The `AlgorithmIdentifier` SEQUENCE has more than its two permitted fields (algorithm,
    /// parameters): bytes remain in its content after the parameters TLV.
    TrailingElements,
}

/// Decode the `algorithm` OID TLV from the front of `input`, returning its validated content
/// octets and the bytes consumed. Composes [`decode_tlv`] + [`validate_oid`].
fn decode_oid_tlv(input: &[u8]) -> Result<(&[u8], usize), AlgIdError> {
    let (tlv, used) = decode_tlv(input).map_err(AlgIdError::BadOidTlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != OID_TAG {
        return Err(AlgIdError::OidWrongTag);
    }
    if tlv.tag.constructed {
        return Err(AlgIdError::OidConstructed);
    }
    validate_oid(tlv.value).map_err(AlgIdError::BadOid)?;
    Ok((tlv.value, used))
}

/// Parse one `AlgorithmIdentifier` from the front of `input`.
///
/// Composable, like [`crate::sequence::decode_sequence_tlv`]: does **not** require `input` to be
/// consumed exactly (trailing bytes after this AlgorithmIdentifier are ignored, as with any
/// non-top-level TLV) — a top-level caller checks the returned length itself.
///
/// Decodes, in order:
/// 1. the SEQUENCE envelope ([`decode_sequence_tlv`]);
/// 2. inside it, the OID ([`decode_tlv`] + [`validate_oid`]) then the optional `ANY` parameters
///    TLV ([`decode_tlv`], stored raw), requiring the two fields to exactly tile the SEQUENCE's
///    content.
///
/// Never panics on any input (proven by the `parse_algorithm_identifier_never_panics` Kani harness
/// below); returns a classified [`AlgIdError`] on any structural deviation.
pub fn parse_algorithm_identifier(
    input: &[u8],
) -> Result<(AlgorithmIdentifier<'_>, usize), AlgIdError> {
    // 1. SEQUENCE envelope.
    let (algo_content, used) = decode_sequence_tlv(input).map_err(AlgIdError::BadSeq)?;

    // 2. Inside: the OID, then the optional ANY parameters, exact-tiling.
    let (algorithm_oid, oid_used) = decode_oid_tlv(algo_content)?;
    let rest = &algo_content[oid_used..];
    let parameters = if rest.is_empty() {
        None
    } else {
        let (_params_tlv, params_used) = decode_tlv(rest).map_err(AlgIdError::BadParametersTlv)?;
        if params_used != rest.len() {
            return Err(AlgIdError::TrailingElements);
        }
        Some(&rest[..params_used])
    };

    Ok((AlgorithmIdentifier { algorithm_oid, parameters }, used))
}

// ---------------------------------------------------------------------------
// Kani proof harness.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer covers a small but structurally complete
// AlgorithmIdentifier (e.g. a truncated/malformed variant of the 7-byte Ed25519-shaped specimen in
// the tests below). The call chain performs up to three independent `decode_tlv` calls (SEQUENCE
// envelope, OID, optional parameters) plus `validate_oid`'s own bounded loop over the OID content
// (at most `content.len()` iterations) — no call recurses or loops over an unbounded number of
// siblings (this parser reads a fixed two-field schema), so the dominant loop is `validate_oid`'s.
// `#[kani::unwind(20)]` covers a maximal-header `decode_tlv` (~11, per `tlv.rs`) and a full 16-byte
// `validate_oid` walk with margin, matching `x509_spki::parse_never_panics`'s bound; if Kani
// reports an unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_algorithm_identifier` never panics on any input up to 16 octets.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_algorithm_identifier_never_panics() {
        let buf: [u8; 16] = kani::any();
        let _ = parse_algorithm_identifier(&buf);
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A real Ed25519 AlgorithmIdentifier (RFC 8410 §4): exactly one field, no parameters.
    ///
    /// `30 05`                  SEQUENCE, len 5
    ///    `06 03 2b 65 70`      OID 1.3.101.112 (id-Ed25519)
    #[rustfmt::skip]
    const ED25519_ALGID: [u8; 7] = [
        0x30, 0x05,
            0x06, 0x03, 0x2b, 0x65, 0x70,
    ];

    /// A real RSA-shaped AlgorithmIdentifier: OID `rsaEncryption` (1.2.840.113549.1.1.1) with NULL
    /// parameters.
    ///
    /// `30 0d`                                          SEQUENCE, len 13
    ///    `06 09 2a 86 48 86 f7 0d 01 01 01`             OID 1.2.840.113549.1.1.1 (rsaEncryption)
    ///    `05 00`                                        NULL parameters
    #[rustfmt::skip]
    const RSA_ALGID: [u8; 15] = [
        0x30, 0x0d,
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            0x05, 0x00,
    ];

    #[test]
    fn parses_ed25519_one_field_algid() {
        let (algid, used) = parse_algorithm_identifier(&ED25519_ALGID).unwrap();
        assert_eq!(used, 7);
        assert_eq!(algid.algorithm_oid, &[0x2b, 0x65, 0x70]); // 1.3.101.112
        assert_eq!(algid.parameters, None);
    }

    #[test]
    fn parses_rsa_oid_plus_null_params() {
        let (algid, used) = parse_algorithm_identifier(&RSA_ALGID).unwrap();
        assert_eq!(used, 15);
        assert_eq!(algid.algorithm_oid, &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01]);
        assert_eq!(algid.parameters, Some(&[0x05, 0x00][..]));
    }

    #[test]
    fn ignores_trailing_bytes_after_algid_composable() {
        // Composable stance: bytes after this AlgorithmIdentifier are not consumed or checked.
        let mut bytes = ED25519_ALGID.to_vec();
        bytes.push(0xFF);
        let (algid, used) = parse_algorithm_identifier(&bytes).unwrap();
        assert_eq!(used, 7);
        assert_eq!(algid.algorithm_oid, &[0x2b, 0x65, 0x70]);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn rejects_wrong_seq_tag() {
        // Replace the SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = ED25519_ALGID;
        bytes[0] = 0x31;
        assert_eq!(
            parse_algorithm_identifier(&bytes),
            Err(AlgIdError::BadSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_oid_wrong_tag() {
        // The algorithm field is an INTEGER (0x02) instead of an OBJECT IDENTIFIER.
        let mut bytes = ED25519_ALGID;
        bytes[2] = 0x02;
        assert_eq!(parse_algorithm_identifier(&bytes), Err(AlgIdError::OidWrongTag));
    }

    #[test]
    fn rejects_constructed_oid() {
        // OID identifier in the constructed form (0x26) -- forbidden.
        let mut bytes = ED25519_ALGID;
        bytes[2] = 0x26;
        assert_eq!(parse_algorithm_identifier(&bytes), Err(AlgIdError::OidConstructed));
    }

    #[test]
    fn rejects_non_canonical_oid() {
        // A non-minimal OID subidentifier (leading 0x80 group): 06 03 80 65 70.
        let mut bytes = ED25519_ALGID;
        bytes[4] = 0x80;
        assert_eq!(
            parse_algorithm_identifier(&bytes),
            Err(AlgIdError::BadOid(OidError::NonMinimalSubid))
        );
    }

    #[test]
    fn rejects_trailing_elements() {
        // Three fields: OID, then a NULL parameters, then a bogus extra BOOLEAN -- the second
        // field's TLV (NULL, 05 00) tiles exactly, but a third TLV remains. Content is
        // 5 (OID) + 2 (NULL) + 3 (BOOLEAN) = 10 bytes, so the SEQUENCE length is 0x0a.
        // 30 0a 06 03 2b 65 70 05 00 01 01 ff
        let bytes = [
            0x30, 0x0a, // SEQUENCE, len 10
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID
            0x05, 0x00, // NULL parameters
            0x01, 0x01, 0xff, // extra BOOLEAN -- not permitted
        ];
        assert_eq!(parse_algorithm_identifier(&bytes), Err(AlgIdError::TrailingElements));
    }

    #[test]
    fn rejects_malformed_parameters_tlv() {
        // A parameters TLV that declares more content than is present. Content present is
        // 5 (OID) + 2 (partial OCTET STRING header, no value) = 7 bytes, so the SEQUENCE length
        // is 0x07 (its own envelope is well-formed and fully present); the OCTET STRING TLV
        // inside declares 5 value bytes but none are present.
        // 30 07 06 03 2b 65 70 04 05
        let bytes = [0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x05];
        assert_eq!(
            parse_algorithm_identifier(&bytes),
            Err(AlgIdError::BadParametersTlv(TlvError::Truncated))
        );
    }

    #[test]
    fn rejects_truncated_seq_envelope() {
        // Declares 5 content bytes but only 3 are present.
        let bytes = [0x30, 0x05, 0x06, 0x03, 0x2b];
        assert_eq!(
            parse_algorithm_identifier(&bytes),
            Err(AlgIdError::BadSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }
}
