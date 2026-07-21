//! X.509 `SubjectPublicKeyInfo` (RFC 5280 §4.1.2.7) — a bounded, **structural** consumer that
//! composes this crate's verified primitives.
//!
//! ```text
//! SubjectPublicKeyInfo ::= SEQUENCE { algorithm AlgorithmIdentifier, subjectPublicKey BIT STRING }
//! AlgorithmIdentifier  ::= SEQUENCE { algorithm OBJECT IDENTIFIER, parameters ANY OPTIONAL }
//! ```
//!
//! This module is a **demonstration of composition**, not an expansion of the crate's DER-layer
//! scope (see the crate-level docs): it frames the outer SEQUENCE and the BIT STRING using
//! [`crate::sequence`], [`crate::tlv`], and [`crate::bit_string`] verbatim, and delegates the
//! `algorithm` field entirely to [`crate::x509_algorithm_identifier::parse_algorithm_identifier`]
//! — the same AlgorithmIdentifier shape RFC 5280 reuses for `TBSCertificate.signature` and
//! `Certificate.signatureAlgorithm`. It does not hand-roll any tag/length/TLV parsing of its own.
//!
//! **Scope boundaries (deliberate):**
//! - *Structural framing only.* [`parse_subject_public_key_info`] validates that the byte string
//!   is a well-formed, DER-canonical `SubjectPublicKeyInfo` with the exact field tiling the ASN.1
//!   schema requires (algorithm OID, then an optional ANY, then the key BIT STRING — nothing more,
//!   nothing less, at either SEQUENCE level). It does **not** interpret *which* algorithm the OID
//!   names, does not parse the key material inside the BIT STRING, and does not touch any other
//!   X.509 semantics (certificate paths, validity, extensions, signatures).
//! - *`parameters` stays raw.* AlgorithmIdentifier's second field is ASN.1 `ANY` — its DER
//!   encoding (tag + length + value) is returned unparsed and uninterpreted; this module does not
//!   know or care whether it holds an OID (as for EC), is absent (as for Ed25519, RFC 8410 §3), or
//!   is a NULL (as for classic RSA).
//! - *Strict, top-to-bottom.* The outer SEQUENCE must consume the entire input (no trailing bytes
//!   after the whole SPKI); the AlgorithmIdentifier's two fields must exactly tile its content; the
//!   two top-level fields (algorithm identifier + public key) must exactly tile the outer content.
//!   Every level rejects trailing bytes — the classic parser-differential vector this crate's other
//!   modules guard against (`decode_tlv_strict` / `decode_sequence_tlv_strict`).

use crate::bit_string::{decode_bit_string, BitString, BitStringError};
use crate::bit_string::TAG as BIT_STRING_TAG;
use crate::oid::OidError;
use crate::sequence::{decode_sequence_tlv_strict, SequenceError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};
use crate::x509_algorithm_identifier::{parse_algorithm_identifier, AlgIdError, AlgorithmIdentifier};

/// A structurally-parsed `SubjectPublicKeyInfo`, borrowing from the input it was parsed from.
///
/// See the module docs for the scope of what "parsed" means here: framing only, no algorithm- or
/// key-material interpretation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct SubjectPublicKeyInfo<'a> {
    /// `algorithm.algorithm`: the canonically-validated OBJECT IDENTIFIER **content** octets (not
    /// the TLV header) — see [`crate::oid::validate_oid`]. This module does not decode which arcs
    /// the OID names; a caller that needs that materializes/compares the arcs itself.
    pub algorithm_oid: &'a [u8],
    /// `algorithm.parameters` (`ANY OPTIONAL`): the raw DER encoding of the parameters TLV — its
    /// own tag, length, and value octets, verbatim — when the AlgorithmIdentifier has a second
    /// field. `None` when it does not (e.g. Ed25519's AlgorithmIdentifier per RFC 8410 §3, which is
    /// exactly one field). Completely uninterpreted: this module does not know what type the `ANY`
    /// holds.
    pub parameters: Option<&'a [u8]>,
    /// `subjectPublicKey`: the BIT STRING decoded to its value octets + unused-bit count (the key
    /// material itself is opaque bytes — this module does not parse it).
    pub subject_public_key: BitString<'a>,
}

/// Why a `SubjectPublicKeyInfo` was rejected. Every variant names a specific structural cause,
/// wrapping the underlying primitive's error where one exists (mirrors [`SequenceError`]'s
/// `Tlv`/`Element` wrapping style).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SpkiError {
    /// The outer `SubjectPublicKeyInfo` SEQUENCE envelope was malformed: bad identifier/length,
    /// the primitive (non-constructed) form, or trailing bytes after the whole structure (this is
    /// a top-level object, decoded with [`decode_sequence_tlv_strict`]).
    BadOuterSeq(SequenceError),
    /// The `algorithm` (AlgorithmIdentifier) SEQUENCE envelope — the outer SEQUENCE's first child
    /// — was malformed.
    BadAlgorithmId(SequenceError),
    /// The `algorithm.algorithm` OID's TLV framing (tag/length octets) was malformed.
    BadOidTlv(TlvError),
    /// The `algorithm.algorithm` field's identifier was well-framed but not UNIVERSAL 6 (OBJECT
    /// IDENTIFIER).
    OidWrongTag,
    /// The `algorithm.algorithm` field's identifier was UNIVERSAL 6 but in the constructed form —
    /// OBJECT IDENTIFIER content is always primitive.
    OidConstructed,
    /// The `algorithm.algorithm` OID's content failed canonical-DER validation.
    BadOid(OidError),
    /// The optional `algorithm.parameters` TLV's framing (tag/length octets) was malformed.
    BadParametersTlv(TlvError),
    /// The AlgorithmIdentifier SEQUENCE has more than its two permitted fields (algorithm,
    /// parameters): bytes remain in its content after the parameters TLV.
    AlgorithmTrailingElements,
    /// No `subjectPublicKey` BIT STRING is present after the AlgorithmIdentifier (the outer
    /// SEQUENCE's content ended after its first child).
    MissingPublicKey,
    /// The `subjectPublicKey` TLV's framing (tag/length octets) was malformed.
    BadPublicKeyTlv(TlvError),
    /// The `subjectPublicKey` field's identifier was well-framed but not UNIVERSAL 3 (BIT STRING).
    PublicKeyWrongTag,
    /// The `subjectPublicKey` field's identifier was UNIVERSAL 3 but in the constructed (BER
    /// segmented) form — forbidden in DER.
    PublicKeyConstructed,
    /// The `subjectPublicKey` BIT STRING's content failed canonical-DER validation.
    BadPublicKey(BitStringError),
    /// Bytes remain in the outer SEQUENCE's content after its two fields (algorithm identifier +
    /// public key) were consumed — more than the two permitted top-level fields.
    TrailingBytes,
}

/// Map an [`AlgIdError`] (from [`parse_algorithm_identifier`]) onto the equivalent [`SpkiError`]
/// variant, preserving the exact underlying-error payload so every pre-existing SPKI test's
/// expected error value is unchanged by the delegation.
fn map_algid_error(e: AlgIdError) -> SpkiError {
    match e {
        AlgIdError::BadSeq(e) => SpkiError::BadAlgorithmId(e),
        AlgIdError::BadOidTlv(e) => SpkiError::BadOidTlv(e),
        AlgIdError::OidWrongTag => SpkiError::OidWrongTag,
        AlgIdError::OidConstructed => SpkiError::OidConstructed,
        AlgIdError::BadOid(e) => SpkiError::BadOid(e),
        AlgIdError::BadParametersTlv(e) => SpkiError::BadParametersTlv(e),
        AlgIdError::TrailingElements => SpkiError::AlgorithmTrailingElements,
    }
}

/// Decode the `subjectPublicKey` BIT STRING TLV from the front of `input`, returning the decoded
/// [`BitString`] and the bytes consumed. Composes [`decode_tlv`] + [`decode_bit_string`].
fn decode_public_key_tlv(input: &[u8]) -> Result<(BitString<'_>, usize), SpkiError> {
    let (tlv, used) = decode_tlv(input).map_err(SpkiError::BadPublicKeyTlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != BIT_STRING_TAG {
        return Err(SpkiError::PublicKeyWrongTag);
    }
    if tlv.tag.constructed {
        return Err(SpkiError::PublicKeyConstructed);
    }
    let bs = decode_bit_string(tlv.value).map_err(SpkiError::BadPublicKey)?;
    Ok((bs, used))
}

/// Parse a complete DER `SubjectPublicKeyInfo` from `input`.
///
/// **Strict, top level**: `input` must be *exactly* one SPKI — no trailing bytes are tolerated at
/// any level (outer SEQUENCE, AlgorithmIdentifier SEQUENCE, or the top-level field tiling).
///
/// Decodes, in order:
/// 1. the outer SEQUENCE envelope ([`decode_sequence_tlv_strict`]);
/// 2. the `algorithm` AlgorithmIdentifier, delegated whole to
///    [`crate::x509_algorithm_identifier::parse_algorithm_identifier`] (its own SEQUENCE envelope,
///    the OID, and the optional `ANY` parameters, exact-tiled);
/// 3. back at the outer level, the `subjectPublicKey` BIT STRING ([`decode_tlv`] +
///    [`decode_bit_string`]), requiring it to exactly fill what remains of the outer content.
///
/// Never panics on any input (proven by the `parse_never_panics` Kani harness below); returns a
/// classified [`SpkiError`] on any structural deviation.
pub fn parse_subject_public_key_info(input: &[u8]) -> Result<SubjectPublicKeyInfo<'_>, SpkiError> {
    // 1. Outer SEQUENCE: must consume the whole input (top-level anti-trailing-data).
    let outer_content = decode_sequence_tlv_strict(input).map_err(SpkiError::BadOuterSeq)?;

    // 2. First child: the AlgorithmIdentifier (delegated to `x509_algorithm_identifier`, which
    //    handles both the SEQUENCE envelope and the OID + optional ANY parameters tiling).
    let (algo_id, algo_used) =
        parse_algorithm_identifier(outer_content).map_err(map_algid_error)?;
    let AlgorithmIdentifier { algorithm_oid, parameters } = algo_id;

    // 3. Second (and last) child of the outer SEQUENCE: subjectPublicKey.
    let outer_rest = &outer_content[algo_used..];
    if outer_rest.is_empty() {
        return Err(SpkiError::MissingPublicKey);
    }
    let (subject_public_key, pk_used) = decode_public_key_tlv(outer_rest)?;
    if pk_used != outer_rest.len() {
        return Err(SpkiError::TrailingBytes);
    }

    Ok(SubjectPublicKeyInfo { algorithm_oid, parameters, subject_public_key })
}

// ---------------------------------------------------------------------------
// Kani proof harness.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer covers a small but structurally complete SPKI
// (e.g. a truncated/malformed variant of the 12-byte Ed25519-shaped prefix in the tests below).
// The call chain performs up to five independent `decode_tlv` calls (outer SEQUENCE, algorithm
// SEQUENCE, OID, optional parameters, BIT STRING) plus `validate_oid`'s own bounded loop over the
// OID content (at most `content.len()` iterations) — no call recurses or loops over an unbounded
// number of *siblings* (unlike `sequence::Elements`, this parser reads a fixed schema, not an
// arbitrary child count), so the dominant loop is `validate_oid`'s. `#[kani::unwind(20)]` covers a
// maximal-header `decode_tlv` (~11, per `tlv.rs`) and a full 16-byte `validate_oid` walk with
// margin; if Kani reports an unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_subject_public_key_info` never panics on any input up to 16 octets.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached for a genuine, fully-tiled SPKI
    /// (outer SEQUENCE strict, delegated AlgorithmIdentifier, then the subjectPublicKey BIT
    /// STRING all decode and exactly tile) -- not merely that malformed 16-byte inputs are
    /// rejected. Would NOT be SAT if `parse_subject_public_key_info`'s body were a no-op always
    /// returning `Err`.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_never_panics() {
        let buf: [u8; 16] = kani::any();
        let result = parse_subject_public_key_info(&buf);
        kani::cover(result.is_ok(), "a well-formed SubjectPublicKeyInfo reaches the Ok tail");
        let _ = result;
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A real Ed25519 `SubjectPublicKeyInfo` (RFC 8410 §4): AlgorithmIdentifier is exactly one
    /// field (OID `1.3.101.112`, `id-Ed25519`, no parameters — RFC 8410 §3 mandates their
    /// absence), followed by a 32-byte raw public key wrapped in a BIT STRING.
    ///
    /// `30 2a`                            SEQUENCE, len 42
    ///    `30 05`                         SEQUENCE (AlgorithmIdentifier), len 5
    ///       `06 03 2b 65 70`             OID 1.3.101.112 (id-Ed25519)
    ///    `03 21 00 <32 bytes>`           BIT STRING, len 33 (0 unused, 32-byte key)
    #[rustfmt::skip]
    const ED25519_SPKI: [u8; 44] = [
        0x30, 0x2a,
            0x30, 0x05,
                0x06, 0x03, 0x2b, 0x65, 0x70,
            0x03, 0x21, 0x00,
                0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
                0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
                0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18,
                0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
    ];

    /// A real P-256 (`prime256v1`) EC `SubjectPublicKeyInfo` shape: AlgorithmIdentifier is
    /// `id-ecPublicKey` (1.2.840.10045.2.1) with `parameters` = the `prime256v1` curve OID
    /// (1.2.840.10045.3.1.7) — the standard, widely-deployed 91-byte P-256 SPKI encoding. The
    /// key point (an uncompressed EC point `04 || X || Y`) uses a placeholder 65-byte payload:
    /// this module never validates curve membership (out of scope), so any bytes structurally
    /// exercise the same framing a real point would.
    ///
    /// `30 59`                                        SEQUENCE, len 89
    ///    `30 13`                                      SEQUENCE (AlgorithmIdentifier), len 19
    ///       `06 07 2a 86 48 ce 3d 02 01`               OID 1.2.840.10045.2.1 (id-ecPublicKey)
    ///       `06 08 2a 86 48 ce 3d 03 01 07`            OID 1.2.840.10045.3.1.7 (prime256v1)
    ///    `03 42 00 04 <64 bytes X||Y>`                 BIT STRING, len 66 (0 unused, 65-byte point)
    #[rustfmt::skip]
    const P256_SPKI: [u8; 91] = [
        0x30, 0x59,
            0x30, 0x13,
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01,
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0x03, 0x42, 0x00,
                0x04,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
                0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb, 0xbb,
    ];

    #[test]
    fn parses_ed25519_spki() {
        let spki = parse_subject_public_key_info(&ED25519_SPKI).unwrap();
        assert_eq!(spki.algorithm_oid, &[0x2b, 0x65, 0x70]); // 1.3.101.112
        assert_eq!(spki.parameters, None); // RFC 8410 §3: no parameters
        assert_eq!(spki.subject_public_key.unused, 0);
        assert_eq!(spki.subject_public_key.data.len(), 32);
        assert_eq!(spki.subject_public_key.data[0], 0x01);
        assert_eq!(spki.subject_public_key.data[31], 0x20);
    }

    #[test]
    fn parses_p256_spki_with_parameters() {
        let spki = parse_subject_public_key_info(&P256_SPKI).unwrap();
        assert_eq!(spki.algorithm_oid, &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01]); // id-ecPublicKey
        // parameters carries the raw prime256v1 OID TLV, uninterpreted.
        assert_eq!(
            spki.parameters,
            Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07][..])
        );
        assert_eq!(spki.subject_public_key.unused, 0);
        assert_eq!(spki.subject_public_key.data.len(), 65);
        assert_eq!(spki.subject_public_key.data[0], 0x04); // uncompressed point marker
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn rejects_trailing_byte_after_spki() {
        let mut bytes = ED25519_SPKI.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            parse_subject_public_key_info(&bytes),
            Err(SpkiError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[0] = 0x31;
        assert_eq!(
            parse_subject_public_key_info(&bytes),
            Err(SpkiError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_truncated_input() {
        // Drop the last 10 bytes: the outer SEQUENCE declares more content than is present.
        let bytes = &ED25519_SPKI[..ED25519_SPKI.len() - 10];
        assert_eq!(
            parse_subject_public_key_info(bytes),
            Err(SpkiError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_missing_public_key() {
        // An outer SEQUENCE containing only the AlgorithmIdentifier child, nothing after it:
        // 30 07 30 05 06 03 2b 65 70  (SEQUENCE { AlgorithmIdentifier }, no BIT STRING)
        let bytes = [0x30, 0x07, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70];
        assert_eq!(parse_subject_public_key_info(&bytes), Err(SpkiError::MissingPublicKey));
    }

    #[test]
    fn rejects_non_canonical_outer_length() {
        // The outer length re-encoded in the long form (0x81 0x2a) where the short form (0x2a)
        // is required — non-minimal, forbidden by DER.
        let mut bytes = vec![0x30, 0x81, 0x2a];
        bytes.extend_from_slice(&ED25519_SPKI[2..]);
        use crate::length::LengthError;
        assert_eq!(
            parse_subject_public_key_info(&bytes),
            Err(SpkiError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_algorithm_identifier_wrong_tag() {
        // The AlgorithmIdentifier child is a SET (0x31) instead of a SEQUENCE.
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[2] = 0x31;
        assert_eq!(
            parse_subject_public_key_info(&bytes),
            Err(SpkiError::BadAlgorithmId(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_oid_wrong_tag() {
        // The algorithm field is an INTEGER (0x02) instead of an OBJECT IDENTIFIER.
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[4] = 0x02;
        assert_eq!(parse_subject_public_key_info(&bytes), Err(SpkiError::OidWrongTag));
    }

    #[test]
    fn rejects_non_canonical_oid() {
        // A non-minimal OID subidentifier (leading 0x80 group): 06 03 80 65 70.
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[6] = 0x80;
        assert_eq!(
            parse_subject_public_key_info(&bytes),
            Err(SpkiError::BadOid(OidError::NonMinimalSubid))
        );
    }

    #[test]
    fn rejects_bit_string_wrong_tag() {
        // subjectPublicKey uses OCTET STRING (0x04) instead of BIT STRING (0x03).
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[9] = 0x04;
        assert_eq!(parse_subject_public_key_info(&bytes), Err(SpkiError::PublicKeyWrongTag));
    }

    #[test]
    fn rejects_bit_string_nonzero_padding() {
        // Build a minimal SPKI whose BIT STRING has 4 unused bits with a non-zero padding nibble:
        // 30 0b 30 05 06 03 2b 65 70 03 02 04 f1 -- low nibble of 0xf1 is 0x1, set under a 4-bit mask.
        let bytes = [
            0x30, 0x0b, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x02, 0x04, 0xf1,
        ];
        assert_eq!(
            parse_subject_public_key_info(&bytes),
            Err(SpkiError::BadPublicKey(BitStringError::NonZeroPadding))
        );
    }

    #[test]
    fn rejects_algorithm_trailing_elements() {
        // AlgorithmIdentifier with three fields: OID, then a NULL parameters, then a bogus extra
        // BOOLEAN — the second field's TLV (NULL, 05 00) tiles exactly, but a third TLV remains.
        // 30 10 30 0a 06 03 2b 65 70 05 00 01 01 ff  ...continuing with a BIT STRING
        let mut bytes = vec![
            0x30, 0x10, // outer SEQUENCE, len 16
            0x30, 0x0a, // AlgorithmIdentifier SEQUENCE, len 10
            0x06, 0x03, 0x2b, 0x65, 0x70, // OID
            0x05, 0x00, // NULL parameters
            0x01, 0x01, 0xff, // extra BOOLEAN -- not permitted, AlgorithmIdentifier has only 2 fields
        ];
        bytes.extend_from_slice(&[0x03, 0x02, 0x00, 0xaa]); // a trailing BIT STRING (irrelevant; rejected earlier)
        assert_eq!(
            parse_subject_public_key_info(&bytes),
            Err(SpkiError::AlgorithmTrailingElements)
        );
    }

    #[test]
    fn accepts_null_parameters_as_raw_bytes() {
        // RSA-shaped AlgorithmIdentifier: OID + NULL parameters (the classic rsaEncryption shape).
        // 30 0d 30 07 06 03 2b 65 70 05 00 03 02 00 aa
        let bytes = [
            0x30, 0x0d, 0x30, 0x07, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x05, 0x00, 0x03, 0x02, 0x00,
            0xaa,
        ];
        let spki = parse_subject_public_key_info(&bytes).unwrap();
        assert_eq!(spki.parameters, Some(&[0x05, 0x00][..])); // raw NULL TLV, uninterpreted
    }

    // --- coverage completeness (review spki-01): exercise the three error paths the code handles
    //     but the suite above did not reach — TrailingBytes, OidConstructed, PublicKeyConstructed. ---

    #[test]
    fn rejects_trailing_bytes_inside_outer_sequence() {
        // Distinct from `rejects_trailing_byte_after_spki` (which trips `decode_sequence_tlv_strict`
        // on data *after* the whole SPKI): here the junk byte is *inside* the outer SEQUENCE content,
        // so the two top-level fields tile 42 of 43 content bytes and one remains → TrailingBytes.
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[1] = 0x2b; // outer content length 42 → 43
        bytes.push(0xAA); // the extra content octet
        assert_eq!(parse_subject_public_key_info(&bytes), Err(SpkiError::TrailingBytes));
    }

    #[test]
    fn rejects_constructed_oid() {
        // OID identifier in the constructed form (0x26) — forbidden; OID content is always primitive.
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[4] = 0x26;
        assert_eq!(parse_subject_public_key_info(&bytes), Err(SpkiError::OidConstructed));
    }

    #[test]
    fn rejects_constructed_public_key() {
        // subjectPublicKey BIT STRING in the constructed (BER segmented) form (0x23) — forbidden in DER.
        let mut bytes = ED25519_SPKI.to_vec();
        bytes[9] = 0x23;
        assert_eq!(parse_subject_public_key_info(&bytes), Err(SpkiError::PublicKeyConstructed));
    }
}
