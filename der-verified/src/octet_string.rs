//! DER OCTET STRING (X.690 §8.7, §10.2).
//!
//! An OCTET STRING is UNIVERSAL tag 4. Its content is an arbitrary sequence of octets — there is
//! **no content-level canonical form** (any byte string is a valid value), so unlike the
//! content-canonical primitives ([`crate::boolean`], [`crate::integer`], [`crate::null`]) this
//! module has nothing to check *inside* the value. Its sole DER constraint is **structural**: DER
//! requires the *primitive*, definite-length form (§10.2). BER additionally allows a *constructed*
//! OCTET STRING carrying the value as a sequence of nested segments — a well-known parser-
//! differential vector (a lax reader reassembles segments a strict signer never produced). We
//! reject it. Because that constraint lives in the identifier octet, this module operates at the
//! TLV level (composing [`crate::tlv`]) rather than on pre-stripped content octets.
//!
//! The security-critical property is inherited from the TLV reader: an accepted OCTET STRING
//! never exposes bytes beyond the input (**no over-read**).

use crate::tag::{Class, Tag};
use crate::tlv::{decode_tlv, encode_tlv_into, TlvError};

/// The universal tag number for OCTET STRING.
pub const TAG: u32 = 4;

/// Why an OCTET STRING was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OctetStringError {
    /// The TLV envelope was malformed (bad identifier/length, indefinite length, over-read, …).
    Tlv(TlvError),
    /// The identifier is well formed but is not UNIVERSAL 4.
    WrongTag,
    /// UNIVERSAL 4 but in the *constructed* (BER segmented) form — forbidden in DER (§10.2).
    Constructed,
}

/// Decode a complete DER OCTET STRING from the front of `input`, returning the content octets and
/// the total number of bytes consumed (`tag + length + value`).
///
/// Enforces UNIVERSAL 4, **primitive** form (the constructed/segmented form is BER-only), definite
/// length, and — via the TLV reader — no over-read. The content octets are returned unchanged;
/// there is no content-level validation to perform.
///
/// Tag-identity is checked before primitiveness, so a non-OCTET-STRING constructed type (e.g.
/// SEQUENCE `0x30`) is `WrongTag`, not `Constructed`. Trailing bytes after the OCTET STRING are
/// ignored (as in [`decode_tlv`]) so this composes inside constructed types; a top-level caller
/// that must consume the whole input should check the returned length against `input.len()`.
pub fn decode_octet_string(input: &[u8]) -> Result<(&[u8], usize), OctetStringError> {
    let (tlv, used) = decode_tlv(input).map_err(OctetStringError::Tlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != TAG {
        return Err(OctetStringError::WrongTag);
    }
    if tlv.tag.constructed {
        return Err(OctetStringError::Constructed);
    }
    Ok((tlv.value, used))
}

/// Encode `content` as a canonical DER OCTET STRING (UNIVERSAL 4, primitive) into `out`.
///
/// Returns the number of bytes written, or `None` if `out` is too small or `content` is longer
/// than the length codec supports (`> u32::MAX`). Delegates the envelope to [`encode_tlv_into`].
pub fn encode_octet_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    let tag = Tag { class: Class::Universal, constructed: false, number: TAG };
    encode_tlv_into(tag, content, out)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Round-trip: any short content encodes to an OCTET STRING that decodes back to exactly it,
    /// consuming exactly the produced bytes. Length 0..=3 is covered by the symbolic content.
    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip_small() {
        let content: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        let mut out = [0u8; 16]; // 1 (tag) + 1 (len) + 3 (value) = 5 fits
        let written = encode_octet_string_into(&content[..n], &mut out).unwrap();
        let (dec, used) = decode_octet_string(&out[..written]).unwrap();
        assert!(used == written);
        assert!(dec == &content[..n]);
    }

    /// Robustness: `decode_octet_string` never panics or overflows on *any* input.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached with a genuine non-empty value
    /// (the TLV envelope, tag check, and constructed-flag check all pass on real content), not
    /// merely that malformed inputs are rejected. Would NOT be SAT if `decode_octet_string`'s body
    /// were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_never_panics() {
        let buf: [u8; 16] = kani::any();
        let result = decode_octet_string(&buf);
        kani::cover(result.is_ok(), "a well-formed OCTET STRING reaches decode_octet_string's Ok tail");
        if let Ok((content, _used)) = result {
            kani::cover(!content.is_empty(), "a non-empty OCTET STRING value is accepted");
        }
        let _ = result;
    }

    /// Structure + **no over-read**: an accepted OCTET STRING consumes no more than the input and
    /// returns exactly the underlying TLV's value borrow (nothing added, nothing beyond bounds).
    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_content_is_the_tlv_value() {
        let buf: [u8; 16] = kani::any();
        if let Ok((dec, used)) = decode_octet_string(&buf) {
            let (tlv, tused) = decode_tlv(&buf).unwrap();
            assert!(used == tused);
            assert!(used <= buf.len());
            assert!(dec.len() == tlv.value.len());
            assert!(dec == tlv.value);
        }
    }

    /// Canonicality / anti-differential: the *constructed* form of UNIVERSAL 4 (identifier `0x24`)
    /// — BER's segmented OCTET STRING — is rejected as `Constructed` for *any* well-formed body.
    #[kani::proof]
    #[kani::unwind(16)]
    fn constructed_form_is_rejected() {
        // 0x24 = class 00 (Universal), bit6 set (constructed), number 4. A 1-octet definite body.
        let a: u8 = kani::any();
        assert!(decode_octet_string(&[0x24, 0x01, a]) == Err(OctetStringError::Constructed));
    }

    /// Error-class: a well-formed TLV whose tag is not OCTET STRING is `WrongTag`. Exercised with
    /// the low-tag identifier space (single identifier octet, definite short length, 1 value byte);
    /// the UNIVERSAL-4 primitive identifier `0x04` is the sole accepted case.
    #[kani::proof]
    #[kani::unwind(16)]
    fn non_octet_string_tag_is_wrong_tag() {
        let id: u8 = kani::any();
        kani::assume(id & 0x1F != 0x1F); // low-tag form (number 0..=30), so the identifier is 1 octet
        kani::assume(id != 0x04); // 0x04 is the OCTET STRING identifier itself (accepted)
        kani::assume(id != 0x24); // 0x24 is UNIVERSAL-4 constructed (rejected as Constructed, not WrongTag)
        let v: u8 = kani::any();
        assert!(decode_octet_string(&[id, 0x01, v]) == Err(OctetStringError::WrongTag));
    }

    /// Identifier canonicality, machine-checked end-to-end (closes the reviewers' convergent
    /// "non-canonical tag accepted" finding): over *all* inputs, an accepted OCTET STRING begins
    /// with **exactly** the single canonical identifier octet `0x04`. This rules out the high-tag
    /// form of tag 4 (`0x1F 0x04 …`, which the tag codec rejects as non-minimal), the constructed
    /// form (`0x24`), and any wrong class/number — so no non-canonical identifier is ever admitted,
    /// without the reader having to trust the delegation to `decode_tlv` by inspection.
    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical_0x04() {
        let buf: [u8; 16] = kani::any();
        if decode_octet_string(&buf).is_ok() {
            assert!(buf[0] == 0x04);
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_simple() {
        // 04 03 01 02 03  =  OCTET STRING { 01 02 03 }
        let (content, used) = decode_octet_string(&[0x04, 0x03, 0x01, 0x02, 0x03]).unwrap();
        assert_eq!(used, 5);
        assert_eq!(content, &[0x01, 0x02, 0x03]);
    }

    #[test]
    fn decodes_empty() {
        // 04 00  =  OCTET STRING { } (a valid, common encoding)
        let (content, used) = decode_octet_string(&[0x04, 0x00]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(content, &[] as &[u8]);
    }

    #[test]
    fn ignores_trailing_bytes() {
        // one OCTET STRING followed by extra bytes: only the first object is consumed
        let (content, used) = decode_octet_string(&[0x04, 0x01, 0xAA, 0xFF, 0xFF]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(content, &[0xAA]);
    }

    #[test]
    fn roundtrips_via_encode() {
        let content = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut out = [0u8; 32];
        let n = encode_octet_string_into(&content, &mut out).unwrap();
        assert_eq!(&out[..2], &[0x04, 0x04]); // tag 0x04, length 4
        let (dec, used) = decode_octet_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, &content);
    }

    // --- seeded-bad specimens: each MUST be rejected ---
    #[test]
    fn rejects_constructed_form() {
        // 0x24 = constructed OCTET STRING (BER segmented). DER forbids it (§10.2); a lax parser
        // that reassembles segments is the classic parser differential.
        assert_eq!(
            decode_octet_string(&[0x24, 0x03, 0x01, 0x02, 0x03]),
            Err(OctetStringError::Constructed)
        );
    }
    #[test]
    fn rejects_wrong_tag() {
        // 0x02 = INTEGER, not OCTET STRING.
        assert_eq!(decode_octet_string(&[0x02, 0x01, 0x07]), Err(OctetStringError::WrongTag));
    }
    #[test]
    fn rejects_sequence_tag_as_wrong_not_constructed() {
        // 0x30 = SEQUENCE (constructed, number 16): tag-identity is checked first, so this is
        // WrongTag, not Constructed.
        assert_eq!(decode_octet_string(&[0x30, 0x00]), Err(OctetStringError::WrongTag));
    }
    #[test]
    fn rejects_truncated_value() {
        // declares 5 content octets, only 1 present -> the TLV reader rejects Truncated
        assert_eq!(
            decode_octet_string(&[0x04, 0x05, 0xAA]),
            Err(OctetStringError::Tlv(TlvError::Truncated))
        );
    }
    #[test]
    fn rejects_indefinite_length() {
        // 0x80 length = indefinite (BER streaming form) -> rejected by the length codec
        use crate::length::LengthError;
        assert_eq!(
            decode_octet_string(&[0x04, 0x80, 0x00, 0x00]),
            Err(OctetStringError::Tlv(TlvError::Length(LengthError::Indefinite)))
        );
    }

    // --- canonicality inherited from the tag/length codecs (convergent review findings) ---
    #[test]
    fn rejects_high_tag_form_of_tag_4() {
        // 1F 04 = the high-tag (multi-octet) encoding of tag number 4. DER requires the low-tag
        // single-octet form 0x04 for numbers <= 30, so the tag codec rejects it as non-minimal:
        // a non-canonical OCTET STRING identifier is never accepted.
        use crate::tag::TagError;
        assert_eq!(
            decode_octet_string(&[0x1F, 0x04, 0x01, 0xAA]),
            Err(OctetStringError::Tlv(TlvError::Tag(TagError::NonMinimal)))
        );
    }
    #[test]
    fn rejects_non_minimal_length() {
        // 04 81 01 AA = length 1 in the long form; DER requires the short form (04 01 AA). The
        // length codec rejects the non-minimal length.
        use crate::length::LengthError;
        assert_eq!(
            decode_octet_string(&[0x04, 0x81, 0x01, 0xAA]),
            Err(OctetStringError::Tlv(TlvError::Length(LengthError::NonMinimal)))
        );
    }
    #[test]
    fn roundtrips_long_form_length() {
        // A 128-byte OCTET STRING needs the long-form length (0x81 0x80): exercises the >127-byte
        // length path the small-content proofs do not reach.
        let content = [0x5Au8; 128];
        let mut out = [0u8; 160];
        let n = encode_octet_string_into(&content, &mut out).unwrap();
        assert_eq!(&out[..3], &[0x04, 0x81, 0x80]); // tag, long-form marker (1 length octet), 128
        let (dec, used) = decode_octet_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, &content[..]);
    }
}
