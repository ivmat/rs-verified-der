//! DER INTEGER content (X.690 §8.3, §11.x) as `i64`.
//!
//! Content is a two's-complement, big-endian, **minimal** encoding: at least one octet, and (per
//! §8.3.2) the leading octet and bit 8 of the second must not be all-zero (redundant positive
//! padding) nor all-one (redundant negative padding). These functions operate on the content
//! octets of a TLV whose tag is UNIVERSAL 2 (`0x02`).
//!
//! **Range:** values fitting `i64` (≤ 8 content octets). A minimal integer needing more octets is
//! rejected as `TooLarge` — a documented deviation from full DER (arbitrary-precision), safe for
//! the small integers in X.509 (versions, key sizes, small serials). Large serial numbers need a
//! big-integer type (a later addition); this is the `i64` core.
//!
//! # Examples
//!
//! ```
//! use der_verified::integer::{decode_integer, encode_integer};
//!
//! // 128 needs a leading 0x00 to stay positive (0x80 alone would decode as -128).
//! let (buf, n) = encode_integer(128);
//! assert_eq!(&buf[..n], &[0x00, 0x80]);
//! assert_eq!(decode_integer(&buf[..n]), Ok(128));
//!
//! // Redundant padding is rejected: 0x00 0x01 is a non-minimal encoding of 1.
//! assert!(decode_integer(&[0x00, 0x01]).is_err());
//! ```

/// The universal tag number for INTEGER.
pub const TAG: u32 = 2;

/// Why INTEGER content was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IntError {
    /// Content was empty (an INTEGER needs at least one octet).
    Empty,
    /// Redundant leading `0x00`/`0xFF` padding — forbidden by DER's minimal encoding (§8.3.2).
    NonMinimal,
    /// The value needs more than 8 octets and does not fit `i64` (see the module docs).
    TooLarge,
}

/// Encode `v` as minimal two's-complement DER content. Returns a fixed 8-byte buffer and the
/// number of octets used (`1..=8`).
pub fn encode_integer(v: i64) -> ([u8; 8], usize) {
    let be = v.to_be_bytes(); // 8 octets, two's-complement big-endian
    let mut start = 0usize;
    if v >= 0 {
        // strip redundant leading 0x00 while the sign stays positive (next octet's bit 8 == 0)
        while start < 7 && be[start] == 0x00 && (be[start + 1] & 0x80) == 0 {
            start += 1;
        }
    } else {
        // strip redundant leading 0xFF while the sign stays negative (next octet's bit 8 == 1)
        while start < 7 && be[start] == 0xFF && (be[start + 1] & 0x80) != 0 {
            start += 1;
        }
    }
    let n = 8 - start;
    let mut out = [0u8; 8];
    let mut i = 0;
    while i < n {
        out[i] = be[start + i];
        i += 1;
    }
    (out, n)
}

/// Decode minimal two's-complement DER INTEGER content into an `i64`.
pub fn decode_integer(content: &[u8]) -> Result<i64, IntError> {
    if content.is_empty() {
        return Err(IntError::Empty);
    }
    if content.len() >= 2 {
        let c0 = content[0];
        let c1 = content[1];
        if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
            return Err(IntError::NonMinimal);
        }
    }
    if content.len() > 8 {
        return Err(IntError::TooLarge);
    }
    // Two's-complement via a u64 accumulator seeded with the sign, then reinterpreted.
    let neg = (content[0] & 0x80) != 0;
    let mut acc: u64 = if neg { u64::MAX } else { 0 };
    let mut i = 0;
    while i < content.len() {
        // EQUIVALENT-MUTANT: disjoint bitfields, |≡^ (cargo-mutants survivor, not a coverage
        // gap) — `acc << 8` always has its low 8 bits zero, and `content[i]` fits in 8 bits.
        acc = (acc << 8) | content[i] as u64;
        i += 1;
    }
    Ok(acc as i64)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Round-trip: every `i64` encodes to minimal content that decodes back to it.
    #[kani::proof]
    #[kani::unwind(12)]
    fn roundtrip_all_i64() {
        let v: i64 = kani::any();
        let (buf, n) = encode_integer(v);
        assert!(decode_integer(&buf[..n]) == Ok(v));
    }

    /// Robustness: `decode_integer` never panics/overflows on any content up to 10 octets.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached for a genuine multi-octet minimal
    /// integer (not just the trivial single-octet case), so the accumulator loop actually iterates
    /// more than once. Would NOT be SAT if `decode_integer`'s body were a no-op always returning
    /// `Err`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_never_panics() {
        let buf: [u8; 10] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 10);
        let result = decode_integer(&buf[..n]);
        kani::cover(result.is_ok(), "a minimal INTEGER encoding reaches decode_integer's Ok tail");
        kani::cover(result.is_ok() && n >= 2, "a genuine multi-octet minimal INTEGER is decoded (accumulator loop runs >1 iteration)");
        let _ = result;
    }

    /// Canonicality: any accepted content is exactly the minimal encoding of its value. The
    /// buffer spans the full i64 width (8 octets) so the property holds for every valid length,
    /// not just short ones (the review's bound-too-small fix).
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_accepts_only_minimal() {
        let buf: [u8; 8] = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 8);
        if let Ok(v) = decode_integer(&buf[..n]) {
            let (re, relen) = encode_integer(v);
            assert!(relen == n);
            assert!(re[..relen] == buf[..n]);
        }
    }

    /// Empty content is `Empty`.
    #[kani::proof]
    fn empty_is_classified() {
        assert!(decode_integer(&[]) == Err(IntError::Empty));
    }

    /// Redundant leading `0x00` (positive padding) is `NonMinimal`.
    #[kani::proof]
    fn redundant_positive_padding_is_non_minimal() {
        let c: u8 = kani::any();
        kani::assume(c & 0x80 == 0); // next octet keeps the value positive -> the 0x00 is redundant
        assert!(decode_integer(&[0x00, c]) == Err(IntError::NonMinimal));
    }

    /// Redundant leading `0xFF` (negative padding) is `NonMinimal`.
    #[kani::proof]
    fn redundant_negative_padding_is_non_minimal() {
        let c: u8 = kani::any();
        kani::assume(c & 0x80 != 0); // next octet keeps the value negative -> the 0xFF is redundant
        assert!(decode_integer(&[0xFF, c]) == Err(IntError::NonMinimal));
    }

    /// A minimal 9-octet integer exceeds `i64` and is `TooLarge`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn nine_octets_is_too_large() {
        let b: [u8; 8] = kani::any();
        // c0 = 0x01 is neither 0x00 nor 0xFF, so it passes minimality; 9 octets > 8 => TooLarge.
        let content = [0x01, b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]];
        assert!(decode_integer(&content) == Err(IntError::TooLarge));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn small_values_roundtrip() {
        for v in [0i64, 1, -1, 127, 128, -128, -129, 255, 256, i64::MAX, i64::MIN] {
            let (buf, n) = encode_integer(v);
            assert_eq!(decode_integer(&buf[..n]), Ok(v), "value {v}");
        }
    }

    #[test]
    fn canonical_encodings() {
        assert_eq!(encode_integer(0), ([0x00, 0, 0, 0, 0, 0, 0, 0], 1));
        assert_eq!(&encode_integer(127).0[..1], &[0x7F]);
        assert_eq!(&encode_integer(128).0[..2], &[0x00, 0x80]); // leading 0x00 to stay positive
        assert_eq!(&encode_integer(-128).0[..1], &[0x80]);
        assert_eq!(&encode_integer(-129).0[..2], &[0xFF, 0x7F]);
    }

    // --- seeded-bad specimens ---
    #[test]
    fn rejects_empty() {
        assert_eq!(decode_integer(&[]), Err(IntError::Empty));
    }
    #[test]
    fn rejects_redundant_positive_padding() {
        // 0x00 0x01 is a non-minimal encoding of 1 (should be just 0x01)
        assert_eq!(decode_integer(&[0x00, 0x01]), Err(IntError::NonMinimal));
    }
    #[test]
    fn rejects_redundant_negative_padding() {
        // 0xFF 0xFF is a non-minimal encoding of -1 (should be just 0xFF)
        assert_eq!(decode_integer(&[0xFF, 0xFF]), Err(IntError::NonMinimal));
    }
    #[test]
    fn accepts_minimal_positive_needing_leading_zero() {
        // 0x00 0x80 = 128 is minimal (0x80 alone would be -128)
        assert_eq!(decode_integer(&[0x00, 0x80]), Ok(128));
    }
    #[test]
    fn rejects_too_large() {
        assert_eq!(
            decode_integer(&[0x01, 0, 0, 0, 0, 0, 0, 0, 0]),
            Err(IntError::TooLarge)
        );
    }

    // --- S4a (group 3): per-requirement tests ---

    /// X680-19: an INTEGER TLV carries the literal identifier octet 0x02 (UNIVERSAL 2, decoded and encoded).
    #[test]
    fn accepts_integer_universal_2_identifier_octet() {
        use crate::tag::{Class, Tag};
        use crate::tlv::{decode_tlv_strict, encode_tlv_into};
        // literal specimen: 02 01 05 (INTEGER 5)
        let tlv = decode_tlv_strict(&[0x02, 0x01, 0x05]).unwrap();
        assert_eq!(tlv.tag, Tag { class: Class::Universal, constructed: false, number: TAG });
        assert_eq!(decode_integer(tlv.value), Ok(5));
        // encoder direction: the first output octet is 0x02
        let (content, n) = encode_integer(5);
        let mut out = [0u8; 8];
        let used = encode_tlv_into(
            Tag { class: Class::Universal, constructed: false, number: TAG },
            &content[..n],
            &mut out,
        )
        .unwrap();
        assert_eq!(out[0], 0x02);
        assert_eq!(&out[..used], &[0x02, 0x01, 0x05]);
    }

    /// X690-8.3.1: the INTEGER encoding is primitive (identifier bit 6 clear) with one or more content octets.
    #[test]
    fn accepts_primitive_integer_encoding() {
        use crate::tag::{Class, Tag};
        use crate::tlv::{decode_tlv_strict, encode_tlv_into};
        // encoder: 128 needs two content octets (00 80); the TLV is 02 02 00 80 and primitive
        let (content, n) = encode_integer(128);
        assert!(n >= 1);
        let mut out = [0u8; 8];
        let used = encode_tlv_into(
            Tag { class: Class::Universal, constructed: false, number: TAG },
            &content[..n],
            &mut out,
        )
        .unwrap();
        assert_eq!(&out[..used], &[0x02, 0x02, 0x00, 0x80]);
        assert_eq!(out[0] & 0x20, 0, "constructed bit must be clear");
        // decoder: the same literal TLV is primitive and its content decodes to 128
        let tlv = decode_tlv_strict(&[0x02, 0x02, 0x00, 0x80]).unwrap();
        assert!(!tlv.tag.constructed);
        assert_eq!(decode_integer(tlv.value), Ok(128));
    }

    /// X690-8.3.1-a: a single content octet is the shortest accepted INTEGER payload, and the encoder never emits zero octets.
    #[test]
    fn accepts_single_octet_payload() {
        assert_eq!(decode_integer(&[0x00]), Ok(0));
        assert_eq!(decode_integer(&[0x7F]), Ok(127));
        assert_eq!(decode_integer(&[0x80]), Ok(-128));
        assert_eq!(decode_integer(&[0xFF]), Ok(-1));
        for v in [0i64, 1, -1, 127, -128, i64::MAX, i64::MIN] {
            let (_, n) = encode_integer(v);
            assert!(n >= 1, "value {v} must encode to at least one octet");
        }
        assert_eq!(encode_integer(0).1, 1);
    }

    /// X690-8.3.3: a positive value of 2^63 (or a negative one below -2^63) is rejected as TooLarge, never wrapped through the sign bit.
    #[test]
    fn rejects_two_complement_overflow_instead_of_wrapping() {
        // 00 80 00 .. 00 (9 octets) is +2^63; wrapping would give i64::MIN
        assert_eq!(
            decode_integer(&[0x00, 0x80, 0, 0, 0, 0, 0, 0, 0]),
            Err(IntError::TooLarge)
        );
        // FF 7F FF .. FF (9 octets) is -2^63 - 1; wrapping would give i64::MAX
        assert_eq!(
            decode_integer(&[0xFF, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Err(IntError::TooLarge)
        );
        // the two's-complement neighbours that DO fit are read with the correct sign
        assert_eq!(decode_integer(&[0x80, 0, 0, 0, 0, 0, 0, 0]), Ok(i64::MIN));
        assert_eq!(decode_integer(&[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]), Ok(i64::MAX));
    }

    /// CODEC-integer-encode-decode: accepted content decodes, then re-encodes to exactly the same octets.
    #[test]
    fn roundtrips_accepted_content_through_decode_then_encode() {
        let samples: [&[u8]; 12] = [
            &[0x00],
            &[0x7F],
            &[0x80],
            &[0xFF],
            &[0x00, 0x80],
            &[0xFF, 0x7F],
            &[0x01, 0x00],
            &[0x80, 0x00],
            &[0x00, 0xFF, 0xFF],
            &[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF],
            &[0x80, 0, 0, 0, 0, 0, 0, 0],
            &[0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01],
        ];
        for content in samples {
            let v = decode_integer(content).expect("sample is minimal");
            let (buf, n) = encode_integer(v);
            assert_eq!(&buf[..n], content, "content {content:02X?}");
        }
    }

    /// CODEC-integer-unique: every padded alternate spelling of a value is rejected as NonMinimal; only the one minimal form is accepted.
    #[test]
    fn rejects_every_alternate_spelling_of_a_value() {
        // value 1: minimal 01 accepted; 00 01, 00 00 01 and an 8-octet padded form rejected
        assert_eq!(decode_integer(&[0x01]), Ok(1));
        assert_eq!(decode_integer(&[0x00, 0x01]), Err(IntError::NonMinimal));
        assert_eq!(decode_integer(&[0x00, 0x00, 0x01]), Err(IntError::NonMinimal));
        assert_eq!(
            decode_integer(&[0, 0, 0, 0, 0, 0, 0, 0x01]),
            Err(IntError::NonMinimal)
        );
        // value -1: minimal FF accepted; FF FF, FF FF FF rejected
        assert_eq!(decode_integer(&[0xFF]), Ok(-1));
        assert_eq!(decode_integer(&[0xFF, 0xFF]), Err(IntError::NonMinimal));
        assert_eq!(decode_integer(&[0xFF, 0xFF, 0xFF]), Err(IntError::NonMinimal));
        // value 0: only 00 is accepted; 00 00 is a padded spelling
        assert_eq!(decode_integer(&[0x00]), Ok(0));
        assert_eq!(decode_integer(&[0x00, 0x00]), Err(IntError::NonMinimal));
        // value -128: minimal 80 accepted; FF 80 is the padded spelling
        assert_eq!(decode_integer(&[0x80]), Ok(-128));
        assert_eq!(decode_integer(&[0xFF, 0x80]), Err(IntError::NonMinimal));
    }

    /// PROF-integer-i64-cap: full-width 8-octet contents at both ends of the i64 range are accepted (the cap is 8 octets, not fewer).
    #[test]
    fn accepts_full_width_eight_octet_values_at_the_i64_cap() {
        assert_eq!(
            decode_integer(&[0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF]),
            Ok(i64::MAX)
        );
        assert_eq!(decode_integer(&[0x80, 0, 0, 0, 0, 0, 0, 0]), Ok(i64::MIN));
        let (buf, n) = encode_integer(i64::MAX);
        assert_eq!(n, 8);
        assert_eq!(decode_integer(&buf[..n]), Ok(i64::MAX));
        let (buf, n) = encode_integer(i64::MIN);
        assert_eq!(n, 8);
        assert_eq!(decode_integer(&buf[..n]), Ok(i64::MIN));
    }
}
