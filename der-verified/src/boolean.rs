//! DER BOOLEAN content (X.690 §8.2, §11.1).
//!
//! The content is exactly one octet. DER (unlike BER) is canonical: `FALSE` is `0x00` and `TRUE`
//! is `0xFF` — no other octet is a valid TRUE. These functions operate on the *content* octets
//! of a TLV whose tag is UNIVERSAL 1 (`0x01`); see [`crate::tlv`] for extracting that content.
//!
//! # Examples
//!
//! ```
//! use der_verified::boolean::{decode_bool, encode_bool};
//!
//! assert_eq!(decode_bool(&[0xFF]), Ok(true));
//! assert_eq!(encode_bool(true), 0xFF);
//!
//! // BER would accept 0x01 as TRUE; DER must not.
//! assert!(decode_bool(&[0x01]).is_err());
//! ```

/// The universal tag number for BOOLEAN.
pub const TAG: u32 = 1;

/// Why BOOLEAN content was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BoolError {
    /// Content was not exactly one octet.
    BadLength,
    /// The octet was neither `0x00` nor the canonical `0xFF`.
    NonCanonical,
}

/// The single canonical DER content octet for `v`.
pub fn encode_bool(v: bool) -> u8 {
    if v {
        0xFF
    } else {
        0x00
    }
}

/// Decode BOOLEAN content octets. Accepts only the canonical `0x00` / `0xFF`.
pub fn decode_bool(content: &[u8]) -> Result<bool, BoolError> {
    if content.len() != 1 {
        return Err(BoolError::BadLength);
    }
    match content[0] {
        0x00 => Ok(false),
        0xFF => Ok(true),
        _ => Err(BoolError::NonCanonical),
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Full characterization of one content octet: accepted iff `0x00`/`0xFF`, and canonical.
    #[kani::proof]
    fn one_octet_is_canonical() {
        let b: u8 = kani::any();
        match decode_bool(&[b]) {
            Ok(v) => {
                // only 0x00/0xFF accepted, with the spec polarity (TRUE = 0xFF, FALSE = 0x00),
                // stated from the literals and independently of `encode_bool`
                assert!(b == 0x00 || b == 0xFF);
                assert!(v == (b == 0xFF));
                assert!(b == encode_bool(v)); // and it re-encodes
            }
            Err(e) => {
                assert!(e == BoolError::NonCanonical);
                assert!(b != 0x00 && b != 0xFF);
            }
        }
    }

    /// Round-trip on both values.
    #[kani::proof]
    fn roundtrip() {
        let v: bool = kani::any();
        assert!(decode_bool(&[encode_bool(v)]) == Ok(v));
    }

    /// Any content whose length isn't 1 is `BadLength` (every length 0..=16, symbolic content).
    #[kani::proof]
    fn wrong_length_is_bad_length() {
        let buf: [u8; 16] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 16 && n != 1);
        kani::cover!(n == 0);
        kani::cover!(n == 2);
        kani::cover!(n == 16);
        assert!(decode_bool(&buf[..n]) == Err(BoolError::BadLength));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonical_values() {
        assert_eq!(decode_bool(&[0x00]), Ok(false));
        assert_eq!(decode_bool(&[0xFF]), Ok(true));
        assert_eq!(encode_bool(false), 0x00);
        assert_eq!(encode_bool(true), 0xFF);
    }

    #[test]
    fn rejects_non_canonical_true() {
        // BER would accept 0x01 as TRUE; DER must not.
        assert_eq!(decode_bool(&[0x01]), Err(BoolError::NonCanonical));
        assert_eq!(decode_bool(&[0x7F]), Err(BoolError::NonCanonical));
    }

    #[test]
    fn rejects_wrong_length() {
        assert_eq!(decode_bool(&[]), Err(BoolError::BadLength));
        assert_eq!(decode_bool(&[0x00, 0x00]), Err(BoolError::BadLength));
    }

    // --- S4a (group 3): per-requirement tests ---

    /// X680-18: a BOOLEAN TLV carries the literal identifier octet 0x01 (UNIVERSAL 1, decoded and encoded).
    #[test]
    fn accepts_boolean_universal_1_identifier_octet() {
        use crate::tag::{Class, Tag};
        use crate::tlv::{decode_tlv_strict, encode_tlv_into};
        // literal specimen: 01 01 FF (TRUE)
        let tlv = decode_tlv_strict(&[0x01, 0x01, 0xFF]).unwrap();
        assert_eq!(tlv.tag, Tag { class: Class::Universal, constructed: false, number: TAG });
        assert_eq!(decode_bool(tlv.value), Ok(true));
        // encoder direction: the first output octet is 0x01
        let mut out = [0u8; 4];
        let used = encode_tlv_into(
            Tag { class: Class::Universal, constructed: false, number: TAG },
            &[encode_bool(false)],
            &mut out,
        )
        .unwrap();
        assert_eq!(out[0], 0x01);
        assert_eq!(&out[..used], &[0x01, 0x01, 0x00]);
    }

    /// X680-18d: no octet other than 00 (FALSE) and FF (TRUE) is a BOOLEAN value; the other 254 are NonCanonical.
    #[test]
    fn rejects_every_octet_that_is_neither_true_nor_false() {
        for b in 0u8..=255 {
            match b {
                0x00 => assert_eq!(decode_bool(&[b]), Ok(false)),
                0xFF => assert_eq!(decode_bool(&[b]), Ok(true)),
                _ => assert_eq!(decode_bool(&[b]), Err(BoolError::NonCanonical), "octet {b:#04x}"),
            }
        }
    }

    /// X690-8.2.2: a non-zero octet is never decoded as FALSE (FALSE is the zero octet only).
    #[test]
    fn rejects_non_zero_octet_as_false() {
        for b in 1u8..=255 {
            assert_ne!(decode_bool(&[b]), Ok(false), "octet {b:#04x}");
        }
        // the one TRUE octet DER allows is non-zero, and zero is not TRUE
        assert_eq!(decode_bool(&[0xFF]), Ok(true));
        assert_ne!(decode_bool(&[0x00]), Ok(true));
    }

    /// CODEC-boolean-encode-decode: accepted content decodes, then re-encodes to exactly the same octet.
    #[test]
    fn roundtrips_accepted_content_through_decode_then_encode() {
        for content in [[0x00u8], [0xFF]] {
            let v = decode_bool(&content).expect("canonical octet");
            assert_eq!([encode_bool(v)], content);
        }
    }

    /// CODEC-boolean-unique: TRUE has one accepted spelling (FF); every other non-zero spelling that BER allows is rejected.
    #[test]
    fn rejects_every_alternate_spelling_of_true() {
        assert_eq!(decode_bool(&[0xFF]), Ok(true));
        for alt in [0x01u8, 0x02, 0x7F, 0x80, 0xFE] {
            assert_eq!(decode_bool(&[alt]), Err(BoolError::NonCanonical), "octet {alt:#04x}");
        }
        // and the accepted set maps to exactly two distinct values
        assert_ne!(decode_bool(&[0x00]), decode_bool(&[0xFF]));
    }
}
