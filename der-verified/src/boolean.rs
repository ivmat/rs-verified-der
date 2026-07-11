//! DER BOOLEAN content (X.690 §8.2, §11.1).
//!
//! The content is exactly one octet. DER (unlike BER) is canonical: `FALSE` is `0x00` and `TRUE`
//! is `0xFF` — no other octet is a valid TRUE. These functions operate on the *content* octets
//! of a TLV whose tag is UNIVERSAL 1 (`0x01`); see [`crate::tlv`] for extracting that content.

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
            Ok(v) => assert!(b == encode_bool(v)), // only 0x00/0xFF accepted, and it re-encodes
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

    /// Any content whose length isn't 1 is `BadLength` (length 0, 2, 3 exercised).
    #[kani::proof]
    fn wrong_length_is_bad_length() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let c: u8 = kani::any();
        assert!(decode_bool(&[]) == Err(BoolError::BadLength));
        assert!(decode_bool(&[a, b]) == Err(BoolError::BadLength));
        assert!(decode_bool(&[a, b, c]) == Err(BoolError::BadLength));
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
}
