//! DER NULL content (X.690 §8.8).
//!
//! NULL carries no value: its content must be empty (the TLV is `05 00`). These functions operate
//! on the content octets of a TLV whose tag is UNIVERSAL 5 (`0x05`).
//!
//! # Examples
//!
//! ```
//! use der_verified::null::decode_null;
//!
//! assert_eq!(decode_null(&[]), Ok(()));
//! assert!(decode_null(&[0x00]).is_err()); // NULL content must be empty
//! ```

/// The universal tag number for NULL.
pub const TAG: u32 = 5;

/// Why NULL content was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NullError {
    /// NULL content must be empty.
    NonEmpty,
}

/// Decode NULL content octets — accepts only the empty slice.
pub fn decode_null(content: &[u8]) -> Result<(), NullError> {
    if content.is_empty() {
        Ok(())
    } else {
        Err(NullError::NonEmpty)
    }
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Empty content is accepted; any non-empty content (every length 1..=16, symbolic content)
    /// is rejected.
    #[kani::proof]
    fn only_empty_is_valid() {
        assert!(decode_null(&[]) == Ok(()));
        let buf: [u8; 16] = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 16);
        kani::cover!(n == 1);
        kani::cover!(n == 4);
        kani::cover!(n == 16);
        assert!(decode_null(&buf[..n]) == Err(NullError::NonEmpty));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_empty() {
        assert_eq!(decode_null(&[]), Ok(()));
    }

    #[test]
    fn rejects_non_empty() {
        assert_eq!(decode_null(&[0x00]), Err(NullError::NonEmpty));
    }

    // --- S4a (group 3): per-requirement tests ---

    /// X680-24: a NULL TLV carries the literal identifier octet 0x05 (UNIVERSAL 5, decoded and encoded).
    #[test]
    fn accepts_null_universal_5_identifier_octet() {
        use crate::tag::{Class, Tag};
        use crate::tlv::{decode_tlv_strict, encode_tlv_into};
        // literal specimen: 05 00
        let tlv = decode_tlv_strict(&[0x05, 0x00]).unwrap();
        assert_eq!(tlv.tag, Tag { class: Class::Universal, constructed: false, number: TAG });
        assert_eq!(decode_null(tlv.value), Ok(()));
        // encoder direction: the first output octet is 0x05
        let mut out = [0u8; 4];
        let used = encode_tlv_into(
            Tag { class: Class::Universal, constructed: false, number: TAG },
            &[],
            &mut out,
        )
        .unwrap();
        assert_eq!(out[0], 0x05);
        assert_eq!(&out[..used], &[0x05, 0x00]);
    }

    /// CODEC-null-unique: NULL has exactly one accepted content (empty); content of any length or value is NonEmpty.
    #[test]
    fn rejects_every_non_empty_content() {
        assert_eq!(decode_null(&[]), Ok(()));
        for len in 1usize..=4 {
            for fill in [0x00u8, 0x01, 0x7F, 0x80, 0xFF] {
                let buf = [fill; 4];
                assert_eq!(
                    decode_null(&buf[..len]),
                    Err(NullError::NonEmpty),
                    "len {len} fill {fill:#04x}"
                );
            }
        }
    }

    /// CODEC-null-reject-nonder: a BER long-form spelling of the NULL length (05 81 00, 05 82 00 00) is rejected as a NonMinimal length.
    #[test]
    fn rejects_long_form_length_spelling_of_null() {
        use crate::length::LengthError;
        use crate::tlv::{decode_tlv_strict, TlvError};
        // the DER spelling is accepted
        let tlv = decode_tlv_strict(&[0x05, 0x00]).unwrap();
        assert_eq!(decode_null(tlv.value), Ok(()));
        // BER-valid alternate spellings of the same value (length 0 in long form)
        assert_eq!(
            decode_tlv_strict(&[0x05, 0x81, 0x00]),
            Err(TlvError::Length(LengthError::NonMinimal))
        );
        assert_eq!(
            decode_tlv_strict(&[0x05, 0x82, 0x00, 0x00]),
            Err(TlvError::Length(LengthError::NonMinimal))
        );
    }
}
