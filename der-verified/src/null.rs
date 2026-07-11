//! DER NULL content (X.690 §8.8).
//!
//! NULL carries no value: its content must be empty (the TLV is `05 00`). These functions operate
//! on the content octets of a TLV whose tag is UNIVERSAL 5 (`0x05`).

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

    /// Empty content is accepted; any non-empty content (length 1..=3 exercised) is rejected.
    #[kani::proof]
    fn only_empty_is_valid() {
        assert!(decode_null(&[]) == Ok(()));
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let c: u8 = kani::any();
        assert!(decode_null(&[a]) == Err(NullError::NonEmpty));
        assert!(decode_null(&[a, b]) == Err(NullError::NonEmpty));
        assert!(decode_null(&[a, b, c]) == Err(NullError::NonEmpty));
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
}
