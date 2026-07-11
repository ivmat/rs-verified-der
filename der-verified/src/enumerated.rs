//! DER ENUMERATED content (X.690 §8.4) — the encoding of an enumerated value is defined to be
//! IDENTICAL to that of the integer value with which it is associated (no additional DER rule).
//! This module is therefore a thin re-tagging of [`crate::integer`]'s already-proven i64 content
//! codec: UNIVERSAL 10 (`0x0A`) instead of UNIVERSAL 2, same minimal two's-complement content rule,
//! same [`crate::integer::IntError`] classification. It deliberately does NOT duplicate
//! `crate::integer`'s minimality/round-trip proofs (see `DECISIONS.md` D11's precedent against
//! near-duplicate modules for the same content rule) — it only needs to confirm the delegation and
//! tag number are wired correctly.

/// The universal tag number for ENUMERATED.
pub const TAG: u32 = 10;

/// Decode ENUMERATED content (delegates entirely to [`crate::integer::decode_integer`] — the
/// content rule is byte-for-byte identical, per X.690 §8.4).
pub fn decode_enumerated(content: &[u8]) -> Result<i64, crate::integer::IntError> {
    crate::integer::decode_integer(content)
}

/// Encode `v` as minimal DER ENUMERATED content (delegates entirely to
/// [`crate::integer::encode_integer`]).
pub fn encode_enumerated(v: i64) -> ([u8; 8], usize) {
    crate::integer::encode_integer(v)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Delegation contract: `decode_enumerated` returns literally the same result as
    /// `crate::integer::decode_integer` for any content. Pins the delegation so a future refactor
    /// cannot accidentally diverge the two (`integer.rs`'s own buffer/unwind choices: an 8-octet
    /// buffer, symbolic length `1..=8`).
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_delegates_to_integer() {
        let buf: [u8; 8] = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 8);
        assert!(decode_enumerated(&buf[..n]) == crate::integer::decode_integer(&buf[..n]));
    }

    /// Delegation contract: `encode_enumerated` returns literally the same result as
    /// `crate::integer::encode_integer` for any `i64`.
    #[kani::proof]
    fn encode_delegates_to_integer() {
        let v: i64 = kani::any();
        assert!(encode_enumerated(v) == crate::integer::encode_integer(v));
    }

    /// Round-trip: every `i64` encodes to minimal ENUMERATED content that decodes back to it.
    /// Follows from the two delegation proofs above, but is worth pinning directly on this
    /// module's own public API since it's the property an actual caller relies on.
    #[kani::proof]
    #[kani::unwind(12)]
    fn roundtrip() {
        let v: i64 = kani::any();
        let (buf, n) = encode_enumerated(v);
        assert!(decode_enumerated(&buf[..n]) == Ok(v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_universal_10() {
        // The ENUMERATED identifier octet for a primitive, universal-class tag is just the tag
        // number itself (class bits 00, primitive bit 0) — anchor the 0x0A arithmetic fact.
        assert_eq!(TAG, 10);
        assert_eq!(TAG as u8, 0x0A);
    }

    #[test]
    fn matches_integer_for_concrete_values() {
        for v in [0i64, 1, -1, 127, 128, -129] {
            assert_eq!(encode_enumerated(v), crate::integer::encode_integer(v), "value {v}");
            let (buf, n) = encode_enumerated(v);
            assert_eq!(
                decode_enumerated(&buf[..n]),
                crate::integer::decode_integer(&buf[..n]),
                "value {v}"
            );
            assert_eq!(decode_enumerated(&buf[..n]), Ok(v), "value {v}");
        }
    }

    #[test]
    fn rejects_non_minimal_same_as_integer() {
        // 0x00 0x01 is non-minimal for INTEGER; ENUMERATED shares the same rule (§8.4).
        assert_eq!(
            decode_enumerated(&[0x00, 0x01]),
            crate::integer::decode_integer(&[0x00, 0x01])
        );
        assert_eq!(
            decode_enumerated(&[0x00, 0x01]),
            Err(crate::integer::IntError::NonMinimal)
        );
    }
}
