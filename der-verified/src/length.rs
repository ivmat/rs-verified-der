//! DER definite-length field (X.690 §8.1.3, §10.1) — the place where real X.509 parser
//! differentials live (non-canonical length encodings accepted by lax parsers).
//!
//! **Supported range & a deliberate compliance boundary:** lengths up to `u32::MAX`
//! (≤ 4 length octets). A length field declaring more octets — a value `> u32::MAX` — is
//! rejected as `Err(TooLarge)`, never a panic. This is a *deliberate deviation from full
//! DER*: a strictly-compliant parser would parse an arbitrarily large length and reject the
//! object elsewhere. Rejecting the length field itself is a safe, documented trade-off for
//! X.509, whose lengths are far under 4 GiB.

/// Why a DER length field was rejected. Every rejection is a distinct, testable reason.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum LengthError {
    /// Input ended before a complete length field was present.
    Truncated,
    /// Indefinite-length form (initial octet `0x80`) — forbidden in DER.
    Indefinite,
    /// Reserved initial octet `0xFF`.
    Reserved,
    /// Long form used where short form was required, or leading-zero length octets
    /// (non-minimal) — forbidden by DER's canonical encoding rules.
    NonMinimal,
    /// Length field needs more than 4 octets (value `> u32::MAX`) — a deliberate
    /// deviation from full DER for this codec (see the module docs).
    TooLarge,
}

/// Encode `len` as a canonical DER length field (X.690 §8.1.3).
///
/// Returns a fixed 5-byte buffer and the number of bytes used (`1..=5`); the codec is
/// heap-free. Lengths `< 0x80` use the single-octet short form; the rest use the
/// minimal long form (no leading-zero octets).
pub fn encode_length(len: u32) -> ([u8; 5], usize) {
    let mut out = [0u8; 5];
    if len < 0x80 {
        out[0] = len as u8;
        return (out, 1);
    }
    let be = len.to_be_bytes(); // 4 bytes, most-significant first
    // Minimal octet count = 4 − (leading zero bytes). `len >= 0x80` ⇒ at least one
    // significant byte, so `n >= 1`.
    let mut lead = 0usize;
    while lead < 4 && be[lead] == 0 {
        lead += 1;
    }
    let n = 4 - lead;
    out[0] = 0x80 | (n as u8); // n ∈ 1..=4 ⇒ initial octet ∈ 0x81..=0x84
    let mut i = 0;
    while i < n {
        out[1 + i] = be[lead + i];
        i += 1;
    }
    (out, 1 + n)
}

/// Decode a canonical DER length field from the front of `input`.
///
/// On success returns `(length, bytes_consumed)`. Every non-canonical or malformed
/// encoding is rejected with a specific [`LengthError`]; the function never panics.
pub fn decode_length(input: &[u8]) -> Result<(u32, usize), LengthError> {
    let first = match input.first() {
        Some(&b) => b,
        None => return Err(LengthError::Truncated),
    };
    if first < 0x80 {
        return Ok((first as u32, 1)); // short form
    }
    if first == 0x80 {
        return Err(LengthError::Indefinite);
    }
    if first == 0xFF {
        return Err(LengthError::Reserved);
    }
    let n = (first & 0x7F) as usize; // number of subsequent length octets, 1..=126
    if input.len() < 1 + n {
        return Err(LengthError::Truncated);
    }
    let octets = &input[1..1 + n];
    if octets[0] == 0 {
        return Err(LengthError::NonMinimal); // leading-zero octet
    }
    if n > 4 {
        return Err(LengthError::TooLarge); // cannot fit u32
    }
    let mut val: u32 = 0;
    let mut i = 0;
    while i < n {
        val = (val << 8) | octets[i] as u32;
        i += 1;
    }
    if val < 0x80 {
        return Err(LengthError::NonMinimal); // long form for a short-form value
    }
    Ok((val, 1 + n))
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor). Excluded from ordinary builds/tests.
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    // Harness bounds: an 8-byte symbolic buffer covers every reachable decode branch,
    // including long forms with n = 1..=7 octets — the `n > 4` TooLarge branch (n = 5,6,7)
    // and canonical n ≤ 4, with a byte of margin so the branch coverage is not at the exact
    // truncation boundary. `unwind(10)` clears the ≤4-iteration codec loops with margin.

    /// Round-trip: every `u32` length encodes to bytes that decode back to exactly
    /// that value, consuming exactly the produced encoding.
    #[kani::proof]
    #[kani::unwind(10)]
    fn roundtrip_all_u32() {
        let n: u32 = kani::any();
        let (buf, used) = encode_length(n);
        assert!(decode_length(&buf[..used]) == Ok((n, used)));
    }

    /// Robustness: `decode_length` never panics or overflows on *any* input.
    ///
    /// Cover (T6 primary rule): witnesses that the symbolic 8-byte buffer actually reaches the
    /// `Ok` tail (a real short- or long-form length decodes successfully), not merely that every
    /// malformed prefix is rejected. Would NOT be SAT if `decode_length`'s body were a no-op
    /// always returning `Err`.
    #[kani::proof]
    #[kani::unwind(10)]
    fn decode_never_panics() {
        let buf: [u8; 8] = kani::any();
        let result = decode_length(&buf);
        kani::cover(result.is_ok(), "a well-formed length field reaches decode_length's Ok tail");
        let _ = result;
    }

    /// Canonicality (the security property): if `decode_length` accepts a byte string,
    /// that string is the unique canonical encoding of the decoded value. This rules
    /// out the non-canonical-length parser differentials that plague X.509 stacks.
    #[kani::proof]
    #[kani::unwind(10)]
    fn decode_accepts_only_canonical() {
        let buf: [u8; 8] = kani::any();
        if let Ok((v, used)) = decode_length(&buf) {
            let (re, relen) = encode_length(v);
            assert!(relen == used);
            assert!(re[..relen] == buf[..used]);
        }
    }

    // --- Error-class correctness: every malformed category is rejected with its SPECIFIC
    //     documented `LengthError`, not merely rejected (closes the review's MEDIUM gap). ---

    /// Initial octet `0x80` (indefinite form) is always classified `Indefinite`.
    #[kani::proof]
    #[kani::unwind(10)]
    fn indefinite_is_classified() {
        let buf: [u8; 8] = kani::any();
        kani::assume(buf[0] == 0x80);
        assert!(decode_length(&buf) == Err(LengthError::Indefinite));
    }

    /// Initial octet `0xFF` (reserved) is always classified `Reserved`.
    #[kani::proof]
    #[kani::unwind(10)]
    fn reserved_is_classified() {
        let buf: [u8; 8] = kani::any();
        kani::assume(buf[0] == 0xFF);
        assert!(decode_length(&buf) == Err(LengthError::Reserved));
    }

    /// A long form whose first length octet is zero (non-minimal leading zero) is
    /// classified `NonMinimal`, for every declared octet count that fits the buffer.
    #[kani::proof]
    #[kani::unwind(10)]
    fn leading_zero_is_non_minimal() {
        let buf: [u8; 8] = kani::any();
        // long form declaring n = 1..=7 octets (all present in the 8-byte buffer), leading octet zero
        kani::assume(buf[0] >= 0x81 && buf[0] <= 0x87);
        kani::assume(buf[1] == 0x00);
        assert!(decode_length(&buf) == Err(LengthError::NonMinimal));
    }

    /// A long form encoding a value `< 0x80` (which must use the short form) is
    /// classified `NonMinimal` for every such value.
    #[kani::proof]
    #[kani::unwind(10)]
    fn long_form_of_short_value_is_non_minimal() {
        let v: u8 = kani::any();
        kani::assume(v < 0x80);
        assert!(decode_length(&[0x81, v]) == Err(LengthError::NonMinimal));
    }

    /// A long form declaring more octets than are present is classified `Truncated`.
    #[kani::proof]
    #[kani::unwind(10)]
    fn truncated_long_form_is_classified() {
        // 2 bytes present; a first byte declaring n = first & 0x7F >= 2 needs >= 3 bytes.
        let first: u8 = kani::any();
        kani::assume(first >= 0x82 && first <= 0xFE);
        let second: u8 = kani::any();
        assert!(decode_length(&[first, second]) == Err(LengthError::Truncated));
    }

    /// A long form needing more than 4 octets (value `> u32::MAX`) is classified `TooLarge`.
    #[kani::proof]
    #[kani::unwind(10)]
    fn too_large_is_classified() {
        let b1: u8 = kani::any();
        let (b2, b3, b4, b5): (u8, u8, u8, u8) = (kani::any(), kani::any(), kani::any(), kani::any());
        kani::assume(b1 != 0x00); // a leading zero would be NonMinimal; isolate the TooLarge path
        // first byte 0x85 => n = 5 octets, all present (6 bytes) => exceeds u32
        assert!(decode_length(&[0x85, b1, b2, b3, b4, b5]) == Err(LengthError::TooLarge));
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. the seeded-bad specimens (the mandatory known-bad leg).
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_form_roundtrips() {
        for n in [0u32, 1, 0x7F] {
            let (b, used) = encode_length(n);
            assert_eq!(used, 1);
            assert_eq!(decode_length(&b[..used]), Ok((n, 1)));
        }
    }

    #[test]
    fn long_form_canonical_examples() {
        let (b, used) = encode_length(0x80);
        assert_eq!(&b[..used], &[0x81, 0x80]);
        assert_eq!(decode_length(&b[..used]), Ok((0x80, 2)));

        let (b, used) = encode_length(0x1234);
        assert_eq!(&b[..used], &[0x82, 0x12, 0x34]);
        assert_eq!(decode_length(&b[..used]), Ok((0x1234, 3)));

        let (b, used) = encode_length(u32::MAX);
        assert_eq!(&b[..used], &[0x84, 0xFF, 0xFF, 0xFF, 0xFF]);
        assert_eq!(decode_length(&b[..used]), Ok((u32::MAX, 5)));
    }

    // --- seeded-bad specimens: each MUST be rejected ---
    #[test]
    fn rejects_indefinite_length() {
        assert_eq!(decode_length(&[0x80]), Err(LengthError::Indefinite));
    }
    #[test]
    fn rejects_reserved_initial_octet() {
        assert_eq!(decode_length(&[0xFF]), Err(LengthError::Reserved));
    }
    #[test]
    fn rejects_non_minimal_long_form_of_zero() {
        assert_eq!(decode_length(&[0x81, 0x00]), Err(LengthError::NonMinimal));
    }
    #[test]
    fn rejects_non_minimal_long_form_of_small_value() {
        // 127 fits the short form; encoding it long form is non-canonical.
        assert_eq!(decode_length(&[0x81, 0x7F]), Err(LengthError::NonMinimal));
    }
    #[test]
    fn rejects_leading_zero_octet() {
        assert_eq!(decode_length(&[0x82, 0x00, 0xFF]), Err(LengthError::NonMinimal));
    }
    #[test]
    fn rejects_truncated_long_form() {
        assert_eq!(decode_length(&[0x82, 0x01]), Err(LengthError::Truncated));
    }
    #[test]
    fn rejects_length_too_large_for_u32() {
        assert_eq!(
            decode_length(&[0x85, 0x01, 0x00, 0x00, 0x00, 0x00]),
            Err(LengthError::TooLarge)
        );
    }
    #[test]
    fn rejects_empty_input() {
        assert_eq!(decode_length(&[]), Err(LengthError::Truncated));
    }
}
