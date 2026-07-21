//! DER identifier octet(s) — the tag (X.690 §8.1.2).
//!
//! An identifier is a class (2 bits) + a primitive/constructed flag (1 bit) + a tag number.
//! Tag numbers `0..=30` use the single-octet low-tag form; `>= 31` use the high-tag form
//! (initial 5 bits all 1, then base-128 big-endian continuation octets, MSB set on all but
//! the last). DER canonicality requires the *minimal* encoding: the low-tag form whenever it
//! fits, and no leading-zero continuation group in the high-tag form.
//!
//! **Supported range & compliance boundary:** tag numbers up to `u32::MAX`; a high-tag form
//! encoding a larger value is rejected as `Err(TooLarge)`, never a panic — the same
//! deliberate deviation from full DER as the length codec (safe for X.509).

/// The tag class (X.690 §8.1.2.2).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Class {
    /// UNIVERSAL — the built-in ASN.1 types (tag numbers assigned by X.680).
    Universal,
    /// APPLICATION — application-scoped types.
    Application,
    /// CONTEXT-SPECIFIC — meaning depends on the enclosing structure (the `[n]` tags in X.509).
    ContextSpecific,
    /// PRIVATE — enterprise / private-use types.
    Private,
}

/// A decoded DER identifier: class, primitive/constructed flag, and tag number.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Tag {
    /// The tag class (UNIVERSAL / APPLICATION / CONTEXT-SPECIFIC / PRIVATE).
    pub class: Class,
    /// `true` for a constructed encoding (nested TLVs), `false` for primitive (raw content octets).
    pub constructed: bool,
    /// The tag number (X.690 §8.1.2); the high-tag-number form is decoded, oversized values rejected.
    pub number: u32,
}

/// Why a DER identifier was rejected. Every rejection is a distinct, testable reason.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TagError {
    /// Input ended before a complete identifier was present.
    Truncated,
    /// High-tag form used for a number that fits the low-tag form (`<= 30`), or a
    /// leading-zero continuation octet — forbidden by DER's minimal encoding rules.
    NonMinimal,
    /// Tag number needs more than fits in `u32` — a deliberate deviation from full DER
    /// for this codec (see the module docs).
    TooLarge,
}

fn class_bits(c: Class) -> u8 {
    match c {
        Class::Universal => 0b00,
        Class::Application => 0b01,
        Class::ContextSpecific => 0b10,
        Class::Private => 0b11,
    }
}

/// Encode `tag` as a canonical DER identifier (X.690 §8.1.2).
///
/// Returns a fixed 6-byte buffer and the number of bytes used (`1..=6`); heap-free.
pub fn encode_tag(tag: Tag) -> ([u8; 6], usize) {
    let mut out = [0u8; 6];
    let cc = (class_bits(tag.class) << 6) | if tag.constructed { 0x20 } else { 0x00 };
    if tag.number <= 30 {
        out[0] = cc | (tag.number as u8);
        return (out, 1);
    }
    out[0] = cc | 0x1F; // high-tag marker
    // Minimal base-128, big-endian; continuation bit (0x80) on all but the last octet.
    let mut ndig = 1usize;
    let mut t = tag.number >> 7;
    while t > 0 {
        ndig += 1;
        t >>= 7;
    }
    let mut i = 0;
    while i < ndig {
        let shift = 7 * (ndig - 1 - i);
        let mut byte = ((tag.number >> shift) & 0x7F) as u8;
        if i != ndig - 1 {
            byte |= 0x80;
        }
        out[1 + i] = byte;
        i += 1;
    }
    (out, 1 + ndig)
}

/// Decode a canonical DER identifier from the front of `input`.
///
/// On success returns `(tag, bytes_consumed)`. Every non-canonical or malformed encoding is
/// rejected with a specific [`TagError`]; the function never panics.
pub fn decode_tag(input: &[u8]) -> Result<(Tag, usize), TagError> {
    let first = match input.first() {
        Some(&b) => b,
        None => return Err(TagError::Truncated),
    };
    let class = match first >> 6 {
        0b00 => Class::Universal,
        0b01 => Class::Application,
        0b10 => Class::ContextSpecific,
        _ => Class::Private,
    };
    let constructed = (first & 0x20) != 0;
    if first & 0x1F != 0x1F {
        // low-tag form: the number is in the low 5 bits (0..=30)
        return Ok((
            Tag { class, constructed, number: (first & 0x1F) as u32 },
            1,
        ));
    }
    // high-tag form: base-128 continuation octets
    let mut number: u32 = 0;
    let mut i = 1usize;
    let mut count = 0usize;
    loop {
        let byte = match input.get(i) {
            Some(&b) => b,
            None => return Err(TagError::Truncated),
        };
        if count == 0 && byte == 0x80 {
            return Err(TagError::NonMinimal); // leading-zero continuation group
        }
        if number > (u32::MAX >> 7) {
            return Err(TagError::TooLarge); // a further 7-bit group would exceed u32
        }
        number = (number << 7) | (byte & 0x7F) as u32;
        count += 1;
        i += 1;
        if byte & 0x80 == 0 {
            break; // last octet (continuation bit clear)
        }
    }
    if number <= 30 {
        return Err(TagError::NonMinimal); // high-tag form for a low-tag-representable number
    }
    Ok((Tag { class, constructed, number }, i))
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    fn any_class() -> Class {
        let sel: u8 = kani::any();
        kani::assume(sel < 4);
        match sel {
            0 => Class::Universal,
            1 => Class::Application,
            2 => Class::ContextSpecific,
            _ => Class::Private,
        }
    }

    /// Round-trip: every `Tag` (any class, flag, and `u32` number) encodes to bytes that
    /// decode back to exactly that tag, consuming exactly the produced encoding.
    #[kani::proof]
    #[kani::unwind(12)]
    fn roundtrip_all_tags() {
        let tag = Tag { class: any_class(), constructed: kani::any(), number: kani::any() };
        let (buf, used) = encode_tag(tag);
        assert!(decode_tag(&buf[..used]) == Ok((tag, used)));
    }

    /// Robustness: `decode_tag` never panics or overflows on *any* input.
    ///
    /// Cover (T6 primary rule): witnesses that the symbolic 7-byte buffer actually reaches the
    /// `Ok` tail (both the low-tag single-octet form AND a genuine multi-octet high-tag form are
    /// live), not merely that malformed prefixes are rejected. Would NOT be SAT if `decode_tag`'s
    /// body were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_tag_never_panics() {
        let buf: [u8; 7] = kani::any();
        let result = decode_tag(&buf);
        kani::cover(result.is_ok(), "a well-formed identifier reaches decode_tag's Ok tail");
        if let Ok((_, used)) = result {
            kani::cover(used > 1, "a genuine multi-octet high-tag identifier is decoded (not just low-tag)");
        }
        let _ = result;
    }

    /// Canonicality: if `decode_tag` accepts a byte string, that string is the unique
    /// canonical encoding of the decoded tag (no non-minimal identifier is ever accepted).
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_tag_accepts_only_canonical() {
        let buf: [u8; 7] = kani::any();
        if let Ok((tag, used)) = decode_tag(&buf) {
            let (re, relen) = encode_tag(tag);
            assert!(relen == used);
            assert!(re[..relen] == buf[..used]);
        }
    }

    // --- Error-class correctness. ---

    /// High-tag form encoding a number `<= 30` (which must use the low-tag form) is `NonMinimal`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn high_tag_of_small_number_is_non_minimal() {
        let first: u8 = kani::any();
        kani::assume(first & 0x1F == 0x1F); // high-tag marker, any class/constructed
        let v: u8 = kani::any();
        kani::assume(v <= 30); // single continuation octet (bit8 clear), value <= 30
        assert!(decode_tag(&[first, v]) == Err(TagError::NonMinimal));
    }

    /// A high-tag form whose first continuation octet is `0x80` (leading-zero group) is `NonMinimal`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn leading_zero_high_tag_is_non_minimal() {
        let first: u8 = kani::any();
        kani::assume(first & 0x1F == 0x1F);
        let b2: u8 = kani::any();
        let b3: u8 = kani::any();
        assert!(decode_tag(&[first, 0x80, b2, b3]) == Err(TagError::NonMinimal));
    }

    /// A high-tag marker with no continuation octet is `Truncated`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn truncated_high_tag_is_classified() {
        let first: u8 = kani::any();
        kani::assume(first & 0x1F == 0x1F);
        assert!(decode_tag(&[first]) == Err(TagError::Truncated));
    }

    /// A high-tag form whose value exceeds `u32::MAX` is `TooLarge`.
    #[kani::proof]
    #[kani::unwind(12)]
    fn too_large_tag_is_classified() {
        let first: u8 = kani::any();
        kani::assume(first & 0x1F == 0x1F);
        // 0x10·128^4 = 2^32 > u32::MAX; first continuation octet 0x90 (nonzero, so not a
        // leading-zero false positive), then zero groups.
        assert!(decode_tag(&[first, 0x90, 0x80, 0x80, 0x80, 0x00]) == Err(TagError::TooLarge));
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn low_tag_examples_roundtrip() {
        // Universal INTEGER (number 2, primitive) = 0x02
        let t = Tag { class: Class::Universal, constructed: false, number: 2 };
        let (b, used) = encode_tag(t);
        assert_eq!(&b[..used], &[0x02]);
        assert_eq!(decode_tag(&b[..used]), Ok((t, 1)));

        // Universal SEQUENCE (number 16, constructed) = 0x30
        let t = Tag { class: Class::Universal, constructed: true, number: 16 };
        let (b, used) = encode_tag(t);
        assert_eq!(&b[..used], &[0x30]);
        assert_eq!(decode_tag(&b[..used]), Ok((t, 1)));

        // Context-specific [0], constructed = 0xA0
        let t = Tag { class: Class::ContextSpecific, constructed: true, number: 0 };
        let (b, used) = encode_tag(t);
        assert_eq!(&b[..used], &[0xA0]);
        assert_eq!(decode_tag(&b[..used]), Ok((t, 1)));
    }

    #[test]
    fn high_tag_examples_roundtrip() {
        // number 31 (smallest high-tag), universal primitive = [0x1F, 0x1F]
        let t = Tag { class: Class::Universal, constructed: false, number: 31 };
        let (b, used) = encode_tag(t);
        assert_eq!(&b[..used], &[0x1F, 0x1F]);
        assert_eq!(decode_tag(&b[..used]), Ok((t, 2)));

        // number 128 = [0x1F, 0x81, 0x00]
        let t = Tag { class: Class::Application, constructed: false, number: 128 };
        let (b, used) = encode_tag(t);
        assert_eq!(&b[..used], &[0x1F | 0x40, 0x81, 0x00]);
        assert_eq!(decode_tag(&b[..used]), Ok((t, 3)));

        // number u32::MAX round-trips
        let t = Tag { class: Class::Private, constructed: true, number: u32::MAX };
        let (b, used) = encode_tag(t);
        assert_eq!(decode_tag(&b[..used]), Ok((t, used)));
    }

    // --- seeded-bad specimens: each MUST be rejected ---
    #[test]
    fn rejects_truncated_high_tag() {
        assert_eq!(decode_tag(&[0x1F]), Err(TagError::Truncated));
    }
    #[test]
    fn rejects_high_tag_for_small_number() {
        // number 30 fits the low-tag form; high-tag form is non-canonical.
        assert_eq!(decode_tag(&[0x1F, 0x1E]), Err(TagError::NonMinimal));
    }
    #[test]
    fn rejects_high_tag_number_zero() {
        assert_eq!(decode_tag(&[0x1F, 0x00]), Err(TagError::NonMinimal));
    }
    #[test]
    fn rejects_leading_zero_continuation() {
        assert_eq!(decode_tag(&[0x1F, 0x80, 0x01]), Err(TagError::NonMinimal));
    }
    #[test]
    fn rejects_empty_input() {
        assert_eq!(decode_tag(&[]), Err(TagError::Truncated));
    }
}
