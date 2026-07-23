//! DER TLV (tag-length-value) reader — composes [`crate::tag`] + [`crate::length`] into the
//! fundamental X.690 structural unit.
//!
//! A TLV is an identifier, a definite length `L`, then exactly `L` content octets. This reader
//! returns the decoded tag and a borrowed slice of the value; the caller recurses into the value
//! for constructed types. DER's definite-length requirement is inherited from the length codec
//! (indefinite `0x80` is already rejected there). The security-critical property proven here is
//! **no over-read**: an accepted TLV never claims or exposes bytes beyond the input.

use crate::length::{decode_length, encode_length, LengthError};
use crate::tag::{decode_tag, encode_tag, Tag, TagError};

/// A decoded DER TLV: the identifier and a borrow of exactly the value octets.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Tlv<'a> {
    /// The decoded identifier (class, constructed flag, tag number).
    pub tag: Tag,
    /// A borrow of exactly the value octets (the `V` in TLV) — no copy.
    pub value: &'a [u8],
}

/// Why a TLV was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TlvError {
    /// The identifier octet(s) were malformed.
    Tag(TagError),
    /// The length field was malformed.
    Length(LengthError),
    /// Fewer value octets are present than the length field declares.
    Truncated,
    /// The declared length does not fit this machine's address space (`usize`) — a
    /// portability guard, reachable only on targets where `usize` is narrower than the
    /// length (e.g. 16-bit); never taken on 32/64-bit.
    LengthTooLarge,
    /// Strict decode only: bytes remain after a complete TLV (see [`decode_tlv_strict`]).
    TrailingData,
}

/// Decode one DER TLV from the front of `input`.
///
/// On success returns the [`Tlv`] and the total bytes consumed (`tag + length + value`). The
/// value borrow is exactly the declared number of octets; the function never panics and never
/// reads past `input`.
///
/// **Trailing bytes are ignored** — this reads exactly one TLV so it can drive recursive parsing
/// of constructed values. If the entire `input` must be a single TLV (e.g. a signature block),
/// use [`decode_tlv_strict`].
pub fn decode_tlv(input: &[u8]) -> Result<(Tlv<'_>, usize), TlvError> {
    // NOTE: the closures below (`|e| TlvError::Tag(e)`) are deliberately NOT the point-free
    // `TlvError::Tag`/`TlvError::Length` form (behaviorally identical): Aeneas materializes a
    // point-free enum-variant-as-value reference as a standalone function whose auto-generated
    // name collides with the variant's own qualified constructor name ("name clash" error),
    // blocking Lean extraction. This is the `tlv` lid's own instance of the `writing-verifiable-
    // rust.md` §4 "write for Aeneas extraction" guidance — a pure style change, re-verified by
    // the unchanged Kani harnesses + tests below (see D-series decision log).
    // `clippy::redundant_closure` would rewrite these to the point-free `TlvError::Tag` /
    // `TlvError::Length` form, which reintroduces the Aeneas name-clash described in the NOTE
    // above and breaks Lean extraction — so the closures are load-bearing, not redundant.
    #[allow(clippy::redundant_closure)]
    let (tag, t_used) = decode_tag(input).map_err(|e| TlvError::Tag(e))?;
    #[allow(clippy::redundant_closure)]
    let (len_u32, l_used) = decode_length(&input[t_used..]).map_err(|e| TlvError::Length(e))?;
    let header = t_used + l_used;
    // Portability: `decode_length` yields a u32; on targets where `usize` is narrower this
    // could truncate, so convert fallibly rather than `as`-cast. Unreachable on 32/64-bit.
    let len = match usize::try_from(len_u32) {
        Ok(l) => l,
        Err(_) => return Err(TlvError::LengthTooLarge),
    };
    // Overflow-safe: reject a header+len beyond the address space, then require the value present.
    let end = match header.checked_add(len) {
        Some(e) => e,
        None => return Err(TlvError::LengthTooLarge),
    };
    if input.len() < end {
        return Err(TlvError::Truncated);
    }
    Ok((Tlv { tag, value: &input[header..end] }, end))
}

/// Decode one DER TLV, requiring it to consume the *entire* `input` (no trailing bytes).
///
/// Use this where a slice must be exactly one TLV; [`decode_tlv`] deliberately ignores trailing
/// bytes so it can drive recursive parsers, which is unsafe for top-level "the whole blob is one
/// object" contexts (an attacker could append ignored data).
pub fn decode_tlv_strict(input: &[u8]) -> Result<Tlv<'_>, TlvError> {
    let (tlv, used) = decode_tlv(input)?;
    if used != input.len() {
        return Err(TlvError::TrailingData);
    }
    Ok(tlv)
}

/// Encode a TLV (`tag`, then `value.len()` as a DER length, then `value`) into `out`.
///
/// Returns the number of bytes written, or `None` if `out` is too small or `value` is longer
/// than the length codec supports (`> u32::MAX`).
pub fn encode_tlv_into(tag: Tag, value: &[u8], out: &mut [u8]) -> Option<usize> {
    if value.len() > u32::MAX as usize {
        return None;
    }
    let (tbuf, t) = encode_tag(tag);
    let (lbuf, l) = encode_length(value.len() as u32);
    let total = t + l + value.len();
    if out.len() < total {
        return None;
    }
    out[..t].copy_from_slice(&tbuf[..t]);
    out[t..t + l].copy_from_slice(&lbuf[..l]);
    out[t + l..total].copy_from_slice(value);
    Some(total)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;
    use crate::tag::Class;

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

    /// Robustness: `decode_tlv` never panics or overflows on *any* input. The 16-byte buffer
    /// covers the maximal header (6-byte high-tag + 5-byte long length = 11) plus value octets,
    /// so every header construct is exercised (the review's HIGH bounds-gap fix).
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached with a non-empty value AND,
    /// separately, that a genuine multi-octet header (tag+length together > 2 bytes) is decoded —
    /// so both the tag and length sub-decodes' non-trivial branches are live, not just the
    /// minimal 1-tag-octet/1-length-octet/0-value case. Would NOT be SAT if `decode_tlv`'s body
    /// were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_tlv_never_panics() {
        let buf: [u8; 16] = kani::any();
        let result = decode_tlv(&buf);
        kani::cover(result.is_ok(), "a well-formed TLV reaches decode_tlv's Ok tail");
        if let Ok((tlv, used)) = result {
            kani::cover(!tlv.value.is_empty(), "a non-empty TLV value is accepted");
            kani::cover(used > 2, "a genuine multi-octet header (beyond the minimal 1+1+0 form) is decoded");
        }
        let _ = result;
    }

    /// Structural correctness + **no over-read**: an accepted TLV consumes exactly
    /// `header + declared_length` bytes, its value borrow is exactly those value octets, and
    /// the total never exceeds the input.
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_tlv_structure() {
        let buf: [u8; 16] = kani::any();
        if let Ok((tlv, used)) = decode_tlv(&buf) {
            // Re-derive the header independently; the unwraps hold because decode_tlv only
            // returns Ok after both sub-decodes succeeded on these same bytes.
            let (_t, t_used) = decode_tag(&buf).unwrap();
            let (len_u32, l_used) = decode_length(&buf[t_used..]).unwrap();
            let header = t_used + l_used;
            // Oracle stated in SPEC terms: compare the consumed and value-borrow counts against
            // the *declared* length widened losslessly to `u64` — never re-using the impl's own
            // `as usize` cast. Asserting `== len as usize` would be tautological: a truncating
            // `len_u32 as usize` in `decode_tlv` (a known seeded-defect class) would be mirrored by the
            // identical cast here and stay invisible. The residual portability truncation is
            // caught *in code* by the `usize::try_from` guard (→ `LengthTooLarge`), not by this
            // proof: Kani models `usize` as 64-bit, so on this host the cast is lossless anyway.
            assert!(used as u64 == header as u64 + len_u32 as u64);
            assert!(tlv.value.len() as u64 == len_u32 as u64);
            assert!(used <= buf.len());
            assert!(tlv.value == &buf[header..used]);
        }
    }

    /// Round-trip: any tag + short value encodes to a TLV that decodes back to exactly it.
    #[kani::proof]
    #[kani::unwind(16)]
    fn tlv_roundtrip_small() {
        let tag = Tag { class: any_class(), constructed: kani::any(), number: kani::any() };
        let value: [u8; 3] = kani::any();
        let mut out = [0u8; 16]; // 6 (tag) + 5 (len) + 3 (value) = 14 fits
        let n = encode_tlv_into(tag, &value, &mut out).unwrap();
        let (tlv, used) = decode_tlv(&out[..n]).unwrap();
        assert!(tlv.tag == tag);
        assert!(tlv.value == &value[..]);
        assert!(used == n);
    }

    /// A value shorter than the length field declares is rejected as `Truncated`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn tlv_truncated_value_is_classified() {
        // tag 0x02 (INTEGER, 1 byte), length 0x05, but only 2 value bytes follow.
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        assert!(decode_tlv(&[0x02, 0x05, a, b]) == Err(TlvError::Truncated));
    }

    /// Strict decode rejects any trailing byte after a complete TLV.
    #[kani::proof]
    #[kani::unwind(16)]
    fn strict_rejects_trailing() {
        // a valid 1-byte-value INTEGER TLV (consumes 3) plus one trailing byte (input len 4).
        let v: u8 = kani::any();
        let t: u8 = kani::any();
        assert!(decode_tlv_strict(&[0x02, 0x01, v, t]) == Err(TlvError::TrailingData));
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tag::Class;

    #[test]
    fn decodes_simple_integer_tlv() {
        // 02 01 07  =  INTEGER 7
        let (tlv, used) = decode_tlv(&[0x02, 0x01, 0x07]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(tlv.tag, Tag { class: Class::Universal, constructed: false, number: 2 });
        assert_eq!(tlv.value, &[0x07]);
    }

    #[test]
    fn decodes_empty_value() {
        // 05 00  =  NULL
        let (tlv, used) = decode_tlv(&[0x05, 0x00]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(tlv.value, &[] as &[u8]);
    }

    #[test]
    fn roundtrips_via_encode() {
        let tag = Tag { class: Class::ContextSpecific, constructed: true, number: 3 };
        let value = [0xDE, 0xAD, 0xBE, 0xEF];
        let mut out = [0u8; 32];
        let n = encode_tlv_into(tag, &value, &mut out).unwrap();
        let (tlv, used) = decode_tlv(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(tlv.tag, tag);
        assert_eq!(tlv.value, &value);
    }

    #[test]
    fn trailing_bytes_are_not_consumed() {
        // one TLV followed by extra bytes: only the first TLV is consumed
        let (tlv, used) = decode_tlv(&[0x02, 0x01, 0x07, 0xFF, 0xFF]).unwrap();
        assert_eq!(used, 3);
        assert_eq!(tlv.value, &[0x07]);
    }

    #[test]
    fn strict_accepts_exact_tlv() {
        let tlv = decode_tlv_strict(&[0x02, 0x01, 0x07]).unwrap();
        assert_eq!(tlv.value, &[0x07]);
    }

    #[test]
    fn strict_rejects_trailing_bytes() {
        assert_eq!(decode_tlv_strict(&[0x02, 0x01, 0x07, 0xFF]), Err(TlvError::TrailingData));
    }

    // --- seeded-bad specimens ---
    #[test]
    fn rejects_truncated_value() {
        // declares 5 value bytes, only 1 present
        assert_eq!(decode_tlv(&[0x02, 0x05, 0xAA]), Err(TlvError::Truncated));
    }
    #[test]
    fn rejects_indefinite_length_via_length_codec() {
        // 0x80 length = indefinite, forbidden in DER
        assert_eq!(
            decode_tlv(&[0x30, 0x80, 0x00, 0x00]),
            Err(TlvError::Length(LengthError::Indefinite))
        );
    }
    #[test]
    fn rejects_bad_tag() {
        // 0xFF is a reserved initial identifier octet path -> high-tag truncated here
        assert_eq!(decode_tlv(&[0x1F]), Err(TlvError::Tag(TagError::Truncated)));
    }
    #[test]
    fn rejects_empty_input() {
        assert_eq!(decode_tlv(&[]), Err(TlvError::Tag(TagError::Truncated)));
    }
}
