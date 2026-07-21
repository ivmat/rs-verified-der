//! DER BIT STRING content (X.690 §8.6, §11.2).
//!
//! Content is a leading **unused-bits** octet `u` (`0..=7`, §11.2.1) followed by the value octets;
//! `u` counts the unused low-order bits of the *final* value octet. DER (unlike BER) is canonical:
//! - §11.2.2 — every unused bit shall be **zero** (a non-zero padding bit is a classic parser
//!   differential: a lax reader ignores it, a strict signer never emits it);
//! - §11.2.2.1 — an *empty* bit string is exactly `[0x00]` (no value octets, and `u = 0`);
//! - the primitive/definite form is required (§10.2) — that constraint lives in the identifier and
//!   is enforced by [`crate::tag`]/[`crate::tlv`], so, like the other content decoders
//!   ([`crate::integer`], [`crate::boolean`]), this module validates the *content* octets of a TLV
//!   whose tag is UNIVERSAL 3 (`0x03`).
//!
//! **Scope — generic BIT STRING transfer syntax only.** §11.2 canonicality *preserves the
//! bit-length*: the 12-bit value `0001_0010_0000` (encoded `04 12 00`) is a **distinct** value from
//! the 8-bit `0001_0010` (encoded `00 12`), and each is canonical — this codec correctly accepts
//! both. It deliberately does **not** apply rules that live *above* the transfer syntax:
//! - **NamedBitList minimality** (X.680 §22.7, e.g. `KeyUsage`): trailing *named* zero bits are
//!   dropped in the canonical form. That is a property of the ASN.1 *type*, not of a bare BIT
//!   STRING, so it belongs to the schema layer — applying it here would reject valid values.
//! - **Octet alignment** (e.g. `SubjectPublicKeyInfo.subjectPublicKey`, which wraps a DER blob):
//!   callers needing a byte-aligned value must require `unused == 0` — see [`require_octet_aligned`].

/// The universal tag number for BIT STRING.
pub const TAG: u32 = 3;

/// A decoded DER BIT STRING: the value octets and the count of unused trailing bits (`0..=7`).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct BitString<'a> {
    /// The value octets (the leading unused-bits octet stripped). Empty for an empty bit string.
    pub data: &'a [u8],
    /// Unused low-order bits of the final `data` octet (`0..=7`; `0` when `data` is empty).
    pub unused: u8,
}

/// Why BIT STRING content was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BitStringError {
    /// Content was empty — a BIT STRING needs at least the unused-bits octet.
    Empty,
    /// The unused-bits octet was `> 7` (§11.2.1).
    UnusedBitsTooLarge,
    /// An unused (padding) bit of the final octet was set — forbidden by DER (§11.2.2).
    NonZeroPadding,
    /// No value octets, yet the unused-bits octet was non-zero — an empty bit string must be
    /// exactly `[0x00]` (§11.2.2.1).
    EmptyNonZeroUnused,
}

/// Decode BIT STRING content octets into the value octets + unused-bit count.
///
/// Accepts only the canonical DER form: unused-bits `0..=7`, all padding bits zero, and the empty
/// bit string encoded as exactly `[0x00]`.
///
/// ⚠️ **Commonly mis-read (see `DECISIONS.md` D1):** DER canonicality here *preserves bit-length*.
/// Trailing zero **value bits are NOT stripped** — `04 12 00` is the canonical encoding of the
/// distinct 12-bit value `0001_0010_0000`, and is accepted. Trailing-zero-*bit* removal is the
/// `NamedBitList` rule (X.680 §22.7), which applies only to typed fields like `KeyUsage`, not a bare
/// BIT STRING (confirmed by IETF PKIX + OSS Nokalva; even a PKIX expert once conflated the two). We
/// enforce only the padding-bits-zero half of §11.2.2, which *is* universal.
pub fn decode_bit_string(content: &[u8]) -> Result<BitString<'_>, BitStringError> {
    let (&unused, data) = match content.split_first() {
        Some(pair) => pair,
        None => return Err(BitStringError::Empty),
    };
    if unused > 7 {
        return Err(BitStringError::UnusedBitsTooLarge);
    }
    if data.is_empty() {
        // No value octets: the only canonical form is [0x00].
        if unused != 0 {
            return Err(BitStringError::EmptyNonZeroUnused);
        }
        return Ok(BitString { data, unused: 0 });
    }
    // `unused <= 7` so `1u8 << unused <= 0x80`: the shift and subtraction never overflow.
    let mask = (1u8 << unused) - 1; // the low `unused` bits of the final octet
    if data[data.len() - 1] & mask != 0 {
        return Err(BitStringError::NonZeroPadding);
    }
    Ok(BitString { data, unused })
}

/// Require a BIT STRING to be **octet-aligned** (`unused == 0`) and return its byte-aligned value.
///
/// Generic DER permits `unused != 0`, but several X.509 fields carry a byte-aligned payload — most
/// commonly `SubjectPublicKeyInfo.subjectPublicKey`, a BIT STRING wrapping a DER structure — where a
/// non-zero unused count is a *profile* violation and a real cross-parser differential. This is the
/// field-specific constraint the generic decoder cannot enforce; callers apply it explicitly.
/// Returns `None` if `bs` has unused bits.
pub fn require_octet_aligned<'a>(bs: BitString<'a>) -> Option<&'a [u8]> {
    if bs.unused == 0 {
        Some(bs.data)
    } else {
        None
    }
}

/// Encode value octets + `unused` trailing-bit count as canonical DER BIT STRING content
/// (`[unused, data...]`) into `out`.
///
/// Returns the number of bytes written, or `None` if the arguments are not canonical (`unused > 7`,
/// a set padding bit, or empty `data` with `unused != 0`) or `out` is too small. The canonicality
/// guard makes `encode`/`decode` exact inverses on the accepted set.
pub fn encode_bit_string_into(data: &[u8], unused: u8, out: &mut [u8]) -> Option<usize> {
    if unused > 7 {
        return None;
    }
    if data.is_empty() {
        if unused != 0 {
            return None;
        }
    } else {
        let mask = (1u8 << unused) - 1;
        if data[data.len() - 1] & mask != 0 {
            return None;
        }
    }
    // A `&[u8]` cannot exceed `isize::MAX` bytes (Rust's slice-size invariant), so `1 + len` never
    // overflows `usize` on any target — the same reasoning that keeps `encode_tlv_into`'s total safe.
    let total = 1 + data.len();
    if out.len() < total {
        return None;
    }
    out[0] = unused;
    out[1..total].copy_from_slice(data);
    Some(total)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Round-trip: any *canonical* (data, unused) encodes to content that decodes back to exactly
    /// it. Canonicality is imposed symbolically (clear the padding bits; force `unused = 0` when
    /// empty) so the whole accepted set is covered, not a hand-picked case.
    #[kani::proof]
    #[kani::unwind(8)]
    fn roundtrip_canonical() {
        let mut data: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        let raw: u8 = kani::any();
        kani::assume(raw <= 7);
        let unused = if n == 0 { 0 } else { raw };
        if n > 0 {
            let mask = (1u8 << unused) - 1;
            data[n - 1] &= !mask; // make the padding bits zero -> canonical
        }
        let mut out = [0u8; 8];
        let w = encode_bit_string_into(&data[..n], unused, &mut out).unwrap();
        let bs = decode_bit_string(&out[..w]).unwrap();
        assert!(bs.unused == unused);
        assert!(bs.data == &data[..n]);
    }

    /// Robustness: `decode_bit_string` never panics/overflows. The decision reads only the first
    /// octet and — under a non-empty guard — the last, so it is length-independent: a 6-octet
    /// symbolic buffer exercises every branch (empty, unused-only, single- and multi-octet value).
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached for a genuine multi-octet value
    /// (not just the trivial empty-bit-string `[0x00]` case), so the padding-mask arithmetic on
    /// `data[data.len() - 1]` is actually exercised. Would NOT be SAT if `decode_bit_string`'s body
    /// were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn decode_never_panics() {
        let buf: [u8; 6] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 6);
        let result = decode_bit_string(&buf[..n]);
        kani::cover(result.is_ok(), "a well-formed BIT STRING reaches decode_bit_string's Ok tail");
        if let Ok(bs) = result {
            kani::cover(
                !bs.data.is_empty(),
                "a non-empty BIT STRING value is accepted (exercises the trailing-padding-mask check)",
            );
        }
        let _ = result;
    }

    /// Canonicality: any accepted content re-encodes to *itself* — so `decode` admits a byte
    /// string only if it is the unique canonical encoding of the decoded value.
    #[kani::proof]
    #[kani::unwind(8)]
    fn decode_accepts_only_canonical() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        if let Ok(bs) = decode_bit_string(&buf[..n]) {
            let mut out = [0u8; 8];
            let w = encode_bit_string_into(bs.data, bs.unused, &mut out).unwrap();
            assert!(w == n);
            assert!(out[..w] == buf[..n]);
        }
    }

    // --- Error-class correctness. ---

    /// Empty content is `Empty`.
    #[kani::proof]
    fn empty_is_classified() {
        assert!(decode_bit_string(&[]) == Err(BitStringError::Empty));
    }

    /// An unused-bits octet `> 7` is `UnusedBitsTooLarge`, with or without a following octet.
    #[kani::proof]
    #[kani::unwind(6)]
    fn unused_too_large_is_classified() {
        let u: u8 = kani::any();
        kani::assume(u > 7);
        let d: u8 = kani::any();
        assert!(decode_bit_string(&[u]) == Err(BitStringError::UnusedBitsTooLarge));
        assert!(decode_bit_string(&[u, d]) == Err(BitStringError::UnusedBitsTooLarge));
    }

    /// A set padding bit in the final octet is `NonZeroPadding` (the DER canonicality core).
    #[kani::proof]
    #[kani::unwind(6)]
    fn nonzero_padding_is_classified() {
        let unused: u8 = kani::any();
        kani::assume(unused >= 1 && unused <= 7);
        let last: u8 = kani::any();
        let mask = (1u8 << unused) - 1;
        kani::assume(last & mask != 0); // at least one unused bit is set
        assert!(decode_bit_string(&[unused, last]) == Err(BitStringError::NonZeroPadding));
    }

    /// No value octets but a non-zero unused count is `EmptyNonZeroUnused` (empty must be `[0x00]`).
    #[kani::proof]
    fn empty_nonzero_unused_is_classified() {
        let u: u8 = kani::any();
        kani::assume(u >= 1 && u <= 7);
        assert!(decode_bit_string(&[u]) == Err(BitStringError::EmptyNonZeroUnused));
    }

    /// `require_octet_aligned` yields the value exactly when there are no unused bits, and returns
    /// the value octets unchanged — the field-specific octet-alignment check for the SPKI class.
    #[kani::proof]
    #[kani::unwind(8)]
    fn octet_aligned_iff_unused_zero() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        if let Ok(bs) = decode_bit_string(&buf[..n]) {
            match require_octet_aligned(bs) {
                Some(d) => {
                    assert!(bs.unused == 0);
                    assert!(d == bs.data);
                }
                None => assert!(bs.unused != 0),
            }
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
    fn accepts_empty_bit_string() {
        // 0x00 = zero unused bits, no value octets = the empty bit string
        let bs = decode_bit_string(&[0x00]).unwrap();
        assert_eq!(bs.data, &[] as &[u8]);
        assert_eq!(bs.unused, 0);
    }

    #[test]
    fn accepts_full_octet() {
        // 0x00 0xFF = 8 bits, none unused
        let bs = decode_bit_string(&[0x00, 0xFF]).unwrap();
        assert_eq!(bs.data, &[0xFF]);
        assert_eq!(bs.unused, 0);
    }

    #[test]
    fn accepts_partial_octet_with_zero_padding() {
        // 0x04 0xF0 = 4 bits used (top nibble), low 4 bits are zero padding -> canonical
        let bs = decode_bit_string(&[0x04, 0xF0]).unwrap();
        assert_eq!(bs.data, &[0xF0]);
        assert_eq!(bs.unused, 4);
    }

    #[test]
    fn roundtrips_via_encode() {
        let mut out = [0u8; 16];
        let w = encode_bit_string_into(&[0xF0], 4, &mut out).unwrap();
        assert_eq!(&out[..w], &[0x04, 0xF0]);
        let bs = decode_bit_string(&out[..w]).unwrap();
        assert_eq!(bs.data, &[0xF0]);
        assert_eq!(bs.unused, 4);
    }

    // --- seeded-bad specimens: each MUST be rejected ---
    #[test]
    fn rejects_empty_content() {
        assert_eq!(decode_bit_string(&[]), Err(BitStringError::Empty));
    }
    #[test]
    fn rejects_unused_bits_over_seven() {
        // 0x08 = 8 unused bits, impossible in a single octet (§11.2.1)
        assert_eq!(decode_bit_string(&[0x08, 0x00]), Err(BitStringError::UnusedBitsTooLarge));
    }
    #[test]
    fn rejects_nonzero_padding() {
        // 0x01 0x01 = 1 unused bit, but the low bit is SET. BER-lax accepts; DER must reject.
        assert_eq!(decode_bit_string(&[0x01, 0x01]), Err(BitStringError::NonZeroPadding));
    }
    #[test]
    fn rejects_empty_with_nonzero_unused() {
        // 0x03 = 3 unused bits but no value octet -> an empty bit string must be exactly [0x00]
        assert_eq!(decode_bit_string(&[0x03]), Err(BitStringError::EmptyNonZeroUnused));
    }
    #[test]
    fn encode_rejects_noncanonical_padding() {
        // the encoder refuses to emit a non-canonical padding bit
        let mut out = [0u8; 4];
        assert_eq!(encode_bit_string_into(&[0x01], 1, &mut out), None);
    }

    // --- canonicality boundary (a review HIGH false positive, memorialized) ---
    #[test]
    fn accepts_trailing_zero_bits_as_distinct_value() {
        // 04 12 00 is the CANONICAL encoding of the 12-bit string 0001_0010_0000 — a DISTINCT value
        // from the 8-bit 00 12 (0001_0010). Generic DER preserves bit-length (§11.2); trailing-zero
        // *bit* stripping is a NamedBitList rule (X.680 §22.7), not applicable to a bare BIT STRING.
        // MUST be accepted — rejecting it (a reviewer's suggested "fix") would drop valid values.
        let bs = decode_bit_string(&[0x04, 0x12, 0x00]).unwrap();
        assert_eq!(bs.data, &[0x12, 0x00]);
        assert_eq!(bs.unused, 4);
    }

    // --- field-specific octet alignment (require_octet_aligned) ---
    #[test]
    fn octet_aligned_accepts_zero_unused() {
        // 00 30 00 = an octet-aligned 2-byte payload (e.g. the start of a wrapped DER blob)
        let bs = decode_bit_string(&[0x00, 0x30, 0x00]).unwrap();
        assert_eq!(require_octet_aligned(bs), Some(&[0x30, 0x00][..]));
    }
    #[test]
    fn octet_aligned_rejects_unused_bits() {
        // 04 F0 = 4 unused bits -> not byte-aligned -> rejected where octet alignment is required
        let bs = decode_bit_string(&[0x04, 0xF0]).unwrap();
        assert_eq!(require_octet_aligned(bs), None);
    }
}
