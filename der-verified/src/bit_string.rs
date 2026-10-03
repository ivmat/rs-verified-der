//! DER BIT STRING content (X.690 §8.6, §11.2).
//!
//! Content is a leading **unused-bits** octet `u` (`0..=7`, §11.2.1) followed by the value octets;
//! `u` counts the unused low-order bits of the *final* value octet. DER (unlike BER) is canonical:
//! - §11.2.2 — every unused bit shall be **zero** (a non-zero padding bit is a classic parser
//!   differential: a lax reader ignores it, a strict signer never emits it);
//! - §11.2.2.1 — an *empty* bit string is exactly `[0x00]` (no value octets, and `u = 0`);
//! - the primitive/definite form is required (§10.2) — the *primitive* half is a constraint on the
//!   identifier octet, the *definite* half a constraint on the length field. **This module enforces
//!   neither.** Read the next paragraph before assuming something else does.
//!
//! **Who enforces the identifier — precisely.** Like the other content decoders
//! ([`crate::integer`], [`crate::boolean`]), this module validates only the *content* octets of a
//! TLV whose tag is UNIVERSAL 3 (`0x03`). It does not look at the identifier at all. Splitting the
//! §10.2 requirement into its two halves:
//! - the **definite**-length half *is* enforced upstream — **but only if you actually came through
//!   [`crate::tlv`]**, which delegates to [`crate::length`] and so rejects the indefinite form
//!   (`0x80`). This function takes content octets, so it has no way to know whether you did;
//! - the **primitive**-form half and the **tag identity** (UNIVERSAL 3) are enforced by *neither*
//!   [`crate::tag`] nor [`crate::tlv`]. `decode_tag` attaches no meaning to the class/constructed
//!   combination and `decode_tlv` passes the parsed `Tag` through untouched; neither has so much as
//!   a "constructed" rejection.
//!
//! Where each IS decided — and note the two are **not** decided in the same place:
//! - **tag identity (this is UNIVERSAL 3, and not something else) is decided ONLY by typed
//!   callers.** `x509_spki.rs`'s `decode_public_key_tlv` (wrong tag → `PublicKeyWrongTag`,
//!   constructed → `PublicKeyConstructed`) and `x509_certificate.rs`'s signatureValue step
//!   (→ `SignatureValueWrongTag`) both check it before calling in.
//! - **the primitive-form rule is decided generically by [`crate::identifier_form`]** — but that
//!   module decides *form only*. It has no idea which tag you expected, and will happily accept a
//!   primitive INTEGER identifier where you wanted a BIT STRING. It is not a substitute for the
//!   identity check above.
//!
//! **So a direct caller of [`decode_bit_string`] must decide the identifier itself.** Handing this
//! function the content of a constructed `0x23` TLV, or of a TLV that is not UNIVERSAL 3 at all,
//! will not be caught here.
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
//!
//! # Examples
//!
//! ```
//! use der_verified::bit_string::decode_bit_string;
//!
//! // 0x04 0xF0 = 4 bits used (top nibble); the low 4 padding bits are zero -> canonical.
//! let bs = decode_bit_string(&[0x04, 0xF0]).unwrap();
//! assert_eq!(bs.data, &[0xF0]);
//! assert_eq!(bs.unused, 4);
//! ```

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
/// **Error precedence.** Content that breaks more than one rule reports the first of these checks
/// that fails, in this order: [`BitStringError::Empty`] (no content at all), then
/// [`BitStringError::UnusedBitsTooLarge`] (first octet `> 7`), then, only for a first octet `<= 7`,
/// either [`BitStringError::NonZeroPadding`] (value octets present and a padding bit of the final
/// one set) or [`BitStringError::EmptyNonZeroUnused`] (no value octets and a non-zero count). The
/// last two cannot both apply to the same content (one needs value octets, the other none), so the
/// only overlap is `UnusedBitsTooLarge`, which precedes both: `[9]` is `UnusedBitsTooLarge`, not
/// `EmptyNonZeroUnused`, and `[9, x, ..]` is `UnusedBitsTooLarge` whatever the final octet holds.
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
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
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
            data[n - 1] = (data[n - 1] >> unused) << unused; // make the padding bits zero -> canonical
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
            // the decoded fields are the input octets themselves: unused count = octet 0, value =
            // the rest (so a decoder that dropped or shifted a field is caught directly)
            assert!(n >= 1);
            assert!(bs.unused == buf[0]);
            assert!(bs.data == &buf[1..n]);
            // canonical shape, stated without the decoder's mask expression: at most 7 unused bits,
            // the final value octet has at least `unused` trailing zero bits, and empty means `[0x00]`
            assert!(bs.unused <= 7);
            if bs.data.is_empty() {
                assert!(bs.unused == 0);
            } else {
                assert!(bs.data[bs.data.len() - 1].trailing_zeros() >= bs.unused as u32);
            }
            let mut out = [0u8; 8];
            let w = encode_bit_string_into(bs.data, bs.unused, &mut out).unwrap();
            assert!(w == n);
            assert!(out[..w] == buf[..n]);
        }
    }

    /// Accept-set biconditional: `decode_bit_string` accepts a content exactly when it is
    /// non-empty, its first octet (the unused-bits count) is `<= 7`, and the final value octet has
    /// at least that many trailing zero bits (an empty value requires the count to be `0`). The
    /// predicate is written with `trailing_zeros`, not the decoder's `(1 << unused) - 1` mask.
    #[kani::proof]
    #[kani::unwind(8)]
    fn accepted_iff_canonical_oracle() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let canonical = n >= 1
            && buf[0] <= 7
            && if n == 1 { buf[0] == 0 } else { buf[n - 1].trailing_zeros() >= buf[0] as u32 };
        kani::cover!(canonical && n >= 2 && buf[0] > 0);
        kani::cover!(!canonical && n >= 2 && buf[0] <= 7);
        assert!(decode_bit_string(&buf[..n]).is_ok() == canonical);
    }

    /// Encoder soundness, including its reject path: for *any* `(data <= 3 octets, unused, out
    /// capacity 0..=8)` the encoder returns `Some(1 + data.len())` and writes `[unused, data...]`
    /// exactly when the arguments are canonical (`unused <= 7`, the final value octet has at least
    /// `unused` trailing zero bits, empty data needs `unused == 0`) and `out` is large enough; in
    /// every other case it returns `None`. The canonical predicate uses `trailing_zeros`, not the
    /// encoder's `(1 << unused) - 1` mask. The output buffer starts SYMBOLIC (8 octets), and the
    /// documented write contract ("on `None` nothing is written to `out`; on `Some(n)` only
    /// `out[..n]` is written") is asserted for every input: `out` unchanged on `None`, `out[n..]`
    /// unchanged on `Some(n)` -- so an encoder that writes past the `total` octets it reports fails.
    #[kani::proof]
    #[kani::unwind(10)]
    fn encode_rejects_exactly_the_non_canonical() {
        let data: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        let unused: u8 = kani::any();
        let cap: usize = kani::any();
        kani::assume(cap <= 8);
        let backing: [u8; 8] = kani::any();
        let mut out = backing;
        let canonical = unused <= 7
            && if n == 0 { unused == 0 } else { data[n - 1].trailing_zeros() >= unused as u32 };
        kani::cover!(canonical && n >= 1 && unused > 0 && cap >= n + 1);
        kani::cover!(unused > 7);
        kani::cover!(unused <= 7 && n >= 1 && !canonical);
        kani::cover!(unused >= 1 && unused <= 7 && n == 0);
        kani::cover!(canonical && cap < n + 1);
        let r = encode_bit_string_into(&data[..n], unused, &mut out[..cap]);
        // Rustdoc write contract: `None` => nothing written; `Some(n)` => only `out[..n]` written.
        match r {
            None => assert!(out == backing),
            Some(w) => assert!(out[w..] == backing[w..]),
        }
        if canonical && cap >= n + 1 {
            assert!(r == Some(n + 1));
            assert!(out[0] == unused);
            assert!(out[1..n + 1] == data[..n]);
            assert!(out[n + 1..] == backing[n + 1..]);
        } else {
            assert!(r == None);
        }
    }

    /// TOTAL reference for BIT STRING content: the exact `Result`, every error variant, in the
    /// precedence the `decode_bit_string` rustdoc states ("Error precedence"): `Empty` (no content
    /// at all), then `UnusedBitsTooLarge` (first octet `> 7`), then `NonZeroPadding` (a set unused
    /// bit in the final value octet) or `EmptyNonZeroUnused` (no value octets with a non-zero
    /// count). The last two exclude each other (one needs value octets, the other none), so the only
    /// precedence the rustdoc decides is `UnusedBitsTooLarge` before both of them -- the overlap
    /// cases `[9]` and `[9, x, ..]`. Nothing here is inferred beyond that documented order.
    ///
    /// Built unlike the decoder: the padding test walks the unused bit positions one by one (bit
    /// `k` of the final octet for `k < unused`) instead of forming a mask, and the answer is one
    /// precedence-ordered `if` chain.
    fn reference_bit_string(c: &[u8]) -> Result<BitString<'_>, BitStringError> {
        let nonempty = !c.is_empty();
        let count = if nonempty { c[0] } else { 0 };
        let has_value = c.len() >= 2;
        let mut padding_bit_set = false;
        if has_value && count <= 7 {
            let last = c[c.len() - 1];
            let mut k = 0u8;
            while k < count {
                if (last >> k) & 1 == 1 {
                    padding_bit_set = true;
                }
                k += 1;
            }
        }
        if !nonempty {
            Err(BitStringError::Empty)
        } else if count > 7 {
            Err(BitStringError::UnusedBitsTooLarge)
        } else if padding_bit_set {
            Err(BitStringError::NonZeroPadding)
        } else if !has_value && count != 0 {
            Err(BitStringError::EmptyNonZeroUnused)
        } else {
            Ok(BitString { data: &c[1..], unused: count })
        }
    }

    /// **Exact-result classification:** over a fully symbolic
    /// 6-octet buffer and every length `0..=6`, `decode_bit_string(content) ==
    /// reference_bit_string(content)` -- the exact `Result`, including which error and the
    /// documented precedence on overlapping invalidity (`UnusedBitsTooLarge` over the other two) and
    /// the decoded `data` / `unused` on `Ok`. So a decoder that returns a different error only for
    /// one content length (for instance only for three-octet content) is caught, which the accept
    /// biconditional and the two-octet-only `nonzero_padding_is_classified` could not see. Covers:
    /// every error variant and both accepting shapes (empty value, non-empty value with padding)
    /// reach the assert, plus the two overlap cases.
    #[kani::proof]
    #[kani::unwind(8)]
    fn decode_is_exactly_the_reference() {
        let buf: [u8; 6] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 6);
        let c = &buf[..n];
        let got = decode_bit_string(c);
        let want = reference_bit_string(c);
        assert!(got == want);
        kani::cover(got == Err(BitStringError::Empty), "Empty reaches the exact-result assert");
        kani::cover(
            got == Err(BitStringError::UnusedBitsTooLarge),
            "UnusedBitsTooLarge reaches the exact-result assert",
        );
        kani::cover(got == Err(BitStringError::NonZeroPadding), "NonZeroPadding reaches the exact-result assert");
        kani::cover(
            got == Err(BitStringError::NonZeroPadding) && n == 3,
            "NonZeroPadding on three-octet content reaches the exact-result assert",
        );
        kani::cover(
            got == Err(BitStringError::EmptyNonZeroUnused),
            "EmptyNonZeroUnused reaches the exact-result assert",
        );
        kani::cover(matches!(got, Ok(bs) if bs.data.is_empty()), "the empty bit string is accepted");
        kani::cover(
            matches!(got, Ok(bs) if !bs.data.is_empty() && bs.unused > 0),
            "a non-empty value with padding is accepted",
        );
        kani::cover(
            got == Err(BitStringError::UnusedBitsTooLarge) && n == 1,
            "overlap: a too-large count with no value octets is UnusedBitsTooLarge, not EmptyNonZeroUnused",
        );
        kani::cover(
            got == Err(BitStringError::UnusedBitsTooLarge) && n >= 2 && buf[n - 1] != 0,
            "overlap: a too-large count with a non-zero final octet is UnusedBitsTooLarge",
        );
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
        kani::assume(last.trailing_zeros() < unused as u32); // at least one unused bit is set
        kani::cover!(unused == 7 && last == 0x01);
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

    /// `require_octet_aligned` on a **hand-built** `BitString` (its fields are public, so a caller
    /// can construct values the decoder never yields, including `unused > 7`): over symbolic data
    /// (`0..=3` octets) and an unrestricted symbolic `u8` `unused`, the result is EXACTLY
    /// `Some(data)` -- the very same octets -- when `unused == 0`, and `None` for every other count,
    /// legal (`1..=7`) or not (`8..=255`). The decoded-value harness above cannot reach
    /// `unused > 7`; this one does. Covers: all three classes of count reach the assert.
    #[kani::proof]
    #[kani::unwind(8)]
    fn require_octet_aligned_exact_on_built_values() {
        let buf: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        let unused: u8 = kani::any();
        let built = BitString { data: &buf[..n], unused };
        let got = require_octet_aligned(built);
        kani::cover!(unused == 0 && n >= 1, "octet-aligned non-empty value");
        kani::cover!(unused >= 1 && unused <= 7, "legal non-zero unused count");
        kani::cover!(unused > 7, "unused count beyond the legal range");
        let want = match unused {
            0 => Some(&buf[..n]),
            _ => None,
        };
        assert!(got == want);
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
    #[test]
    fn encode_rejects_unused_over_seven() {
        // unused = 8 is impossible in a single octet (§11.2.1) -- rejected before any data check.
        let mut out = [0u8; 4];
        assert_eq!(encode_bit_string_into(&[0xF0], 8, &mut out), None);
    }
    #[test]
    fn encode_rejects_empty_data_with_nonzero_unused() {
        // no value octets but unused != 0: an empty bit string must be exactly [0x00].
        let mut out = [0u8; 4];
        assert_eq!(encode_bit_string_into(&[], 3, &mut out), None);
    }
    #[test]
    fn encode_accepts_empty_data_with_zero_unused() {
        // the canonical empty-data counterpart: unused == 0 with no value octets succeeds ([0x00]).
        let mut out = [0u8; 4];
        assert_eq!(encode_bit_string_into(&[], 0, &mut out), Some(1));
        assert_eq!(&out[..1], &[0x00]);
    }
    #[test]
    fn encode_rejects_output_buffer_too_small() {
        // canonical (data, unused) = ([0xF0], 4) needs 2 bytes; a 1-byte buffer is too small.
        let mut out = [0u8; 1];
        assert_eq!(encode_bit_string_into(&[0xF0], 4, &mut out), None);
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

    // --- mutation-killing boundary tests (cargo-mutants survivors) ---

    #[test]
    fn accepts_unused_seven_boundary() {
        // unused = 7 is the maximum LEGAL value (§11.2.1): only its top bit is significant, so the
        // 7 low-order padding bits must be zero. Pins the `unused > 7` boundary (a `>` -> `>=`
        // mutation would reject this legal value).
        let bs = decode_bit_string(&[0x07, 0x80]).unwrap();
        assert_eq!(bs.data, &[0x80]);
        assert_eq!(bs.unused, 7);
    }

    #[test]
    fn encode_accepts_unused_seven_boundary() {
        // Encode-side counterpart: unused = 7 is legal and must be accepted (a `>` -> `>=`
        // mutation on the encoder's own `unused > 7` guard would reject it).
        let mut out = [0u8; 4];
        let w = encode_bit_string_into(&[0x80], 7, &mut out).unwrap();
        assert_eq!(&out[..w], &[0x07, 0x80]);
    }

    #[test]
    fn encode_accepts_exact_fit_buffer() {
        // total = 1 (unused-bits octet) + 1 (data) = 2; an exact-fit buffer must succeed, not be
        // rejected -- pins the `out.len() < total` boundary (a `<` -> `<=` mutation would reject
        // an exact-fit buffer).
        let mut out = [0u8; 2];
        let w = encode_bit_string_into(&[0xF0], 4, &mut out).unwrap();
        assert_eq!(w, 2);
        assert_eq!(&out[..w], &[0x04, 0xF0]);
    }
}
