//! DER INTEGER content (X.690 §8.3, §11.x) at **arbitrary magnitude** — the big-serial-number
//! complement to [`crate::integer`]'s `i64` core.
//!
//! Content is a two's-complement, big-endian, **minimal** encoding: at least one octet, and (per
//! §8.3.2) the leading octet and bit 8 of the second must not be all-zero (redundant positive
//! padding) nor all-one (redundant negative padding). These functions operate on the content
//! octets of a TLV whose tag is UNIVERSAL 2 (`0x02`) — the same tag as `crate::integer`; this
//! module is a different **content interpretation** of it, not a different type.
//!
//! **Why a separate module instead of widening `integer`'s cap (`DECISIONS.md` D2a/D14):**
//! X.509 serial numbers (RFC 5280 §4.1.2.2 permits up to 20 octets in practice, and DER's own
//! encoding rule has no upper bound at all) are used as **opaque, comparison-only identifiers** —
//! nothing in X.509 does arithmetic on a serial number. Materializing one into a numeric type is
//! therefore both unnecessary and the wrong shape: this module validates minimality and hands back
//! the validated content bytes themselves (for storage/equality/ordering), never a bignum value.
//! `crate::integer`'s `i64` cap stays the right, separate choice for small numeric fields (versions,
//! key sizes) that genuinely are used as numbers.
//!
//! **The locality insight this module is built on.** DER INTEGER minimality (§8.3.2) is a
//! **local** property of only the leading one or two octets — `content.len() >= 2 &&
//! ((content[0]==0x00 && content[1]&0x80==0) || (content[0]==0xFF && content[1]&0x80!=0))` never
//! inspects `content[2..]`. `crate::integer::decode_integer`'s minimality check is already exactly
//! this rule, unmodified by its `i64` cap; only its subsequent `content.len() > 8 -> TooLarge` and
//! i64-materialization bound it to small integers. This module keeps the identical minimality rule
//! and drops the cap: any content length is structurally valid. [`minimality_is_local`] machine-checks
//! the locality claim directly (same leading two octets, arbitrary differing tail => same verdict).

/// The universal tag number for INTEGER (same UNIVERSAL 2 as [`crate::integer`]; this module is
/// the arbitrary-magnitude complement to that module's `i64` materialization — same tag, different
/// content interpretation, for a different use case: opaque comparison-only values).
pub const TAG: u32 = 2;

/// Why arbitrary-magnitude INTEGER content was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum BigIntError {
    /// Content was empty (an INTEGER needs at least one octet).
    Empty,
    /// Redundant leading `0x00`/`0xFF` padding — forbidden by DER's minimal encoding (§8.3.2).
    NonMinimal,
}

/// Validate that `content` is a minimal two's-complement DER INTEGER of **any** magnitude — no
/// upper size bound (the `i64`-only cap lives in [`crate::integer`], `DECISIONS.md` D2a/D14).
///
/// Rejects empty content and rejects redundant leading-byte padding — exactly
/// `crate::integer::decode_integer`'s minimality rule, generalized: the rule is a *local* property
/// of the leading one or two octets only, so it holds unchanged at any length.
pub fn validate_integer_content(content: &[u8]) -> Result<(), BigIntError> {
    if content.is_empty() {
        return Err(BigIntError::Empty);
    }
    if content.len() >= 2 {
        let c0 = content[0];
        let c1 = content[1];
        if (c0 == 0x00 && (c1 & 0x80) == 0) || (c0 == 0xFF && (c1 & 0x80) != 0) {
            return Err(BigIntError::NonMinimal);
        }
    }
    Ok(())
}

/// Whether the two's-complement value is negative (bit 8 of the leading octet). Total: returns
/// `false` on empty content rather than requiring the caller to validate first — no panic either
/// way, on any input.
pub fn is_negative(content: &[u8]) -> bool {
    content.first().is_some_and(|b| b & 0x80 != 0)
}

/// Normalize an **already-two's-complement** byte string representing some integer value —
/// possibly with redundant leading `0x00`/`0xFF` padding, e.g. from a bignum library or a raw
/// byte-array serial generator that isn't itself DER-minimal — down to its minimal DER form,
/// writing the minimized octets into `out`. This is the encode-side counterpart to
/// [`validate_integer_content`]: a caller wraps the result in a TLV
/// (`crate::tlv::encode_tlv_into`, UNIVERSAL 2, primitive) the same way it would wrap
/// `crate::integer::encode_integer`'s output.
///
/// **Contract — this function only STRIPS, it never ADDS.** `content` must already be a correct
/// two's-complement representation of the caller's intended value (the same convention DER
/// itself uses) — *not* sign-and-magnitude, not little-endian, not any other encoding. Given that,
/// this strips every redundant leading sign-extension byte (there can be more than one — e.g.
/// `[0x00, 0x00, 0x01]` fully reduces to `[0x01]`), but it will never *prepend* a `0x00` guard
/// byte to force a value positive. If `content` is not already a valid two's-complement encoding
/// of the intended value (e.g. it is sign-and-magnitude, or is a bare unsigned magnitude whose top
/// bit happens to be set), the output is DER-minimal for *whatever two's-complement value those
/// bytes actually represent*, which may not be the value the caller intended.
///
/// Returns the number of bytes written (`<= content.len()`), or `None` if `content` is empty (not
/// a valid encoding of anything) or `out` is too small to hold the minimized result.
pub fn encode_minimal_integer_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    if content.is_empty() {
        return None;
    }
    // Strip a redundant leading 0x00 while the value stays non-negative, or a redundant leading
    // 0xFF while it stays negative — generalizes `crate::integer::encode_integer`'s stripping loop
    // (bounded to 8 octets by its `i64` source type) to a slice of any length; same logic.
    let mut start = 0usize;
    while start + 1 < content.len() {
        if content[start] == 0x00 && (content[start + 1] & 0x80) == 0 {
            start += 1;
        } else if content[start] == 0xFF && (content[start + 1] & 0x80) != 0 {
            start += 1;
        } else {
            break;
        }
    }
    let minimal = &content[start..];
    if out.len() < minimal.len() {
        return None;
    }
    out[..minimal.len()].copy_from_slice(minimal);
    Some(minimal.len())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    // Buffer sizing / unwind: `N = 20`. RFC 5280 practice keeps real X.509 serial numbers within
    // ~20 octets (the field is itself capped there, informally, at that width), and the crate's
    // other symbolic-content proofs already run at comparable widths (13-19 octets for the time
    // types). N=20 is a representative-not-limiting bound: every proof below is a claim about the
    // leading one-or-two octets only (or, for the locality proof, an explicit statement that
    // everything past index 1 is irrelevant), so widening N further would not change what is being
    // proven, only the size of the state space Kani explores — the property is length-uniform.
    // `#[kani::unwind]` is tuned per-harness to the loop(s) each one actually exercises (the
    // minimality check itself is unwind-free — a single `if`, no loop — but the stripping loop in
    // `encode_minimal_integer_into` needs a bound of N-1 iterations in the worst case). If Kani
    // ever reports an unwinding-assertion failure here, raise the bound — never weaken the proof.
    const N: usize = 20;

    /// Independent oracle for §8.3.2 minimality, restated in a **genuinely different shape** from
    /// production `validate_integer_content`'s direct bitwise `if`-chain: instead of checking "is
    /// the leading octet a redundant all-zero/all-one padding byte", this phrases minimality as
    /// "the leading octet's value does NOT equal the sign-extension byte implied by octet 1" —
    /// i.e. it independently recomputes what the *hypothetical* sign-extension byte for `content[1]`
    /// would be (`0x00` if bit 8 of `content[1]` is clear, `0xFF` if set) and asks whether
    /// `content[0]` equals that byte. Redundancy is exactly this equality; production instead
    /// enumerates the two `(0x00, clear)` / `(0xFF, set)` cases directly. A bug that flipped a
    /// `==`/`!=` or an `&`/`|` in one formulation would not be mirrored by the same bug in the other.
    fn is_minimal_oracle(content: &[u8]) -> bool {
        if content.is_empty() {
            return false;
        }
        if content.len() < 2 {
            return true;
        }
        let implied_sign_extension_byte = if content[1] & 0x80 == 0 { 0x00u8 } else { 0xFFu8 };
        content[0] != implied_sign_extension_byte
    }

    /// The de-tautologized biconditional: `validate_integer_content` accepts iff the independent
    /// `is_minimal_oracle` says the content is minimal (and it is non-empty).
    #[kani::proof]
    #[kani::unwind(1)]
    fn validate_iff_minimal_oracle() {
        let buf: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        let content = &buf[..n];
        let accepted = validate_integer_content(content).is_ok();
        let oracle_says_ok = !content.is_empty() && is_minimal_oracle(content);
        assert!(accepted == oracle_says_ok);
    }

    /// Fixed-point / round-trip framing: any content `validate_integer_content` accepts is left
    /// unchanged (a no-op) by the independently-implemented minimizer — i.e. accepted content is
    /// already a fixed point of `encode_minimal_integer_into`. This ties decode-side acceptance to
    /// encode-side normalization without ever materializing a numeric value.
    #[kani::proof]
    #[kani::unwind(22)]
    fn accepted_is_fixed_point_of_minimizer() {
        let buf: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        let content = &buf[..n];
        if validate_integer_content(content).is_ok() {
            let mut out = [0u8; N];
            let written = encode_minimal_integer_into(content, &mut out);
            assert!(written == Some(n));
            assert!(out[..n] == buf[..n]);
        }
    }

    /// **The encoder's primary post-condition, proven generally (closes the gap independent
    /// reviewers converged on): the
    /// output of `encode_minimal_integer_into` is *always* itself minimal, for *any* non-empty
    /// input** — not just the single-redundant-byte case `strips_redundant_padding` below
    /// deliberately isolates. This is the property that actually matters: a caller feeding this
    /// function a multi-byte-redundant buffer (e.g. `[0x00, 0x00, 0x01]`, plausible output from a
    /// naive bignum-library export) gets back something `validate_integer_content` accepts,
    /// regardless of how many leading bytes needed stripping.
    #[kani::proof]
    #[kani::unwind(21)]
    fn minimizer_output_is_always_minimal() {
        let content: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n > 0 && n <= N); // empty correctly returns None, not "minimal" content
        let mut out = [0u8; N];
        if let Some(written) = encode_minimal_integer_into(&content[..n], &mut out) {
            assert!(validate_integer_content(&out[..written]).is_ok());
        }
    }

    /// Locality: minimality depends **only** on the leading one or two octets — for `n < 2` this
    /// is vacuous (empty is always `Empty`, a single byte is always minimal, independent of the
    /// buffer entirely), and for `n >= 2` it depends only on indices 0 and 1, never on anything
    /// from index 2 onward. Two symbolic buffers forced to agree on indices 0 and 1 but differing
    /// arbitrarily from index 2 on (and unconstrained relative to each other below `n = 2`, which
    /// the assertion covers too since it holds at every length, not just `n >= 2`) must get the
    /// SAME accept/reject verdict. This is the machine-checked form of the module doc's "local
    /// property" claim — the reason the unbounded i64-module minimality check generalizes to
    /// arbitrary length verbatim.
    #[kani::proof]
    #[kani::unwind(1)]
    fn minimality_is_local() {
        let a: [u8; N] = kani::any();
        let mut b: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        // Force b to share a's leading two octets (harmless when n < 2 too — b[0]/b[1] always
        // exist in the backing [u8; N] array regardless of the slice length n used below); leave
        // everything else free (symbolic, and may differ arbitrarily from a's tail).
        b[0] = a[0];
        b[1] = a[1];
        assert!(validate_integer_content(&a[..n]) == validate_integer_content(&b[..n]));
    }

    /// Robustness: `validate_integer_content` never panics on any content up to `N` octets.
    #[kani::proof]
    #[kani::unwind(1)]
    fn validate_never_panics() {
        let buf: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        let _ = validate_integer_content(&buf[..n]);
    }

    /// Robustness: `encode_minimal_integer_into` never panics on any content up to `N` octets, into
    /// an `out` buffer of any length up to `N` (undersized `out` is a documented `None`, not a panic).
    #[kani::proof]
    #[kani::unwind(20)]
    fn encode_never_panics() {
        let buf: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= N);
        let mut out: [u8; N] = kani::any();
        let out_len: usize = kani::any();
        kani::assume(out_len <= N);
        let _ = encode_minimal_integer_into(&buf[..n], &mut out[..out_len]);
    }

    /// Empty content is rejected by both the validator and the minimizer.
    #[kani::proof]
    fn empty_is_empty() {
        assert!(validate_integer_content(&[]) == Err(BigIntError::Empty));
        let mut out = [0u8; 4];
        assert!(encode_minimal_integer_into(&[], &mut out) == None);
    }

    /// Redundant leading `0x00` (positive padding) is `NonMinimal` — the 2-octet case from
    /// `crate::integer`, restated here to anchor the arbitrary-length version below.
    #[kani::proof]
    fn redundant_positive_padding_is_non_minimal() {
        let c: u8 = kani::any();
        kani::assume(c & 0x80 == 0); // next octet keeps the value positive -> the 0x00 is redundant
        assert!(validate_integer_content(&[0x00, c]) == Err(BigIntError::NonMinimal));
    }

    /// Redundant leading `0xFF` (negative padding) is `NonMinimal` — the 2-octet case.
    #[kani::proof]
    fn redundant_negative_padding_is_non_minimal() {
        let c: u8 = kani::any();
        kani::assume(c & 0x80 != 0); // next octet keeps the value negative -> the 0xFF is redundant
        assert!(validate_integer_content(&[0xFF, c]) == Err(BigIntError::NonMinimal));
    }

    /// Redundant leading `0x00` is `NonMinimal` at an arbitrary-magnitude length (not just 2
    /// octets) — the length-generalization made concrete, not just asserted: an `N`-octet buffer
    /// whose leading byte is `0x00`, whose second byte keeps the value non-negative, and whose
    /// remaining `N-2` octets are fully symbolic (arbitrary tail) is still rejected.
    #[kani::proof]
    #[kani::unwind(1)]
    fn redundant_positive_padding_is_non_minimal_at_length() {
        let buf: [u8; N] = kani::any();
        kani::assume(buf[0] == 0x00);
        kani::assume(buf[1] & 0x80 == 0);
        assert!(validate_integer_content(&buf) == Err(BigIntError::NonMinimal));
    }

    /// Redundant leading `0xFF` is `NonMinimal` at an arbitrary-magnitude length, mirroring the
    /// proof above for the negative-padding case.
    #[kani::proof]
    #[kani::unwind(1)]
    fn redundant_negative_padding_is_non_minimal_at_length() {
        let buf: [u8; N] = kani::any();
        kani::assume(buf[0] == 0xFF);
        kani::assume(buf[1] & 0x80 != 0);
        assert!(validate_integer_content(&buf) == Err(BigIntError::NonMinimal));
    }

    /// `is_negative` matches the raw sign-bit check on the leading octet for any non-empty
    /// content, and is `false` on empty content (rather than panicking).
    #[kani::proof]
    #[kani::unwind(1)]
    fn is_negative_matches_sign_bit() {
        let buf: [u8; N] = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= N);
        assert!(is_negative(&buf[..n]) == (buf[0] & 0x80 != 0));
        assert!(!is_negative(&[]));
    }

    /// `encode_minimal_integer_into` strips exactly the redundant leading byte, not more: given
    /// content with a known redundant leading `0x00` (`buf[0]`, redundant because `buf[1]`'s top bit
    /// is clear — the value stays non-negative without it) followed by a *non-zero* second byte (so
    /// `buf[1]` itself is never `0x00` and therefore can never itself look like a redundant leading
    /// byte — the loop's stripping conditions cannot fire a second time), the minimized output drops
    /// exactly that one byte and the result re-validates as minimal. (Constraining only `buf[1]` —
    /// not the whole tail — keeps the rest of the buffer, `buf[2..]`, fully symbolic, so this also
    /// exercises the "arbitrary tail" framing the locality proof uses.)
    #[kani::proof]
    #[kani::unwind(20)]
    fn strips_redundant_padding() {
        let mut buf: [u8; N] = kani::any();
        buf[0] = 0x00;
        buf[1] &= 0x7F; // top bit clear -> buf[0] is redundant (value stays non-negative)
        kani::assume(buf[1] != 0x00); // buf[1] itself is not 0x00, so it cannot also be stripped
        let mut out = [0u8; N];
        let written = encode_minimal_integer_into(&buf, &mut out);
        assert!(written == Some(N - 1));
        assert!(out[..N - 1] == buf[1..]);
        assert!(validate_integer_content(&out[..N - 1]) == Ok(()));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_empty() {
        assert_eq!(validate_integer_content(&[]), Err(BigIntError::Empty));
        let mut out = [0u8; 4];
        assert_eq!(encode_minimal_integer_into(&[], &mut out), None);
    }

    #[test]
    fn accepts_zero_and_minus_one() {
        assert_eq!(validate_integer_content(&[0x00]), Ok(())); // value 0
        assert_eq!(validate_integer_content(&[0xFF]), Ok(())); // value -1
        assert!(!is_negative(&[0x00]));
        assert!(is_negative(&[0xFF]));
    }

    #[test]
    fn rejects_redundant_positive_padding() {
        // 0x00 0x01 is a non-minimal encoding of 1 (should be just 0x01)
        assert_eq!(
            validate_integer_content(&[0x00, 0x01]),
            Err(BigIntError::NonMinimal)
        );
    }

    #[test]
    fn rejects_redundant_negative_padding() {
        // 0xFF 0xFF is a non-minimal encoding of -1 (should be just 0xFF)
        assert_eq!(
            validate_integer_content(&[0xFF, 0xFF]),
            Err(BigIntError::NonMinimal)
        );
    }

    #[test]
    fn accepts_minimal_positive_needing_leading_zero() {
        // 0x00 0x80 = 128 is minimal (0x80 alone would be -128)
        assert_eq!(validate_integer_content(&[0x00, 0x80]), Ok(()));
    }

    #[test]
    fn accepts_minimal_positive_needing_leading_zero_at_x509_scale() {
        // A 17-octet value whose top content byte is 0x80 needs a leading 0x00 guard byte to stay
        // positive (mirrors integer.rs's 2-octet case, at a scale integer.rs itself cannot accept:
        // 17 octets > its 8-octet i64 cap).
        let mut content = [0u8; 17];
        content[0] = 0x00;
        content[1] = 0x80;
        for (i, b) in content[2..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(37).wrapping_add(1);
        }
        assert_eq!(validate_integer_content(&content), Ok(()));
        assert!(!is_negative(&content));
    }

    #[test]
    fn accepts_x509_scale_serial_number_integer_rs_would_reject_as_too_large() {
        // A minimal 20-octet positive serial number (leading byte < 0x80, so no sign-guard byte is
        // needed) -- exactly the case `crate::integer::decode_integer` rejects as `TooLarge` (its
        // cap is 8 octets), and this module's whole reason for existing.
        let mut serial = [0u8; 20];
        serial[0] = 0x5A; // < 0x80: positive, and not 0x00 either, so no minimality issue
        for (i, b) in serial[1..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(83).wrapping_add(7);
        }
        assert_eq!(validate_integer_content(&serial), Ok(()));
        assert!(!is_negative(&serial));

        // Prepending a redundant leading 0x00 (21 octets total) makes the SAME value's encoding
        // non-minimal.
        let mut padded = [0u8; 21];
        padded[0] = 0x00;
        padded[1..].copy_from_slice(&serial);
        assert_eq!(
            validate_integer_content(&padded),
            Err(BigIntError::NonMinimal)
        );
    }

    #[test]
    fn negative_bignum_at_x509_scale() {
        // A minimal 20-octet negative value: leading byte >= 0x80 with its second byte NOT forcing
        // redundancy (i.e. not also all-one-continuing in a way that would make byte 0 redundant).
        let mut content = [0u8; 20];
        content[0] = 0xA3; // >= 0x80: negative; not 0xFF, so no minimality issue regardless of byte 1
        for (i, b) in content[1..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(29).wrapping_add(3);
        }
        assert_eq!(validate_integer_content(&content), Ok(()));
        assert!(is_negative(&content));
    }

    #[test]
    fn roundtrips_redundant_padded_buffer_through_the_minimizer() {
        // 0x00 0x01 0x02 0x03 (redundant leading 0x00) minimizes to 0x01 0x02 0x03, which then
        // re-validates as already minimal (a fixed point).
        let padded = [0x00u8, 0x01, 0x02, 0x03];
        let mut out = [0u8; 4];
        let n = encode_minimal_integer_into(&padded, &mut out).unwrap();
        assert_eq!(&out[..n], &[0x01, 0x02, 0x03]);
        assert_eq!(validate_integer_content(&out[..n]), Ok(()));

        // Re-running the minimizer on the already-minimal result changes nothing (fixed point).
        let mut out2 = [0u8; 4];
        let n2 = encode_minimal_integer_into(&out[..n], &mut out2).unwrap();
        assert_eq!(n2, n);
        assert_eq!(&out2[..n2], &out[..n]);
    }

    #[test]
    fn strips_multiple_redundant_leading_bytes() {
        // 0x00 0x00 0x01 has TWO redundant leading zeros (each one, in turn, redundant relative to
        // the byte after it) -- confirms the stripping loop cascades rather than stopping after a
        // single strip. Independent reviewers flagged this case as real but
        // previously unproven (only the single-strip case had a harness).
        let mut out = [0u8; 3];
        let n = encode_minimal_integer_into(&[0x00, 0x00, 0x01], &mut out).unwrap();
        assert_eq!(&out[..n], &[0x01]);
        assert_eq!(validate_integer_content(&out[..n]), Ok(()));

        // The negative-sign analogue: 0xFF 0xFF 0x80 has two redundant leading 0xFFs.
        let mut out2 = [0u8; 3];
        let n2 = encode_minimal_integer_into(&[0xFF, 0xFF, 0x80], &mut out2).unwrap();
        assert_eq!(&out2[..n2], &[0x80]);
        assert_eq!(validate_integer_content(&out2[..n2]), Ok(()));
    }

    #[test]
    fn strips_multiple_redundant_leading_bytes_at_x509_scale() {
        // A 20-octet buffer with FOUR redundant leading 0x00 bytes ahead of a 16-octet minimal
        // positive value (top bit of the first real byte clear, so no positivity guard is needed).
        let mut padded = [0u8; 20];
        // padded[0..4] stay 0x00 (redundant); padded[4] must keep the value non-negative.
        padded[4] = 0x5A; // < 0x80
        for (i, b) in padded[5..].iter_mut().enumerate() {
            *b = (i as u8).wrapping_mul(11).wrapping_add(2);
        }
        let mut out = [0u8; 20];
        let n = encode_minimal_integer_into(&padded, &mut out).unwrap();
        assert_eq!(n, 16);
        assert_eq!(&out[..n], &padded[4..]);
        assert_eq!(validate_integer_content(&out[..n]), Ok(()));
    }

    #[test]
    fn does_not_strip_past_a_sign_flipping_boundary() {
        // 0xFF 0x7F is -129, already minimal: stripping the leading 0xFF would flip the sign (0x7F
        // alone is +127), so it must be left untouched.
        assert_eq!(validate_integer_content(&[0xFF, 0x7F]), Ok(()));
        let mut out = [0u8; 2];
        let n = encode_minimal_integer_into(&[0xFF, 0x7F], &mut out).unwrap();
        assert_eq!(&out[..n], &[0xFF, 0x7F]);

        // 0xFF 0xFF 0x7F has exactly one redundant leading 0xFF (the second 0xFF is NOT redundant,
        // since 0xFF followed by 0x7F -- bit 8 clear -- would flip the sign): strips to 0xFF 0x7F.
        let mut out2 = [0u8; 3];
        let n2 = encode_minimal_integer_into(&[0xFF, 0xFF, 0x7F], &mut out2).unwrap();
        assert_eq!(&out2[..n2], &[0xFF, 0x7F]);
        assert_eq!(validate_integer_content(&out2[..n2]), Ok(()));
    }

    #[test]
    fn encode_reports_none_when_out_is_too_small() {
        let mut out = [0u8; 1];
        assert_eq!(encode_minimal_integer_into(&[0x01, 0x02], &mut out), None);
    }
}
