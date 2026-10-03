//! ASN.1 `[n]` context-tag wrapper — the EXPLICIT half only (X.690 §8.14).
//!
//! X.690 lets a schema override a type's default (UNIVERSAL) tag with a context-specific one, in
//! either of two disjoint styles:
//! - **EXPLICIT** (§8.14.2): the context-specific tag *wraps* the underlying type's own complete
//!   TLV — the value octets of the `[n]` TLV are themselves a full, independently-tagged TLV. An
//!   EXPLICIT `[n]` is therefore always **constructed** (it contains one nested TLV), regardless of
//!   whether the underlying type is itself primitive or constructed.
//! - **IMPLICIT** (§8.14.3): the context-specific tag *replaces* the underlying type's own tag —
//!   there is no nested TLV; the `[n]` TLV's value octets are the underlying type's content
//!   directly, and whether `[n]` is primitive or constructed depends on the underlying type.
//!
//! This module decodes **EXPLICIT only**. That is a deliberate scope boundary, not an oversight:
//! peeling an EXPLICIT wrapper is purely structural — the wrapper's own tag/length framing is all
//! that is needed, and the caller applies whatever inner-type decoder it wants to the returned
//! content, entirely independent of this module. Decoding IMPLICIT, by contrast, is inherently
//! schema-dependent: since the context tag *replaces* the underlying tag, recovering the content
//! requires already knowing the underlying type (primitive vs. constructed, and how to frame its
//! content) — a dependency this crate's schema-free fence deliberately does not take on (see the
//! crate-level docs). A caller decoding an IMPLICIT field applies its own tag override atop the
//! relevant primitive decoder directly; there is nothing generic for this module to provide there.
//!
//! `TBSCertificate.version` (RFC 5280 §4.1.2.1) is the canonical example this module targets:
//! `version` is `[0] EXPLICIT Version DEFAULT v1`, encoded as `A0 <len> 02 <len> <int>` — a
//! context-specific constructed `[0]` wrapping one INTEGER TLV.
//!
//! **Canonicality is inherited, not re-proven here.** The wrapper's own tag-number minimality and
//! length-field minimality are exactly the properties [`crate::tag`] and [`crate::length`] already
//! prove for every TLV, and this module reaches them only via [`crate::tlv::decode_tlv`] — it adds
//! no framing logic of its own beyond the class/number/constructed classification below.
//!
//! # Examples
//!
//! ```
//! use der_verified::context_tag::decode_explicit_context;
//!
//! // [0] EXPLICIT INTEGER 5: A0 03 02 01 05 -- wrapper, then the nested INTEGER TLV.
//! let bytes = [0xA0, 0x03, 0x02, 0x01, 0x05];
//! let (inner, used) = decode_explicit_context(0, &bytes).unwrap();
//! assert_eq!(used, 5);
//! assert_eq!(inner, &[0x02, 0x01, 0x05]);
//! ```

use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};

/// Why an EXPLICIT `[n]` context-tag wrapper was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ContextTagError {
    /// The wrapper TLV's own tag/length framing was malformed (bad identifier/length, truncated,
    /// non-canonical, …).
    BadTlv(TlvError),
    /// The wrapper TLV was well-framed but its class was not context-specific.
    WrongClass,
    /// The wrapper was context-specific but its tag number was not the expected `n`.
    WrongNumber,
    /// The wrapper was context-specific with the expected number, but in the *primitive* form.
    /// EXPLICIT tagging is always constructed (it wraps a nested TLV) — a primitive `[n]` here
    /// would be an IMPLICIT encoding, which this helper deliberately does not handle (see the
    /// module docs).
    NotConstructed,
}

/// Decode an EXPLICIT `[n]` context-tag wrapper (`expected_number`) from the front of `input`.
///
/// On success returns the **inner content octets** — the wrapped TLV's own bytes (tag + length +
/// value), not yet decoded — and the total number of bytes the wrapper and its content consumed
/// from `input`. The caller applies the inner type's own decoder to the returned slice.
///
/// Never panics on any input **up to the harness's 16-octet symbolic bound** (proven by the `decode_explicit_context_never_panics` harness); returns a classified [`ContextTagError`] on any structural
/// deviation.
pub fn decode_explicit_context(
    expected_number: u32,
    input: &[u8],
) -> Result<(&[u8], usize), ContextTagError> {
    let (tlv, used) = decode_tlv(input).map_err(ContextTagError::BadTlv)?;
    if tlv.tag.class != Class::ContextSpecific {
        return Err(ContextTagError::WrongClass);
    }
    if tlv.tag.number != expected_number {
        return Err(ContextTagError::WrongNumber);
    }
    if !tlv.tag.constructed {
        return Err(ContextTagError::NotConstructed);
    }
    Ok((tlv.value, used))
}

// ---------------------------------------------------------------------------
// Kani proof harness.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer covers a maximal TLV header (6-byte high-tag
// + 5-byte long length = 11) plus value octets. The call chain is a single `decode_tlv` call with
// no further loop, so `#[kani::unwind(20)]` (matching the sibling `x509_*` modules' bound) is
// generous margin; if Kani reports an unwinding-assertion failure, raise this bound (do not
// weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `decode_explicit_context` never panics on any input up to 16 octets, for any
    /// expected tag number.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached with a genuine non-empty inner
    /// TLV (a real EXPLICIT wrapper: context-specific class, matching number, constructed flag,
    /// AND a non-empty wrapped value all pass), not merely that malformed/mismatched inputs are
    /// rejected. Would NOT be SAT if `decode_explicit_context`'s body were a no-op always
    /// returning `Err`.
    #[kani::proof]
    #[kani::unwind(20)]
    fn decode_explicit_context_never_panics() {
        let buf: [u8; 16] = kani::any();
        // Symbolic input length so the "up to 16 octets" claim holds at every length in `0..=16`,
        // not just the single length 16 -- control flow is length-dependent (crate convention:
        // `pkcs8`/`ec_private_key`/`x509_name`).
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let n: u32 = kani::any();
        let result = decode_explicit_context(n, &buf[..len]);
        kani::cover(result.is_ok(), "a well-formed EXPLICIT [n] wrapper reaches the Ok tail");
        if let Ok((inner, _used)) = result {
            kani::cover(!inner.is_empty(), "a non-empty wrapped inner TLV is accepted");
        }
        let _ = result;
    }

    /// Typed-decoder faithfulness: `decode_explicit_context`'s Ok/Err split is
    /// exactly TLV-well-formed ∧ class == ContextSpecific ∧ tag number == `expected_number`
    /// **exactly** ∧ constructed, with the returned inner slice and consumed length tied exactly
    /// (exact tiling) to the underlying TLV: `used == decode_tlv`'s own consumed length, and the
    /// returned inner content IS `tlv.value` -- checked as pointer+length identity
    /// (`core::ptr::eq` on the slice starts, plus equal `len()`), not mere byte equality, so a
    /// re-derived or re-sliced copy with the same bytes would NOT pass.
    /// `decode_explicit_context_never_panics` above never checks that a WRONG tag number is
    /// actually rejected, nor that the returned slice is exactly the TLV's value — this harness
    /// closes both gaps. For `n <= 30` (low-tag form) it also pins the concrete identifier octet.
    /// Control: widen the tag-number guard's `!=` to `>` (so a wrapper whose number is `<=` the
    /// expected number, not only an EXACT match, would satisfy the check) -> predicted RED.
    ///
    /// CONTRACT SURFACE / bounded-backing evidence for the Ok/Err split only (the exact error
    /// variants are pinned by `decode_explicit_context_exact_result`). Backing `[u8; 16]`, symbolic
    /// `len <= 16`, symbolic `n: u32` (full range), `#[kani::unwind(20)]`, no assumptions beyond
    /// `len <= 16`, no stubs.
    #[kani::proof]
    #[kani::unwind(20)]
    fn decode_explicit_context_faithful() {
        let buf: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let n: u32 = kani::any();
        let input = &buf[..len];
        let result = decode_explicit_context(n, input);
        let tlv_result = decode_tlv(input);
        let expected_ok = matches!(&tlv_result, Ok((tlv, _))
            if tlv.tag.class == Class::ContextSpecific
                && tlv.tag.number == n
                && tlv.tag.constructed);
        assert!(result.is_ok() == expected_ok);
        if let Ok((v, u)) = result {
            let (tlv, tused) = tlv_result.unwrap();
            // Exact tiling: the wrapper consumes precisely what `decode_tlv` itself consumed, and
            // the returned inner content is exactly the underlying TLV's value BORROW -- not merely
            // byte-equal to it (a re-derived or re-sliced copy with the same bytes would also pass
            // `v == tlv.value`; pointer+length identity is what rules that out).
            assert!(u == tused);
            assert!(core::ptr::eq(v.as_ptr(), tlv.value.as_ptr()) && v.len() == tlv.value.len());
            if n <= 30 {
                assert!(input[0] == 0xA0 | (n as u8));
            }
        }
        kani::cover(result.is_ok(), "a well-formed EXPLICIT [n] wrapper reaches Ok under the faithful oracle");
    }

    /// Exact-result contract: `decode_explicit_context(n, input)`
    /// equals a TOTAL expected `Result`, error variant and documented check order included
    /// (framing -> class -> number -> constructed), not merely
    /// the Ok/Err split pinned by `decode_explicit_context_faithful`.
    ///
    /// Oracle: `decode_tlv(input)` is `Err(e)` -> `Err(BadTlv(e))`. Otherwise, in the low-tag form
    /// (`input[0] & 0x1F != 0x1F`) the class, constructed flag and number are computed from the
    /// LITERAL bits of `input[0]` (`t >> 6`, `t & 0x20`, `t & 0x1F`), not from the implementation's
    /// own tag-match expression; in the high-tag form the class and constructed flag are still the
    /// literal bits and only the number comes from `decode_tlv`'s `tlv.tag` (the `tag` lid). Then class != 2 -> `WrongClass`; number != `n` -> `WrongNumber`; primitive
    /// -> `NotConstructed`; else `Ok((tlv.value, tused))`, with pointer identity on the value.
    ///
    /// CONTRACT SURFACE / bounded-backing evidence. Backing `[u8; 16]`, symbolic `len <= 16`,
    /// symbolic `n: u32` (full range), `#[kani::unwind(20)]`, no assumptions beyond `len <= 16`,
    /// no stubs. Only the EXPLICIT form is covered (IMPLICIT is not modelled); TLV framing
    /// correctness is trusted from the `decode_tlv` lid. An `Ok` does not require the value octets to
    /// be one complete inner TLV (`A0 00` and `A0 01 FF` are accepted): inner well-formedness and
    /// tiling are the caller's, not checked here.
    /// Covers: one per outcome class (`BadTlv`, `WrongClass`, `WrongNumber`, `NotConstructed`,
    /// `Ok`) plus a high-tag-form `Ok`.
    #[kani::proof]
    #[kani::unwind(20)]
    fn decode_explicit_context_exact_result() {
        let buf: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let n: u32 = kani::any();
        let input = &buf[..len];
        let r = decode_explicit_context(n, input);

        let expected: Result<(&[u8], usize), ContextTagError> = match decode_tlv(input) {
            Err(e) => Err(ContextTagError::BadTlv(e)),
            Ok((tlv, tused)) => {
                let t = input[0];
                // Class and constructed flag are literal bits of the first octet in BOTH identifier
                // forms; only the number of a high-tag identifier comes from `decode_tlv`.
                let number = if t & 0x1F != 0x1F { (t & 0x1F) as u32 } else { tlv.tag.number };
                let (class_bits, constructed) = (t >> 6, t & 0x20 != 0);
                if class_bits != 2 {
                    Err(ContextTagError::WrongClass)
                } else if number != n {
                    Err(ContextTagError::WrongNumber)
                } else if !constructed {
                    Err(ContextTagError::NotConstructed)
                } else {
                    Ok((tlv.value, tused))
                }
            }
        };
        assert!(r == expected, "decode_explicit_context result differs from the total expected result");
        if let (Ok((v, u)), Ok((ev, eu))) = (r, expected) {
            assert!(u == eu);
            assert!(core::ptr::eq(v.as_ptr(), ev.as_ptr()) && v.len() == ev.len());
        }

        kani::cover(matches!(r, Err(ContextTagError::BadTlv(_))), "BadTlv outcome reached");
        kani::cover(matches!(r, Err(ContextTagError::WrongClass)), "WrongClass outcome reached");
        kani::cover(matches!(r, Err(ContextTagError::WrongNumber)), "WrongNumber outcome reached");
        kani::cover(matches!(r, Err(ContextTagError::NotConstructed)), "NotConstructed outcome reached");
        kani::cover(r.is_ok(), "Ok outcome reached");
        kani::cover(
            r.is_ok() && len > 0 && input[0] & 0x1F == 0x1F,
            "Ok outcome reached through the high-tag identifier form",
        );
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::length::LengthError;

    /// `[0] EXPLICIT INTEGER 5`: `A0 03 02 01 05`.
    ///
    /// `A0 03`        context-specific [0], constructed, len 3
    ///    `02 01 05`  INTEGER, len 1, value 5
    #[rustfmt::skip]
    const EXPLICIT_0_INT_5: [u8; 5] = [
        0xA0, 0x03,
            0x02, 0x01, 0x05,
    ];

    /// `[3] EXPLICIT INTEGER 5`: `A3 03 02 01 05`.
    #[rustfmt::skip]
    const EXPLICIT_3_INT_5: [u8; 5] = [
        0xA3, 0x03,
            0x02, 0x01, 0x05,
    ];

    #[test]
    fn accepts_explicit_0_wrapper() {
        let (inner, used) = decode_explicit_context(0, &EXPLICIT_0_INT_5).unwrap();
        assert_eq!(used, 5);
        assert_eq!(inner, &[0x02, 0x01, 0x05]);
    }

    #[test]
    fn accepts_explicit_3_wrapper() {
        let (inner, used) = decode_explicit_context(3, &EXPLICIT_3_INT_5).unwrap();
        assert_eq!(used, 5);
        assert_eq!(inner, &[0x02, 0x01, 0x05]);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn rejects_wrong_class() {
        // 0x30 = UNIVERSAL 16 (SEQUENCE) constructed -- not context-specific at all.
        let mut bytes = EXPLICIT_0_INT_5;
        bytes[0] = 0x30;
        assert_eq!(decode_explicit_context(0, &bytes), Err(ContextTagError::WrongClass));
    }

    #[test]
    fn rejects_wrong_number() {
        // Well-framed context-specific constructed [0], but the caller expects [1].
        assert_eq!(decode_explicit_context(1, &EXPLICIT_0_INT_5), Err(ContextTagError::WrongNumber));
    }

    #[test]
    fn rejects_primitive_form() {
        // 0x80 = context-specific PRIMITIVE number 0 -- EXPLICIT tagging is always constructed.
        let bytes = [0x80u8, 0x01, 0x05];
        assert_eq!(decode_explicit_context(0, &bytes), Err(ContextTagError::NotConstructed));
    }

    #[test]
    fn rejects_malformed_wrapper() {
        // Truncated: declares 3 content octets but only 1 is present.
        let bytes = [0xA0u8, 0x03, 0x02];
        assert_eq!(
            decode_explicit_context(0, &bytes),
            Err(ContextTagError::BadTlv(TlvError::Truncated))
        );
    }

    #[test]
    fn rejects_high_tag_form_of_context_number_0() {
        // BF 00 = the high-tag (multi-octet) encoding of context-specific number 0 (X.690
        // §8.1.2.4.2), constructed bit set. DER requires the low-tag single-octet form 0xA0 for
        // numbers <= 30, so the tag codec rejects this as non-minimal -- a lax BER reader might
        // still accept the redundant high-tag spelling of a small context number.
        use crate::tag::TagError;
        assert_eq!(
            decode_explicit_context(0, &[0xBF, 0x00]),
            Err(ContextTagError::BadTlv(TlvError::Tag(TagError::NonMinimal)))
        );
    }

    #[test]
    fn rejects_non_canonical_wrapper_length() {
        // The wrapper length re-encoded in the long form (0x81 0x03) where the short form (0x03)
        // is required -- non-minimal, forbidden by DER.
        let bytes = [0xA0u8, 0x81, 0x03, 0x02, 0x01, 0x05];
        assert_eq!(
            decode_explicit_context(0, &bytes),
            Err(ContextTagError::BadTlv(TlvError::Length(LengthError::NonMinimal)))
        );
    }
}
