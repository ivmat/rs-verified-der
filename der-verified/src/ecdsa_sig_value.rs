//! `ECDSA-Sig-Value` (RFC 3279 §2.2.3; re-used unchanged by RFC 5480 §2.2) — a bounded,
//! **structural** consumer that composes this crate's verified primitives.
//!
//! ```text
//! ECDSA-Sig-Value ::= SEQUENCE { r INTEGER, s INTEGER }
//! ```
//!
//! This module is the sibling of [`crate::x509_algorithm_identifier`] and [`crate::x509_validity`]:
//! a **demonstration of composition**, not an expansion of the crate's DER-layer scope (see the
//! crate-level docs). It frames the outer SEQUENCE and the two INTEGER fields using
//! [`crate::sequence`], [`crate::tlv`], and [`crate::big_integer`] verbatim — it does not hand-roll
//! any tag/length/TLV parsing of its own. This is where an ECDSA signature's `r`/`s` pair actually
//! lives on the wire: the crate already extracts a certificate's `signatureValue` as an **opaque**
//! `BitString` (`x509_certificate.rs` — *"Neither the signature nor the encoding it was computed over
//! is verified by this crate"*); this module is what a caller who *has* extracted that BIT STRING's
//! bit-payload octets applies next, to frame it as its own two-INTEGER `SEQUENCE`.
//!
//! **`r`/`s` are exposed as raw validated content, not materialized as numbers.** Following
//! [`crate::big_integer`]'s own stance (`DECISIONS.md` D14) and [`crate::x509_tbs_certificate`]'s
//! `serial_number` field (the crate's other opaque-bignum precedent): a signature scalar is used
//! downstream for comparison/range-checking against a curve order, never for arithmetic this crate
//! would perform, so [`EcdsaSigValue::r`] and [`EcdsaSigValue::s`] are `&[u8]` — the validated-minimal
//! two's-complement content octets, borrowed from the input, exactly as `big_integer` hands them back.
//!
//! **Scope boundaries (deliberate) — this module proves DER framing and canonicality ONLY:**
//! - *Structural framing only.* [`parse_ecdsa_sig_value`] / [`parse_ecdsa_sig_value_strict`] validate
//!   that the byte string is a well-formed, DER-canonical `ECDSA-Sig-Value` with the exact field
//!   tiling the ASN.1 schema requires (`r`, then `s`, nothing more, nothing less), and that each
//!   INTEGER's *content* is itself canonical DER (minimal two's-complement, no redundant sign-guard
//!   padding — [`crate::big_integer::validate_integer_content`]).
//! - **⛔ Out of scope: range checks against a curve order.** `1 <= r,s <= n-1` (SEC1 §4.1.3) needs a
//!   named curve's order `n`, which is not carried by `ECDSA-Sig-Value` itself — it lives in a
//!   *different* structure (an `AlgorithmIdentifier`/SPKI's curve OID). Proving that range would make
//!   this module a property of the signature *composed with* a curve identifier, not of the container
//!   alone (`CRYPTO-FV-SCOPING.md` §1.3, "Band B").
//! - **⛔ Out of scope: low-S policy.** `s <= n/2` (e.g. Bitcoin BIP-62/BIP-66) is a *protocol profile*
//!   rule specific consumers impose, not an RFC 3279/5480 or general ECDSA DER-validity requirement —
//!   it belongs in a profile layer alongside [`crate::profile`], not in a transfer-syntax codec.
//! - **⛔ Out of scope: any cryptographic interpretation.** No curve-point, subgroup-membership, or
//!   signature-verification semantics; `r`/`s` are opaque comparison-only byte strings to this module,
//!   exactly as `big_integer`'s own module doc frames a serial number.
//! - *Strict/lenient outer-trailing variants, matching the crate's established split
//!   ([`crate::sequence::decode_sequence_tlv`] / [`crate::sequence::decode_sequence_tlv_strict`]).*
//!   [`parse_ecdsa_sig_value`] is composable — it does not require `input` to be consumed exactly, so
//!   it can sit inside a larger structure (e.g. as the payload of a BIT STRING whose own length was
//!   already checked by the caller). [`parse_ecdsa_sig_value_strict`] additionally requires `input` to
//!   be consumed exactly — the right choice when a caller already knows the whole byte string is
//!   supposed to be one `ECDSA-Sig-Value` and nothing else (e.g. the DER `ANY` inside a signature
//!   field), guarding the classic trailing-data parser-differential vector.
//!
//! **Why this module matters: the differential surface, not the arithmetic.** `ECDSA-Sig-Value`'s
//! DER-vs-BER framing is a historically productive parser-differential surface: BER's lax INTEGER
//! encoding (leading-zero padding, non-canonical lengths) tolerated by some OpenSSL-era parsers was
//! exactly the crack Bitcoin's BIP-66 soft fork closed by mandating strict DER for every consensus
//! signature. This module proves the DER-canonicality half of that boundary — malleable encodings of
//! the *same* `(r, s)` pair are rejected, not merely one canonical encoding accepted — leaving the
//! *value*-level policy questions above (range, low-S) to a caller with a curve.
//!
//! # Examples
//!
//! ```
//! use der_verified::ecdsa_sig_value::parse_ecdsa_sig_value_strict;
//!
//! // A P-256-shaped ECDSA-Sig-Value: r is 32 raw octets with its top bit set, so DER's minimal
//! // two's-complement encoding requires a leading 0x00 sign-guard octet (33 content octets total);
//! // s is 32 octets whose top bit is clear (no guard needed).
//! #[rustfmt::skip]
//! let sig_der: [u8; 71] = [
//!     0x30, 0x45,
//!         0x02, 0x21,
//!             0x00,
//!             0xc6, 0x47, 0xd2, 0x3d, 0x87, 0xd2, 0x8e, 0x9f, 0x40, 0x8b, 0x4e, 0xcb, 0x1d, 0x27,
//!             0xd3, 0x90, 0x8a, 0xed, 0x6f, 0xe1, 0xe0, 0x3e, 0x79, 0x4a, 0x3c, 0x5d, 0x21, 0x40,
//!             0xb4, 0xe3, 0xd7, 0xe0,
//!         0x02, 0x20,
//!             0x5a, 0x12, 0x9e, 0x44, 0x0f, 0x6b, 0x3a, 0x8c, 0x27, 0x51, 0xd0, 0x9a, 0x63, 0x1f,
//!             0x84, 0xc2, 0x0e, 0x77, 0xab, 0x53, 0x19, 0xf6, 0x82, 0xcd, 0x45, 0x0b, 0x8e, 0x3d,
//!             0x71, 0x2a, 0x96, 0x08,
//! ];
//! let sig = parse_ecdsa_sig_value_strict(&sig_der).unwrap();
//! assert_eq!(sig.r.len(), 33); // includes the mandatory 0x00 sign-guard octet
//! assert_eq!(sig.s.len(), 32);
//! ```

use crate::big_integer::{validate_integer_content, BigIntError, TAG as BIG_INTEGER_TAG};
use crate::sequence::{decode_sequence_tlv, decode_sequence_tlv_strict, SequenceError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};

/// A structurally-parsed `ECDSA-Sig-Value`, borrowing from the input it was parsed from.
///
/// See the module docs for the scope of what "parsed" means here: DER framing and canonicality only
/// — no curve-order range check, no low-S policy, no cryptographic interpretation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EcdsaSigValue<'a> {
    /// `r`: the validated-minimal INTEGER **content** octets (not the TLV header), opaque — see
    /// [`crate::big_integer`]'s comparison-only stance. Never materialized as a numeric value; a
    /// caller that needs the numeric value (e.g. to range-check against a curve order) does that
    /// itself.
    pub r: &'a [u8],
    /// `s`: the validated-minimal INTEGER **content** octets, opaque, exactly like [`Self::r`].
    pub s: &'a [u8],
}

/// Why one of the two INTEGER fields (`r` or `s`) was rejected. Shared taxonomy for both fields,
/// mirroring [`crate::x509_algorithm_identifier`]'s per-field wrapping style.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IntegerFieldError {
    /// The field's TLV framing (tag/length octets) was malformed.
    Tlv(TlvError),
    /// The field's identifier was well-framed but not UNIVERSAL 2 (INTEGER).
    WrongTag,
    /// The field's identifier was UNIVERSAL 2 but in the constructed form — INTEGER content is
    /// always primitive.
    Constructed,
    /// The field's content failed canonical-DER minimality (empty, or redundant sign-guard padding).
    Content(BigIntError),
}

/// Why an `ECDSA-Sig-Value` was rejected. Every variant names a specific structural cause, wrapping
/// the underlying primitive's error where one exists.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EcdsaSigValueError {
    /// The outer `ECDSA-Sig-Value` SEQUENCE envelope was malformed: bad identifier/length, the
    /// primitive (non-constructed) form, or — for [`parse_ecdsa_sig_value_strict`] only — trailing
    /// bytes after the whole structure.
    BadOuterSeq(SequenceError),
    /// No `r` is present — the outer SEQUENCE's content is empty.
    MissingR,
    /// The `r` field failed to decode.
    R(IntegerFieldError),
    /// No `s` is present — the outer SEQUENCE's content ended after `r`.
    MissingS,
    /// The `s` field failed to decode.
    S(IntegerFieldError),
    /// The `ECDSA-Sig-Value` SEQUENCE has more than its two permitted fields (`r`, `s`): bytes
    /// remain in its content after the `s` TLV.
    TrailingElements,
}

/// Decode one INTEGER field TLV from the front of `input`, returning its validated content octets
/// and the bytes consumed. Composes [`decode_tlv`] + [`validate_integer_content`], the same shape as
/// [`crate::x509_tbs_certificate`]'s inline `serialNumber` handling.
fn decode_integer_tlv(input: &[u8]) -> Result<(&[u8], usize), IntegerFieldError> {
    let (tlv, used) = decode_tlv(input).map_err(IntegerFieldError::Tlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != BIG_INTEGER_TAG {
        return Err(IntegerFieldError::WrongTag);
    }
    if tlv.tag.constructed {
        return Err(IntegerFieldError::Constructed);
    }
    validate_integer_content(tlv.value).map_err(IntegerFieldError::Content)?;
    Ok((tlv.value, used))
}

/// Decode `r` then `s` from an already-unwrapped outer SEQUENCE `content` slice, requiring the two
/// fields to exactly tile it. Shared by both [`parse_ecdsa_sig_value`] and
/// [`parse_ecdsa_sig_value_strict`] — the only difference between the two entry points is how the
/// outer envelope itself is decoded (composable vs. top-level-strict).
fn parse_fields(outer_content: &[u8]) -> Result<EcdsaSigValue<'_>, EcdsaSigValueError> {
    if outer_content.is_empty() {
        return Err(EcdsaSigValueError::MissingR);
    }
    let (r, r_used) = decode_integer_tlv(outer_content).map_err(EcdsaSigValueError::R)?;

    let rest = &outer_content[r_used..];
    if rest.is_empty() {
        return Err(EcdsaSigValueError::MissingS);
    }
    let (s, s_used) = decode_integer_tlv(rest).map_err(EcdsaSigValueError::S)?;
    if s_used != rest.len() {
        return Err(EcdsaSigValueError::TrailingElements);
    }

    Ok(EcdsaSigValue { r, s })
}

/// Parse one `ECDSA-Sig-Value` from the front of `input`.
///
/// Composable, like [`crate::sequence::decode_sequence_tlv`] and
/// [`crate::x509_algorithm_identifier::parse_algorithm_identifier`]: does **not** require `input` to
/// be consumed exactly (trailing bytes after this `ECDSA-Sig-Value` are ignored) — a top-level caller
/// checks the returned length itself, or uses [`parse_ecdsa_sig_value_strict`] directly.
///
/// Decodes, in order:
/// 1. the outer SEQUENCE envelope ([`decode_sequence_tlv`]);
/// 2. inside it, `r` then `s` (each an INTEGER TLV, composing [`crate::tlv::decode_tlv`] +
///    [`crate::big_integer::validate_integer_content`]), requiring the two fields to exactly tile
///    the SEQUENCE's content.
///
/// Never panics on any input (proven by the `parse_never_panics` Kani harness below); returns a
/// classified [`EcdsaSigValueError`] on any structural deviation.
pub fn parse_ecdsa_sig_value(input: &[u8]) -> Result<(EcdsaSigValue<'_>, usize), EcdsaSigValueError> {
    let (outer_content, used) = decode_sequence_tlv(input).map_err(EcdsaSigValueError::BadOuterSeq)?;
    let sig = parse_fields(outer_content)?;
    Ok((sig, used))
}

/// Parse a complete DER `ECDSA-Sig-Value`, requiring it to consume the *entire* `input` (no trailing
/// bytes) — mirrors [`crate::sequence::decode_sequence_tlv_strict`] and [`crate::x509_validity::parse_validity`]'s
/// top-level stance.
///
/// Use this when `input` is known to be exactly one `ECDSA-Sig-Value` and nothing else (e.g. the raw
/// bytes of a signature's `ANY`/OCTET STRING field, once the caller has already isolated them):
/// [`parse_ecdsa_sig_value`] deliberately ignores trailing bytes so it can compose inside a larger
/// structure, which is unsafe for a top-level object (the classic trailing-data parser differential).
pub fn parse_ecdsa_sig_value_strict(input: &[u8]) -> Result<EcdsaSigValue<'_>, EcdsaSigValueError> {
    let outer_content = decode_sequence_tlv_strict(input).map_err(EcdsaSigValueError::BadOuterSeq)?;
    parse_fields(outer_content)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer, matching `x509_algorithm_identifier`'s and
// `x509_validity`'s own bound. Unlike `x509_validity` (whose Time fields have an arithmetic floor of
// 13/15 content octets each, pushing its own Ok cover past 16 octets into disclosed vacuity), the
// smallest possible ECDSA-Sig-Value is small: an outer SEQUENCE header (>= 2 octets) plus two
// minimal-INTEGER TLVs (each `tag + len + >=1 content octet` = >= 3 octets), an arithmetic floor of
// 2 + 3 + 3 = 8 octets -- well inside 16, so (unlike `x509_validity::parse_never_panics`) the Ok cover
// below is NOT expected to be vacuous; run and read the actual satisfaction count rather than trusting
// this arithmetic (crate convention, `DOCS-SYNC.md`'s "watched to fail" discipline). The call chain
// performs up to three independent `decode_tlv` calls (outer SEQUENCE, `r`, `s`) plus
// `validate_integer_content`'s own unwind-free `if`-chain (no loop) -- no call recurses or loops over
// an unbounded sibling count (this parser reads a fixed two-field schema). `#[kani::unwind(20)]`
// covers a maximal-header `decode_tlv` (~11, per `tlv.rs`) with margin, matching
// `x509_algorithm_identifier::parse_algorithm_identifier_never_panics`'s bound; if Kani reports an
// unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_ecdsa_sig_value` never panics on any input up to 16 octets.
    ///
    /// Cover (T6 primary rule): witnesses the `Ok` tail AND, separately, every distinct structural
    /// rejection variant this module can classify -- not just "some input is accepted, some is
    /// rejected". Would NOT be SAT if `parse_ecdsa_sig_value`'s body were a no-op always returning
    /// `Err`, and a `0 of N satisfied` count on any one of these would flag a specific reject class
    /// as structurally unreachable at this bound (none is expected to be, given the 8-octet floor
    /// above; see the module doc's non-vacuity discipline).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_never_panics() {
        let buf: [u8; 16] = kani::any();
        let result = parse_ecdsa_sig_value(&buf);

        kani::cover(result.is_ok(), "a well-formed ECDSA-Sig-Value reaches the Ok tail");

        kani::cover(
            matches!(result, Err(EcdsaSigValueError::BadOuterSeq(SequenceError::WrongTag))),
            "outer envelope: a non-SEQUENCE tag is rejected",
        );
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::BadOuterSeq(SequenceError::NotConstructed))),
            "outer envelope: the primitive-form SEQUENCE identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::BadOuterSeq(SequenceError::Tlv(_)))),
            "outer envelope: malformed TLV framing (bad length / truncated) is rejected",
        );

        kani::cover(result == Err(EcdsaSigValueError::MissingR), "an empty outer content (no r) is rejected");
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::R(IntegerFieldError::WrongTag))),
            "r field: a non-INTEGER tag is rejected",
        );
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::R(IntegerFieldError::Constructed))),
            "r field: the constructed-form INTEGER identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::R(IntegerFieldError::Content(_)))),
            "r field: non-canonical INTEGER content (empty or non-minimal) is rejected",
        );

        kani::cover(
            result == Err(EcdsaSigValueError::MissingS),
            "r present but s absent (outer content ends after r) is rejected",
        );
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::S(IntegerFieldError::WrongTag))),
            "s field: a non-INTEGER tag is rejected",
        );
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::S(IntegerFieldError::Constructed))),
            "s field: the constructed-form INTEGER identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::S(IntegerFieldError::Content(_)))),
            "s field: non-canonical INTEGER content (empty or non-minimal) is rejected",
        );

        kani::cover(
            result == Err(EcdsaSigValueError::TrailingElements),
            "a third element inside the outer SEQUENCE (bytes remain after s) is rejected",
        );

        let _ = result;
    }

    /// Robustness: `parse_ecdsa_sig_value_strict` never panics on any input up to 16 octets, and
    /// specifically exercises its one behavioural difference from the composable entry point: a
    /// top-level trailing byte after an otherwise-complete `ECDSA-Sig-Value` is rejected.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_strict_never_panics() {
        let buf: [u8; 16] = kani::any();
        let result = parse_ecdsa_sig_value_strict(&buf);

        kani::cover(result.is_ok(), "a well-formed top-level ECDSA-Sig-Value (no trailing bytes) reaches the Ok tail");
        kani::cover(
            matches!(result, Err(EcdsaSigValueError::BadOuterSeq(SequenceError::TrailingData))),
            "strict decode rejects a byte trailing the whole ECDSA-Sig-Value",
        );

        let _ = result;
    }

    /// Positive-construction companion, on a real P-256-shaped specimen: `r` is 32 raw octets with
    /// its top bit set (so DER's minimal encoding needs the 33-octet 0x00 sign-guard form), `s` is 32
    /// octets with its top bit clear (no guard needed) -- byte-for-byte the module doc's own example.
    /// Unlike `x509_validity::parse_never_panics` (whose fully-symbolic 16-octet buffer cannot reach
    /// the >= 32-octet arithmetic floor its own Time fields impose, a disclosed vacuity), this
    /// module's floor is small enough that the fully-symbolic harnesses above ARE expected to witness
    /// `Ok` on their own -- this harness instead exists to machine-check the *specific*
    /// sign-guard-needed shape the module doc calls out, which the 16-octet symbolic harnesses cannot
    /// reach (33 + 32 content octets alone exceed 16).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_strict_ok_path_witnessed_high_bit_r() {
        #[rustfmt::skip]
        const SIG_P256_HIGH_BIT_R: [u8; 71] = [
            0x30, 0x45,
                0x02, 0x21,
                    0x00,
                    0xc6, 0x47, 0xd2, 0x3d, 0x87, 0xd2, 0x8e, 0x9f, 0x40, 0x8b, 0x4e, 0xcb, 0x1d, 0x27,
                    0xd3, 0x90, 0x8a, 0xed, 0x6f, 0xe1, 0xe0, 0x3e, 0x79, 0x4a, 0x3c, 0x5d, 0x21, 0x40,
                    0xb4, 0xe3, 0xd7, 0xe0,
                0x02, 0x20,
                    0x5a, 0x12, 0x9e, 0x44, 0x0f, 0x6b, 0x3a, 0x8c, 0x27, 0x51, 0xd0, 0x9a, 0x63, 0x1f,
                    0x84, 0xc2, 0x0e, 0x77, 0xab, 0x53, 0x19, 0xf6, 0x82, 0xcd, 0x45, 0x0b, 0x8e, 0x3d,
                    0x71, 0x2a, 0x96, 0x08,
        ];

        let result = parse_ecdsa_sig_value_strict(&SIG_P256_HIGH_BIT_R);
        kani::cover(
            result.is_ok(),
            "parse_ecdsa_sig_value_strict reaches its Ok tail on a real P-256-shaped signature whose \
             r needs the 33-octet sign-guard form -- the specific shape the 16-octet symbolic \
             harnesses above are too narrow to reach",
        );
        if let Ok(sig) = result {
            assert!(sig.r.len() == 33);
            assert!(sig.s.len() == 32);
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A real P-256-shaped ECDSA-Sig-Value: `r` is 32 raw octets with its top bit set, so DER's
    /// minimal two's-complement encoding requires a leading `0x00` sign-guard octet (33 content
    /// octets total); `s` is 32 octets whose top bit is clear (no guard needed). Same specimen as the
    /// module doc's own example and the Kani `parse_strict_ok_path_witnessed_high_bit_r` harness.
    ///
    /// `30 45`                    SEQUENCE, len 69
    ///    `02 21 00 c6 ..`        INTEGER r, len 33 (0x00 guard + 32 raw octets, top bit set)
    ///    `02 20 5a 12 ..`        INTEGER s, len 32 (top bit clear, no guard needed)
    #[rustfmt::skip]
    const SIG_P256_HIGH_BIT_R: [u8; 71] = [
        0x30, 0x45,
            0x02, 0x21,
                0x00,
                0xc6, 0x47, 0xd2, 0x3d, 0x87, 0xd2, 0x8e, 0x9f, 0x40, 0x8b, 0x4e, 0xcb, 0x1d, 0x27,
                0xd3, 0x90, 0x8a, 0xed, 0x6f, 0xe1, 0xe0, 0x3e, 0x79, 0x4a, 0x3c, 0x5d, 0x21, 0x40,
                0xb4, 0xe3, 0xd7, 0xe0,
            0x02, 0x20,
                0x5a, 0x12, 0x9e, 0x44, 0x0f, 0x6b, 0x3a, 0x8c, 0x27, 0x51, 0xd0, 0x9a, 0x63, 0x1f,
                0x84, 0xc2, 0x0e, 0x77, 0xab, 0x53, 0x19, 0xf6, 0x82, 0xcd, 0x45, 0x0b, 0x8e, 0x3d,
                0x71, 0x2a, 0x96, 0x08,
    ];

    /// A small ECDSA-Sig-Value with both `r` and `s` well below curve-scalar size: `r = 0x07`,
    /// `s = 0x2a` (both single-octet, positive, no guard needed) -- the minimal well-formed shape.
    ///
    /// `30 06`              SEQUENCE, len 6
    ///    `02 01 07`        INTEGER r = 7
    ///    `02 01 2a`        INTEGER s = 42
    #[rustfmt::skip]
    const SIG_SMALL: [u8; 8] = [
        0x30, 0x06,
            0x02, 0x01, 0x07,
            0x02, 0x01, 0x2a,
    ];

    #[test]
    fn parses_p256_shaped_sig_with_high_bit_r() {
        let sig = parse_ecdsa_sig_value_strict(&SIG_P256_HIGH_BIT_R).unwrap();
        assert_eq!(sig.r.len(), 33);
        assert_eq!(sig.r[0], 0x00); // the mandatory sign-guard octet
        assert_eq!(sig.r[1], 0xc6); // the real top byte, top bit set
        assert_eq!(sig.s.len(), 32);
        assert_eq!(sig.s[0], 0x5a);
    }

    #[test]
    fn parses_small_sig_composable() {
        let (sig, used) = parse_ecdsa_sig_value(&SIG_SMALL).unwrap();
        assert_eq!(used, 8);
        assert_eq!(sig.r, &[0x07]);
        assert_eq!(sig.s, &[0x2a]);
    }

    #[test]
    fn parses_small_sig_strict() {
        let sig = parse_ecdsa_sig_value_strict(&SIG_SMALL).unwrap();
        assert_eq!(sig.r, &[0x07]);
        assert_eq!(sig.s, &[0x2a]);
    }

    #[test]
    fn composable_ignores_trailing_bytes() {
        let mut bytes = SIG_SMALL.to_vec();
        bytes.push(0xFF);
        let (sig, used) = parse_ecdsa_sig_value(&bytes).unwrap();
        assert_eq!(used, 8);
        assert_eq!(sig.r, &[0x07]);
        assert_eq!(sig.s, &[0x2a]);
    }

    #[test]
    fn accepts_negative_r_der_permits_it_range_is_out_of_scope() {
        // r content is a single octet `0xFF` (value -1) -- structurally a valid *negative* minimal
        // INTEGER (DER permits negative INTEGERs; ECDSA's `1 <= r <= n-1` range rule needs a curve
        // order this module does not have -- see the module doc's Band B note). This test documents
        // that scope boundary directly: DER framing ACCEPTS this, exactly as `crate::big_integer`
        // does on its own.
        let bytes = [0x30, 0x06, 0x02, 0x01, 0xFF, 0x02, 0x01, 0x2a];
        let sig = parse_ecdsa_sig_value(&bytes).unwrap().0;
        assert_eq!(sig.r, &[0xFF]); // decodes to the negative value -1 -- accepted at the DER layer
        assert!(crate::big_integer::is_negative(sig.r));
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn strict_rejects_trailing_byte_after_sig() {
        let mut bytes = SIG_SMALL.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            parse_ecdsa_sig_value_strict(&bytes),
            Err(EcdsaSigValueError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = SIG_SMALL;
        bytes[0] = 0x31;
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_primitive_outer_sequence_identifier() {
        // 0x10 = UNIVERSAL 16 primitive. A SEQUENCE is always constructed (X.690 §8.9.1).
        let mut bytes = SIG_SMALL;
        bytes[0] = 0x10;
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::BadOuterSeq(SequenceError::NotConstructed))
        );
    }

    #[test]
    fn rejects_ber_long_form_length_where_short_form_fits() {
        // Outer SEQUENCE length 6 re-encoded in the BER long form (0x81 0x06) where DER requires the
        // short form (0x06) -- non-minimal (X.690 §8.1.3), forbidden by DER.
        use crate::length::LengthError;
        let mut bytes = vec![0x30, 0x81, 0x06];
        bytes.extend_from_slice(&SIG_SMALL[2..]);
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_truncated_outer_envelope() {
        // Declares 6 content bytes but only 3 are present.
        let bytes = [0x30, 0x06, 0x02, 0x01, 0x07];
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_empty_outer_content_missing_r() {
        let bytes = [0x30, 0x00];
        assert_eq!(parse_ecdsa_sig_value(&bytes), Err(EcdsaSigValueError::MissingR));
    }

    #[test]
    fn rejects_one_child_missing_s() {
        // Only r is present: 30 03 02 01 07  (SEQUENCE { INTEGER 7 }, no s)
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x07];
        assert_eq!(parse_ecdsa_sig_value(&bytes), Err(EcdsaSigValueError::MissingS));
    }

    #[test]
    fn rejects_three_children_trailing_elements() {
        // r, s, then a bogus extra BOOLEAN -- the third element is not permitted.
        // Content: 3 (INTEGER r) + 3 (INTEGER s) + 3 (BOOLEAN) = 9, so SEQUENCE length is 0x09.
        let bytes = [
            0x30, 0x09, // SEQUENCE, len 9
            0x02, 0x01, 0x07, // r = 7
            0x02, 0x01, 0x2a, // s = 42
            0x01, 0x01, 0xff, // extra BOOLEAN -- not permitted
        ];
        assert_eq!(parse_ecdsa_sig_value(&bytes), Err(EcdsaSigValueError::TrailingElements));
    }

    #[test]
    fn rejects_trailing_bytes_inside_sequence_content() {
        // r and s tile 6 of 7 declared content bytes -- one extra raw byte remains (not itself a
        // valid TLV start either, but that does not matter: s_used != rest.len() is caught first).
        let bytes = [0x30, 0x07, 0x02, 0x01, 0x07, 0x02, 0x01, 0x2a, 0xAA];
        assert_eq!(parse_ecdsa_sig_value(&bytes), Err(EcdsaSigValueError::TrailingElements));
    }

    #[test]
    fn rejects_r_wrong_tag() {
        // r's identifier is BOOLEAN (0x01) instead of INTEGER (0x02).
        let mut bytes = SIG_SMALL;
        bytes[2] = 0x01;
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::R(IntegerFieldError::WrongTag))
        );
    }

    #[test]
    fn rejects_r_constructed() {
        // r's identifier is INTEGER's tag number but in the constructed form (0x22 instead of 0x02).
        let mut bytes = SIG_SMALL;
        bytes[2] = 0x22;
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::R(IntegerFieldError::Constructed))
        );
    }

    #[test]
    fn rejects_r_empty_integer() {
        // r's INTEGER has zero content octets -- an INTEGER needs at least one (X.690 §8.3.1).
        // 30 05 02 00 02 01 2a  (SEQUENCE { INTEGER <empty>, INTEGER 42 })
        let bytes = [0x30, 0x05, 0x02, 0x00, 0x02, 0x01, 0x2a];
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::R(IntegerFieldError::Content(BigIntError::Empty)))
        );
    }

    #[test]
    fn rejects_r_non_minimal_redundant_leading_zero() {
        // r content is `00 07` -- a non-minimal encoding of 7 (redundant leading 0x00, since 0x07's
        // top bit is already clear and needs no sign guard). DER requires the minimal `07` alone.
        // 30 07 02 02 00 07 02 01 2a
        let bytes = [0x30, 0x07, 0x02, 0x02, 0x00, 0x07, 0x02, 0x01, 0x2a];
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::R(IntegerFieldError::Content(BigIntError::NonMinimal)))
        );
    }

    #[test]
    fn rejects_s_wrong_tag() {
        // s's identifier is BOOLEAN (0x01) instead of INTEGER (0x02).
        let mut bytes = SIG_SMALL;
        bytes[5] = 0x01;
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::S(IntegerFieldError::WrongTag))
        );
    }

    #[test]
    fn rejects_s_constructed() {
        let mut bytes = SIG_SMALL;
        bytes[5] = 0x22;
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::S(IntegerFieldError::Constructed))
        );
    }

    #[test]
    fn rejects_s_empty_integer() {
        // s's INTEGER has zero content octets.
        // 30 05 02 01 07 02 00  (SEQUENCE { INTEGER 7, INTEGER <empty> })
        let bytes = [0x30, 0x05, 0x02, 0x01, 0x07, 0x02, 0x00];
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::S(IntegerFieldError::Content(BigIntError::Empty)))
        );
    }

    #[test]
    fn rejects_s_non_minimal_redundant_leading_zero() {
        // s content is `00 2a` -- non-minimal (redundant leading 0x00; 0x2a's top bit is clear).
        // 30 07 02 01 07 02 02 00 2a
        let bytes = [0x30, 0x07, 0x02, 0x01, 0x07, 0x02, 0x02, 0x00, 0x2a];
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::S(IntegerFieldError::Content(BigIntError::NonMinimal)))
        );
    }

    #[test]
    fn rejects_truncated_r_tlv() {
        // r declares 4 content octets but the SEQUENCE content ends after 1.
        // 30 03 02 04 07 (r TLV over-reads)
        let bytes = [0x30, 0x03, 0x02, 0x04, 0x07];
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::R(IntegerFieldError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_truncated_s_tlv() {
        // r is a complete, valid INTEGER; s declares 4 content octets but only 1 is present. The
        // outer SEQUENCE's own declared length (6) matches what is actually present (so the outer
        // envelope itself is well-formed, and the truncation is caught later, inside s's own TLV).
        // 30 06 02 01 07 02 04 2a
        let bytes = [0x30, 0x06, 0x02, 0x01, 0x07, 0x02, 0x04, 0x2a];
        assert_eq!(
            parse_ecdsa_sig_value(&bytes),
            Err(EcdsaSigValueError::S(IntegerFieldError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_indefinite_length_outer_envelope() {
        // 0x30 0x80 = SEQUENCE with the BER indefinite length form; rejected by the length codec
        // (inherited), surfaced as Tlv(Length(Indefinite)).
        use crate::length::LengthError;
        assert_eq!(
            parse_ecdsa_sig_value(&[0x30, 0x80, 0x00, 0x00]),
            Err(EcdsaSigValueError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::Indefinite
            ))))
        );
    }
}
