//! `RSAPublicKey` (RFC 8017 §A.1.1, PKCS#1) — a bounded, **structural** consumer that composes
//! this crate's verified primitives.
//!
//! ```text
//! RSAPublicKey ::= SEQUENCE {
//!     modulus         INTEGER,  -- n
//!     publicExponent  INTEGER   -- e
//! }
//! ```
//!
//! This module is the sibling of [`crate::ecdsa_sig_value`]: structurally the *same* two-INTEGER
//! `SEQUENCE` shape, re-purposed for RFC 8017's RSA public key container rather than RFC 3279's
//! ECDSA signature container. It is a **demonstration of composition**, not an expansion of the
//! crate's DER-layer scope (see the crate-level docs). It frames the outer SEQUENCE and the two
//! INTEGER fields using [`crate::sequence`], [`crate::tlv`], and [`crate::big_integer`] verbatim —
//! it does not hand-roll any tag/length/TLV parsing of its own.
//!
//! **Where this container lives on the wire.** For an `rsaEncryption` key
//! (RFC 8017 §A.1, RFC 3279 §2.3.1), an X.509 `SubjectPublicKeyInfo`'s `subjectPublicKey` BIT
//! STRING payload is *itself* the DER encoding of an `RSAPublicKey`: [`crate::x509_spki`] already
//! extracts that BIT STRING's bit-payload octets as an opaque, uninterpreted span (it does not
//! know or care which algorithm the SPKI names). This module is what a caller who *has* extracted
//! those octets — having checked the SPKI's `algorithm` OID names `rsaEncryption` — applies next,
//! to frame the payload as an `RSAPublicKey`. **This module parses the container wherever it
//! appears in a byte string; it does not unwrap an SPKI itself, and it does not check any
//! algorithm OID** — that composition is the caller's job, exactly as `ecdsa_sig_value`'s own doc
//! frames its relationship to a signature's `BIT STRING`/OCTET STRING payload.
//!
//! **A composing caller must also check the BIT STRING is octet-aligned.** [`crate::x509_spki`]'s
//! [`SubjectPublicKeyInfo::subject_public_key`](crate::x509_spki::SubjectPublicKeyInfo) is a
//! [`crate::bit_string::BitString`], not a bare byte slice: it carries an `unused`
//! (`0..=7`) count of trailing padding bits alongside `data`. A BIT STRING with `unused != 0` is
//! *not* a complete, octet-aligned DER payload — its final octet carries padding bits that are
//! part of the encoding, not of an embedded `RSAPublicKey`. A caller MUST require `unused == 0`
//! (e.g. via [`crate::bit_string::require_octet_aligned`]) before handing `subject_public_key.data`
//! to [`parse_rsa_public_key_strict`]; skipping that check silently discards metadata this module
//! has no way to see, since it only ever receives `&[u8]`.
//!
//! **`modulus`/`publicExponent` are exposed as raw validated content, not materialized as
//! numbers.** Following [`crate::big_integer`]'s own stance (`DECISIONS.md` D14) and
//! [`crate::ecdsa_sig_value`]'s `r`/`s` precedent: an RSA modulus and exponent are used downstream
//! for arithmetic (modular exponentiation) this crate does not perform, so
//! [`RsaPublicKey::modulus`] and [`RsaPublicKey::public_exponent`] are `&[u8]` — the
//! validated-minimal two's-complement content octets, borrowed from the input, exactly as
//! `big_integer` hands them back.
//!
//! **Scope boundaries (deliberate) — this module proves DER framing and canonicality ONLY:**
//! - *Structural framing only.* [`parse_rsa_public_key`] / [`parse_rsa_public_key_strict`]
//!   validate that the byte string is a well-formed, DER-canonical `RSAPublicKey` with the exact
//!   field tiling the ASN.1 schema requires (`modulus`, then `publicExponent`, nothing more,
//!   nothing less), and that each INTEGER's *content* is itself canonical DER (minimal two's-complement,
//!   no redundant sign-guard padding — [`crate::big_integer::validate_integer_content`]).
//! - **⛔ Out of scope: exponent oddness/minimum-value policy.** Real-world guidance (e.g. requiring
//!   `e` to be odd, `e >= 3`, or `e == 65537`) is a *key-generation/acceptance policy* choice, not a
//!   DER-validity requirement of RFC 8017's ASN.1 schema itself — RFC 8017 places no such
//!   constraint on the encoding, only on how the key is *used*. Any such rule belongs in a
//!   profile layer alongside [`crate::profile`], not in a transfer-syntax codec.
//! - **⛔ Out of scope: modulus size policy.** Minimum/maximum bit-length requirements (e.g. "reject
//!   moduli under 2048 bits") are a deployment/acceptance policy, not a framing property this
//!   module can universally assert — this module only proves the INTEGER's *encoding* is
//!   canonical DER, not any bound on its magnitude.
//! - **⛔ Out of scope: any RSA semantics.** No primality, no `n = p*q` structure check, no
//!   relationship between `modulus` and `publicExponent`, no cryptographic interpretation
//!   whatsoever — `modulus`/`public_exponent` are opaque, comparison/arithmetic-elsewhere byte
//!   strings to this module, exactly as `ecdsa_sig_value`'s own module doc frames `r`/`s`.
//! - **⛔ Out of scope: unwrapping an SPKI.** This module parses an `RSAPublicKey` wherever the
//!   caller hands it one — it does not know about, and does not parse, the outer
//!   `SubjectPublicKeyInfo` SEQUENCE or its `AlgorithmIdentifier`/BIT STRING framing (that is
//!   [`crate::x509_spki`]'s and [`crate::x509_algorithm_identifier`]'s job).
//! - *Strict/lenient outer-trailing variants, matching the crate's established split
//!   ([`crate::sequence::decode_sequence_tlv`] / [`crate::sequence::decode_sequence_tlv_strict`]).*
//!   [`parse_rsa_public_key`] is composable — it does not require `input` to be consumed exactly,
//!   so it can sit inside a larger structure (e.g. as the payload of a BIT STRING whose own length
//!   was already checked by the caller). [`parse_rsa_public_key_strict`] additionally requires
//!   `input` to be consumed exactly — the right choice when a caller already knows the whole byte
//!   string is supposed to be one `RSAPublicKey` and nothing else (e.g. an SPKI's already-isolated
//!   BIT STRING payload for an `rsaEncryption` key), guarding the classic trailing-data parser-
//!   differential vector.
//!
//! **Why this module matters: the differential surface, not the arithmetic.** Just like
//! `ECDSA-Sig-Value`, `RSAPublicKey`'s DER-vs-BER framing is a historically productive
//! parser-differential surface: BER's lax INTEGER encoding (leading-zero padding, non-canonical
//! lengths) tolerated by some parsers is exactly the kind of malleability strict DER forecloses.
//! This module proves the DER-canonicality half of that boundary — malleable encodings of the
//! *same* `(modulus, publicExponent)` pair are rejected, not merely one canonical encoding
//! accepted — leaving the *value*-level policy questions above (exponent policy, modulus size) to
//! a caller.
//!
//! # Examples
//!
//! ```
//! use der_verified::rsa_public_key::parse_rsa_public_key_strict;
//!
//! // A small RSAPublicKey: modulus = 0x00E1 (a leading-zero sign guard, since 0xE1's top bit is
//! // set), publicExponent = 65537 (0x010001, the conventional `e`).
//! #[rustfmt::skip]
//! let key_der: [u8; 11] = [
//!     0x30, 0x09,
//!         0x02, 0x02, 0x00, 0xE1,
//!         0x02, 0x03, 0x01, 0x00, 0x01,
//! ];
//! let key = parse_rsa_public_key_strict(&key_der).unwrap();
//! assert_eq!(key.modulus, &[0x00, 0xE1]);
//! assert_eq!(key.public_exponent, &[0x01, 0x00, 0x01]);
//! ```

use crate::big_integer::{validate_integer_content, BigIntError, TAG as BIG_INTEGER_TAG};
use crate::sequence::{decode_sequence_tlv, decode_sequence_tlv_strict, SequenceError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};

/// A structurally-parsed `RSAPublicKey`, borrowing from the input it was parsed from.
///
/// See the module docs for the scope of what "parsed" means here: DER framing and canonicality
/// only — no exponent policy, no modulus size policy, no RSA semantics.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RsaPublicKey<'a> {
    /// `modulus` (`n`): the validated-minimal INTEGER **content** octets (not the TLV header),
    /// opaque — see [`crate::big_integer`]'s comparison-only stance. Never materialized as a
    /// numeric value; a caller that needs the numeric value (e.g. for modular exponentiation, or
    /// to check its bit-length against a policy) does that itself.
    pub modulus: &'a [u8],
    /// `publicExponent` (`e`): the validated-minimal INTEGER **content** octets, opaque, exactly
    /// like [`Self::modulus`].
    pub public_exponent: &'a [u8],
}

/// Why one of the two INTEGER fields (`modulus` or `publicExponent`) was rejected. Shared
/// taxonomy for both fields, mirroring [`crate::ecdsa_sig_value::IntegerFieldError`]'s pattern.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum IntegerFieldError {
    /// The field's TLV framing (tag/length octets) was malformed.
    Tlv(TlvError),
    /// The field's identifier was well-framed but not UNIVERSAL 2 (INTEGER).
    WrongTag,
    /// The field's identifier was UNIVERSAL 2 but in the constructed form — INTEGER content is
    /// always primitive.
    Constructed,
    /// The field's content failed canonical-DER minimality (empty, or redundant sign-guard
    /// padding).
    Content(BigIntError),
}

/// Why an `RSAPublicKey` was rejected. Every variant names a specific structural cause, wrapping
/// the underlying primitive's error where one exists.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RsaPublicKeyError {
    /// The outer `RSAPublicKey` SEQUENCE envelope was malformed: bad identifier/length, the
    /// primitive (non-constructed) form, or — for [`parse_rsa_public_key_strict`] only — trailing
    /// bytes after the whole structure.
    BadOuterSeq(SequenceError),
    /// No `modulus` is present — the outer SEQUENCE's content is empty.
    MissingModulus,
    /// The `modulus` field failed to decode.
    Modulus(IntegerFieldError),
    /// No `publicExponent` is present — the outer SEQUENCE's content ended after `modulus`.
    MissingPublicExponent,
    /// The `publicExponent` field failed to decode.
    PublicExponent(IntegerFieldError),
    /// The `RSAPublicKey` SEQUENCE has more than its two permitted fields (`modulus`,
    /// `publicExponent`): bytes remain in its content after the `publicExponent` TLV.
    TrailingElements,
}

/// Decode one INTEGER field TLV from the front of `input`, returning its validated content octets
/// and the bytes consumed. Composes [`decode_tlv`] + [`validate_integer_content`], the same shape
/// as [`crate::ecdsa_sig_value`]'s own `decode_integer_tlv`.
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

/// Decode `modulus` then `publicExponent` from an already-unwrapped outer SEQUENCE `content`
/// slice, requiring the two fields to exactly tile it. Shared by both [`parse_rsa_public_key`]
/// and [`parse_rsa_public_key_strict`] — the only difference between the two entry points is how
/// the outer envelope itself is decoded (composable vs. top-level-strict).
fn parse_fields(outer_content: &[u8]) -> Result<RsaPublicKey<'_>, RsaPublicKeyError> {
    if outer_content.is_empty() {
        return Err(RsaPublicKeyError::MissingModulus);
    }
    let (modulus, modulus_used) =
        decode_integer_tlv(outer_content).map_err(RsaPublicKeyError::Modulus)?;

    let rest = &outer_content[modulus_used..];
    if rest.is_empty() {
        return Err(RsaPublicKeyError::MissingPublicExponent);
    }
    let (public_exponent, exponent_used) =
        decode_integer_tlv(rest).map_err(RsaPublicKeyError::PublicExponent)?;
    if exponent_used != rest.len() {
        return Err(RsaPublicKeyError::TrailingElements);
    }

    Ok(RsaPublicKey { modulus, public_exponent })
}

/// Parse one `RSAPublicKey` from the front of `input`.
///
/// Composable, like [`crate::sequence::decode_sequence_tlv`] and
/// [`crate::ecdsa_sig_value::parse_ecdsa_sig_value`]: does **not** require `input` to be consumed
/// exactly (trailing bytes after this `RSAPublicKey` are ignored) — a top-level caller checks the
/// returned length itself, or uses [`parse_rsa_public_key_strict`] directly.
///
/// Decodes, in order:
/// 1. the outer SEQUENCE envelope ([`decode_sequence_tlv`]);
/// 2. inside it, `modulus` then `publicExponent` (each an INTEGER TLV, composing
///    [`crate::tlv::decode_tlv`] + [`crate::big_integer::validate_integer_content`]), requiring
///    the two fields to exactly tile the SEQUENCE's content.
///
/// Never panics on any input (proven by the `parse_never_panics` Kani harness below); returns a
/// classified [`RsaPublicKeyError`] on any structural deviation.
pub fn parse_rsa_public_key(input: &[u8]) -> Result<(RsaPublicKey<'_>, usize), RsaPublicKeyError> {
    let (outer_content, used) =
        decode_sequence_tlv(input).map_err(RsaPublicKeyError::BadOuterSeq)?;
    let key = parse_fields(outer_content)?;
    Ok((key, used))
}

/// Parse a complete DER `RSAPublicKey`, requiring it to consume the *entire* `input` (no trailing
/// bytes) — mirrors [`crate::sequence::decode_sequence_tlv_strict`] and
/// [`crate::ecdsa_sig_value::parse_ecdsa_sig_value_strict`]'s top-level stance.
///
/// Use this when `input` is known to be exactly one `RSAPublicKey` and nothing else (e.g. an
/// SPKI's already-isolated BIT STRING payload octets for an `rsaEncryption` key, once the caller
/// has already checked the SPKI's `algorithm` OID and isolated the payload):
/// [`parse_rsa_public_key`] deliberately ignores trailing bytes so it can compose inside a larger
/// structure, which is unsafe for a top-level object (the classic trailing-data parser
/// differential).
pub fn parse_rsa_public_key_strict(input: &[u8]) -> Result<RsaPublicKey<'_>, RsaPublicKeyError> {
    let outer_content = decode_sequence_tlv_strict(input).map_err(RsaPublicKeyError::BadOuterSeq)?;
    parse_fields(outer_content)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer with a symbolic LENGTH (`0..=16`), matching
// `ecdsa_sig_value`'s own bound (the two modules share the identical two-INTEGER SEQUENCE shape)
// and the crate's established symbolic-length convention (`x509_certificate.rs`,
// `x509_tbs_certificate.rs`, `x509_name.rs`, `x509_extension.rs`): a fixed-length-only proof would
// leave every shorter input UNDISCHARGED, since control flow is length-dependent — a claim of
// "every input up to 16 octets" requires exploring every length in `0..=16`, not just the single
// length 16. The smallest possible RSAPublicKey is small: an outer SEQUENCE header (>= 2 octets)
// plus two minimal-INTEGER TLVs (each `tag + len + >=1 content octet` = >= 3 octets), an
// arithmetic floor of 2 + 3 + 3 = 8 octets -- well inside the 0..=16 domain, so the Ok cover below
// is NOT expected to be vacuous; run and read the actual satisfaction count rather than trusting
// this arithmetic (crate convention). The call chain performs up to three independent `decode_tlv`
// calls (outer SEQUENCE, `modulus`, `publicExponent`) plus `validate_integer_content`'s own
// unwind-free `if`-chain (no loop) -- no call recurses or loops over an unbounded sibling count
// (this parser reads a fixed two-field schema). `#[kani::unwind(20)]` covers a maximal-header
// `decode_tlv` (~11, per `tlv.rs`) with margin, matching `ecdsa_sig_value`'s own bound; if Kani
// reports an unwinding-assertion failure, raise this bound (do not weaken scope).
//
// A realistic RSA-2048 modulus (257 content octets: a 256-octet 2048-bit value whose top bit is
// set, plus the mandatory 0x00 sign-guard octet) is far outside what a 16-octet symbolic buffer
// can reach, and CBMC does not scale to a >256-octet fully-symbolic buffer for this crate's
// harness style -- so, exactly like `ecdsa_sig_value::parse_strict_ok_path_witnessed_high_bit_r`,
// that realistic shape is witnessed by a dedicated CONCRETE-specimen harness below
// (`parse_strict_ok_path_witnessed_rsa_2048_shaped`) rather than by widening the symbolic bound;
// the large-modulus case is additionally covered by a concrete `#[test]` (not just the Kani
// harness) in the tests module below.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_rsa_public_key` never panics on any input **of any length up to 16
    /// octets** -- the buffer AND its length are both symbolic (see the module's Kani sizing
    /// comment), so this is a bounded claim over the whole `0..=16`-octet domain, not just the
    /// single 16-octet length.
    ///
    /// Cover (T6 primary rule): witnesses the `Ok` tail AND, separately, every distinct structural
    /// rejection variant this module can classify -- not just "some input is accepted, some is
    /// rejected". Would NOT be SAT if `parse_rsa_public_key`'s body were a no-op always returning
    /// `Err`, and a `0 of N satisfied` count on any one of these would flag a specific reject class
    /// as structurally unreachable at this bound (none is expected to be, given the 8-octet floor
    /// above; see the module doc's non-vacuity discipline).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_never_panics() {
        let buf: [u8; 16] = kani::any();
        // Symbolic input length, matching the crate's established convention (see
        // `x509_tbs_certificate.rs`, `x509_name.rs`): so the "any input up to 16 octets" claim
        // above holds at every length in the domain, not just the single length 16.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = parse_rsa_public_key(input);

        kani::cover(result.is_ok(), "a well-formed RSAPublicKey reaches the Ok tail");

        kani::cover(
            matches!(result, Err(RsaPublicKeyError::BadOuterSeq(SequenceError::WrongTag))),
            "outer envelope: a non-SEQUENCE tag is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::BadOuterSeq(SequenceError::NotConstructed))),
            "outer envelope: the primitive-form SEQUENCE identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::BadOuterSeq(SequenceError::Tlv(_)))),
            "outer envelope: malformed TLV framing (bad length / truncated) is rejected",
        );

        kani::cover(
            result == Err(RsaPublicKeyError::MissingModulus),
            "an empty outer content (no modulus) is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::Modulus(IntegerFieldError::Tlv(_)))),
            "modulus field: malformed TLV framing (bad length / truncated) is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::Modulus(IntegerFieldError::WrongTag))),
            "modulus field: a non-INTEGER tag is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::Modulus(IntegerFieldError::Constructed))),
            "modulus field: the constructed-form INTEGER identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::Modulus(IntegerFieldError::Content(_)))),
            "modulus field: non-canonical INTEGER content (empty or non-minimal) is rejected",
        );

        kani::cover(
            result == Err(RsaPublicKeyError::MissingPublicExponent),
            "modulus present but publicExponent absent (outer content ends after modulus) is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::Tlv(_)))),
            "publicExponent field: malformed TLV framing (bad length / truncated) is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::WrongTag))),
            "publicExponent field: a non-INTEGER tag is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::Constructed))),
            "publicExponent field: the constructed-form INTEGER identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::Content(_)))),
            "publicExponent field: non-canonical INTEGER content (empty or non-minimal) is rejected",
        );

        kani::cover(
            result == Err(RsaPublicKeyError::TrailingElements),
            "a third element inside the outer SEQUENCE (bytes remain after publicExponent) is rejected",
        );

        let _ = result;
    }

    /// Robustness: `parse_rsa_public_key_strict` never panics on any input **of any length up to
    /// 16 octets** (buffer and length both symbolic, matching `parse_never_panics` above), and
    /// specifically exercises its one behavioural difference from the composable entry point: a
    /// top-level trailing byte after an otherwise-complete `RSAPublicKey` is rejected.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_strict_never_panics() {
        let buf: [u8; 16] = kani::any();
        // Symbolic input length -- see `parse_never_panics`'s doc comment.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = parse_rsa_public_key_strict(input);

        kani::cover(result.is_ok(), "a well-formed top-level RSAPublicKey (no trailing bytes) reaches the Ok tail");
        kani::cover(
            matches!(result, Err(RsaPublicKeyError::BadOuterSeq(SequenceError::TrailingData))),
            "strict decode rejects a byte trailing the whole RSAPublicKey",
        );

        let _ = result;
    }

    /// Positive-construction companion, on a real RSA-2048-shaped specimen: `modulus` is a
    /// 256-octet (2048-bit) value whose top bit is set, so DER's minimal encoding needs the
    /// 257-octet `0x00` sign-guard form; `publicExponent` is `65537` (the conventional `e`,
    /// `02 03 01 00 01`). Unlike `x509_validity::parse_never_panics` (whose fully-symbolic
    /// 16-octet buffer cannot reach its own arithmetic floor, a disclosed vacuity), this module's
    /// floor is small enough that the fully-symbolic harnesses above ARE expected to witness `Ok`
    /// on their own -- this harness instead exists to machine-check the *specific* realistic
    /// RSA-2048-shaped specimen the module doc calls out, which the 16-octet symbolic harnesses
    /// cannot reach (257 + 3 content octets alone vastly exceed 16). The large-modulus case is
    /// deliberately NOT pushed into the symbolic bound above (CBMC does not scale to a
    /// >256-octet fully-symbolic buffer at this crate's harness style) -- it is covered by this
    /// one concrete Kani harness plus a concrete `#[test]` below, exactly the same tradeoff
    /// `ecdsa_sig_value` makes for its own P-256-shaped specimen.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_strict_ok_path_witnessed_rsa_2048_shaped() {
        let result = parse_rsa_public_key_strict(&RSA_2048_SHAPED_DER);
        kani::cover(
            result.is_ok(),
            "parse_rsa_public_key_strict reaches its Ok tail on a real RSA-2048-shaped key whose \
             modulus needs the 257-octet sign-guard form -- the specific shape the 16-octet \
             symbolic harnesses above are too narrow to reach",
        );
        if let Ok(key) = result {
            assert!(key.modulus.len() == 257);
            assert!(key.public_exponent == [0x01, 0x00, 0x01]);
        }
    }
}

/// A concrete RSA-2048-shaped `RSAPublicKey` DER encoding, shared by the Kani harness above and
/// the concrete test below (so the two stay byte-for-byte identical): a 256-octet modulus with a
/// deterministic non-uniform filler and its top bit forced set (so DER's minimal two's-complement
/// encoding requires the leading `0x00` sign-guard octet, 257 content octets total), and
/// `publicExponent = 65537` (`02 03 01 00 01`, the conventional `e`).
///
/// `30 82 01 0a`                 SEQUENCE, len 266 (long form, 2 length octets)
///    `02 82 01 01 00 <256 octets>`   INTEGER modulus, len 257 (0x00 guard + 256 raw octets, top bit set)
///    `02 03 01 00 01`                INTEGER publicExponent = 65537
#[cfg(any(kani, test))]
#[rustfmt::skip]
const RSA_2048_SHAPED_DER: [u8; 270] = [
    0x30, 0x82, 0x01, 0x0a, 0x02, 0x82, 0x01, 0x01, 0x00, 0xa5, 0x06, 0x67,
    0xc8, 0x29, 0x8a, 0xeb, 0x4c, 0xad, 0x0e, 0x6f, 0xd0, 0x31, 0x92, 0xf3,
    0x54, 0xb5, 0x16, 0x77, 0xd8, 0x39, 0x9a, 0xfb, 0x5c, 0xbd, 0x1e, 0x7f,
    0xe0, 0x41, 0xa2, 0x03, 0x64, 0xc5, 0x26, 0x87, 0xe8, 0x49, 0xaa, 0x0b,
    0x6c, 0xcd, 0x2e, 0x8f, 0xf0, 0x51, 0xb2, 0x13, 0x74, 0xd5, 0x36, 0x97,
    0xf8, 0x59, 0xba, 0x1b, 0x7c, 0xdd, 0x3e, 0x9f, 0x00, 0x61, 0xc2, 0x23,
    0x84, 0xe5, 0x46, 0xa7, 0x08, 0x69, 0xca, 0x2b, 0x8c, 0xed, 0x4e, 0xaf,
    0x10, 0x71, 0xd2, 0x33, 0x94, 0xf5, 0x56, 0xb7, 0x18, 0x79, 0xda, 0x3b,
    0x9c, 0xfd, 0x5e, 0xbf, 0x20, 0x81, 0xe2, 0x43, 0xa4, 0x05, 0x66, 0xc7,
    0x28, 0x89, 0xea, 0x4b, 0xac, 0x0d, 0x6e, 0xcf, 0x30, 0x91, 0xf2, 0x53,
    0xb4, 0x15, 0x76, 0xd7, 0x38, 0x99, 0xfa, 0x5b, 0xbc, 0x1d, 0x7e, 0xdf,
    0x40, 0xa1, 0x02, 0x63, 0xc4, 0x25, 0x86, 0xe7, 0x48, 0xa9, 0x0a, 0x6b,
    0xcc, 0x2d, 0x8e, 0xef, 0x50, 0xb1, 0x12, 0x73, 0xd4, 0x35, 0x96, 0xf7,
    0x58, 0xb9, 0x1a, 0x7b, 0xdc, 0x3d, 0x9e, 0xff, 0x60, 0xc1, 0x22, 0x83,
    0xe4, 0x45, 0xa6, 0x07, 0x68, 0xc9, 0x2a, 0x8b, 0xec, 0x4d, 0xae, 0x0f,
    0x70, 0xd1, 0x32, 0x93, 0xf4, 0x55, 0xb6, 0x17, 0x78, 0xd9, 0x3a, 0x9b,
    0xfc, 0x5d, 0xbe, 0x1f, 0x80, 0xe1, 0x42, 0xa3, 0x04, 0x65, 0xc6, 0x27,
    0x88, 0xe9, 0x4a, 0xab, 0x0c, 0x6d, 0xce, 0x2f, 0x90, 0xf1, 0x52, 0xb3,
    0x14, 0x75, 0xd6, 0x37, 0x98, 0xf9, 0x5a, 0xbb, 0x1c, 0x7d, 0xde, 0x3f,
    0xa0, 0x01, 0x62, 0xc3, 0x24, 0x85, 0xe6, 0x47, 0xa8, 0x09, 0x6a, 0xcb,
    0x2c, 0x8d, 0xee, 0x4f, 0xb0, 0x11, 0x72, 0xd3, 0x34, 0x95, 0xf6, 0x57,
    0xb8, 0x19, 0x7a, 0xdb, 0x3c, 0x9d, 0xfe, 0x5f, 0xc0, 0x21, 0x82, 0xe3,
    0x44, 0x02, 0x03, 0x01, 0x00, 0x01,
];

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A small RSAPublicKey with both fields well below realistic RSA size: `modulus = 0x00E1`
    /// (leading-zero sign guard, since 0xE1's top bit is set), `publicExponent = 65537`
    /// (`0x010001`, the conventional `e`) -- the minimal well-formed shape this module's own
    /// module-doc example uses.
    ///
    /// `30 09`                    SEQUENCE, len 9
    ///    `02 02 00 e1`           INTEGER modulus (guard + 1 raw octet, top bit set)
    ///    `02 03 01 00 01`        INTEGER publicExponent = 65537
    #[rustfmt::skip]
    const KEY_SMALL: [u8; 11] = [
        0x30, 0x09,
            0x02, 0x02, 0x00, 0xE1,
            0x02, 0x03, 0x01, 0x00, 0x01,
    ];

    #[test]
    fn parses_small_key_composable() {
        let (key, used) = parse_rsa_public_key(&KEY_SMALL).unwrap();
        assert_eq!(used, 11);
        assert_eq!(key.modulus, &[0x00, 0xE1]);
        assert_eq!(key.public_exponent, &[0x01, 0x00, 0x01]);
    }

    #[test]
    fn parses_small_key_strict() {
        let key = parse_rsa_public_key_strict(&KEY_SMALL).unwrap();
        assert_eq!(key.modulus, &[0x00, 0xE1]);
        assert_eq!(key.public_exponent, &[0x01, 0x00, 0x01]);
    }

    /// The realistic accept-vector: an RSA-2048-shaped modulus (257 content octets, incl. the
    /// mandatory 0x00 sign-guard) with `e = 65537` -- the shape a real `rsaEncryption` SPKI
    /// carries, and the shape the module doc's Kani sizing note explains is out of the symbolic
    /// harnesses' reach. Same specimen as `proofs::parse_strict_ok_path_witnessed_rsa_2048_shaped`.
    #[test]
    fn parses_rsa_2048_shaped_key_strict() {
        let key = parse_rsa_public_key_strict(&RSA_2048_SHAPED_DER).unwrap();
        assert_eq!(key.modulus.len(), 257);
        assert_eq!(key.modulus[0], 0x00); // the mandatory sign-guard octet
        assert!(key.modulus[1] & 0x80 != 0); // the real top byte, top bit set
        assert_eq!(key.public_exponent, &[0x01, 0x00, 0x01]);
    }

    #[test]
    fn composable_ignores_trailing_bytes() {
        let mut bytes = KEY_SMALL.to_vec();
        bytes.push(0xFF);
        let (key, used) = parse_rsa_public_key(&bytes).unwrap();
        assert_eq!(used, 11);
        assert_eq!(key.modulus, &[0x00, 0xE1]);
        assert_eq!(key.public_exponent, &[0x01, 0x00, 0x01]);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn strict_rejects_trailing_byte_after_key() {
        let mut bytes = KEY_SMALL.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            parse_rsa_public_key_strict(&bytes),
            Err(RsaPublicKeyError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = KEY_SMALL;
        bytes[0] = 0x31;
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_primitive_outer_sequence_identifier() {
        // 0x10 = UNIVERSAL 16 primitive. A SEQUENCE is always constructed (X.690 §8.9.1).
        let mut bytes = KEY_SMALL;
        bytes[0] = 0x10;
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::BadOuterSeq(SequenceError::NotConstructed))
        );
    }

    #[test]
    fn rejects_ber_long_form_length_where_short_form_fits() {
        // Outer SEQUENCE length 9 re-encoded in the BER long form (0x81 0x09) where DER requires
        // the short form (0x09) -- non-minimal (X.690 §8.1.3), forbidden by DER.
        use crate::length::LengthError;
        let mut bytes = vec![0x30, 0x81, 0x09];
        bytes.extend_from_slice(&KEY_SMALL[2..]);
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_truncated_outer_envelope() {
        // Declares 9 content bytes but only 4 are present.
        let bytes = [0x30, 0x09, 0x02, 0x02, 0x00, 0xE1];
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_empty_outer_content_missing_modulus() {
        let bytes = [0x30, 0x00];
        assert_eq!(parse_rsa_public_key(&bytes), Err(RsaPublicKeyError::MissingModulus));
    }

    #[test]
    fn rejects_one_child_missing_public_exponent() {
        // Only modulus is present: 30 04 02 02 00 e1 (SEQUENCE { INTEGER 0x00E1 }, no exponent)
        let bytes = [0x30, 0x04, 0x02, 0x02, 0x00, 0xE1];
        assert_eq!(parse_rsa_public_key(&bytes), Err(RsaPublicKeyError::MissingPublicExponent));
    }

    #[test]
    fn rejects_three_children_trailing_elements() {
        // modulus, publicExponent, then a bogus extra BOOLEAN -- the third element is not
        // permitted. Content: 4 (INTEGER modulus) + 5 (INTEGER exponent) + 3 (BOOLEAN) = 12, so
        // SEQUENCE length is 0x0c.
        let bytes = [
            0x30, 0x0c, // SEQUENCE, len 12
            0x02, 0x02, 0x00, 0xE1, // modulus = 0x00E1
            0x02, 0x03, 0x01, 0x00, 0x01, // publicExponent = 65537
            0x01, 0x01, 0xff, // extra BOOLEAN -- not permitted
        ];
        assert_eq!(parse_rsa_public_key(&bytes), Err(RsaPublicKeyError::TrailingElements));
    }

    #[test]
    fn rejects_trailing_bytes_inside_sequence_content() {
        // modulus and publicExponent tile 9 of 10 declared content bytes -- one extra raw byte
        // remains (not itself a valid TLV start either, but that does not matter:
        // exponent_used != rest.len() is caught first).
        let bytes = [0x30, 0x0a, 0x02, 0x02, 0x00, 0xE1, 0x02, 0x03, 0x01, 0x00, 0x01, 0xAA];
        assert_eq!(parse_rsa_public_key(&bytes), Err(RsaPublicKeyError::TrailingElements));
    }

    #[test]
    fn rejects_modulus_wrong_tag() {
        // modulus's identifier is BOOLEAN (0x01) instead of INTEGER (0x02).
        let mut bytes = KEY_SMALL;
        bytes[2] = 0x01;
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::Modulus(IntegerFieldError::WrongTag))
        );
    }

    #[test]
    fn rejects_modulus_constructed() {
        // modulus's identifier is INTEGER's tag number but in the constructed form (0x22 instead
        // of 0x02).
        let mut bytes = KEY_SMALL;
        bytes[2] = 0x22;
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::Modulus(IntegerFieldError::Constructed))
        );
    }

    #[test]
    fn rejects_modulus_empty_integer() {
        // modulus's INTEGER has zero content octets -- an INTEGER needs at least one (X.690
        // §8.3.1). 30 07 02 00 02 03 01 00 01 (SEQUENCE { INTEGER <empty>, INTEGER 65537 })
        let bytes = [0x30, 0x07, 0x02, 0x00, 0x02, 0x03, 0x01, 0x00, 0x01];
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::Modulus(IntegerFieldError::Content(BigIntError::Empty)))
        );
    }

    #[test]
    fn rejects_modulus_non_minimal_redundant_leading_zero() {
        // modulus content is `00 07` -- a non-minimal encoding of 7 (redundant leading 0x00,
        // since 0x07's top bit is already clear and needs no sign guard). DER requires the
        // minimal `07` alone.
        // 30 09 02 02 00 07 02 03 01 00 01
        let bytes = [0x30, 0x09, 0x02, 0x02, 0x00, 0x07, 0x02, 0x03, 0x01, 0x00, 0x01];
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::Modulus(IntegerFieldError::Content(BigIntError::NonMinimal)))
        );
    }

    #[test]
    fn rejects_public_exponent_wrong_tag() {
        // publicExponent's identifier is BOOLEAN (0x01) instead of INTEGER (0x02).
        let mut bytes = KEY_SMALL;
        bytes[6] = 0x01;
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::WrongTag))
        );
    }

    #[test]
    fn rejects_public_exponent_constructed() {
        let mut bytes = KEY_SMALL;
        bytes[6] = 0x22;
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::Constructed))
        );
    }

    #[test]
    fn rejects_public_exponent_empty_integer() {
        // publicExponent's INTEGER has zero content octets.
        // 30 06 02 02 00 e1 02 00 (SEQUENCE { INTEGER 0x00E1, INTEGER <empty> })
        let bytes = [0x30, 0x06, 0x02, 0x02, 0x00, 0xE1, 0x02, 0x00];
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::Content(BigIntError::Empty)))
        );
    }

    #[test]
    fn rejects_public_exponent_non_minimal_redundant_leading_zero() {
        // publicExponent content is `00 01 00 01` -- non-minimal (redundant leading 0x00; the
        // real value 0x010001's top bit is already clear). DER requires the minimal `01 00 01`
        // alone.
        // 30 0a 02 02 00 e1 02 04 00 01 00 01
        let bytes = [0x30, 0x0a, 0x02, 0x02, 0x00, 0xE1, 0x02, 0x04, 0x00, 0x01, 0x00, 0x01];
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::Content(BigIntError::NonMinimal)))
        );
    }

    #[test]
    fn rejects_truncated_modulus_tlv() {
        // modulus declares 4 content octets but the SEQUENCE content ends after 1.
        // 30 03 02 04 e1 (modulus TLV over-reads)
        let bytes = [0x30, 0x03, 0x02, 0x04, 0xE1];
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::Modulus(IntegerFieldError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_truncated_public_exponent_tlv() {
        // modulus is a complete, valid INTEGER; publicExponent declares 4 content octets but
        // only 1 is present. The outer SEQUENCE's own declared length (7) matches what is
        // actually present (so the outer envelope itself is well-formed, and the truncation is
        // caught later, inside the exponent's own TLV).
        // 30 07 02 02 00 e1 02 04 01
        let bytes = [0x30, 0x07, 0x02, 0x02, 0x00, 0xE1, 0x02, 0x04, 0x01];
        assert_eq!(
            parse_rsa_public_key(&bytes),
            Err(RsaPublicKeyError::PublicExponent(IntegerFieldError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_indefinite_length_outer_envelope() {
        // 0x30 0x80 = SEQUENCE with the BER indefinite length form; rejected by the length codec
        // (inherited), surfaced as Tlv(Length(Indefinite)).
        use crate::length::LengthError;
        assert_eq!(
            parse_rsa_public_key(&[0x30, 0x80, 0x00, 0x00]),
            Err(RsaPublicKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::Indefinite
            ))))
        );
    }
}
