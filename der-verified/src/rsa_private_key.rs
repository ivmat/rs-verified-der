//! PKCS#1 `RSAPrivateKey` (RFC 8017 §A.1.2) — a bounded, **structural** consumer that composes
//! this crate's verified primitives.
//!
//! ```text
//! RSAPrivateKey ::= SEQUENCE {
//!     version          Version,
//!     modulus          INTEGER,  -- n
//!     publicExponent   INTEGER,  -- e
//!     privateExponent  INTEGER,  -- d
//!     prime1           INTEGER,  -- p
//!     prime2           INTEGER,  -- q
//!     exponent1        INTEGER,  -- d mod (p-1)
//!     exponent2        INTEGER,  -- d mod (q-1)
//!     coefficient      INTEGER,  -- (inverse of q) mod p
//!     otherPrimeInfos  OtherPrimeInfos OPTIONAL
//! }
//! Version ::= INTEGER { two-prime(0), multi(1) }
//! OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo
//! OtherPrimeInfo ::= SEQUENCE { prime INTEGER, exponent INTEGER, coefficient INTEGER }
//! ```
//!
//! This module is the sibling of [`crate::rsa_public_key`] and [`crate::pkcs8`]: a
//! **demonstration of composition**, not an expansion of the crate's DER-layer scope (see the
//! crate-level docs). It frames the outer SEQUENCE and the nine (`version` + eight) INTEGER fields
//! using [`crate::sequence`], [`crate::tlv`], and [`crate::big_integer`] verbatim, and — unlike
//! `rsa_public_key`'s two-field shape — additionally frames one optional trailing SEQUENCE
//! (`otherPrimeInfos`) with a **tag-first** classification, the same discipline
//! [`crate::ec_private_key`] uses for its own optional `[0]`/`[1]` trailing fields.
//!
//! **The interesting part isn't nine copies of `rsa_public_key`'s INTEGER framing — it's the
//! `version` ↔ `otherPrimeInfos` cross-field rule.** RFC 8017 §A.1.2 ties the two together:
//! `version` is `two-prime(0)` when `otherPrimeInfos` is absent and `multi(1)` when it is present —
//! never any other combination. This module enforces that as [`RsaPrivateKeyError::VersionMismatch`],
//! checked *after* both `version` and `otherPrimeInfos` have themselves been individually validated
//! — the one place this module reasons about more than a single field at a time.
//!
//! **Scope boundaries (deliberate) — this module proves DER framing and canonicality ONLY:**
//! - **The eight key-material INTEGERs are opaque, comparison-only content, never materialized as
//!   numbers.** Following [`crate::big_integer`]'s own stance (`DECISIONS.md` D14) and
//!   [`crate::rsa_public_key`]'s `modulus`/`public_exponent` precedent: `modulus`, `public_exponent`,
//!   `private_exponent`, `prime1`, `prime2`, `exponent1`, `exponent2`, and `coefficient` are all
//!   `&[u8]` — the validated-minimal two's-complement content octets, borrowed from the input. No
//!   arithmetic (`n = p*q`, `d*e ≡ 1 mod λ(n)`, CRT-parameter consistency, primality, …) is checked;
//!   that is entirely outside a transfer-syntax codec's remit.
//! - **`version` is not stored.** It is validated to be a canonical INTEGER whose content is exactly
//!   `[0x00]` or `[0x01]` (else [`RsaPrivateKeyError::UnsupportedVersion`]), and its value is used
//!   only internally to enforce the cross-field rule above — a caller has no further use for the raw
//!   version octet once a successful parse has already confirmed it agrees with
//!   `other_prime_infos.is_some()`. This mirrors [`crate::pkcs8`]'s and [`crate::ec_private_key`]'s
//!   own no-stored-version rationale.
//! - **`other_prime_infos`'s FRAMING is fully validated, down to each member; only the integer
//!   VALUES stay opaque.** When present, this module validates that the trailing element is a
//!   well-formed, DER-canonical `SEQUENCE` that exactly tiles the remaining outer content, that its
//!   content is non-empty (`OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF …` forbids zero members —
//!   an empty `30 00` is [`RsaPrivateKeyError::OtherPrimeInfosEmpty`]), and — unlike
//!   [`crate::pkcs8`]'s opaque `SET OF Attribute` `attributes` field, whose members are an
//!   open-ended `ANY`-shaped `AttributeTypeAndValue` this crate cannot generically walk —
//!   `OtherPrimeInfo ::= SEQUENCE { prime INTEGER, exponent INTEGER, coefficient INTEGER }` is a
//!   **fully-closed grammar**, so this module walks the whole run of members and validates that
//!   *each one* is a well-formed SEQUENCE containing exactly three canonical INTEGERs, tiling
//!   exactly — a malformed member ([`RsaPrivateKeyError::OtherPrimeInfoMember`], see
//!   [`OtherPrimeInfoError`]) is rejected, not silently passed through opaque. What stays
//!   deliberately opaque is only the *value* of each `prime`/`exponent`/`coefficient` — this module
//!   never materializes them as numbers, exactly the same comparison-only stance as the eight
//!   top-level fields. The whole SEQUENCE's **content** octets (the concatenation of however many
//!   now-validated `OtherPrimeInfo` members it holds) are exposed verbatim as
//!   [`RsaPrivateKey::other_prime_infos`] (`Option<&'a [u8]>`) — a caller that wants the individual
//!   member values re-walks that content with the same three-INTEGER shape already proven to hold.
//! - *Strict/lenient outer-trailing variants, matching the crate's established split
//!   ([`crate::sequence::decode_sequence_tlv`] / [`crate::sequence::decode_sequence_tlv_strict`]).*
//!   [`parse_rsa_private_key`] is composable — it does not require `input` to be consumed exactly —
//!   so it can sit inside a larger structure (e.g. as `pkcs8`'s opaque `private_key` payload for the
//!   `rsaEncryption` algorithm). [`parse_rsa_private_key_strict`] additionally requires `input` to
//!   be consumed exactly — the right choice when a caller already knows the whole byte string is
//!   supposed to be one `RSAPrivateKey` and nothing else (e.g. an entire `.der`/`.pem`-decoded RSA
//!   private key file), guarding the classic trailing-data parser-differential vector.
//!
//! # Examples
//!
//! ```
//! use der_verified::rsa_private_key::parse_rsa_private_key_strict;
//!
//! // A real openssl-generated 512-bit two-prime RSAPrivateKey (`openssl genrsa -traditional 512`),
//! // hand-verified with `openssl asn1parse -inform DER` before trusting it.
//! #[rustfmt::skip]
//! let key_der: [u8; 317] = [
//!     0x30, 0x82, 0x01, 0x39,
//!         0x02, 0x01, 0x00,
//!         0x02, 0x41,
//!             0x00, 0xd7, 0x51, 0x82, 0x5b, 0x6b, 0x41, 0x9a, 0x84, 0xb0, 0x41, 0x71, 0x22,
//!             0xa7, 0x67, 0x10, 0x15, 0x88, 0xe1, 0x1d, 0x67, 0x03, 0xdc, 0xa5, 0xd6, 0xe8,
//!             0xbc, 0xea, 0xcc, 0x46, 0xc0, 0x94, 0xde, 0x67, 0x98, 0xbb, 0xa7, 0xab, 0xbc,
//!             0x26, 0x49, 0x6f, 0xa3, 0x28, 0x19, 0x55, 0x23, 0xe5, 0x3a, 0x8f, 0xbb, 0x16,
//!             0x91, 0xc0, 0x02, 0x0e, 0x27, 0x30, 0x31, 0x01, 0x4d, 0xde, 0x31, 0xc3, 0x5d,
//!         0x02, 0x03,
//!             0x01, 0x00, 0x01,
//!         0x02, 0x40,
//!             0x26, 0x6a, 0xaf, 0x94, 0x7a, 0x0d, 0x89, 0x71, 0x35, 0x35, 0x67, 0xe7, 0x23,
//!             0xf1, 0x1a, 0x88, 0x8d, 0x14, 0x85, 0x37, 0x75, 0x13, 0xf0, 0x2e, 0xe8, 0xf5,
//!             0x93, 0xfb, 0x00, 0x80, 0xa9, 0xce, 0xb4, 0xc8, 0x62, 0xd8, 0x65, 0xb7, 0x09,
//!             0xf6, 0xaf, 0xba, 0x8e, 0x82, 0xb9, 0x96, 0xcb, 0x42, 0x7b, 0xc8, 0xa6, 0x95,
//!             0x8b, 0xee, 0x69, 0x5b, 0xe2, 0x36, 0x17, 0x53, 0x14, 0x5f, 0xf1, 0xad,
//!         0x02, 0x21,
//!             0x00, 0xf8, 0xa2, 0xd4, 0xfd, 0x73, 0xc4, 0x61, 0x25, 0xa2, 0xde, 0x64, 0xc6,
//!             0x68, 0xaf, 0x05, 0xb5, 0x52, 0xcf, 0x13, 0x00, 0x5f, 0x67, 0x72, 0xa4, 0x25,
//!             0xfd, 0x73, 0xe4, 0x71, 0x2b, 0xa6, 0x47,
//!         0x02, 0x21,
//!             0x00, 0xdd, 0xb2, 0x0f, 0xb8, 0x48, 0xa9, 0xba, 0x1c, 0x8f, 0x54, 0x8d, 0xc9,
//!             0xcd, 0x88, 0x19, 0x50, 0x25, 0x3a, 0xf4, 0x20, 0xf1, 0x79, 0x47, 0x80, 0x12,
//!             0x5e, 0x41, 0x38, 0x0a, 0x75, 0x87, 0x3b,
//!         0x02, 0x20,
//!             0x36, 0xb5, 0xf5, 0xf2, 0x33, 0x88, 0x31, 0xec, 0x4b, 0x33, 0x6e, 0xaf, 0x6e,
//!             0x17, 0x9d, 0x44, 0xf2, 0x0c, 0xd8, 0xdc, 0x8b, 0x21, 0xc3, 0x4b, 0x35, 0x84,
//!             0xd8, 0xfc, 0x9a, 0x9e, 0x85, 0x3f,
//!         0x02, 0x20,
//!             0x7a, 0x99, 0x07, 0x9c, 0x6f, 0x82, 0x7c, 0xcb, 0x62, 0x6f, 0xed, 0xe1, 0x15,
//!             0x6a, 0x18, 0x25, 0x7c, 0x11, 0x38, 0x04, 0x27, 0xc5, 0x5b, 0xc6, 0xf5, 0x61,
//!             0x6e, 0x4b, 0xa1, 0x6d, 0x11, 0x15,
//!         0x02, 0x20,
//!             0x6d, 0xcb, 0x5c, 0xd7, 0xff, 0x5f, 0x42, 0xf1, 0x96, 0x0e, 0x37, 0x23, 0x05,
//!             0x0b, 0x41, 0x7c, 0x91, 0xdb, 0x9a, 0x51, 0xa0, 0xc6, 0x4c, 0xf4, 0x73, 0x06,
//!             0x76, 0x54, 0x12, 0x82, 0xa7, 0xc9,
//! ];
//! let key = parse_rsa_private_key_strict(&key_der).unwrap();
//! assert_eq!(key.modulus.len(), 65); // includes the mandatory 0x00 sign-guard octet
//! assert_eq!(key.public_exponent, &[0x01, 0x00, 0x01]); // 65537, the conventional e
//! assert_eq!(key.other_prime_infos, None); // two-prime (version 0): no otherPrimeInfos
//! ```

use crate::big_integer::{validate_integer_content, BigIntError, TAG as BIG_INTEGER_TAG};
use crate::sequence::{decode_sequence_tlv, decode_sequence_tlv_strict, SequenceError, TAG as SEQUENCE_TAG};
use crate::tag::{decode_tag, Class};
use crate::tlv::{decode_tlv, TlvError};

/// A structurally-parsed PKCS#1 `RSAPrivateKey`, borrowing from the input it was parsed from.
///
/// See the module docs for the scope of what "parsed" means here: DER framing and canonicality
/// only, all eight key-material fields left opaque, and `other_prime_infos` framing-validated but
/// its members left for the caller to walk. There is no `version` field on this struct — a
/// successful parse already guarantees `version` agrees with `other_prime_infos.is_some()` per RFC
/// 8017's cross-field rule (see [`RsaPrivateKeyError::VersionMismatch`]), so there is nothing
/// further for a caller to check.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct RsaPrivateKey<'a> {
    /// `modulus` (`n`): the validated-minimal INTEGER **content** octets, opaque — see the module
    /// docs. Never materialized as a numeric value.
    pub modulus: &'a [u8],
    /// `publicExponent` (`e`): the validated-minimal INTEGER **content** octets, opaque, exactly
    /// like [`Self::modulus`].
    pub public_exponent: &'a [u8],
    /// `privateExponent` (`d`): the validated-minimal INTEGER **content** octets, opaque, exactly
    /// like [`Self::modulus`].
    pub private_exponent: &'a [u8],
    /// `prime1` (`p`): the validated-minimal INTEGER **content** octets, opaque, exactly like
    /// [`Self::modulus`].
    pub prime1: &'a [u8],
    /// `prime2` (`q`): the validated-minimal INTEGER **content** octets, opaque, exactly like
    /// [`Self::modulus`].
    pub prime2: &'a [u8],
    /// `exponent1` (`d mod (p-1)`): the validated-minimal INTEGER **content** octets, opaque,
    /// exactly like [`Self::modulus`].
    pub exponent1: &'a [u8],
    /// `exponent2` (`d mod (q-1)`): the validated-minimal INTEGER **content** octets, opaque,
    /// exactly like [`Self::modulus`].
    pub exponent2: &'a [u8],
    /// `coefficient` (`(inverse of q) mod p`): the validated-minimal INTEGER **content** octets,
    /// opaque, exactly like [`Self::modulus`].
    pub coefficient: &'a [u8],
    /// `otherPrimeInfos` (`SEQUENCE SIZE(1..MAX) OF OtherPrimeInfo OPTIONAL`): the raw, non-empty
    /// SEQUENCE **content** octets (the concatenation of however many `OtherPrimeInfo` members it
    /// holds) when present. Every member's FRAMING has already been validated (each is a
    /// well-formed SEQUENCE of exactly three canonical INTEGERs, tiling exactly) — only the
    /// individual `prime`/`exponent`/`coefficient` *values* remain opaque, uninterpreted in these
    /// bytes — see the module docs. `None` when absent (the common, two-prime case).
    pub other_prime_infos: Option<&'a [u8]>,
}

/// Why one of the nine INTEGER fields (`version` or one of the eight key-material fields) was
/// rejected. Shared taxonomy for all nine, mirroring [`crate::rsa_public_key::IntegerFieldError`]'s
/// and [`crate::ecdsa_sig_value::IntegerFieldError`]'s identical shape.
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

/// Names one of the eight mandatory key-material INTEGER fields, for
/// [`RsaPrivateKeyError::MissingField`] / [`RsaPrivateKeyError::Field`]. A named enum here (rather
/// than sixteen structurally-identical `MissingModulus`/`Modulus(_)`-style variant pairs) keeps the
/// error type from being pure per-field noise while still identifying exactly which field failed.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RsaField {
    /// `modulus` (`n`).
    Modulus,
    /// `publicExponent` (`e`).
    PublicExponent,
    /// `privateExponent` (`d`).
    PrivateExponent,
    /// `prime1` (`p`).
    Prime1,
    /// `prime2` (`q`).
    Prime2,
    /// `exponent1` (`d mod (p-1)`).
    Exponent1,
    /// `exponent2` (`d mod (q-1)`).
    Exponent2,
    /// `coefficient` (`(inverse of q) mod p`).
    Coefficient,
}

/// Names one of an `OtherPrimeInfo` member's three mandatory INTEGER fields, for
/// [`OtherPrimeInfoError::MissingField`] / [`OtherPrimeInfoError::Field`] — the same
/// named-enum-over-per-field-variant-noise rationale as [`RsaField`], one level deeper.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OpiField {
    /// `prime` — the `OtherPrimeInfo`'s prime factor.
    Prime,
    /// `exponent` — `d mod (prime - 1)`.
    Exponent,
    /// `coefficient` — the CRT coefficient for this prime.
    Coefficient,
}

/// Why a single `OtherPrimeInfo` member (a 3-INTEGER `SEQUENCE { prime, exponent, coefficient }`)
/// was rejected. `OtherPrimeInfo` is a fully-closed grammar (unlike, e.g., `pkcs8`'s `SET OF
/// Attribute`, whose members are an open-ended `ANY`-shaped `AttributeTypeAndValue`), so — unlike
/// `other_prime_infos`'s own opaque-content stance for the *values* — this module validates a
/// member's *framing* completely: see the module docs.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OtherPrimeInfoError {
    /// The member's own SEQUENCE framing was malformed (wrong tag, primitive form, bad length, …).
    BadSeq(SequenceError),
    /// The member SEQUENCE ended before this mandatory INTEGER field.
    MissingField(OpiField),
    /// One of the member's three INTEGER fields failed to decode canonically.
    Field(OpiField, IntegerFieldError),
    /// Bytes remain in the member SEQUENCE after its three INTEGERs.
    TrailingElements,
}

/// Why an `RSAPrivateKey` was rejected. Every variant names a specific structural cause, wrapping
/// the underlying primitive's/sub-module's error where one exists.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RsaPrivateKeyError {
    /// The outer `RSAPrivateKey` SEQUENCE envelope was malformed: bad identifier/length, the
    /// primitive (non-constructed) form, or — for [`parse_rsa_private_key_strict`] only — trailing
    /// bytes after the whole structure.
    BadOuterSeq(SequenceError),
    /// No `version` is present — the outer SEQUENCE's content is empty.
    MissingVersion,
    /// The `version` field failed to decode as a structurally well-formed INTEGER.
    Version(IntegerFieldError),
    /// `version` decoded as a well-formed INTEGER, but its value is neither `0` (two-prime) nor `1`
    /// (multi) — the only two values RFC 8017's `Version` type permits.
    UnsupportedVersion,
    /// One of the eight mandatory key-material fields is absent — the outer SEQUENCE's content
    /// ended before reaching it.
    MissingField(RsaField),
    /// One of the eight mandatory key-material fields failed to decode.
    Field(RsaField, IntegerFieldError),
    /// `version` and `other_prime_infos` disagree with RFC 8017's cross-field rule: `version == 1`
    /// (multi) if and only if `otherPrimeInfos` is present. Checked only after both `version` and
    /// (if present) `otherPrimeInfos` have each individually validated — see the module docs.
    VersionMismatch,
    /// A UNIVERSAL-16-tagged (SEQUENCE) `otherPrimeInfos` attempt was malformed: its own TLV framing
    /// — a bad length, a truncated body, or the primitive/non-constructed form of tag 16 (surfaced
    /// as [`SequenceError::NotConstructed`]) — see the module docs' tag-first classification.
    OtherPrimeInfos(SequenceError),
    /// A confirmed `otherPrimeInfos` SEQUENCE's content is empty — `OtherPrimeInfos ::= SEQUENCE
    /// SIZE(1..MAX) OF OtherPrimeInfo` requires at least one member.
    OtherPrimeInfosEmpty,
    /// A confirmed, non-empty `otherPrimeInfos` SEQUENCE has a member that is not a well-formed
    /// `OtherPrimeInfo` (its own SEQUENCE framing, one of its three mandatory INTEGER fields, or
    /// trailing bytes within the member) — see [`OtherPrimeInfoError`] and the module docs.
    OtherPrimeInfoMember(OtherPrimeInfoError),
    /// A trailing element that is not a valid `otherPrimeInfos` SEQUENCE attempt at all (a non-
    /// SEQUENCE tag, or an identifier octet too malformed to even decode as a tag), or bytes remain
    /// after a well-formed `otherPrimeInfos`. The outer SEQUENCE admits nothing beyond `version`,
    /// the eight key-material fields, and at most one optional trailing `otherPrimeInfos` SEQUENCE.
    TrailingElements,
}

/// Decode one INTEGER field TLV from the front of `input`, returning its validated content octets
/// and the bytes consumed. Composes [`decode_tlv`] + [`validate_integer_content`], the same shape
/// as [`crate::rsa_public_key`]'s own `decode_integer_tlv`. Shared by `version` and all eight
/// key-material fields.
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

/// Decode one mandatory key-material INTEGER `field` from the front of `rest`, returning its
/// validated content octets and the bytes consumed. `MissingField(field)` if `rest` is empty (the
/// outer content ended before this field); `Field(field, _)` if it decodes but is malformed.
/// Composes [`decode_integer_tlv`], reused across all eight key-material fields (`version` is
/// handled separately in [`parse_fields`], since it has its own missing/unsupported-value rules).
fn decode_field(rest: &[u8], field: RsaField) -> Result<(&[u8], usize), RsaPrivateKeyError> {
    if rest.is_empty() {
        return Err(RsaPrivateKeyError::MissingField(field));
    }
    decode_integer_tlv(rest).map_err(|e| RsaPrivateKeyError::Field(field, e))
}

/// Validate a single `OtherPrimeInfo` member's content: exactly three canonical INTEGERs
/// (`prime`, `exponent`, `coefficient`) that tile `member_content` exactly. Framing only — the
/// integer VALUES stay opaque, exactly like the eight top-level fields (this module never returns
/// the individual field bytes for a member; a caller that wants them re-walks the exposed content
/// with this same three-INTEGER shape in hand).
fn validate_other_prime_info(member_content: &[u8]) -> Result<(), OtherPrimeInfoError> {
    let mut rest = member_content;
    for field in [OpiField::Prime, OpiField::Exponent, OpiField::Coefficient] {
        if rest.is_empty() {
            return Err(OtherPrimeInfoError::MissingField(field));
        }
        let (_content, used) =
            decode_integer_tlv(rest).map_err(|e| OtherPrimeInfoError::Field(field, e))?;
        rest = &rest[used..];
    }
    if !rest.is_empty() {
        return Err(OtherPrimeInfoError::TrailingElements);
    }
    Ok(())
}

/// Validate the whole `otherPrimeInfos` SEQUENCE content: a run of `OtherPrimeInfo` members (each
/// a 3-INTEGER SEQUENCE) that tile `content` exactly. `content` is already known non-empty by the
/// time this is called (the [`RsaPrivateKeyError::OtherPrimeInfosEmpty`] check happens first in
/// [`parse_fields`]) — this only walks and validates each member's framing; the integer values
/// stay opaque. Each loop iteration consumes `used >= 2` octets (the minimal possible TLV header),
/// so the walk is bounded by `content.len() / 2`, exactly the termination argument
/// [`crate::sequence`]'s own shallow walk relies on.
fn validate_other_prime_infos(content: &[u8]) -> Result<(), RsaPrivateKeyError> {
    let mut rest = content;
    while !rest.is_empty() {
        let (member_content, used) = decode_sequence_tlv(rest)
            .map_err(|e| RsaPrivateKeyError::OtherPrimeInfoMember(OtherPrimeInfoError::BadSeq(e)))?;
        validate_other_prime_info(member_content).map_err(RsaPrivateKeyError::OtherPrimeInfoMember)?;
        rest = &rest[used..];
    }
    Ok(())
}

/// Decode `version`, the eight mandatory key-material INTEGERs, and the optional `otherPrimeInfos`
/// SEQUENCE from an already-unwrapped outer SEQUENCE `content` slice, requiring the fields to
/// exactly tile it, and enforcing RFC 8017's `version` ↔ `otherPrimeInfos` cross-field rule. Shared
/// by both [`parse_rsa_private_key`] and [`parse_rsa_private_key_strict`] — the only difference
/// between the two entry points is how the outer envelope itself is decoded (composable vs.
/// top-level-strict).
fn parse_fields(outer_content: &[u8]) -> Result<RsaPrivateKey<'_>, RsaPrivateKeyError> {
    // 1. version: INTEGER, structurally validated, then required to be exactly 0 (two-prime) or 1
    // (multi). Not stored — only its two-prime/multi value is used, below, for the cross-field rule.
    if outer_content.is_empty() {
        return Err(RsaPrivateKeyError::MissingVersion);
    }
    let (version_content, version_used) =
        decode_integer_tlv(outer_content).map_err(RsaPrivateKeyError::Version)?;
    let version_is_multi = if version_content.len() == 1 && version_content[0] == 0x00 {
        false
    } else if version_content.len() == 1 && version_content[0] == 0x01 {
        true
    } else {
        return Err(RsaPrivateKeyError::UnsupportedVersion);
    };

    // 2. the eight mandatory key-material INTEGERs, in RFC 8017 order.
    let mut rest = &outer_content[version_used..];
    let (modulus, used) = decode_field(rest, RsaField::Modulus)?;
    rest = &rest[used..];
    let (public_exponent, used) = decode_field(rest, RsaField::PublicExponent)?;
    rest = &rest[used..];
    let (private_exponent, used) = decode_field(rest, RsaField::PrivateExponent)?;
    rest = &rest[used..];
    let (prime1, used) = decode_field(rest, RsaField::Prime1)?;
    rest = &rest[used..];
    let (prime2, used) = decode_field(rest, RsaField::Prime2)?;
    rest = &rest[used..];
    let (exponent1, used) = decode_field(rest, RsaField::Exponent1)?;
    rest = &rest[used..];
    let (exponent2, used) = decode_field(rest, RsaField::Exponent2)?;
    rest = &rest[used..];
    let (coefficient, used) = decode_field(rest, RsaField::Coefficient)?;
    rest = &rest[used..];

    // 3. otherPrimeInfos OPTIONAL — TAG-FIRST classification (the `ec_private_key` discipline,
    // replicated here): an element whose tag is UNIVERSAL 16 (SEQUENCE's tag number) is an
    // otherPrimeInfos attempt, and from there its own framing errors — INCLUDING the primitive
    // (non-constructed) form, which `decode_sequence_tlv` reports as `SequenceError::NotConstructed`
    // — are genuinely `OtherPrimeInfos(_)` errors, exactly as `ec_private_key` lets a primitive
    // context `[0]` surface as `Parameters(NotConstructed)` rather than pre-filtering on
    // constructed-ness. A tag that is not UNIVERSAL 16 at all (a different universal type, a
    // context/application-class tag), or an identifier octet too malformed to even decode as a tag,
    // is never blamed on `otherPrimeInfos` — it falls straight through to the final tiling check as
    // an unpermitted trailing element (`TrailingElements`).
    let (other_prime_infos, rest) = if rest.is_empty() {
        (None, rest)
    } else {
        match decode_tag(rest) {
            Ok((tag, _)) if tag.class == Class::Universal && tag.number == SEQUENCE_TAG => {
                // It IS a SEQUENCE attempt: from here, its own TLV-framing errors (including the
                // primitive-form `NotConstructed`) are genuinely `OtherPrimeInfos(_)` errors.
                let (content, used) =
                    decode_sequence_tlv(rest).map_err(RsaPrivateKeyError::OtherPrimeInfos)?;
                if used != rest.len() {
                    return Err(RsaPrivateKeyError::TrailingElements);
                }
                if content.is_empty() {
                    return Err(RsaPrivateKeyError::OtherPrimeInfosEmpty);
                }
                // `OtherPrimeInfo` is a fully-closed grammar (unlike pkcs8's ANY-shaped `SET OF
                // Attribute`), so its members' framing is validated completely here — only the
                // integer VALUES stay opaque. See the module docs.
                validate_other_prime_infos(content)?;
                (Some(content), &rest[used..])
            }
            _ => (None, rest),
        }
    };

    // 4. exact tiling: nothing beyond version, the eight key-material fields, and the one optional
    // trailing otherPrimeInfos SEQUENCE is permitted.
    if !rest.is_empty() {
        return Err(RsaPrivateKeyError::TrailingElements);
    }

    // 5. RFC 8017's cross-field rule, checked only now that both version and (if present)
    // otherPrimeInfos have each individually validated.
    if version_is_multi != other_prime_infos.is_some() {
        return Err(RsaPrivateKeyError::VersionMismatch);
    }

    Ok(RsaPrivateKey {
        modulus,
        public_exponent,
        private_exponent,
        prime1,
        prime2,
        exponent1,
        exponent2,
        coefficient,
        other_prime_infos,
    })
}

/// Parse one `RSAPrivateKey` from the front of `input`.
///
/// Composable, like [`crate::sequence::decode_sequence_tlv`] and
/// [`crate::rsa_public_key::parse_rsa_public_key`]: does **not** require `input` to be consumed
/// exactly (trailing bytes after this `RSAPrivateKey` are ignored) — a top-level caller checks the
/// returned length itself, or uses [`parse_rsa_private_key_strict`] directly.
///
/// Decodes, in order: the outer SEQUENCE envelope ([`decode_sequence_tlv`]); inside it, `version`
/// (INTEGER, required `0` or `1`), the eight mandatory key-material INTEGERs, and the optional
/// trailing `otherPrimeInfos` SEQUENCE — requiring the fields to exactly tile the SEQUENCE's
/// content, and enforcing RFC 8017's `version` ↔ `otherPrimeInfos` cross-field rule.
///
/// Never panics on any input **≤ 20 bytes** (proven by `parse_never_panics`). **A real
/// two-prime `RSAPrivateKey` is far larger** (~317 bytes for a 512-bit modulus; the module doc's
/// own fixture is 317 bytes) — panic-freedom on inputs beyond the 20-byte bound is **not
/// machine-checked** here: it rests on an un-machine-checked compositional argument (each field's
/// own decoder — `decode_sequence_tlv`, `big_integer::validate_integer_content`, the
/// `otherPrimeInfos` walk — is separately proven panic-free on its own, modularly), plus a single
/// concrete 317-byte accept-path witness (`parse_ok_2prime_witnessed`, a fixture, not a symbolic
/// proof) and `#[cfg(test)]` examples (see the Kani sizing comment below). Returns a classified
/// [`RsaPrivateKeyError`] on any structural deviation.
pub fn parse_rsa_private_key(input: &[u8]) -> Result<(RsaPrivateKey<'_>, usize), RsaPrivateKeyError> {
    let (outer_content, used) =
        decode_sequence_tlv(input).map_err(RsaPrivateKeyError::BadOuterSeq)?;
    let key = parse_fields(outer_content)?;
    Ok((key, used))
}

/// Parse a complete DER `RSAPrivateKey`, requiring it to consume the *entire* `input` (no trailing
/// bytes) — mirrors [`crate::sequence::decode_sequence_tlv_strict`] and
/// [`crate::rsa_public_key::parse_rsa_public_key_strict`]'s top-level stance.
///
/// Use this when `input` is known to be exactly one `RSAPrivateKey` and nothing else (e.g. an
/// entire `.der`/`.pem`-decoded RSA private key file's contents): [`parse_rsa_private_key`]
/// deliberately ignores trailing bytes so it can compose inside a larger structure, which is unsafe
/// for a top-level object (the classic trailing-data parser differential).
///
/// Never panics on any input **≤ 20 bytes** (proven by `parse_strict_never_panics`). As with
/// [`parse_rsa_private_key`], a real key is far larger (~317 bytes) and panic-freedom beyond the
/// 20-byte bound is **not machine-checked** — it rests on the same un-machine-checked
/// compositional argument, a single concrete witness fixture, and `#[cfg(test)]` examples (see
/// [`parse_rsa_private_key`]'s doc for the full statement, and the Kani sizing comment below).
pub fn parse_rsa_private_key_strict(input: &[u8]) -> Result<RsaPrivateKey<'_>, RsaPrivateKeyError> {
    let outer_content = decode_sequence_tlv_strict(input).map_err(RsaPrivateKeyError::BadOuterSeq)?;
    parse_fields(outer_content)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (partly MODULAR — see below).
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: **a 20-octet symbolic buffer with a symbolic LENGTH (`0..=20`)** for the
// two `parse_*` harnesses, wider than the crate's usual 16-octet convention but still deliberately
// NOT wide enough to reach an `Ok` verdict — see below. The minimal two-prime `RSAPrivateKey` floor
// is **~29 octets**: outer SEQUENCE header (2) + `version` (3: `02 01 00`) + eight minimal
// one-octet-content INTEGERs (8x3 = 24) = 2 + 3 + 24 = 29. 29 > 20, so — unlike
// `ecdsa_sig_value`/`rsa_public_key`'s own 8-octet floors, which sit comfortably inside their
// 16-octet symbolic domain — a fully-symbolic `Ok` cover is PROVABLY OUT OF REACH at 20 octets (an
// arithmetic argument, not something that needs running to disprove, exactly like
// `x509_validity::parse_never_panics`'s own disclosed-floor-exceeds-bound reasoning). Rather than
// disclose a vacuous `Ok` cover (or widen the buffer far enough that CBMC's cost for nine sequential
// symbolic INTEGER decodes turns this into a HEAVY-tier module), this module follows the crate's
// "small symbolic + concrete positives" route: `parse_never_panics` below asserts panic-freedom over
// the full `0..=20`-octet domain and covers ONLY the reject classes that ARE reachable within 20
// octets (the outer envelope, `version` including `UnsupportedVersion`, and the generic
// `MissingField`/`Field` classes, reachable as early as `modulus`) — it deliberately carries NO `Ok`
// cover and NO cover for `VersionMismatch`, `OtherPrimeInfos*`, or `TrailingElements` (all of which
// need the otherPrimeInfos tail, itself past the 29-octet two-prime floor, to even be reached). `Ok`
// for the common two-prime path is witnessed CONCRETELY by `parse_ok_2prime_witnessed` (the real
// 512-bit specimen), exactly like `ecdsa_sig_value`'s/`rsa_public_key`'s own concrete-specimen
// harnesses for shapes their symbolic bound cannot reach. The version==1/otherPrimeInfos-present
// `Ok` path, and the deep reject classes (`VersionMismatch`, `OtherPrimeInfos*`, per-member
// `OtherPrimeInfoMember`, `TrailingElements` after otherPrimeInfos) are all past this floor too, and
// are covered by `#[cfg(test)]` tests below rather than a Kani harness (see the modular-proof
// discussion next for why a Kani witness on that path is not kept).
//
// `otherPrimeInfos`'s MEMBER WALK (`validate_other_prime_infos`) is proven panic-free MODULARLY,
// exactly like `x509_name::validate_name` stubs `validate_rdn` for its own SET-OF/RDN walk. A
// monolithic proof — the walk's `while` loop (around `decode_sequence_tlv` +
// `validate_other_prime_info`) reached through the FULL `parse_rsa_private_key` call graph, under one
// global `#[kani::unwind]` — is intractable: MEASURED, once the member-validation call was compiled
// into `parse_fields`, `parse_ok_2prime_witnessed` and `parse_strict_never_panics` each exceeded
// 270s (killed), even though NEITHER harness's own input ever reaches otherPrimeInfos on the merits
// — a single `unwind(20)` unrolls the member `while` loop by the same bound as every other loop in
// the graph, not independently, so its cost is paid regardless of whether the loop body is ever
// entered by that harness's inputs. A direct, fully-symbolic harness over
// `validate_other_prime_infos` itself (no stub) fares no better: it exceeded a 20 GB memory cap
// (the `x509_name`-class variable-count-walk cost). Fix (mirrors `x509_name`): prove the walk's two
// layers SEPARATELY, then stub the heavier one out of every harness above it:
// 1. the per-member LEAF validator (`validate_other_prime_info`, no loop) — proven panic-free (plus
//    every `OtherPrimeInfoError` reject class) by `validate_other_prime_info_never_panics`, UNCHANGED
//    by this fold;
// 2. the member WALK (`validate_other_prime_infos`) itself, with the leaf validator MODULARLY
//    STUBBED — a nondeterministic `Result` carrying ONLY the leaf lemma's PROVEN panic-freedom
//    postcondition, never its actual matching logic (never assume what is not separately proven) —
//    proven by the new `validate_other_prime_infos_never_panics`;
// 3. every harness that reaches the walk through `parse_fields` (`parse_never_panics`,
//    `parse_strict_never_panics`, `parse_ok_2prime_witnessed`) STUBS THE WALK ITSELF, so none of
//    them unrolls the member machinery at all. This changes nothing about what those three harnesses
//    verify — none of them reaches `otherPrimeInfos` on the merits anyway (the two-prime specimen has
//    none; the symbolic ones are bounded well below the ~29-octet two-prime floor, let alone
//    whatever floor a present otherPrimeInfos would additionally add) — the stub only removes the
//    walk's unroll cost from their symbolic-execution graph. All `#[kani::stub]` harnesses below
//    require `-Z stubbing`, already the crate's default in `check.sh`/CI.
// A concrete Kani witness for the version==1/otherPrimeInfos-present `Ok` path itself was
// deliberately NOT kept for the same underlying reason: routing even a *concrete* multi-prime
// specimen through the REAL (unstubbed) `validate_other_prime_infos` inside a full `parse_fields`
// call, under the module's `unwind(20)`, measured intractable (>9 min, killed) — the `#[cfg(test)]`
// multiprime tests cover that path instead, consistent with this module's disclosed
// "concrete/tested past the floor" stance.
//
// The call chain performs up to eleven independent `decode_tlv`/`decode_tag` calls of its own
// (outer SEQUENCE, `version`, the eight key-material fields, the otherPrimeInfos tag peek) plus one
// more `decode_tlv` inside `decode_sequence_tlv` for a confirmed otherPrimeInfos SEQUENCE — no call
// recurses or loops over an unbounded sibling count (this parser reads a fixed nine-field-plus-one
// schema); with the walk stubbed in `parse_never_panics`/`parse_strict_never_panics`/
// `parse_ok_2prime_witnessed`, none of their call graphs unrolls the member walk at all.
// `#[kani::unwind(20)]` covers a maximal-header `decode_tlv` (~11, per `tlv.rs`) with margin,
// matching every other module's bound; if Kani reports an unwinding-assertion failure, raise this
// bound (do not weaken scope).
//
// Harness count: **5** — `parse_never_panics`, `parse_strict_never_panics`, `parse_ok_2prime_witnessed`
// (all three now STUBBING `validate_other_prime_infos`), `validate_other_prime_info_never_panics`
// (the leaf lemma, UNCHANGED by this fold), and `validate_other_prime_infos_never_panics` (the new
// walk lemma, STUBBING `validate_other_prime_info`).
//
// MEASURED (`cargo kani -Z stubbing --harness rsa_private_key::`, Kani 0.67.0; crate non-vacuity
// discipline — never claim a cover is satisfied without reading the real number): all **5 harnesses
// SUCCESSFUL, 0 failures** in ~258 s total wall-clock (with the modular stubs; without them the parse
// harnesses each exceeded 270 s). Per-harness cover counts, all satisfied — none vacuous:
// `parse_never_panics` **11 of 11** (the `Ok`-free reachable reject set); `parse_strict_never_panics`
// no cover (panic-freedom only, by design); `parse_ok_2prime_witnessed` **1 of 1** (the real two-prime
// `Ok` witness); `validate_other_prime_infos_never_panics` **2 of 2** (the member-walk lemma's `Ok`
// plus a propagated member `Err`, with the per-member validator stubbed); and
// `validate_other_prime_info_never_panics` **4 of 4** (the leaf member validator's `Ok` plus its three
// member-reject classes). No disclosed-unsatisfiable cover is introduced, so the crate's LIGHT-tier
// one-unsatisfiable-cover budget is untouched. The whole five-harness `rsa_private_key::` run completes
// in ~250 s with no OOM at a MEASURED peak of ~4.9 GB (cgroup `memory.peak` for the whole CBMC process
// tree, under a fixed 22 GB cap) — comfortably inside the ~7 GB LIGHT envelope (`gates/tiers.txt`), so
// LIGHT placement holds by this five-harness measurement (not the earlier pre-stub four-harness ~3.5 GB
// figure). The leaf lemma's 16-octet buffer is what raised the peak above the pre-stub number while
// keeping it LIGHT.
#[cfg(kani)]
mod proofs {
    use super::*;

    // Modular stub for the otherPrimeInfos MEMBER WALK (`validate_other_prime_infos`) -- see the
    // module's Kani sizing comment for why a monolithic harness through `parse_fields` cannot afford
    // to unroll it. INDEPENDENTLY proven panic-free by `validate_other_prime_infos_never_panics`
    // below. A nondeterministic `Result` over-approximates the real walk (which returns `Ok` on a
    // strict subset of inputs); sound for the PARSE harnesses' panic-freedom, since `parse_fields`
    // uses only the Ok/Err outcome (propagates `Err` via `?`, and on `Ok` only stores the already-
    // borrowed `content` slice it already had in hand -- the stub touches no bytes and slices
    // nothing, so it cannot introduce an out-of-bounds access the real walk wouldn't already have
    // avoided). Assuming ONLY panic-freedom, discharged by the walk lemma -- never assume what is not
    // separately proven.
    // (rustc's dead-code lint doesn't see the `#[kani::stub]` reference below as a use.)
    #[allow(dead_code)]
    fn stub_validate_other_prime_infos(_content: &[u8]) -> Result<(), RsaPrivateKeyError> {
        if kani::any() {
            Ok(())
        } else {
            Err(RsaPrivateKeyError::OtherPrimeInfosEmpty)
        }
    }

    /// Robustness: `parse_rsa_private_key` never panics on any input **of any length up to 20
    /// octets** -- the buffer AND its length are both symbolic (see the module's Kani sizing
    /// comment), so this is a bounded claim over the whole `0..=20`-octet domain, not just the
    /// single 20-octet length. The otherPrimeInfos MEMBER WALK (`validate_other_prime_infos`) is
    /// MODULARLY STUBBED (see the module's Kani sizing comment and the stub above) -- this changes
    /// nothing about what this harness verifies, since no input up to 20 octets ever reaches
    /// otherPrimeInfos on the merits anyway (the two-prime floor alone is ~29 octets); the stub only
    /// removes the walk's unroll cost from this harness's symbolic-execution graph.
    ///
    /// Deliberately carries **no `Ok` cover**: the minimal two-prime floor (~29 octets) provably
    /// exceeds this 20-octet bound (see the sizing comment) -- `Ok` is instead witnessed
    /// concretely by `parse_ok_2prime_witnessed` below (and the version==1 path by `#[cfg(test)]`
    /// tests). Covers
    /// ONLY the reject classes reachable within 20 octets: the outer envelope, `version` (incl.
    /// `UnsupportedVersion`), and the generic `MissingField`/`Field` classes (satisfiable as early
    /// as `modulus`, immediately after `version`). `VersionMismatch`, `OtherPrimeInfos*`, and
    /// `TrailingElements` are NOT covered here -- they need the otherPrimeInfos tail, past the
    /// 29-octet floor, and are exercised by `#[cfg(test)]` tests instead (adding an unsatisfiable
    /// cover for any of them here would trip the crate's LIGHT-tier "one disclosed-unsatisfiable
    /// cover" ceiling for no benefit, since they are already covered concretely).
    #[kani::proof]
    #[kani::stub(validate_other_prime_infos, stub_validate_other_prime_infos)]
    #[kani::unwind(20)]
    fn parse_never_panics() {
        let buf: [u8; 20] = kani::any();
        // Symbolic input length, matching the crate's established convention: so the "any input up
        // to 20 octets" claim above holds at every length in the domain, not just the single
        // length 20.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = parse_rsa_private_key(input);

        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::WrongTag))),
            "outer envelope: a non-SEQUENCE tag is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::NotConstructed))),
            "outer envelope: the primitive-form SEQUENCE identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::Tlv(_)))),
            "outer envelope: malformed TLV framing (bad length / truncated) is rejected",
        );

        kani::cover(
            result == Err(RsaPrivateKeyError::MissingVersion),
            "an empty outer content (no version) is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::Version(IntegerFieldError::Tlv(_)))),
            "version field: malformed TLV framing (bad length / truncated) is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::Version(IntegerFieldError::WrongTag))),
            "version field: a non-INTEGER tag is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::Version(IntegerFieldError::Constructed))),
            "version field: the constructed-form INTEGER identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::Version(IntegerFieldError::Content(_)))),
            "version field: non-canonical INTEGER content (empty or non-minimal) is rejected",
        );
        kani::cover(
            result == Err(RsaPrivateKeyError::UnsupportedVersion),
            "a structurally well-formed but non-{0,1} version value is rejected",
        );

        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::MissingField(_))),
            "a key-material field absent (outer content ends early, e.g. right after version) is rejected",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::Field(_, _))),
            "a key-material field that decodes but is malformed is rejected",
        );

        let _ = result;
    }

    /// Robustness: `parse_rsa_private_key_strict` never panics on any input **of any length up to
    /// 20 octets** (buffer and length both symbolic, matching `parse_never_panics` above). No
    /// `Ok`/`TrailingData` covers here either, for the same reason `parse_never_panics` carries no
    /// `Ok` cover: the floor is past 20 octets. Both are exercised by `#[cfg(test)]` tests
    /// (`strict_rejects_trailing_byte_after_key`, and the strict-parse positive tests) instead. The
    /// otherPrimeInfos MEMBER WALK is MODULARLY STUBBED here too, for the same reason and with the
    /// same "changes nothing verified" argument as `parse_never_panics` above.
    #[kani::proof]
    #[kani::stub(validate_other_prime_infos, stub_validate_other_prime_infos)]
    #[kani::unwind(20)]
    fn parse_strict_never_panics() {
        let buf: [u8; 20] = kani::any();
        // Symbolic input length -- see `parse_never_panics`'s doc comment.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = parse_rsa_private_key_strict(input);
        let _ = result;
    }

    /// Positive-construction companion, on a real openssl-generated 512-bit two-prime specimen
    /// (`openssl genrsa -traditional 512`), the same bytes as the module doc's own example,
    /// hand-verified against `openssl asn1parse -inform DER` before trusting it. Witnesses `Ok`
    /// concretely -- the real-world shape (317 octets) the 20-octet symbolic harnesses above are
    /// far too narrow to reach (see the module's Kani sizing comment) -- and machine-checks every
    /// field's exact byte length. The otherPrimeInfos MEMBER WALK is MODULARLY STUBBED here as well
    /// (see the module's Kani sizing comment): this real two-prime specimen has no `otherPrimeInfos`
    /// field at all, so the walk is never genuinely reached regardless -- the stub only removes its
    /// unroll cost from this harness's symbolic-execution graph, it does not change what the
    /// specimen's actual `Ok` witness proves.
    #[kani::proof]
    #[kani::stub(validate_other_prime_infos, stub_validate_other_prime_infos)]
    #[kani::unwind(20)]
    fn parse_ok_2prime_witnessed() {
        #[rustfmt::skip]
        const RSA_2PRIME: [u8; 317] = [
            0x30, 0x82, 0x01, 0x39,
                0x02, 0x01, 0x00,
                0x02, 0x41,
                    0x00, 0xd7, 0x51, 0x82, 0x5b, 0x6b, 0x41, 0x9a, 0x84, 0xb0, 0x41, 0x71, 0x22,
                    0xa7, 0x67, 0x10, 0x15, 0x88, 0xe1, 0x1d, 0x67, 0x03, 0xdc, 0xa5, 0xd6, 0xe8,
                    0xbc, 0xea, 0xcc, 0x46, 0xc0, 0x94, 0xde, 0x67, 0x98, 0xbb, 0xa7, 0xab, 0xbc,
                    0x26, 0x49, 0x6f, 0xa3, 0x28, 0x19, 0x55, 0x23, 0xe5, 0x3a, 0x8f, 0xbb, 0x16,
                    0x91, 0xc0, 0x02, 0x0e, 0x27, 0x30, 0x31, 0x01, 0x4d, 0xde, 0x31, 0xc3, 0x5d,
                0x02, 0x03,
                    0x01, 0x00, 0x01,
                0x02, 0x40,
                    0x26, 0x6a, 0xaf, 0x94, 0x7a, 0x0d, 0x89, 0x71, 0x35, 0x35, 0x67, 0xe7, 0x23,
                    0xf1, 0x1a, 0x88, 0x8d, 0x14, 0x85, 0x37, 0x75, 0x13, 0xf0, 0x2e, 0xe8, 0xf5,
                    0x93, 0xfb, 0x00, 0x80, 0xa9, 0xce, 0xb4, 0xc8, 0x62, 0xd8, 0x65, 0xb7, 0x09,
                    0xf6, 0xaf, 0xba, 0x8e, 0x82, 0xb9, 0x96, 0xcb, 0x42, 0x7b, 0xc8, 0xa6, 0x95,
                    0x8b, 0xee, 0x69, 0x5b, 0xe2, 0x36, 0x17, 0x53, 0x14, 0x5f, 0xf1, 0xad,
                0x02, 0x21,
                    0x00, 0xf8, 0xa2, 0xd4, 0xfd, 0x73, 0xc4, 0x61, 0x25, 0xa2, 0xde, 0x64, 0xc6,
                    0x68, 0xaf, 0x05, 0xb5, 0x52, 0xcf, 0x13, 0x00, 0x5f, 0x67, 0x72, 0xa4, 0x25,
                    0xfd, 0x73, 0xe4, 0x71, 0x2b, 0xa6, 0x47,
                0x02, 0x21,
                    0x00, 0xdd, 0xb2, 0x0f, 0xb8, 0x48, 0xa9, 0xba, 0x1c, 0x8f, 0x54, 0x8d, 0xc9,
                    0xcd, 0x88, 0x19, 0x50, 0x25, 0x3a, 0xf4, 0x20, 0xf1, 0x79, 0x47, 0x80, 0x12,
                    0x5e, 0x41, 0x38, 0x0a, 0x75, 0x87, 0x3b,
                0x02, 0x20,
                    0x36, 0xb5, 0xf5, 0xf2, 0x33, 0x88, 0x31, 0xec, 0x4b, 0x33, 0x6e, 0xaf, 0x6e,
                    0x17, 0x9d, 0x44, 0xf2, 0x0c, 0xd8, 0xdc, 0x8b, 0x21, 0xc3, 0x4b, 0x35, 0x84,
                    0xd8, 0xfc, 0x9a, 0x9e, 0x85, 0x3f,
                0x02, 0x20,
                    0x7a, 0x99, 0x07, 0x9c, 0x6f, 0x82, 0x7c, 0xcb, 0x62, 0x6f, 0xed, 0xe1, 0x15,
                    0x6a, 0x18, 0x25, 0x7c, 0x11, 0x38, 0x04, 0x27, 0xc5, 0x5b, 0xc6, 0xf5, 0x61,
                    0x6e, 0x4b, 0xa1, 0x6d, 0x11, 0x15,
                0x02, 0x20,
                    0x6d, 0xcb, 0x5c, 0xd7, 0xff, 0x5f, 0x42, 0xf1, 0x96, 0x0e, 0x37, 0x23, 0x05,
                    0x0b, 0x41, 0x7c, 0x91, 0xdb, 0x9a, 0x51, 0xa0, 0xc6, 0x4c, 0xf4, 0x73, 0x06,
                    0x76, 0x54, 0x12, 0x82, 0xa7, 0xc9,
        ];

        let result = parse_rsa_private_key(&RSA_2PRIME);
        kani::cover(
            result.is_ok(),
            "parse_rsa_private_key reaches its Ok tail on a real openssl-generated 512-bit \
             two-prime RSAPrivateKey -- the specific real-world shape the 20-octet symbolic \
             harnesses above are too narrow to reach",
        );
        if let Ok((k, _used)) = result {
            assert!(k.modulus.len() == 65);
            assert!(k.public_exponent.len() == 3);
            assert!(k.private_exponent.len() == 64);
            assert!(k.prime1.len() == 33);
            assert!(k.prime2.len() == 33);
            assert!(k.exponent1.len() == 32);
            assert!(k.exponent2.len() == 32);
            assert!(k.coefficient.len() == 32);
            assert!(k.other_prime_infos == None);
        }
    }

    // Modular stub for the per-member validator (INDEPENDENTLY proven panic-free by
    // `validate_other_prime_info_never_panics` below). A nondeterministic `Result` over-approximates
    // the real validator (which returns `Ok` on a strict subset of inputs); sound for the WALK's
    // panic-freedom, since the walk uses only the Ok/Err outcome (propagates `Err` via `?`) and its
    // progress/in-bounds slicing depend solely on the REAL `decode_sequence_tlv`'s `used` (`>= 2`,
    // `<= input.len()`), which is NOT stubbed here. Assuming ONLY panic-freedom, discharged by the
    // leaf lemma below -- never assume what is not separately proven.
    // (rustc's dead-code lint doesn't see the `#[kani::stub]` reference below as a use.)
    #[allow(dead_code)]
    fn stub_validate_other_prime_info(_member_content: &[u8]) -> Result<(), OtherPrimeInfoError> {
        if kani::any() {
            Ok(())
        } else {
            Err(OtherPrimeInfoError::TrailingElements)
        }
    }

    /// Robustness: `validate_other_prime_infos` (the otherPrimeInfos MEMBER WALK) never panics on
    /// any input **of any length up to 16 octets**, with the per-member validator MODULARLY STUBBED
    /// (see the stub above and the module's Kani sizing comment). Exercises the REAL member walk:
    /// `decode_sequence_tlv` (a verified primitive, NOT stubbed) plus the offset arithmetic, bounds,
    /// and loop termination, over the stub's Ok/Err outcomes -- the exact analogue of
    /// `x509_name::validate_never_panics`'s own stub-based composition.
    ///
    /// A minimal well-formed one-member `otherPrimeInfos` content (`30 09 02 01 01 02 01 01 02 01
    /// 01`, 11 octets) fits inside 16, so the `Ok` cover (which requires a non-empty walk of >= 1
    /// member -- see the cover) is expected to be non-vacuous; a stubbed
    /// member `Err` propagating straight through the walk (`OtherPrimeInfoMember(_)`) is reachable
    /// well within 16 octets too (even a 2-octet truncated first member reaches the stub call).
    /// `#[kani::unwind(16)]`: each loop iteration is one `decode_sequence_tlv` call (a single
    /// `decode_tlv`, ~11-octet maximal header per `tlv.rs`) -- the stubbed member validator
    /// contributes no loop of its own to this harness's unwind cost, unlike the unstubbed real
    /// validator's three-iteration `for` loop; if Kani reports an unwinding-assertion failure, raise
    /// this bound (do not weaken scope).
    #[kani::proof]
    #[kani::stub(validate_other_prime_info, stub_validate_other_prime_info)]
    #[kani::unwind(16)]
    fn validate_other_prime_infos_never_panics() {
        let buf: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let content = &buf[..len];
        let result = validate_other_prime_infos(content);

        // `is_ok() && !content.is_empty()` (not bare `is_ok()`): the empty walk returns `Ok`
        // immediately WITHOUT entering the loop, so a bare `is_ok()` cover is satisfiable at `len == 0`
        // and would witness zero member walks. Requiring non-empty content forces the witness through
        // >= 1 real `decode_sequence_tlv` + stubbed-member iteration -- panic-freedom itself still
        // covers the empty case (no `assume` narrows the harness domain).
        kani::cover(
            result.is_ok() && !content.is_empty(),
            "the member walk reaches Ok after walking >= 1 stubbed member",
        );
        kani::cover(
            matches!(result, Err(RsaPrivateKeyError::OtherPrimeInfoMember(_))),
            "a stubbed member Err propagates through the walk",
        );

        let _ = result;
    }

    /// Robustness: `validate_other_prime_info` -- a SINGLE `OtherPrimeInfo` member (three canonical
    /// INTEGERs, no loop) -- never panics on any input **of any length up to 16 octets** (buffer and
    /// length both symbolic). This harness proves the per-member validator, the part of the
    /// otherPrimeInfos machinery that carries the real branching logic. The 16-octet domain is not
    /// arbitrary: it matches `validate_other_prime_infos_never_panics`'s 16-octet buffer, so the
    /// panic-freedom contract that walk lemma STUBS into `validate_other_prime_info` is discharged
    /// here over the full `member_content` the walk can hand it (a 16-octet walk buffer, minus a
    /// >=2-octet member SEQUENCE header, yields at most 14 content octets -- inside 16). A leaf buffer
    /// below 14 (the former 10 among them) would leave the stub's contract undischarged over that tail.
    ///
    /// The OUTER walk (`validate_other_prime_infos`'s `while` loop over an unbounded member count) IS
    /// harnessed symbolically for panic-freedom -- by `validate_other_prime_infos_never_panics` above,
    /// with THIS per-member validator STUBBED. What is deliberately NOT attempted is the
    /// fully-symbolic UNSTUBBED nested walk (the outer loop with the real member validator inlined):
    /// that variable-count-nested walk explodes CBMC's state (the `x509_name`-class cost -- an earlier
    /// 14-octet attempt at it exceeded a 20 GB cap; and even a *concrete* multi-prime specimen through
    /// the loop measured intractable, >9 min). The unstubbed multi-member composition is instead
    /// witnessed by the `#[cfg(test)]` one-/two-member tests. That is sound: the loop
    /// body only composes two
    /// independently-proven-panic-free functions (`decode_sequence_tlv` -- a verified primitive -- and
    /// this validator) and advances by a primitive-guaranteed `used >= 2`, so the loop itself adds no
    /// unproven branching, exactly the crate's disclosed "small symbolic + concrete positives" stance
    /// for everything past this module's ~29-octet floor.
    ///
    /// The minimal well-formed member content (`02 01 01 02 01 01 02 01 01`, 9 octets) fits inside 16,
    /// so the `Ok` cover is non-vacuous, and each member-reject class ([`OtherPrimeInfoError`]) is
    /// reachable within 16. `#[kani::unwind(12)]` covers the three sequential `decode_integer_tlv`
    /// calls (each a maximal-header `decode_tlv`, ~11 per `tlv.rs`) with margin; if Kani reports an
    /// unwinding-assertion failure, raise this bound (do not weaken scope).
    #[kani::proof]
    #[kani::unwind(12)]
    fn validate_other_prime_info_never_panics() {
        let buf: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let member_content = &buf[..len];
        let result = validate_other_prime_info(member_content);

        kani::cover(result.is_ok(), "a well-formed 3-INTEGER OtherPrimeInfo member is accepted");
        kani::cover(
            matches!(result, Err(OtherPrimeInfoError::MissingField(_))),
            "a member ending before one of its three INTEGERs is rejected",
        );
        kani::cover(
            matches!(result, Err(OtherPrimeInfoError::Field(_, _))),
            "a member with a malformed INTEGER field is rejected",
        );
        kani::cover(
            result == Err(OtherPrimeInfoError::TrailingElements),
            "a member with a fourth element after its three INTEGERs is rejected",
        );

        let _ = result;
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A real openssl-generated 512-bit two-prime `RSAPrivateKey` (`openssl genrsa -traditional
    /// 512`). Same specimen as the module doc's own example and the Kani `parse_ok_2prime_witnessed`
    /// harness; hand-verified octet-by-octet against `openssl asn1parse -inform DER` before
    /// trusting it (see the module doc's TLV framing breakdown).
    #[rustfmt::skip]
    const RSA_2PRIME: [u8; 317] = [
        0x30, 0x82, 0x01, 0x39,
            0x02, 0x01, 0x00,
            0x02, 0x41,
                0x00, 0xd7, 0x51, 0x82, 0x5b, 0x6b, 0x41, 0x9a, 0x84, 0xb0, 0x41, 0x71, 0x22,
                0xa7, 0x67, 0x10, 0x15, 0x88, 0xe1, 0x1d, 0x67, 0x03, 0xdc, 0xa5, 0xd6, 0xe8,
                0xbc, 0xea, 0xcc, 0x46, 0xc0, 0x94, 0xde, 0x67, 0x98, 0xbb, 0xa7, 0xab, 0xbc,
                0x26, 0x49, 0x6f, 0xa3, 0x28, 0x19, 0x55, 0x23, 0xe5, 0x3a, 0x8f, 0xbb, 0x16,
                0x91, 0xc0, 0x02, 0x0e, 0x27, 0x30, 0x31, 0x01, 0x4d, 0xde, 0x31, 0xc3, 0x5d,
            0x02, 0x03,
                0x01, 0x00, 0x01,
            0x02, 0x40,
                0x26, 0x6a, 0xaf, 0x94, 0x7a, 0x0d, 0x89, 0x71, 0x35, 0x35, 0x67, 0xe7, 0x23,
                0xf1, 0x1a, 0x88, 0x8d, 0x14, 0x85, 0x37, 0x75, 0x13, 0xf0, 0x2e, 0xe8, 0xf5,
                0x93, 0xfb, 0x00, 0x80, 0xa9, 0xce, 0xb4, 0xc8, 0x62, 0xd8, 0x65, 0xb7, 0x09,
                0xf6, 0xaf, 0xba, 0x8e, 0x82, 0xb9, 0x96, 0xcb, 0x42, 0x7b, 0xc8, 0xa6, 0x95,
                0x8b, 0xee, 0x69, 0x5b, 0xe2, 0x36, 0x17, 0x53, 0x14, 0x5f, 0xf1, 0xad,
            0x02, 0x21,
                0x00, 0xf8, 0xa2, 0xd4, 0xfd, 0x73, 0xc4, 0x61, 0x25, 0xa2, 0xde, 0x64, 0xc6,
                0x68, 0xaf, 0x05, 0xb5, 0x52, 0xcf, 0x13, 0x00, 0x5f, 0x67, 0x72, 0xa4, 0x25,
                0xfd, 0x73, 0xe4, 0x71, 0x2b, 0xa6, 0x47,
            0x02, 0x21,
                0x00, 0xdd, 0xb2, 0x0f, 0xb8, 0x48, 0xa9, 0xba, 0x1c, 0x8f, 0x54, 0x8d, 0xc9,
                0xcd, 0x88, 0x19, 0x50, 0x25, 0x3a, 0xf4, 0x20, 0xf1, 0x79, 0x47, 0x80, 0x12,
                0x5e, 0x41, 0x38, 0x0a, 0x75, 0x87, 0x3b,
            0x02, 0x20,
                0x36, 0xb5, 0xf5, 0xf2, 0x33, 0x88, 0x31, 0xec, 0x4b, 0x33, 0x6e, 0xaf, 0x6e,
                0x17, 0x9d, 0x44, 0xf2, 0x0c, 0xd8, 0xdc, 0x8b, 0x21, 0xc3, 0x4b, 0x35, 0x84,
                0xd8, 0xfc, 0x9a, 0x9e, 0x85, 0x3f,
            0x02, 0x20,
                0x7a, 0x99, 0x07, 0x9c, 0x6f, 0x82, 0x7c, 0xcb, 0x62, 0x6f, 0xed, 0xe1, 0x15,
                0x6a, 0x18, 0x25, 0x7c, 0x11, 0x38, 0x04, 0x27, 0xc5, 0x5b, 0xc6, 0xf5, 0x61,
                0x6e, 0x4b, 0xa1, 0x6d, 0x11, 0x15,
            0x02, 0x20,
                0x6d, 0xcb, 0x5c, 0xd7, 0xff, 0x5f, 0x42, 0xf1, 0x96, 0x0e, 0x37, 0x23, 0x05,
                0x0b, 0x41, 0x7c, 0x91, 0xdb, 0x9a, 0x51, 0xa0, 0xc6, 0x4c, 0xf4, 0x73, 0x06,
                0x76, 0x54, 0x12, 0x82, 0xa7, 0xc9,
    ];

    /// A hand-built minimal `version = 1` + one-`OtherPrimeInfo` specimen — the concrete witness for
    /// the version==1 / otherPrimeInfos-present `Ok` path (which the symbolic harnesses, bounded below
    /// the ~29-octet floor, and `parse_ok_2prime_witnessed`, a two-prime key, do not reach). Note
    /// the TWO levels of SEQUENCE nesting: `otherPrimeInfos` (`30 0b`) wraps a run of
    /// `OtherPrimeInfo` members, each itself its own SEQUENCE (`30 09`) of three INTEGERs — a bare
    /// `SEQUENCE OF INTEGER` (no member-level SEQUENCE wrapper) is NOT a valid `OtherPrimeInfos`.
    #[rustfmt::skip]
    const RSA_MULTIPRIME: [u8; 42] = [
        0x30, 0x28,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x30, 0x0b,
                0x30, 0x09,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
    ];

    /// The raw `otherPrimeInfos` SEQUENCE content `RSA_MULTIPRIME` carries: one `OtherPrimeInfo`
    /// member's complete TLV bytes (`30 09 …`), verbatim — see [`RsaPrivateKey::other_prime_infos`].
    const RSA_MULTIPRIME_ONE_MEMBER_CONTENT: [u8; 11] = [
        0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01,
    ];

    /// The smallest well-formed two-prime `RSAPrivateKey`: `version = 0`, all eight key-material
    /// fields the minimal one-octet INTEGER `0x01`, no `otherPrimeInfos` — exactly the module's own
    /// documented ~29-octet floor. Used as the base specimen for the seeded-bad field-level tests
    /// below (small enough that a single mutated byte isolates exactly one field).
    ///
    /// `30 1b`              SEQUENCE, len 27
    ///    `02 01 00`        INTEGER version = 0 (two-prime)
    ///    `02 01 01` x8     the eight key-material fields (modulus .. coefficient)
    #[rustfmt::skip]
    const RSA_MINIMAL: [u8; 29] = [
        0x30, 0x1b,
            0x02, 0x01, 0x00,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
            0x02, 0x01, 0x01,
    ];

    #[test]
    fn parses_2prime_specimen_composable_and_strict() {
        let (key_c, used) = parse_rsa_private_key(&RSA_2PRIME).unwrap();
        assert_eq!(used, 317);
        assert_eq!(key_c.modulus.len(), 65);
        assert_eq!(key_c.public_exponent, &[0x01, 0x00, 0x01][..]);
        assert_eq!(key_c.private_exponent.len(), 64);
        assert_eq!(key_c.prime1.len(), 33);
        assert_eq!(key_c.prime2.len(), 33);
        assert_eq!(key_c.exponent1.len(), 32);
        assert_eq!(key_c.exponent2.len(), 32);
        assert_eq!(key_c.coefficient.len(), 32);
        assert_eq!(key_c.other_prime_infos, None);

        let key_s = parse_rsa_private_key_strict(&RSA_2PRIME).unwrap();
        assert_eq!(key_s, key_c);
    }

    #[test]
    fn parses_multiprime_specimen_composable_and_strict() {
        let (key_c, used) = parse_rsa_private_key(&RSA_MULTIPRIME).unwrap();
        assert_eq!(used, 42);
        assert_eq!(key_c.other_prime_infos, Some(&RSA_MULTIPRIME_ONE_MEMBER_CONTENT[..]));

        let key_s = parse_rsa_private_key_strict(&RSA_MULTIPRIME).unwrap();
        assert_eq!(key_s, key_c);
    }

    #[test]
    fn parses_minimal_2prime_specimen() {
        let key = parse_rsa_private_key_strict(&RSA_MINIMAL).unwrap();
        assert_eq!(key.modulus, &[0x01][..]);
        assert_eq!(key.coefficient, &[0x01][..]);
        assert_eq!(key.other_prime_infos, None);
    }

    #[test]
    fn composable_ignores_trailing_bytes() {
        let mut bytes = RSA_MINIMAL.to_vec();
        bytes.push(0xFF);
        let (key, used) = parse_rsa_private_key(&bytes).unwrap();
        assert_eq!(used, 29);
        assert_eq!(key.modulus, &[0x01][..]);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn strict_rejects_trailing_byte_after_key() {
        let mut bytes = RSA_MINIMAL.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            parse_rsa_private_key_strict(&bytes),
            Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = RSA_MINIMAL;
        bytes[0] = 0x31;
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_primitive_outer_sequence_identifier() {
        // 0x10 = UNIVERSAL 16 primitive. A SEQUENCE is always constructed (X.690 §8.9.1).
        let mut bytes = RSA_MINIMAL;
        bytes[0] = 0x10;
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::NotConstructed))
        );
    }

    #[test]
    fn rejects_ber_long_form_length_where_short_form_fits() {
        // Outer SEQUENCE length 27 re-encoded in the BER long form (0x81 0x1b) where DER requires
        // the short form (0x1b) -- non-minimal (X.690 §8.1.3), forbidden by DER.
        use crate::length::LengthError;
        let mut bytes = vec![0x30, 0x81, 0x1b];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_truncated_outer_envelope() {
        // Declares 27 content bytes but only 10 are present.
        let bytes = &RSA_MINIMAL[..12];
        assert_eq!(
            parse_rsa_private_key(bytes),
            Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_indefinite_length_outer_envelope() {
        // 0x30 0x80 = SEQUENCE with the BER indefinite length form; rejected by the length codec
        // (inherited), surfaced as Tlv(Length(Indefinite)).
        use crate::length::LengthError;
        assert_eq!(
            parse_rsa_private_key(&[0x30, 0x80, 0x00, 0x00]),
            Err(RsaPrivateKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::Indefinite
            ))))
        );
    }

    #[test]
    fn rejects_empty_outer_content_missing_version() {
        let bytes = [0x30, 0x00];
        assert_eq!(parse_rsa_private_key(&bytes), Err(RsaPrivateKeyError::MissingVersion));
    }

    #[test]
    fn rejects_version_wrong_tag() {
        // version's identifier is BOOLEAN (0x01) instead of INTEGER (0x02).
        let mut bytes = RSA_MINIMAL;
        bytes[2] = 0x01;
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::Version(IntegerFieldError::WrongTag))
        );
    }

    #[test]
    fn rejects_version_constructed() {
        // version's identifier is INTEGER's tag number but in the constructed form (0x22 instead
        // of 0x02).
        let mut bytes = RSA_MINIMAL;
        bytes[2] = 0x22;
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::Version(IntegerFieldError::Constructed))
        );
    }

    #[test]
    fn rejects_version_empty_integer() {
        // version's INTEGER has zero content octets -- an INTEGER needs at least one (X.690
        // §8.3.1). Outer content shrinks by 1 (26 = 0x1a instead of 27 = 0x1b).
        let bytes = [
            0x30, 0x1a,
                0x02, 0x00,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
        ];
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::Version(IntegerFieldError::Content(BigIntError::Empty)))
        );
    }

    #[test]
    fn rejects_unsupported_version_two() {
        // version content is 0x02 -- a structurally well-formed, minimal, single-octet INTEGER,
        // but RFC 8017's Version type permits only 0 (two-prime) or 1 (multi).
        let mut bytes = RSA_MINIMAL;
        bytes[4] = 0x02;
        assert_eq!(parse_rsa_private_key(&bytes), Err(RsaPrivateKeyError::UnsupportedVersion));
    }

    #[test]
    fn rejects_missing_field_early_modulus() {
        // Only version is present: 30 03 02 01 00 (SEQUENCE { INTEGER 0 }, no key-material fields).
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x00];
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::MissingField(RsaField::Modulus))
        );
    }

    #[test]
    fn rejects_missing_field_late_coefficient() {
        // version + the first seven key-material fields are present; coefficient is missing.
        // Outer content: 3 (version) + 7*3 (seven fields) = 24 (0x18).
        let bytes = [
            0x30, 0x18,
                0x02, 0x01, 0x00,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
                0x02, 0x01, 0x01,
        ];
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::MissingField(RsaField::Coefficient))
        );
    }

    #[test]
    fn rejects_field_malformed_early_modulus() {
        // modulus's identifier is BOOLEAN (0x01) instead of INTEGER (0x02).
        let mut bytes = RSA_MINIMAL;
        bytes[5] = 0x01;
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::Field(RsaField::Modulus, IntegerFieldError::WrongTag))
        );
    }

    #[test]
    fn rejects_field_malformed_late_prime2() {
        // prime2's identifier is BOOLEAN (0x01) instead of INTEGER (0x02). prime2 is the fifth
        // key-material field; its tag byte sits at array index 2 (outer header) + 3 (version) +
        // 4*3 (modulus..prime1, four fields at 3 bytes each) = 17.
        let mut bytes = RSA_MINIMAL;
        bytes[17] = 0x01;
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::Field(RsaField::Prime2, IntegerFieldError::WrongTag))
        );
    }

    #[test]
    fn rejects_version_mismatch_two_prime_with_other_prime_infos() {
        // version = 0 (two-prime), but a well-formed, non-empty otherPrimeInfos SEQUENCE with one
        // well-formed OtherPrimeInfo member is present -- the eight fields all decode fine,
        // otherPrimeInfos's own framing AND its one member's framing are both well-formed, so this
        // is caught only by the cross-field rule, not by any earlier structural check.
        // member: `30 09 02 01 01 02 01 01 02 01 01` (11 bytes). otherPrimeInfos: `30 0b <member>`
        // (13 bytes). Outer content: 27 (RSA_MINIMAL's) + 13 = 40 (0x28).
        let mut bytes = vec![0x30, 0x28];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes.extend_from_slice(&[
            0x30, 0x0b,
                0x30, 0x09,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
        ]);
        assert_eq!(parse_rsa_private_key(&bytes), Err(RsaPrivateKeyError::VersionMismatch));
    }

    #[test]
    fn rejects_version_mismatch_multi_without_other_prime_infos() {
        // version = 1 (multi), but no otherPrimeInfos follows -- the eight fields all decode fine,
        // so this too is caught only by the cross-field rule.
        let mut bytes = RSA_MINIMAL;
        bytes[4] = 0x01;
        assert_eq!(parse_rsa_private_key(&bytes), Err(RsaPrivateKeyError::VersionMismatch));
    }

    #[test]
    fn rejects_other_prime_infos_empty() {
        // version = 1, followed by an EMPTY otherPrimeInfos SEQUENCE (`30 00`) -- well-formed TLV
        // framing, but `OtherPrimeInfos ::= SEQUENCE SIZE(1..MAX) OF …` forbids zero members.
        // Outer content: 27 (RSA_MINIMAL's, with version mutated to 1) + 2 (`30 00`) = 29 (0x1d).
        let mut bytes = vec![0x30, 0x1d];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[2 + 2] = 0x01; // mutate the copied version content octet (index 4 in the new buffer) to 1
        bytes.extend_from_slice(&[0x30, 0x00]);
        assert_eq!(parse_rsa_private_key(&bytes), Err(RsaPrivateKeyError::OtherPrimeInfosEmpty));
    }

    #[test]
    fn rejects_other_prime_infos_malformed_truncated() {
        // version = 1, followed by an otherPrimeInfos SEQUENCE that declares 5 content octets but
        // only 3 (`02 01 01`) are present -- caught inside otherPrimeInfos's own TLV parse.
        // Outer content: 27 + 5 (`30 05 02 01 01`) = 32 (0x20).
        let mut bytes = vec![0x30, 0x20];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[2 + 2] = 0x01; // mutate the copied version content octet to 1
        bytes.extend_from_slice(&[0x30, 0x05, 0x02, 0x01, 0x01]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::OtherPrimeInfos(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_non_sequence_trailing_element_as_trailing_elements() {
        // A trailing BOOLEAN (universal, not a SEQUENCE) after a complete RSAPrivateKey -- not an
        // otherPrimeInfos attempt at all, so this is a genuinely unpermitted extra field.
        let mut bytes = RSA_MINIMAL.to_vec();
        bytes[1] = 0x1e; // outer content length 27 -> 30 (+3 for the trailing BOOLEAN TLV)
        bytes.extend_from_slice(&[0x01, 0x01, 0xFF]);
        assert_eq!(parse_rsa_private_key(&bytes), Err(RsaPrivateKeyError::TrailingElements));
    }

    #[test]
    fn rejects_other_prime_infos_primitive_sequence_form() {
        // A trailing element tagged UNIVERSAL 16 but in the PRIMITIVE form (0x10, not 0x30). Its tag
        // NUMBER is SEQUENCE, so tag-first classification treats it as an otherPrimeInfos attempt
        // (matching ec_private_key's handling of a primitive context tag), and decode_sequence_tlv
        // reports the primitive form as SequenceError::NotConstructed -- surfaced as
        // OtherPrimeInfos(NotConstructed), NOT the TrailingElements umbrella. The error fires in the
        // otherPrimeInfos step, before the cross-field version check, so RSA_MINIMAL's version 0 is
        // irrelevant here.
        let mut bytes = RSA_MINIMAL.to_vec();
        bytes[1] = 0x20; // outer content length 27 -> 32 (+5 for the trailing `10 03 02 01 01`)
        bytes.extend_from_slice(&[0x10, 0x03, 0x02, 0x01, 0x01]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::OtherPrimeInfos(SequenceError::NotConstructed))
        );
    }

    // --- otherPrimeInfos MEMBER validation (the ec_private_key-parameters-style fold: framing of
    // each OtherPrimeInfo is fully validated, only the three integer values stay opaque) ---

    #[test]
    fn rejects_other_prime_info_member_not_sequence() {
        // version = 1, followed by an otherPrimeInfos SEQUENCE whose single "member" is a bare
        // INTEGER (`02 01 01`), not a SEQUENCE -- `OtherPrimeInfo` must itself be a SEQUENCE, so
        // this is caught by the member's own SEQUENCE-framing check (WrongTag), not by anything
        // integer-shaped succeeding.
        // otherPrimeInfos: `30 03 02 01 01` (5 bytes). Outer content: 27 (RSA_MINIMAL's, version
        // mutated to 1) + 5 = 32 (0x20).
        let mut bytes = vec![0x30, 0x20];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[4] = 0x01; // version -> multi
        bytes.extend_from_slice(&[0x30, 0x03, 0x02, 0x01, 0x01]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::OtherPrimeInfoMember(OtherPrimeInfoError::BadSeq(
                SequenceError::WrongTag
            )))
        );
    }

    #[test]
    fn rejects_other_prime_info_member_content_not_tlv() {
        // version = 1, followed by an otherPrimeInfos SEQUENCE whose content is the single byte
        // `0xff` -- not a valid TLV start at all: `0xff`'s low 5 bits are all set (the high-tag-form
        // marker), so the tag codec expects a continuation octet that never comes, failing as
        // `TagError::Truncated` deep inside the member's own `decode_sequence_tlv` call.
        // otherPrimeInfos: `30 01 ff` (3 bytes). Outer content: 27 + 3 = 30 (0x1e).
        let mut bytes = vec![0x30, 0x1e];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[4] = 0x01; // version -> multi
        bytes.extend_from_slice(&[0x30, 0x01, 0xff]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::OtherPrimeInfoMember(OtherPrimeInfoError::BadSeq(
                SequenceError::Tlv(TlvError::Tag(crate::tag::TagError::Truncated))
            )))
        );
    }

    #[test]
    fn rejects_other_prime_info_member_missing_field() {
        // version = 1; the otherPrimeInfos SEQUENCE's one member is well-formed as a SEQUENCE but
        // holds only TWO INTEGERs (prime, exponent) -- coefficient is missing.
        // member: `30 06 02 01 01 02 01 01` (8 bytes). otherPrimeInfos: `30 08 <member>` (10 bytes).
        // Outer content: 27 + 10 = 37 (0x25).
        let mut bytes = vec![0x30, 0x25];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[4] = 0x01; // version -> multi
        bytes.extend_from_slice(&[
            0x30, 0x08,
                0x30, 0x06,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
        ]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::OtherPrimeInfoMember(OtherPrimeInfoError::MissingField(
                OpiField::Coefficient
            )))
        );
    }

    #[test]
    fn rejects_other_prime_info_member_trailing() {
        // version = 1; the otherPrimeInfos SEQUENCE's one member is a SEQUENCE of FOUR INTEGERs --
        // one more than `OtherPrimeInfo`'s three (prime, exponent, coefficient), so bytes remain
        // after the third is consumed.
        // member: `30 0c 02 01 01 02 01 01 02 01 01 02 01 01` (14 bytes).
        // otherPrimeInfos: `30 0e <member>` (16 bytes). Outer content: 27 + 16 = 43 (0x2b).
        let mut bytes = vec![0x30, 0x2b];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[4] = 0x01; // version -> multi
        bytes.extend_from_slice(&[
            0x30, 0x0e,
                0x30, 0x0c,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
        ]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::OtherPrimeInfoMember(OtherPrimeInfoError::TrailingElements))
        );
    }

    #[test]
    fn rejects_other_prime_info_member_non_canonical_integer() {
        // version = 1; the otherPrimeInfos SEQUENCE's one member's `prime` field is `02 02 00 01`
        // -- non-minimal (redundant leading 0x00; 0x01's top bit is already clear). `exponent` and
        // `coefficient` are both the minimal `02 01 01`.
        // member: `30 0a 02 02 00 01 02 01 01 02 01 01` (12 bytes).
        // otherPrimeInfos: `30 0c <member>` (14 bytes). Outer content: 27 + 14 = 41 (0x29).
        let mut bytes = vec![0x30, 0x29];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[4] = 0x01; // version -> multi
        bytes.extend_from_slice(&[
            0x30, 0x0c,
                0x30, 0x0a,
                    0x02, 0x02, 0x00, 0x01,
                    0x02, 0x01, 0x01,
                    0x02, 0x01, 0x01,
        ]);
        assert_eq!(
            parse_rsa_private_key(&bytes),
            Err(RsaPrivateKeyError::OtherPrimeInfoMember(OtherPrimeInfoError::Field(
                OpiField::Prime,
                IntegerFieldError::Content(BigIntError::NonMinimal)
            )))
        );
    }

    #[test]
    fn accepts_two_member_other_prime_infos() {
        // version = 1; the otherPrimeInfos SEQUENCE holds TWO well-formed OtherPrimeInfo members,
        // each `30 09 02 01 01 02 01 01 02 01 01` (11 bytes) -- both members' framing validates
        // cleanly, so this parses Ok, exercising the member-walk loop beyond a single iteration.
        // otherPrimeInfos: `30 16 <member> <member>` (2 + 22 = 24 bytes). Outer content: 27 + 24 =
        // 51 (0x33).
        const MEMBER: [u8; 11] = [0x30, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
        let mut bytes = vec![0x30, 0x33];
        bytes.extend_from_slice(&RSA_MINIMAL[2..]);
        bytes[4] = 0x01; // version -> multi
        bytes.extend_from_slice(&[0x30, 0x16]);
        bytes.extend_from_slice(&MEMBER);
        bytes.extend_from_slice(&MEMBER);

        let key = parse_rsa_private_key_strict(&bytes).unwrap();
        let mut expected_content = MEMBER.to_vec();
        expected_content.extend_from_slice(&MEMBER);
        assert_eq!(key.other_prime_infos, Some(&expected_content[..]));
    }
}
