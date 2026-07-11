//! X.509 `Name` / `RDNSequence` (RFC 5280 §4.1.2.4) — a bounded, **structural** consumer that
//! composes this crate's verified primitives.
//!
//! ```text
//! Name                       ::= RDNSequence
//! RDNSequence                ::= SEQUENCE OF RelativeDistinguishedName
//! RelativeDistinguishedName  ::= SET SIZE (1..MAX) OF AttributeTypeAndValue
//! AttributeTypeAndValue      ::= SEQUENCE { type OBJECT IDENTIFIER, value ANY }
//! ```
//!
//! This module is the sibling of [`crate::x509_spki`]: a **demonstration of composition**, not an
//! expansion of the crate's DER-layer scope (see the crate-level docs). It frames the outer
//! `RDNSequence` SEQUENCE, each `RelativeDistinguishedName` SET OF, and each
//! `AttributeTypeAndValue` SEQUENCE using [`crate::sequence`], [`crate::set_of`], [`crate::tlv`],
//! and [`crate::oid`] verbatim — it does not hand-roll any tag/length/TLV parsing of its own.
//!
//! **Design note — a validator, not a materialized tree.** Unlike [`crate::x509_spki`]'s
//! `SubjectPublicKeyInfo` (a fixed two/three-field schema that borrows straight into a struct), a
//! `Name` is a variable-count `SEQUENCE OF … SET OF …`: the number of RDNs and the number of
//! `AttributeTypeAndValue`s per RDN are both unbounded at the type level. Materializing that into
//! an owned tree would need `alloc` (`Vec`s of RDNs, of ATVs), which this heap-free crate forbids
//! (`#![forbid(unsafe_code)]`, no `alloc`). So [`validate_name`] follows [`crate::big_integer`]'s
//! "validate, don't materialize" stance: it walks the whole structure and returns `Result<(),
//! NameError>` — proof that the bytes are a well-formed, DER-canonical `Name`, with no owned or
//! borrowed collection of the variable-count children. A caller that needs the individual RDNs/ATVs
//! re-walks with [`crate::sequence::Elements`] / [`crate::set_of::decode_set_of`] itself, exactly as
//! this module does internally.
//!
//! **Scope boundaries (deliberate):**
//! - *Structural framing only.* [`validate_name`] validates that the byte string is a well-formed,
//!   DER-canonical `RDNSequence` with the exact field tiling the ASN.1 schema requires at every
//!   level — nothing more, nothing less. It does **not** interpret *which* attribute type an OID
//!   names (`countryName`, `commonName`, …), does not decode or charset-check the attribute
//!   `value` (`DirectoryString`'s `PrintableString`/`UTF8String`/… CHOICE is a caller concern), and
//!   does not touch any other X.509 semantics (certificate paths, validity, extensions, signatures).
//! - *`value` stays raw.* `AttributeTypeAndValue.value` is ASN.1 `ANY` — its DER encoding (tag +
//!   length + value) is walked only far enough to confirm it is one well-framed TLV that exactly
//!   fills the remainder of the ATV's content; this module does not know or care whether it holds a
//!   `PrintableString`, a `UTF8String`, or any other type.
//! - *Strict, top to bottom, but level-appropriate.* The outer `RDNSequence` must consume the
//!   entire input (no trailing bytes after the whole `Name`); each RDN's SET OF content must
//!   exactly tile into its `AttributeTypeAndValue` children *and* be in §11.6 ascending order
//!   ([`crate::set_of::decode_set_of`]); each ATV's SEQUENCE content must exactly tile into its two
//!   mandatory fields. The outer `RDNSequence`, being a plain `SEQUENCE OF`, has **no** §11.6
//!   ordering requirement of its own — element order there is significant (RFC 4514 renders RDNs in
//!   the order they appear), not sorted.
//! - *RFC 5280's `SIZE(1..MAX)` on the RDN, enforced explicitly.* [`crate::set_of::decode_set_of`]
//!   accepts empty content as vacuously ordered (zero children trivially satisfy "no descending
//!   adjacent pair"), but RFC 5280 §4.1.2.4 requires `RelativeDistinguishedName ::= SET SIZE
//!   (1..MAX) OF AttributeTypeAndValue` — at least one `AttributeTypeAndValue`. This module adds
//!   that check itself ([`NameError::EmptyRdn`]); `set_of` deliberately stays schema-free (it has
//!   no `SIZE` concept) and is not the place for it.

use crate::oid::TAG as OID_TAG;
use crate::oid::{validate_oid, OidError};
use crate::sequence::TAG as SEQUENCE_TAG;
use crate::sequence::{decode_sequence_tlv_strict, Elements, SequenceError};
use crate::set_of::{decode_set_of_tlv, SetOfError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, Tlv, TlvError};

/// Why a `Name` (`RDNSequence`) was rejected. Every variant names a specific structural cause,
/// wrapping the underlying primitive's error where one exists (mirrors [`crate::x509_spki::SpkiError`]'s
/// wrapping style).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum NameError {
    /// The outer `RDNSequence` SEQUENCE envelope was malformed: bad identifier/length, the
    /// primitive (non-constructed) form, or trailing bytes after the whole structure (this is a
    /// top-level object, decoded with [`decode_sequence_tlv_strict`]).
    BadOuterSeq(SequenceError),
    /// A `RelativeDistinguishedName` child of the outer `RDNSequence` was malformed: bad
    /// identifier/length, a non-SET tag, the primitive form of SET, a malformed
    /// `AttributeTypeAndValue` child TLV, or a §11.6 member-ordering violation among the RDN's
    /// `AttributeTypeAndValue`s. Wraps [`SetOfError`] — [`decode_set_of_tlv`] enforces the tag,
    /// framing, *and* ordering checks in one call.
    BadRdn(SetOfError),
    /// A `RelativeDistinguishedName` was well-formed and correctly ordered but contained **zero**
    /// `AttributeTypeAndValue`s — RFC 5280 §4.1.2.4 requires `SIZE (1..MAX)`, so an empty RDN is
    /// rejected here explicitly (a check [`crate::set_of`] deliberately does not make; see the
    /// module docs).
    EmptyRdn,
    /// An `AttributeTypeAndValue` child TLV's own framing (tag/length octets), while walking the
    /// RDN's already-validated SET OF content, was malformed. Structurally unreachable in practice
    /// — [`decode_set_of_tlv`] already proved this content is a clean concatenation of well-formed
    /// TLVs — but decode_tlv is re-run (via [`Elements`]) rather than assumed, so this arm stays
    /// live and this module never `unwrap`s.
    BadAtvTlv(TlvError),
    /// An `AttributeTypeAndValue` child's identifier was well-framed but not UNIVERSAL 16
    /// (SEQUENCE).
    AtvWrongTag,
    /// An `AttributeTypeAndValue` child's identifier was UNIVERSAL 16 but in the *primitive* form —
    /// a SEQUENCE is always constructed.
    AtvNotConstructed,
    /// The `AttributeTypeAndValue.type` OID's TLV framing (tag/length octets) was malformed.
    BadAtvOidTlv(TlvError),
    /// The `AttributeTypeAndValue.type` field's identifier was well-framed but not UNIVERSAL 6
    /// (OBJECT IDENTIFIER).
    AtvOidWrongTag,
    /// The `AttributeTypeAndValue.type` field's identifier was UNIVERSAL 6 but in the constructed
    /// form — OBJECT IDENTIFIER content is always primitive.
    AtvOidConstructed,
    /// The `AttributeTypeAndValue.type` OID's content failed canonical-DER validation.
    BadAtvOid(OidError),
    /// No `AttributeTypeAndValue.value` (`ANY`) is present after the `type` OID — the ATV
    /// SEQUENCE's content ended after its first field.
    MissingAtvValue,
    /// The `AttributeTypeAndValue.value` TLV's framing (tag/length octets) was malformed.
    BadAtvValueTlv(TlvError),
    /// The `AttributeTypeAndValue` SEQUENCE has more than its two permitted fields (`type`,
    /// `value`): bytes remain in its content after the `value` TLV.
    AtvTrailingElements,
}

/// Decode the `AttributeTypeAndValue.type` OID TLV from the front of `input`, returning its
/// validated content octets and the bytes consumed. Composes [`decode_tlv`] + [`validate_oid`],
/// mirroring [`crate::x509_spki`]'s `decode_oid_tlv` exactly.
fn decode_atv_oid_tlv(input: &[u8]) -> Result<(&[u8], usize), NameError> {
    let (tlv, used) = decode_tlv(input).map_err(NameError::BadAtvOidTlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != OID_TAG {
        return Err(NameError::AtvOidWrongTag);
    }
    if tlv.tag.constructed {
        return Err(NameError::AtvOidConstructed);
    }
    validate_oid(tlv.value).map_err(NameError::BadAtvOid)?;
    Ok((tlv.value, used))
}

/// Validate one `AttributeTypeAndValue` (`type` OID + `value` ANY, exactly tiling `tlv.value`).
///
/// `tlv` is one child of an already tag/order-validated RDN SET OF content (yielded by
/// [`Elements`]): its identifier must be UNIVERSAL 16 (SEQUENCE) constructed, and its content must
/// tile into exactly two fields — the `type` OID, then one more well-framed TLV (the `value`,
/// left uninterpreted, as ASN.1 `ANY`).
fn validate_atv(tlv: Tlv<'_>) -> Result<(), NameError> {
    if tlv.tag.class != Class::Universal || tlv.tag.number != SEQUENCE_TAG {
        return Err(NameError::AtvWrongTag);
    }
    if !tlv.tag.constructed {
        return Err(NameError::AtvNotConstructed);
    }
    let content = tlv.value;

    // Field 1: `type` (OBJECT IDENTIFIER).
    let (_atv_type, oid_used) = decode_atv_oid_tlv(content)?;
    let rest = &content[oid_used..];
    if rest.is_empty() {
        return Err(NameError::MissingAtvValue);
    }

    // Field 2: `value` (ANY) — one well-framed TLV, left raw/uninterpreted, must exactly fill
    // what remains of the ATV's content (no third field permitted).
    let (_value_tlv, value_used) = decode_tlv(rest).map_err(NameError::BadAtvValueTlv)?;
    if value_used != rest.len() {
        return Err(NameError::AtvTrailingElements);
    }
    Ok(())
}

/// Validate one `RelativeDistinguishedName` from the front of `input`, returning the bytes
/// consumed (`tag + length + value` of the SET OF TLV).
///
/// Composes [`decode_set_of_tlv`] (SET tag/framing + §11.6 ordering, in one call) then walks the
/// validated content's `AttributeTypeAndValue` children with [`Elements`], validating each with
/// [`validate_atv`]. Enforces RFC 5280 §4.1.2.4's `SIZE (1..MAX)`: empty content is [`NameError::EmptyRdn`].
fn validate_rdn(input: &[u8]) -> Result<usize, NameError> {
    let (rdn_content, used) = decode_set_of_tlv(input).map_err(NameError::BadRdn)?;
    if rdn_content.is_empty() {
        return Err(NameError::EmptyRdn);
    }
    for child in Elements::new(rdn_content) {
        let tlv = child.map_err(NameError::BadAtvTlv)?;
        validate_atv(tlv)?;
    }
    Ok(used)
}

/// Validate a complete DER `Name` (`RDNSequence`) from `input`.
///
/// **Strict, top level**: `input` must be *exactly* one `Name` — no trailing bytes are tolerated
/// after the whole `RDNSequence`.
///
/// Validates, in order:
/// 1. the outer `RDNSequence` SEQUENCE envelope, requiring it to consume the entire input
///    ([`decode_sequence_tlv_strict`]);
/// 2. each `RelativeDistinguishedName` child, in the order they appear — a plain `SEQUENCE OF`
///    has no §11.6 ordering requirement of its own — via [`validate_rdn`];
/// 3. inside each RDN, its `AttributeTypeAndValue` children: §11.6 encoding-order among siblings
///    ([`crate::set_of::decode_set_of`]) and each one's `type`/`value` field tiling
///    ([`validate_atv`]).
///
/// Never panics on any input (proven by the `validate_never_panics` Kani harness below); returns a
/// classified [`NameError`] on any structural deviation. Returns `Ok(())` — this is a validator,
/// not a materializing parser; see the module docs for why.
pub fn validate_name(input: &[u8]) -> Result<(), NameError> {
    // 1. Outer RDNSequence: must consume the whole input (top-level anti-trailing-data).
    let outer_content = decode_sequence_tlv_strict(input).map_err(NameError::BadOuterSeq)?;

    // 2. Walk each RelativeDistinguishedName in order (SEQUENCE OF: no §11.6 requirement here).
    let mut off = 0usize;
    while off < outer_content.len() {
        let used = validate_rdn(&outer_content[off..])?;
        off += used;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kani proof harness.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer covers a small but structurally complete Name
// (e.g. one RDN with one short ATV, or a truncated/malformed variant thereof). Kani's `--unwind N`
// bounds each loop independently (not cumulatively across nesting), so the relevant figure is the
// *widest single loop* reachable, not the sum across the call tree: `validate_name`'s outer RDN
// walk, `decode_set_of`'s (via `decode_set_of_tlv`) child walk, `Elements`'s ATV walk, and
// `validate_oid`'s subidentifier walk each individually iterate at most `content.len() / 2 <= 8`
// times against a 16-byte buffer (every accepted TLV consumes `>= 2` bytes), and `decode_tlv`'s own
// header decode needs up to ~11 iterations for a maximal (high-tag + long-length) header.
// `#[kani::unwind(20)]` covers all of these with margin, matching `x509_spki::parse_never_panics`'s
// bound; if Kani reports an unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `validate_name` never panics on any input up to 16 octets.
    #[kani::proof]
    #[kani::unwind(20)]
    fn validate_never_panics() {
        let buf: [u8; 16] = kani::any();
        let _ = validate_name(&buf);
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A real multi-RDN DN: `C=US` (PrintableString), `O=Example Inc` (UTF8String),
    /// `CN=Example CA` (UTF8String) — three single-ATV RDNs, in RFC 4514 rendering order.
    ///
    /// `30 38`                                        RDNSequence, len 56
    ///    `31 0b`                                      RDN 1: SET, len 11
    ///       `30 09`                                    AttributeTypeAndValue SEQUENCE, len 9
    ///          `06 03 55 04 06`                        OID 2.5.4.6 (countryName)
    ///          `13 02 55 53`                           PrintableString "US"
    ///    `31 14`                                      RDN 2: SET, len 20
    ///       `30 12`                                    AttributeTypeAndValue SEQUENCE, len 18
    ///          `06 03 55 04 0a`                        OID 2.5.4.10 (organizationName)
    ///          `0c 0b "Example Inc"`                   UTF8String, len 11
    ///    `31 13`                                      RDN 3: SET, len 19
    ///       `30 11`                                    AttributeTypeAndValue SEQUENCE, len 17
    ///          `06 03 55 04 03`                        OID 2.5.4.3 (commonName)
    ///          `0c 0a "Example CA"`                    UTF8String, len 10
    #[rustfmt::skip]
    const MULTI_RDN_DN: [u8; 58] = [
        0x30, 0x38, 0x31, 0x0b, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31,
        0x14, 0x30, 0x12, 0x06, 0x03, 0x55, 0x04, 0x0a,
        0x0c, 0x0b, 0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c,
        0x65, 0x20, 0x49, 0x6e, 0x63, 0x31, 0x13, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a,
        0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20,
        0x43, 0x41,
    ];

    /// A single-RDN DN: just `CN=Example CA` (UTF8String) — the third RDN of [`MULTI_RDN_DN`],
    /// standing alone as the whole `Name`.
    ///
    /// `30 15`                                        RDNSequence, len 21
    ///    `31 13`                                      RDN: SET, len 19
    ///       `30 11`                                    AttributeTypeAndValue SEQUENCE, len 17
    ///          `06 03 55 04 03`                        OID 2.5.4.3 (commonName)
    ///          `0c 0a "Example CA"`                    UTF8String, len 10
    #[rustfmt::skip]
    const SINGLE_RDN_DN: [u8; 23] = [
        0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
        0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x78, 0x61,
        0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41,
    ];

    /// A multi-ATV RDN DN: one RDN containing **two** `AttributeTypeAndValue`s — `C=US`
    /// (PrintableString) and `CN=Example CA` (UTF8String) — correctly §11.6-sorted. The two ATVs'
    /// raw TLV encodings both start `30` (SEQUENCE); their *second* byte (the DER length) is `09`
    /// for the `C` ATV and `11` for the `CN` ATV, so `09 < 11` already decides the padded
    /// comparison at that byte — `C` sorts before `CN`.
    ///
    /// `30 20`                                        RDNSequence, len 32
    ///    `31 1e`                                      RDN: SET, len 30
    ///       `30 09 06 03 55 04 06 13 02 55 53`         ATV 1: C=US (PrintableString)
    ///       `30 11 06 03 55 04 03 0c 0a "Example CA"`  ATV 2: CN=Example CA (UTF8String)
    #[rustfmt::skip]
    const MULTI_ATV_RDN_DN: [u8; 34] = [
        0x30, 0x20, 0x31, 0x1e, 0x30, 0x09, 0x06, 0x03,
        0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x30,
        0x11, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0c, 0x0a,
        0x45, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x20,
        0x43, 0x41,
    ];

    #[test]
    fn accepts_multi_rdn_dn() {
        assert_eq!(validate_name(&MULTI_RDN_DN), Ok(()));
    }

    #[test]
    fn accepts_single_rdn_dn() {
        assert_eq!(validate_name(&SINGLE_RDN_DN), Ok(()));
    }

    #[test]
    fn accepts_multi_atv_rdn_dn() {
        assert_eq!(validate_name(&MULTI_ATV_RDN_DN), Ok(()));
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn rejects_unsorted_set_of_members() {
        // The same two ATVs as MULTI_ATV_RDN_DN, but swapped into DESCENDING order (CN then C):
        // violates §11.6 at the first (only) adjacent pair.
        //
        // `30 20`                                        RDNSequence, len 32
        //    `31 1e`                                      RDN: SET, len 30
        //       `30 11 06 03 55 04 03 0c 0a "Example CA"`  ATV 1: CN=Example CA
        //       `30 09 06 03 55 04 06 13 02 55 53`         ATV 2: C=US
        #[rustfmt::skip]
        let bytes: [u8; 34] = [
            0x30, 0x20, 0x31, 0x1e, 0x30, 0x11, 0x06, 0x03,
            0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x78, 0x61,
            0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41, 0x30,
            0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02,
            0x55, 0x53,
        ];
        assert_eq!(validate_name(&bytes), Err(NameError::BadRdn(SetOfError::Unsorted { index: 0 })));
    }

    #[test]
    fn rejects_empty_rdn() {
        // RDNSequence { SET {} } — an RDN with zero ATVs, well-framed and vacuously "ordered" (so
        // `decode_set_of` alone would accept it), but RFC 5280 §4.1.2.4 requires SIZE(1..MAX).
        //
        // `30 02`      RDNSequence, len 2
        //    `31 00`    RDN: SET, len 0 (empty)
        let bytes = [0x30, 0x02, 0x31, 0x00];
        assert_eq!(validate_name(&bytes), Err(NameError::EmptyRdn));
    }

    #[test]
    fn rejects_atv_with_one_field() {
        // ATV SEQUENCE containing only the `type` OID, no `value`.
        //
        // `30 09`      RDNSequence, len 9
        //    `31 07`    RDN: SET, len 7
        //       `30 05`  ATV SEQUENCE, len 5
        //          `06 03 55 04 06`  OID 2.5.4.6 (countryName), no value field
        let bytes =
            [0x30, 0x09, 0x31, 0x07, 0x30, 0x05, 0x06, 0x03, 0x55, 0x04, 0x06];
        assert_eq!(validate_name(&bytes), Err(NameError::MissingAtvValue));
    }

    #[test]
    fn rejects_atv_with_three_fields() {
        // ATV SEQUENCE containing type + value + a bogus extra BOOLEAN field.
        //
        // `30 10`         RDNSequence, len 16
        //    `31 0e`       RDN: SET, len 14
        //       `30 0c`     ATV SEQUENCE, len 12
        //          `06 03 55 04 06`  OID 2.5.4.6 (countryName)
        //          `13 02 55 53`     PrintableString "US"
        //          `01 01 ff`        extra BOOLEAN -- not permitted, ATV has only 2 fields
        let bytes = [
            0x30, 0x10, 0x31, 0x0e, 0x30, 0x0c, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
            0x53, 0x01, 0x01, 0xff,
        ];
        assert_eq!(validate_name(&bytes), Err(NameError::AtvTrailingElements));
    }

    #[test]
    fn rejects_atv_first_field_not_oid() {
        // The ATV's first field is an INTEGER (0x02) instead of an OBJECT IDENTIFIER.
        let mut bytes = MULTI_RDN_DN;
        bytes[6] = 0x02; // first ATV's OID tag, inside RDN 1's ATV SEQUENCE
        assert_eq!(validate_name(&bytes), Err(NameError::AtvOidWrongTag));
    }

    #[test]
    fn rejects_non_canonical_length_somewhere() {
        // The outer RDNSequence's length re-encoded in the long form (0x81 0x38) where the short
        // form (0x38) is required -- non-minimal, forbidden by DER.
        use crate::length::LengthError;
        let mut bytes = vec![0x30, 0x81, 0x38];
        bytes.extend_from_slice(&MULTI_RDN_DN[2..]);
        assert_eq!(
            validate_name(&bytes),
            Err(NameError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_trailing_bytes_after_whole_name() {
        let mut bytes = MULTI_RDN_DN.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            validate_name(&bytes),
            Err(NameError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_trailing_bytes_inside_rdn() {
        // A single-RDN Name whose SET declares one extra content byte (0xAA) beyond its sole ATV:
        // the SET content does not tile into complete child TLVs -- after the ATV, the lone
        // trailing byte is an identifier octet with no length octet following it (input
        // exhausted), so it fails as a truncated length field, not a truncated value.
        //
        // `30 0e`                                RDNSequence, len 14
        //    `31 0c`                              RDN: SET, len 12 (one more than the ATV fills)
        //       `30 09 06 03 55 04 06 13 02 55 53`  ATV: C=US (11 bytes)
        //       `aa`                                trailing junk octet (no length field follows)
        let bytes: [u8; 16] = [
            0x30, 0x0e, 0x31, 0x0c, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
            0x53, 0xaa,
        ];
        assert_eq!(
            validate_name(&bytes),
            Err(NameError::BadRdn(SetOfError::Element(TlvError::Length(
                crate::length::LengthError::Truncated
            ))))
        );
    }

    #[test]
    fn rejects_trailing_bytes_inside_atv() {
        // A single-RDN, single-ATV Name whose ATV SEQUENCE declares one extra content byte (0xAA)
        // beyond its two fields (OID + PrintableString): `decode_tlv` on the remainder after the
        // OID successfully decodes just the PrintableString `value` TLV, leaving the trailing junk
        // byte un-tiled -- caught by the exact-tiling check as a "more than two fields" violation,
        // exactly like a real extra field would be (see `rejects_atv_with_three_fields`).
        //
        // `30 0e`                                   RDNSequence, len 14
        //    `31 0c`                                 RDN: SET, len 12
        //       `30 0a`                                ATV SEQUENCE, len 10 (one more than 2 fields fill)
        //          `06 03 55 04 06`                     OID 2.5.4.6 (countryName)
        //          `13 02 55 53`                        PrintableString "US"
        //          `aa`                                 trailing junk octet
        let bytes: [u8; 16] = [
            0x30, 0x0e, 0x31, 0x0c, 0x30, 0x0a, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55,
            0x53, 0xaa,
        ];
        assert_eq!(validate_name(&bytes), Err(NameError::AtvTrailingElements));
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer RDNSequence tag (0x30) with SET (0x31).
        let mut bytes = MULTI_RDN_DN;
        bytes[0] = 0x31;
        assert_eq!(validate_name(&bytes), Err(NameError::BadOuterSeq(SequenceError::WrongTag)));
    }

    #[test]
    fn rejects_truncated_input() {
        // Drop the last 10 bytes: the outer RDNSequence declares more content than is present.
        let bytes = &MULTI_RDN_DN[..MULTI_RDN_DN.len() - 10];
        assert_eq!(
            validate_name(bytes),
            Err(NameError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_rdn_wrong_tag() {
        // RDN 1's child is a SEQUENCE (0x30) instead of a SET.
        let mut bytes = MULTI_RDN_DN;
        bytes[2] = 0x30;
        assert_eq!(validate_name(&bytes), Err(NameError::BadRdn(SetOfError::WrongTag)));
    }

    #[test]
    fn rejects_atv_wrong_tag() {
        // RDN 1's ATV child is a SET (0x31) instead of a SEQUENCE.
        let mut bytes = MULTI_RDN_DN;
        bytes[4] = 0x31;
        assert_eq!(validate_name(&bytes), Err(NameError::AtvWrongTag));
    }

    #[test]
    fn rejects_atv_primitive_form() {
        // RDN 1's ATV child is the correct SEQUENCE tag NUMBER (UNIVERSAL 16) but in the
        // *primitive* form (0x10 instead of the constructed 0x30) — a SEQUENCE is always
        // constructed. Distinct from `rejects_atv_wrong_tag` (a wrong tag number): this exercises
        // the constructed-bit check specifically (NameError::AtvNotConstructed).
        let mut bytes = MULTI_RDN_DN;
        bytes[4] = 0x10;
        assert_eq!(validate_name(&bytes), Err(NameError::AtvNotConstructed));
    }

    #[test]
    fn rejects_constructed_oid() {
        // The ATV's OID identifier in the constructed form (0x26) -- forbidden; OID content is
        // always primitive.
        let mut bytes = MULTI_RDN_DN;
        bytes[6] = 0x26;
        assert_eq!(validate_name(&bytes), Err(NameError::AtvOidConstructed));
    }

    #[test]
    fn rejects_non_canonical_oid() {
        // A non-minimal OID subidentifier (leading 0x80 group) in RDN 1's ATV type OID.
        let mut bytes = MULTI_RDN_DN;
        bytes[8] = 0x80;
        assert_eq!(validate_name(&bytes), Err(NameError::BadAtvOid(OidError::NonMinimalSubid)));
    }
}
