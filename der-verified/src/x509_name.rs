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
//!
//! # Examples
//!
//! ```
//! use der_verified::x509_name::validate_name;
//!
//! // A single-RDN Name: CN=Example CA (UTF8String).
//! #[rustfmt::skip]
//! let name_der: [u8; 23] = [
//!     0x30, 0x15, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03,
//!     0x55, 0x04, 0x03, 0x0c, 0x0a, 0x45, 0x78, 0x61,
//!     0x6d, 0x70, 0x6c, 0x65, 0x20, 0x43, 0x41,
//! ];
//! assert_eq!(validate_name(&name_der), Ok(()));
//! ```

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
///    has no §11.6 ordering requirement of its own — via `validate_rdn`;
/// 3. inside each RDN, its `AttributeTypeAndValue` children: §11.6 encoding-order among siblings
///    ([`crate::set_of::decode_set_of`]) and each one's `type`/`value` field tiling
///    (`validate_atv`).
///
/// Never panics on any input up to 16 octets (proven by the `validate_never_panics` Kani harness
/// below); returns a classified [`NameError`] on any structural deviation. Returns `Ok(())` — this is a validator,
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
// Kani proof harnesses (MODULAR — see below).
// ---------------------------------------------------------------------------
//
// `validate_name` is proven panic-free MODULARLY, because a monolithic harness over the whole
// validator is intractable for CBMC. The loops nest three deep — the outer RDN walk (`validate_name`)
// around the SET-OF §11.6 ordering walk + `Elements` ATV walk (`validate_rdn` via `decode_set_of`)
// around the per-child `validate_oid` / `decode_tlv` loops — and a single global unwind makes
// symbolic execution build the PRODUCT of those loops' unrolled copies, not their max. (The widest
// SINGLE loop is only 10 iterations at 16 bytes — `set_of::cmp_padded`'s virtual-padding tail over an
// adjacent 2-byte/12-byte pair; `decode_tag` ≤ 6 and `decode_length` ≤ 4 are SEPARATE, shorter loops
// — so unwind depth is NOT the driver; the nesting product is.) The §11.6
// `set_of::cmp_padded` comparison, re-derived over symbolic content for every member-partition,
// dominates: empirically the monolithic `[u8;16]/unwind(20)` harness exceeds ~100 GB during symex
// (before any SAT solve), and even `[u8;13]/unwind(8)` exceeds ~34 GB.
//
// Fix (mirrors `x509_tbs_certificate`, which stubs `validate_name`): prove the heavy SET-OF/RDN layer
// (`validate_rdn`) panic-free at its own one-RDN scale in `validate_rdn_never_panics`, then have
// `validate_never_panics` STUB `validate_rdn` with a nondeterministic `Result` carrying that lemma's
// proven postcondition — so CBMC verifies only the real outer `RDNSequence` envelope + RDN-walk glue.
// Both require `-Z stubbing` (wired into `check.sh`). If Kani reports an unwinding-assertion failure,
// raise the bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    // Modular stub for the heavy SET-OF/RDN sub-parser. `validate_rdn` is INDEPENDENTLY proven
    // panic-free — and proven to return `Ok(used)` only with `2 <= used <= input.len()` — by
    // `validate_rdn_never_panics` below. Replacing its body with a nondeterministic `Result` whose
    // `used` is constrained to that PROVEN postcondition is SOUND for this composition's panic-freedom:
    // `validate_name`'s loop uses only the Ok/Err outcome and advances `off` by the returned `used`,
    // and `2 <= used <= remaining` is exactly what keeps `off` progressing and in bounds. Returning
    // BOTH Ok and Err over-approximates the real `validate_rdn` (which returns Ok on a strict subset of
    // inputs) — sound, because exploring MORE control-flow outcomes cannot hide a panic. The returned
    // error variant is immaterial: the caller propagates any `Err` verbatim via `?`. The `used` bound
    // is an ASSUMED postcondition, DISCHARGED by `validate_rdn_never_panics` — never assume what is not
    // separately proven (PROOF_MANIFEST modular-proof rule).
    // (rustc's dead-code lint doesn't see the `#[kani::stub]` reference below as a use.)
    #[allow(dead_code)]
    fn stub_validate_rdn(input: &[u8]) -> Result<usize, NameError> {
        if kani::any() {
            let used: usize = kani::any();
            kani::assume(2 <= used && used <= input.len());
            Ok(used)
        } else {
            Err(NameError::EmptyRdn)
        }
    }

    /// Lemma discharging `stub_validate_rdn`'s contract: `validate_rdn` never panics on any input up
    /// to 16 octets, and on `Ok(used)` returns `2 <= used <= input.len()` — the postcondition the RDN
    /// walk in `validate_name` (and the stub above) rely on for progress and in-bounds slicing. This
    /// is the full SET-OF §11.6 ordering + `Elements`/ATV walk proof at one-RDN scale (a 16-octet
    /// buffer admits a two-`AttributeTypeAndValue` RDN, so real §11.6 ordering between well-formed
    /// ATVs is exercised). The input LENGTH is symbolic (`0..=16`): the composition consumes
    /// `validate_rdn` at outer-content suffix lengths `1..=14`, never exactly 16, and its control flow
    /// is length-dependent — so the contract must be discharged across all consumed lengths, not just
    /// the full buffer. Unwind 12: the widest single loop is 10 (`set_of::cmp_padded`'s virtual-padding
    /// tail over an adjacent 2-byte/12-byte pair), +2 margin.
    #[kani::proof]
    #[kani::unwind(12)]
    fn validate_rdn_never_panics() {
        let buf: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        if let Ok(used) = validate_rdn(input) {
            assert!(2 <= used && used <= input.len());
        }
    }

    /// Robustness: `validate_name` never panics on any input up to 16 octets, with the heavy
    /// SET-OF/RDN sub-parser (`validate_rdn`) MODULARLY STUBBED (see the comment above). Exercises the
    /// REAL outer `RDNSequence` SEQUENCE envelope decode and the real RDN-walk offset arithmetic and
    /// bounds. The input LENGTH is symbolic (`0..=16`) so the "up to 16 octets" claim holds at every
    /// length (with a fixed 16-byte buffer, `decode_sequence_tlv_strict`'s anti-trailing-data check
    /// means only a length-14 content ever reaches the RDN walk; symbolic length also exercises the
    /// empty-`Name` and short-envelope paths). Unwind 10: with the stub advancing `off` by `>= 2`, the
    /// outer walk runs `<= 7` over a `<= 14`-octet content, and the envelope's header loops are `<= 6`.
    ///
    /// Cover (T6 primary rule + T2-COROLLARY-A): `validate_never_panics` stacks TWO reductions on
    /// `validate_name` -- a `[u8; 16]` bound AND a `validate_rdn` stub -- so per the corollary the
    /// intersection must be checked for vacuity, not assumed non-vacuous. The strongest observable
    /// post-state fact through `validate_name`'s opaque `Result<(), NameError>` is that the REAL
    /// outer-envelope decode + RDN-walk glue reaches the `Ok` tail -- which requires
    /// `decode_sequence_tlv_strict` to accept the envelope AND the walk loop to run to completion
    /// on the stub's Ok outcomes (never inspecting a stubbed value, exactly as the module comment
    /// argues). This would NOT be SAT if `validate_name`'s body were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::stub(validate_rdn, stub_validate_rdn)]
    #[kani::unwind(10)]
    fn validate_never_panics() {
        let buf: [u8; 16] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let result = validate_name(&buf[..len]);
        kani::cover(
            result.is_ok(),
            "validate_name reaches its Ok tail: the real outer RDNSequence envelope decode + \
             RDN-walk glue ran to completion over the stubbed validate_rdn's Ok outcomes",
        );
        let _ = result;
    }

    // ------------------------------------------------------------------------------------------
    // Contract-surface harnesses (exact-result; bounded-backing evidence). `validate_name` returns
    // `()`, so its contract is the EXACT RESULT (accept/reject, the error variant and the documented
    // check order) over structured shapes: concrete TLV framing, symbolic content bytes.
    // ------------------------------------------------------------------------------------------
    //
    // Shapes. ATV `A(o, v) = 30 05 06 01 o v 00` (7 octets; 1-octet OID content `o`, then a
    // zero-length value TLV whose identifier octet `v` is symbolic with the literal low-tag
    // predicate `v & 0x1F != 0x1F`, so it is always well-framed). RDN `R(..) = 31 <len> ATVs`.
    // Outer `30 <len> RDNs`. Identifier perturbation octets (`t_*`) are symbolic with
    // `t & 0x1F != 0x1F` (low-tag). Attribute values are uninterpreted (module scope).
    //
    // Every harness: concrete framing, `#[kani::unwind(N)]` stated per harness (CBMC's unwinding
    // assertions are enabled and report SUCCESS in the logs), no stubs, no assumptions beyond the
    // stated low-tag predicates.
    //
    // Scope (disclosed). Multi-valued RDNs are covered for exactly TWO ATVs of DIFFERENT encoded
    // lengths (`30 05 ..` against `30 06 ..`): the SET OF ordering compare then decides at the
    // second octet, which keeps the compare loop inside the harness's unwind bound. The sorted pair
    // validates BOTH ATVs; the swapped pair is `BadRdn(Unsorted { index: 0 })`. NOT covered here:
    // two ATVs of EQUAL encoded length (the ordering compare then runs over symbolic content), and
    // RDNs with more than two ATVs. The equal-length case is a tool limit: the fully symbolic
    // 18-octet harness exceeded 16 GB under one global `#[kani::unwind]` bound (8 is the least bound
    // that unwinds `set_of::cmp_padded`'s seven-iteration loop, and that bound multiplies every other
    // nested loop), while a per-loop CBMC bound on that one loop verified it in about 2 minutes at
    // about 7.6 GB. `check.sh` has no per-harness solver arguments, so it is not shipped. Ordering
    // correctness itself is the `set_of` claim.

    /// Expected result for the single-ATV skeleton
    /// `[t_outer, 09, t_rdn, 07, t_atv, 05, t_oid, 01, o, v, 00]` for ANY identifier octets with
    /// the documented outer-to-inner precedence: outer SEQUENCE identifier (`0x30` ok / `0x10`
    /// `NotConstructed` / else `WrongTag`), RDN SET identifier (`0x31` / `0x11` / else), ATV
    /// SEQUENCE identifier (`0x30` / `0x10` -> `AtvNotConstructed` / else `AtvWrongTag`), OID
    /// identifier (`0x06` / `0x26` -> `AtvOidConstructed` / else `AtvOidWrongTag`), then the OID
    /// content via the verified primitive `validate_oid`. Identifier checks are stated from the
    /// literal octets, not from the implementation's tag-match expressions.
    fn expected_single(t_outer: u8, t_rdn: u8, t_atv: u8, t_oid: u8, o: u8) -> Result<(), NameError> {
        if t_outer != 0x30 {
            return Err(NameError::BadOuterSeq(if t_outer == 0x10 {
                SequenceError::NotConstructed
            } else {
                SequenceError::WrongTag
            }));
        }
        if t_rdn != 0x31 {
            return Err(NameError::BadRdn(if t_rdn == 0x11 {
                SetOfError::NotConstructed
            } else {
                SetOfError::WrongTag
            }));
        }
        if t_atv != 0x30 {
            return Err(if t_atv == 0x10 { NameError::AtvNotConstructed } else { NameError::AtvWrongTag });
        }
        if t_oid != 0x06 {
            return Err(if t_oid == 0x26 { NameError::AtvOidConstructed } else { NameError::AtvOidWrongTag });
        }
        match validate_oid(&[o]) {
            Err(e) => Err(NameError::BadAtvOid(e)),
            Ok(()) => Ok(()),
        }
    }

    fn single_atv_case(t_outer: u8, t_rdn: u8, t_atv: u8, t_oid: u8, o: u8, v: u8) -> Result<(), NameError> {
        let input: [u8; 11] = [t_outer, 0x09, t_rdn, 0x07, t_atv, 0x05, t_oid, 0x01, o, v, 0x00];
        let r = validate_name(&input);
        assert!(
            r == expected_single(t_outer, t_rdn, t_atv, t_oid, o),
            "validate_name result differs from the total expected result"
        );
        r
    }

    /// (base): `30 09 31 07 A(o, v)`, 11 octets, symbolic `o` and `v` (low-tag). Expected:
    /// `validate_oid(&[o])` `Err(e)` -> `Err(BadAtvOid(e))`, else `Ok(())`.
    ///
    /// CONTRACT SURFACE / bounded-backing evidence. Backing `[u8; 11]`, `#[kani::unwind(3)]`, no
    /// stubs. Covers: `Ok`, `BadAtvOid(NonMinimalSubid)`, `BadAtvOid(Truncated)`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_single_atv_exact() {
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        kani::assume(v & 0x1F != 0x1F);
        let r = single_atv_case(0x30, 0x31, 0x30, 0x06, o, v);
        kani::cover(r == Ok(()), "single ATV: Ok");
        kani::cover(r == Err(NameError::BadAtvOid(OidError::NonMinimalSubid)), "single ATV: BadAtvOid(NonMinimalSubid)");
        kani::cover(r == Err(NameError::BadAtvOid(OidError::Truncated)), "single ATV: BadAtvOid(Truncated)");
    }

    /// Outer identifier: `t_outer` symbolic low-tag, `o` symbolic (no assumption: an invalid `o`
    /// is reported only after every identifier check passes). `0x30` -> `Ok`; `0x10` -> `BadOuterSeq(NotConstructed)`; else
    /// `BadOuterSeq(WrongTag)`. Same backing/unwind/stub statement as the base harness.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_outer_identifier() {
        let t: u8 = kani::any();
        kani::assume(t & 0x1F != 0x1F);
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        kani::assume(v & 0x1F != 0x1F);
        let r = single_atv_case(t, 0x31, 0x30, 0x06, o, v);
        kani::cover(t == 0x30 && r == Ok(()), "outer 0x30: Ok");
        kani::cover(r == Err(NameError::BadOuterSeq(SequenceError::NotConstructed)), "outer 0x10: NotConstructed");
        kani::cover(r == Err(NameError::BadOuterSeq(SequenceError::WrongTag)), "outer other: WrongTag");
    }

    /// RDN identifier: `0x31` -> `Ok`; `0x11` -> `BadRdn(NotConstructed)`; else
    /// `BadRdn(WrongTag)`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_rdn_identifier() {
        let t: u8 = kani::any();
        kani::assume(t & 0x1F != 0x1F);
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        kani::assume(v & 0x1F != 0x1F);
        let r = single_atv_case(0x30, t, 0x30, 0x06, o, v);
        kani::cover(t == 0x31 && r == Ok(()), "RDN 0x31: Ok");
        kani::cover(r == Err(NameError::BadRdn(SetOfError::NotConstructed)), "RDN 0x11: NotConstructed");
        kani::cover(r == Err(NameError::BadRdn(SetOfError::WrongTag)), "RDN other: WrongTag");
    }

    /// ATV identifier: `0x30` -> `Ok`; `0x10` -> `AtvNotConstructed`; else `AtvWrongTag`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_atv_identifier() {
        let t: u8 = kani::any();
        kani::assume(t & 0x1F != 0x1F);
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        kani::assume(v & 0x1F != 0x1F);
        let r = single_atv_case(0x30, 0x31, t, 0x06, o, v);
        kani::cover(t == 0x30 && r == Ok(()), "ATV 0x30: Ok");
        kani::cover(r == Err(NameError::AtvNotConstructed), "ATV 0x10: AtvNotConstructed");
        kani::cover(r == Err(NameError::AtvWrongTag), "ATV other: AtvWrongTag");
    }

    /// OID identifier: `0x06` -> `Ok`; `0x26` -> `AtvOidConstructed`; else
    /// `AtvOidWrongTag`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_oid_identifier() {
        let t: u8 = kani::any();
        kani::assume(t & 0x1F != 0x1F);
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        kani::assume(v & 0x1F != 0x1F);
        let r = single_atv_case(0x30, 0x31, 0x30, t, o, v);
        kani::cover(t == 0x06 && r == Ok(()), "OID 0x06: Ok");
        kani::cover(r == Err(NameError::AtvOidConstructed), "OID 0x26: AtvOidConstructed");
        kani::cover(r == Err(NameError::AtvOidWrongTag), "OID other: AtvOidWrongTag");
    }

    /// Two RDNs `30 12 R(A(o1, v1)) R(A(o2, v2))`, 20 octets (`R(A) = 31 07 A`).
    /// Expected: the first `validate_oid` failure in order -> `BadAtvOid(e)`, else `Ok(())`, with NO
    /// ordering constraint ACROSS RDNs (a "greater" first RDN is fine: SET OF ordering applies
    /// inside one RDN only). Backing `[u8; 20]`, `#[kani::unwind(3)]`, no stubs. Covers:
    /// `Ok`, `Ok` with the first RDN's `(o, v)` greater than the second's (no spurious cross-RDN
    /// ordering), `BadAtvOid`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_two_rdns_exact() {
        let o1: u8 = kani::any();
        let o2: u8 = kani::any();
        let v1: u8 = kani::any();
        let v2: u8 = kani::any();
        kani::assume(v1 & 0x1F != 0x1F);
        kani::assume(v2 & 0x1F != 0x1F);
        let input: [u8; 20] = [
            0x30, 0x12, 0x31, 0x07, 0x30, 0x05, 0x06, 0x01, o1, v1, 0x00, 0x31, 0x07, 0x30, 0x05, 0x06, 0x01, o2, v2,
            0x00,
        ];
        let r = validate_name(&input);
        let expected = match validate_oid(&[o1]) {
            Err(e) => Err(NameError::BadAtvOid(e)),
            Ok(()) => match validate_oid(&[o2]) {
                Err(e) => Err(NameError::BadAtvOid(e)),
                Ok(()) => Ok(()),
            },
        };
        assert!(r == expected, "validate_name result differs from the total expected result");
        kani::cover(r == Ok(()), "two RDNs: Ok");
        kani::cover(r == Ok(()) && (o1 > o2 || (o1 == o2 && v1 > v2)), "two RDNs: Ok with the first RDN greater (no cross-RDN ordering)");
        kani::cover(matches!(r, Err(NameError::BadAtvOid(_))), "two RDNs: BadAtvOid");
    }

    /// `30 02 31 00` -> `Err(EmptyRdn)`. Backing `[u8; 4]`, `#[kani::unwind(3)]`, concrete.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_empty_rdn() {
        let input: [u8; 4] = [0x30, 0x02, 0x31, 0x00];
        let r = validate_name(&input);
        assert!(r == Err(NameError::EmptyRdn));
        kani::cover(r == Err(NameError::EmptyRdn), "empty RDN: EmptyRdn");
    }

    /// `30 00` -> `Ok(())`: an empty RDNSequence is ACCEPTED (RFC-legal for
    /// issuer/subject-empty structures; recorded as the module's actual behaviour). Backing
    /// `[u8; 2]`, `#[kani::unwind(3)]`, concrete.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_empty_sequence_accepted() {
        let input: [u8; 2] = [0x30, 0x00];
        let r = validate_name(&input);
        assert!(r == Ok(()));
        kani::cover(r == Ok(()), "empty RDNSequence: Ok");
    }

    /// A 3-field ATV `30 0B 31 09 30 07 06 01 o v 00 w 00` (13 octets; symbolic `o`, `v`,
    /// `w` with `v`/`w` low-tag). Expected: `validate_oid(&[o])` `Err(e)` -> `BadAtvOid(e)` (the OID
    /// is checked before the value fields), else `AtvTrailingElements`. Backing `[u8; 13]`,
    /// `#[kani::unwind(3)]`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_atv_trailing_exact() {
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        let w: u8 = kani::any();
        kani::assume(v & 0x1F != 0x1F);
        kani::assume(w & 0x1F != 0x1F);
        let input: [u8; 13] = [0x30, 0x0b, 0x31, 0x09, 0x30, 0x07, 0x06, 0x01, o, v, 0x00, w, 0x00];
        let r = validate_name(&input);
        let expected = match validate_oid(&[o]) {
            Err(e) => Err(NameError::BadAtvOid(e)),
            Ok(()) => Err(NameError::AtvTrailingElements),
        };
        assert!(r == expected, "validate_name result differs from the total expected result");
        kani::cover(r == Err(NameError::AtvTrailingElements), "3-field ATV: AtvTrailingElements");
        kani::cover(matches!(r, Err(NameError::BadAtvOid(_))), "3-field ATV: BadAtvOid first");
    }

    /// A 1-field ATV `30 07 31 05 30 03 06 01 o` (9 octets; symbolic `o`). Expected:
    /// `validate_oid(&[o])` `Err(e)` -> `BadAtvOid(e)`, else `MissingAtvValue`. Backing `[u8; 9]`,
    /// `#[kani::unwind(3)]`.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_atv_missing_value_exact() {
        let o: u8 = kani::any();
        let input: [u8; 9] = [0x30, 0x07, 0x31, 0x05, 0x30, 0x03, 0x06, 0x01, o];
        let r = validate_name(&input);
        let expected = match validate_oid(&[o]) {
            Err(e) => Err(NameError::BadAtvOid(e)),
            Ok(()) => Err(NameError::MissingAtvValue),
        };
        assert!(r == expected, "validate_name result differs from the total expected result");
        kani::cover(r == Err(NameError::MissingAtvValue), "1-field ATV: MissingAtvValue");
        kani::cover(matches!(r, Err(NameError::BadAtvOid(_))), "1-field ATV: BadAtvOid first");
    }

    /// Two ATVs in ONE RDN, sorted: `30 11 31 0F A1 A2` (19 octets) with `A1 = 30 05 06 01 o1 v1 00`
    /// and `A2 = 30 06 06 01 o2 v2 01 x`. The encodings differ in length (`05 < 06` at the second
    /// octet), so the SET OF ordering compare decides at that octet. Symbolic `o1`, `o2`, `x`, and
    /// low-tag `v1`, `v2`. Expected: the first `validate_oid` failure in ATV order ->
    /// `BadAtvOid(e)`, else `Ok(())` -- the second ATV is validated too. CONTRACT SURFACE /
    /// bounded-backing evidence. Backing `[u8; 19]`, `#[kani::unwind(3)]`, no stubs. Covers: `Ok`,
    /// `BadAtvOid` from the first ATV, `BadAtvOid` from the second ATV only.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_two_atvs_exact() {
        let o1: u8 = kani::any();
        let o2: u8 = kani::any();
        let v1: u8 = kani::any();
        let v2: u8 = kani::any();
        let x: u8 = kani::any();
        kani::assume(v1 & 0x1F != 0x1F);
        kani::assume(v2 & 0x1F != 0x1F);
        let input: [u8; 19] = [
            0x30, 0x11, 0x31, 0x0F, 0x30, 0x05, 0x06, 0x01, o1, v1, 0x00, 0x30, 0x06, 0x06, 0x01, o2, v2, 0x01, x,
        ];
        let r = validate_name(&input);
        let expected = match validate_oid(&[o1]) {
            Err(e) => Err(NameError::BadAtvOid(e)),
            Ok(()) => match validate_oid(&[o2]) {
                Err(e) => Err(NameError::BadAtvOid(e)),
                Ok(()) => Ok(()),
            },
        };
        assert!(r == expected, "validate_name result differs from the total expected result");
        kani::cover(r == Ok(()), "two ATVs: Ok");
        kani::cover(matches!(r, Err(NameError::BadAtvOid(_))) && validate_oid(&[o1]).is_err(), "two ATVs: first ATV's OID fails");
        kani::cover(matches!(r, Err(NameError::BadAtvOid(_))) && validate_oid(&[o1]).is_ok(), "two ATVs: only the second ATV's OID fails");
    }

    /// The same two ATVs in descending order: `30 11 31 0F A2 A1`. The SET OF ordering check
    /// (`30 06 ..` before `30 05 ..`) runs before any ATV is validated, so the exact result is
    /// `Err(BadRdn(Unsorted { index: 0 }))` for EVERY symbolic content (all of `o1`, `v1`, `o2`,
    /// `v2`, `x` unconstrained). CONTRACT SURFACE / bounded-backing evidence. Backing `[u8; 19]`,
    /// `#[kani::unwind(3)]`, no stubs.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_two_atvs_unsorted() {
        let o1: u8 = kani::any();
        let o2: u8 = kani::any();
        let v1: u8 = kani::any();
        let v2: u8 = kani::any();
        let x: u8 = kani::any();
        let input: [u8; 19] = [
            0x30, 0x11, 0x31, 0x0F, 0x30, 0x06, 0x06, 0x01, o2, v2, 0x01, x, 0x30, 0x05, 0x06, 0x01, o1, v1, 0x00,
        ];
        let r = validate_name(&input);
        assert!(r == Err(NameError::BadRdn(SetOfError::Unsorted { index: 0 })));
        kani::cover(r == Err(NameError::BadRdn(SetOfError::Unsorted { index: 0 })), "two ATVs descending: Unsorted at index 0");
    }

    /// ATV value framing: `30 09 31 07 30 05 06 01 o v l` (11 octets) with `o`, `l` symbolic and
    /// `v` low-tag. Expected: `validate_oid(&[o])` `Err(e)` -> `BadAtvOid(e)` (the OID precedes the
    /// value), else `l == 0` -> `Ok(())`, else the value TLV `[v, l]` lacks its `l` content octets
    /// and the result is `BadAtvValueTlv(e)` with `e` the error of the verified primitive
    /// `decode_tlv` on `[v, l]`. CONTRACT SURFACE / bounded-backing evidence. Backing `[u8; 11]`,
    /// `#[kani::unwind(3)]`, no stubs.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_atv_value_length() {
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        let l: u8 = kani::any();
        kani::assume(v & 0x1F != 0x1F);
        let input: [u8; 11] = [0x30, 0x09, 0x31, 0x07, 0x30, 0x05, 0x06, 0x01, o, v, l];
        let r = validate_name(&input);
        let expected = match validate_oid(&[o]) {
            Err(e) => Err(NameError::BadAtvOid(e)),
            Ok(()) => {
                if l == 0 {
                    Ok(())
                } else {
                    Err(NameError::BadAtvValueTlv(decode_tlv(&[v, l]).unwrap_err()))
                }
            }
        };
        assert!(r == expected, "validate_name result differs from the total expected result");
        kani::cover(r == Ok(()), "ATV value length 0: Ok");
        kani::cover(matches!(r, Err(NameError::BadAtvValueTlv(_))), "ATV value length > 0: BadAtvValueTlv");
        kani::cover(matches!(r, Err(NameError::BadAtvOid(_))), "ATV value length: BadAtvOid first");
    }

    /// ATV `type` framing: `30 09 31 07 30 05 06 L o v 00` (11 octets) with the OID length octet `L`
    /// and `o`, `v` fully symbolic. The ATV content is `[06, L, o, v, 00]`; the expected result is
    /// derived from the verified primitives in the documented order: `decode_tlv` on the content
    /// `Err(e)` -> `BadAtvOidTlv(e)`; the OID content failing `validate_oid` -> `BadAtvOid(e)`;
    /// nothing left after the OID -> `MissingAtvValue`; `decode_tlv` on the rest `Err(e)` ->
    /// `BadAtvValueTlv(e)`; bytes left after that value -> `AtvTrailingElements`; else `Ok(())`.
    /// CONTRACT SURFACE / bounded-backing evidence. Backing `[u8; 11]`, `#[kani::unwind(3)]`, no
    /// stubs. The two values `L == 0x03` (a three-octet OID content walk) and `L == 0x83` (a
    /// three-octet long-form length) need a loop bound of 4, which about doubles the cost, so they
    /// are excluded; `L == 0x03` is the only value that reaches `MissingAtvValue` here (that outcome
    /// is pinned by `validate_name_atv_missing_value_exact`), and every other outcome class of
    /// `L == 0x83` is reached by other values.
    #[kani::proof]
    #[kani::unwind(3)]
    fn validate_name_atv_oid_length() {
        let l: u8 = kani::any();
        kani::assume(l != 0x03 && l != 0x83);
        let o: u8 = kani::any();
        let v: u8 = kani::any();
        let input: [u8; 11] = [0x30, 0x09, 0x31, 0x07, 0x30, 0x05, 0x06, l, o, v, 0x00];
        let r = validate_name(&input);
        let content: [u8; 5] = [0x06, l, o, v, 0x00];
        let expected = match decode_tlv(&content) {
            Err(e) => Err(NameError::BadAtvOidTlv(e)),
            Ok((oid, used)) => match validate_oid(oid.value) {
                Err(e) => Err(NameError::BadAtvOid(e)),
                Ok(()) => {
                    let rest = &content[used..];
                    if rest.is_empty() {
                        Err(NameError::MissingAtvValue)
                    } else {
                        match decode_tlv(rest) {
                            Err(e) => Err(NameError::BadAtvValueTlv(e)),
                            Ok((_, value_used)) => {
                                if value_used != rest.len() {
                                    Err(NameError::AtvTrailingElements)
                                } else {
                                    Ok(())
                                }
                            }
                        }
                    }
                }
            },
        };
        assert!(r == expected, "validate_name result differs from the total expected result");
        kani::cover(r == Ok(()), "ATV OID length: Ok");
        kani::cover(matches!(r, Err(NameError::BadAtvOidTlv(_))), "ATV OID length: BadAtvOidTlv");
        kani::cover(matches!(r, Err(NameError::BadAtvOid(_))), "ATV OID length: BadAtvOid");
        kani::cover(matches!(r, Err(NameError::BadAtvValueTlv(_))), "ATV OID length: BadAtvValueTlv");
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
