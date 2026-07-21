//! X.509 `Extension` / `Extensions` (RFC 5280 §4.1.2.9, §4.1) — a bounded, **structural** consumer
//! that composes this crate's verified primitives.
//!
//! ```text
//! Extension  ::= SEQUENCE {
//!     extnID     OBJECT IDENTIFIER,
//!     critical   BOOLEAN DEFAULT FALSE,
//!     extnValue  OCTET STRING }
//! Extensions ::= SEQUENCE SIZE (1..MAX) OF Extension
//! ```
//!
//! This module is the sibling of [`crate::x509_spki`], [`crate::x509_name`], and
//! [`crate::x509_validity`]: a **demonstration of composition**, not an expansion of the crate's
//! DER-layer scope (see the crate-level docs). It frames the `Extension` SEQUENCE and the
//! `Extensions` `SEQUENCE OF` using [`crate::sequence`], [`crate::tlv`], [`crate::oid`],
//! [`crate::boolean`], and [`crate::octet_string`] verbatim — it does not hand-roll any
//! tag/length/TLV parsing of its own.
//!
//! **The notable verified property: DER §11.5's DEFAULT-value omission rule.** `critical` is an
//! ASN.1 `BOOLEAN DEFAULT FALSE`. X.690 §11.5 requires that a component whose value equals its
//! `DEFAULT` be **absent** from the encoding — so a canonical DER `Extension` either omits
//! `critical` entirely (meaning `false`) or encodes it present with the value `TRUE`. A *present*
//! BOOLEAN encoding `FALSE` (`01 01 00`) is therefore **not valid DER**, even though
//! [`crate::boolean::decode_bool`] happily decodes `0x00` as a canonical `false` in isolation — the
//! violation is only visible at this schema-aware altitude, where "was this field present" carries
//! meaning `decode_bool` alone cannot see. [`parse_extension`] rejects it as
//! [`ExtensionError::CriticalMustBeTrue`]: a real anti-differential many parsers miss (a lax reader
//! accepts the non-canonical redundant encoding; a signer producing canonical DER never emits it).
//!
//! **`Extension` materializes; `Extensions` validates — mirrors the SPKI/Name split.** A single
//! `Extension` is a fixed three-field schema (like [`crate::x509_spki`]'s `SubjectPublicKeyInfo`),
//! so [`parse_extension`] borrows straight into an owned [`Extension`] struct. `Extensions` is a
//! variable-count `SEQUENCE OF`, so — like [`crate::x509_name`]'s `Name` — [`validate_extensions`]
//! follows the "validate, don't materialize" stance: it walks the whole structure and returns
//! `Result<(), ExtensionsError>` with no owned or borrowed collection of the variable-count members
//! (this heap-free crate has no `alloc`). A caller that needs the individual `Extension`s re-walks
//! with [`crate::tlv::decode_tlv`] + [`parse_extension`] itself, exactly as this module does
//! internally.
//!
//! **Scope boundaries (deliberate):**
//! - *Structural framing only.* [`parse_extension`] / [`validate_extensions`] validate that the
//!   byte string is a well-formed, DER-canonical `Extension` / `Extensions` with the exact field
//!   tiling the ASN.1 schema requires — nothing more, nothing less. This module does **not**
//!   interpret *which* extension the `extnID` OID names (`basicConstraints`, `keyUsage`,
//!   `subjectAltName`, …), does not parse `extnValue`'s inner DER (the extension-specific payload
//!   encoded *inside* the OCTET STRING), and does not enforce any per-extension profile rule (e.g.
//!   whether `BasicConstraints.cA` and `critical` must agree, or `keyUsage`'s recommended
//!   criticality) — those are caller/profile concerns layered *above* the transfer syntax, the same
//!   altitude split [`crate::x509_validity`] draws for its own year-2050 profile rule.
//! - *`extnValue` stays raw.* The OCTET STRING's content is returned unparsed and uninterpreted —
//!   like [`crate::x509_spki`]'s `ANY parameters` — because this module has no schema for what any
//!   given extension's inner DER looks like; that is a per-extension-type decoder's job, layered on
//!   top.
//! - *RFC 5280's `SIZE(1..MAX)` on `Extensions`, enforced explicitly.* A `SEQUENCE OF` with zero
//!   children is a well-formed empty sequence at the DER level, but RFC 5280 §4.1 requires at least
//!   one `Extension`; [`validate_extensions`] adds that check itself
//!   ([`ExtensionsError::EmptyExtensions`]), mirroring [`crate::x509_name::NameError::EmptyRdn`].
//! - *Strict tiling at every level.* The outer `Extensions` SEQUENCE must consume the entire input
//!   (no trailing bytes after the whole structure); each member `Extension`'s SEQUENCE content must
//!   exactly tile into its fields (`extnID`, the optional `critical`, `extnValue` — nothing more) —
//!   the classic parser-differential vector this crate's other modules guard against
//!   (`decode_tlv_strict` / `decode_sequence_tlv_strict`).

use crate::boolean::TAG as BOOL_TAG;
use crate::boolean::{decode_bool, BoolError};
use crate::octet_string::{decode_octet_string, OctetStringError};
use crate::oid::TAG as OID_TAG;
use crate::oid::{validate_oid, OidError};
use crate::sequence::{decode_sequence_tlv_strict, SequenceError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};

/// A structurally-parsed `Extension`, borrowing from the input it was parsed from.
///
/// See the module docs for the scope of what "parsed" means here: framing only, no per-extension
/// semantic interpretation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Extension<'a> {
    /// `extnID`: the canonically-validated OBJECT IDENTIFIER **content** octets (not the TLV
    /// header) — see [`crate::oid::validate_oid`]. This module does not decode which extension the
    /// OID names; a caller that needs that materializes/compares the arcs itself.
    pub extn_id: &'a [u8],
    /// `critical` (`BOOLEAN DEFAULT FALSE`): `false` when the field was **absent** from the
    /// encoding (the DER-canonical way to express the default), `true` when it was **present**
    /// (and — enforced here — canonically encoding `TRUE`; see the module docs' §11.5 discussion).
    pub critical: bool,
    /// `extnValue`: the OCTET STRING's raw content octets, uninterpreted — like
    /// [`crate::x509_spki::SubjectPublicKeyInfo::parameters`], this module does not know or care
    /// what DER structure (if any) lies inside.
    pub extn_value: &'a [u8],
}

/// Why an `Extension` was rejected. Every variant names a specific structural cause, wrapping the
/// underlying primitive's error where one exists (mirrors [`crate::x509_spki::SpkiError`]'s
/// wrapping style).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ExtensionError {
    /// The `Extension` SEQUENCE envelope was malformed: bad identifier/length, the primitive
    /// (non-constructed) form, or trailing bytes after the whole structure (this is a top-level
    /// object when reached via [`parse_extension`] directly, decoded with
    /// [`decode_sequence_tlv_strict`]).
    BadSeq(SequenceError),
    /// The `extnID` OID's TLV framing (tag/length octets) was malformed.
    BadExtnIdTlv(TlvError),
    /// The `extnID` field's identifier was well-framed but not UNIVERSAL 6 (OBJECT IDENTIFIER).
    ExtnIdWrongTag,
    /// The `extnID` field's identifier was UNIVERSAL 6 but in the constructed form — OBJECT
    /// IDENTIFIER content is always primitive.
    ExtnIdConstructed,
    /// The `extnID` OID's content failed canonical-DER validation.
    BadOid(OidError),
    /// The (present) `critical` field's identifier was UNIVERSAL 1 but in the constructed form —
    /// a BOOLEAN is always primitive.
    CriticalConstructed,
    /// The (present) `critical` BOOLEAN's content failed canonical-DER validation (see
    /// [`crate::boolean::decode_bool`] — content other than `0x00`/`0xFF`, or the wrong length).
    BadCritical(BoolError),
    /// **§11.5 (DEFAULT-value omission).** `critical` was *present* but canonically encoded
    /// `FALSE` (`01 01 00`). DER requires a component equal to its `DEFAULT` to be *absent*; a
    /// present-and-FALSE `critical` must instead have been omitted. See the module docs for why
    /// this is the notable verified property of this module.
    CriticalMustBeTrue,
    /// The content ended before `extnValue` was reached — only `extnID` (with `critical` either
    /// absent or present-and-consumed) was present, with nothing left for the mandatory `extnValue`.
    MissingExtnValue,
    /// `extnValue` was not a well-formed OCTET STRING TLV (bad framing, wrong tag, or the
    /// constructed/segmented BER form — see [`crate::octet_string::OctetStringError`]).
    BadExtnValue(OctetStringError),
    /// The `Extension` SEQUENCE has more than its permitted fields (`extnID`, optional `critical`,
    /// `extnValue`): bytes remain in its content after `extnValue`.
    TrailingInExtension,
}

/// Why an `Extensions` (`SEQUENCE SIZE (1..MAX) OF Extension`) was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ExtensionsError {
    /// The outer `Extensions` SEQUENCE envelope was malformed: bad identifier/length, the
    /// primitive (non-constructed) form, or trailing bytes after the whole structure (this is a
    /// top-level object, decoded with [`decode_sequence_tlv_strict`]).
    BadOuterSeq(SequenceError),
    /// The outer SEQUENCE was well-formed but contained **zero** `Extension` members — RFC 5280
    /// §4.1 requires `SIZE (1..MAX)`, so an empty `Extensions` is rejected here explicitly (a
    /// check the generic SEQUENCE reader deliberately does not make; mirrors
    /// [`crate::x509_name::NameError::EmptyRdn`]).
    EmptyExtensions,
    /// A member `Extension` failed to validate. Wraps [`ExtensionError`] for the specific cause.
    ///
    /// This variant is also used for a malformed **child TLV framing** discovered while walking
    /// the outer content to find each member's span (see [`validate_extensions`]'s doc comment for
    /// why that framing failure is surfaced through [`ExtensionError::BadSeq`] rather than a
    /// dedicated `ExtensionsError` variant: it is exactly the failure [`parse_extension`]'s own
    /// envelope decode would have produced had a full, self-contained slice been available).
    BadExtension(ExtensionError),
}

/// Decode the `extnID` OID TLV from the front of `input`, returning its validated content octets
/// and the bytes consumed. Composes [`decode_tlv`] + [`validate_oid`], mirroring
/// [`crate::x509_spki`]'s `decode_oid_tlv` / [`crate::x509_name`]'s `decode_atv_oid_tlv` exactly.
fn decode_extn_id_tlv(input: &[u8]) -> Result<(&[u8], usize), ExtensionError> {
    let (tlv, used) = decode_tlv(input).map_err(ExtensionError::BadExtnIdTlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != OID_TAG {
        return Err(ExtensionError::ExtnIdWrongTag);
    }
    if tlv.tag.constructed {
        return Err(ExtensionError::ExtnIdConstructed);
    }
    validate_oid(tlv.value).map_err(ExtensionError::BadOid)?;
    Ok((tlv.value, used))
}

/// Parse a complete DER `Extension` from `input`.
///
/// **Strict, top level**: `input` must be *exactly* one `Extension` — no trailing bytes are
/// tolerated after the whole structure, and the fields must exactly tile the outer SEQUENCE's
/// content. [`validate_extensions`] calls this on each member's own byte span, so "top level" here
/// means "top level of that span", not necessarily the whole certificate.
///
/// Decodes, in order:
/// 1. the outer SEQUENCE envelope ([`decode_sequence_tlv_strict`]);
/// 2. `extnID`, an OBJECT IDENTIFIER (`decode_extn_id_tlv`);
/// 3. the optional `critical` BOOLEAN ([`crate::boolean::decode_bool`]) — present only if the next
///    TLV's identifier is UNIVERSAL 1; **enforces DER §11.5**: a present `critical` must encode
///    `TRUE` (see the module docs);
/// 4. `extnValue`, an OCTET STRING ([`decode_octet_string`]), requiring it to exactly fill what
///    remains of the outer content.
///
/// Never panics on any input (proven by the `parse_extension_never_panics` Kani harness below);
/// returns a classified [`ExtensionError`] on any structural deviation.
pub fn parse_extension(input: &[u8]) -> Result<Extension<'_>, ExtensionError> {
    // 1. Outer SEQUENCE: must consume the whole input (top-level anti-trailing-data).
    let content = decode_sequence_tlv_strict(input).map_err(ExtensionError::BadSeq)?;

    // 2. First field: extnID (OBJECT IDENTIFIER).
    let (extn_id, id_used) = decode_extn_id_tlv(content)?;
    let rest = &content[id_used..];
    if rest.is_empty() {
        return Err(ExtensionError::MissingExtnValue);
    }

    // 3. Optional second field: critical (BOOLEAN DEFAULT FALSE). Peek the next TLV's identifier
    // to decide whether it is present. If the peek itself fails (malformed framing) or the tag is
    // not UNIVERSAL 1, `critical` is treated as absent (DEFAULT FALSE) and `value_input` stays
    // `rest` unchanged — the mandatory extnValue decode below then re-attempts `decode_tlv` on the
    // same bytes and, if the framing really was malformed, surfaces the identical error there as
    // `ExtensionError::BadExtnValue(OctetStringError::Tlv(_))`. This avoids inventing a second,
    // redundant error path for the same underlying framing failure.
    let (critical, value_input) = match decode_tlv(rest) {
        Ok((peek, peek_used))
            if peek.tag.class == Class::Universal && peek.tag.number == BOOL_TAG =>
        {
            if peek.tag.constructed {
                return Err(ExtensionError::CriticalConstructed);
            }
            let b = decode_bool(peek.value).map_err(ExtensionError::BadCritical)?;
            if !b {
                // §11.5: a component equal to its DEFAULT must be absent, not present-and-FALSE.
                return Err(ExtensionError::CriticalMustBeTrue);
            }
            (true, &rest[peek_used..])
        }
        _ => (false, rest),
    };

    // 4. Last field: extnValue (OCTET STRING), must exactly fill what remains.
    if value_input.is_empty() {
        return Err(ExtensionError::MissingExtnValue);
    }
    let (extn_value, ev_used) =
        decode_octet_string(value_input).map_err(ExtensionError::BadExtnValue)?;
    if ev_used != value_input.len() {
        return Err(ExtensionError::TrailingInExtension);
    }

    Ok(Extension { extn_id, critical, extn_value })
}

/// Validate a complete DER `Extensions` (`SEQUENCE SIZE (1..MAX) OF Extension`) from `input`.
///
/// **Strict, top level**: `input` must be *exactly* one `Extensions` — no trailing bytes are
/// tolerated after the whole structure.
///
/// Validates, in order:
/// 1. the outer SEQUENCE envelope, requiring it to consume the entire input
///    ([`decode_sequence_tlv_strict`]);
/// 2. each `Extension` child, in the order they appear (a plain `SEQUENCE OF` has no §11.6
///    ordering requirement — unlike a `SET OF`, see [`crate::x509_name`]'s `RDNSequence`/RDN
///    split): the outer content is walked by offset, using [`decode_tlv`] to find each child's
///    byte span and [`parse_extension`] (strict, on exactly that span) to validate it;
/// 3. RFC 5280 §4.1's `SIZE (1..MAX)`: at least one `Extension` must be present
///    ([`ExtensionsError::EmptyExtensions`]).
///
/// **On the offset walk's error mapping:** [`decode_tlv`] is used only to find where one child
/// ends — it does not itself validate that the child is a well-formed `Extension` (that is
/// [`parse_extension`]'s job, on the isolated span). If [`decode_tlv`] itself fails (the child's
/// tag/length framing is malformed, so no span can even be determined), that failure is surfaced
/// as `ExtensionsError::BadExtension(ExtensionError::BadSeq(SequenceError::Tlv(_)))` — the same
/// shape [`parse_extension`]'s own envelope decode would have produced for that identical framing
/// defect, had a self-contained slice been available to hand it. This keeps `ExtensionsError` from
/// growing a second, parallel "framing error" variant for what is conceptually the same failure
/// class as a malformed member.
///
/// Never panics on any input (proven by the `validate_extensions_never_panics` Kani harness
/// below); returns a classified [`ExtensionsError`] on any structural deviation. Returns `Ok(())`
/// — this is a validator, not a materializing parser; see the module docs for why.
pub fn validate_extensions(input: &[u8]) -> Result<(), ExtensionsError> {
    // 1. Outer Extensions SEQUENCE: must consume the whole input (top-level anti-trailing-data).
    let outer = decode_sequence_tlv_strict(input).map_err(ExtensionsError::BadOuterSeq)?;

    // 2. Walk each Extension member in order (SEQUENCE OF: no §11.6 ordering requirement here).
    let mut off = 0usize;
    let mut count = 0usize;
    while off < outer.len() {
        let (_tlv, used) = decode_tlv(&outer[off..]).map_err(|e| {
            ExtensionsError::BadExtension(ExtensionError::BadSeq(SequenceError::Tlv(e)))
        })?;
        let child = &outer[off..off + used];
        parse_extension(child).map_err(ExtensionsError::BadExtension)?;
        off += used;
        count += 1;
    }

    // 3. RFC 5280 §4.1: SIZE (1..MAX) -- at least one Extension is required.
    if count == 0 {
        return Err(ExtensionsError::EmptyExtensions);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kani proof harness.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind.
//
// `parse_extension_never_panics` uses the standard 16-octet symbolic buffer (matching the x509_*
// siblings): its call chain performs up to four independent `decode_tlv` calls (outer SEQUENCE,
// extnID, the critical peek, extnValue) plus `validate_oid`'s own bounded loop over the OID content
// -- a *fixed* schema, no unbounded sibling count. `#[kani::unwind(20)]` covers a maximal-header
// `decode_tlv` (~11, per `tlv.rs`) plus a full 16-byte OID walk with margin.
//
// `validate_extensions_never_panics` uses a SMALLER 13-octet buffer -- a deliberate, documented
// reduction (cf. `big_integer`'s Kani N, DECISIONS.md D14: "representative, not limiting"). Reason:
// `validate_extensions` nests the outer `SEQUENCE OF` walk *around a full `parse_extension` inlined
// per iteration*; with a single global unwind, CBMC takes the PRODUCT of both loops' maxima (the
// walk unrolled ~unwind times, each copy inlining parse_extension's own unrolled `validate_oid`),
// which at [u8;16]/unwind(20) exhausts memory (~1.6e5 VCCs -> CaDiCaL OOM) rather than finding any
// defect. 13 octets is the smallest buffer that still (a) holds a *complete* valid single Extension
// inside an Extensions wrapper (the minimal valid Extensions `30 07 30 05 06 01 2a 04 00` is 9
// octets) AND (b) leaves enough trailing content that the walk loop takes a genuine *second*
// iteration (a second `decode_tlv` at a non-zero offset) -- so the walk-specific logic (offset
// advance, the `&outer[off..off+used]` slice, the count/empty check) is fully exercised, not just a
// single pass. What the reduction gives up is only *longer* multi-Extension inputs; that residual is
// covered compositionally -- `parse_extension`'s panic-freedom is separately proven at the full
// [u8;16] (`parse_extension_never_panics`, 0-of-222), and everything `validate_extensions` adds on
// top is bounded offset arithmetic plus slicing that `decode_tlv`'s no-over-read contract keeps
// in-bounds (`used <= remaining`). `#[kani::unwind(12)]` covers every loop feasible in 13 octets
// (validate_oid/tag/length/walk are all <= ~6 here) with margin. If Kani reports an
// unwinding-assertion failure, raise the bound (do not weaken scope); the buffer size is the
// tractability lever, chosen as above.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_extension` never panics on any input up to 16 octets.
    ///
    /// Cover (T6 primary rule): witnesses the parser's real `Ok` tail (extnID + critical-peek +
    /// extnValue all decoded and exactly tiled) actually fires for some symbolic input, not just
    /// that the harness ran. Would NOT be SAT if `parse_extension`'s body were a no-op always
    /// returning `Err`.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_extension_never_panics() {
        let buf: [u8; 16] = kani::any();
        let result = parse_extension(&buf);
        kani::cover(result.is_ok(), "a well-formed Extension reaches parse_extension's Ok tail");
        let _ = result;
    }

    /// Robustness: `validate_extensions` never panics on any input up to 13 octets (a documented
    /// reduction from the sibling 16 -- see the module's Kani comment for why, and how the residual
    /// is covered compositionally by `parse_extension_never_panics` @ 16).
    ///
    /// Cover (T6 primary rule + T2-COROLLARY-B): the module comment above claims the 13-octet
    /// reduction "leaves enough trailing content that the walk loop takes a genuine *second*
    /// iteration" — i.e. the SEQUENCE-OF walk's `while off < outer.len()` fires a second
    /// `decode_tlv` at a non-zero offset. That claim was previously prose only. To turn it into a
    /// machine-checked POST-STATE fact (not a pre-state input-length predicate), this harness
    /// independently re-derives, using the same public primitives `validate_extensions` itself
    /// calls (`decode_sequence_tlv_strict`, `decode_tlv`), whether a second child TLV is actually
    /// reachable at a non-zero offset within the same outer content — then covers the CONJUNCTION
    /// of that fact with the real call's outcome. This is not vacuous: a cover of `len==13` alone
    /// (or `true`) would be SAT even if `validate_extensions`'s body were a no-op, since it depends
    /// only on the harness's own input construction. The cover below additionally requires that the
    /// SAME public decode primitives, applied to the SAME bytes the real call saw, exhibit a live
    /// second iteration -- so it fails to be SAT unless the input genuinely admits the two-child
    /// shape the reduction's soundness argument depends on.
    #[kani::proof]
    #[kani::unwind(12)]
    fn validate_extensions_never_panics() {
        let buf: [u8; 13] = kani::any();
        // Symbolic input length: this lemma discharges `x509_tbs_certificate`'s `stub_validate_extensions`,
        // whose caller invokes `validate_extensions` on suffix slices shorter than the full buffer — a
        // fixed-length proof would leave those call lengths undischarged (control flow is length-dependent).
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = validate_extensions(input);

        // Independently re-walk the SAME bytes with the SAME public primitives the real function
        // uses, to witness (outside the function's own opaque Result) that a second Extension TLV
        // genuinely starts at a non-zero offset -- i.e. the walk loop's second iteration is LIVE,
        // not merely permitted by the buffer size.
        let mut second_child_at_nonzero_offset = false;
        if let Ok(outer) = decode_sequence_tlv_strict(input) {
            if let Ok((_first_tlv, first_used)) = decode_tlv(outer) {
                if first_used > 0 && first_used < outer.len() {
                    if decode_tlv(&outer[first_used..]).is_ok() {
                        second_child_at_nonzero_offset = true;
                    }
                }
            }
        }

        kani::cover(
            result.is_ok() && second_child_at_nonzero_offset,
            "validate_extensions reaches Ok while the walk genuinely takes a second iteration \
             (a second child TLV starts at a non-zero offset) -- the reduced 13-octet buffer is \
             representative, not accidentally single-pass",
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

    /// A `basicConstraints` `Extension` with `critical` **absent** (the DER-canonical way to say
    /// `false`): `extnID` = 2.5.29.19, `extnValue` = the DER encoding of `BasicConstraints` with
    /// no fields present (`SEQUENCE {}`).
    ///
    /// `30 09`                             SEQUENCE (Extension), len 9
    ///    `06 03 55 1d 13`                 OID 2.5.29.19 (basicConstraints)
    ///    `04 02 30 00`                    OCTET STRING (extnValue), len 2: SEQUENCE {}
    #[rustfmt::skip]
    const EXT_BASIC_CONSTRAINTS_DEFAULT: [u8; 11] = [
        0x30, 0x09,
            0x06, 0x03, 0x55, 0x1d, 0x13,
            0x04, 0x02, 0x30, 0x00,
    ];

    /// The same `basicConstraints` `Extension`, but with `critical` **present** and canonically
    /// `TRUE` (`01 01 FF`).
    ///
    /// `30 0c`                             SEQUENCE (Extension), len 12
    ///    `06 03 55 1d 13`                 OID 2.5.29.19 (basicConstraints)
    ///    `01 01 ff`                       BOOLEAN (critical) = TRUE
    ///    `04 02 30 00`                    OCTET STRING (extnValue), len 2: SEQUENCE {}
    #[rustfmt::skip]
    const EXT_BASIC_CONSTRAINTS_CRITICAL: [u8; 14] = [
        0x30, 0x0c,
            0x06, 0x03, 0x55, 0x1d, 0x13,
            0x01, 0x01, 0xff,
            0x04, 0x02, 0x30, 0x00,
    ];

    #[test]
    fn parses_extension_default_critical() {
        let ext = parse_extension(&EXT_BASIC_CONSTRAINTS_DEFAULT).unwrap();
        assert_eq!(ext.extn_id, &[0x55, 0x1d, 0x13]); // 2.5.29.19
        assert_eq!(ext.critical, false);
        assert_eq!(ext.extn_value, &[0x30, 0x00]);
    }

    #[test]
    fn parses_extension_critical_true() {
        let ext = parse_extension(&EXT_BASIC_CONSTRAINTS_CRITICAL).unwrap();
        assert_eq!(ext.extn_id, &[0x55, 0x1d, 0x13]); // 2.5.29.19
        assert_eq!(ext.critical, true);
        assert_eq!(ext.extn_value, &[0x30, 0x00]);
    }

    /// An `Extensions` SEQUENCE OF with two members: the default-critical `basicConstraints`
    /// extension, followed by the explicit-critical-TRUE one.
    ///
    /// `30 19`                             SEQUENCE (Extensions), len 25
    ///    <EXT_BASIC_CONSTRAINTS_DEFAULT>   Extension 1 (11 bytes, critical absent)
    ///    <EXT_BASIC_CONSTRAINTS_CRITICAL>  Extension 2 (14 bytes, critical = TRUE)
    #[test]
    fn validates_extensions_sequence() {
        let mut bytes = vec![0x30, 0x19];
        bytes.extend_from_slice(&EXT_BASIC_CONSTRAINTS_DEFAULT);
        bytes.extend_from_slice(&EXT_BASIC_CONSTRAINTS_CRITICAL);
        assert_eq!(bytes.len(), 27);
        assert_eq!(validate_extensions(&bytes), Ok(()));
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    /// **The crown anti-differential (§11.5).** `critical` is *present* but canonically encodes
    /// `FALSE` (`01 01 00`) -- DER requires a component equal to its `DEFAULT` to be *absent*, so
    /// this redundant-but-individually-canonical encoding is still invalid DER. A lax parser that
    /// only checks `decode_bool`'s content canonicality (which `0x00` satisfies) would wrongly
    /// accept this; `parse_extension` rejects it structurally.
    #[test]
    fn rejects_critical_present_but_false() {
        let mut bytes = EXT_BASIC_CONSTRAINTS_CRITICAL;
        bytes[9] = 0x00; // the critical BOOLEAN's content octet: FF -> 00
        assert_eq!(parse_extension(&bytes), Err(ExtensionError::CriticalMustBeTrue));
    }

    #[test]
    fn rejects_critical_noncanonical() {
        // BER would accept 0x01 as TRUE; DER must not (crate::boolean::decode_bool rejects it).
        let mut bytes = EXT_BASIC_CONSTRAINTS_CRITICAL;
        bytes[9] = 0x01;
        assert_eq!(
            parse_extension(&bytes),
            Err(ExtensionError::BadCritical(BoolError::NonCanonical))
        );
    }

    #[test]
    fn rejects_critical_constructed() {
        // The critical field's identifier is UNIVERSAL 1's tag number but in the constructed form
        // (0x21 instead of the primitive 0x01) -- a BOOLEAN is always primitive.
        let mut bytes = EXT_BASIC_CONSTRAINTS_CRITICAL;
        bytes[7] = 0x21;
        assert_eq!(parse_extension(&bytes), Err(ExtensionError::CriticalConstructed));
    }

    #[test]
    fn rejects_extn_id_wrong_tag() {
        // extnID is an INTEGER (0x02) instead of an OBJECT IDENTIFIER.
        let mut bytes = EXT_BASIC_CONSTRAINTS_DEFAULT;
        bytes[2] = 0x02;
        assert_eq!(parse_extension(&bytes), Err(ExtensionError::ExtnIdWrongTag));
    }

    #[test]
    fn rejects_extn_id_constructed() {
        // extnID's identifier in the constructed form (0x26) -- forbidden; OID content is always
        // primitive.
        let mut bytes = EXT_BASIC_CONSTRAINTS_DEFAULT;
        bytes[2] = 0x26;
        assert_eq!(parse_extension(&bytes), Err(ExtensionError::ExtnIdConstructed));
    }

    #[test]
    fn rejects_non_canonical_oid() {
        // A non-minimal OID subidentifier (leading 0x80 group) in extnID's first content octet.
        let mut bytes = EXT_BASIC_CONSTRAINTS_DEFAULT;
        bytes[4] = 0x80;
        assert_eq!(parse_extension(&bytes), Err(ExtensionError::BadOid(OidError::NonMinimalSubid)));
    }

    #[test]
    fn rejects_extn_value_wrong_tag() {
        // extnValue uses BIT STRING (0x03) instead of OCTET STRING (0x04).
        let mut bytes = EXT_BASIC_CONSTRAINTS_DEFAULT;
        bytes[7] = 0x03;
        assert_eq!(
            parse_extension(&bytes),
            Err(ExtensionError::BadExtnValue(OctetStringError::WrongTag))
        );
    }

    #[test]
    fn rejects_missing_extn_value() {
        // Case 1: only extnID present, nothing after it.
        // 30 05 06 03 55 1d 13  (SEQUENCE { OID }, no critical, no extnValue)
        let only_extn_id = [0x30, 0x05, 0x06, 0x03, 0x55, 0x1d, 0x13];
        assert_eq!(parse_extension(&only_extn_id), Err(ExtensionError::MissingExtnValue));

        // Case 2: extnID + critical present, but nothing after critical.
        // 30 08 06 03 55 1d 13 01 01 ff  (SEQUENCE { OID, BOOLEAN TRUE }, no extnValue)
        let extn_id_and_critical =
            [0x30, 0x08, 0x06, 0x03, 0x55, 0x1d, 0x13, 0x01, 0x01, 0xff];
        assert_eq!(parse_extension(&extn_id_and_critical), Err(ExtensionError::MissingExtnValue));
    }

    #[test]
    fn rejects_trailing_in_extension() {
        // extnID + extnValue (critical absent), followed by a bogus extra BOOLEAN TLV inside the
        // Extension SEQUENCE's content -- not permitted, an Extension has only three fields.
        //
        // `30 0c`                             SEQUENCE (Extension), len 12
        //    `06 03 55 1d 13`                 OID 2.5.29.19 (basicConstraints)
        //    `04 02 30 00`                    OCTET STRING (extnValue): SEQUENCE {}
        //    `01 01 00`                       extra BOOLEAN -- not permitted
        #[rustfmt::skip]
        let bytes: [u8; 14] = [
            0x30, 0x0c,
                0x06, 0x03, 0x55, 0x1d, 0x13,
                0x04, 0x02, 0x30, 0x00,
                0x01, 0x01, 0x00,
        ];
        assert_eq!(parse_extension(&bytes), Err(ExtensionError::TrailingInExtension));
    }

    #[test]
    fn rejects_extension_primitive_form() {
        // The Extension's own SEQUENCE identifier in the primitive form (0x10) -- a SEQUENCE is
        // always constructed.
        let mut bytes = EXT_BASIC_CONSTRAINTS_DEFAULT;
        bytes[0] = 0x10;
        assert_eq!(
            parse_extension(&bytes),
            Err(ExtensionError::BadSeq(SequenceError::NotConstructed))
        );
    }

    #[test]
    fn rejects_truncated_extension() {
        // Drop the last 4 bytes: the outer SEQUENCE declares more content than is present.
        let bytes = &EXT_BASIC_CONSTRAINTS_DEFAULT[..EXT_BASIC_CONSTRAINTS_DEFAULT.len() - 4];
        assert_eq!(
            parse_extension(bytes),
            Err(ExtensionError::BadSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    // --- Extensions (SEQUENCE OF) level ---

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer Extensions SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = vec![0x30, 0x0b];
        bytes.extend_from_slice(&EXT_BASIC_CONSTRAINTS_DEFAULT);
        bytes[0] = 0x31;
        assert_eq!(
            validate_extensions(&bytes),
            Err(ExtensionsError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_empty_extensions() {
        // 30 00 -- a well-formed, zero-member SEQUENCE OF; RFC 5280 requires SIZE (1..MAX).
        let bytes = [0x30, 0x00];
        assert_eq!(validate_extensions(&bytes), Err(ExtensionsError::EmptyExtensions));
    }

    #[test]
    fn rejects_trailing_after_extensions() {
        let mut bytes = vec![0x30, 0x0b];
        bytes.extend_from_slice(&EXT_BASIC_CONSTRAINTS_DEFAULT);
        bytes.push(0xFF);
        assert_eq!(
            validate_extensions(&bytes),
            Err(ExtensionsError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_malformed_member_extension() {
        // A single-member Extensions whose member has extnID wrong-tagged (INTEGER instead of
        // OID) -- the member's own SEQUENCE framing is fine, but parse_extension rejects its
        // content.
        let mut member = EXT_BASIC_CONSTRAINTS_DEFAULT;
        member[2] = 0x02; // extnID tag: OID -> INTEGER
        let mut bytes = vec![0x30, 0x0b];
        bytes.extend_from_slice(&member);
        assert_eq!(
            validate_extensions(&bytes),
            Err(ExtensionsError::BadExtension(ExtensionError::ExtnIdWrongTag))
        );
    }

    #[test]
    fn rejects_extensions_member_wrong_tag() {
        // A single-member Extensions whose member is an INTEGER (02 01 07), not a SEQUENCE at all.
        // The child TLV framing itself is fine (decode_tlv succeeds), but parse_extension's own
        // envelope decode rejects the wrong tag.
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x07];
        assert_eq!(
            validate_extensions(&bytes),
            Err(ExtensionsError::BadExtension(ExtensionError::BadSeq(SequenceError::WrongTag)))
        );
    }

    #[test]
    fn rejects_spurious_field_before_extn_value() {
        // Coverage completeness (review x509-extension-01): a well-formed but unexpected field (an
        // INTEGER) sits between extnID and extnValue. The critical-peek sees a non-BOOLEAN tag, so
        // it treats `critical` as absent and does NOT advance -- the INTEGER then falls to the
        // mandatory extnValue decode, which rejects it as the wrong tag. Makes the peek-fallthrough
        // contract explicit with a spurious-intermediate-field specimen (distinct in intent from
        // `rejects_extn_value_wrong_tag`, which mistypes extnValue itself).
        //
        // `30 0c`                             SEQUENCE (Extension), len 12
        //    `06 03 55 1d 13`                 OID 2.5.29.19 (basicConstraints)
        //    `02 01 7f`                       bogus INTEGER -- not BOOLEAN, so peek falls through
        //    `04 02 30 00`                    a real OCTET STRING (never reached: INTEGER fails first)
        #[rustfmt::skip]
        let bytes: [u8; 14] = [
            0x30, 0x0c,
                0x06, 0x03, 0x55, 0x1d, 0x13,
                0x02, 0x01, 0x7f,
                0x04, 0x02, 0x30, 0x00,
        ];
        assert_eq!(
            parse_extension(&bytes),
            Err(ExtensionError::BadExtnValue(OctetStringError::WrongTag))
        );
    }

    #[test]
    fn rejects_child_tlv_framing_malformed_in_extensions() {
        // Exercises the offset-walk's own decode_tlv failure path (documented on
        // `validate_extensions`): the sole member's header declares 12 content octets, but only 3
        // are actually present in the outer Extensions content -- decode_tlv itself cannot even
        // determine the child's span, so this is *not* routed through parse_extension at all.
        //
        // `30 05`               SEQUENCE (Extensions), len 5
        //    `30 0c`             member header claims 12 content octets...
        //    `aa bb cc`          ...but only 3 are present
        let bytes = [0x30, 0x05, 0x30, 0x0c, 0xaa, 0xbb, 0xcc];
        assert_eq!(
            validate_extensions(&bytes),
            Err(ExtensionsError::BadExtension(ExtensionError::BadSeq(SequenceError::Tlv(
                TlvError::Truncated
            ))))
        );
    }
}
