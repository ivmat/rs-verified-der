//! DER SEQUENCE / constructed-content reader (X.690 §8.9, §8.10).
//!
//! A SEQUENCE is UNIVERSAL tag 16 in the **constructed** form (identifier octet `0x30`); a SET is
//! UNIVERSAL 17 (`0x31`). Their content is the concatenation of the encodings of the component
//! TLVs (§8.9.1, §8.10.1). This module validates and iterates the *immediate* children of a
//! content slice by composing [`crate::tlv::decode_tlv`].
//!
//! **Shallow only.** It does not recurse into nested constructed children — a caller that needs a
//! deep walk decodes each yielded child and re-enters. Keeping the walk to a single bounded loop
//! (no recursion) is what makes the Kani proofs tractable. Termination is by the bound: every DER
//! TLV header is at least two octets (one identifier + one length), so each child consumes
//! `used >= 2` and the child count is at most `content.len() / 2` (see the `#[kani::unwind]`
//! annotations below).
//!
//! Because the SEQUENCE/SET constraint (constructed UNIVERSAL 16/17) lives in the identifier
//! octet, [`decode_sequence_tlv`] operates at the TLV level (like [`crate::octet_string`]); the
//! content-only entry points ([`decode_sequence`], [`Elements`]) take pre-stripped content octets.
//!
//! **Scope — TLV framing, not content canonicality.** [`decode_sequence`] / [`Elements`] validate
//! that the content is a concatenation of well-formed child TLVs whose *framing* (identifier +
//! length) is DER-canonical — non-minimal length, high-tag form, and the indefinite length are all
//! rejected (inherited and proven by [`crate::tag`]/[`crate::length`]). They do **not** check each
//! child's *content* canonicality (a canonical BOOLEAN, a minimal INTEGER, …); apply the typed
//! decoders ([`crate::boolean`], [`crate::integer`], …) per child for that. (`DECISIONS.md` D5.)
//!
//! **SET is recognized, not decoded.** [`SET_TAG`] exists for tag checks, but this module does not
//! decode SET or enforce §11.6 member ordering; [`decode_sequence_tlv`] rejects a SET identifier as
//! [`SequenceError::WrongTag`]. A future `decode_set` is the home for the ordering proof.
//! (`DECISIONS.md` D6.)
//!
//! The security-critical property, proven over all inputs, is **no over-read**: an accepted
//! SEQUENCE never yields a child value beyond the content slice, and the walk never advances past
//! `content.len()`. DER's definite-length requirement is inherited from the length codec (the BER
//! indefinite form `0x80` is already rejected there, so a `0x30 0x80 …` SEQUENCE cannot decode).

use crate::tag::{Class, Tag};
use crate::tlv::{decode_tlv, encode_tlv_into, Tlv, TlvError};

/// The universal tag number for SEQUENCE.
pub const TAG: u32 = 16;

/// The universal tag number for SET. Provided for tag checks; this module does **not** implement
/// SET-of DER ordering canonicality (§11.6) — it only recognizes the SET identifier.
pub const SET_TAG: u32 = 17;

/// Why a SEQUENCE was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SequenceError {
    /// A child element failed to decode (bad TLV: over-read, bad identifier/length, …).
    Element(TlvError),
    /// The identifier is UNIVERSAL 16 but in the *primitive* form (`0x10`) — a SEQUENCE is always
    /// constructed (§8.9.1), so the primitive form is malformed.
    NotConstructed,
    /// The identifier is a well-formed TLV but is not UNIVERSAL 16 (e.g. a SET `0x31`, or any
    /// other type). Checked before over-read/element validity of the content.
    WrongTag,
    /// The envelope TLV itself was malformed (bad identifier/length, indefinite length, …) — as
    /// distinct from a well-formed envelope whose *content* has a bad child ([`Self::Element`]).
    Tlv(TlvError),
    /// Strict decode only: bytes remain after a complete SEQUENCE (see [`decode_sequence_tlv_strict`]).
    TrailingData,
}

/// A lazy, allocation-free iterator over the immediate child TLVs of a SEQUENCE/SET *content*
/// slice (the octets between the length and the end of the object — not the whole TLV).
///
/// Each `next()` decodes one child from the front of the remaining content with
/// [`decode_tlv`], advances by the bytes it consumed, and yields the child. Iteration stops when
/// the content is exhausted. On the **first** malformed child it yields that `Err` exactly once
/// and then stops (fused): the borrow returned by [`decode_tlv`] guarantees every yielded child
/// value lies within the original content (no over-read).
#[derive(Debug, Clone)]
pub struct Elements<'a> {
    rest: &'a [u8],
    done: bool,
}

impl<'a> Elements<'a> {
    /// Iterate the immediate children of a SEQUENCE/SET `content` slice.
    pub fn new(content: &'a [u8]) -> Self {
        Elements { rest: content, done: false }
    }
}

impl<'a> Iterator for Elements<'a> {
    type Item = Result<Tlv<'a>, TlvError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done || self.rest.is_empty() {
            return None;
        }
        match decode_tlv(self.rest) {
            Ok((tlv, used)) => {
                // `used` is always in `1..=self.rest.len()` for an accepted TLV (proven in `tlv`),
                // so this slice is in bounds and strictly shrinks `rest` (each header is >= 2).
                self.rest = &self.rest[used..];
                Some(Ok(tlv))
            }
            Err(e) => {
                self.done = true; // fuse: yield the error once, then stop
                Some(Err(e))
            }
        }
    }
}

/// Validate that `content` is **exactly** a concatenation of well-formed child TLVs — every child
/// decodes and nothing is left over — and return the child count.
///
/// This is the well-formed-SEQUENCE / no-over-read gate for the content octets. It validates TLV
/// **framing** only (identifier + length canonicality, inherited) — NOT each child's *content*
/// canonicality; apply the typed decoders per child for that (module scope note; `DECISIONS.md` D5).
/// It walks the
/// children with [`Elements`]; a malformed child is reported as [`SequenceError::Element`]. Because
/// [`Elements`] can only stop on an empty `rest` or an error, a clean run has consumed the whole
/// slice, so no explicit trailing-bytes check is needed. Allocation-free: it only counts.
pub fn decode_sequence(content: &[u8]) -> Result<usize, SequenceError> {
    let mut count = 0usize;
    for child in Elements::new(content) {
        match child {
            Ok(_) => count += 1,
            Err(e) => return Err(SequenceError::Element(e)),
        }
    }
    Ok(count)
}

/// Decode a complete DER SEQUENCE from the front of `input`, returning the SEQUENCE **content**
/// octets and the total number of bytes consumed (`tag + length + value`).
///
/// Requires the identifier to be UNIVERSAL 16 in the constructed form. Mirroring
/// [`crate::octet_string::decode_octet_string`], tag-identity is checked before the
/// primitive/constructed flag, so:
/// - a non-SEQUENCE tag (e.g. SET `0x31`, or an INTEGER `0x02`) is [`SequenceError::WrongTag`];
/// - the *primitive* form of UNIVERSAL 16 (`0x10`) is [`SequenceError::NotConstructed`].
///
/// The content octets are returned unvalidated (use [`decode_sequence`] / [`Elements`] to walk the
/// children). Trailing bytes after the SEQUENCE are ignored (as in [`decode_tlv`]) so this composes
/// inside larger structures; a top-level caller should check the returned length against
/// `input.len()`.
pub fn decode_sequence_tlv(input: &[u8]) -> Result<(&[u8], usize), SequenceError> {
    let (tlv, used) = decode_tlv(input).map_err(SequenceError::Tlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != TAG {
        return Err(SequenceError::WrongTag);
    }
    if !tlv.tag.constructed {
        return Err(SequenceError::NotConstructed);
    }
    Ok((tlv.value, used))
}

/// Decode a complete DER SEQUENCE, requiring it to consume the *entire* `input` (no trailing bytes).
///
/// Use this at the **top level** (e.g. a whole certificate is one SEQUENCE): [`decode_sequence_tlv`]
/// deliberately ignores trailing bytes so it can compose inside larger structures, which is unsafe
/// for a top-level object — an attacker could append ignored data (the classic trailing-data parser
/// differential). Mirrors [`crate::tlv::decode_tlv_strict`]. Returns the SEQUENCE content octets.
pub fn decode_sequence_tlv_strict(input: &[u8]) -> Result<&[u8], SequenceError> {
    let (content, used) = decode_sequence_tlv(input)?;
    if used != input.len() {
        return Err(SequenceError::TrailingData);
    }
    Ok(content)
}

/// Wrap already-encoded child bytes as a DER SEQUENCE TLV (constructed UNIVERSAL 16, then the
/// length, then `elements_content`) into `out`.
///
/// `elements_content` must be the concatenation of the children's own DER encodings; this only
/// adds the SEQUENCE envelope (it does not validate the children). Returns the number of bytes
/// written, or `None` if `out` is too small or the content is longer than the length codec
/// supports (`> u32::MAX`). Delegates the envelope to [`encode_tlv_into`].
pub fn encode_sequence_into(elements_content: &[u8], out: &mut [u8]) -> Option<usize> {
    let tag = Tag { class: Class::Universal, constructed: true, number: TAG };
    encode_tlv_into(tag, elements_content, out)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: the content buffer is `[u8; 8]`. Each child TLV consumes `used >= 2`, so
// there are at most 4 children — but `decode_tlv` itself contains loops up to ~11 iterations for a
// maximal header (6-byte high-tag + 5-byte long length). `#[kani::unwind(16)]` therefore covers
// both the outer element walk and the inner header decode; if Kani reports an unwinding-assertion
// failure, that bound must be raised (do not weaken the proof).
//
// Coverage envelope: at width 8 the tiling / over-read proofs symbolically explore up to 4 children
// (and up to ~2 multi-byte-header children). The per-child logic is width-agnostic — each step is an
// independent decode_tlv with the proven `used >= 2` progress bound — so the property generalizes;
// a wider buffer would add breadth, not new logic.
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: iterating `Elements` (and thus `decode_sequence`) over *arbitrary* content
    /// never panics or overflows, and the iterator always terminates within the unwind bound
    /// (each accepted child consumes `>= 2` bytes, so `rest` strictly shrinks).
    ///
    /// Cover (T6 primary rule): witnesses the `Ok` tail is reached with at least two children (the
    /// walk loop genuinely iterates more than once, not just the trivial 0- or 1-child case) AND,
    /// separately, that a malformed child is surfaced as `Element(..)` — turning "the loop
    /// actually loops, and the error path actually fires" from an unwind-bound assumption into a
    /// checked post-state fact. Would NOT be SAT if `decode_sequence`'s body were a no-op.
    #[kani::proof]
    #[kani::unwind(16)]
    fn iterate_never_panics() {
        let content: [u8; 8] = kani::any();
        let result = decode_sequence(&content);
        kani::cover(result == Ok(2), "the walk genuinely takes a second iteration (2 children tiled)");
        kani::cover(
            matches!(result, Err(SequenceError::Element(_))),
            "a malformed child is surfaced as Element(..)",
        );
        let _ = result;
    }

    /// **No over-read.** Walking the content — exactly what [`Elements::next`] does: `decode_tlv`
    /// then advance by `used` — never advances past `content.len()` and never exposes a value
    /// beyond it. Proven by an independent *index* walk (no pointer / `usize`-address arithmetic, so
    /// it is target-width agnostic and cannot be vacuously true under address wraparound): from
    /// offset 0, each accepted child consumes `used >= 2` with `off + used <= content.len()`, and
    /// its value lies inside that child (`value.len() <= used`).
    #[kani::proof]
    #[kani::unwind(16)]
    fn no_over_read() {
        let content: [u8; 8] = kani::any();
        let mut off = 0usize;
        while off < content.len() {
            match decode_tlv(&content[off..]) {
                Ok((tlv, used)) => {
                    assert!(used >= 2); // progress lower bound == the termination invariant
                    assert!(off + used <= content.len()); // never advance past the content
                    assert!(tlv.value.len() <= used); // the value lies within this child
                    off += used;
                }
                Err(_) => break,
            }
        }
    }

    /// **Exact tiling.** `decode_sequence(content) == Ok(k)` implies the `k` children *exactly*
    /// tile `content`: an independent re-walk of `content` (this proof's own `decode_tlv` loop,
    /// not the impl's offset counter) consumes `k` children and lands its offset exactly on
    /// `content.len()`. The oracle here is the SPEC ("children exactly cover the content"),
    /// re-derived from scratch, so a bug that let `decode_sequence` return `Ok` with bytes left
    /// over would fail this — the tautological-oracle trap is avoided.
    #[kani::proof]
    #[kani::unwind(16)]
    fn ok_implies_exact_tiling() {
        let content: [u8; 8] = kani::any();
        if let Ok(k) = decode_sequence(&content) {
            // Independent re-walk from raw offsets.
            let mut off = 0usize;
            let mut seen = 0usize;
            while off < content.len() {
                let (_tlv, used) = decode_tlv(&content[off..]).unwrap();
                // Each accepted TLV consumes at least its 2-octet header and never over-reads.
                assert!(used >= 2);
                off += used;
                seen += 1;
                assert!(off <= content.len());
            }
            assert!(off == content.len()); // exact tiling: no leftover, no over-run
            assert!(seen == k); // and the reported count matches the independent walk
        }
    }

    /// Round-trip: two known child TLVs (INTEGER `02 01 07` and BOOLEAN `01 01 FF`) concatenated
    /// and wrapped by `encode_sequence_into` decode back — via `decode_sequence_tlv` +
    /// `Elements` — to exactly those two children, in order.
    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip_two_children() {
        // Build the concatenated child content: INTEGER 7, then BOOLEAN TRUE.
        let children = [0x02u8, 0x01, 0x07, 0x01, 0x01, 0xFF];
        let mut out = [0u8; 16]; // 0x30 + len(1) + 6 content = 8 fits
        let n = encode_sequence_into(&children, &mut out).unwrap();

        // Envelope: UNIVERSAL-16 constructed, content recovered verbatim.
        let (content, used) = decode_sequence_tlv(&out[..n]).unwrap();
        assert!(used == n);
        assert!(content == &children[..]);

        // Exactly two children, in order.
        assert!(decode_sequence(content) == Ok(2));
        let mut it = Elements::new(content);
        let c0 = it.next().unwrap().unwrap();
        assert!(c0.tag.class == Class::Universal);
        assert!(c0.tag.number == 2);
        assert!(!c0.tag.constructed);
        assert!(c0.value == &[0x07]);
        let c1 = it.next().unwrap().unwrap();
        assert!(c1.tag.class == Class::Universal);
        assert!(c1.tag.number == 1);
        assert!(c1.value == &[0xFF]);
        assert!(it.next().is_none());
    }

    /// Tag correctness for `decode_sequence_tlv`: the canonical SEQUENCE identifier `0x30` is
    /// accepted; the primitive form `0x10` is `NotConstructed`; a different constructed tag (SET
    /// `0x31`) is `WrongTag`. Exercised over an arbitrary 1-octet child body.
    #[kani::proof]
    #[kani::unwind(16)]
    fn tag_correctness() {
        let a: u8 = kani::any();
        // 0x30 = UNIVERSAL 16 constructed: accepted, content is the 1-octet body.
        let seq = [0x30, 0x01, a];
        let body = [a];
        assert!(decode_sequence_tlv(&seq) == Ok((&body[..], 3)));
        // 0x10 = UNIVERSAL 16 *primitive*: a SEQUENCE must be constructed.
        let prim = [0x10, 0x01, a];
        assert!(decode_sequence_tlv(&prim) == Err(SequenceError::NotConstructed));
        // 0x31 = UNIVERSAL 17 constructed (SET): right class/constructed, wrong number.
        let set = [0x31, 0x01, a];
        assert!(decode_sequence_tlv(&set) == Err(SequenceError::WrongTag));
    }

    /// Identifier canonicality, machine-checked end-to-end: over *all* inputs, an accepted
    /// SEQUENCE begins with **exactly** the single canonical identifier octet `0x30`. This rules
    /// out the high-tag form of tag 16, the primitive form `0x10`, and any wrong class/number,
    /// without trusting the delegation to `decode_tlv` by inspection.
    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical_0x30() {
        let buf: [u8; 16] = kani::any();
        if decode_sequence_tlv(&buf).is_ok() {
            assert!(buf[0] == 0x30);
        }
    }

    /// Strict decode rejects any trailing byte after a complete SEQUENCE (top-level anti-smuggling).
    #[kani::proof]
    #[kani::unwind(16)]
    fn strict_rejects_trailing() {
        // a valid empty SEQUENCE (30 00, consumes 2) plus one trailing byte (input len 3).
        let t: u8 = kani::any();
        assert!(decode_sequence_tlv_strict(&[0x30, 0x00, t]) == Err(SequenceError::TrailingData));
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_two_element_sequence() {
        // 30 06 02 01 07 01 01 FF  =  SEQUENCE { INTEGER 7, BOOLEAN TRUE }
        let der = [0x30, 0x06, 0x02, 0x01, 0x07, 0x01, 0x01, 0xFF];
        let (content, used) = decode_sequence_tlv(&der).unwrap();
        assert_eq!(used, 8);
        assert_eq!(content, &[0x02, 0x01, 0x07, 0x01, 0x01, 0xFF]);
        assert_eq!(decode_sequence(content), Ok(2));

        // The children iterate in order with the expected tags/values.
        let kids: Vec<_> = Elements::new(content).map(|r| r.unwrap()).collect();
        assert_eq!(kids.len(), 2);
        assert_eq!(kids[0].tag.number, 2); // INTEGER
        assert_eq!(kids[0].value, &[0x07]);
        assert_eq!(kids[1].tag.number, 1); // BOOLEAN
        assert_eq!(kids[1].value, &[0xFF]);
    }

    #[test]
    fn decodes_empty_sequence() {
        // 30 00  =  SEQUENCE { } — a valid, common encoding with zero children.
        let (content, used) = decode_sequence_tlv(&[0x30, 0x00]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(content, &[] as &[u8]);
        assert_eq!(decode_sequence(content), Ok(0));
        assert!(Elements::new(content).next().is_none());
    }

    #[test]
    fn decode_sequence_counts_children_directly() {
        // Three one-byte NULLs back to back: 05 00 05 00 05 00.
        let content = [0x05, 0x00, 0x05, 0x00, 0x05, 0x00];
        assert_eq!(decode_sequence(&content), Ok(3));
    }

    #[test]
    fn ignores_trailing_bytes_after_sequence() {
        // A SEQUENCE followed by extra bytes: only the object is consumed.
        let der = [0x30, 0x02, 0x05, 0x00, 0xFF, 0xFF];
        let (content, used) = decode_sequence_tlv(&der).unwrap();
        assert_eq!(used, 4);
        assert_eq!(decode_sequence(content), Ok(1));
    }

    #[test]
    fn roundtrips_via_encode() {
        // Wrap two children, then recover them.
        let children = [0x02, 0x01, 0x07, 0x01, 0x01, 0xFF];
        let mut out = [0u8; 32];
        let n = encode_sequence_into(&children, &mut out).unwrap();
        assert_eq!(&out[..2], &[0x30, 0x06]); // constructed UNIVERSAL 16, length 6
        let (content, used) = decode_sequence_tlv(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(content, &children[..]);
        assert_eq!(decode_sequence(content), Ok(2));
    }

    #[test]
    fn iterator_is_fused_after_error() {
        // Second child (0x02 0x05 …) over-runs; the iterator yields one Err then stops.
        let content = [0x05, 0x00, 0x02, 0x05, 0xAA];
        let mut it = Elements::new(&content);
        assert_eq!(it.next().unwrap().unwrap().tag.number, 5); // first child OK (NULL)
        assert_eq!(it.next(), Some(Err(TlvError::Truncated))); // second child truncated
        assert_eq!(it.next(), None); // fused: nothing after the error
    }

    // --- seeded-bad specimens: each MUST be rejected ---
    #[test]
    fn rejects_child_that_overruns_content() {
        // Child declares 5 content octets but only 1 is present in the SEQUENCE content:
        // decode_sequence surfaces it as Element(Truncated).
        let content = [0x02, 0x05, 0xAA];
        assert_eq!(decode_sequence(&content), Err(SequenceError::Element(TlvError::Truncated)));
    }
    #[test]
    fn rejects_primitive_sequence_identifier() {
        // 0x10 = UNIVERSAL 16 primitive. A SEQUENCE is always constructed (§8.9.1).
        assert_eq!(decode_sequence_tlv(&[0x10, 0x00]), Err(SequenceError::NotConstructed));
    }
    #[test]
    fn rejects_set_tag_as_wrong_tag() {
        // 0x31 = SET (UNIVERSAL 17, constructed): tag-identity is checked first, so this is
        // WrongTag (this module recognizes but does not decode SET).
        assert_eq!(decode_sequence_tlv(&[0x31, 0x00]), Err(SequenceError::WrongTag));
    }
    #[test]
    fn rejects_non_sequence_tag_as_wrong_tag() {
        // 0x02 = INTEGER, not a SEQUENCE.
        assert_eq!(decode_sequence_tlv(&[0x02, 0x01, 0x07]), Err(SequenceError::WrongTag));
    }
    #[test]
    fn rejects_indefinite_length_envelope() {
        // 0x30 0x80 … = SEQUENCE with the BER indefinite length form; rejected by the length
        // codec (inherited), surfaced as Tlv(Length(Indefinite)).
        use crate::length::LengthError;
        assert_eq!(
            decode_sequence_tlv(&[0x30, 0x80, 0x00, 0x00]),
            Err(SequenceError::Tlv(TlvError::Length(LengthError::Indefinite)))
        );
    }
    #[test]
    fn rejects_truncated_envelope() {
        // 0x30 0x06 with only 2 content octets present: the envelope itself is truncated.
        assert_eq!(
            decode_sequence_tlv(&[0x30, 0x06, 0x05, 0x00]),
            Err(SequenceError::Tlv(TlvError::Truncated))
        );
    }
    #[test]
    fn empty_content_is_zero_not_error() {
        // The empty content slice is a well-formed zero-child SEQUENCE body.
        assert_eq!(decode_sequence(&[]), Ok(0));
    }

    #[test]
    fn strict_accepts_exact_and_rejects_trailing() {
        // decode_sequence_tlv_strict requires the SEQUENCE to consume the whole input.
        assert_eq!(decode_sequence_tlv_strict(&[0x30, 0x00]), Ok(&[] as &[u8]));
        // one SEQUENCE (consumes 4) followed by a trailing byte -> TrailingData.
        assert_eq!(
            decode_sequence_tlv_strict(&[0x30, 0x02, 0x05, 0x00, 0xFF]),
            Err(SequenceError::TrailingData)
        );
    }

    #[test]
    fn accepts_framing_but_not_content_canonicality() {
        // A BOOLEAN child whose CONTENT is 0x01: well-FRAMED (canonical tag+length) but a
        // non-canonical TRUE (DER requires 0xFF). decode_sequence validates framing only, so it
        // accepts (Ok(1)); the caller's typed decoder is what rejects the content. (DECISIONS.md D5.)
        let content = [0x01u8, 0x01, 0x01]; // BOOLEAN, len 1, value 0x01
        assert_eq!(decode_sequence(&content), Ok(1)); // framing OK
        let child = Elements::new(&content).next().unwrap().unwrap();
        assert_eq!(
            crate::boolean::decode_bool(child.value),
            Err(crate::boolean::BoolError::NonCanonical) // content-canonicality is the caller's check
        );
    }

    #[test]
    fn unsorted_set_content_is_currently_accepted() {
        // SET-OF content in DESCENDING (non-DER) order: INTEGER 2 then INTEGER 1. DER §11.6 requires
        // SET members sorted by encoding, but this SEQUENCE module does not decode SET, so the
        // generic walk accepts it. Captures the D6 scope gap (a future decode_set must enforce §11.6).
        let set_content = [0x02u8, 0x01, 0x02, 0x02, 0x01, 0x01]; // INTEGER 2, INTEGER 1 (unsorted)
        assert_eq!(decode_sequence(&set_content), Ok(2));
    }
}
