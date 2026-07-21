//! DER SET OF member-ordering canonicality (X.690 §11.6).
//!
//! A SET (and SET OF) is UNIVERSAL tag 17 in the **constructed** form (identifier octet `0x31`;
//! the primitive form `0x11` is malformed, mirroring [`crate::sequence`]'s SEQUENCE rule). Its
//! content is the concatenation of the encodings of the component TLVs, exactly like SEQUENCE —
//! **except** DER/CER additionally require the children to appear in a specific order. This module
//! is the home `DECISIONS.md` D6 reserved for that ordering proof.
//!
//! **§11.6 "Set-of components" (DER/CER restriction), quoted verbatim from X.690:**
//! ```text
//! The encodings of the component values of a set-of value shall appear in ascending order, the
//! encodings being compared as octet strings with the shorter components being padded at their
//! trailing end with 0-octets.
//! NOTE – The padding octets are for comparison purposes only and do not appear in the encodings.
//! ```
//! "The encodings of the component values" means the **complete TLV bytes** (identifier + length +
//! value) of each child, exactly as they sit concatenated in the SET's content octets — not just
//! each child's value/content part (X.690 clause 8 uses "encoding" this way throughout, e.g. the
//! SEQUENCE analogue in 8.9.2). The comparison is **not** plain lexicographic/prefix comparison:
//! the shorter of two encodings is conceptually padded with trailing `0x00` bytes (for comparison
//! purposes only — the padding never appears in the actual bytes) out to the longer one's length,
//! and *then* the two equal-length byte strings are compared. This differs from `<[u8]>::cmp`,
//! which instead treats a strict prefix as *less than* the longer string with no padding — so
//! `slice::cmp`/`Ord` on `&[u8]` must **not** be used directly here; [`cmp_padded`] implements the
//! padded rule explicitly.
//!
//! **Scope — SET OF (§11.6), not general SET (§10.3).** §10.3 governs a general, heterogeneous
//! SET, ordered by each field's ASN.1-schema-assigned **tag** — a rule this crate cannot implement
//! because it is schema-free (it never sees the ASN.1 module that assigns those tags). §11.6
//! governs SET OF specifically: a homogeneous repetition of one component type, ordered by
//! **encoding** with no schema needed. This module implements §11.6 only; everything here is named
//! around "SET OF" rather than bare "SET" so as not to over-advertise general SET support — the
//! same over-advertising trap `DECISIONS.md` D6 already flagged once for [`crate::sequence`]'s
//! `SET_TAG` export. (`DECISIONS.md` D13.)
//!
//! **Non-strict ("ascending", not "strictly ascending").** Two *distinct* SET OF elements can
//! legitimately share a byte-identical DER encoding (e.g. two INTEGER members both encoding the
//! value 5) — nothing in X.690 forbids duplicate members of a SET OF — so the order check accepts
//! ties: for every adjacent pair, [`cmp_padded`] must not report [`core::cmp::Ordering::Greater`].
//!
//! **A documented spec quirk, not a bug.** Because padding is virtual and zero-filled, the padded
//! rule can equate two textually *different* byte strings: if the shorter encoding is a byte-for-
//! byte prefix of the longer one, and every byte in the longer one's non-shared tail is `0x00`,
//! the two compare **equal** under §11.6 even though their raw bytes differ (e.g. `[0xAA, 0x00]`
//! and `[0xAA]` compare equal — see the `cmp_padded` tests). This is an accepted property of the
//! spec itself, not a defect to work around.
//!
//! **Scope — TLV framing, not content canonicality.** Like [`crate::sequence`], [`decode_set_of`]
//! validates that the content is a concatenation of well-formed child TLVs (framing only — non-
//! minimal length, high-tag form, indefinite length are all rejected, inherited from
//! [`crate::tag`]/[`crate::length`]); it does not additionally re-validate each child's own content
//! canonicality (a canonical BOOLEAN, a minimal INTEGER, …) — same D5 boundary, extended.

use crate::tag::{Class, Tag};
use crate::tlv::{decode_tlv, encode_tlv_into, TlvError};
use core::cmp::Ordering;

/// The universal tag number for SET / SET OF (the same wire tag; see the module's scope note —
/// this module implements only the SET OF, schema-free, order-by-encoding rule).
pub const TAG: u32 = 17;

/// Why a SET OF was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SetOfError {
    /// The envelope TLV itself was malformed (bad identifier/length, indefinite length, …) — as
    /// distinct from a well-formed envelope whose *content* has a problem ([`Self::Element`] /
    /// [`Self::Unsorted`]).
    Tlv(TlvError),
    /// The identifier is a well-formed TLV but is not UNIVERSAL 17.
    WrongTag,
    /// The identifier is UNIVERSAL 17 but in the *primitive* form (`0x11`) — a SET OF is always
    /// constructed (§8.11.1/§8.12.1), so the primitive form is malformed.
    NotConstructed,
    /// A child element failed to decode (bad TLV: over-read, bad identifier/length, …). Mirrors
    /// [`crate::sequence::SequenceError::Element`].
    Element(TlvError),
    /// `children[index]`'s encoding compares *greater than* `children[index + 1]`'s under
    /// [`cmp_padded`] (§11.6 violated). `index` is the **first** offending adjacent pair —
    /// everything before it is already known to be in non-descending order.
    Unsorted {
        /// The index of the earlier element in the first out-of-order adjacent pair.
        index: usize,
    },
    /// Strict decode only: bytes remain after a complete SET OF (see [`decode_set_of_tlv_strict`]).
    TrailingData,
}

/// Compare two encodings under X.690 §11.6's padded-comparison rule: the shared prefix is compared
/// byte-by-byte, and if one is a prefix of the other, the longer one's extra tail is compared
/// against implicit trailing zero padding (never against nothing, as plain `slice::cmp` would).
pub fn cmp_padded(a: &[u8], b: &[u8]) -> Ordering {
    let n = core::cmp::min(a.len(), b.len());
    let mut i = 0;
    while i < n {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
        i += 1;
    }
    // Shared prefix is equal; the longer one's extra tail is compared against virtual zero padding.
    if a.len() == b.len() {
        return Ordering::Equal;
    }
    let (longer, is_a_longer) = if a.len() > b.len() { (a, true) } else { (b, false) };
    let mut j = n;
    while j < longer.len() {
        if longer[j] != 0 {
            // The longer encoding has a non-zero byte where the shorter is virtually zero-padded.
            return if is_a_longer { Ordering::Greater } else { Ordering::Less };
        }
        j += 1;
    }
    Ordering::Equal // every extra tail byte of the longer one is zero -> equal under the padded rule
}

/// Validate that `content` is **exactly** a concatenation of well-formed child TLVs — every child
/// decodes and nothing is left over, same framing-only gate as [`crate::sequence::decode_sequence`]
/// — **and** that successive children's raw encodings are in non-descending order under
/// [`cmp_padded`] (§11.6). Returns the child count.
///
/// Walks children directly with [`decode_tlv`] in a loop tracking a byte offset, rather than
/// [`crate::sequence::Elements`], because §11.6 compares each child's **whole raw TLV byte span**
/// (identifier + length + value) — `Elements` only yields the decoded `Tlv { tag, value }`, not
/// that raw span. On the first adjacent pair that violates the order, returns
/// [`SetOfError::Unsorted`] naming the earlier element's index; a malformed child is
/// [`SetOfError::Element`].
pub fn decode_set_of(content: &[u8]) -> Result<usize, SetOfError> {
    let mut off = 0usize;
    let mut count = 0usize;
    let mut prev: Option<&[u8]> = None;
    while off < content.len() {
        let (_tlv, used) = decode_tlv(&content[off..]).map_err(SetOfError::Element)?;
        let this = &content[off..off + used];
        if let Some(p) = prev {
            // Invariant: `prev` is `Some` only after the first iteration has run to completion,
            // at which point `count` has already been incremented to `1` — so `count >= 1` here,
            // and `count - 1` (the previous child's index) cannot underflow.
            if cmp_padded(p, this) == Ordering::Greater {
                return Err(SetOfError::Unsorted { index: count - 1 });
            }
        }
        prev = Some(this);
        off += used;
        count += 1;
    }
    Ok(count)
}

/// Decode a complete DER SET OF from the front of `input`, returning the SET OF **content** octets
/// and the total number of bytes consumed (`tag + length + value`).
///
/// Mirrors [`crate::sequence::decode_sequence_tlv`] exactly: tag-identity is checked before the
/// primitive/constructed flag, so a non-SET tag (e.g. SEQUENCE `0x30`) is [`SetOfError::WrongTag`],
/// and the *primitive* form of UNIVERSAL 17 (`0x11`) is [`SetOfError::NotConstructed`]. Unlike a
/// bare "recognize but don't decode" placeholder, the content is then run through
/// [`decode_set_of`], so this call **also enforces §11.6 ordering** — an unsorted SET OF is
/// rejected here, not merely accepted-but-flagged.
///
/// The trailing-bytes convention matches [`decode_tlv`] / [`crate::sequence::decode_sequence_tlv`]:
/// bytes after the SET OF are ignored so this composes inside larger structures; a top-level
/// caller should use [`decode_set_of_tlv_strict`] instead.
pub fn decode_set_of_tlv(input: &[u8]) -> Result<(&[u8], usize), SetOfError> {
    let (tlv, used) = decode_tlv(input).map_err(SetOfError::Tlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != TAG {
        return Err(SetOfError::WrongTag);
    }
    if !tlv.tag.constructed {
        return Err(SetOfError::NotConstructed);
    }
    decode_set_of(tlv.value)?;
    Ok((tlv.value, used))
}

/// Decode a complete DER SET OF, requiring it to consume the *entire* `input` (no trailing bytes).
///
/// Mirrors [`crate::sequence::decode_sequence_tlv_strict`]: use this at the top level, where
/// [`decode_set_of_tlv`]'s trailing-bytes tolerance would otherwise let an attacker append ignored
/// data (the classic trailing-data parser differential).
pub fn decode_set_of_tlv_strict(input: &[u8]) -> Result<&[u8], SetOfError> {
    let (content, used) = decode_set_of_tlv(input)?;
    if used != input.len() {
        return Err(SetOfError::TrailingData);
    }
    Ok(content)
}

/// Wrap already-encoded, **already-sorted** child bytes as a DER SET OF TLV (constructed
/// UNIVERSAL 17, then the length, then `children_content`) into `out`.
///
/// Mirrors [`crate::sequence::encode_sequence_into`] exactly: a thin envelope wrapper — it does
/// not validate or sort the children; the caller is responsible for pre-sorting under
/// [`cmp_padded`] (§11.6) before calling this. Returns the number of bytes written, or `None` if
/// `out` is too small or the content is longer than the length codec supports (`> u32::MAX`).
pub fn encode_set_of_into(children_content: &[u8], out: &mut [u8]) -> Option<usize> {
    let tag = Tag { class: Class::Universal, constructed: true, number: TAG };
    encode_tlv_into(tag, children_content, out)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 proof floor).
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: mirrors `sequence.rs` — the content buffer is `[u8; 8]`. Each child TLV
// consumes `used >= 2`, so there are at most 4 children; `decode_tlv` itself needs up to ~11
// iterations for a maximal header. `#[kani::unwind(16)]` covers both the outer walk and the inner
// header decode; if Kani reports an unwinding-assertion failure, raise the bound (never weaken the
// proof).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Independent oracle for §11.6's padded comparison, in a **genuinely different shape** from
    /// production `cmp_padded`: materialize *both* operands into fixed-size zero-padded arrays
    /// (copy each into a zero-initialized `[u8; N]`, so the padding is physically present rather
    /// than checked incrementally), then compare the two equal-length padded arrays index by
    /// index. Production is an incremental "compare-shared-prefix, then check-tail-for-zero" loop;
    /// this is "materialize-padded, then compare" — different code shapes, so a bug in one (e.g. an
    /// off-by-one in the tail-zero check, or a flipped return sign) cannot hide behind an identical
    /// bug in the other.
    ///
    /// `N` bounds the operands this oracle can faithfully compare (silently truncating beyond it
    /// would misrepresent §11.6, not just narrow the proof) — `8` matches the `[u8; 8]` content
    /// buffer convention used throughout this module's other proofs, comfortably covering every
    /// current call site (all ≤ 3 bytes). The `assert!` below turns any future call that exceeds
    /// `N` into a loud Kani verification failure demanding `N` be raised, rather than a silent,
    /// wrong answer from truncated copies (the failure mode a fixed-size buffer would otherwise
    /// invite).
    fn cmp_padded_oracle(a: &[u8], b: &[u8]) -> Ordering {
        const N: usize = 8;
        assert!(a.len() <= N && b.len() <= N, "cmp_padded_oracle: operand exceeds N; raise N");
        let mut pa = [0u8; N];
        let mut pb = [0u8; N];
        let mut i = 0;
        while i < a.len() && i < N {
            pa[i] = a[i];
            i += 1;
        }
        let mut j = 0;
        while j < b.len() && j < N {
            pb[j] = b[j];
            j += 1;
        }
        let mut k = 0;
        while k < N {
            if pa[k] != pb[k] {
                return pa[k].cmp(&pb[k]);
            }
            k += 1;
        }
        Ordering::Equal
    }

    /// Robustness: `decode_set_of` on any `[u8; 8]` content never panics.
    ///
    /// Cover (T6 primary rule): witnesses the `Ok` tail with at least two children (the walk loop
    /// genuinely iterates and the `cmp_padded` ordering check actually runs on a real adjacent
    /// pair), AND separately that `Unsorted` actually fires — turning "the ordering check is live,
    /// not vacuously always-true" into a checked post-state fact. Would NOT be SAT if
    /// `decode_set_of`'s body were a no-op.
    #[kani::proof]
    #[kani::unwind(16)]
    fn iterate_never_panics() {
        let content: [u8; 8] = kani::any();
        let result = decode_set_of(&content);
        kani::cover(result == Ok(2), "the walk genuinely takes a second iteration, exercising cmp_padded on a real adjacent pair");
        kani::cover(matches!(result, Err(SetOfError::Unsorted { .. })), "the §11.6 ordering check actually rejects a real unsorted pair");
        let _ = result;
    }

    /// **No over-read.** Independent index-walk (own `decode_tlv` loop from raw offsets, exactly
    /// like `sequence.rs`'s `no_over_read`), regardless of the ordering outcome: from offset 0,
    /// each accepted child consumes `used >= 2` with `off + used <= content.len()`, and its value
    /// lies inside that child.
    #[kani::proof]
    #[kani::unwind(16)]
    fn no_over_read() {
        let content: [u8; 8] = kani::any();
        let mut off = 0usize;
        while off < content.len() {
            match decode_tlv(&content[off..]) {
                Ok((tlv, used)) => {
                    assert!(used >= 2);
                    assert!(off + used <= content.len());
                    assert!(tlv.value.len() <= used);
                    off += used;
                }
                Err(_) => break,
            }
        }
    }

    /// **Exact tiling.** `decode_set_of(content) == Ok(k)` implies an independent re-walk of
    /// `content` (this proof's own `decode_tlv` loop, not the impl's counter) tiles it exactly into
    /// `k` children. Mirrors `sequence.rs`'s `ok_implies_exact_tiling`, adapted for `SetOfError`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn ok_implies_exact_tiling() {
        let content: [u8; 8] = kani::any();
        if let Ok(k) = decode_set_of(&content) {
            let mut off = 0usize;
            let mut seen = 0usize;
            while off < content.len() {
                let (_tlv, used) = decode_tlv(&content[off..]).unwrap();
                assert!(used >= 2);
                off += used;
                seen += 1;
                assert!(off <= content.len());
            }
            assert!(off == content.len());
            assert!(seen == k);
        }
    }

    /// **THE security property — de-tautologized ordering biconditional.** Two symbolic 1-content-
    /// byte NULL TLVs (`05 01 a`, `05 01 b`, tag/length fixed so framing is trivially valid,
    /// content bytes `a`/`b` fully symbolic) concatenated into an 8-byte buffer:
    /// `decode_set_of` accepts iff the independent pad-then-compare oracle says the first is not
    /// (padded-)greater than the second. An implementation that got the padded-comparison direction
    /// or tie-handling wrong would fail this.
    #[kani::proof]
    #[kani::unwind(16)]
    fn ordering_iff_oracle() {
        let a: u8 = kani::any();
        let b: u8 = kani::any();
        let content = [0x05u8, 0x01, a, 0x05, 0x01, b];
        let child0 = &content[0..3];
        let child1 = &content[3..6];
        let accepted = decode_set_of(&content).is_ok();
        let ordered = cmp_padded_oracle(child0, child1) != Ordering::Greater;
        assert!(accepted == ordered);
    }

    /// Standalone de-tautologization proof: production `cmp_padded` and the independent
    /// pad-then-compare-arrays oracle **agree** over symbolic small byte arrays of differing
    /// (symbolic) lengths, up to 3 bytes each. Analogous to `utf8_string`'s `validate_iff_oracle`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn cmp_padded_matches_oracle() {
        let abuf: [u8; 3] = kani::any();
        let bbuf: [u8; 3] = kani::any();
        let alen: usize = kani::any();
        let blen: usize = kani::any();
        kani::assume(alen <= 3);
        kani::assume(blen <= 3);
        let a = &abuf[..alen];
        let b = &bbuf[..blen];
        assert!(cmp_padded(a, b) == cmp_padded_oracle(a, b));
    }

    /// Two concrete children where child0's encoding is (padded-)greater than child1's — same
    /// tag/length, content byte 2 then 1, clearly descending — are rejected as
    /// `Unsorted { index: 0 }`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn unsorted_children_are_rejected() {
        let content = [0x05u8, 0x01, 0x02, 0x05, 0x01, 0x01];
        assert!(decode_set_of(&content) == Err(SetOfError::Unsorted { index: 0 }));
    }

    /// **Maximality.** Three concrete children where the first two are properly ordered but the
    /// second pair (index 1) is the first violation: `decode_set_of` must report
    /// `Unsorted { index: 1 }` specifically — naming the *earliest* adjacent violation, not merely
    /// a within-bounds one. Children are three NULL TLVs with content bytes `1, 2, 0` (1 <= 2 is
    /// fine; 2 > 0 is the first, and only, violation).
    #[kani::proof]
    #[kani::unwind(16)]
    fn unsorted_reports_first_violation_index() {
        let content = [0x05u8, 0x01, 0x01, 0x05, 0x01, 0x02, 0x05, 0x01, 0x00];
        assert!(decode_set_of(&content) == Err(SetOfError::Unsorted { index: 1 }));
    }

    /// **Maximality, depth 4.** Four concrete children where the first *two* adjacent pairs (index
    /// 0 and index 1) are properly ordered and only the *third* pair (index 2) violates — closing
    /// the gap the depth-3 `unsorted_reports_first_violation_index` proof above leaves open (that
    /// the earlier-violation logic also holds once `count` has advanced past 2). Content bytes
    /// `0, 1, 2, 0`: `0<=1` and `1<=2` are fine; `2 > 0` is the first, and only, violation.
    #[kani::proof]
    #[kani::unwind(16)]
    fn unsorted_reports_first_violation_index_depth_four() {
        let content = [
            0x05u8, 0x01, 0x00, //
            0x05, 0x01, 0x01, //
            0x05, 0x01, 0x02, //
            0x05, 0x01, 0x00,
        ];
        assert!(decode_set_of(&content) == Err(SetOfError::Unsorted { index: 2 }));
    }

    /// Two children with byte-identical encodings are accepted (`Ok(2)`), confirming the non-
    /// strict / tie-permitting design: equal adjacent encodings are valid, not rejected.
    #[kani::proof]
    #[kani::unwind(16)]
    fn duplicate_adjacent_encodings_are_accepted() {
        let content = [0x02u8, 0x01, 0x05, 0x02, 0x01, 0x05]; // two INTEGER-5 TLVs back to back
        assert!(decode_set_of(&content) == Ok(2));
    }

    /// Tag correctness for `decode_set_of_tlv`: the canonical SET OF identifier `0x31` is accepted;
    /// the primitive form `0x11` is `NotConstructed`; a different constructed tag (SEQUENCE `0x30`)
    /// is `WrongTag`. Unlike `sequence.rs`'s analogous proof, the *content* here must itself be a
    /// well-formed (single-child, trivially "sorted") TLV — `decode_set_of_tlv` validates §11.6
    /// ordering, so an opaque 1-octet body (not a full child TLV) would fail as `Element(..)`
    /// rather than exercise the tag/constructed checks. A single NULL child (`05 00`) is used
    /// instead: well-formed, and a lone child is vacuously ordered.
    #[kani::proof]
    #[kani::unwind(16)]
    fn tag_correctness() {
        // 0x31 = UNIVERSAL 17 constructed: accepted, content is the 2-octet NULL child.
        let set = [0x31, 0x02, 0x05, 0x00];
        let body = [0x05, 0x00];
        assert!(decode_set_of_tlv(&set) == Ok((&body[..], 4)));
        // 0x11 = UNIVERSAL 17 *primitive*: a SET OF must be constructed.
        let prim = [0x11, 0x02, 0x05, 0x00];
        assert!(decode_set_of_tlv(&prim) == Err(SetOfError::NotConstructed));
        // 0x30 = UNIVERSAL 16 constructed (SEQUENCE): right class/constructed, wrong number.
        let seq = [0x30, 0x02, 0x05, 0x00];
        assert!(decode_set_of_tlv(&seq) == Err(SetOfError::WrongTag));
    }

    /// Identifier canonicality, machine-checked end-to-end: over *all* inputs, an accepted SET OF
    /// begins with **exactly** the single canonical identifier octet `0x31`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical_0x31() {
        let buf: [u8; 16] = kani::any();
        if decode_set_of_tlv(&buf).is_ok() {
            assert!(buf[0] == 0x31);
        }
    }

    /// Strict decode rejects any trailing byte after a complete SET OF.
    #[kani::proof]
    #[kani::unwind(16)]
    fn strict_rejects_trailing() {
        // a valid empty SET OF (31 00, consumes 2) plus one trailing byte (input len 3).
        let t: u8 = kani::any();
        assert!(decode_set_of_tlv_strict(&[0x31, 0x00, t]) == Err(SetOfError::TrailingData));
    }

    /// Round-trip: two known, already-sorted child TLVs (INTEGER 1, then INTEGER 2 — ascending
    /// content byte, so ascending encoding order) concatenated and wrapped via
    /// `encode_set_of_into` decode back — via `decode_set_of_tlv` + `decode_set_of` — to exactly
    /// those two children. Mirrors `sequence.rs`'s `roundtrip_two_children`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip_two_sorted_children() {
        let children = [0x02u8, 0x01, 0x01, 0x02, 0x01, 0x02]; // INTEGER 1, INTEGER 2
        let mut out = [0u8; 16];
        let n = encode_set_of_into(&children, &mut out).unwrap();

        let (content, used) = decode_set_of_tlv(&out[..n]).unwrap();
        assert!(used == n);
        assert!(content == &children[..]);
        assert!(decode_set_of(content) == Ok(2));
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_empty_set_of() {
        // 31 00 = SET OF { } — a valid, common encoding with zero children.
        let (content, used) = decode_set_of_tlv(&[0x31, 0x00]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(content, &[] as &[u8]);
        assert_eq!(decode_set_of(content), Ok(0));
    }

    #[test]
    fn decodes_sorted_three_element_set_of() {
        // 31 09 { INTEGER 1, INTEGER 2, INTEGER 3 } — same tag+length prefix, ascending content
        // byte, so ascending encoding order: a real non-trivial (non-tie) ascending case.
        let der = [
            0x31, 0x09, //
            0x02, 0x01, 0x01, //
            0x02, 0x01, 0x02, //
            0x02, 0x01, 0x03,
        ];
        let (content, used) = decode_set_of_tlv(&der).unwrap();
        assert_eq!(used, 11);
        assert_eq!(decode_set_of(content), Ok(3));
    }

    #[test]
    fn roundtrips_via_encode() {
        let children = [0x02u8, 0x01, 0x01, 0x02, 0x01, 0x02];
        let mut out = [0u8; 32];
        let n = encode_set_of_into(&children, &mut out).unwrap();
        assert_eq!(&out[..2], &[0x31, 0x06]); // constructed UNIVERSAL 17, length 6
        let (content, used) = decode_set_of_tlv(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(content, &children[..]);
        assert_eq!(decode_set_of(content), Ok(2));
    }

    // --- the padding subtlety itself ---
    #[test]
    fn cmp_padded_equates_prefix_with_zero_tail() {
        // [0xAA, 0x00] (2 bytes) vs [0xAA] (1 byte, virtually padded to [0xAA, 0x00]): these are
        // DIFFERENT byte strings but compare EQUAL under the padded rule — a documented spec
        // property (module docs), not a bug.
        assert_eq!(cmp_padded(&[0xAA, 0x00], &[0xAA]), Ordering::Equal);
        assert_eq!(cmp_padded(&[0xAA], &[0xAA, 0x00]), Ordering::Equal);
        // A non-zero tail, in contrast, is NOT equal (the longer one is strictly greater).
        assert_eq!(cmp_padded(&[0xAA, 0x01], &[0xAA]), Ordering::Greater);
        assert_eq!(cmp_padded(&[0xAA], &[0xAA, 0x01]), Ordering::Less);
    }

    #[test]
    fn cmp_padded_plain_lexicographic_cases() {
        assert_eq!(cmp_padded(&[0x01], &[0x02]), Ordering::Less);
        assert_eq!(cmp_padded(&[0x02], &[0x01]), Ordering::Greater);
        assert_eq!(cmp_padded(&[0x01, 0x02], &[0x01, 0x02]), Ordering::Equal);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn rejects_descending_three_element_set_of() {
        // Same three INTEGERs as decodes_sorted_three_element_set_of, but in DESCENDING order:
        // must be Unsorted{index: 0} (the first adjacent pair already violates §11.6). The TLV
        // envelope itself is well-formed, so the rejection surfaces through the content check.
        let der = [
            0x31, 0x09, //
            0x02, 0x01, 0x03, //
            0x02, 0x01, 0x02, //
            0x02, 0x01, 0x01,
        ];
        assert_eq!(decode_set_of_tlv(&der), Err(SetOfError::Unsorted { index: 0 }));
    }

    #[test]
    fn rejects_violation_only_at_second_pair() {
        // INTEGER 1, INTEGER 2, INTEGER 0: first pair (1 <= 2) fine, second pair (2 > 0) is the
        // first, and only, violation -> Unsorted{index: 1}.
        let content = [
            0x02u8, 0x01, 0x01, //
            0x02, 0x01, 0x02, //
            0x02, 0x01, 0x00,
        ];
        assert_eq!(decode_set_of(&content), Err(SetOfError::Unsorted { index: 1 }));
    }

    #[test]
    fn rejects_violation_only_at_third_pair() {
        // INTEGER 0, 1, 2, 0: the first two adjacent pairs are fine; only the third (2 > 0) is a
        // violation -> Unsorted{index: 2}. Closes the depth-3-only gap the prior test leaves open.
        let content = [
            0x02u8, 0x01, 0x00, //
            0x02, 0x01, 0x01, //
            0x02, 0x01, 0x02, //
            0x02, 0x01, 0x00,
        ];
        assert_eq!(decode_set_of(&content), Err(SetOfError::Unsorted { index: 2 }));
    }

    #[test]
    fn duplicate_adjacent_encodings_are_accepted() {
        // Two byte-identical INTEGER-5 encodings: ties are legal (nothing in X.690 forbids
        // duplicate SET OF members).
        let content = [0x02u8, 0x01, 0x05, 0x02, 0x01, 0x05];
        assert_eq!(decode_set_of(&content), Ok(2));
    }

    #[test]
    fn rejects_primitive_set_identifier() {
        // 0x11 = UNIVERSAL 17 primitive. A SET OF is always constructed (§8.11.1/§8.12.1).
        assert_eq!(decode_set_of_tlv(&[0x11, 0x00]), Err(SetOfError::NotConstructed));
    }

    #[test]
    fn rejects_sequence_tag_as_wrong_tag() {
        // 0x30 = SEQUENCE (UNIVERSAL 16, constructed): tag-identity is checked first.
        assert_eq!(decode_set_of_tlv(&[0x30, 0x00]), Err(SetOfError::WrongTag));
    }

    #[test]
    fn rejects_non_set_tag_as_wrong_tag() {
        // 0x02 = INTEGER, not a SET OF.
        assert_eq!(decode_set_of_tlv(&[0x02, 0x01, 0x07]), Err(SetOfError::WrongTag));
    }

    #[test]
    fn rejects_indefinite_length_envelope() {
        use crate::length::LengthError;
        assert_eq!(
            decode_set_of_tlv(&[0x31, 0x80, 0x00, 0x00]),
            Err(SetOfError::Tlv(TlvError::Length(LengthError::Indefinite)))
        );
    }

    #[test]
    fn rejects_truncated_envelope() {
        assert_eq!(
            decode_set_of_tlv(&[0x31, 0x06, 0x05, 0x00]),
            Err(SetOfError::Tlv(TlvError::Truncated))
        );
    }

    #[test]
    fn rejects_child_that_overruns_content() {
        let content = [0x02u8, 0x05, 0xAA];
        assert_eq!(decode_set_of(&content), Err(SetOfError::Element(TlvError::Truncated)));
    }

    #[test]
    fn strict_accepts_exact_and_rejects_trailing() {
        assert_eq!(decode_set_of_tlv_strict(&[0x31, 0x00]), Ok(&[] as &[u8]));
        assert_eq!(
            decode_set_of_tlv_strict(&[0x31, 0x02, 0x05, 0x00, 0xFF]),
            Err(SetOfError::TrailingData)
        );
    }
}
