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
//!
//! # Examples
//!
//! ```
//! use der_verified::set_of::decode_set_of_tlv;
//!
//! // 31 09 { INTEGER 1, INTEGER 2, INTEGER 3 } — ascending encoding order (§11.6).
//! let der = [0x31, 0x09, 0x02, 0x01, 0x01, 0x02, 0x01, 0x02, 0x02, 0x01, 0x03];
//! assert!(decode_set_of_tlv(&der).is_ok());
//!
//! // The same members in descending order violate §11.6 and are rejected.
//! let unsorted = [0x31, 0x09, 0x02, 0x01, 0x03, 0x02, 0x01, 0x02, 0x02, 0x01, 0x01];
//! assert!(decode_set_of_tlv(&unsorted).is_err());
//! ```

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
    // EQUIVALENT-MUTANT: `a.len() > b.len()` can never itself become `a.len() >= b.len()` in a
    // way a test could observe here — the `a.len() == b.len()` case already returned above, so by
    // this point the lengths are always unequal (cargo-mutants survivor, not a coverage gap).
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
///
/// Children are checked strictly in order, and the first failure of that walk is the one reported:
/// each child is decoded and then compared with its predecessor, so an out-of-order pair among the
/// children before a malformed child is reported as `Unsorted`, in preference to the `Element` error
/// of that later malformed child (a malformed child itself is never compared, so it is reported as
/// `Element`).
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
///
/// **Error precedence.** This is [`decode_set_of_tlv`] followed by a trailing-data check, so the
/// trailing-data check runs last: every error of the non-strict decoder (envelope, tag/form and
/// content errors) is returned unchanged and passes through before trailing bytes are looked at, and
/// [`SetOfError::TrailingData`] is returned only for input that [`decode_set_of_tlv`] accepts and
/// that has bytes after the SET OF. A malformed or unsorted SET OF followed by extra bytes therefore
/// reports its own error, not `TrailingData`.
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
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
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

    /// Robustness: `decode_set_of` on any content **of any length up to 8 octets** never panics --
    /// the content buffer AND its length are both symbolic, so this is a bounded claim over the
    /// whole `0..=8`-octet domain, not just the single 8-octet length.
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
        // Symbolic input length, matching the crate's established convention (see
        // `x509_tbs_certificate.rs`, `ecdsa_sig_value.rs`): so the "any content up to 8 octets"
        // claim above holds at every length in the domain, not just the single length 8.
        let len: usize = kani::any();
        kani::assume(len <= content.len());
        let result = decode_set_of(&content[..len]);
        kani::cover(result == Ok(2), "the walk genuinely takes a second iteration, exercising cmp_padded on a real adjacent pair");
        kani::cover(matches!(result, Err(SetOfError::Unsorted { .. })), "the §11.6 ordering check actually rejects a real unsorted pair");
        let _ = result;
    }

    /// **No over-read of [`decode_set_of`], in the two senses this walk permits.** Bounded
    /// memory-safety of the shipped walk, plus an extensional postcondition on what it accepts.
    ///
    /// **What drives this proof is load-bearing, and it used to be the wrong thing.** Until
    /// 2026-08-24 this harness ran its own `decode_tlv` loop from raw offsets — copied from
    /// `sequence.rs`'s harness, and described as being "exactly like" it. That made it a proof
    /// about a *copy* of the walk: a regression inside [`decode_set_of`]'s own loop could have
    /// left it green. It now drives [`decode_set_of`] itself. Two legs carry the claim:
    ///
    /// 1. **No out-of-bounds access, over `0..=8` octets.** [`decode_set_of`] indexes
    ///    `content[off..]` and `content[off..off + used]` directly and the crate forbids `unsafe`,
    ///    so an over-read inside it is an out-of-bounds slice — a panic — and Kani checks panics
    ///    on every path. Reaching the `if let` below at all is that claim.
    /// 2. **On `Ok(k)`, an independent index oracle pins the tiling — at *symbolic* length.** The
    ///    sibling `ok_implies_exact_tiling` checks the same shape only at the fixed 8-octet
    ///    length; this covers the whole domain. Index arithmetic only (no pointer /
    ///    `usize`-address arithmetic, so it is target-width agnostic and cannot be vacuously true
    ///    under address wraparound). Each child consumes `used >= 2` (DER's two-octet framing
    ///    floor) without passing `content.len()`, holds its value at its own tail (a **byte**
    ///    comparison — it says the value matches the octets at that position, not that it is, in
    ///    the provenance sense, a pointer into them), the children tile the content exactly, and
    ///    `seen == k`.
    ///
    /// **What this does NOT prove, stated because the sibling in `sequence.rs` DOES prove it.**
    /// The two are not structurally equivalent, and the difference is in the shipped code, not in
    /// the effort spent: [`crate::sequence::Elements`] carries its cursor in a field its harness
    /// can read back after every step, so that harness pins the shipped walk's advance
    /// *per child* against a separately computed oracle. [`decode_set_of`] keeps `off` in a local
    /// and returns only a count, so nothing here observes its cursor. Consequently this harness
    /// does not show that the shipped loop used the *same per-child boundaries* as the oracle's
    /// re-walk, nor that the local cursor never ends up past `content.len()` after the final
    /// read — a terminal over-advance that reads nothing more would neither panic nor change `k`.
    /// Leg 2 is an extensional property of the accepted *input*, not a trace of the walk.
    /// Closing that gap needs the walk itself refactored onto [`crate::sequence::Elements`]
    /// (which would also retire a duplicated walk in shipped code); it is logged in
    /// `DER-REMAINING-WORK.md` rather than claimed here.
    ///
    /// Covers (T6 primary rule): the walk genuinely takes a second iteration, and the rejection
    /// path genuinely fires. What a cover buys is narrower than it looks — `kani::cover`
    /// satisfaction is observed at a run and is not gate-enforced in this repo
    /// (`PROOF_MANIFEST.md` §8.2), and an always-`Err` body would satisfy every *conditional*
    /// assertion above while merely leaving the `Ok` cover unsatisfied. These are evidence that
    /// the paths were reached at this run, not an enforced anti-vacuity guard.
    #[kani::proof]
    #[kani::unwind(16)]
    fn no_over_read() {
        let buf: [u8; 8] = kani::any();
        // Symbolic input length (same idiom as iterate_never_panics above): the no-over-read
        // claim must hold at every length in the domain, not just the full buffer.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let content = &buf[..len];

        // Leg 1: the shipped walk. Reaching the next statement at all is the no-OOB-access claim
        // -- this call, not a re-implementation of it, is what Kani's panic checks range over.
        let result = decode_set_of(content);

        // Leg 2: an EXTENSIONAL postcondition on the accepted input. This re-walk observes the
        // shipped cursor not at all (it is a local); see the doc comment on what that leaves open.
        if let Ok(k) = result {
            let mut off = 0usize;
            let mut seen = 0usize;
            while off < content.len() {
                let (tlv, used) = decode_tlv(&content[off..]).unwrap();
                assert!(used >= 2); // DER's two-octet framing floor
                assert!(off + used <= content.len()); // never past the content
                assert!(tlv.value.len() <= used); // the value lies within this child ...
                // ... and matches the octets at that child's tail (byte comparison).
                assert!(tlv.value == &content[off + used - tlv.value.len()..off + used]);
                off += used;
                seen += 1;
            }
            assert!(off == content.len()); // exact tiling: no leftover, no over-run
            assert!(seen == k); // and the reported count matches the independent walk
        }
        kani::cover(
            matches!(result, Ok(k) if k >= 2),
            "the shipped walk genuinely takes a second iteration",
        );
        kani::cover(result.is_err(), "the shipped walk's rejection path genuinely fires");
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
        // Symbolic input length (same idiom as iterate_never_panics above): the canonicality
        // claim must hold at every length in the domain, not just the full buffer.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        if decode_set_of_tlv(input).is_ok() {
            assert!(input[0] == 0x31);
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

    // -----------------------------------------------------------------------
    // §11.6 ordering over WHOLE child encodings, at symbolic framing (the fixed-`05 01` header of
    // `ordering_iff_oracle` cannot tell "compare whole encodings" from "compare contents only").
    // The expected result below is computed by an oracle that shares NO code with `decode_set_of` /
    // `cmp_padded`: a two-phase formulation (tile first, then scan the pairs), a fresh
    // index-wise padded comparison, and `decode_tlv` (the separately-verified framing primitive)
    // only to find each child's extent.
    // -----------------------------------------------------------------------

    /// §11.6 comparison of two raw child encodings, formulated index-wise over `0..max(len)` with a
    /// virtual zero fetched for the shorter operand (no materialized arrays, no shared-prefix-then-
    /// tail split) -- a third shape beside `cmp_padded` and `cmp_padded_oracle`.
    fn oracle_encoding_cmp(a: &[u8], b: &[u8]) -> Ordering {
        let m = if a.len() > b.len() { a.len() } else { b.len() };
        let mut k = 0;
        while k < m {
            let x = if k < a.len() { a[k] } else { 0 };
            let y = if k < b.len() { b[k] } else { 0 };
            if x < y {
                return Ordering::Less;
            }
            if x > y {
                return Ordering::Greater;
            }
            k += 1;
        }
        Ordering::Equal
    }

    /// Expected `decode_set_of(content)` (content <= 8 octets => at most 4 children).
    /// Phase 1 tiles `content` into raw child spans `[starts[i], ends[i])` (header + value) with
    /// `decode_tlv`, stopping at the first framing failure. Phase 2 scans the adjacent pairs of the
    /// children decoded so far for the FIRST pair whose encodings are padded-descending
    /// (`Unsorted { index: i }`); only if there is none does a framing failure surface as
    /// `Element(e)`, else `Ok(child count)`. (That precedence -- a descending pair that precedes a
    /// bad child is reported before the bad child -- is stated in `decode_set_of`'s rustdoc: children
    /// are checked in order and the first failure of the walk is reported.)
    fn oracle_set_of(content: &[u8]) -> Result<usize, SetOfError> {
        let mut starts = [0usize; 4];
        let mut ends = [0usize; 4];
        let mut c = 0usize;
        let mut off = 0usize;
        let mut framing_err: Option<TlvError> = None;
        while off < content.len() {
            match decode_tlv(&content[off..]) {
                Err(e) => {
                    framing_err = Some(e);
                    break;
                }
                Ok((_, used)) => {
                    assert!(c < 4, "oracle_set_of: more children than the 8-octet bound allows");
                    starts[c] = off;
                    ends[c] = off + used;
                    c += 1;
                    off += used;
                }
            }
        }
        let mut i = 0;
        while i + 1 < c {
            let a = &content[starts[i]..ends[i]];
            let b = &content[starts[i + 1]..ends[i + 1]];
            if oracle_encoding_cmp(a, b) == Ordering::Greater {
                return Err(SetOfError::Unsorted { index: i });
            }
            i += 1;
        }
        match framing_err {
            Some(e) => Err(SetOfError::Element(e)),
            None => Ok(c),
        }
    }

    /// **§11.6 over whole child encodings, symbolic framing.** For every content of `0..=8` octets
    /// (fully symbolic bytes and length -- children may differ in identifier octet, length octets
    /// and value), `decode_set_of` returns EXACTLY what the independent two-phase oracle says:
    /// `Ok(k)` iff the children tile the content and every consecutive pair of FULL encodings is
    /// non-descending under the padded comparison; `Unsorted { index }` names the FIRST descending
    /// pair; `Element(e)` carries the framing error of the first undecodable child.
    ///
    /// Bounded-backing (8 octets): the differential input `02 02 00 80 02 01 05` (INTEGER 128 before
    /// INTEGER 5: descending as encodings, yet ascending as contents `00 80` < `05`) is in the domain
    /// -- see the cover below -- as is every mix of children fitting the eight-octet content bound.
    #[kani::proof]
    #[kani::unwind(16)]
    fn ordering_matches_whole_encoding_oracle() {
        let buf: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let content = &buf[..len];
        let result = decode_set_of(content);
        assert!(result == oracle_set_of(content));
        kani::cover(
            matches!(result, Ok(k) if k >= 2),
            "an accepted SET OF with at least two children is reached",
        );
        kani::cover(
            matches!(result, Err(SetOfError::Unsorted { index: 0 })),
            "a descending first pair is rejected",
        );
        kani::cover(
            matches!(result, Err(SetOfError::Unsorted { index: 1 })),
            "a descending second pair (first pair ordered) is rejected",
        );
        kani::cover(
            matches!(result, Err(SetOfError::Element(_))),
            "a framing failure inside the content is reached",
        );
        kani::cover(
            len == 7 && content == &[0x02u8, 0x02, 0x00, 0x80, 0x02, 0x01, 0x05][..],
            "the differential input (INTEGER 128 before INTEGER 5) is in the reachable domain",
        );
    }

    /// **The TLV entry point enforces §11.6** (and is classified exactly). Over a symbolic 9-octet
    /// buffer with symbolic length `0..=9` -- so the content of a short-form SET OF reaches 7 octets,
    /// which contains the differential `31 07 02 02 00 80 02 01 05` -- `decode_set_of_tlv` equals:
    /// envelope error (reference `decode_tlv`) -> `WrongTag` -> `NotConstructed` -> the independent
    /// content oracle's error -> `Ok((tlv.value, used))`. In particular an unsorted (or malformed)
    /// content is never accepted at this entry point.
    #[kani::proof]
    #[kani::unwind(16)]
    fn tlv_entry_enforces_ordering_exactly() {
        let buf: [u8; 9] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let r = decode_set_of_tlv(input);
        match decode_tlv(input) {
            Err(e) => {
                kani::cover(true, "envelope error branch reached");
                assert!(r == Err(SetOfError::Tlv(e)));
            }
            Ok((tlv, used)) => {
                if tlv.tag.class != Class::Universal || tlv.tag.number != 17 {
                    kani::cover(true, "well-formed TLV of another type reached");
                    assert!(r == Err(SetOfError::WrongTag));
                } else if !tlv.tag.constructed {
                    kani::cover(true, "primitive-form UNIVERSAL 17 reached");
                    assert!(r == Err(SetOfError::NotConstructed));
                } else {
                    match oracle_set_of(tlv.value) {
                        Err(e) => {
                            kani::cover(
                                matches!(e, SetOfError::Unsorted { .. }),
                                "an unsorted SET OF content is rejected at the TLV entry",
                            );
                            assert!(r == Err(e));
                        }
                        Ok(k) => {
                            kani::cover(k >= 2, "a sorted multi-child SET OF is accepted at the TLV entry");
                            match r {
                                Ok((content, consumed)) => {
                                    assert!(consumed == used);
                                    assert!(content == tlv.value);
                                }
                                Err(_) => panic!("well-formed sorted SET OF rejected"),
                            }
                        }
                    }
                }
                kani::cover(
                    len == 9 && input == &[0x31u8, 0x07, 0x02, 0x02, 0x00, 0x80, 0x02, 0x01, 0x05][..],
                    "the differential TLV `31 07 02 02 00 80 02 01 05` is in the reachable domain",
                );
            }
        }
    }

    /// **Strict decoder, exact result**. Over a fully symbolic 9-octet
    /// buffer with symbolic length `0..=9` (the bound of `tlv_entry_enforces_ordering_exactly`),
    /// `decode_set_of_tlv_strict(input)` is derived from the non-strict decoder's already-verified
    /// contract plus an independent trailing-byte computation:
    /// - non-strict `Err(e)` -> strict `Err(e)` (same error, nothing remapped: envelope, tag/form and
    ///   content errors pass through BEFORE trailing data is checked, as the strict rustdoc's
    ///   "Error precedence" paragraph states, so a bad SET OF followed by extra bytes is never
    ///   reported as `TrailingData`);
    /// - non-strict `Ok((content, used))` -> the accepted TLV is `31 L ..` with a short-form length
    ///   (`L < 0x80`, since `len <= 9`), so `used` is recomputed as `2 + input[1]` (asserted equal to
    ///   the decoder's `used`); then strict is `Err(TrailingData)` iff `len > 2 + input[1]` (bytes
    ///   remain), else `Ok(content)` with the very same content window as the non-strict decoder.
    /// Covers: strict Ok with non-empty content, strict Ok on the empty SET OF, `TrailingData` after
    /// a non-empty SET OF, `TrailingData` after the empty SET OF, an error passed through.
    #[kani::proof]
    #[kani::unwind(16)]
    fn strict_is_exact_composition() {
        let buf: [u8; 9] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let strict = decode_set_of_tlv_strict(input);
        match decode_set_of_tlv(input) {
            Err(e) => {
                kani::cover(true, "a non-strict error is passed through");
                assert!(strict == Err(e));
            }
            Ok((content, used)) => {
                // independent consumed-length computation from the accepted bytes
                assert!(input[0] == 0x31 && input[1] < 0x80);
                let framed = 2 + input[1] as usize;
                assert!(used == framed);
                assert!(content.len() == input[1] as usize);
                if len > framed {
                    kani::cover(!content.is_empty(), "trailing data after a non-empty SET OF");
                    kani::cover(content.is_empty(), "trailing data after the empty SET OF");
                    assert!(strict == Err(SetOfError::TrailingData));
                } else {
                    kani::cover(!content.is_empty(), "strict accepts a non-empty SET OF");
                    kani::cover(content.is_empty(), "strict accepts the empty SET OF");
                    assert!(len == framed);
                    assert!(strict == Ok(content));
                }
            }
        }
    }

    /// **Encoder, exact result**. Content is symbolic `0..=8` octets
    /// (including EMPTY content; the encoder is a thin envelope wrapper and does not validate or
    /// sort, so any bytes are legal), capacity symbolic `0..=12`, output initially symbolic.
    /// `encode_set_of_into(content, &mut out[..cap])` returns EXACTLY `None` iff `cap < 2 + n`, else
    /// `Some(2 + n)` with bytes `31 n content` (constructed UNIVERSAL 17, short-form length since
    /// `n <= 8`) and every octet past the written length untouched; on `None` the output is
    /// untouched (the documented write contract: "on `None` nothing is written to `out`; on `Some(n)`
    /// only `out[..n]` is written"). Covers: empty content encoded, non-empty encoded, minimal capacity, `None` for
    /// capacity one short.
    #[kani::proof]
    #[kani::unwind(16)]
    fn encode_is_exact_over_content_and_capacity() {
        let content: [u8; 8] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 8);
        let content = &content[..n];
        let cap: usize = kani::any();
        kani::assume(cap <= 12);
        let init: [u8; 12] = kani::any();
        let mut out = init;
        let r = encode_set_of_into(content, &mut out[..cap]);
        let total = 2 + n;
        if cap < total {
            kani::cover(cap + 1 == total, "capacity one octet short is rejected");
            assert!(r == None);
            assert!(out == init);
        } else {
            kani::cover(n == 0, "empty content encoded");
            kani::cover(n > 0, "non-empty content encoded");
            kani::cover(cap == total, "encoded at exactly the minimal capacity");
            assert!(r == Some(total));
            assert!(out[0] == 0x31);
            assert!(out[1] as usize == n);
            let mut i = 0;
            while i < n {
                assert!(out[2 + i] == content[i]);
                i += 1;
            }
            let mut j = total;
            while j < 12 {
                assert!(out[j] == init[j]);
                j += 1;
            }
        }
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

    // --- non-canonical framing (a lax/BER-tolerant reader would accept these; DER must not) ---

    #[test]
    fn rejects_high_tag_form_of_tag_17() {
        // 3F 11 = the high-tag (multi-octet) encoding of SET OF's tag number 17 (X.690
        // §8.1.2.4.2), constructed bit set. DER requires the low-tag single-octet form 0x31 for
        // numbers <= 30, so the tag codec rejects this as non-minimal.
        use crate::tag::TagError;
        assert_eq!(
            decode_set_of_tlv(&[0x3F, 0x11]),
            Err(SetOfError::Tlv(TlvError::Tag(TagError::NonMinimal)))
        );
    }

    #[test]
    fn rejects_non_minimal_length() {
        // 31 81 00 = length 0 in the long form (X.690 §8.1.3); DER requires the short form
        // (31 00). A lax parser tolerates the redundant long-form length; DER must not.
        use crate::length::LengthError;
        assert_eq!(
            decode_set_of_tlv(&[0x31, 0x81, 0x00]),
            Err(SetOfError::Tlv(TlvError::Length(LengthError::NonMinimal)))
        );
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
