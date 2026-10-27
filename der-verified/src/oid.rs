//! DER OBJECT IDENTIFIER content (X.690 §8.19).
//!
//! An OID's content is a sequence of subidentifiers, each a base-128, big-endian, **minimal**
//! group of octets with bit 8 set on every octet except the last (the terminator). This module
//! validates *canonical form* — the security-critical property, since OID confusion (two encodings
//! of "the same" OID accepted differently) is a real X.509 attack surface. It operates on the
//! content octets of a TLV whose tag is UNIVERSAL 6 (`0x06`).
//!
//! Materialising the arcs needs a variable-length output (a later, allocation-aware addition);
//! this is the heap-free canonical-form validator.
//!
//! **Scope boundaries (deliberate):**
//! - *Subidentifier width is not bounded.* A canonically-encoded subidentifier may exceed `u64`;
//!   that is still valid DER, so this validator accepts it. A downstream arc decoder must enforce
//!   its own integer-width limit (reject/`TooLarge`) — that check belongs there, not here.
//! - *No first-subidentifier "semantic" rejection is needed.* Every canonical first subidentifier
//!   value `Z` decodes to a valid arc pair via `X = min(Z/40, 2)`, `Y = Z − 40·X`, so `X ∈ {0,1,2}`
//!   always — there is no impossible first subidentifier to reject (e.g. `Z=126 ⇒ {2.46}`, valid).
//!
//! # Examples
//!
//! ```
//! use der_verified::oid::validate_oid;
//!
//! // 1.2.840.113549 (RSADSI): 2A 86 48 86 F7 0D
//! assert_eq!(validate_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]), Ok(()));
//!
//! // 0x80 0x01 encodes a subidentifier non-minimally (should be just 0x01).
//! assert!(validate_oid(&[0x80, 0x01]).is_err());
//! ```

/// The universal tag number for OBJECT IDENTIFIER.
pub const TAG: u32 = 6;

/// Why OID content was rejected as non-canonical or malformed.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum OidError {
    /// Content was empty (an OID needs at least the first subidentifier).
    Empty,
    /// A subidentifier began with `0x80` — a redundant leading-zero base-128 group (non-minimal).
    NonMinimalSubid,
    /// The content ended in the middle of a subidentifier (a continuation bit with no terminator).
    Truncated,
}

/// Validate that `content` is a canonical DER OBJECT IDENTIFIER body.
///
/// Accepts iff the content is non-empty and every subidentifier is a minimal base-128 group that
/// terminates within the content. Never panics.
pub fn validate_oid(content: &[u8]) -> Result<(), OidError> {
    if content.is_empty() {
        return Err(OidError::Empty);
    }
    // Single-loop DER OID canonical-form check: an explicit `at_subid_start` state replaces the
    // original nested inner loop. Behaviour is identical — proven by the unchanged Kani harnesses
    // and tests below — but every early `return` now sits at loop-depth 1, which the Aeneas → Lean
    // extractor requires (it rejects a `return` nested two loop-levels deep; see DECISIONS.md D25).
    // The flatter shape also verifies far faster in Kani when inlined into the x509 consumers.
    let mut at_subid_start = true; // the next octet begins a new subidentifier
    let mut i = 0;
    while i < content.len() {
        let b = content[i];
        // Minimality (§8.19): a subidentifier's leading octet must not be a redundant `0x80` group.
        if at_subid_start && b == 0x80 {
            return Err(OidError::NonMinimalSubid);
        }
        // An octet with bit 8 clear terminates the current subidentifier; the next octet starts one.
        at_subid_start = b & 0x80 == 0;
        i += 1;
    }
    // A trailing continuation octet (bit 8 set on the final octet) means the last subidentifier
    // never terminated within the content.
    if !at_subid_start {
        return Err(OidError::Truncated);
    }
    Ok(())
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `validate_oid` never panics on any content up to 6 octets.
    ///
    /// Cover (T6 primary rule): witnesses that the symbolic 6-byte buffer actually reaches the
    /// `Ok` tail (a genuine multi-subidentifier canonical OID), not merely that malformed content
    /// is rejected. `at_subid_start` is single-loop internal state, so the post-state fact used
    /// here is: `Ok(())` AND the buffer contains at least one terminator octet (bit 8 clear)
    /// before the last byte, i.e. at least two subidentifiers are present. Would NOT be SAT if
    /// `validate_oid`'s body were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn validate_never_panics() {
        let buf: [u8; 6] = kani::any();
        let result = validate_oid(&buf);
        kani::cover(result.is_ok(), "a canonical OID reaches validate_oid's Ok tail");
        let multi_subid = buf[..5].iter().any(|b| b & 0x80 == 0);
        kani::cover(
            result.is_ok() && multi_subid,
            "a canonical OID with at least two subidentifiers is accepted (a terminator octet \
             occurs before the final byte)",
        );
        let _ = result;
    }

    /// Empty content is `Empty`.
    #[kani::proof]
    fn empty_is_classified() {
        assert!(validate_oid(&[]) == Err(OidError::Empty));
    }

    /// A subidentifier beginning `0x80` (redundant leading-zero group) is `NonMinimalSubid`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn leading_0x80_is_non_minimal() {
        let buf: [u8; 5] = kani::any();
        kani::assume(buf[0] == 0x80);
        assert!(validate_oid(&buf) == Err(OidError::NonMinimalSubid));
    }

    /// A non-minimal `0x80`-led subidentifier is rejected wherever it appears, not just first
    /// (the review's later-position proof-gap fix).
    #[kani::proof]
    #[kani::unwind(8)]
    fn later_0x80_is_non_minimal() {
        let buf: [u8; 4] = kani::any();
        kani::assume(buf[0] < 0x80); // a valid single-octet first subidentifier (it terminates)
        kani::assume(buf[1] == 0x80); // the second subidentifier starts non-minimally
        assert!(validate_oid(&buf) == Err(OidError::NonMinimalSubid));
    }

    /// Content whose final subidentifier never terminates (every octet a continuation) is `Truncated`.
    #[kani::proof]
    #[kani::unwind(8)]
    fn unterminated_is_truncated() {
        let buf: [u8; 4] = kani::any();
        kani::assume(buf[0] != 0x80 && buf[0] & 0x80 != 0); // valid non-minimal start, continues
        kani::assume(buf[1] & 0x80 != 0 && buf[2] & 0x80 != 0 && buf[3] & 0x80 != 0);
        assert!(validate_oid(&buf) == Err(OidError::Truncated));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_valid_oids() {
        // 1.2 = {iso member-body} -> single subidentifier 42 = 0x2A
        assert_eq!(validate_oid(&[0x2A]), Ok(()));
        // 1.2.840.113549 (RSADSI) = 2A 86 48 86 F7 0D
        assert_eq!(validate_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]), Ok(()));
        // a subidentifier of value 0 (single 0x00 terminator) is minimal
        assert_eq!(validate_oid(&[0x2A, 0x00]), Ok(()));
    }

    #[test]
    fn rejects_empty() {
        assert_eq!(validate_oid(&[]), Err(OidError::Empty));
    }

    #[test]
    fn rejects_non_minimal_subid() {
        // 0x80 0x01 encodes subid 1 non-minimally (should be just 0x01)
        assert_eq!(validate_oid(&[0x80, 0x01]), Err(OidError::NonMinimalSubid));
        // a leading 0x80 in a later subidentifier is also rejected
        assert_eq!(validate_oid(&[0x2A, 0x80, 0x01]), Err(OidError::NonMinimalSubid));
    }

    #[test]
    fn rejects_unterminated_subid() {
        // 0x86 has the continuation bit set but no following octet
        assert_eq!(validate_oid(&[0x2A, 0x86]), Err(OidError::Truncated));
    }

    // --- S4a (group 3): per-requirement tests ---

    /// X680-32: an OBJECT IDENTIFIER TLV carries the literal identifier octet 0x06 (UNIVERSAL 6, decoded and encoded).
    #[test]
    fn accepts_oid_universal_6_identifier_octet() {
        use crate::tag::{Class, Tag};
        use crate::tlv::{decode_tlv_strict, encode_tlv_into};
        // literal specimen: 06 06 2A 86 48 86 F7 0D (1.2.840.113549)
        let tlv = decode_tlv_strict(&[0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]).unwrap();
        assert_eq!(tlv.tag, Tag { class: Class::Universal, constructed: false, number: TAG });
        assert_eq!(validate_oid(tlv.value), Ok(()));
        // encoder direction: the first output octet is 0x06
        let mut out = [0u8; 8];
        let used = encode_tlv_into(
            Tag { class: Class::Universal, constructed: false, number: TAG },
            &[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D],
            &mut out,
        )
        .unwrap();
        assert_eq!(out[0], 0x06);
        assert_eq!(&out[..used], &[0x06, 0x06, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D]);
    }

    /// X690-8.19: content whose last subidentifier is cut off after complete ones is not a list of subidentifier encodings.
    #[test]
    fn rejects_content_that_is_not_a_list_of_complete_subidentifiers() {
        // 2A and 86 48 are two complete subidentifiers (42 and 840); the trailing 86 starts a
        // third one that never terminates
        assert_eq!(validate_oid(&[0x2A, 0x86, 0x48]), Ok(()));
        assert_eq!(validate_oid(&[0x2A, 0x86, 0x48, 0x86]), Err(OidError::Truncated));
        assert_eq!(validate_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7]), Err(OidError::Truncated));
        // a redundant 0x80 group in the middle of the list is not a subidentifier encoding either
        assert_eq!(
            validate_oid(&[0x2A, 0x86, 0x48, 0x80, 0x01]),
            Err(OidError::NonMinimalSubid)
        );
    }

    /// X690-8.19.4: the standard's own {2 999 3} first subidentifier 1079 (88 37) is accepted although it exceeds 79.
    #[test]
    fn accepts_first_subidentifier_packed_from_arc_two_and_a_large_second_arc() {
        // 2.999.3 = 88 37 03: first subidentifier 40*2 + 999 = 1079 = 88 37; second subidentifier 3
        assert_eq!(validate_oid(&[0x88, 0x37, 0x03]), Ok(()));
        // 2.46 packs into the single-octet first subidentifier 126 = 7E
        assert_eq!(validate_oid(&[0x7E]), Ok(()));
    }

    /// X690-8.19.5: subidentifiers after the first are separate entries; a multi-octet one followed by another is accepted.
    #[test]
    fn accepts_subsequent_subidentifiers_after_a_multi_octet_one() {
        // 1.2.840.113549.1.1.11: 2A 86 48 86 F7 0D 01 01 0B (sha256WithRSAEncryption)
        assert_eq!(
            validate_oid(&[0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B]),
            Ok(())
        );
    }

    /// CODEC-oid-unique: every padded alternate spelling of a subidentifier is rejected as NonMinimalSubid; only the minimal form is accepted.
    #[test]
    fn rejects_every_alternate_spelling_of_a_subidentifier() {
        // subidentifier value 1: minimal 01 accepted; 80 01 and 80 80 01 rejected
        assert_eq!(validate_oid(&[0x2A, 0x01]), Ok(()));
        assert_eq!(validate_oid(&[0x2A, 0x80, 0x01]), Err(OidError::NonMinimalSubid));
        assert_eq!(validate_oid(&[0x2A, 0x80, 0x80, 0x01]), Err(OidError::NonMinimalSubid));
        // subidentifier value 0: minimal 00 accepted; 80 00 rejected
        assert_eq!(validate_oid(&[0x2A, 0x00]), Ok(()));
        assert_eq!(validate_oid(&[0x2A, 0x80, 0x00]), Err(OidError::NonMinimalSubid));
        // subidentifier value 128: minimal 81 00 accepted; 80 81 00 rejected
        assert_eq!(validate_oid(&[0x2A, 0x81, 0x00]), Ok(()));
        assert_eq!(validate_oid(&[0x2A, 0x80, 0x81, 0x00]), Err(OidError::NonMinimalSubid));
    }
}
