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
    #[kani::proof]
    #[kani::unwind(8)]
    fn validate_never_panics() {
        let buf: [u8; 6] = kani::any();
        let _ = validate_oid(&buf);
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
}
