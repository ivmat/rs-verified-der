//! DER ENUMERATED content (X.690 §8.4) — the encoding of an enumerated value is defined to be
//! IDENTICAL to that of the integer value with which it is associated (no additional DER rule).
//! This module is therefore a thin re-tagging of [`crate::integer`]'s already-proven i64 content
//! codec: UNIVERSAL 10 (`0x0A`) instead of UNIVERSAL 2, same minimal two's-complement content rule,
//! same [`crate::integer::IntError`] classification. It deliberately does NOT duplicate
//! `crate::integer`'s minimality/round-trip proofs (see `DECISIONS.md` D11's precedent against
//! near-duplicate modules for the same content rule) — it only needs to confirm the delegation and
//! tag number are wired correctly.

/// The universal tag number for ENUMERATED.
pub const TAG: u32 = 10;

/// Decode ENUMERATED content (delegates entirely to [`crate::integer::decode_integer`] — the
/// content rule is byte-for-byte identical, per X.690 §8.4).
pub fn decode_enumerated(content: &[u8]) -> Result<i64, crate::integer::IntError> {
    crate::integer::decode_integer(content)
}

/// Encode `v` as minimal DER ENUMERATED content (delegates entirely to
/// [`crate::integer::encode_integer`]).
pub fn encode_enumerated(v: i64) -> ([u8; 8], usize) {
    crate::integer::encode_integer(v)
}

#[cfg(kani)]
mod proofs {
    use super::*;

    /// Delegation contract: `decode_enumerated` returns literally the same result as
    /// `crate::integer::decode_integer` for any content. Pins the delegation so a future refactor
    /// cannot accidentally diverge the two.
    ///
    /// **The domain is the wrapper's WHOLE reachable input space**, not `integer`'s: a 9-octet
    /// buffer with symbolic length `0..=9` reaches the empty slice and an over-long slice as well as
    /// every accepted width, so all three of `decode_integer`'s outcome classes are exercised
    /// *through the delegation*. An earlier version of this harness assumed `1 <= n <= 8` — mirroring
    /// `integer.rs`'s own buffer choices — and then explained the two excluded error paths away by
    /// pointing at `integer`'s harnesses. That left the delegation unproven at exactly the two
    /// lengths the wrapper can still be handed, which sits badly with the point of the harness.
    #[kani::proof]
    #[kani::unwind(12)]
    fn decode_delegates_to_integer() {
        let buf: [u8; 9] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 9);
        let r = decode_enumerated(&buf[..n]);
        assert!(r == crate::integer::decode_integer(&buf[..n]));
        // The assert is an AGREEMENT property, and agreement is the shape that survives vacuity: it
        // would hold just as well if both sides only ever rejected, or if only one width were ever
        // explored. The covers below name one reachable behaviour of the delegation each.
        //
        // Read them as a SET, and read the claim precisely: no single constant body satisfies all
        // seven (a constant `Ok(0)` fires the positive-width witnesses but neither the negative one
        // nor any rejection; a constant `Err` fires at most one rejection witness). Individually, a
        // cover here is weaker than that — `r.is_ok() && n == 1` alone is satisfiable under a body
        // that always returns `Ok(0)`. What rules out every constant body is the assert, which pins
        // `r` to `decode_integer`'s real behaviour at every length on any green run.
        kani::cover(r.is_ok() && n == 1, "a 1-octet ENUMERATED is accepted through the delegation");
        kani::cover(
            r.is_ok() && n >= 2 && n <= 7,
            "an INTERMEDIATE-width ENUMERATED is accepted through the delegation (not just the two \
             ends of the range)",
        );
        kani::cover(r.is_ok() && n == 8, "a full-width 8-octet ENUMERATED is accepted through the delegation");
        // Sign extension is only genuinely exercised at full width: a negative value is cheapest to
        // witness at `n == 1` (`0x80` alone decodes to -128), which would leave the eight-shift
        // accumulator path unwitnessed here. Hence the `n == 8` conjunct.
        kani::cover(
            matches!(r, Ok(v) if v < 0) && n == 8,
            "a negative two's-complement value survives the re-tag at full width",
        );
        kani::cover(
            r == Err(crate::integer::IntError::NonMinimal),
            "the NonMinimal rejection path is reached through the delegation",
        );
        kani::cover(
            r == Err(crate::integer::IntError::Empty),
            "the Empty rejection path is reached through the delegation (n == 0)",
        );
        kani::cover(
            r == Err(crate::integer::IntError::TooLarge),
            "the TooLarge rejection path is reached through the delegation (n == 9)",
        );
    }

    /// Delegation contract: `encode_enumerated` returns literally the same result as
    /// `crate::integer::encode_integer` for any `i64`. Total — no `kani::assume`.
    #[kani::proof]
    fn encode_delegates_to_integer() {
        let v: i64 = kani::any();
        let (out, n) = encode_enumerated(v);
        assert!((out, n) == crate::integer::encode_integer(v));
        // Same reasoning as `decode_delegates_to_integer`: an agreement assert is not by itself a
        // witness that the delegation produced anything in particular. These pin the returned
        // *length* (a post-state effect — a no-op body returning `([0; 8], 0)` satisfies none of
        // them) at both ends of the minimal-encoding range, plus the sign octet at full width.
        kani::cover(n == 1, "a small value encodes to a single octet through the delegation");
        kani::cover(n == 8, "a full-width value encodes to all eight octets through the delegation");
        kani::cover(
            n == 8 && out[0] & 0x80 != 0,
            "a negative full-width value keeps its sign octet through the re-tag",
        );
    }

    /// Round-trip: every `i64` encodes to minimal ENUMERATED content that decodes back to it.
    /// Follows from the two delegation proofs above, but is worth pinning directly on this
    /// module's own public API since it's the property an actual caller relies on.
    #[kani::proof]
    #[kani::unwind(12)]
    fn roundtrip() {
        let v: i64 = kani::any();
        let (buf, n) = encode_enumerated(v);
        assert!(decode_enumerated(&buf[..n]) == Ok(v));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tag_is_universal_10() {
        // The ENUMERATED identifier octet for a primitive, universal-class tag is just the tag
        // number itself (class bits 00, primitive bit 0) — anchor the 0x0A arithmetic fact.
        assert_eq!(TAG, 10);
        assert_eq!(TAG as u8, 0x0A);
    }

    #[test]
    fn matches_integer_for_concrete_values() {
        for v in [0i64, 1, -1, 127, 128, -129] {
            assert_eq!(encode_enumerated(v), crate::integer::encode_integer(v), "value {v}");
            let (buf, n) = encode_enumerated(v);
            assert_eq!(
                decode_enumerated(&buf[..n]),
                crate::integer::decode_integer(&buf[..n]),
                "value {v}"
            );
            assert_eq!(decode_enumerated(&buf[..n]), Ok(v), "value {v}");
        }
    }

    #[test]
    fn rejects_non_minimal_same_as_integer() {
        // 0x00 0x01 is non-minimal for INTEGER; ENUMERATED shares the same rule (§8.4).
        assert_eq!(
            decode_enumerated(&[0x00, 0x01]),
            crate::integer::decode_integer(&[0x00, 0x01])
        );
        assert_eq!(
            decode_enumerated(&[0x00, 0x01]),
            Err(crate::integer::IntError::NonMinimal)
        );
    }
}
