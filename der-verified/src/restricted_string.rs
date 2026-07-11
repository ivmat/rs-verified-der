//! DER ASCII-restricted string types (X.690 §8.23; DER primitive-only form per §10.2; X.680
//! clause 41 for the `PrintableString` / `IA5String` / `NumericString` / `VisibleString` character
//! sets).
//!
//! These four X.509-relevant string types share the exact same DER shape as
//! [`crate::octet_string`] — a primitive, definite-length TLV whose content is a byte string — plus
//! **one extra content-level rule**: every content octet must belong to the type's fixed character
//! set (X.680). They differ from each other only in *which* tag number and *which* charset apply, so
//! this module is a single generic core (a [`Charset`] enum + one validator/codec) parameterized over
//! the four, rather than four near-duplicate modules.
//!
//! Like [`crate::octet_string`], the DER constraint on the *structure* is that BER's constructed
//! (segmented) form is forbidden — a well-known parser-differential vector (a lax reader reassembles
//! segments a strict signer never produced) — so this module also operates at the TLV level,
//! composing [`crate::tlv`] rather than validating pre-stripped content alone.
//!
//! **The four character sets, verified against X.680 (not folklore):**
//! - **PrintableString** (UNIVERSAL 19, identifier `0x13`): *exactly* 74 characters — `A`-`Z`, `a`-`z`,
//!   `0`-`9`, SPACE, and the 11 punctuation marks `' ( ) + , - . / : =  ?`. Notably **excludes**
//!   `@ * _ & !` and every other ASCII punctuation/symbol — a classic differential trap (some lax
//!   parsers erroneously widen this set).
//! - **IA5String** (UNIVERSAL 22, identifier `0x16`): the full 7-bit set, `0x00..=0x7F` (control
//!   characters included). Any octet `>= 0x80` is invalid.
//! - **NumericString** (UNIVERSAL 18, identifier `0x12`): digits `0x30..=0x39` and SPACE (`0x20`)
//!   **only** — notably excludes hyphen `-` and colon `:`, which some implementations wrongly permit.
//! - **VisibleString** / ISO646String (UNIVERSAL 26, identifier `0x1A`): the graphic characters
//!   `0x20..=0x7E` (SPACE through `~`) — excludes control characters and DEL (`0x7F`).
//!
//! **Scope boundary (see `DECISIONS.md`).** This module validates **charset-membership only** — the
//! sole content-level DER rule for these types (there is no "minimal encoding" concept here: the
//! octets *are* the value). Empty content (zero octets) is **accepted** — vacuously charset-valid.
//! Out of scope, as a caller-applied X.509 profile layer (the same altitude split as the time types,
//! D10): `SIZE` / length-limit constraints, and the `DirectoryString` CHOICE rules (which of these
//! types — plus `TeletexString`/`UTF8String`/`BMPString` — an attribute is allowed to use).

use crate::tag::{Class, Tag};
use crate::tlv::{decode_tlv, encode_tlv_into, TlvError};

/// Which ASCII-restricted string type is being validated/encoded. Carries the type's universal tag
/// number and its X.680 character-set predicate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Charset {
    /// PrintableString — UNIVERSAL 19.
    Printable,
    /// IA5String — UNIVERSAL 22.
    Ia5,
    /// NumericString — UNIVERSAL 18.
    Numeric,
    /// VisibleString (ISO646String) — UNIVERSAL 26.
    Visible,
}

impl Charset {
    /// The X.680 universal tag number for this string type.
    pub const fn tag_number(self) -> u32 {
        match self {
            Charset::Printable => 19,
            Charset::Ia5 => 22,
            Charset::Numeric => 18,
            Charset::Visible => 26,
        }
    }

    /// The canonical DER identifier octet: primitive, UNIVERSAL, this type's tag number (all four
    /// tag numbers are `<= 30`, so each fits the single-octet low-tag form).
    pub const fn identifier(self) -> u8 {
        match self {
            Charset::Printable => 0x13,
            Charset::Ia5 => 0x16,
            Charset::Numeric => 0x12,
            Charset::Visible => 0x1A,
        }
    }

    /// Whether byte `b` belongs to this type's X.680 character set. This is the production
    /// predicate; the Kani proofs check it against an *independently*-formulated oracle per charset
    /// (see the module's `#[cfg(kani)]` block) so a typo in either side cannot hide.
    pub fn contains(self, b: u8) -> bool {
        match self {
            // PrintableString (X.680 §41): letters, digits, space, and exactly these 11 marks.
            // An ASCII-class helper plus a small explicit punctuation set — a different shape from
            // the Kani oracle's full explicit 74-byte allow-list, so a typo cannot hide in both.
            Charset::Printable => {
                b.is_ascii_alphanumeric()
                    || b == b' '
                    || matches!(b, b'\'' | b'(' | b')' | b'+' | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?')
            }
            // IA5String: the full 7-bit set. Bit-test formulation (distinct from the oracle's
            // numeric-range formulation `b <= 0x7F`).
            Charset::Ia5 => b & 0x80 == 0,
            // NumericString: digits + space only (no hyphen, no colon).
            Charset::Numeric => b.is_ascii_digit() || b == b' ',
            // VisibleString: the graphic subset of ASCII, space through tilde.
            Charset::Visible => b >= 0x20 && b <= 0x7E,
        }
    }
}

/// Why a restricted-string TLV was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StringError {
    /// The TLV envelope was malformed (bad identifier/length, indefinite length, over-read, …).
    Tlv(TlvError),
    /// The identifier is well formed but is not the expected UNIVERSAL tag number for this charset.
    WrongTag,
    /// The expected UNIVERSAL tag number, but in the *constructed* (BER segmented) form — forbidden
    /// in DER, exactly as for [`crate::octet_string`].
    Constructed,
    /// Content-level: the first octet outside the charset, and its zero-based position.
    OutOfCharset {
        /// Byte offset of the first invalid octet within the content.
        position: usize,
        /// The invalid octet's value.
        byte: u8,
    },
}

/// Validate that every octet of `content` belongs to `charset`. Returns the *first* offending
/// position/byte on failure (error-class correctness: [`StringError::OutOfCharset`] always names the
/// earliest violation). Empty content is accepted (vacuously charset-valid — see the module docs).
pub fn validate_content(content: &[u8], charset: Charset) -> Result<(), StringError> {
    let mut i = 0;
    while i < content.len() {
        let b = content[i];
        if !charset.contains(b) {
            return Err(StringError::OutOfCharset { position: i, byte: b });
        }
        i += 1;
    }
    Ok(())
}

/// Decode a complete DER restricted string of the given `charset` from the front of `input`,
/// returning the content octets and the total number of bytes consumed (`tag + length + value`).
///
/// Enforces: the correct UNIVERSAL tag number (else [`StringError::WrongTag`]), **primitive** form
/// (else [`StringError::Constructed`] — the constructed/segmented form is BER-only), definite length
/// and no over-read (via [`decode_tlv`]), and charset-membership of every content octet (else
/// [`StringError::OutOfCharset`]).
///
/// Tag identity is checked before primitiveness, so a well-formed TLV of a *different* type (e.g.
/// SEQUENCE `0x30`) is `WrongTag`, not `Constructed` — mirroring [`crate::octet_string`]. Trailing
/// bytes after the string are ignored (as in [`decode_tlv`]) so this composes inside constructed
/// types; a top-level caller that must consume the whole input should check the returned length
/// against `input.len()`.
pub fn decode_restricted_string(
    input: &[u8],
    charset: Charset,
) -> Result<(&[u8], usize), StringError> {
    let (tlv, used) = decode_tlv(input).map_err(StringError::Tlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != charset.tag_number() {
        return Err(StringError::WrongTag);
    }
    if tlv.tag.constructed {
        return Err(StringError::Constructed);
    }
    validate_content(tlv.value, charset)?;
    Ok((tlv.value, used))
}

/// Encode `content` as a canonical DER restricted string of the given `charset` (primitive, the
/// charset's UNIVERSAL tag number) into `out`.
///
/// Returns the number of bytes written, or `None` if any content byte is out-of-charset, `out` is
/// too small, or `content` is longer than the length codec supports (`> u32::MAX`).
pub fn encode_restricted_string_into(content: &[u8], charset: Charset, out: &mut [u8]) -> Option<usize> {
    if validate_content(content, charset).is_err() {
        return None;
    }
    let tag = Tag { class: Class::Universal, constructed: false, number: charset.tag_number() };
    encode_tlv_into(tag, content, out)
}

/// Decode a DER PrintableString (UNIVERSAL 19).
pub fn decode_printable_string(input: &[u8]) -> Result<(&[u8], usize), StringError> {
    decode_restricted_string(input, Charset::Printable)
}

/// Decode a DER IA5String (UNIVERSAL 22).
pub fn decode_ia5_string(input: &[u8]) -> Result<(&[u8], usize), StringError> {
    decode_restricted_string(input, Charset::Ia5)
}

/// Decode a DER NumericString (UNIVERSAL 18).
pub fn decode_numeric_string(input: &[u8]) -> Result<(&[u8], usize), StringError> {
    decode_restricted_string(input, Charset::Numeric)
}

/// Decode a DER VisibleString (UNIVERSAL 26).
pub fn decode_visible_string(input: &[u8]) -> Result<(&[u8], usize), StringError> {
    decode_restricted_string(input, Charset::Visible)
}

/// Encode a DER PrintableString (UNIVERSAL 19).
pub fn encode_printable_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_restricted_string_into(content, Charset::Printable, out)
}

/// Encode a DER IA5String (UNIVERSAL 22).
pub fn encode_ia5_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_restricted_string_into(content, Charset::Ia5, out)
}

/// Encode a DER NumericString (UNIVERSAL 18).
pub fn encode_numeric_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_restricted_string_into(content, Charset::Numeric, out)
}

/// Encode a DER VisibleString (UNIVERSAL 26).
pub fn encode_visible_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_restricted_string_into(content, Charset::Visible, out)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    // -----------------------------------------------------------------------
    // Independent per-charset oracles (X.680, stated in a DIFFERENT shape from the production
    // `Charset::contains` formulation, so the biconditional proofs below are a genuine
    // de-tautologized conformance check, not a restatement of the parser's own control flow).
    // -----------------------------------------------------------------------

    /// The 74-byte PrintableString allow-list (X.680 §41), enumerated explicitly as a flat
    /// disjunction — a different shape from the production predicate's ASCII-class-helper +
    /// explicit-punctuation formulation, and loop-free so it composes into any caller's unwind
    /// bound without a separate one of its own (a hand-rolled linear scan would silently inherit
    /// whatever unwind bound the *caller* harness picked for its own loop, which is wrong for a
    /// 74-way scan — this sidesteps that).
    fn oracle_printable(b: u8) -> bool {
        matches!(
            b,
            b'A' | b'B' | b'C' | b'D' | b'E' | b'F' | b'G' | b'H' | b'I' | b'J' | b'K' | b'L'
                | b'M' | b'N' | b'O' | b'P' | b'Q' | b'R' | b'S' | b'T' | b'U' | b'V' | b'W'
                | b'X' | b'Y' | b'Z' | b'a' | b'b' | b'c' | b'd' | b'e' | b'f' | b'g' | b'h'
                | b'i' | b'j' | b'k' | b'l' | b'm' | b'n' | b'o' | b'p' | b'q' | b'r' | b's'
                | b't' | b'u' | b'v' | b'w' | b'x' | b'y' | b'z' | b'0' | b'1' | b'2' | b'3'
                | b'4' | b'5' | b'6' | b'7' | b'8' | b'9' | b' ' | b'\'' | b'(' | b')' | b'+'
                | b',' | b'-' | b'.' | b'/' | b':' | b'=' | b'?'
        )
    }

    fn oracle_ia5(b: u8) -> bool {
        b <= 0x7F
    }

    fn oracle_numeric(b: u8) -> bool {
        matches!(b, b'0'..=b'9') || b == 0x20
    }

    fn oracle_visible(b: u8) -> bool {
        (0x20..=0x7E).contains(&b)
    }

    // -----------------------------------------------------------------------
    // 1. Charset-exactness: production `Charset::contains` matches the independent oracle over
    //    *all* 256 bytes. The killer proof against widening/narrowing typos (`@` in Printable,
    //    `-`/`:` in Numeric, `0x80` in IA5, `0x7F` in Visible, etc.).
    // -----------------------------------------------------------------------

    #[kani::proof]
    fn charset_exactly_matches_oracle_printable() {
        let b: u8 = kani::any();
        assert!(Charset::Printable.contains(b) == oracle_printable(b));
    }

    #[kani::proof]
    fn charset_exactly_matches_oracle_ia5() {
        let b: u8 = kani::any();
        assert!(Charset::Ia5.contains(b) == oracle_ia5(b));
    }

    #[kani::proof]
    fn charset_exactly_matches_oracle_numeric() {
        let b: u8 = kani::any();
        assert!(Charset::Numeric.contains(b) == oracle_numeric(b));
    }

    #[kani::proof]
    fn charset_exactly_matches_oracle_visible() {
        let b: u8 = kani::any();
        assert!(Charset::Visible.contains(b) == oracle_visible(b));
    }

    // -----------------------------------------------------------------------
    // 2. `validate_content` accepts iff every byte is oracle-in-charset (ties the scanning loop to
    //    the per-byte oracle over short symbolic content).
    // -----------------------------------------------------------------------

    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_all_in_charset_printable() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let all_in = (0..n).all(|i| oracle_printable(buf[i]));
        assert!(validate_content(&buf[..n], Charset::Printable).is_ok() == all_in);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_all_in_charset_ia5() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let all_in = (0..n).all(|i| oracle_ia5(buf[i]));
        assert!(validate_content(&buf[..n], Charset::Ia5).is_ok() == all_in);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_all_in_charset_numeric() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let all_in = (0..n).all(|i| oracle_numeric(buf[i]));
        assert!(validate_content(&buf[..n], Charset::Numeric).is_ok() == all_in);
    }

    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_all_in_charset_visible() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let all_in = (0..n).all(|i| oracle_visible(buf[i]));
        assert!(validate_content(&buf[..n], Charset::Visible).is_ok() == all_in);
    }

    // -----------------------------------------------------------------------
    // 3. Round-trip: any short in-charset content encodes then decodes back to exactly itself,
    //    consuming exactly the produced bytes.
    // -----------------------------------------------------------------------

    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip_printable() {
        let content: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        kani::assume((0..n).all(|i| oracle_printable(content[i])));
        let mut out = [0u8; 16];
        let written = encode_restricted_string_into(&content[..n], Charset::Printable, &mut out).unwrap();
        let (dec, used) = decode_restricted_string(&out[..written], Charset::Printable).unwrap();
        assert!(used == written);
        assert!(dec == &content[..n]);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip_ia5() {
        let content: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        kani::assume((0..n).all(|i| oracle_ia5(content[i])));
        let mut out = [0u8; 16];
        let written = encode_restricted_string_into(&content[..n], Charset::Ia5, &mut out).unwrap();
        let (dec, used) = decode_restricted_string(&out[..written], Charset::Ia5).unwrap();
        assert!(used == written);
        assert!(dec == &content[..n]);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip_numeric() {
        let content: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        kani::assume((0..n).all(|i| oracle_numeric(content[i])));
        let mut out = [0u8; 16];
        let written = encode_restricted_string_into(&content[..n], Charset::Numeric, &mut out).unwrap();
        let (dec, used) = decode_restricted_string(&out[..written], Charset::Numeric).unwrap();
        assert!(used == written);
        assert!(dec == &content[..n]);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip_visible() {
        let content: [u8; 3] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 3);
        kani::assume((0..n).all(|i| oracle_visible(content[i])));
        let mut out = [0u8; 16];
        let written = encode_restricted_string_into(&content[..n], Charset::Visible, &mut out).unwrap();
        let (dec, used) = decode_restricted_string(&out[..written], Charset::Visible).unwrap();
        assert!(used == written);
        assert!(dec == &content[..n]);
    }

    // -----------------------------------------------------------------------
    // 4. Robustness: decode never panics, for any input and any charset.
    // -----------------------------------------------------------------------

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_never_panics() {
        let buf: [u8; 16] = kani::any();
        let charset: Charset = match kani::any::<u8>() % 4 {
            0 => Charset::Printable,
            1 => Charset::Ia5,
            2 => Charset::Numeric,
            _ => Charset::Visible,
        };
        let _ = decode_restricted_string(&buf, charset);
    }

    // -----------------------------------------------------------------------
    // 5. Structural anti-differential: the constructed (BER segmented) form of each charset's
    //    UNIVERSAL tag is rejected as `Constructed` for any well-formed 1-octet body.
    // -----------------------------------------------------------------------

    #[kani::proof]
    #[kani::unwind(16)]
    fn constructed_form_is_rejected_printable() {
        // 0x33 = class Universal, constructed bit set, number 19 (0x13 | 0x20).
        let a: u8 = kani::any();
        assert!(decode_restricted_string(&[0x33, 0x01, a], Charset::Printable) == Err(StringError::Constructed));
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn constructed_form_is_rejected_ia5() {
        // 0x36 = class Universal, constructed bit set, number 22 (0x16 | 0x20).
        let a: u8 = kani::any();
        assert!(decode_restricted_string(&[0x36, 0x01, a], Charset::Ia5) == Err(StringError::Constructed));
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn constructed_form_is_rejected_numeric() {
        // 0x32 = class Universal, constructed bit set, number 18 (0x12 | 0x20).
        let a: u8 = kani::any();
        assert!(decode_restricted_string(&[0x32, 0x01, a], Charset::Numeric) == Err(StringError::Constructed));
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn constructed_form_is_rejected_visible() {
        // 0x3A = class Universal, constructed bit set, number 26 (0x1A | 0x20).
        let a: u8 = kani::any();
        assert!(decode_restricted_string(&[0x3A, 0x01, a], Charset::Visible) == Err(StringError::Constructed));
    }

    // -----------------------------------------------------------------------
    // 6. Identifier canonicality: an accepted restricted string always begins with exactly the
    //    canonical identifier octet for its charset (rules out high-tag forms, wrong class/number,
    //    and the constructed form, without inspecting the delegation to `decode_tlv` by hand).
    // -----------------------------------------------------------------------

    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical_printable() {
        let buf: [u8; 16] = kani::any();
        if decode_restricted_string(&buf, Charset::Printable).is_ok() {
            assert!(buf[0] == Charset::Printable.identifier());
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical_ia5() {
        let buf: [u8; 16] = kani::any();
        if decode_restricted_string(&buf, Charset::Ia5).is_ok() {
            assert!(buf[0] == Charset::Ia5.identifier());
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical_numeric() {
        let buf: [u8; 16] = kani::any();
        if decode_restricted_string(&buf, Charset::Numeric).is_ok() {
            assert!(buf[0] == Charset::Numeric.identifier());
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical_visible() {
        let buf: [u8; 16] = kani::any();
        if decode_restricted_string(&buf, Charset::Visible).is_ok() {
            assert!(buf[0] == Charset::Visible.identifier());
        }
    }

    // -----------------------------------------------------------------------
    // 7. Error-class correctness: `OutOfCharset` always names the first offending byte/position.
    // -----------------------------------------------------------------------

    #[kani::proof]
    #[kani::unwind(6)]
    fn out_of_charset_reports_position() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 4);
        // Force at least one out-of-charset byte to exist within the chosen prefix.
        kani::assume(!(0..n).all(|i| oracle_numeric(buf[i])));
        if let Err(StringError::OutOfCharset { position, byte }) =
            validate_content(&buf[..n], Charset::Numeric)
        {
            // The reported position is the first violation: every earlier byte is in-charset, and
            // the reported byte is exactly the buffer's byte at that position.
            assert!(position < n);
            assert!(buf[position] == byte);
            assert!(!oracle_numeric(byte));
            assert!((0..position).all(|i| oracle_numeric(buf[i])));
        } else {
            panic!("expected OutOfCharset");
        }
    }

    // -----------------------------------------------------------------------
    // 8. Wrong-tag: a well-formed low-tag identifier that is neither this charset's own identifier
    //    nor its constructed form is `WrongTag`. Exercised for PrintableString.
    // -----------------------------------------------------------------------

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrong_tag_is_classified_printable() {
        let id: u8 = kani::any();
        kani::assume(id & 0x1F != 0x1F); // low-tag form (number 0..=30): single identifier octet
        kani::assume(id != Charset::Printable.identifier()); // 0x13 itself is accepted
        kani::assume(id != 0x33); // constructed PrintableString -> Constructed, not WrongTag
        let v: u8 = kani::any();
        kani::assume(oracle_printable(v)); // so a WrongTag input isn't confused with OutOfCharset
        assert!(decode_restricted_string(&[id, 0x01, v], Charset::Printable) == Err(StringError::WrongTag));
    }

    // The dispatch keys on `charset.tag_number()`, which differs per charset (19/22/18/26), so the
    // WrongTag path is proven per charset (not only for PrintableString): a refactor touching one
    // charset's tag comparison cannot silently escape into `Constructed`/`OutOfCharset`/`Ok`.

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrong_tag_is_classified_ia5() {
        let id: u8 = kani::any();
        kani::assume(id & 0x1F != 0x1F); // low-tag form
        kani::assume(id != Charset::Ia5.identifier()); // 0x16 itself is accepted
        kani::assume(id != 0x36); // constructed IA5String -> Constructed, not WrongTag
        let v: u8 = kani::any();
        kani::assume(oracle_ia5(v));
        assert!(decode_restricted_string(&[id, 0x01, v], Charset::Ia5) == Err(StringError::WrongTag));
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrong_tag_is_classified_numeric() {
        let id: u8 = kani::any();
        kani::assume(id & 0x1F != 0x1F); // low-tag form
        kani::assume(id != Charset::Numeric.identifier()); // 0x12 itself is accepted
        kani::assume(id != 0x32); // constructed NumericString -> Constructed, not WrongTag
        let v: u8 = kani::any();
        kani::assume(oracle_numeric(v));
        assert!(decode_restricted_string(&[id, 0x01, v], Charset::Numeric) == Err(StringError::WrongTag));
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrong_tag_is_classified_visible() {
        let id: u8 = kani::any();
        kani::assume(id & 0x1F != 0x1F); // low-tag form
        kani::assume(id != Charset::Visible.identifier()); // 0x1A itself is accepted
        kani::assume(id != 0x3A); // constructed VisibleString -> Constructed, not WrongTag
        let v: u8 = kani::any();
        kani::assume(oracle_visible(v));
        assert!(decode_restricted_string(&[id, 0x01, v], Charset::Visible) == Err(StringError::WrongTag));
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- accept cases ---

    #[test]
    fn printable_accepts_letters_digits_space_and_marks() {
        for &b in &[b'A', b'z', b'0', b' ', b'\'', b'?'] {
            assert!(Charset::Printable.contains(b), "byte {:#04x} should be printable", b);
        }
    }

    #[test]
    fn ia5_accepts_full_7_bit_range() {
        assert!(Charset::Ia5.contains(0x00));
        assert!(Charset::Ia5.contains(0x7F));
    }

    #[test]
    fn numeric_accepts_digits_and_space() {
        for b in b'0'..=b'9' {
            assert!(Charset::Numeric.contains(b));
        }
        assert!(Charset::Numeric.contains(b' '));
    }

    #[test]
    fn visible_accepts_space_through_tilde() {
        assert!(Charset::Visible.contains(0x20));
        assert!(Charset::Visible.contains(0x7E));
    }

    #[test]
    fn decodes_simple_printable() {
        // 13 05 "Hello" = PrintableString { "Hello" }
        let (content, used) =
            decode_restricted_string(&[0x13, 0x05, b'H', b'e', b'l', b'l', b'o'], Charset::Printable).unwrap();
        assert_eq!(used, 7);
        assert_eq!(content, b"Hello");
    }

    #[test]
    fn decodes_empty_content() {
        // 12 00 = NumericString {} — empty content is charset-valid (vacuously).
        let (content, used) = decode_restricted_string(&[0x12, 0x00], Charset::Numeric).unwrap();
        assert_eq!(used, 2);
        assert_eq!(content, b"");
    }

    #[test]
    fn roundtrips_printable_cn_like_string() {
        // A typical certificate CN: letters, comma, period, space are all allowed in PrintableString.
        let content = b"Hello, World.";
        let mut out = [0u8; 32];
        let n = encode_printable_string_into(content, &mut out).unwrap();
        assert_eq!(&out[..2], &[0x13, 0x0D]); // tag 0x13, length 13
        let (dec, used) = decode_printable_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, content);
    }

    #[test]
    fn roundtrips_ia5_email_like_string() {
        let content = b"user@example.com";
        let mut out = [0u8; 32];
        let n = encode_ia5_string_into(content, &mut out).unwrap();
        let (dec, used) = decode_ia5_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, content);
    }

    #[test]
    fn roundtrips_numeric_string() {
        let content = b"01 234 567";
        let mut out = [0u8; 32];
        let n = encode_numeric_string_into(content, &mut out).unwrap();
        let (dec, used) = decode_numeric_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, content);
    }

    #[test]
    fn roundtrips_visible_string() {
        let content = b"Visible ~ test!";
        let mut out = [0u8; 32];
        let n = encode_visible_string_into(content, &mut out).unwrap();
        let (dec, used) = decode_visible_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, content);
    }

    // --- seeded-bad specimens: PrintableString excludes @ * _ & (the classic differential trap) ---

    #[test]
    fn printable_rejects_at_star_underscore_ampersand() {
        for &b in &[b'@', b'*', b'_', b'&'] {
            assert!(!Charset::Printable.contains(b), "byte {:#04x} must NOT be printable", b);
            assert_eq!(
                validate_content(&[b], Charset::Printable),
                Err(StringError::OutOfCharset { position: 0, byte: b })
            );
        }
    }

    // --- seeded-bad: IA5String excludes >= 0x80 ---

    #[test]
    fn ia5_rejects_high_bit_bytes() {
        for &b in &[0x80u8, 0xFF] {
            assert!(!Charset::Ia5.contains(b));
            assert_eq!(
                validate_content(&[b], Charset::Ia5),
                Err(StringError::OutOfCharset { position: 0, byte: b })
            );
        }
    }

    // --- seeded-bad: NumericString excludes letters, hyphen, colon (the hyphen/colon trap) ---

    #[test]
    fn numeric_rejects_letters_hyphen_and_colon() {
        for &b in &[b'A', b'-', b':'] {
            assert!(!Charset::Numeric.contains(b), "byte {:#04x} must NOT be numeric", b);
            assert_eq!(
                validate_content(&[b], Charset::Numeric),
                Err(StringError::OutOfCharset { position: 0, byte: b })
            );
        }
    }

    // --- seeded-bad: VisibleString excludes control chars and DEL ---

    #[test]
    fn visible_rejects_control_chars_and_del() {
        for &b in &[0x1Fu8, 0x7F, 0x00] {
            assert!(!Charset::Visible.contains(b), "byte {:#04x} must NOT be visible", b);
            assert_eq!(
                validate_content(&[b], Charset::Visible),
                Err(StringError::OutOfCharset { position: 0, byte: b })
            );
        }
    }

    // --- seeded-bad: constructed form per type ---

    #[test]
    fn rejects_constructed_printable() {
        assert_eq!(
            decode_restricted_string(&[0x33, 0x01, b'A'], Charset::Printable),
            Err(StringError::Constructed)
        );
    }
    #[test]
    fn rejects_constructed_ia5() {
        assert_eq!(decode_restricted_string(&[0x36, 0x01, b'A'], Charset::Ia5), Err(StringError::Constructed));
    }
    #[test]
    fn rejects_constructed_numeric() {
        assert_eq!(
            decode_restricted_string(&[0x32, 0x01, b'0'], Charset::Numeric),
            Err(StringError::Constructed)
        );
    }
    #[test]
    fn rejects_constructed_visible() {
        assert_eq!(
            decode_restricted_string(&[0x3A, 0x01, b'A'], Charset::Visible),
            Err(StringError::Constructed)
        );
    }

    // --- seeded-bad: wrong tag ---

    #[test]
    fn rejects_wrong_tag() {
        // 0x02 = INTEGER, not any restricted string type.
        assert_eq!(decode_restricted_string(&[0x02, 0x01, 0x07], Charset::Printable), Err(StringError::WrongTag));
    }

    #[test]
    fn rejects_octet_string_tag_as_wrong_tag_for_ia5() {
        assert_eq!(decode_restricted_string(&[0x04, 0x01, b'A'], Charset::Ia5), Err(StringError::WrongTag));
    }

    // --- content-level rejection surfaced through the TLV entry point ---

    #[test]
    fn decode_rejects_out_of_charset_content() {
        // 13 01 40 = PrintableString { '@' } — well-formed TLV, bad content.
        assert_eq!(
            decode_restricted_string(&[0x13, 0x01, 0x40], Charset::Printable),
            Err(StringError::OutOfCharset { position: 0, byte: 0x40 })
        );
    }

    #[test]
    fn encode_rejects_out_of_charset_content() {
        // The encode path applies the same charset gate: out-of-charset content yields None (you
        // cannot produce an invalid restricted string), so a round-trip can never mint a differential.
        let mut out = [0u8; 16];
        assert_eq!(encode_printable_string_into(b"@", &mut out), None); // 0x40 not printable
        assert_eq!(encode_numeric_string_into(b"-", &mut out), None); // hyphen not numeric
        assert_eq!(encode_ia5_string_into(&[0x80], &mut out), None); // high bit set
        assert_eq!(encode_visible_string_into(&[0x7F], &mut out), None); // DEL not visible
    }

    #[test]
    fn decode_rejects_truncated_value() {
        use crate::tlv::TlvError;
        assert_eq!(
            decode_restricted_string(&[0x13, 0x05, b'H', b'i'], Charset::Printable),
            Err(StringError::Tlv(TlvError::Truncated))
        );
    }
}
