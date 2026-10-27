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
//!   characters included), **except the escape octet `0x1B`**. Any octet `>= 0x80` is invalid.
//!   X.690 Table 3 lists IA5String among the types that do not allow explicit escape sequences
//!   (§8.23.5.3), and every escape sequence starts with ESC, so the codec rejects `0x1B` with
//!   [`StringError::Ia5Escape`]. [`Charset::contains`] still answers the X.680 repertoire question
//!   (ESC is an IA5 character); the escape rule is applied by [`validate_content`]. CR, LF, TAB and
//!   the other C0 controls stay accepted.
//! - **NumericString** (UNIVERSAL 18, identifier `0x12`): digits `0x30..=0x39` and SPACE (`0x20`)
//!   **only** — notably excludes hyphen `-` and colon `:`, which some implementations wrongly permit.
//! - **VisibleString** / ISO646String (UNIVERSAL 26, identifier `0x1A`): the graphic characters
//!   `0x20..=0x7E` (SPACE through `~`) — excludes control characters and DEL (`0x7F`).
//!
//! **Scope boundary (see `DECISIONS.md`).** This module validates **charset-membership** — the
//! main content-level DER rule for these types (there is no "minimal encoding" concept here: the
//! octets *are* the value) — plus the X.690 Table 3 ban on escape sequences in IA5String. Empty content (zero octets) is **accepted** — vacuously charset-valid.
//! Out of scope, as a caller-applied X.509 profile layer (the same altitude split as the time types,
//! D10): `SIZE` / length-limit constraints, and the `DirectoryString` CHOICE rules (which of these
//! types — plus `TeletexString`/`UTF8String`/`BMPString` — an attribute is allowed to use).
//!
//! # Examples
//!
//! ```
//! use der_verified::restricted_string::decode_printable_string;
//!
//! // 13 05 "Hello" = PrintableString { "Hello" }
//! let (content, used) =
//!     decode_printable_string(&[0x13, 0x05, b'H', b'e', b'l', b'l', b'o']).unwrap();
//! assert_eq!(used, 7);
//! assert_eq!(content, b"Hello");
//!
//! // PrintableString excludes '@' -- a classic charset-widening differential.
//! assert!(decode_printable_string(&[0x13, 0x01, b'@']).is_err());
//! ```

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

    /// Whether byte `b` belongs to this type's X.680 character set. For IA5String this is the
    /// whole 7-bit repertoire, ESC (`0x1B`) included: the X.690 ban on escape sequences is not a
    /// repertoire rule and is applied in [`validate_content`] (see [`StringError::Ia5Escape`]).
    /// This is the production predicate; the Kani proofs check it against an *independently*-formulated oracle per charset
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
///
/// This enum is `#[non_exhaustive]`: later releases may add error variants, so a `match` over it
/// outside this crate needs a wildcard arm. The attribute only protects `match` expressions from
/// breaking on a new variant; stricter validation can still change behaviour incompatibly.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
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
    /// Content-level, IA5String only: the escape octet ESC (`0x1B`) at `position`. X.690 §8.23.5.3
    /// and Table 3 say IA5String does not allow explicit escape sequences, and §8.23.5.1 and
    /// §8.23.5.4 limit the escapes and announcers a type may carry; every ISO 2022 escape sequence
    /// or announcer starts with ESC, so ESC itself is rejected. All other IA5 octets, including
    /// CR, LF, TAB and the other C0 controls, stay accepted.
    Ia5Escape {
        /// Byte offset of the first ESC octet within the content.
        position: usize,
    },
}

/// Validate that every octet of `content` belongs to `charset`, and, for IA5String, that no octet
/// is ESC (`0x1B`, X.690 Table 3). Returns the *first* offending octet on failure
/// ([`StringError::OutOfCharset`] for an octet outside the charset, [`StringError::Ia5Escape`] for an
/// IA5 ESC octet; whichever comes earliest in the content is reported). Empty content is accepted
/// (vacuously charset-valid — see the module docs).
pub fn validate_content(content: &[u8], charset: Charset) -> Result<(), StringError> {
    let mut i = 0;
    while i < content.len() {
        let b = content[i];
        if !charset.contains(b) {
            return Err(StringError::OutOfCharset { position: i, byte: b });
        }
        if charset == Charset::Ia5 && b == 0x1B {
            return Err(StringError::Ia5Escape { position: i });
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
/// [`StringError::OutOfCharset`]; for IA5String also no ESC octet, else [`StringError::Ia5Escape`]).
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
/// Returns the number of bytes written, or `None` if any content byte is out-of-charset (for
/// IA5String this includes ESC, `0x1B`: the encoder never emits what the decoder rejects), `out` is
/// too small, or `content` is longer than the length codec supports (`> u32::MAX`).
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
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
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
pub fn encode_printable_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_restricted_string_into(content, Charset::Printable, out)
}

/// Encode a DER IA5String (UNIVERSAL 22).
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
pub fn encode_ia5_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_restricted_string_into(content, Charset::Ia5, out)
}

/// Encode a DER NumericString (UNIVERSAL 18).
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
pub fn encode_numeric_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    encode_restricted_string_into(content, Charset::Numeric, out)
}

/// Encode a DER VisibleString (UNIVERSAL 26).
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
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

    /// Whether the CODEC accepts octet `b` in `cs`: the X.680 repertoire oracle, minus ESC
    /// (`0x1B`) for IA5String (X.690 Table 3, §8.23.5.3: no explicit escape sequences).
    fn oracle_accepts(cs: Charset, b: u8) -> bool {
        oracle_of(cs, b) && !(cs == Charset::Ia5 && b == 0x1B)
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
        // IA5String: the 7-bit repertoire minus ESC (0x1B), the X.690 Table 3 escape rule.
        let all_in = (0..n).all(|i| oracle_ia5(buf[i]) && buf[i] != 0x1B);
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
        kani::assume((0..n).all(|i| oracle_ia5(content[i]) && content[i] != 0x1B));
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

    /// Robustness: `decode_restricted_string` never panics on any input **of any length up to 16
    /// octets** -- the buffer AND its length are both symbolic, so this is a bounded claim over the
    /// whole `0..=16`-octet domain, not just the single 16-octet length.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached for EACH of the four charsets
    /// individually (not merely "some charset, some input") -- so the per-charset `contains`
    /// dispatch and the TLV/tag-number wiring are each independently exercised on real content,
    /// not just that at least one arm happens to be live. Would NOT be SAT if
    /// `decode_restricted_string`'s body were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_never_panics() {
        let buf: [u8; 16] = kani::any();
        // Symbolic input length, matching the crate's established convention (see
        // `x509_tbs_certificate.rs`, `ecdsa_sig_value.rs`): so the "any input up to 16 octets"
        // claim above holds at every length in the domain, not just the single length 16.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let charset: Charset = match kani::any::<u8>() % 4 {
            0 => Charset::Printable,
            1 => Charset::Ia5,
            2 => Charset::Numeric,
            _ => Charset::Visible,
        };
        let result = decode_restricted_string(&buf[..len], charset);
        kani::cover(
            result.is_ok() && charset == Charset::Printable,
            "a well-formed PrintableString reaches the Ok tail",
        );
        kani::cover(
            result.is_ok() && charset == Charset::Ia5,
            "a well-formed IA5String reaches the Ok tail",
        );
        kani::cover(
            result.is_ok() && charset == Charset::Numeric,
            "a well-formed NumericString reaches the Ok tail",
        );
        kani::cover(
            result.is_ok() && charset == Charset::Visible,
            "a well-formed VisibleString reaches the Ok tail",
        );
        let _ = result;
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

    // -----------------------------------------------------------------------
    // 9. Decoder-level faithfulness (the typed TLV decoder's WHOLE acceptance set, not only the
    //    content validator): over a fully symbolic 6-octet buffer with symbolic length 0..=6,
    //    `decode_restricted_string` is classified EXACTLY, in the documented order, against
    //    - the independent per-charset allow-list oracles above (content; IA5String also refuses
    //      ESC, 0x1B, with its own `Ia5Escape` variant),
    //    - an independent literal UNIVERSAL tag number per charset (not `Charset::tag_number`),
    //    - `decode_tlv` as the separately-verified envelope reference.
    //    Without this, the content gate at `decode_restricted_string` (`validate_content(tlv.value,
    //    charset)?`) is reached by no Kani assertion on a non-encoder input.
    // -----------------------------------------------------------------------

    /// Dispatch to the independent allow-list oracle of `cs` (no call into `Charset::contains`).
    fn oracle_of(cs: Charset, b: u8) -> bool {
        match cs {
            Charset::Printable => oracle_printable(b),
            Charset::Ia5 => oracle_ia5(b),
            Charset::Numeric => oracle_numeric(b),
            Charset::Visible => oracle_visible(b),
        }
    }

    /// The X.680 UNIVERSAL tag number of `cs`, restated as literals (independent of
    /// `Charset::tag_number`).
    fn oracle_tag_number(cs: Charset) -> u32 {
        match cs {
            Charset::Printable => 19,
            Charset::Ia5 => 22,
            Charset::Numeric => 18,
            Charset::Visible => 26,
        }
    }

    /// The in-repertoire-but-refused branch for IA5String (its ESC octet): a cover that the branch is
    /// reached. Passed ONLY by the IA5 harness, so the cover is reachable in that harness alone (an
    /// unreachable cover would count as unsatisfied in the other three).
    fn esc_branch_ia5(_cs: Charset) {
        kani::cover(true, "IA5String ESC content reached");
    }

    /// The same branch for the other three charsets: it must be impossible, so it is asserted (dead
    /// but still checked); no cover is placed here.
    fn esc_branch_other(cs: Charset) {
        assert!(matches!(cs, Charset::Ia5), "only IA5String refuses an in-repertoire octet");
    }

    /// Shared body: classify `decode_restricted_string(buf[..len], cs)` exactly.
    /// Expected result, in the documented check order: envelope error (reference `decode_tlv`) ->
    /// `WrongTag` (class != UNIVERSAL or number != charset's) -> `Constructed` -> first
    /// out-of-charset content octet (position + byte) -> `Ok((tlv.value, used))`.
    /// `on_esc` is the in-repertoire-but-refused branch hook, chosen per harness (IA5 passes the
    /// cover, the others pass the impossibility assertion); every other check is shared.
    fn check_decode_faithful(cs: Charset, on_esc: fn(Charset)) {
        let buf: [u8; 6] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 6);
        let input = &buf[..len];
        let r = decode_restricted_string(input, cs);
        match decode_tlv(input) {
            Err(e) => {
                kani::cover(true, "envelope error branch reached");
                assert!(r == Err(StringError::Tlv(e)));
            }
            Ok((tlv, used)) => {
                if tlv.tag.class != Class::Universal || tlv.tag.number != oracle_tag_number(cs) {
                    kani::cover(true, "well-formed TLV of another type reached");
                    assert!(r == Err(StringError::WrongTag));
                } else if tlv.tag.constructed {
                    kani::cover(true, "constructed form of the charset's tag reached");
                    assert!(r == Err(StringError::Constructed));
                } else {
                    let v = tlv.value;
                    let mut first_bad: Option<usize> = None;
                    let mut i = 0;
                    while i < v.len() {
                        if !oracle_accepts(cs, v[i]) {
                            first_bad = Some(i);
                            break;
                        }
                        i += 1;
                    }
                    match first_bad {
                        Some(p) => {
                            if oracle_of(cs, v[p]) {
                                // only IA5String's ESC octet is in the repertoire yet refused
                                on_esc(cs);
                                assert!(r == Err(StringError::Ia5Escape { position: p }));
                            } else {
                                kani::cover(true, "out-of-charset content reached");
                                assert!(r == Err(StringError::OutOfCharset { position: p, byte: v[p] }));
                            }
                        }
                        None => {
                            kani::cover(!v.is_empty(), "non-empty in-charset content accepted");
                            kani::cover(v.is_empty(), "empty content accepted");
                            match r {
                                Ok((content, consumed)) => {
                                    assert!(consumed == used);
                                    assert!(content.len() == v.len());
                                    assert!(content == v);
                                }
                                Err(_) => panic!("well-formed in-charset universal primitive rejected"),
                            }
                        }
                    }
                }
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_is_faithful_printable() {
        check_decode_faithful(Charset::Printable, esc_branch_other);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_is_faithful_ia5() {
        check_decode_faithful(Charset::Ia5, esc_branch_ia5);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_is_faithful_numeric() {
        check_decode_faithful(Charset::Numeric, esc_branch_other);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_is_faithful_visible() {
        check_decode_faithful(Charset::Visible, esc_branch_other);
    }

    // -----------------------------------------------------------------------
    // 10. the eight convenience wrappers delegate EXACTLY to the generic
    //     codec with the RIGHT charset, and the generic encoder is a TOTAL oracle per charset.
    // -----------------------------------------------------------------------

    /// Shared body for the decode wrappers: over a fully symbolic 8-octet buffer with symbolic
    /// length `0..=8`, the per-type wrapper `f` returns the SAME `Result` as the generic decoder
    /// with the charset `cs` it must stand for. Inputs exist that tell the charsets apart (e.g. a
    /// well-formed `16 01 40` is accepted as IA5 but is `WrongTag` as Printable), so a wrapper that
    /// names the wrong charset is rejected. Cover: the accepted tail is reached for this wrapper.
    fn check_decode_wrapper(
        cs: Charset,
        f: fn(&[u8]) -> Result<(&[u8], usize), StringError>,
    ) {
        let buf: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let via_wrapper = f(input);
        let via_generic = decode_restricted_string(input, cs);
        kani::cover(via_generic.is_ok(), "the wrapper's accepted tail is reached");
        assert!(via_wrapper == via_generic);
    }

    /// Shared body for the encode wrappers: same `Option` and same emitted buffer as the generic
    /// encoder with `cs`, over symbolic content `0..=4`, symbolic capacity `0..=8` and a symbolic
    /// initial output buffer. Cover: a successful encode through this wrapper.
    fn check_encode_wrapper(cs: Charset, f: fn(&[u8], &mut [u8]) -> Option<usize>) {
        let content: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let cap: usize = kani::any();
        kani::assume(cap <= 8);
        let init: [u8; 8] = kani::any();
        let mut out_w = init;
        let mut out_g = init;
        let rw = f(&content[..n], &mut out_w[..cap]);
        let rg = encode_restricted_string_into(&content[..n], cs, &mut out_g[..cap]);
        kani::cover(rg.is_some(), "the wrapper's successful encode is reached");
        assert!(rw == rg);
        assert!(out_w == out_g);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_decode_printable_delegates() {
        check_decode_wrapper(Charset::Printable, decode_printable_string);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_decode_ia5_delegates() {
        check_decode_wrapper(Charset::Ia5, decode_ia5_string);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_decode_numeric_delegates() {
        check_decode_wrapper(Charset::Numeric, decode_numeric_string);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_decode_visible_delegates() {
        check_decode_wrapper(Charset::Visible, decode_visible_string);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_encode_printable_delegates() {
        check_encode_wrapper(Charset::Printable, encode_printable_string_into);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_encode_ia5_delegates() {
        check_encode_wrapper(Charset::Ia5, encode_ia5_string_into);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_encode_numeric_delegates() {
        check_encode_wrapper(Charset::Numeric, encode_numeric_string_into);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn wrapper_encode_visible_delegates() {
        check_encode_wrapper(Charset::Visible, encode_visible_string_into);
    }

    /// Shared body of the TOTAL encoder oracle for `cs`: content fully symbolic (`0..=4` octets,
    /// in-charset AND out-of-charset), capacity symbolic (`0..=8`), output buffer initially
    /// symbolic. `encode_restricted_string_into(content, cs, &mut out[..cap])` returns EXACTLY:
    /// - `None` if some content octet is outside the charset per the independent allow-list oracle
    ///   `oracle_of` (no call into `Charset::contains`), or is ESC (`0x1B`) in IA5String, whatever
    ///   the capacity;
    /// - else `None` if `cap < 2 + n` (identifier octet = the charset's literal UNIVERSAL tag number
    ///   as a primitive low-tag octet, one short-form length octet since `n <= 4`, then content);
    /// - else `Some(2 + n)` with emitted bytes exactly `tag n content` and every octet at or past the
    ///   written length untouched.
    /// On `None` the output is untouched (the documented write contract, "on `None` nothing is
    /// written to `out`; on `Some(n)` only `out[..n]` is written").
    /// Bounded-backing: content `<= 4`, capacity `<= 8`. Covers: out-of-charset content rejected
    /// despite ample capacity; in-charset rejected for too-small capacity; non-empty / empty
    /// success; success at exactly the minimal capacity.
    fn check_encode_exact(cs: Charset) {
        let content: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let content = &content[..n];
        let cap: usize = kani::any();
        kani::assume(cap <= 8);
        let init: [u8; 8] = kani::any();
        let mut out = init;
        let r = encode_restricted_string_into(content, cs, &mut out[..cap]);
        let all_in = (0..n).all(|i| oracle_accepts(cs, content[i]));
        let total = 2 + n;
        if !all_in {
            kani::cover(cap >= total, "out-of-charset content rejected despite ample capacity");
            assert!(r == None);
            assert!(out == init);
        } else if cap < total {
            kani::cover(true, "in-charset content rejected for insufficient capacity");
            assert!(r == None);
            assert!(out == init);
        } else {
            kani::cover(n > 0, "non-empty in-charset content encoded");
            kani::cover(n == 0, "empty content encoded");
            kani::cover(cap == total, "encoded at exactly the minimal capacity");
            assert!(r == Some(total));
            assert!(out[0] == oracle_tag_number(cs) as u8);
            assert!(out[1] as usize == n);
            let mut i = 0;
            while i < n {
                assert!(out[2 + i] == content[i]);
                i += 1;
            }
            let mut j = total;
            while j < 8 {
                assert!(out[j] == init[j]);
                j += 1;
            }
        }
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn encode_is_exact_printable() {
        check_encode_exact(Charset::Printable);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn encode_is_exact_ia5() {
        check_encode_exact(Charset::Ia5);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn encode_is_exact_numeric() {
        check_encode_exact(Charset::Numeric);
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn encode_is_exact_visible() {
        check_encode_exact(Charset::Visible);
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
    fn charset_identifier_is_the_der_identifier_octet() {
        // The canonical DER identifier octet: primitive, UNIVERSAL, this type's tag number --
        // exercised directly since `identifier()` (unlike `tag_number()`) is never invoked by
        // decode/encode and so is otherwise dead from a coverage standpoint.
        assert_eq!(Charset::Printable.identifier(), 0x13);
        assert_eq!(Charset::Ia5.identifier(), 0x16);
        assert_eq!(Charset::Numeric.identifier(), 0x12);
        assert_eq!(Charset::Visible.identifier(), 0x1A);
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

    // --- non-canonical framing (a lax/BER-tolerant reader would accept these; DER must not) ---

    #[test]
    fn rejects_high_tag_form_of_own_tag() {
        // 1F 13 = the high-tag (multi-octet) encoding of PrintableString's tag number 19 (X.690
        // §8.1.2.4.2). DER requires the low-tag single-octet form 0x13 for numbers <= 30, so the
        // tag codec rejects this as non-minimal.
        use crate::tag::TagError;
        use crate::tlv::TlvError;
        assert_eq!(
            decode_restricted_string(&[0x1F, 0x13, 0x01, b'A'], Charset::Printable),
            Err(StringError::Tlv(TlvError::Tag(TagError::NonMinimal)))
        );
    }

    #[test]
    fn rejects_non_minimal_length() {
        // 13 81 01 41 = length 1 in the long form (X.690 §8.1.3); DER requires the short form
        // (13 01 41). A lax parser tolerates the redundant long-form length; DER must not.
        use crate::length::LengthError;
        use crate::tlv::TlvError;
        assert_eq!(
            decode_restricted_string(&[0x13, 0x81, 0x01, b'A'], Charset::Printable),
            Err(StringError::Tlv(TlvError::Length(LengthError::NonMinimal)))
        );
    }

    // --- S4a: tests for rows that had no accept or reject test ---

    /// Rows X690-8.23.3, X690-8.23.3-a, X680-40b (reject): a restricted string is tagged
    /// [UNIVERSAL x]. The same tag number in the APPLICATION, context-specific or PRIVATE class
    /// is a different tag and is rejected. Identifier octets are literal.
    #[test]
    fn rejects_own_tag_number_in_a_non_universal_class() {
        // (charset, universal identifier, [application, context-specific, private] identifiers)
        let table: [(Charset, u8, [u8; 3]); 4] = [
            (Charset::Printable, 0x13, [0x53, 0x93, 0xD3]),
            (Charset::Ia5, 0x16, [0x56, 0x96, 0xD6]),
            (Charset::Numeric, 0x12, [0x52, 0x92, 0xD2]),
            (Charset::Visible, 0x1A, [0x5A, 0x9A, 0xDA]),
        ];
        for (charset, universal, others) in table {
            // '1' is in all four character sets, so only the identifier class is wrong
            assert_eq!(decode_restricted_string(&[universal, 0x01, b'1'], charset), Ok((&b"1"[..], 3)));
            for id in others {
                assert_eq!(
                    decode_restricted_string(&[id, 0x01, b'1'], charset),
                    Err(StringError::WrongTag),
                    "identifier {:#04x} for {:?}",
                    id,
                    charset
                );
            }
        }
    }

    /// Rows X690-8.23.5, X690-8.23.5.2 (accept): IA5String starts with ISO 646 G0 (registration
    /// 6) and the C0 controls (registration 1) assigned, so every octet 0x00..=0x7F is its own
    /// ISO 2022 code and is accepted unchanged. The one exception is ESC (0x1B): Table 3 allows
    /// no explicit escape sequences in IA5String, so that octet is rejected (see
    /// `rejects_ia5_escape_octet_and_names_its_position`) and is left out of this specimen.
    #[test]
    fn accepts_ia5_c0_and_g0_octets_as_their_iso2022_codes() {
        let mut input = [0u8; 2 + 127];
        input[..2].copy_from_slice(&[0x16, 127]);
        let mut n = 2;
        for i in 0..128u8 {
            if i != 0x1B {
                input[n] = i;
                n += 1;
            }
        }
        assert_eq!(n, input.len());
        let (content, used) = decode_restricted_string(&input, Charset::Ia5).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(content, &input[2..]);
        assert!(!content.contains(&0x1B));
    }

    /// Rows X690-8.23.5, X690-8.23.5.2 (accept): VisibleString starts with G0 (registration 6)
    /// only, so every graphic octet 0x20..=0x7E is its own ISO 2022 code and is accepted
    /// unchanged.
    #[test]
    fn accepts_visible_g0_octets_as_their_iso2022_codes() {
        let mut input = [0u8; 2 + 95];
        input[..2].copy_from_slice(&[0x1A, 95]);
        for (i, b) in (0x20u8..=0x7E).enumerate() {
            input[2 + i] = b;
        }
        let (content, used) = decode_restricted_string(&input, Charset::Visible).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(content, &input[2..]);
    }

    /// Rows X690-8.23.5, X690-8.23.5.2 (reject): an octet outside the sets assigned at the start
    /// of the string is rejected. IA5String has no C1 set (0x80..=0x9F) and no designated G1
    /// set (0xA0..=0xFF). PrintableString, NumericString and VisibleString have no C0 or C1
    /// set at all, so the control octets, DEL and every high octet are rejected.
    #[test]
    fn rejects_octets_outside_the_assigned_iso2022_sets() {
        let identifier = |c: Charset| c.identifier();
        for b in 0x80u8..=0xFF {
            assert_eq!(
                decode_restricted_string(&[identifier(Charset::Ia5), 0x02, b'A', b], Charset::Ia5),
                Err(StringError::OutOfCharset { position: 1, byte: b })
            );
        }
        for charset in [Charset::Printable, Charset::Numeric, Charset::Visible] {
            let id = identifier(charset);
            // C0 controls, DEL, C1 controls and the G1 area
            for b in (0x00u8..=0x1F).chain([0x7F]).chain(0x80..=0xFF) {
                assert_eq!(
                    decode_restricted_string(&[id, 0x02, b'1', b], charset),
                    Err(StringError::OutOfCharset { position: 1, byte: b }),
                    "{:?} byte {:#04x}",
                    charset,
                    b
                );
            }
        }
    }

    /// Rows X690-8.23.5.4 (accept): an announcer is ESC SP F (0x1B 0x20 0x46 ...). Without the
    /// ESC introducer the same SP and F octets are ordinary text and are accepted.
    #[test]
    fn accepts_announcer_tail_octets_without_the_escape_introducer() {
        for charset in [Charset::Printable, Charset::Visible, Charset::Ia5] {
            let input = [charset.identifier(), 0x03, b'A', 0x20, 0x46];
            let (content, used) = decode_restricted_string(&input, charset).unwrap();
            assert_eq!((content, used), (&[b'A', 0x20, 0x46][..], 5), "{:?}", charset);
        }
    }

    /// Rows X690-8.23.5.4 (reject): an announcer (ESC SP F) in PrintableString, NumericString
    /// or VisibleString is rejected at the ESC octet. These types never permit announcers.
    #[test]
    fn rejects_announcer_escape_sequence_in_printable_numeric_visible() {
        for charset in [Charset::Printable, Charset::Numeric, Charset::Visible] {
            let input = [charset.identifier(), 0x04, b'1', 0x1B, 0x20, 0x46];
            assert_eq!(
                decode_restricted_string(&input, charset),
                Err(StringError::OutOfCharset { position: 1, byte: 0x1B }),
                "{:?}",
                charset
            );
        }
    }

    /// Row X690-8.23.5.3 (accept): the escape ban of Table 3 is about escape sequences only. The
    /// C0 controls next to ESC (0x1A, 0x1C), CR, LF, TAB, NUL and DEL stay accepted in
    /// IA5String, in the decoder and in the encoder. `Charset::contains` keeps answering the
    /// X.680 repertoire question, so ESC is still an IA5 character there.
    #[test]
    fn accepts_ia5_controls_that_are_not_the_escape_octet() {
        let content: [u8; 9] = [0x0D, 0x0A, 0x09, 0x1A, 0x1C, 0x00, 0x7F, b'A', 0x1F];
        let mut input = [0u8; 2 + 9];
        input[..2].copy_from_slice(&[0x16, 9]);
        input[2..].copy_from_slice(&content);
        assert_eq!(decode_ia5_string(&input), Ok((&content[..], 11)));
        let mut out = [0u8; 16];
        assert_eq!(encode_ia5_string_into(&content, &mut out), Some(11));
        assert_eq!(&out[..11], &input[..]);
        assert!(Charset::Ia5.contains(0x1B));
    }

    /// Rows X690-8.23.5.1, X690-8.23.5.3 (reject): IA5String allows no explicit escape sequences,
    /// and every escape sequence starts with ESC (0x1B). The decoder rejects the ESC octet alone,
    /// at the start, in the middle and at the end, and reports its position. When an octet
    /// outside the repertoire comes first, that octet is reported instead (first offender wins).
    #[test]
    fn rejects_ia5_escape_octet_and_names_its_position() {
        assert_eq!(decode_ia5_string(&[0x16, 0x01, 0x1B]), Err(StringError::Ia5Escape { position: 0 }));
        assert_eq!(
            decode_ia5_string(&[0x16, 0x03, b'a', 0x1B, b'b']),
            Err(StringError::Ia5Escape { position: 1 })
        );
        assert_eq!(
            decode_ia5_string(&[0x16, 0x03, b'a', b'b', 0x1B]),
            Err(StringError::Ia5Escape { position: 2 })
        );
        // the first ESC is reported when there are two
        assert_eq!(
            decode_ia5_string(&[0x16, 0x03, 0x1B, b'a', 0x1B]),
            Err(StringError::Ia5Escape { position: 0 })
        );
        // an earlier out-of-repertoire octet wins; an earlier ESC wins over a later one
        assert_eq!(
            decode_ia5_string(&[0x16, 0x02, 0x80, 0x1B]),
            Err(StringError::OutOfCharset { position: 0, byte: 0x80 })
        );
        assert_eq!(
            decode_ia5_string(&[0x16, 0x02, 0x1B, 0x80]),
            Err(StringError::Ia5Escape { position: 0 })
        );
        assert_eq!(
            validate_content(&[b'x', 0x1B], Charset::Ia5),
            Err(StringError::Ia5Escape { position: 1 })
        );
        // the same octet is an out-of-repertoire octet in the other three types, not an escape
        for charset in [Charset::Printable, Charset::Numeric, Charset::Visible] {
            assert_eq!(
                validate_content(&[0x1B], charset),
                Err(StringError::OutOfCharset { position: 0, byte: 0x1B })
            );
        }
    }

    /// Row X690-8.23.5.4 (reject): an announcer is ESC SP F (0x1B 0x20 0x46 ...). In IA5String it
    /// is rejected at the ESC octet, the same as in the other three types, even though SP and F
    /// alone are ordinary IA5 text.
    #[test]
    fn rejects_announcer_escape_sequence_in_ia5() {
        assert_eq!(
            decode_ia5_string(&[0x16, 0x04, b'1', 0x1B, 0x20, 0x46]),
            Err(StringError::Ia5Escape { position: 1 })
        );
        // the tail without the introducer is accepted
        assert_eq!(decode_ia5_string(&[0x16, 0x03, b'1', 0x20, 0x46]), Ok((&b"1 F"[..], 5)));
    }

    /// Row X690-8.23.5.3 (reject): an encoder never emits what the decoder rejects. The IA5String
    /// encoder refuses content that holds an ESC octet and writes nothing.
    #[test]
    fn encode_refuses_ia5_escape_octet() {
        let mut out = [0xA5u8; 16];
        assert_eq!(encode_ia5_string_into(&[0x1B], &mut out), None);
        assert_eq!(encode_ia5_string_into(&[b'a', 0x1B, 0x20, 0x46], &mut out), None);
        assert_eq!(encode_restricted_string_into(&[b'a', 0x1B], Charset::Ia5, &mut out), None);
        assert_eq!(out, [0xA5u8; 16]);
        // the neighbouring octets 0x1A and 0x1C encode
        assert_eq!(encode_ia5_string_into(&[0x1A, 0x1C], &mut out), Some(4));
        assert_eq!(&out[..4], &[0x16, 0x02, 0x1A, 0x1C]);
    }

    /// Rows RFC5280-B-printable-specials, X680-41.4 (accept): the whole 74-character
    /// PrintableString repertoire is accepted, including the characters next to the two
    /// excluded ones (`?` and `A` around `@`; `Z` and `a` around `_`). The excluded `@` and
    /// `_` are rejected in the same context.
    #[test]
    fn accepts_the_full_printable_repertoire_next_to_at_and_underscore() {
        let repertoire: &[u8] =
            b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789 '()+,-./:=?";
        assert_eq!(repertoire.len(), 74);
        let mut input = [0u8; 2 + 74];
        input[..2].copy_from_slice(&[0x13, 74]);
        input[2..].copy_from_slice(repertoire);
        let (content, used) = decode_printable_string(&input).unwrap();
        assert_eq!((content, used), (repertoire, input.len()));
        // neighbours of the excluded characters in code order
        assert_eq!(decode_printable_string(&[0x13, 0x02, b'?', b'A']), Ok((&b"?A"[..], 4)));
        assert_eq!(decode_printable_string(&[0x13, 0x02, b'Z', b'a']), Ok((&b"Za"[..], 4)));
        // the excluded characters themselves
        assert_eq!(
            decode_printable_string(&[0x13, 0x02, b'?', b'@']),
            Err(StringError::OutOfCharset { position: 1, byte: b'@' })
        );
        assert_eq!(
            decode_printable_string(&[0x13, 0x02, b'Z', b'_']),
            Err(StringError::OutOfCharset { position: 1, byte: b'_' })
        );
    }

    /// Rows CODEC-restricted-string-encode-decode (accept): bytes the decoder accepts are
    /// re-encoded to the identical octets, for every character set.
    #[test]
    fn roundtrips_accepted_bytes_through_decode_then_encode() {
        let specimens: [(Charset, &[u8]); 6] = [
            (Charset::Printable, &[0x13, 0x05, b'H', b'e', b'l', b'l', b'o']),
            (Charset::Ia5, &[0x16, 0x0B, b'a', b'@', b'b', b'.', b'c', b'o', b'm', 0x00, 0x7F, b'~', b'!']),
            (Charset::Numeric, &[0x12, 0x04, b'1', b' ', b'2', b'3']),
            (Charset::Visible, &[0x1A, 0x03, b'~', b' ', b'!']),
            (Charset::Printable, &[0x13, 0x00]),
            (Charset::Visible, &[0x1A, 0x00]),
        ];
        for (charset, bytes) in specimens {
            let (content, used) = decode_restricted_string(bytes, charset).unwrap();
            assert_eq!(used, bytes.len());
            let mut out = [0u8; 32];
            let n = encode_restricted_string_into(content, charset, &mut out).unwrap();
            assert_eq!(&out[..n], bytes, "{:?}", charset);
        }
    }

    /// Rows CODEC-restricted-string-unique, CODEC-restricted-string-reject-nonder, X690-7.4,
    /// X690-10.2 (reject): the value "A" (or "1" for NumericString) has one accepted spelling.
    /// Every BER-valid alternate spelling is rejected: a constructed string with a valid
    /// segment, long-form lengths, a high-tag identifier, and an indefinite-length constructed
    /// string. Identifier octets are literal.
    #[test]
    fn rejects_alternate_spellings_of_one_restricted_string_value() {
        use crate::length::LengthError;
        use crate::tag::TagError;
        // (charset, primitive identifier, constructed identifier, tag number, character)
        let table: [(Charset, u8, u8, u8, u8); 4] = [
            (Charset::Printable, 0x13, 0x33, 19, b'A'),
            (Charset::Ia5, 0x16, 0x36, 22, b'A'),
            (Charset::Numeric, 0x12, 0x32, 18, b'1'),
            (Charset::Visible, 0x1A, 0x3A, 26, b'A'),
        ];
        for (charset, prim, cons, number, c) in table {
            assert_eq!(decode_restricted_string(&[prim, 0x01, c], charset), Ok((&[c][..], 3)));
            // constructed, one valid segment [UNIVERSAL x] holding the character
            assert_eq!(
                decode_restricted_string(&[cons, 0x03, prim, 0x01, c], charset),
                Err(StringError::Constructed),
                "{:?}",
                charset
            );
            // long-form lengths for length 1
            assert_eq!(
                decode_restricted_string(&[prim, 0x81, 0x01, c], charset),
                Err(StringError::Tlv(TlvError::Length(LengthError::NonMinimal)))
            );
            assert_eq!(
                decode_restricted_string(&[prim, 0x82, 0x00, 0x01, c], charset),
                Err(StringError::Tlv(TlvError::Length(LengthError::NonMinimal)))
            );
            // high-tag form of the tag number
            assert_eq!(
                decode_restricted_string(&[0x1F, number, 0x01, c], charset),
                Err(StringError::Tlv(TlvError::Tag(TagError::NonMinimal)))
            );
            // BER indefinite-length constructed form with a valid segment and end-of-contents
            assert_eq!(
                decode_restricted_string(&[cons, 0x80, prim, 0x01, c, 0x00, 0x00], charset),
                Err(StringError::Tlv(TlvError::Length(LengthError::Indefinite)))
            );
        }
    }
}
