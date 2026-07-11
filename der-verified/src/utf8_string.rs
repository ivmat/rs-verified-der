//! DER UTF8String (X.690 §8.23 general note on string types; X.680 clause 41; type UNIVERSAL 12 /
//! identifier `0x0C`).
//!
//! A UTF8String's content is arbitrary UTF-8-encoded text (RFC 3629 / Unicode §3.9, Table 3-7
//! "Well-Formed UTF-8 Byte Sequences"). Unlike [`crate::restricted_string`]'s four ASCII charsets —
//! each a *per-byte* membership predicate — UTF-8 well-formedness is a **multi-byte** structural
//! property (a lead byte commits to a sequence length, and every continuation byte, and even the
//! *range* of the first continuation byte, is constrained by which lead byte started the
//! sequence), so this is a genuinely different kind of check and gets its own module rather than
//! folding into `Charset`.
//!
//! Like [`crate::octet_string`] / [`crate::restricted_string`], the DER structural constraint is
//! that BER's constructed (segmented) form is forbidden — the same parser-differential vector — so
//! this module also operates at the TLV level, composing [`crate::tlv`] rather than validating
//! pre-stripped content alone.
//!
//! **The UTF-8 well-formedness rules (verified against RFC 3629 / Unicode Table 3-7, not folklore):**
//! ```text
//!   Code Points          1st Byte   2nd Byte   3rd Byte   4th Byte
//!   U+0000  .. U+007F     00..7F
//!   U+0080  .. U+07FF     C2..DF     80..BF
//!   U+0800  .. U+0FFF     E0         A0..BF     80..BF
//!   U+1000  .. U+CFFF     E1..EC     80..BF     80..BF
//!   U+D000  .. U+D7FF     ED         80..9F     80..BF
//!   U+E000  .. U+FFFF     EE..EF     80..BF     80..BF
//!   U+10000 .. U+3FFFF    F0         90..BF     80..BF     80..BF
//!   U+40000 .. U+FFFFF    F1..F3     80..BF     80..BF     80..BF
//!   U+100000.. U+10FFFF   F4         80..8F     80..BF     80..BF
//! ```
//! The narrowed second-byte ranges on the `E0`/`ED`/`F0`/`F4` rows are exactly what closes the
//! classic differential classes: **overlong encodings** (`E0 80..9F ..` / `F0 80..8F .. ..` would
//! re-encode a code point representable in fewer bytes — `E0`'s second byte therefore starts at
//! `A0`, `F0`'s at `90`), **UTF-8-encoded surrogates** (`ED A0..BF ..` would encode `U+D800..U+DFFF`,
//! which is not a scalar value — `ED`'s second byte therefore stops at `9F`), and **code points
//! beyond `U+10FFFF`** (`F4 90..BF .. ..` would exceed the Unicode range — `F4`'s second byte
//! therefore stops at `8F`). Lead bytes `C0`, `C1` (always overlong 2-byte forms) and `F5..FF`
//! (always beyond `U+10FFFF`) are never valid; a byte `80..BF` as a *lead* is a stray continuation.
//!
//! **Scope boundary (see `DECISIONS.md`).** In scope: content-level UTF-8 well-formedness, plus the
//! structural constructed-form rejection. **Empty content is accepted** (the empty string is
//! well-formed UTF-8). Out of scope, as caller-applied profile concerns: Unicode **normalization**
//! (NFC/NFKC — a PKIX name-comparison rule, not a DER encoding rule), `SIZE`/length limits, and the
//! `DirectoryString` CHOICE (which of `UTF8String`/`PrintableString`/... an attribute may use — see
//! `restricted_string`'s D11 boundary, the same split). Well-formed UTF-8 has exactly one valid byte
//! sequence per code point (an overlong form is *invalid*, not merely a non-canonical alternate
//! spelling of a valid one), so well-formedness *is* the canonicality property here — there is no
//! separate "shortest form" check layered on top the way there is for, say, DER integers.

use crate::tag::{Class, Tag};
use crate::tlv::{decode_tlv, encode_tlv_into, TlvError};

/// The universal tag number for UTF8String.
pub const TAG: u32 = 12;

/// Why a UTF8String TLV, or its content alone, was rejected.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Utf8Error {
    /// The TLV envelope was malformed (bad identifier/length, indefinite length, over-read, …).
    Tlv(TlvError),
    /// The identifier is well formed but is not UNIVERSAL 12.
    WrongTag,
    /// UNIVERSAL 12 but in the *constructed* (BER segmented) form — forbidden in DER.
    Constructed,
    /// The content is not well-formed UTF-8. `position` is the length of the longest well-formed
    /// prefix — equivalently, the offset at which well-formedness first fails: `content[..position]`
    /// is itself well-formed UTF-8 (zero or more complete code points) and `content[..position + 1]`
    /// is not. This is exactly the standard library's
    /// `str::from_utf8(..).unwrap_err().valid_up_to()`. Note it is the **start of the ill-formed
    /// sequence**, not the offset of the specific rule-breaking byte within it — e.g. `E2 28 A1`
    /// reports `0` (as `str::from_utf8` does), since nothing precedes the sequence `0xE2` began.
    IllFormed {
        /// Length of the longest well-formed prefix (= `str::from_utf8`'s `valid_up_to()`).
        position: usize,
    },
}

/// The number of bytes a UTF-8 sequence beginning with lead byte `b` commits to, from the lead
/// byte's high bits alone (RFC 3629 §4): `0xxxxxxx` -> 1, `110xxxxx` -> 2, `1110xxxx` -> 3,
/// `11110xxx` -> 4. Any other pattern — including a `10xxxxxx` stray continuation byte, and the
/// bit patterns `11111xxx` (always invalid as a lead) — is not a valid lead byte.
fn sequence_len(b: u8) -> Option<usize> {
    if b & 0x80 == 0x00 {
        Some(1)
    } else if b & 0xE0 == 0xC0 {
        Some(2)
    } else if b & 0xF0 == 0xE0 {
        Some(3)
    } else if b & 0xF8 == 0xF0 {
        Some(4)
    } else {
        None
    }
}

/// Validate that `content` is well-formed UTF-8 (RFC 3629 / Unicode Table 3-7).
///
/// This is a **decoder**: it walks the content lead-byte by lead-byte, determines the committed
/// sequence length from the lead byte's bit pattern, requires that many continuation bytes (each
/// in `0x80..=0xBF`) to be *present*, **computes the code point** via the standard bit-shifts, and
/// then checks the code point against the value-space well-formedness conditions: not overlong
/// (2-byte `>= 0x80`, 3-byte `>= 0x800`, 4-byte `>= 0x10000`), not a UTF-16 surrogate
/// (`0xD800..=0xDFFF` excluded), and `<= 0x10FFFF`. This is a genuinely different shape from the
/// Kani oracle in `proofs` below, which instead states Table 3-7 directly as byte-range matching
/// with no code-point arithmetic — so a bug in one cannot hide behind the same bug in the other.
///
/// Empty content is accepted (vacuously well-formed). On failure, returns
/// [`Utf8Error::IllFormed`] naming the first byte not part of a well-formed sequence.
pub fn validate_utf8(content: &[u8]) -> Result<(), Utf8Error> {
    let mut i = 0;
    while i < content.len() {
        let lead = content[i];
        let len = match sequence_len(lead) {
            Some(l) => l,
            None => return Err(Utf8Error::IllFormed { position: i }),
        };
        if len == 1 {
            i += 1;
            continue;
        }
        if i + len > content.len() {
            return Err(Utf8Error::IllFormed { position: i });
        }
        // Require every continuation byte present and in 0x80..=0xBF, computing the code point by
        // the standard bit-shifts as we go.
        let mut cp: u32 = match len {
            2 => (lead & 0x1F) as u32,
            3 => (lead & 0x0F) as u32,
            _ => (lead & 0x07) as u32,
        };
        let mut k = 1;
        while k < len {
            let cont = content[i + k];
            if cont & 0xC0 != 0x80 {
                return Err(Utf8Error::IllFormed { position: i });
            }
            cp = (cp << 6) | (cont & 0x3F) as u32;
            k += 1;
        }
        // Value-space well-formedness: shortest form, not a surrogate, within the Unicode range.
        let min_cp: u32 = match len {
            2 => 0x80,
            3 => 0x800,
            _ => 0x10000,
        };
        if cp < min_cp {
            return Err(Utf8Error::IllFormed { position: i });
        }
        if (0xD800..=0xDFFF).contains(&cp) {
            return Err(Utf8Error::IllFormed { position: i });
        }
        if cp > 0x10FFFF {
            return Err(Utf8Error::IllFormed { position: i });
        }
        i += len;
    }
    Ok(())
}

/// Decode a complete DER UTF8String from the front of `input`, returning the content octets and
/// the total number of bytes consumed (`tag + length + value`).
///
/// Enforces UNIVERSAL 12, **primitive** form (else [`Utf8Error::Constructed`] — the
/// constructed/segmented form is BER-only), definite length and no over-read (via [`decode_tlv`]),
/// and well-formed UTF-8 content (else [`Utf8Error::IllFormed`]).
///
/// Tag identity is checked before primitiveness, so a well-formed TLV of a *different* type (e.g.
/// OCTET STRING `0x04`) is `WrongTag`, not `Constructed` — mirroring [`crate::octet_string`] /
/// [`crate::restricted_string`]. Trailing bytes after the string are ignored (as in [`decode_tlv`])
/// so this composes inside constructed types; a top-level caller that must consume the whole input
/// should check the returned length against `input.len()`.
pub fn decode_utf8_string(input: &[u8]) -> Result<(&[u8], usize), Utf8Error> {
    let (tlv, used) = decode_tlv(input).map_err(Utf8Error::Tlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != TAG {
        return Err(Utf8Error::WrongTag);
    }
    if tlv.tag.constructed {
        return Err(Utf8Error::Constructed);
    }
    validate_utf8(tlv.value)?;
    Ok((tlv.value, used))
}

/// Decode a complete DER UTF8String, exposing the validated content as `&str`.
///
/// A convenience over [`decode_utf8_string`]: since the content has just been proven well-formed
/// UTF-8, exposing it as `&str` needs no re-validation. Kept as a thin wrapper — the `&[u8]` form
/// above remains the primary decoder, consistent with the other codecs in this crate.
pub fn decode_utf8_str(input: &[u8]) -> Result<(&str, usize), Utf8Error> {
    let (content, used) = decode_utf8_string(input)?;
    // `validate_utf8` above already proved `content` well-formed UTF-8 per RFC 3629, so this branch
    // is unreachable (they agree by the `validate_iff_std` proof on bounded inputs, and both are
    // stateless per code point, so equivalence composes to any length). We still return the error
    // rather than `expect`/`unwrap`, so `decode_utf8_str` is **total** — no panic on untrusted input
    // even in this proven-unreachable case, preserving the crate's never-panic property.
    match core::str::from_utf8(content) {
        Ok(s) => Ok((s, used)),
        Err(e) => Err(Utf8Error::IllFormed { position: e.valid_up_to() }),
    }
}

/// Encode `content` as a canonical DER UTF8String (UNIVERSAL 12, primitive) into `out`.
///
/// Returns the number of bytes written, or `None` if `content` is not well-formed UTF-8, `out` is
/// too small, or `content` is longer than the length codec supports (`> u32::MAX`).
pub fn encode_utf8_string_into(content: &[u8], out: &mut [u8]) -> Option<usize> {
    if validate_utf8(content).is_err() {
        return None;
    }
    let tag = Tag { class: Class::Universal, constructed: false, number: TAG };
    encode_tlv_into(tag, content, out)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 proof floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    /// **Independent** oracle for RFC 3629 / Unicode Table 3-7 "Well-Formed UTF-8 Byte Sequences",
    /// stated directly as **byte-range matching** — no code-point arithmetic, no bit-shifts — a
    /// genuinely different shape from the production `validate_utf8` decoder above (which computes
    /// a code point and range-checks it). Consumes 1/2/3/4 bytes per the matched row; any mismatch
    /// or truncation is ill-formed. This is the gold-standard spec the biconditional proofs below
    /// check the decoder against, so a typo in either formulation cannot hide behind the other.
    fn oracle_wellformed_utf8(c: &[u8]) -> bool {
        let mut i = 0;
        while i < c.len() {
            let b0 = c[i];
            let ok = if (0x00..=0x7F).contains(&b0) {
                i += 1;
                true
            } else if (0xC2..=0xDF).contains(&b0) {
                i + 1 < c.len() && (0x80..=0xBF).contains(&c[i + 1]) && {
                    i += 2;
                    true
                }
            } else if b0 == 0xE0 {
                i + 2 < c.len()
                    && (0xA0..=0xBF).contains(&c[i + 1])
                    && (0x80..=0xBF).contains(&c[i + 2])
                    && {
                        i += 3;
                        true
                    }
            } else if (0xE1..=0xEC).contains(&b0) {
                i + 2 < c.len()
                    && (0x80..=0xBF).contains(&c[i + 1])
                    && (0x80..=0xBF).contains(&c[i + 2])
                    && {
                        i += 3;
                        true
                    }
            } else if b0 == 0xED {
                i + 2 < c.len()
                    && (0x80..=0x9F).contains(&c[i + 1])
                    && (0x80..=0xBF).contains(&c[i + 2])
                    && {
                        i += 3;
                        true
                    }
            } else if (0xEE..=0xEF).contains(&b0) {
                i + 2 < c.len()
                    && (0x80..=0xBF).contains(&c[i + 1])
                    && (0x80..=0xBF).contains(&c[i + 2])
                    && {
                        i += 3;
                        true
                    }
            } else if b0 == 0xF0 {
                i + 3 < c.len()
                    && (0x90..=0xBF).contains(&c[i + 1])
                    && (0x80..=0xBF).contains(&c[i + 2])
                    && (0x80..=0xBF).contains(&c[i + 3])
                    && {
                        i += 4;
                        true
                    }
            } else if (0xF1..=0xF3).contains(&b0) {
                i + 3 < c.len()
                    && (0x80..=0xBF).contains(&c[i + 1])
                    && (0x80..=0xBF).contains(&c[i + 2])
                    && (0x80..=0xBF).contains(&c[i + 3])
                    && {
                        i += 4;
                        true
                    }
            } else if b0 == 0xF4 {
                i + 3 < c.len()
                    && (0x80..=0x8F).contains(&c[i + 1])
                    && (0x80..=0xBF).contains(&c[i + 2])
                    && (0x80..=0xBF).contains(&c[i + 3])
                    && {
                        i += 4;
                        true
                    }
            } else {
                // C0, C1, 80..BF as a lead, F5..FF: never a valid lead byte.
                false
            };
            if !ok {
                return false;
            }
        }
        true
    }

    /// THE security property (de-tautologized): `validate_utf8` accepts iff the independent
    /// Table 3-7 oracle accepts, over every 4-byte buffer and every prefix length `<= 4`. Four
    /// bytes is sufficient to reach every single-code-point class, including every overlong,
    /// surrogate, and beyond-`U+10FFFF` boundary row (the longest row is 4 bytes).
    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_oracle() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        assert!(validate_utf8(&buf[..n]).is_ok() == oracle_wellformed_utf8(&buf[..n]));
    }

    /// Sequencing / state-reset across *multiple* code points: the same biconditional over a
    /// longer buffer, so a validator that mis-resets its position between sequences (e.g. failing
    /// to skip a full multi-byte sequence before checking the next lead byte) is caught. 6 bytes
    /// covers two 3-byte sequences or one 4-byte + a 2-byte, etc., while keeping unwind cost modest.
    #[kani::proof]
    #[kani::unwind(8)]
    fn validate_iff_oracle_multi() {
        let buf: [u8; 6] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 6);
        assert!(validate_utf8(&buf[..n]).is_ok() == oracle_wellformed_utf8(&buf[..n]));
    }

    /// Bonus independent oracle: agreement with `core::str::from_utf8`, the standard library's own
    /// RFC 3629 validator — a *third*, implementation-independent lineage (std's fast-path/SIMD
    /// internals are a wholly different code path from both `validate_utf8` and
    /// `oracle_wellformed_utf8` above). Kept only because it verifies cleanly within the same
    /// unwind bound as `validate_iff_oracle`; see the module report if this ever needs dropping.
    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_std() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        assert!(validate_utf8(&buf[..n]).is_ok() == core::str::from_utf8(&buf[..n]).is_ok());
    }

    /// Round-trip: any short well-formed content encodes then decodes back to exactly itself,
    /// consuming exactly the produced bytes.
    #[kani::proof]
    #[kani::unwind(16)]
    fn roundtrip() {
        let content: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        kani::assume(oracle_wellformed_utf8(&content[..n]));
        let mut out = [0u8; 16]; // 6 (max tag, unused here) + 5 (len) + 4 (value) fits comfortably
        let written = encode_utf8_string_into(&content[..n], &mut out).unwrap();
        let (dec, used) = decode_utf8_string(&out[..written]).unwrap();
        assert!(used == written);
        assert!(dec == &content[..n]);
    }

    /// Robustness: `decode_utf8_string` never panics on *any* input.
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_never_panics() {
        let buf: [u8; 8] = kani::any();
        let _ = decode_utf8_string(&buf);
    }

    /// Structural anti-differential: the *constructed* form of UNIVERSAL 12 (identifier `0x2C`) —
    /// BER's segmented UTF8String — is rejected as `Constructed` for any well-formed 1-octet body.
    #[kani::proof]
    #[kani::unwind(16)]
    fn constructed_form_is_rejected() {
        // 0x2C = class Universal, constructed bit set, number 12 (0x0C | 0x20).
        let a: u8 = kani::any();
        kani::assume(a < 0x80); // a well-formed 1-byte body (ASCII), so content-validity never masks this
        assert!(decode_utf8_string(&[0x2C, 0x01, a]) == Err(Utf8Error::Constructed));
    }

    /// Identifier canonicality: an accepted UTF8String always begins with exactly the canonical
    /// identifier octet `0x0C` (rules out high-tag forms, wrong class/number, and the constructed
    /// form, without inspecting the delegation to `decode_tlv` by hand).
    #[kani::proof]
    #[kani::unwind(16)]
    fn accepted_identifier_is_canonical() {
        let buf: [u8; 16] = kani::any();
        if decode_utf8_string(&buf).is_ok() {
            assert!(buf[0] == 0x0C);
        }
    }

    /// Error-class: a well-formed low-tag identifier that is neither UTF8String's own identifier
    /// nor its constructed form is `WrongTag`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn wrong_tag_is_classified() {
        let id: u8 = kani::any();
        kani::assume(id & 0x1F != 0x1F); // low-tag form (number 0..=30): single identifier octet
        kani::assume(id != 0x0C); // 0x0C itself is accepted
        kani::assume(id != 0x2C); // constructed UTF8String -> Constructed, not WrongTag
        let v: u8 = kani::any();
        kani::assume(v < 0x80); // in-range 1-byte content, so a WrongTag input isn't confused with IllFormed
        assert!(decode_utf8_string(&[id, 0x01, v]) == Err(Utf8Error::WrongTag));
    }

    /// Error-class correctness: `IllFormed { position }` names exactly the length of the longest
    /// well-formed prefix (= `str::from_utf8`'s `valid_up_to()`): `content[..position]` is
    /// well-formed *and* `content[..position + 1]` is not. The **maximality** clause is what makes
    /// this non-vacuous — without it, a lazy validator that always returned `position: 0` would
    /// satisfy the prefix clause alone (`content[..0]` is vacuously well-formed).
    #[kani::proof]
    #[kani::unwind(6)]
    fn ill_formed_reports_position() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 4);
        kani::assume(!oracle_wellformed_utf8(&buf[..n])); // force at least one ill-formed prefix
        if let Err(Utf8Error::IllFormed { position }) = validate_utf8(&buf[..n]) {
            assert!(position < n); // so `position + 1 <= n` and the slice below is in bounds
            assert!(oracle_wellformed_utf8(&buf[..position])); // prefix is well-formed ...
            assert!(!oracle_wellformed_utf8(&buf[..position + 1])); // ... and maximal (first failure)
        } else {
            panic!("expected IllFormed");
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    // --- accept cases: valid UTF-8 of increasing sequence length ---

    #[test]
    fn accepts_ascii() {
        assert!(validate_utf8(b"Hi").is_ok());
        assert_eq!(validate_utf8(b"Hi").is_ok(), core::str::from_utf8(b"Hi").is_ok());
    }

    #[test]
    fn accepts_empty() {
        assert!(validate_utf8(b"").is_ok());
        assert_eq!(validate_utf8(b"").is_ok(), core::str::from_utf8(b"").is_ok());
    }

    #[test]
    fn accepts_two_byte_e_acute() {
        // é = U+00E9 = C3 A9
        let x = [0xC3, 0xA9];
        assert!(validate_utf8(&x).is_ok());
        assert_eq!(validate_utf8(&x).is_ok(), core::str::from_utf8(&x).is_ok());
    }

    #[test]
    fn accepts_three_byte_euro_sign() {
        // € = U+20AC = E2 82 AC
        let x = [0xE2, 0x82, 0xAC];
        assert!(validate_utf8(&x).is_ok());
        assert_eq!(validate_utf8(&x).is_ok(), core::str::from_utf8(&x).is_ok());
    }

    #[test]
    fn accepts_four_byte_emoji() {
        // 😀 = U+1F600 = F0 9F 98 80
        let x = [0xF0, 0x9F, 0x98, 0x80];
        assert!(validate_utf8(&x).is_ok());
        assert_eq!(validate_utf8(&x).is_ok(), core::str::from_utf8(&x).is_ok());
    }

    // --- seeded-bad specimens: each MUST be rejected, and MUST agree with std ---

    fn assert_ill_formed_and_agrees_with_std(x: &[u8]) {
        assert!(validate_utf8(x).is_err(), "expected {:x?} to be rejected", x);
        assert_eq!(
            validate_utf8(x).is_ok(),
            core::str::from_utf8(x).is_ok(),
            "disagreement with std::str::from_utf8 on {:x?}",
            x
        );
    }

    #[test]
    fn rejects_overlong_encodings() {
        assert_ill_formed_and_agrees_with_std(&[0xC0, 0x80]); // overlong NUL
        assert_ill_formed_and_agrees_with_std(&[0xC1, 0xBF]); // overlong (C1 always invalid)
        assert_ill_formed_and_agrees_with_std(&[0xE0, 0x80, 0x80]); // overlong 3-byte
        assert_ill_formed_and_agrees_with_std(&[0xF0, 0x80, 0x80, 0x80]); // overlong 4-byte
    }

    #[test]
    fn rejects_surrogates() {
        assert_ill_formed_and_agrees_with_std(&[0xED, 0xA0, 0x80]); // U+D800
        assert_ill_formed_and_agrees_with_std(&[0xED, 0xBF, 0xBF]); // U+DFFF
    }

    #[test]
    fn rejects_beyond_max_code_point() {
        assert_ill_formed_and_agrees_with_std(&[0xF4, 0x90, 0x80, 0x80]); // U+110000
        assert_ill_formed_and_agrees_with_std(&[0xF5, 0x80, 0x80, 0x80]); // lead byte always invalid
    }

    #[test]
    fn rejects_stray_and_truncated_sequences() {
        assert_ill_formed_and_agrees_with_std(&[0x80]); // lone continuation byte
        assert_ill_formed_and_agrees_with_std(&[0xE2, 0x82]); // truncated 3-byte
        assert_ill_formed_and_agrees_with_std(&[0xF0, 0x9F, 0x98]); // truncated 4-byte
        assert_ill_formed_and_agrees_with_std(&[0xC3]); // truncated 2-byte
    }

    #[test]
    // The specimens are deliberately invalid literals — that is exactly what this test checks — so
    // the `invalid_from_utf8` lint (which flags `from_utf8` on a known-bad literal) is expected here.
    #[allow(invalid_from_utf8)]
    fn ill_formed_position_is_valid_up_to() {
        // `position` is the longest-well-formed-prefix length, matching std's `valid_up_to()` — NOT
        // the offset of the specific rule-breaking byte. For "E2 28 A1" the 0x28 breaks the sequence
        // 0xE2 started, but nothing precedes it, so `position` is 0 (as std reports), not 1.
        let x = [0xE2u8, 0x28, 0xA1];
        assert_eq!(validate_utf8(&x), Err(Utf8Error::IllFormed { position: 0 }));
        assert_eq!(core::str::from_utf8(&x).unwrap_err().valid_up_to(), 0);
        // With a valid ASCII byte first, the well-formed prefix has length 1.
        let y = [0x41u8, 0xE2, 0x28];
        assert_eq!(validate_utf8(&y), Err(Utf8Error::IllFormed { position: 1 }));
        assert_eq!(core::str::from_utf8(&y).unwrap_err().valid_up_to(), 1);
    }

    // --- round-trip via encode/decode ---

    #[test]
    fn roundtrips_ascii() {
        let content = b"Hello, UTF8String.";
        let mut out = [0u8; 32];
        let n = encode_utf8_string_into(content, &mut out).unwrap();
        assert_eq!(&out[..2], &[0x0C, content.len() as u8]); // tag 0x0C, length
        let (dec, used) = decode_utf8_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, content);
    }

    #[test]
    fn roundtrips_multibyte_content() {
        // "Café €" mixing 1-, 2-, and 3-byte sequences.
        let content = "Caf\u{e9} \u{20ac}".as_bytes();
        let mut out = [0u8; 32];
        let n = encode_utf8_string_into(content, &mut out).unwrap();
        let (dec, used) = decode_utf8_string(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(dec, content);
    }

    #[test]
    fn decodes_empty_content() {
        // 0C 00 = UTF8String {} — empty content is well-formed (vacuously).
        let (content, used) = decode_utf8_string(&[0x0C, 0x00]).unwrap();
        assert_eq!(used, 2);
        assert_eq!(content, b"");
    }

    #[test]
    fn decode_utf8_str_exposes_str() {
        let content = "hello".as_bytes();
        let mut out = [0u8; 16];
        let n = encode_utf8_string_into(content, &mut out).unwrap();
        let (s, used) = decode_utf8_str(&out[..n]).unwrap();
        assert_eq!(used, n);
        assert_eq!(s, "hello");
    }

    // --- structural rejection: constructed form and wrong tag ---

    #[test]
    fn rejects_constructed_form() {
        // 0x2C = constructed UTF8String (BER segmented). DER forbids it.
        assert_eq!(decode_utf8_string(&[0x2C, 0x01, b'A']), Err(Utf8Error::Constructed));
    }

    #[test]
    fn rejects_wrong_tag() {
        // 0x04 = OCTET STRING, not UTF8String.
        assert_eq!(decode_utf8_string(&[0x04, 0x01, b'A']), Err(Utf8Error::WrongTag));
    }

    #[test]
    fn rejects_well_formed_tlv_with_bad_content() {
        // 0C 01 80 = UTF8String { lone continuation byte } — well-formed TLV, ill-formed content.
        assert_eq!(decode_utf8_string(&[0x0C, 0x01, 0x80]), Err(Utf8Error::IllFormed { position: 0 }));
    }

    #[test]
    fn rejects_truncated_value() {
        use crate::tlv::TlvError;
        assert_eq!(decode_utf8_string(&[0x0C, 0x05, b'H', b'i']), Err(Utf8Error::Tlv(TlvError::Truncated)));
    }
}
