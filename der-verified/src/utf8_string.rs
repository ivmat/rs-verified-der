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
//! **Forbidden control functions (X.690 §8.23.9 a–f).** Well-formed UTF-8 is not enough: X.690
//! allows the C0 and C1 control functions of ISO/IEC 6429 in a UTF8String (CR, LF, TAB, ...) but
//! forbids the ones that announce, designate or invoke an ISO/IEC 2022 escape or shift. This module
//! rejects exactly five code points, with [`Utf8Error::ForbiddenControl`]: `U+001B` ESC (`1B`),
//! `U+000E` SO (`0E`), `U+000F` SI (`0F`), `U+008E` SS2 (`C2 8E`) and `U+008F` SS3 (`C2 8F`). Every
//! other well-formed code point stays accepted, including all other C0 and C1 controls. A
//! malformed sequence is reported first: the forbidden-control check applies only to content that
//! is well-formed UTF-8, so [`Utf8Error::IllFormed`] keeps its `valid_up_to` meaning.
//!
//! **Scope boundary (see `DECISIONS.md`).** In scope: content-level UTF-8 well-formedness, the
//! forbidden control functions above, plus the structural constructed-form rejection. **Empty content is accepted** (the empty string is
//! well-formed UTF-8). Out of scope, as caller-applied profile concerns: Unicode **normalization**
//! (NFC/NFKC — a PKIX name-comparison rule, not a DER encoding rule), `SIZE`/length limits, and the
//! `DirectoryString` CHOICE (which of `UTF8String`/`PrintableString`/... an attribute may use — see
//! `restricted_string`'s D11 boundary, the same split). Well-formed UTF-8 has exactly one valid byte
//! sequence per code point (an overlong form is *invalid*, not merely a non-canonical alternate
//! spelling of a valid one), so well-formedness *is* the canonicality property here — there is no
//! separate "shortest form" check layered on top the way there is for, say, DER integers.
//!
//! # Examples
//!
//! ```
//! use der_verified::utf8_string::decode_utf8_str;
//!
//! // 0C 01 41 = UTF8String { "A" }
//! let (s, used) = decode_utf8_str(&[0x0C, 0x01, b'A']).unwrap();
//! assert_eq!(used, 3);
//! assert_eq!(s, "A");
//!
//! // A lone continuation byte (0x80) is not well-formed UTF-8.
//! assert!(decode_utf8_str(&[0x0C, 0x01, 0x80]).is_err());
//! ```

use crate::tag::{Class, Tag};
use crate::tlv::{decode_tlv, encode_tlv_into, TlvError};

/// The universal tag number for UTF8String.
pub const TAG: u32 = 12;

/// Why a UTF8String TLV, or its content alone, was rejected.
///
/// This enum is `#[non_exhaustive]`: later releases may add error variants, so a `match` over it
/// outside this crate needs a wildcard arm. The attribute only protects `match` expressions from
/// breaking on a new variant; stricter validation can still change behaviour incompatibly.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
#[non_exhaustive]
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
    /// The content is well-formed UTF-8 but holds a control function that X.690 §8.23.9 a)–f)
    /// forbids in a UTF8String, because it announces, designates or invokes an ISO/IEC 2022 escape
    /// or shift: `U+001B` ESC, `U+000E` SO, `U+000F` SI, `U+008E` SS2 or `U+008F` SS3. Other C0
    /// and C1 controls (CR, LF, TAB, ...) are allowed by §8.23.9 and are accepted. Only reported
    /// for well-formed content: ill-formed content is [`Utf8Error::IllFormed`].
    ForbiddenControl {
        /// Byte offset of the start of the first forbidden code point within the content.
        position: usize,
        /// The forbidden code point: `0x1B`, `0x0E`, `0x0F`, `0x8E` or `0x8F`.
        code_point: u32,
    },
}

/// Whether code point `cp` is one of the five control functions that X.690 §8.23.9 a)–f) forbids
/// in a UTF8String: ESC `U+001B`, SO `U+000E`, SI `U+000F`, SS2 `U+008E`, SS3 `U+008F`.
fn is_forbidden_control(cp: u32) -> bool {
    matches!(cp, 0x0E | 0x0F | 0x1B | 0x8E | 0x8F)
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
/// The walk also tracks the first of the five control functions that X.690 §8.23.9 a)–f) forbids
/// (ESC, SO, SI, SS2, SS3). Well-formedness is decided first: when `content` is not well-formed
/// the result is [`Utf8Error::IllFormed`] whatever controls come before the defect; when it is
/// well-formed and holds a forbidden control the result is [`Utf8Error::ForbiddenControl`] naming
/// the first one.
///
/// Empty content is accepted (vacuously well-formed). On failure, returns
/// [`Utf8Error::IllFormed`] naming the first byte not part of a well-formed sequence.
pub fn validate_utf8(content: &[u8]) -> Result<(), Utf8Error> {
    let mut i = 0;
    let mut forbidden: Option<(usize, u32)> = None;
    while i < content.len() {
        let lead = content[i];
        let len = match sequence_len(lead) {
            Some(l) => l,
            None => return Err(Utf8Error::IllFormed { position: i }),
        };
        if len == 1 {
            if forbidden.is_none() && is_forbidden_control(lead as u32) {
                forbidden = Some((i, lead as u32));
            }
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
            // EQUIVALENT-MUTANT: disjoint bitfields, |≡^ (cargo-mutants survivor, not a coverage
            // gap) — `cp << 6` always has its low 6 bits zero, and `cont & 0x3F` fits in 6 bits.
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
        if forbidden.is_none() && is_forbidden_control(cp) {
            forbidden = Some((i, cp));
        }
        i += len;
    }
    match forbidden {
        Some((position, code_point)) => Err(Utf8Error::ForbiddenControl { position, code_point }),
        None => Ok(()),
    }
}

/// Decode a complete DER UTF8String from the front of `input`, returning the content octets and
/// the total number of bytes consumed (`tag + length + value`).
///
/// Enforces UNIVERSAL 12, **primitive** form (else [`Utf8Error::Constructed`] — the
/// constructed/segmented form is BER-only), definite length and no over-read (via [`decode_tlv`]),
/// and well-formed UTF-8 content (else [`Utf8Error::IllFormed`]) free of the control functions
/// X.690 §8.23.9 forbids (else [`Utf8Error::ForbiddenControl`]).
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
/// Returns the number of bytes written, or `None` if `content` is not well-formed UTF-8 or holds
/// one of the control functions X.690 §8.23.9 forbids (ESC, SO, SI, SS2, SS3; the encoder never
/// emits what the decoder rejects), `out` is too small, or `content` is longer than the length codec supports (`> u32::MAX`).
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
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

    /// Independent oracle for the X.690 §8.23.9 forbidden controls, valid for WELL-FORMED UTF-8
    /// only: ESC `1B`, SO `0E` and SI `0F` are one-octet code points (and no continuation or lead
    /// octet can equal them, since those are `>= 0x80`); SS2 and SS3 are the two-octet sequences
    /// `C2 8E` and `C2 8F` (`C2` is a lead octet only, never a continuation octet). Stated as
    /// byte patterns, with no code-point arithmetic and no call into `is_forbidden_control`.
    fn oracle_has_forbidden_control(c: &[u8]) -> bool {
        let mut i = 0;
        while i < c.len() {
            if c[i] == 0x1B || c[i] == 0x0E || c[i] == 0x0F {
                return true;
            }
            if c[i] == 0xC2 && i + 1 < c.len() && (c[i + 1] == 0x8E || c[i + 1] == 0x8F) {
                return true;
            }
            i += 1;
        }
        false
    }

    /// The first forbidden control of a `&str`, by the standard library's own `char` iteration
    /// (a different lineage from both `validate_utf8` and the byte-pattern oracle above): byte
    /// offset and code point.
    fn std_first_forbidden(s: &str) -> Option<(usize, u32)> {
        s.char_indices()
            .find(|&(_, c)| matches!(c, '\u{1B}' | '\u{0E}' | '\u{0F}' | '\u{8E}' | '\u{8F}'))
            .map(|(i, c)| (i, c as u32))
    }

    /// THE security property (de-tautologized): `validate_utf8` accepts iff the independent
    /// Table 3-7 oracle accepts and the content holds none of the five X.690 §8.23.9 forbidden
    /// controls (ESC, SO, SI, SS2, SS3), over every 4-byte buffer and every prefix length `<= 4`. Four
    /// bytes is sufficient to reach every single-code-point class, including every overlong,
    /// surrogate, and beyond-`U+10FFFF` boundary row (the longest row is 4 bytes).
    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_oracle() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        assert!(
            validate_utf8(&buf[..n]).is_ok()
                == (oracle_wellformed_utf8(&buf[..n]) && !oracle_has_forbidden_control(&buf[..n]))
        );
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
        assert!(
            validate_utf8(&buf[..n]).is_ok()
                == (oracle_wellformed_utf8(&buf[..n]) && !oracle_has_forbidden_control(&buf[..n]))
        );
    }

    /// Bonus independent oracle: agreement with `core::str::from_utf8`, the standard library's own
    /// RFC 3629 validator — a *third*, implementation-independent lineage (std's fast-path/SIMD
    /// internals are a wholly different code path from both `validate_utf8` and
    /// `oracle_wellformed_utf8` above). Kept only because it verifies cleanly within the same
    /// unwind bound as `validate_iff_oracle`; see the module report if this ever needs dropping.
    /// With the X.690 §8.23.9 rule, "accepts" means std accepts AND the standard library's own
    /// `char` iteration finds none of the five forbidden controls (`std_first_forbidden`).
    #[kani::proof]
    #[kani::unwind(6)]
    fn validate_iff_std() {
        let buf: [u8; 4] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 4);
        let std_ok = match core::str::from_utf8(&buf[..n]) {
            Ok(s) => std_first_forbidden(s).is_none(),
            Err(_) => false,
        };
        assert!(validate_utf8(&buf[..n]).is_ok() == std_ok);
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
        kani::assume(!oracle_has_forbidden_control(&content[..n]));
        let mut out = [0u8; 16]; // 6 (max tag, unused here) + 5 (len) + 4 (value) fits comfortably
        let written = encode_utf8_string_into(&content[..n], &mut out).unwrap();
        let (dec, used) = decode_utf8_string(&out[..written]).unwrap();
        assert!(used == written);
        assert!(dec == &content[..n]);
    }

    /// Robustness: `decode_utf8_string` never panics on *any* input.
    ///
    /// Robustness: `decode_utf8_string` never panics on any input **of any length up to 8 octets**
    /// -- the buffer AND its length are both symbolic, so this is a bounded claim over the whole
    /// `0..=8`-octet domain, not just the single 8-octet length.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached AND, separately, that a genuine
    /// non-empty (well-formed UTF-8) value is accepted -- so the TLV envelope, tag check, and the
    /// `validate_utf8` content walk all pass on real content, not merely on the trivial empty
    /// value. Would NOT be SAT if `decode_utf8_string`'s body were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_never_panics() {
        let buf: [u8; 8] = kani::any();
        // Symbolic input length, matching the crate's established convention (see
        // `x509_tbs_certificate.rs`, `ecdsa_sig_value.rs`): so the "any input up to 8 octets"
        // claim above holds at every length in the domain, not just the single length 8.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let result = decode_utf8_string(&buf[..len]);
        kani::cover(result.is_ok(), "a well-formed UTF8String reaches decode_utf8_string's Ok tail");
        if let Ok((content, _used)) = result {
            kani::cover(!content.is_empty(), "a non-empty well-formed UTF-8 value is accepted");
        }
        let _ = result;
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
    /// well-formed prefix, i.e. EXACTLY `core::str::from_utf8`'s `valid_up_to()` (the external
    /// oracle, asserted with `==` below). The two local clauses -- `content[..position]` is
    /// well-formed *and* `content[..position + 1]` is not -- are kept as sanity checks, but they
    /// alone are only a LOCAL boundary property: they hold at ANY earlier multi-byte-lead boundary
    /// too (e.g. `41 C3 A9 FF`: true position 3, yet `p = 1` also satisfies both), so they cannot
    /// distinguish the longest valid prefix from an earlier sequence start. The equality with
    /// `valid_up_to()` is what pins the exact (maximal) position. Bound: content `1..=6` octets
    /// (so a failure after >= 4 octets of valid multi-byte sequences, e.g. `C3 A9 C3 A9 FF`, is in
    /// the domain and `position` cannot be clamped to 3).
    #[kani::proof]
    #[kani::unwind(8)]
    fn ill_formed_reports_position() {
        let buf: [u8; 6] = kani::any();
        let n: usize = kani::any();
        kani::assume(n >= 1 && n <= 6);
        kani::assume(!oracle_wellformed_utf8(&buf[..n])); // force at least one ill-formed prefix
        if let Err(Utf8Error::IllFormed { position }) = validate_utf8(&buf[..n]) {
            assert!(position < n); // so `position + 1 <= n` and the slice below is in bounds
            assert!(oracle_wellformed_utf8(&buf[..position])); // prefix is well-formed ...
            assert!(!oracle_wellformed_utf8(&buf[..position + 1])); // ... and locally maximal
            // Exact longest-valid-prefix, against the external (other-author) oracle:
            assert!(position == core::str::from_utf8(&buf[..n]).unwrap_err().valid_up_to());
        } else {
            panic!("expected IllFormed");
        }
    }

    /// Decoder-level faithfulness (the typed TLV decoder's WHOLE acceptance set, not only the
    /// content validator): over a fully symbolic 6-octet buffer with symbolic length `0..=6`
    /// (content <= 4 octets for a short-form length), `decode_utf8_string` is classified EXACTLY,
    /// in the documented check order, against
    /// - `decode_tlv` as the separately-verified envelope reference,
    /// - a literal UNIVERSAL tag number 12 (not the `TAG` const),
    /// - `core::str::from_utf8` as the content oracle (external, other author; no call into
    ///   `validate_utf8`): ill-formed content -> `IllFormed { position: valid_up_to() }` exactly;
    ///   well-formed content with a forbidden control -> `ForbiddenControl` at the first one
    ///   (`std_first_forbidden`).
    ///
    /// Without this, the content gate `validate_utf8(tlv.value)?` in `decode_utf8_string` is reached
    /// by no Kani assertion on a non-encoder input (`constructed_form_is_rejected` /
    /// `wrong_tag_is_classified` assume ASCII bodies).
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_is_faithful() {
        let buf: [u8; 6] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= 6);
        let input = &buf[..len];
        let r = decode_utf8_string(input);
        match decode_tlv(input) {
            Err(e) => {
                kani::cover(true, "envelope error branch reached");
                assert!(r == Err(Utf8Error::Tlv(e)));
            }
            Ok((tlv, used)) => {
                if tlv.tag.class != Class::Universal || tlv.tag.number != 12 {
                    kani::cover(true, "well-formed TLV of another type reached");
                    assert!(r == Err(Utf8Error::WrongTag));
                } else if tlv.tag.constructed {
                    kani::cover(true, "constructed UTF8String reached");
                    assert!(r == Err(Utf8Error::Constructed));
                } else {
                    let v = tlv.value;
                    match core::str::from_utf8(v) {
                        Err(e) => {
                            kani::cover(true, "ill-formed content reached");
                            assert!(r == Err(Utf8Error::IllFormed { position: e.valid_up_to() }));
                        }
                        Ok(text) => match std_first_forbidden(text) {
                            Some((p, cp)) => {
                                kani::cover(true, "well-formed content with a forbidden control reached");
                                assert!(r == Err(Utf8Error::ForbiddenControl { position: p, code_point: cp }));
                            }
                            None => {
                                kani::cover(!v.is_empty(), "non-empty well-formed content accepted");
                                kani::cover(v.is_empty(), "empty content accepted");
                                match r {
                                    Ok((content, consumed)) => {
                                        assert!(consumed == used);
                                        assert!(content.len() == v.len());
                                        assert!(content == v);
                                    }
                                    Err(_) => panic!("well-formed UTF-8 universal primitive rejected"),
                                }
                            }
                        },
                    }
                }
            }
        }
    }

    /// **`decode_utf8_str` is EXACT delegation to `decode_utf8_string`**.
    /// Over a fully symbolic 8-octet buffer with symbolic length `0..=8` (the bound of
    /// `decode_never_panics`): on EVERY input the `&str` wrapper's result is the mapping of the byte
    /// decoder's result -- the same error on `Err`; on `Ok((content, used))` the same consumed
    /// length `used` and a `&str` whose bytes ARE the content window (same pointer, same length,
    /// same bytes), so a wrapper that returns `""` (or any other string) on success is rejected.
    ///
    /// Covers: a non-empty content accepted, an empty content accepted, and an error passed through.
    #[kani::proof]
    #[kani::unwind(16)]
    fn decode_str_is_exact_delegation() {
        let buf: [u8; 8] = kani::any();
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let bytes = decode_utf8_string(input);
        let text = decode_utf8_str(input);
        match bytes {
            Err(e) => {
                kani::cover(true, "an error of decode_utf8_string is reached");
                assert!(text == Err(e));
            }
            Ok((content, used)) => {
                kani::cover(!content.is_empty(), "non-empty content accepted");
                kani::cover(content.is_empty(), "empty content accepted");
                match text {
                    Ok((s, u)) => {
                        assert!(u == used);
                        assert!(s.len() == content.len());
                        assert!(s.as_bytes().as_ptr() == content.as_ptr()); // the SAME window
                        assert!(s.as_bytes() == content);
                    }
                    Err(_) => panic!("decode_utf8_str rejected an input decode_utf8_string accepted"),
                }
            }
        }
    }

    /// **Total encoder oracle**. Content is fully symbolic (`0..=6`
    /// octets, valid AND ill-formed UTF-8), the output capacity is symbolic (`0..=10`) and the output
    /// buffer starts symbolic. `encode_utf8_string_into(content, &mut out[..cap])` returns EXACTLY:
    /// - `None` when `core::str::from_utf8(content)` rejects the content (independent external
    ///   validator; no call into `validate_utf8`) or the content holds a forbidden control
    ///   (ESC, SO, SI, SS2, SS3; `std_first_forbidden`), whatever the capacity;
    /// - else `None` when `cap < 2 + n` (identifier octet `0x0C`, one short-form length octet since
    ///   `n <= 6 < 0x80`, then the `n` content octets);
    /// - else `Some(2 + n)`, with the emitted bytes exactly `0C n content` and every octet at or
    ///   past the written length untouched.
    /// On `None` the output is left untouched (the documented write contract, "on `None` nothing is
    /// written to `out`; on `Some(n)` only `out[..n]` is written"; asserted so a partial write before
    /// failing would be caught).
    ///
    /// Bounded-backing: content `<= 6` octets, capacity `<= 10`, unwind 16.
    /// Covers: ill-formed content rejected with ample capacity; well-formed content rejected for
    /// too small a capacity; success with non-empty content; success with empty content; success at
    /// exactly the minimal capacity.
    #[kani::proof]
    #[kani::unwind(16)]
    fn encode_is_exact_over_content_and_capacity() {
        let content: [u8; 6] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 6);
        let content = &content[..n];
        let cap: usize = kani::any();
        kani::assume(cap <= 10);
        let init: [u8; 10] = kani::any();
        let mut out = init;
        let r = encode_utf8_string_into(content, &mut out[..cap]);
        // encodable = well-formed UTF-8 (external validator) with no X.690 §8.23.9 forbidden control
        let well_formed = match core::str::from_utf8(content) {
            Ok(s) => std_first_forbidden(s).is_none(),
            Err(_) => false,
        };
        let total = 2 + n;
        if !well_formed {
            kani::cover(cap >= total, "ill-formed content rejected despite ample capacity");
            assert!(r == None);
            assert!(out == init);
        } else if cap < total {
            kani::cover(true, "well-formed content rejected for insufficient capacity");
            assert!(r == None);
            assert!(out == init);
        } else {
            kani::cover(n > 0, "non-empty well-formed content encoded");
            kani::cover(n == 0, "empty content encoded");
            kani::cover(cap == total, "encoded at exactly the minimal capacity");
            assert!(r == Some(total));
            assert!(out[0] == 0x0C);
            assert!(out[1] as usize == n);
            let mut i = 0;
            while i < n {
                assert!(out[2 + i] == content[i]);
                i += 1;
            }
            let mut j = total;
            while j < 10 {
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

    // --- non-canonical framing (a lax/BER-tolerant reader would accept these; DER must not) ---

    #[test]
    fn rejects_high_tag_form_of_tag_12() {
        // 1F 0C = the high-tag (multi-octet) encoding of tag number 12 (X.690 §8.1.2.4.2). DER
        // requires the low-tag single-octet form 0x0C for numbers <= 30, so the tag codec rejects
        // this as non-minimal: a non-canonical UTF8String identifier is never accepted.
        use crate::tag::TagError;
        use crate::tlv::TlvError;
        assert_eq!(
            decode_utf8_string(&[0x1F, 0x0C, 0x01, b'A']),
            Err(Utf8Error::Tlv(TlvError::Tag(TagError::NonMinimal)))
        );
    }

    // --- mutation-killing boundary/regression tests (cargo-mutants survivors) ---

    #[test]
    fn two_byte_lead_uses_all_five_low_bits() {
        // 0xC8 0x80: a valid 2-byte sequence (lead 0xC8 is in the legal C2..DF range). Its low 5
        // bits (used to seed the code point, `lead & 0x1F`) are `01000` = 8, distinct from its low
        // 3 bits (`000` = 0): if the match arm seeding `cp` for a 2-byte sequence were deleted (so
        // it fell through to the 4-byte-shaped `& 0x07` seed instead), this input's derived code
        // point would drop from 0x200 to 0x000, spuriously classified as overlong (< 0x80) and
        // rejected. Confirms it is accepted, pinning that the len==2 arm is live.
        assert!(validate_utf8(&[0xC8, 0x80]).is_ok());
        assert_eq!(
            validate_utf8(&[0xC8, 0x80]).is_ok(),
            core::str::from_utf8(&[0xC8, 0x80]).is_ok()
        );
    }

    #[test]
    fn accepts_two_byte_minimum_code_point_boundary() {
        // 0xC2 0x80 = U+0080, the SMALLEST code point requiring the 2-byte form (`cp == min_cp`
        // exactly). Must be accepted: a `<` -> `<=` mutation on the overlong check would reject
        // this boundary value.
        assert!(validate_utf8(&[0xC2, 0x80]).is_ok());
        assert_eq!(
            validate_utf8(&[0xC2, 0x80]).is_ok(),
            core::str::from_utf8(&[0xC2, 0x80]).is_ok()
        );
    }

    #[test]
    fn accepts_maximum_valid_code_point_boundary() {
        // 0xF4 0x8F 0xBF 0xBF = U+10FFFF, the LARGEST legal Unicode code point (`cp ==
        // 0x10FFFF` exactly). Must be accepted: a `>` -> `>=` mutation on the beyond-max check
        // would reject this boundary value.
        let x = [0xF4, 0x8F, 0xBF, 0xBF];
        assert!(validate_utf8(&x).is_ok());
        assert_eq!(validate_utf8(&x).is_ok(), core::str::from_utf8(&x).is_ok());
    }

    #[test]
    fn rejects_non_minimal_length() {
        // 0C 81 01 41 = length 1 in the long form (X.690 §8.1.3); DER requires the short form
        // (0C 01 41). A lax parser tolerates the redundant long-form length; DER must not.
        use crate::length::LengthError;
        use crate::tlv::TlvError;
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x81, 0x01, b'A']),
            Err(Utf8Error::Tlv(TlvError::Length(LengthError::NonMinimal)))
        );
    }

    // --- S4a: tests for rows that had no accept or reject test ---

    /// Rows RFC3629-3, RFC3629-3-c (reject): UTF-8 uses one to four octets. The legacy five- and
    /// six-octet forms (RFC 2279) are rejected even when they encode a value inside the Unicode
    /// range: `F8 84 80 80 80` and `FC 80 84 80 80 80` both spell U+100000.
    #[test]
    fn rejects_five_and_six_octet_sequences() {
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x05, 0xF8, 0x84, 0x80, 0x80, 0x80]),
            Err(Utf8Error::IllFormed { position: 0 })
        );
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x06, 0xFC, 0x80, 0x84, 0x80, 0x80, 0x80]),
            Err(Utf8Error::IllFormed { position: 0 })
        );
        // after a valid prefix the position is the start of the long sequence
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x06, b'A', 0xF8, 0x84, 0x80, 0x80, 0x80]),
            Err(Utf8Error::IllFormed { position: 1 })
        );
        // the four-octet spelling of the same code point U+100000 is accepted
        assert_eq!(
            decode_utf8_str(&[0x0C, 0x04, 0xF4, 0x80, 0x80, 0x80]),
            Ok(("\u{100000}", 6))
        );
    }

    /// Rows RFC3629-3-b (accept): the code points just outside the surrogate range are valid:
    /// U+D7FF (`ED 9F BF`) and U+E000 (`EE 80 80`).
    #[test]
    fn accepts_code_points_adjacent_to_the_surrogate_range() {
        assert_eq!(decode_utf8_str(&[0x0C, 0x03, 0xED, 0x9F, 0xBF]), Ok(("\u{D7FF}", 5)));
        assert_eq!(decode_utf8_str(&[0x0C, 0x03, 0xEE, 0x80, 0x80]), Ok(("\u{E000}", 5)));
    }

    /// Rows RFC3629-3-c (accept): well-formed sequences at the edge of every rejection rule are
    /// not rejected (smallest and largest value of each length, and noncharacters).
    #[test]
    fn accepts_valid_sequences_at_every_rejection_boundary() {
        let cases: [(&[u8], &str); 9] = [
            (&[0xC2, 0x80], "\u{80}"),
            (&[0xDF, 0xBF], "\u{7FF}"),
            (&[0xE0, 0xA0, 0x80], "\u{800}"),
            (&[0xEF, 0xBF, 0xBF], "\u{FFFF}"),
            (&[0xEF, 0xBF, 0xBE], "\u{FFFE}"),
            (&[0xF0, 0x90, 0x80, 0x80], "\u{10000}"),
            (&[0xF4, 0x8F, 0xBF, 0xBF], "\u{10FFFF}"),
            (&[0x7F], "\u{7F}"),
            (&[0x00], "\u{0}"),
        ];
        for (content, expected) in cases {
            let mut input = [0u8; 8];
            input[0] = 0x0C;
            input[1] = content.len() as u8;
            input[2..2 + content.len()].copy_from_slice(content);
            let n = 2 + content.len();
            assert_eq!(decode_utf8_str(&input[..n]), Ok((expected, n)), "{:x?}", content);
        }
    }

    /// Rows X690-8.23.10, RFC3629-3-c (reject): the content octets must be those of ISO/IEC
    /// 10646 Annex D (UTF-8). Latin-1 text, where an accented letter is one octet, is rejected,
    /// and so is a UTF-16 byte-order mark.
    #[test]
    fn rejects_latin1_and_utf16_octets_as_not_annex_d() {
        // "Caf" + Latin-1 e-acute at the end: a three-octet lead with no continuation octets
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x04, 0x43, 0x61, 0x66, 0xE9]),
            Err(Utf8Error::IllFormed { position: 3 })
        );
        // Latin-1 e-acute followed by ASCII text: the following octets are not continuation octets
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x03, 0xE9, 0x41, 0x41]),
            Err(Utf8Error::IllFormed { position: 0 })
        );
        // UTF-16 big-endian byte-order mark
        assert_eq!(decode_utf8_string(&[0x0C, 0x02, 0xFE, 0xFF]), Err(Utf8Error::IllFormed { position: 0 }));
        // the Annex D spelling of the same text is accepted
        assert_eq!(decode_utf8_str(&[0x0C, 0x05, 0x43, 0x61, 0x66, 0xC3, 0xA9]), Ok(("Caf\u{e9}", 7)));
    }

    /// Rows X690-8.23.10, RFC3629-3-b, RFC3629-3-c (reject): CESU-8, which spells a
    /// supplementary character as two UTF-16 surrogates encoded separately, is not Annex D
    /// UTF-8 and is rejected. `ED A0 BD ED B8 80` is CESU-8 for U+1F600.
    #[test]
    fn rejects_cesu8_surrogate_pair_spelling() {
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x06, 0xED, 0xA0, 0xBD, 0xED, 0xB8, 0x80]),
            Err(Utf8Error::IllFormed { position: 0 })
        );
        // the UTF-8 spelling of U+1F600 is accepted
        assert_eq!(decode_utf8_str(&[0x0C, 0x04, 0xF0, 0x9F, 0x98, 0x80]), Ok(("\u{1F600}", 6)));
    }

    /// Rows CODEC-utf8-string-encode-decode (accept): bytes the decoder accepts are re-encoded
    /// to the identical octets.
    #[test]
    fn roundtrips_accepted_bytes_through_decode_then_encode() {
        let specimens: [&[u8]; 5] = [
            &[0x0C, 0x00],
            &[0x0C, 0x02, b'H', b'i'],
            &[0x0C, 0x05, 0x43, 0x61, 0x66, 0xC3, 0xA9],
            &[0x0C, 0x07, 0xE2, 0x82, 0xAC, 0xF0, 0x9F, 0x98, 0x80],
            &[0x0C, 0x04, 0xF4, 0x8F, 0xBF, 0xBF],
        ];
        for bytes in specimens {
            let (content, used) = decode_utf8_string(bytes).unwrap();
            assert_eq!(used, bytes.len());
            let mut out = [0u8; 16];
            let n = encode_utf8_string_into(content, &mut out).unwrap();
            assert_eq!(&out[..n], bytes);
        }
    }

    /// Rows CODEC-utf8-string-unique, CODEC-utf8-string-reject-nonder, X690-7.4, X690-10.2
    /// (reject): the value "A" has one accepted spelling, `0C 01 41`. Every alternate spelling
    /// is rejected: a constructed string with a valid segment, long-form lengths, a high-tag
    /// identifier, an indefinite-length constructed string, and the overlong UTF-8 spelling of
    /// the character itself (`C1 81`).
    #[test]
    fn rejects_alternate_spellings_of_one_utf8_string_value() {
        use crate::length::LengthError;
        use crate::tag::TagError;
        assert_eq!(decode_utf8_string(&[0x0C, 0x01, b'A']), Ok((&b"A"[..], 3)));
        assert_eq!(
            decode_utf8_string(&[0x2C, 0x03, 0x0C, 0x01, b'A']),
            Err(Utf8Error::Constructed)
        );
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x81, 0x01, b'A']),
            Err(Utf8Error::Tlv(TlvError::Length(LengthError::NonMinimal)))
        );
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x82, 0x00, 0x01, b'A']),
            Err(Utf8Error::Tlv(TlvError::Length(LengthError::NonMinimal)))
        );
        assert_eq!(
            decode_utf8_string(&[0x1F, 0x0C, 0x01, b'A']),
            Err(Utf8Error::Tlv(TlvError::Tag(TagError::NonMinimal)))
        );
        assert_eq!(
            decode_utf8_string(&[0x2C, 0x80, 0x0C, 0x01, b'A', 0x00, 0x00]),
            Err(Utf8Error::Tlv(TlvError::Length(LengthError::Indefinite)))
        );
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x02, 0xC1, 0x81]),
            Err(Utf8Error::IllFormed { position: 0 })
        );
    }

    /// Row X690-8.23.9 (accept): the C0 and C1 control functions of ISO/IEC 6429 may be used, with
    /// the exceptions of 8.23.9 a)-f). Every C0 control (U+0000..U+001F) and every C1 control
    /// (U+0080..U+009F) except ESC, SO, SI, SS2 and SS3 is accepted: CR, LF, TAB, NEL, CSI and the
    /// rest. The decoded text is asserted.
    #[test]
    fn accepts_utf8_c0_and_c1_controls_that_are_not_escapes_or_shifts() {
        let mut input = [0u8; 2 + 29 + 2 * 30];
        let mut n = 2;
        let mut text = [0u32; 59];
        let mut t = 0;
        for cp in (0x00u32..=0x1F).chain(0x80..=0x9F) {
            if matches!(cp, 0x0E | 0x0F | 0x1B | 0x8E | 0x8F) {
                continue;
            }
            if cp < 0x80 {
                input[n] = cp as u8;
                n += 1;
            } else {
                input[n] = 0xC2;
                input[n + 1] = (0x80 | (cp & 0x3F)) as u8;
                n += 2;
            }
            text[t] = cp;
            t += 1;
        }
        assert_eq!((n, t), (input.len(), 59));
        input[0] = 0x0C;
        input[1] = (n - 2) as u8;
        let (s, used) = decode_utf8_str(&input).unwrap();
        assert_eq!(used, input.len());
        assert_eq!(s.chars().count(), text.len());
        for (c, expected) in s.chars().zip(text.iter()) {
            assert_eq!(c as u32, *expected);
        }
        // CR LF TAB spelled out
        assert_eq!(decode_utf8_str(&[0x0C, 0x03, 0x0D, 0x0A, 0x09]), Ok(("\r\n\t", 5)));
    }

    /// Row X690-8.23.9 (accept): the forbidden controls are code points, not octet values. Octet
    /// 0x8E or 0x8F as a continuation octet, and 0xC2 before another continuation octet, are
    /// ordinary text: U+00CE (`C3 8E`), U+0E0E (`E0 B8 8E`), U+200E (`E2 80 8E`), U+200F
    /// (`E2 80 8F`), U+0080 (`C2 80`) and U+00A0 (`C2 A0`).
    #[test]
    fn accepts_text_whose_octets_equal_a_forbidden_control_but_whose_code_points_do_not() {
        assert_eq!(decode_utf8_str(&[0x0C, 0x02, 0xC3, 0x8E]), Ok(("\u{CE}", 4)));
        assert_eq!(decode_utf8_str(&[0x0C, 0x03, 0xE0, 0xB8, 0x8E]), Ok(("\u{E0E}", 5)));
        assert_eq!(decode_utf8_str(&[0x0C, 0x03, 0xE2, 0x80, 0x8E]), Ok(("\u{200E}", 5)));
        assert_eq!(decode_utf8_str(&[0x0C, 0x03, 0xE2, 0x80, 0x8F]), Ok(("\u{200F}", 5)));
        assert_eq!(decode_utf8_str(&[0x0C, 0x02, 0xC2, 0x80]), Ok(("\u{80}", 4)));
        assert_eq!(decode_utf8_str(&[0x0C, 0x02, 0xC2, 0xA0]), Ok(("\u{A0}", 4)));
    }

    /// Rows X690-8.23.9, X690-8.23.9a, X690-8.23.9b, X690-8.23.9c, X690-8.23.9d, X690-8.23.9f
    /// (reject): the controls that announce, designate or invoke an ISO 2022 escape or shift are
    /// rejected: ESC (U+001B, `1B`), SO (U+000E, `0E`), SI (U+000F, `0F`), SS2 (U+008E, `C2 8E`)
    /// and SS3 (U+008F, `C2 8F`). Each is rejected alone, after a text prefix and between two
    /// characters, with its byte position and code point.
    #[test]
    fn rejects_utf8_escape_and_shift_controls() {
        let table: [(&[u8], u32); 5] = [
            (&[0x1B], 0x1B),
            (&[0x0E], 0x0E),
            (&[0x0F], 0x0F),
            (&[0xC2, 0x8E], 0x8E),
            (&[0xC2, 0x8F], 0x8F),
        ];
        for (control, cp) in table {
            // alone
            let mut input = [0u8; 8];
            input[0] = 0x0C;
            input[1] = control.len() as u8;
            input[2..2 + control.len()].copy_from_slice(control);
            assert_eq!(
                decode_utf8_string(&input[..2 + control.len()]),
                Err(Utf8Error::ForbiddenControl { position: 0, code_point: cp }),
                "{:x?}",
                control
            );
            // after "A" and a two-octet character (U+00E9): position 3
            let mut input = [0u8; 12];
            input[..5].copy_from_slice(&[0x0C, 0, b'A', 0xC3, 0xA9]);
            input[5..5 + control.len()].copy_from_slice(control);
            input[5 + control.len()] = b'Z';
            let n = 6 + control.len();
            input[1] = (n - 2) as u8;
            assert_eq!(
                decode_utf8_string(&input[..n]),
                Err(Utf8Error::ForbiddenControl { position: 3, code_point: cp }),
                "{:x?}",
                control
            );
            // validate_utf8 directly
            assert_eq!(
                validate_utf8(control),
                Err(Utf8Error::ForbiddenControl { position: 0, code_point: cp })
            );
        }
        // an ISO 2022 announcer, ESC SP F, is rejected at its ESC
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x04, b'x', 0x1B, 0x20, 0x46]),
            Err(Utf8Error::ForbiddenControl { position: 1, code_point: 0x1B })
        );
        // so is a designating escape, ESC ( B
        assert_eq!(
            decode_utf8_string(&[0x0C, 0x03, 0x1B, 0x28, 0x42]),
            Err(Utf8Error::ForbiddenControl { position: 0, code_point: 0x1B })
        );
    }

    /// Rows X690-8.23.9, X690-8.23.9a, X690-8.23.9c (reject): an encoder never emits what the
    /// decoder rejects. The encoder refuses content holding ESC, SO, SI, SS2 or SS3 and writes
    /// nothing; the text next to them encodes.
    #[test]
    fn encode_refuses_utf8_escape_and_shift_controls() {
        let mut out = [0xA5u8; 16];
        for content in [
            &[0x1Bu8][..],
            &[0x0E],
            &[0x0F],
            &[0xC2, 0x8E],
            &[0xC2, 0x8F],
            &[b'a', 0xC3, 0xA9, 0x1B, b'b'],
        ] {
            assert_eq!(encode_utf8_string_into(content, &mut out), None, "{:x?}", content);
        }
        assert_eq!(out, [0xA5u8; 16]);
        // CR, LF, TAB, NEL and SS2's neighbour U+008D encode
        assert_eq!(encode_utf8_string_into(&[0x0D, 0x0A, 0x09, 0xC2, 0x85, 0xC2, 0x8D], &mut out), Some(9));
        assert_eq!(&out[..9], &[0x0C, 0x07, 0x0D, 0x0A, 0x09, 0xC2, 0x85, 0xC2, 0x8D]);
    }

    /// Design record (no requirement row): malformed UTF-8 is reported as `IllFormed` even when a
    /// forbidden control comes first, so `position` keeps its `valid_up_to` meaning; for
    /// well-formed content the first forbidden control is reported.
    #[test]
    fn forbidden_control_is_reported_for_well_formed_content_and_first_one_wins() {
        // ESC then a lone continuation octet: ill-formed, position of the longest valid prefix
        assert_eq!(validate_utf8(&[0x1B, 0x80]), Err(Utf8Error::IllFormed { position: 1 }));
        assert_eq!(validate_utf8(&[0xC2, 0x8E, 0xFF]), Err(Utf8Error::IllFormed { position: 2 }));
        // two forbidden controls: the first one
        assert_eq!(
            validate_utf8(&[b'a', 0x0F, 0x1B]),
            Err(Utf8Error::ForbiddenControl { position: 1, code_point: 0x0F })
        );
        assert_eq!(
            validate_utf8(&[0xC2, 0x8F, 0x0E]),
            Err(Utf8Error::ForbiddenControl { position: 0, code_point: 0x8F })
        );
    }
}
