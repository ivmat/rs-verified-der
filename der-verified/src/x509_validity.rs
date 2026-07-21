//! X.509 `Validity` (RFC 5280 §4.1.2.5) — a bounded, **structural** consumer that composes this
//! crate's verified primitives.
//!
//! ```text
//! Validity ::= SEQUENCE { notBefore Time, notAfter Time }
//! Time     ::= CHOICE  { utcTime UTCTime, generalTime GeneralizedTime }
//! ```
//!
//! This module is the sibling of [`crate::x509_spki`] and [`crate::x509_name`]: a **demonstration
//! of composition**, not an expansion of the crate's DER-layer scope (see the crate-level docs). It
//! frames the outer SEQUENCE and the two `Time` CHOICE fields using [`crate::sequence`],
//! [`crate::tlv`], [`crate::utc_time`], and [`crate::generalized_time`] verbatim — it does not
//! hand-roll any tag/length/TLV parsing of its own.
//!
//! **Design note — the crate's first CHOICE.** `SubjectPublicKeyInfo` and `Name` are both fixed
//! sequences of typed fields; `Time` is this crate's first ASN.1 `CHOICE` composition — a field
//! whose *tag itself* selects between two independently-verified content decoders (UTCTime,
//! UNIVERSAL 23, vs. GeneralizedTime, UNIVERSAL 24). Like [`crate::x509_spki`] (and unlike
//! [`crate::x509_name`]'s validate-only stance), `Validity` is a fixed two-field schema with no
//! unbounded child count, so [`parse_validity`] **materializes** a [`Validity`] struct rather than
//! merely validating — the whole point of a CHOICE type is that the caller needs to see *which* arm
//! was taken, so returning `()` here would throw away the one piece of information this module
//! exists to expose.
//!
//! **Scope boundaries (deliberate):**
//! - *Structural framing only.* [`parse_validity`] validates that the byte string is a well-formed,
//!   DER-canonical `Validity` with the exact field tiling the ASN.1 schema requires (two `Time`
//!   fields, nothing more, nothing less) — and, per field, that the chosen `Time` arm is itself a
//!   canonical UTCTime or GeneralizedTime (delegated to [`crate::utc_time`] /
//!   [`crate::generalized_time`]). It does **not** touch any other X.509 semantics (certificate
//!   paths, names, extensions, signatures) and does **not** interpret the decoded calendar fields
//!   (no "is this certificate currently valid" logic — that is a caller concern, and one that also
//!   needs a clock, which this crate deliberately has no notion of).
//! - **The RFC 5280 §4.1.2.5 profile rule is *not* enforced here.** The RFC additionally requires
//!   that certificate validity dates through the year 2049 be encoded as UTCTime and dates in 2050
//!   or later be encoded as GeneralizedTime — a *profile* constraint layered *above* the ASN.1
//!   transfer syntax (which permits either `Time` spelling anywhere the schema allows a `Time`).
//!   This module accepts either arm for either field, in any combination (both UTCTime, both
//!   GeneralizedTime, or the mixed spelling RFC 5280 actually mandates for long-lived certificates)
//!   — exactly the same generic-syntax-vs-profile split [`crate::utc_time::full_year_rfc5280`] and
//!   [`crate::generalized_time::require_no_fraction`] already draw for their own profile rules. A
//!   caller enforcing the RFC 5280 profile checks the returned [`Time`] variant plus (for UTCTime)
//!   the raw two-digit year itself.
//! - *Strict, top-to-bottom.* The outer SEQUENCE must consume the entire input (no trailing bytes
//!   after the whole `Validity`); the two `Time` fields must exactly tile the outer content — the
//!   classic parser-differential vector this crate's other modules guard against
//!   (`decode_tlv_strict` / `decode_sequence_tlv_strict`).

use crate::generalized_time::TAG as GENERALIZED_TIME_TAG;
use crate::generalized_time::{decode_generalized_time, GeneralizedTime, GeneralizedTimeError};
use crate::sequence::{decode_sequence_tlv_strict, SequenceError};
use crate::tag::Class;
use crate::tlv::{decode_tlv, TlvError};
use crate::utc_time::TAG as UTC_TIME_TAG;
use crate::utc_time::{decode_utc_time, UtcTime, UtcTimeError};

/// A decoded `Time` CHOICE: either a UTCTime (UNIVERSAL 23) or a GeneralizedTime (UNIVERSAL 24).
/// `UtcTime` is owned/`Copy` (no lifetime); `GeneralizedTime` borrows its fraction digits.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum Time<'a> {
    /// The `utcTime` arm — `YYMMDDHHMMSSZ` (see [`crate::utc_time`]).
    Utc(UtcTime),
    /// The `generalTime` arm — `YYYYMMDDHHMMSS[.fff]Z` (see [`crate::generalized_time`]).
    Generalized(GeneralizedTime<'a>),
}

/// A structurally-parsed `Validity`, borrowing from the input it was parsed from (via any
/// [`Time::Generalized`] field's fraction digits).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct Validity<'a> {
    /// `notBefore`: the certificate's validity start.
    pub not_before: Time<'a>,
    /// `notAfter`: the certificate's validity end.
    pub not_after: Time<'a>,
}

/// Why a `Time` CHOICE field was rejected. Every variant names a specific structural cause,
/// wrapping the underlying primitive's error where one exists (mirrors [`crate::x509_spki::SpkiError`]'s
/// wrapping style).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum TimeError {
    /// The `Time` TLV's framing (tag/length octets) was malformed.
    BadTlv(TlvError),
    /// The `Time` TLV was well-framed, but its identifier was not UNIVERSAL 23 (UTCTime) or
    /// UNIVERSAL 24 (GeneralizedTime) — the only two members of the CHOICE.
    WrongTag,
    /// The identifier was UTCTime or GeneralizedTime's tag number, but in the *constructed* form —
    /// both are always primitive in DER.
    Constructed,
    /// The `utcTime` arm's content failed canonical-DER validation.
    BadUtc(UtcTimeError),
    /// The `generalTime` arm's content failed canonical-DER validation.
    BadGeneralized(GeneralizedTimeError),
}

/// Why a `Validity` was rejected. Every variant names a specific structural cause, wrapping the
/// underlying primitive's error where one exists.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ValidityError {
    /// The outer `Validity` SEQUENCE envelope was malformed: bad identifier/length, the primitive
    /// (non-constructed) form, or trailing bytes after the whole structure (this is a top-level
    /// object, decoded with [`decode_sequence_tlv_strict`]).
    BadOuterSeq(SequenceError),
    /// No `notBefore` `Time` is present — the outer SEQUENCE's content is empty.
    MissingNotBefore,
    /// The `notBefore` `Time` field failed to decode.
    NotBefore(TimeError),
    /// No `notAfter` `Time` is present — the outer SEQUENCE's content ended after `notBefore`.
    MissingNotAfter,
    /// The `notAfter` `Time` field failed to decode.
    NotAfter(TimeError),
    /// The `Validity` SEQUENCE has more than its two permitted fields (`notBefore`, `notAfter`):
    /// bytes remain in its content after the `notAfter` TLV.
    TrailingBytes,
}

/// Decode one `Time` CHOICE TLV from the front of `input`, returning the decoded [`Time`] and the
/// bytes consumed. Composes [`decode_tlv`] with a tag-number dispatch to [`decode_utc_time`] /
/// [`decode_generalized_time`] — the CHOICE selection is entirely in the identifier octet, so no
/// other primitive is needed to disambiguate the two arms.
fn decode_time_tlv(input: &[u8]) -> Result<(Time<'_>, usize), TimeError> {
    let (tlv, used) = decode_tlv(input).map_err(TimeError::BadTlv)?;
    if tlv.tag.class != Class::Universal {
        return Err(TimeError::WrongTag);
    }
    match tlv.tag.number {
        UTC_TIME_TAG => {
            if tlv.tag.constructed {
                return Err(TimeError::Constructed);
            }
            let t = decode_utc_time(tlv.value).map_err(TimeError::BadUtc)?;
            Ok((Time::Utc(t), used))
        }
        GENERALIZED_TIME_TAG => {
            if tlv.tag.constructed {
                return Err(TimeError::Constructed);
            }
            let t = decode_generalized_time(tlv.value).map_err(TimeError::BadGeneralized)?;
            Ok((Time::Generalized(t), used))
        }
        _ => Err(TimeError::WrongTag),
    }
}

/// Parse a complete DER `Validity` from `input`.
///
/// **Strict, top level**: `input` must be *exactly* one `Validity` — no trailing bytes are
/// tolerated after the whole structure, and the two `Time` fields must exactly tile the outer
/// SEQUENCE's content.
///
/// Decodes, in order:
/// 1. the outer SEQUENCE envelope ([`decode_sequence_tlv_strict`]);
/// 2. `notBefore`, a `Time` CHOICE (`decode_time_tlv`);
/// 3. `notAfter`, a `Time` CHOICE (`decode_time_tlv`), requiring it to exactly fill what remains
///    of the outer content.
///
/// Never panics on any input (proven by the `parse_never_panics` Kani harness below); returns a
/// classified [`ValidityError`] on any structural deviation. Accepts either `Time` spelling for
/// either field — see the module docs for why the RFC 5280 §4.1.2.5 UTCTime/GeneralizedTime
/// year-2050 profile rule is deliberately not enforced here.
pub fn parse_validity(input: &[u8]) -> Result<Validity<'_>, ValidityError> {
    // 1. Outer SEQUENCE: must consume the whole input (top-level anti-trailing-data).
    let outer_content = decode_sequence_tlv_strict(input).map_err(ValidityError::BadOuterSeq)?;

    // 2. First field: notBefore.
    if outer_content.is_empty() {
        return Err(ValidityError::MissingNotBefore);
    }
    let (not_before, nb_used) = decode_time_tlv(outer_content).map_err(ValidityError::NotBefore)?;

    // 3. Second (and last) field: notAfter, must exactly fill what remains.
    let rest = &outer_content[nb_used..];
    if rest.is_empty() {
        return Err(ValidityError::MissingNotAfter);
    }
    let (not_after, na_used) = decode_time_tlv(rest).map_err(ValidityError::NotAfter)?;
    if na_used != rest.len() {
        return Err(ValidityError::TrailingBytes);
    }

    Ok(Validity { not_before, not_after })
}

// ---------------------------------------------------------------------------
// Kani proof harness.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer covers a small but structurally complete
// Validity (e.g. a truncated/malformed variant of the 32-byte UTC/UTC specimen in the tests below).
// The call chain is `decode_sequence_tlv_strict` (one `decode_tlv`) followed by up to two
// `decode_time_tlv` calls, each itself one `decode_tlv` plus a bounded content walk of at most
// `content.len()` iterations (`decode_utc_time`'s fixed 12-digit loop or
// `decode_generalized_time`'s 14-digit-plus-fraction loop) — no unbounded sibling count (unlike
// `x509_name`'s `SEQUENCE OF`), so the dominant loop is a single time-content walk bounded by the
// 16-byte buffer. `#[kani::unwind(20)]` covers a maximal-header `decode_tlv` (~11, per `tlv.rs`)
// and a full 16-byte content walk with margin, matching `x509_spki::parse_never_panics`'s bound; if
// Kani reports an unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_validity` never panics on any input up to 16 octets.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached (a genuine Validity: outer
    /// SEQUENCE strict, both Time CHOICE fields decode and exactly tile) -- not merely that
    /// malformed 16-byte inputs are rejected. Would NOT be SAT if `parse_validity`'s body were a
    /// no-op always returning `Err`.
    ///
    /// **VACUITY FINDING (2026-07-21): this cover is UNSATISFIABLE at `[u8; 16]`.** Kani reports
    /// `VERIFICATION: SUCCESSFUL` (0 panics) but `0 of 1 cover properties satisfied` — the
    /// harness's 16-octet buffer can never reach `parse_validity`'s `Ok` tail. This is
    /// arithmetically forced, not a cover-authoring bug: [`crate::utc_time::decode_utc_time`]
    /// requires content of *exactly* 13 octets (`content.len() != 13` is rejected outright), so
    /// the smallest possible `Time::Utc` TLV is `tag(1) + len(1) + content(13) = 15` octets, and
    /// [`crate::generalized_time::decode_generalized_time`]'s minimal content is even larger (14
    /// digits + `Z`, no fraction). `Validity` needs an outer SEQUENCE header (>= 2 octets) plus
    /// TWO such `Time` fields — an arithmetic floor of `2 + 15 + 15 = 32` octets, exactly twice
    /// this harness's buffer. The happy path is structurally unreachable at this size.
    ///
    /// What IS proven at 16 octets: the rejection-side glue (the outer-SEQUENCE walk, the
    /// `notBefore`/`notAfter` presence checks, the `Time` CHOICE tag dispatch, and the offset
    /// arithmetic) is panic-free up to wherever the short buffer runs out — but never through to
    /// `Ok`. The module's implicit "exercises the CHOICE dispatch's Ok arm" framing was never
    /// machine-checked at this size, and cannot be at 16 octets. Left in place (rather than
    /// removed) because a cover reporting "0 of 1 satisfied" IS the honest, machine-checked record
    /// of the gap. A dedicated follow-up would need either a >= 32-byte buffer (raising this
    /// harness's cost) or a modular split mirroring `x509_tbs_certificate`'s stub pattern (stub
    /// `decode_time_tlv` with a nondet `Result<Time, TimeError>` and prove the OUTER tiling logic
    /// alone) — not attempted here.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_never_panics() {
        let buf: [u8; 16] = kani::any();
        let result = parse_validity(&buf);
        kani::cover(result.is_ok(), "a well-formed Validity reaches the Ok tail");
        let _ = result;
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// `Validity` with both fields UTCTime: `notBefore` = 1999-01-01 00:00:00Z, `notAfter` =
    /// 1999-12-31 23:59:59Z.
    ///
    /// `30 1e`                                       SEQUENCE, len 30
    ///    `17 0d "990101000000Z"`                     UTCTime (notBefore), len 13
    ///    `17 0d "991231235959Z"`                     UTCTime (notAfter), len 13
    #[rustfmt::skip]
    const VALIDITY_UTC_UTC: [u8; 32] = [
        0x30, 0x1e,
            0x17, 0x0d,
                0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x17, 0x0d,
                0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    ];

    /// `Validity` with both fields GeneralizedTime: `notBefore` = 2050-01-01 00:00:00Z, `notAfter`
    /// = 2099-12-31 23:59:59Z.
    ///
    /// `30 22`                                       SEQUENCE, len 34
    ///    `18 0f "20500101000000Z"`                   GeneralizedTime (notBefore), len 15
    ///    `18 0f "20991231235959Z"`                   GeneralizedTime (notAfter), len 15
    #[rustfmt::skip]
    const VALIDITY_GENERALIZED_GENERALIZED: [u8; 36] = [
        0x30, 0x22,
            0x18, 0x0f,
                0x32, 0x30, 0x35, 0x30, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x18, 0x0f,
                0x32, 0x30, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
    ];

    /// `Validity` with the real RFC 5280 §4.1.2.5 long-lived-cert spelling: `notBefore` = UTCTime
    /// 2023-01-01 00:00:00Z (pre-2050), `notAfter` = GeneralizedTime 2099-01-01 00:00:00Z
    /// (post-2050).
    ///
    /// `30 20`                                       SEQUENCE, len 32
    ///    `17 0d "230101000000Z"`                     UTCTime (notBefore), len 13
    ///    `18 0f "20990101000000Z"`                   GeneralizedTime (notAfter), len 15
    #[rustfmt::skip]
    const VALIDITY_MIXED_UTC_THEN_GENERALIZED: [u8; 34] = [
        0x30, 0x20,
            0x17, 0x0d,
                0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
            0x18, 0x0f,
                0x32, 0x30, 0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
    ];

    #[test]
    fn parses_utc_utc() {
        let v = parse_validity(&VALIDITY_UTC_UTC).unwrap();
        assert_eq!(
            v.not_before,
            Time::Utc(UtcTime { year2: 99, month: 1, day: 1, hour: 0, minute: 0, second: 0 })
        );
        assert_eq!(
            v.not_after,
            Time::Utc(UtcTime { year2: 99, month: 12, day: 31, hour: 23, minute: 59, second: 59 })
        );
    }

    #[test]
    fn parses_generalized_generalized() {
        let v = parse_validity(&VALIDITY_GENERALIZED_GENERALIZED).unwrap();
        assert_eq!(
            v.not_before,
            Time::Generalized(GeneralizedTime {
                year: 2050,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                fraction: &[]
            })
        );
        assert_eq!(
            v.not_after,
            Time::Generalized(GeneralizedTime {
                year: 2099,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                second: 59,
                fraction: &[]
            })
        );
    }

    #[test]
    fn parses_mixed_utc_then_generalized() {
        let v = parse_validity(&VALIDITY_MIXED_UTC_THEN_GENERALIZED).unwrap();
        assert_eq!(
            v.not_before,
            Time::Utc(UtcTime { year2: 23, month: 1, day: 1, hour: 0, minute: 0, second: 0 })
        );
        assert_eq!(
            v.not_after,
            Time::Generalized(GeneralizedTime {
                year: 2099,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                fraction: &[]
            })
        );
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn rejects_trailing_byte_after_validity() {
        let mut bytes = VALIDITY_UTC_UTC.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            parse_validity(&bytes),
            Err(ValidityError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = VALIDITY_UTC_UTC;
        bytes[0] = 0x31;
        assert_eq!(parse_validity(&bytes), Err(ValidityError::BadOuterSeq(SequenceError::WrongTag)));
    }

    #[test]
    fn rejects_non_canonical_outer_length() {
        // The outer length re-encoded in the long form (0x81 0x1e) where the short form (0x1e) is
        // required — non-minimal, forbidden by DER.
        use crate::length::LengthError;
        let mut bytes = vec![0x30, 0x81, 0x1e];
        bytes.extend_from_slice(&VALIDITY_UTC_UTC[2..]);
        assert_eq!(
            parse_validity(&bytes),
            Err(ValidityError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_truncated() {
        // Drop the last 10 bytes: the outer SEQUENCE declares more content than is present.
        let bytes = &VALIDITY_UTC_UTC[..VALIDITY_UTC_UTC.len() - 10];
        assert_eq!(
            parse_validity(bytes),
            Err(ValidityError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_empty_validity() {
        let bytes = [0x30, 0x00];
        assert_eq!(parse_validity(&bytes), Err(ValidityError::MissingNotBefore));
    }

    #[test]
    fn rejects_missing_not_after() {
        // An outer SEQUENCE containing only the notBefore UTCTime child, nothing after it:
        // 30 0f 17 0d "990101000000Z"  (SEQUENCE { Time }, no notAfter)
        #[rustfmt::skip]
        let bytes: [u8; 17] = [
            0x30, 0x0f,
                0x17, 0x0d,
                    0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
        ];
        assert_eq!(parse_validity(&bytes), Err(ValidityError::MissingNotAfter));
    }

    #[test]
    fn rejects_not_before_wrong_tag() {
        // notBefore's identifier is INTEGER (0x02) instead of UTCTime (0x17).
        let mut bytes = VALIDITY_UTC_UTC;
        bytes[2] = 0x02;
        assert_eq!(parse_validity(&bytes), Err(ValidityError::NotBefore(TimeError::WrongTag)));
    }

    #[test]
    fn rejects_not_before_constructed() {
        // notBefore's identifier is UTCTime's tag number but in the constructed form (0x37 instead
        // of 0x17) — UTCTime is always primitive.
        let mut bytes = VALIDITY_UTC_UTC;
        bytes[2] = 0x37;
        assert_eq!(parse_validity(&bytes), Err(ValidityError::NotBefore(TimeError::Constructed)));
    }

    #[test]
    fn rejects_not_before_bad_utc() {
        // Corrupt notBefore's month digits "01" -> "13" (out of range): a clean single MonthRange
        // error, everything else in the UTCTime content stays canonical.
        let mut bytes = VALIDITY_UTC_UTC;
        bytes[6] = b'1';
        bytes[7] = b'3';
        assert_eq!(
            parse_validity(&bytes),
            Err(ValidityError::NotBefore(TimeError::BadUtc(UtcTimeError::MonthRange)))
        );
    }

    #[test]
    fn rejects_not_after_bad_generalized() {
        // notBefore: UTCTime 2023-01-01 (canonical). notAfter: GeneralizedTime with a fraction that
        // ends in a trailing zero (".10" instead of the canonical ".1") — a clean single
        // FractionTrailingZero error.
        //
        // `30 23`                                       SEQUENCE, len 35
        //    `17 0d "230101000000Z"`                     UTCTime (notBefore), len 13
        //    `18 12 "20991231235959.10Z"`                GeneralizedTime (notAfter), len 18
        #[rustfmt::skip]
        let bytes: [u8; 37] = [
            0x30, 0x23,
                0x17, 0x0d,
                    0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
                0x18, 0x12,
                    0x32, 0x30, 0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39,
                    0x2e, 0x31, 0x30, 0x5a,
        ];
        assert_eq!(
            parse_validity(&bytes),
            Err(ValidityError::NotAfter(TimeError::BadGeneralized(
                GeneralizedTimeError::FractionTrailingZero
            )))
        );
    }

    #[test]
    fn rejects_trailing_bytes_inside_outer() {
        // The two Time fields tile 30 of 31 outer content bytes -- one extra byte remains.
        let mut bytes = VALIDITY_UTC_UTC.to_vec();
        bytes[1] = 0x1f; // outer content length 30 -> 31
        bytes.push(0xAA); // the extra content octet
        assert_eq!(parse_validity(&bytes), Err(ValidityError::TrailingBytes));
    }

    // --- coverage completeness (review x509-validity-01): the second mixed permutation, the
    //     tag-CLASS guard (distinct from the tag-NUMBER guard), and symmetric notAfter coverage. ---

    /// The other valid mixed spelling (`GeneralizedTime` notBefore, `UTCTime` notAfter) — completes
    /// the set of Time-arm permutations alongside `parses_mixed_utc_then_generalized`.
    ///
    /// `30 20`                                       SEQUENCE, len 32
    ///    `18 0f "20230101000000Z"`                   GeneralizedTime (notBefore), len 15
    ///    `17 0d "230101000000Z"`                     UTCTime (notAfter), len 13
    #[test]
    fn parses_mixed_generalized_then_utc() {
        #[rustfmt::skip]
        let bytes: [u8; 34] = [
            0x30, 0x20,
                0x18, 0x0f,
                    0x32, 0x30, 0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
                0x17, 0x0d,
                    0x32, 0x33, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
        ];
        let v = parse_validity(&bytes).unwrap();
        assert_eq!(
            v.not_before,
            Time::Generalized(GeneralizedTime {
                year: 2023,
                month: 1,
                day: 1,
                hour: 0,
                minute: 0,
                second: 0,
                fraction: &[]
            })
        );
        assert_eq!(
            v.not_after,
            Time::Utc(UtcTime { year2: 23, month: 1, day: 1, hour: 0, minute: 0, second: 0 })
        );
    }

    #[test]
    fn rejects_not_before_wrong_class() {
        // notBefore's identifier is CONTEXT-SPECIFIC 23 (0x97 = 0b10_0_10111), not UNIVERSAL 23 —
        // exercises the tag-*class* guard (`class != Universal`), distinct from the tag-*number*
        // guard that `rejects_not_before_wrong_tag`'s UNIVERSAL INTEGER (0x02) trips.
        let mut bytes = VALIDITY_UTC_UTC;
        bytes[2] = 0x97;
        assert_eq!(parse_validity(&bytes), Err(ValidityError::NotBefore(TimeError::WrongTag)));
    }

    #[test]
    fn rejects_not_after_wrong_tag() {
        // Symmetric to `rejects_not_before_wrong_tag`: notAfter's identifier is INTEGER (0x02)
        // instead of a Time tag. The notAfter TLV begins at outer offset 17 (0x30 0x1e | 17 0d + 13).
        let mut bytes = VALIDITY_UTC_UTC;
        bytes[17] = 0x02;
        assert_eq!(parse_validity(&bytes), Err(ValidityError::NotAfter(TimeError::WrongTag)));
    }
}
