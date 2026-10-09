//! DER UTCTime content (X.690 §11.8, §8.25; type UNIVERSAL 23 / identifier `0x17`).
//!
//! DER (unlike BER) admits exactly **one** UTCTime spelling: the 13-octet ASCII string
//! `YYMMDDHHMMSSZ`. This module validates the *content* octets of a TLV whose tag is UNIVERSAL 23,
//! and **nothing else** — like the other content decoders ([`crate::integer`], [`crate::boolean`],
//! [`crate::bit_string`]), this codec carries the *content* canonicality and does not look at the
//! identifier.
//!
//! **The identifier is not enforced upstream.** Of the tag identity and the primitive/definite
//! form, only the **definite**-length half is enforced by [`crate::tlv`] (it delegates to
//! [`crate::length`], which rejects the indefinite form) — and only if you actually entered through
//! `tlv`, which this function, taking content octets, cannot tell. The **primitive**-form half and
//! the **tag identity** are enforced by neither [`crate::tag`] nor [`crate::tlv`]: `decode_tag`
//! attaches no meaning to the class/constructed combination and `decode_tlv` passes the parsed
//! `Tag` through untouched.
//!
//! Where each IS decided, and they are **not** the same place: **tag identity (this is UNIVERSAL 23)
//! is decided only by typed callers** — `x509_validity.rs`'s `decode_time_tlv` rejects a
//! non-UNIVERSAL class (`WrongTag`) and a constructed UTCTime (`Constructed`) before dispatching
//! here. The **primitive-form rule** is decided generically by [`crate::identifier_form`], which
//! decides *form only* and does not know which tag you expected. **A direct caller of [`decode_utc_time`]
//! must decide the identifier itself.**
//!
//! The canonical form, verified against the standards (not merely the folklore):
//! - **Terminates with `'Z'`** — §11.8 requires the `Z` (Zulu) form; local time and `±HHMM` offsets
//!   are forbidden. A non-`Z` terminator, an offset, or a missing terminator is rejected.
//! - **Seconds always present** (§11.8), so the string is *exactly* `YYMMDDHHMMSS` + `Z` = 13 octets.
//!   The BER short form `YYMMDDHHMMZ` (no seconds) is rejected as `BadLength`.
//! - **No fractional seconds** — UTCTime has none (that is GeneralizedTime, [`crate::generalized_time`]).
//! - **Field ranges** (from the X.680 base type): month `01..=12`, day `01..=31`, hour `00..=23`
//!   (so `24` — the forbidden "midnight at end of day", §8.25 note / X.680 — is rejected), minute
//!   `00..=59`, second `00..=59`. The two-digit year is unconstrained here (`00..=99`).
//!
//! **Scope boundary (see `DECISIONS.md`).**
//! - **Leap second `SS=60` is rejected** (second `00..=59`). The X.680 base type *permits* `60` for a
//!   positive leap second, so this is a deliberate deviation for the X.509 anti-differential profile:
//!   real X.509 signers never emit a leap second, and a lax parser that accepts one a strict signer
//!   never produced is the classic parser differential. Documented; contestable; recorded in `DECISIONS.md`.
//! - **Calendar validity is out of scope.** Fields are range-checked *independently*; cross-field
//!   validity (Feb-29 leap years, "day 31 in April") is a *date-semantics* concern the fence excludes —
//!   `day` is uniformly `01..=31`.
//! - **The RFC 5280 century mapping** (`YY < 50 ⇒ 20YY`, `YY ≥ 50 ⇒ 19YY`) is a *profile* rule, not an
//!   encoding rule; it is **not** applied here (`year2` is returned raw). A caller in an X.509 context
//!   applies it — see [`full_year_rfc5280`].
//!
//! # Examples
//!
//! ```
//! use der_verified::utc_time::{decode_utc_time, UtcTime};
//!
//! // 991231235959Z = 1999-12-31 23:59:59 UTC (raw fields; no century mapping here).
//! let t = decode_utc_time(b"991231235959Z").unwrap();
//! assert_eq!(t, UtcTime { year2: 99, month: 12, day: 31, hour: 23, minute: 59, second: 59 });
//! ```

/// The universal tag number for UTCTime.
pub const TAG: u32 = 23;

/// A decoded DER UTCTime. All fields are the raw values read from the 13-octet string; no calendar
/// or timezone interpretation is applied (see the module docs).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct UtcTime {
    /// Two-digit year, `00..=99` (raw; not century-mapped — see [`full_year_rfc5280`]).
    pub year2: u8,
    /// Month, `01..=12`.
    pub month: u8,
    /// Day of month, `01..=31` (no per-month calendar check — see the module docs).
    pub day: u8,
    /// Hour, `00..=23`.
    pub hour: u8,
    /// Minute, `00..=59`.
    pub minute: u8,
    /// Second, `00..=59` (leap second `60` is rejected — see `DECISIONS.md`).
    pub second: u8,
}

/// Why UTCTime content was rejected. Each rejection is a distinct, testable reason.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum UtcTimeError {
    /// Content was not exactly 13 octets — includes the seconds-less BER form and any offset form.
    BadLength,
    /// A position that must be an ASCII digit (`0..=11`) was not `b'0'..=b'9'`.
    NonDigit,
    /// The final octet was not `'Z'` — a local-time, offset, or lowercase-`z` terminator (§11.8).
    NotZulu,
    /// Month field outside `01..=12`.
    MonthRange,
    /// Day field outside `01..=31`.
    DayRange,
    /// Hour field outside `00..=23` (includes the forbidden `24`).
    HourRange,
    /// Minute field outside `00..=59`.
    MinuteRange,
    /// Second field outside `00..=59` (includes the rejected leap second `60` — see `DECISIONS.md`).
    SecondRange,
}

/// Read two ASCII digits at `b[i]`, `b[i+1]` as a value `00..=99`. The caller must have validated
/// both as `b'0'..=b'9'`, so each `- b'0'` is `0..=9` and the result never overflows `u8`.
#[inline]
fn two_digits(b: &[u8], i: usize) -> u8 {
    (b[i] - b'0') * 10 + (b[i + 1] - b'0')
}

/// Write `v` (`00..=99`) as two ASCII digits at `out[i]`, `out[i+1]`.
#[inline]
fn write_two(out: &mut [u8], i: usize, v: u8) {
    out[i] = b'0' + v / 10;
    out[i + 1] = b'0' + v % 10;
}

/// Whether a [`UtcTime`]'s fields are all in their canonical ranges — the guard that makes
/// `encode`/`decode` exact inverses on the accepted set (a struct literal can hold out-of-range fields).
#[inline]
fn fields_in_range(t: &UtcTime) -> bool {
    t.year2 <= 99
        && t.month >= 1
        && t.month <= 12
        && t.day >= 1
        && t.day <= 31
        && t.hour <= 23
        && t.minute <= 59
        && t.second <= 59
}

/// Decode DER UTCTime content octets. Accepts **only** the canonical `YYMMDDHHMMSSZ` form: exactly
/// 13 octets, positions `0..=11` ASCII digits, terminator `'Z'`, and every field in range.
///
/// **Error precedence (documented, not left to inference).** When an input has more than one
/// defect, the reported [`UtcTimeError`] is the first applicable one in this order:
/// 1. [`UtcTimeError::BadLength`] -- the content is not exactly 13 octets;
/// 2. [`UtcTimeError::NonDigit`] -- any of positions `0..=11` is not an ASCII digit;
/// 3. [`UtcTimeError::NotZulu`] -- position 12 is not `'Z'`;
/// 4. the field ranges, in field order `MM DD HH MM SS`: [`UtcTimeError::MonthRange`], then
///    [`UtcTimeError::DayRange`], then [`UtcTimeError::HourRange`], then
///    [`UtcTimeError::MinuteRange`], then [`UtcTimeError::SecondRange`]. (The year pair `YY` has no
///    range check.)
///
/// For example `99` in both the month and the day position reports `MonthRange`, and a non-digit
/// together with a non-`'Z'` terminator reports `NonDigit`. A Kani harness
/// (`proofs::decode_is_exactly_the_reference`) pins this order against an independent reference.
pub fn decode_utc_time(content: &[u8]) -> Result<UtcTime, UtcTimeError> {
    if content.len() != 13 {
        return Err(UtcTimeError::BadLength);
    }
    let mut i = 0;
    while i < 12 {
        if !content[i].is_ascii_digit() {
            return Err(UtcTimeError::NonDigit);
        }
        i += 1;
    }
    if content[12] != b'Z' {
        return Err(UtcTimeError::NotZulu);
    }
    let year2 = two_digits(content, 0);
    let month = two_digits(content, 2);
    let day = two_digits(content, 4);
    let hour = two_digits(content, 6);
    let minute = two_digits(content, 8);
    let second = two_digits(content, 10);
    if month < 1 || month > 12 {
        return Err(UtcTimeError::MonthRange);
    }
    if day < 1 || day > 31 {
        return Err(UtcTimeError::DayRange);
    }
    if hour > 23 {
        return Err(UtcTimeError::HourRange);
    }
    if minute > 59 {
        return Err(UtcTimeError::MinuteRange);
    }
    if second > 59 {
        return Err(UtcTimeError::SecondRange);
    }
    Ok(UtcTime { year2, month, day, hour, minute, second })
}

/// Encode a [`UtcTime`] as canonical DER content (`YYMMDDHHMMSSZ`, 13 octets) into `out`.
///
/// Returns the number of octets written (always 13), or `None` if any field is out of its canonical
/// range or `out` is too small. The range guard makes this the exact inverse of [`decode_utc_time`].
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
pub fn encode_utc_time(t: &UtcTime, out: &mut [u8]) -> Option<usize> {
    if !fields_in_range(t) {
        return None;
    }
    if out.len() < 13 {
        return None;
    }
    write_two(out, 0, t.year2);
    write_two(out, 2, t.month);
    write_two(out, 4, t.day);
    write_two(out, 6, t.hour);
    write_two(out, 8, t.minute);
    write_two(out, 10, t.second);
    out[12] = b'Z';
    Some(13)
}

/// The full 4-digit year under the **RFC 5280 §4.1.2.5.1** profile rule: `YY < 50 ⇒ 20YY`,
/// `YY ≥ 50 ⇒ 19YY`. This is a *profile* interpretation, not part of the DER encoding — an X.509
/// caller applies it; the generic codec does not (see the module docs).
pub fn full_year_rfc5280(t: &UtcTime) -> u16 {
    if t.year2 < 50 {
        2000 + t.year2 as u16
    } else {
        1900 + t.year2 as u16
    }
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    /// **Independent** oracle for this library's *profile-canonical* UTCTime set: the X.690 §11.8
    /// structural form + the X.680 field ranges, **narrowed by the one documented deviation** — leap
    /// second `SS=60` is excluded (X.680 *permits* `60`; we reject it for the X.509 anti-differential
    /// profile, see `DECISIONS.md`). It is stated declaratively, deliberately *not* by calling
    /// `decode`/`encode`, so the biconditional below is a genuine conformance check against this
    /// predicate, not a tautology restating the parser's control flow (the de-tautologization
    /// lesson). This is the artifact the independent audit targets: `decode`'s accepted set must
    /// equal *exactly* this set — no over-acceptance (a differential hole) and no over-rejection
    /// *beyond* the single documented leap-second narrowing (a broken cert). That one intentional
    /// point of extra strictness versus the raw X.680 base type is called out here and in
    /// `DECISIONS.md`. Independence is reinforced by a *second, control-flow-distinct* angle:
    /// `decode_accepts_only_canonical` re-encodes every accepted value through `encode` and checks it
    /// reproduces the input byte-for-byte, so an accepted-but-non-canonical string would have to
    /// survive **both** this biconditional and the round-trip.
    fn is_canonical_der_utctime(c: &[u8]) -> bool {
        if c.len() != 13 {
            return false;
        }
        let mut i = 0;
        while i < 12 {
            if c[i] < b'0' || c[i] > b'9' {
                return false;
            }
            i += 1;
        }
        if c[12] != b'Z' {
            return false;
        }
        let month = (c[2] - b'0') * 10 + (c[3] - b'0');
        let day = (c[4] - b'0') * 10 + (c[5] - b'0');
        let hour = (c[6] - b'0') * 10 + (c[7] - b'0');
        let minute = (c[8] - b'0') * 10 + (c[9] - b'0');
        let second = (c[10] - b'0') * 10 + (c[11] - b'0');
        month >= 1 && month <= 12 && day >= 1 && day <= 31 && hour <= 23 && minute <= 59 && second <= 59
    }

    /// Round-trip: every in-range field tuple encodes to content that decodes back to exactly it,
    /// writing exactly 13 octets. The fields are symbolic (constrained to their ranges) so the whole
    /// accepted value set is covered, not a hand-picked case.
    #[kani::proof]
    #[kani::unwind(14)]
    fn roundtrip_all_fields() {
        let t = UtcTime {
            year2: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
        };
        kani::assume(fields_in_range(&t));
        let mut out = [0u8; 13];
        let w = encode_utc_time(&t, &mut out).unwrap();
        assert!(w == 13);
        assert!(decode_utc_time(&out[..w]) == Ok(t));
    }

    /// Robustness: `decode_utc_time` never panics/overflows on *any* input. A 14-octet symbolic
    /// window is *sufficient* to characterize this: `decode` returns `BadLength` on its first line
    /// for every length ≠ 13 before touching a single index, so all lengths > 14 behave identically
    /// to the tested non-13 lengths — length 13 (the only one that indexes) and its neighbours 12/14
    /// exercise the whole reachable behaviour. (Bounded is the nature of the L3 Kani floor; the
    /// unbounded ∀-length lid is the Lean layer, as on the length codec.)
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached (a genuine 13-octet canonical
    /// UTCTime decodes), not merely that every non-13 length is rejected on the length check
    /// alone. Would NOT be SAT if `decode_utc_time`'s body were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(14)]
    fn decode_never_panics() {
        let buf: [u8; 14] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 14);
        let result = decode_utc_time(&buf[..n]);
        kani::cover(result.is_ok(), "a well-formed UTCTime reaches decode_utc_time's Ok tail");
        let _ = result;
    }

    /// Canonicality (re-encode form, matching the repo pattern): any accepted content re-encodes to
    /// *itself* — so `decode` admits a byte string only if it is the unique canonical encoding of the
    /// decoded value.
    #[kani::proof]
    #[kani::unwind(14)]
    fn decode_accepts_only_canonical() {
        let buf: [u8; 14] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 14);
        if let Ok(t) = decode_utc_time(&buf[..n]) {
            let mut out = [0u8; 13];
            let w = encode_utc_time(&t, &mut out).unwrap();
            assert!(w == n);
            assert!(out[..w] == buf[..n]);
        }
    }

    /// Canonicality (de-tautologized oracle — the audit target): the accepted set equals
    /// *exactly* the independent X.690 §11.8 predicate `is_canonical_der_utctime`, in both directions.
    /// This is the strong anti-differential statement: no non-canonical encoding is ever accepted
    /// (no silent differential hole) and no canonical encoding is ever rejected (no broken cert).
    #[kani::proof]
    #[kani::unwind(14)]
    fn accepted_iff_canonical_oracle() {
        let buf: [u8; 14] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 14);
        let result = decode_utc_time(&buf[..n]);
        assert!(result.is_ok() == is_canonical_der_utctime(&buf[..n]));
        kani::cover!(result.is_ok());
        // Value faithfulness: each decoded field is the pair of ASCII digits at its own byte
        // positions (YY MM DD HH MM SS), stated directly on the input rather than as the inverse of
        // `encode` -- so a field read from the wrong position is caught even if `encode` mirrors it.
        if let Ok(t) = result {
            assert!(t.year2 == (buf[0] - b'0') * 10 + (buf[1] - b'0'));
            assert!(t.month == (buf[2] - b'0') * 10 + (buf[3] - b'0'));
            assert!(t.day == (buf[4] - b'0') * 10 + (buf[5] - b'0'));
            assert!(t.hour == (buf[6] - b'0') * 10 + (buf[7] - b'0'));
            assert!(t.minute == (buf[8] - b'0') * 10 + (buf[9] - b'0'));
            assert!(t.second == (buf[10] - b'0') * 10 + (buf[11] - b'0'));
        }
    }

    /// TOTAL reference for UTCTime content: the exact `Result` -- every error variant, with the
    /// check order the module documents. Order (stated explicitly in the "Error precedence" section
    /// of `decode_utc_time`'s rustdoc): `BadLength`, then `NonDigit`, then `NotZulu`, then the first
    /// out-of-range field in the order `MonthRange`, `DayRange`, `HourRange`, `MinuteRange`,
    /// `SecondRange`. Every step of the order, including the order among the five field ranges, is
    /// documented there.
    ///
    /// Deliberately built unlike the decoder: table-driven (a position/range/error table for the five
    /// ranged fields, a computed digit value for every pair), with a single precedence-ordered `if`
    /// chain at the end instead of early returns interleaved with the reads.
    fn reference_utc_time(c: &[u8]) -> Result<UtcTime, UtcTimeError> {
        // (byte position of the pair, lowest legal value, highest legal value, error if outside).
        const RANGED: [(usize, i32, i32, UtcTimeError); 5] = [
            (2, 1, 12, UtcTimeError::MonthRange),
            (4, 1, 31, UtcTimeError::DayRange),
            (6, 0, 23, UtcTimeError::HourRange),
            (8, 0, 59, UtcTimeError::MinuteRange),
            (10, 0, 59, UtcTimeError::SecondRange),
        ];
        let right_length = c.len() == 13;
        // Computed facts, all defined for every input (indices guarded by `right_length`).
        let mut every_digit_ok = true;
        let mut pair = [0i32; 6];
        if right_length {
            let mut k = 0;
            while k < 12 {
                let b = c[k];
                if !(b >= 48 && b <= 57) {
                    every_digit_ok = false;
                }
                k += 1;
            }
            let mut f = 0;
            while f < 6 {
                pair[f] = (c[2 * f] as i32 - 48) * 10 + (c[2 * f + 1] as i32 - 48);
                f += 1;
            }
        }
        let zulu = right_length && c[12] == 90;
        let mut first_bad_field = None;
        let mut r = 0;
        while r < 5 {
            let (at, lo, hi, err) = RANGED[r];
            let v = pair[at / 2];
            if first_bad_field.is_none() && (v < lo || v > hi) {
                first_bad_field = Some(err);
            }
            r += 1;
        }
        if !right_length {
            Err(UtcTimeError::BadLength)
        } else if !every_digit_ok {
            Err(UtcTimeError::NonDigit)
        } else if !zulu {
            Err(UtcTimeError::NotZulu)
        } else if let Some(e) = first_bad_field {
            Err(e)
        } else {
            Ok(UtcTime {
                year2: pair[0] as u8,
                month: pair[1] as u8,
                day: pair[2] as u8,
                hour: pair[3] as u8,
                minute: pair[4] as u8,
                second: pair[5] as u8,
            })
        }
    }

    /// **Exact-result classification:** over a fully symbolic
    /// 14-octet buffer and every length `0..=14` (so every 13-octet input plus the 12/14 neighbours),
    /// `decode_utc_time(content) == reference_utc_time(content)` -- the exact `Result`, so a remapped
    /// error variant, a changed precedence on overlapping invalidity, or a wrong field value on `Ok`
    /// is a failure, not only the accept/reject boundary. Covers: every error variant and the
    /// accepting tail reach this assert, plus inputs where two invalidity conditions overlap (the
    /// documented precedence is what decides them).
    #[kani::proof]
    #[kani::unwind(14)]
    fn decode_is_exactly_the_reference() {
        let buf: [u8; 14] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 14);
        let c = &buf[..n];
        let got = decode_utc_time(c);
        let want = reference_utc_time(c);
        assert!(got == want);
        kani::cover(got == Err(UtcTimeError::BadLength), "BadLength reaches the exact-result assert");
        kani::cover(got == Err(UtcTimeError::NonDigit), "NonDigit reaches the exact-result assert");
        kani::cover(got == Err(UtcTimeError::NotZulu), "NotZulu reaches the exact-result assert");
        kani::cover(got == Err(UtcTimeError::MonthRange), "MonthRange reaches the exact-result assert");
        kani::cover(got == Err(UtcTimeError::DayRange), "DayRange reaches the exact-result assert");
        kani::cover(got == Err(UtcTimeError::HourRange), "HourRange reaches the exact-result assert");
        kani::cover(got == Err(UtcTimeError::MinuteRange), "MinuteRange reaches the exact-result assert");
        kani::cover(got == Err(UtcTimeError::SecondRange), "SecondRange reaches the exact-result assert");
        kani::cover(got.is_ok(), "an accepted value reaches the exact-result assert");
        kani::cover(
            got == Err(UtcTimeError::NonDigit) && n == 13 && buf[12] != b'Z',
            "overlap: a non-digit together with a non-'Z' terminator is NonDigit",
        );
        kani::cover(
            got == Err(UtcTimeError::NotZulu) && n == 13 && buf[12] != b'Z' && buf[2] == b'9' && buf[3] == b'9',
            "overlap: a non-'Z' terminator together with an out-of-range month is NotZulu",
        );
        kani::cover(
            got == Err(UtcTimeError::MonthRange) && n == 13 && buf[4] == b'9' && buf[5] == b'9',
            "overlap: an out-of-range month together with an out-of-range day is MonthRange",
        );
    }

    /// **Total encoder oracle.** Over fully symbolic fields (every `u8` per
    /// field, in or out of range), a symbolic output capacity `0..=16` over a symbolic 16-octet
    /// backing, `encode_utc_time` returns EXACTLY `Some(13)` when every field is in its canonical
    /// range AND the capacity is at least 13, and `None` otherwise. On `Some` the 13 emitted octets
    /// equal an independently built `YYMMDDHHMMSSZ` (each pair emitted by a right-to-left remainder
    /// loop, not the encoder's `/10`, `%10` pair), and the octets past 13 are untouched. The range
    /// predicate here is spelled from the documented ranges (YY `00..=99`, month `01..=12`, day
    /// `01..=31`, hour `00..=23`, minute `00..=59`, second `00..=59`), not from `fields_in_range`.
    /// The documented write contract ("on `None` nothing is written to `out`; on `Some(n)` only
    /// `out[..n]` is written") is asserted for every input: `out` is unchanged on `None`, and
    /// `out[n..]` is unchanged on `Some(n)`.
    /// Covers: success, an in-range value rejected only for capacity (the `Some(0)`-on-short-buffer
    /// shape), and an out-of-range value rejected with ample capacity.
    #[kani::proof]
    #[kani::unwind(18)]
    fn encode_is_total_exact_oracle() {
        let t = UtcTime {
            year2: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
        };
        let backing: [u8; 16] = kani::any();
        let mut out = backing;
        let cap: usize = kani::any();
        kani::assume(cap <= 16);
        let r = encode_utc_time(&t, &mut out[..cap]);
        // Rustdoc write contract: `None` => nothing written; `Some(n)` => only `out[..n]` written.
        match r {
            None => assert!(out == backing),
            Some(n) => assert!(out[n..] == backing[n..]),
        }

        let in_range = t.year2 <= 99
            && (t.month >= 1 && t.month <= 12)
            && (t.day >= 1 && t.day <= 31)
            && t.hour <= 23
            && t.minute <= 59
            && t.second <= 59;
        if in_range && cap >= 13 {
            assert!(r == Some(13));
            // independent expected bytes: two digits per field, filled right to left.
            let fields = [t.year2, t.month, t.day, t.hour, t.minute, t.second];
            let mut want = [0u8; 13];
            let mut f = 0;
            while f < 6 {
                let mut v = fields[f];
                let mut k = 2;
                while k > 0 {
                    k -= 1;
                    want[2 * f + k] = 48 + v % 10;
                    v /= 10;
                }
                f += 1;
            }
            want[12] = 90;
            assert!(out[..13] == want);
            assert!(out[13..] == backing[13..]);
        } else {
            assert!(r.is_none());
        }
        kani::cover(r == Some(13), "a valid time into sufficient capacity is encoded");
        kani::cover(r.is_none() && in_range && cap < 13, "a valid time into insufficient capacity is None");
        kani::cover(r.is_none() && !in_range && cap >= 13, "an out-of-range field with ample capacity is None");
        kani::cover(r == Some(13) && cap == 13, "the exact-fit capacity is accepted");
    }

    // --- Error-class correctness (one harness per rejection reason). ---

    /// Any content whose length isn't 13 is `BadLength` (covers the seconds-less and offset forms).
    #[kani::proof]
    #[kani::unwind(18)]
    fn wrong_length_is_bad_length() {
        let buf: [u8; 17] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 17 && n != 13);
        assert!(decode_utc_time(&buf[..n]) == Err(UtcTimeError::BadLength));
    }

    /// A non-digit anywhere in positions `0..=11` (13-octet input) is `NonDigit`. The base is an
    /// otherwise-*canonical* string (230101000000Z) so the poked non-digit is the sole reason for
    /// rejection — the classification does not lean on the digit-vs-range check ordering (review nit).
    #[kani::proof]
    #[kani::unwind(14)]
    fn non_digit_is_classified() {
        let mut c = *b"230101000000Z";
        let p: usize = kani::any();
        kani::assume(p < 12);
        let bad: u8 = kani::any();
        kani::assume(!bad.is_ascii_digit());
        c[p] = bad;
        assert!(decode_utc_time(&c) == Err(UtcTimeError::NonDigit));
    }

    /// A 13-octet all-digit-prefix string whose terminator isn't `'Z'` is `NotZulu` (local time,
    /// offset sign, or lowercase `z`). Digits are a valid canonical time so only the terminator differs.
    #[kani::proof]
    #[kani::unwind(14)]
    fn not_zulu_is_classified() {
        // "230101000000" + terminator: a valid date/time prefix, so the range checks would pass.
        let mut c = [b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', 0];
        let term: u8 = kani::any();
        kani::assume(term != b'Z');
        c[12] = term;
        assert!(decode_utc_time(&c) == Err(UtcTimeError::NotZulu));
    }

    /// An out-of-range month (`00` or `13..=99`) with an otherwise-canonical string is `MonthRange`.
    #[kani::proof]
    #[kani::unwind(14)]
    fn month_range_is_classified() {
        let mo: u8 = kani::any();
        kani::assume(mo <= 99 && !(mo >= 1 && mo <= 12));
        // year 23, day 01, 00:00:00 Z — everything else canonical, so month is the first failure.
        let mut c = [b'2', b'3', 0, 0, b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
        write_two(&mut c, 2, mo);
        assert!(decode_utc_time(&c) == Err(UtcTimeError::MonthRange));
    }

    /// An out-of-range day (`00` or `32..=99`) with an otherwise-canonical string is `DayRange`.
    #[kani::proof]
    #[kani::unwind(14)]
    fn day_range_is_classified() {
        let d: u8 = kani::any();
        kani::assume(d <= 99 && !(d >= 1 && d <= 31));
        let mut c = [b'2', b'3', b'0', b'1', 0, 0, b'0', b'0', b'0', b'0', b'0', b'0', b'Z'];
        write_two(&mut c, 4, d);
        assert!(decode_utc_time(&c) == Err(UtcTimeError::DayRange));
    }

    /// An out-of-range hour (`24..=99`, including the forbidden midnight `24`) is `HourRange`.
    #[kani::proof]
    #[kani::unwind(14)]
    fn hour_range_is_classified() {
        let h: u8 = kani::any();
        kani::assume(h <= 99 && h > 23);
        let mut c = [b'2', b'3', b'0', b'1', b'0', b'1', 0, 0, b'0', b'0', b'0', b'0', b'Z'];
        write_two(&mut c, 6, h);
        assert!(decode_utc_time(&c) == Err(UtcTimeError::HourRange));
    }

    /// An out-of-range minute (`60..=99`) is `MinuteRange`.
    #[kani::proof]
    #[kani::unwind(14)]
    fn minute_range_is_classified() {
        let m: u8 = kani::any();
        kani::assume(m <= 99 && m > 59);
        let mut c = [b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', 0, 0, b'0', b'0', b'Z'];
        write_two(&mut c, 8, m);
        assert!(decode_utc_time(&c) == Err(UtcTimeError::MinuteRange));
    }

    /// An out-of-range second (`60..=99`, including the rejected leap second `60`) is `SecondRange`.
    /// This is the harness memorializing the leap-second decision (see `DECISIONS.md`).
    #[kani::proof]
    #[kani::unwind(14)]
    fn second_range_is_classified() {
        let s: u8 = kani::any();
        kani::assume(s <= 99 && s > 59);
        let mut c = [b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', 0, 0, b'Z'];
        write_two(&mut c, 10, s);
        assert!(decode_utc_time(&c) == Err(UtcTimeError::SecondRange));
    }

    /// **Decoder postcondition:** every [`UtcTime`] `decode_utc_time` returns has all six fields in
    /// their canonical ranges — in particular `year2 <= 99`.
    ///
    /// Why this is not redundant with `accepted_iff_canonical_oracle`, which already pins the
    /// accepted *byte* set: `UtcTime`'s fields are `pub`, so a struct literal can hold
    /// `year2: 200`, and [`full_year_rfc5280`] would map that to `2100`. Claims elsewhere in this
    /// crate — most visibly `crate::profile`'s "a `Time::Utc` value can never denote a year >= 2050,
    /// by construction" — hold for values *this decoder produced*, and nothing stated that as a
    /// proved property. `full_year_pivot_is_correct` below *assumes* `y <= 99`; this harness is what
    /// discharges that assumption for decoded values, over symbolic content, so the two compose into
    /// an unconditional statement about decoder output.
    #[kani::proof]
    #[kani::unwind(14)]
    fn decode_postcondition_fields_in_range() {
        let buf: [u8; 14] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 14);
        if let Ok(t) = decode_utc_time(&buf[..n]) {
            assert!(fields_in_range(&t));
        }
        // The assert above is discharged CONDITIONALLY (inside `if let Ok`), so on its own it would
        // also hold if the decoder never accepted anything. These two witness that both sides of
        // the century pivot are reachable from real symbolic content, which is what makes the
        // postcondition -- and `profile`'s use of it -- non-vacuous.
        if let Ok(t) = decode_utc_time(&buf[..n]) {
            kani::cover(t.year2 < 50, "a decoded UTCTime on the 20YY side of the pivot is reachable");
            kani::cover(t.year2 >= 50, "a decoded UTCTime on the 19YY side of the pivot is reachable");
        }
    }

    /// The RFC 5280 century-pivot profile helper is total and follows the documented mapping over
    /// EVERY `u8` `year2` (all 256 values), with every other field symbolic too (the helper reads
    /// only `year2`): `< 50 ⇒ 20YY`, `≥ 50 ⇒ 19YY`, i.e. `2000 + year2` / `1900 + year2` as `u16`,
    /// never panicking. For `year2 <= 99` (the field's documented range, `00..=99`, and the decoder
    /// postcondition `decode_postcondition_fields_in_range`) the result is in the RFC 5280
    /// §4.1.2.5.1 window `1950..=2049`.
    ///
    /// Disclosure: `UtcTime`'s fields are `pub`, so a hand-built `year2 > 99` is representable. The
    /// field documentation puts such values outside the type's documented range, and the
    /// `full_year_rfc5280` rustdoc states the formula without a domain; this harness therefore pins
    /// the formula's literal extension there (`1900 + year2`). Values `100..=149` map to
    /// `2000..=2049`; only values `150..=255` map above 2049. It is NOT a claim that such values are
    /// valid input.
    #[kani::proof]
    fn full_year_pivot_is_correct() {
        let y: u8 = kani::any();
        let t = UtcTime {
            year2: y,
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
        };
        let full = full_year_rfc5280(&t);
        if y < 50 {
            assert!(full == 2000 + y as u16);
        } else {
            assert!(full == 1900 + y as u16);
        }
        if y <= 99 {
            assert!(full >= 1950 && full <= 2049);
        }
        kani::cover(y < 50, "the 20YY side of the pivot");
        kani::cover(y >= 50 && y <= 99, "the 19YY side of the pivot, inside 00..=99");
        kani::cover(y > 99 && full > 2049, "a hand-built year2 of 150 or more maps above 2049");
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_canonical() {
        // 991231235959Z = 1999-12-31 23:59:59 UTC (raw fields; century not applied here)
        let t = decode_utc_time(b"991231235959Z").unwrap();
        assert_eq!(t, UtcTime { year2: 99, month: 12, day: 31, hour: 23, minute: 59, second: 59 });
    }

    #[test]
    fn decodes_epoch_like() {
        // 000101000000Z = year 00, Jan 01, 00:00:00
        let t = decode_utc_time(b"000101000000Z").unwrap();
        assert_eq!(t, UtcTime { year2: 0, month: 1, day: 1, hour: 0, minute: 0, second: 0 });
    }

    #[test]
    fn roundtrips_via_encode() {
        let t = UtcTime { year2: 23, month: 6, day: 15, hour: 12, minute: 30, second: 45 };
        let mut out = [0u8; 13];
        let w = encode_utc_time(&t, &mut out).unwrap();
        assert_eq!(&out[..w], b"230615123045Z");
        assert_eq!(decode_utc_time(&out[..w]).unwrap(), t);
    }

    #[test]
    fn rfc5280_century_mapping() {
        // profile helper only (not part of decode): 49 -> 2049, 50 -> 1950
        assert_eq!(full_year_rfc5280(&UtcTime { year2: 49, month: 1, day: 1, hour: 0, minute: 0, second: 0 }), 2049);
        assert_eq!(full_year_rfc5280(&UtcTime { year2: 50, month: 1, day: 1, hour: 0, minute: 0, second: 0 }), 1950);
    }

    // --- seeded-bad specimens: each MUST be rejected ---
    #[test]
    fn rejects_missing_seconds() {
        // 9912312359Z — the BER seconds-less form (11 octets). DER requires seconds (§11.8).
        assert_eq!(decode_utc_time(b"9912312359Z"), Err(UtcTimeError::BadLength));
    }
    #[test]
    fn rejects_local_time_without_z() {
        // 991231235959 — no terminator (12 octets); a local-time reading a strict signer never emits.
        assert_eq!(decode_utc_time(b"991231235959"), Err(UtcTimeError::BadLength));
    }
    #[test]
    fn rejects_offset_form() {
        // 991231235959+0500 — a UTC offset (17 octets). DER forbids offsets; must be Z.
        assert_eq!(decode_utc_time(b"991231235959+0500"), Err(UtcTimeError::BadLength));
    }
    #[test]
    fn rejects_lowercase_z() {
        // 991231235959z — lowercase terminator; DER requires uppercase 'Z'.
        assert_eq!(decode_utc_time(b"991231235959z"), Err(UtcTimeError::NotZulu));
    }
    #[test]
    fn rejects_non_digit() {
        // a letter in a digit position
        assert_eq!(decode_utc_time(b"9912312359X9Z"), Err(UtcTimeError::NonDigit));
    }
    #[test]
    fn rejects_hour_24() {
        // 991231245959Z — hour 24 (forbidden midnight-at-end; canonical is 00 of the next day).
        assert_eq!(decode_utc_time(b"991231245959Z"), Err(UtcTimeError::HourRange));
    }
    #[test]
    fn rejects_leap_second_60() {
        // 991231235960Z — second 60 (leap second). X.680 permits it; we reject for the X.509
        // anti-differential profile (see DECISIONS.md).
        assert_eq!(decode_utc_time(b"991231235960Z"), Err(UtcTimeError::SecondRange));
    }
    #[test]
    fn rejects_month_13_and_00() {
        assert_eq!(decode_utc_time(b"991331235959Z"), Err(UtcTimeError::MonthRange));
        assert_eq!(decode_utc_time(b"990031235959Z"), Err(UtcTimeError::MonthRange));
    }
    #[test]
    fn rejects_day_32_and_00() {
        assert_eq!(decode_utc_time(b"991232235959Z"), Err(UtcTimeError::DayRange));
        assert_eq!(decode_utc_time(b"991200235959Z"), Err(UtcTimeError::DayRange));
    }
    #[test]
    fn rejects_minute_60() {
        assert_eq!(decode_utc_time(b"991231236059Z"), Err(UtcTimeError::MinuteRange));
    }

    // --- encode-side guards (encode_utc_time's None-returning branches) ---
    #[test]
    fn encode_rejects_out_of_range_fields() {
        // month = 13 is out of range -- fields_in_range fails before the buffer-size check.
        let t = UtcTime { year2: 23, month: 13, day: 1, hour: 0, minute: 0, second: 0 };
        let mut out = [0u8; 13];
        assert_eq!(encode_utc_time(&t, &mut out), None);
    }
    #[test]
    fn encode_rejects_output_buffer_too_small() {
        // a valid UtcTime always needs 13 bytes; a 12-byte buffer is too small.
        let t = UtcTime { year2: 23, month: 6, day: 15, hour: 12, minute: 30, second: 45 };
        let mut out = [0u8; 12];
        assert_eq!(encode_utc_time(&t, &mut out), None);
    }
}
