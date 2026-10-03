//! DER GeneralizedTime content (X.690 §11.7, §8.25; type UNIVERSAL 24 / identifier `0x18`).
//!
//! DER admits exactly one GeneralizedTime spelling: the ASCII string `YYYYMMDDHHMMSS[.fff]Z` — a
//! 4-digit year, mandatory seconds, an optional canonical fraction, and the `Z` terminator. This
//! module validates the *content* octets of a TLV whose tag is UNIVERSAL 24, and **nothing else** —
//! like the other content decoders, this codec carries the *content* canonicality and does not look
//! at the identifier.
//!
//! **The identifier is not enforced upstream.** Of the tag identity and the primitive/definite
//! form, only the **definite**-length half is enforced by [`crate::tlv`] (it delegates to
//! [`crate::length`], which rejects the indefinite form) — and only if you actually entered through
//! `tlv`, which this function, taking content octets, cannot tell. The **primitive**-form half and
//! the **tag identity** are enforced by neither [`crate::tag`] nor [`crate::tlv`]: `decode_tag`
//! attaches no meaning to the class/constructed combination and `decode_tlv` passes the parsed
//! `Tag` through untouched.
//!
//! Where each IS decided, and they are **not** the same place: **tag identity (this is UNIVERSAL
//! 24) is decided only by typed callers** — `x509_validity.rs`'s `decode_time_tlv` rejects a
//! non-UNIVERSAL class (`WrongTag`) and a constructed GeneralizedTime (`Constructed`) before
//! dispatching here. The **primitive-form rule** is decided generically by
//! [`crate::identifier_form`], which decides *form only* and does not know which tag you expected.
//! **A direct caller of [`decode_generalized_time`] must decide the identifier itself.**
//!
//! The canonical form, verified against the standards:
//! - **Terminates with `'Z'`** (§11.7) — local time and `±HHMM` offsets are forbidden.
//! - **Seconds always present** (§11.7), so the mandatory part is *exactly* `YYYYMMDDHHMMSS` = 14
//!   octets. The BER minute- or hour-only forms are rejected as `BadLength`.
//! - **Fractional seconds are allowed but canonical** (§11.7): if present, the separator is the point
//!   `'.'` (a comma is forbidden), at least one digit follows, and there are **no trailing zeros**; an
//!   all-zero fraction (and its `'.'`) is **omitted entirely**. This codec *validates* (it does not
//!   normalize): the canonical spelling is `.1` (not `.100`) and no fraction at all (not `.000`), so
//!   the non-canonical `.100` / `.000` forms are **rejected**, not rewritten.
//! - **Field ranges** (X.680 base type): month `01..=12`, day `01..=31`, hour `00..=23` (so `24` is
//!   rejected), minute `00..=59`, second `00..=59`. The 4-digit year is unconstrained (`0000..=9999`).
//!
//! **Scope boundary (see `DECISIONS.md`).**
//! - This implements the **X.690 DER** transfer syntax, where fractions *are* permitted. **RFC 5280
//!   §4.1.2.5.2** additionally forbids fractional seconds in X.509 certificates — a *profile* rule
//!   applied with [`require_no_fraction`] (the same generic-syntax-vs-profile split as
//!   [`crate::bit_string`]'s `require_octet_aligned`). [`crate::profile::validate_profile`] applies it
//!   to a certificate's `notBefore` and `notAfter`; a caller using this module on its own applies it
//!   itself.
//! - **Leap second `SS=60` is rejected** (second `00..=59`) — a deliberate deviation for the X.509
//!   anti-differential profile (X.680 permits `60`; real signers never emit it). Documented, contestable.
//! - **Calendar validity is out of scope** — fields are range-checked independently; `day` is uniformly
//!   `01..=31` (no Feb-29 / per-month-length check). Clock/timezone math is out of scope.
//!
//! # Examples
//!
//! ```
//! use der_verified::generalized_time::decode_generalized_time;
//!
//! // 20230615120000.52Z — canonical fractional seconds (no trailing zero).
//! let t = decode_generalized_time(b"20230615120000.52Z").unwrap();
//! assert_eq!(t.year, 2023);
//! assert_eq!(t.second, 0);
//! assert_eq!(t.fraction, b"52");
//! ```

/// The universal tag number for GeneralizedTime.
pub const TAG: u32 = 24;

/// A decoded DER GeneralizedTime. Raw values from the string; no calendar/timezone interpretation.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct GeneralizedTime<'a> {
    /// Four-digit year, `0000..=9999`.
    pub year: u16,
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
    /// The canonical fractional-second **digits** (no `'.'`, no `'Z'`): empty when there is no
    /// fraction, otherwise `1..` digits whose last is **not** `'0'` (the §11.7 no-trailing-zero form).
    pub fraction: &'a [u8],
}

/// Why GeneralizedTime content was rejected. Each rejection is a distinct, testable reason.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum GeneralizedTimeError {
    /// Content was shorter than the minimal canonical form `YYYYMMDDHHMMSSZ` (15 octets) — includes
    /// the seconds-less / minute-only BER forms.
    BadLength,
    /// A position that must be an ASCII digit (a mandatory `0..=13` position or a fraction digit) was
    /// not `b'0'..=b'9'`.
    NonDigit,
    /// The final octet was not `'Z'` — a local-time, offset, or lowercase-`z` terminator (§11.7).
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
    /// The octet after the 14 mandatory digits was neither `'.'` nor the `'Z'` terminator — e.g. a
    /// comma decimal separator (forbidden by §11.7), or a stray character.
    BadFractionSeparator,
    /// A `'.'` separator was present but no fraction digits followed before `'Z'` (`.Z`).
    FractionEmpty,
    /// The fraction ended in `'0'` — a trailing zero (or an all-zero fraction that should have been
    /// omitted entirely), forbidden by §11.7.
    FractionTrailingZero,
}

/// Read two ASCII digits at `b[i]`, `b[i+1]` as `00..=99`. Caller must have validated both as digits.
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

/// Whether a fraction slice is the canonical §11.7 form: all ASCII digits, and (if non-empty) the
/// last digit is not `'0'`. The empty slice (no fraction) is canonical.
#[inline]
fn fraction_is_canonical(frac: &[u8]) -> bool {
    let mut i = 0;
    while i < frac.len() {
        if !frac[i].is_ascii_digit() {
            return false;
        }
        i += 1;
    }
    frac.is_empty() || frac[frac.len() - 1] != b'0'
}

/// Whether the non-fraction fields are all in their canonical ranges.
#[inline]
fn fields_in_range(t: &GeneralizedTime<'_>) -> bool {
    t.year <= 9999
        && t.month >= 1
        && t.month <= 12
        && t.day >= 1
        && t.day <= 31
        && t.hour <= 23
        && t.minute <= 59
        && t.second <= 59
}

/// Decode DER GeneralizedTime content octets. Accepts **only** the canonical
/// `YYYYMMDDHHMMSS[.fff]Z` form: mandatory 14 digits, in-range fields, an optional canonical fraction
/// (point separator, ≥1 digit, no trailing zero), and the `'Z'` terminator.
///
/// The fraction length is **not** capped (X.690 sets no bound); validation is a single linear pass
/// over `content` with no allocation or amplification, so bounding total input size against resource
/// exhaustion is a caller / upstream concern (the TLV length codec already bounds the content), in
/// keeping with the encoding-only scope (`DECISIONS.md` D10).
///
/// **Error precedence (documented, not left to inference).** When an input has more than one
/// defect, the reported [`GeneralizedTimeError`] is the first applicable one in this order -- the
/// mandatory part first, then the field ranges in field order, then the optional fraction:
/// 1. [`GeneralizedTimeError::BadLength`] -- fewer than 15 octets;
/// 2. [`GeneralizedTimeError::NonDigit`] -- any of the mandatory positions `0..=13` is not an ASCII
///    digit;
/// 3. [`GeneralizedTimeError::NotZulu`] -- the final octet is not `'Z'`;
/// 4. the field ranges, in field order `MM DD HH MM SS`: [`GeneralizedTimeError::MonthRange`], then
///    [`GeneralizedTimeError::DayRange`], then [`GeneralizedTimeError::HourRange`], then
///    [`GeneralizedTimeError::MinuteRange`], then [`GeneralizedTimeError::SecondRange`] (the
///    four-digit year has no range check);
/// 5. the fraction checks, reached only when the input is longer than 15 octets, in this order:
///    [`GeneralizedTimeError::BadFractionSeparator`] (octet 14 is not `'.'` -- this includes a `'Z'`
///    at octet 14 with further octets after it), then [`GeneralizedTimeError::FractionEmpty`] (`'.'`
///    directly followed by the terminating `'Z'`), then [`GeneralizedTimeError::NonDigit`] (a
///    non-digit among the fraction digits), then [`GeneralizedTimeError::FractionTrailingZero`].
///
/// So a fraction defect never outranks a mandatory-part or field-range defect, and a `NonDigit` in
/// the fraction ranks after `NotZulu` and the range errors (while a `NonDigit` in the mandatory
/// part ranks before them). A Kani harness (`proofs::decode_is_exactly_the_reference`) pins this
/// order against an independent reference.
pub fn decode_generalized_time(content: &[u8]) -> Result<GeneralizedTime<'_>, GeneralizedTimeError> {
    // Minimal canonical form is `YYYYMMDDHHMMSS` + `Z` = 15 octets.
    if content.len() < 15 {
        return Err(GeneralizedTimeError::BadLength);
    }
    // Positions 0..=13 are the mandatory YYYYMMDDHHMMSS digits.
    let mut i = 0;
    while i < 14 {
        if !content[i].is_ascii_digit() {
            return Err(GeneralizedTimeError::NonDigit);
        }
        i += 1;
    }
    // The final octet must be the 'Z' terminator.
    let last = content.len() - 1;
    if content[last] != b'Z' {
        return Err(GeneralizedTimeError::NotZulu);
    }
    let year = two_digits(content, 0) as u16 * 100 + two_digits(content, 2) as u16;
    let month = two_digits(content, 4);
    let day = two_digits(content, 6);
    let hour = two_digits(content, 8);
    let minute = two_digits(content, 10);
    let second = two_digits(content, 12);
    if month < 1 || month > 12 {
        return Err(GeneralizedTimeError::MonthRange);
    }
    if day < 1 || day > 31 {
        return Err(GeneralizedTimeError::DayRange);
    }
    if hour > 23 {
        return Err(GeneralizedTimeError::HourRange);
    }
    if minute > 59 {
        return Err(GeneralizedTimeError::MinuteRange);
    }
    if second > 59 {
        return Err(GeneralizedTimeError::SecondRange);
    }
    // The middle segment `content[14..last]` is either empty (no fraction) or `.` + fraction digits.
    let fraction: &[u8] = if last == 14 {
        // len == 15: no fraction; content[14] is the 'Z' terminator.
        &content[14..14]
    } else {
        // A fraction is present: the separator must be the point '.', not a comma or other char.
        if content[14] != b'.' {
            return Err(GeneralizedTimeError::BadFractionSeparator);
        }
        let frac = &content[15..last];
        if frac.is_empty() {
            return Err(GeneralizedTimeError::FractionEmpty);
        }
        let mut j = 0;
        while j < frac.len() {
            if !frac[j].is_ascii_digit() {
                return Err(GeneralizedTimeError::NonDigit);
            }
            j += 1;
        }
        // No trailing zero — this also forbids an all-zero fraction (which must be omitted, §11.7).
        if frac[frac.len() - 1] == b'0' {
            return Err(GeneralizedTimeError::FractionTrailingZero);
        }
        frac
    };
    Ok(GeneralizedTime { year, month, day, hour, minute, second, fraction })
}

/// Encode a [`GeneralizedTime`] as canonical DER content (`YYYYMMDDHHMMSS[.fff]Z`) into `out`.
///
/// Returns the number of octets written, or `None` if any field is out of range, the fraction is not
/// canonical (non-digit or trailing zero), or `out` is too small. The guards make this the exact
/// inverse of [`decode_generalized_time`].
///
/// On `None` nothing is written to `out`; on `Some(n)` only `out[..n]` is written.
pub fn encode_generalized_time_into(t: &GeneralizedTime<'_>, out: &mut [u8]) -> Option<usize> {
    if !fields_in_range(t) {
        return None;
    }
    if !fraction_is_canonical(t.fraction) {
        return None;
    }
    let has_frac = !t.fraction.is_empty();
    // 14 mandatory digits + optional ('.' + fraction) + 'Z'. `fraction.len()` is bounded by the
    // slice-size invariant (≤ isize::MAX), so the additions never overflow `usize`.
    let total = 14 + if has_frac { 1 + t.fraction.len() } else { 0 } + 1;
    if out.len() < total {
        return None;
    }
    out[0] = b'0' + (t.year / 1000) as u8;
    out[1] = b'0' + (t.year / 100 % 10) as u8;
    out[2] = b'0' + (t.year / 10 % 10) as u8;
    out[3] = b'0' + (t.year % 10) as u8;
    write_two(out, 4, t.month);
    write_two(out, 6, t.day);
    write_two(out, 8, t.hour);
    write_two(out, 10, t.minute);
    write_two(out, 12, t.second);
    let mut pos = 14;
    if has_frac {
        out[pos] = b'.';
        pos += 1;
        let mut k = 0;
        while k < t.fraction.len() {
            out[pos + k] = t.fraction[k];
            k += 1;
        }
        pos += t.fraction.len();
    }
    out[pos] = b'Z';
    Some(pos + 1)
}

/// Require the **RFC 5280 §4.1.2.5.2** profile form: no fractional seconds. Generic DER permits a
/// canonical fraction, but X.509 certificates must not carry one; a caller in that context applies
/// this ([`crate::profile::validate_profile`] does so for `validity`). Returns `true` iff `t` has no fraction (mirrors [`crate::bit_string::require_octet_aligned`]).
pub fn require_no_fraction(t: &GeneralizedTime<'_>) -> bool {
    t.fraction.is_empty()
}

// ---------------------------------------------------------------------------
// Kani proof harnesses (the L3 floor).
// ---------------------------------------------------------------------------
#[cfg(kani)]
mod proofs {
    use super::*;

    /// **Independent** oracle for this library's *profile-canonical* GeneralizedTime set: the X.690
    /// §11.7 structural form (mandatory digits, `Z` terminator, canonical fraction) + the X.680 field
    /// ranges, **narrowed by the one documented deviation** — leap second `SS=60` is excluded (X.680
    /// *permits* `60`; we reject it for the X.509 anti-differential profile, see `DECISIONS.md`). It
    /// is stated declaratively, deliberately *not* by calling `decode`/`encode`, so the biconditional
    /// below is a genuine conformance check against this predicate, not a tautology restating the
    /// parser (a hard-won parser-differential lesson). This is the artifact the independent audit
    /// targets: `decode`'s
    /// accepted set must equal *exactly* this set — no over-acceptance (a differential hole) and no
    /// over-rejection *beyond* the single documented leap-second narrowing (a broken cert). Note this
    /// is the **X.690 DER** transfer syntax, in which fractional seconds are canonical-and-allowed;
    /// the RFC 5280 no-fraction rule is a separate profile check ([`super::require_no_fraction`]), not
    /// folded into this oracle. Independence is reinforced by a *second, control-flow-distinct* angle:
    /// `decode_accepts_only_canonical` re-encodes every accepted value through `encode` and checks it
    /// reproduces the input byte-for-byte — so an accepted-but-non-canonical string would have to
    /// survive **both** this biconditional and the round-trip, which a shared oracle/decoder mistake
    /// could not (the encoder emits only the canonical layout).
    fn is_canonical_der_generalizedtime(c: &[u8]) -> bool {
        if c.len() < 15 {
            return false;
        }
        let mut i = 0;
        while i < 14 {
            if c[i] < b'0' || c[i] > b'9' {
                return false;
            }
            i += 1;
        }
        let last = c.len() - 1;
        if c[last] != b'Z' {
            return false;
        }
        let month = (c[4] - b'0') * 10 + (c[5] - b'0');
        let day = (c[6] - b'0') * 10 + (c[7] - b'0');
        let hour = (c[8] - b'0') * 10 + (c[9] - b'0');
        let minute = (c[10] - b'0') * 10 + (c[11] - b'0');
        let second = (c[12] - b'0') * 10 + (c[13] - b'0');
        if !(month >= 1 && month <= 12) {
            return false;
        }
        if !(day >= 1 && day <= 31) {
            return false;
        }
        if hour > 23 || minute > 59 || second > 59 {
            return false;
        }
        if last == 14 {
            // No fraction (length 15).
            return true;
        }
        // A fraction is present: point separator, ≥1 digit, no trailing zero.
        if c[14] != b'.' {
            return false;
        }
        if last == 15 {
            // Empty fraction ("`.Z`").
            return false;
        }
        let mut j = 15;
        while j < last {
            if c[j] < b'0' || c[j] > b'9' {
                return false;
            }
            j += 1;
        }
        c[last - 1] != b'0'
    }

    /// Round-trip: every in-range field tuple with a canonical fraction (0..=3 digits) encodes to
    /// content that decodes back to exactly it. Fields and fraction are symbolic (constrained to the
    /// canonical set) so the whole accepted value set up to 3 fraction digits is covered.
    #[kani::proof]
    #[kani::unwind(20)]
    fn roundtrip_all_fields() {
        let year: u16 = kani::any();
        kani::assume(year <= 9999);
        let frac: [u8; 3] = kani::any();
        let fl: usize = kani::any();
        kani::assume(fl <= 3);
        let mut k = 0;
        while k < fl {
            kani::assume(frac[k].is_ascii_digit());
            k += 1;
        }
        if fl > 0 {
            kani::assume(frac[fl - 1] != b'0'); // canonical: no trailing zero
        }
        let t = GeneralizedTime {
            year,
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
            fraction: &frac[..fl],
        };
        kani::assume(fields_in_range(&t));
        let mut out = [0u8; 19];
        let w = encode_generalized_time_into(&t, &mut out).unwrap();
        let dec = decode_generalized_time(&out[..w]).unwrap();
        assert!(dec == t);
    }

    /// Robustness: `decode_generalized_time` never panics/overflows on *any* input. The 19-octet
    /// symbolic window covers length 15..=19 — no-fraction (15), empty-fraction (16), and 1..=3-digit
    /// fractions — plus the sub-15 lengths that early-return `BadLength`. Fraction length is the only
    /// unbounded axis, and the decode logic over it (a digit loop + a last-octet test) is uniform, so
    /// no new behaviour appears beyond 3 fraction digits; the bounded L3 floor's ∀-length counterpart
    /// would be a Lean lid, as on the length codec.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached for BOTH the no-fraction (`n ==
    /// 15`) AND the with-fraction (`n >= 16`) shapes -- so the module's claim that this window
    /// "covers no-fraction, empty-fraction, and 1..=3-digit fractions" is a checked post-state
    /// fact, not just an input-length observation. Would NOT be SAT if `decode_generalized_time`'s
    /// body were a no-op always returning `Err`.
    #[kani::proof]
    #[kani::unwind(20)]
    fn decode_never_panics() {
        let buf: [u8; 19] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 19);
        let result = decode_generalized_time(&buf[..n]);
        kani::cover(result.is_ok(), "a well-formed GeneralizedTime reaches the Ok tail");
        if let Ok(t) = result {
            kani::cover(t.fraction.is_empty(), "a no-fraction GeneralizedTime is accepted");
            kani::cover(!t.fraction.is_empty(), "a with-fraction GeneralizedTime is accepted");
        }
        let _ = result;
    }

    /// Canonicality (re-encode form): any accepted content re-encodes to *itself*.
    #[kani::proof]
    #[kani::unwind(20)]
    fn decode_accepts_only_canonical() {
        let buf: [u8; 19] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 19);
        if let Ok(t) = decode_generalized_time(&buf[..n]) {
            let mut out = [0u8; 19];
            let w = encode_generalized_time_into(&t, &mut out).unwrap();
            assert!(w == n);
            assert!(out[..w] == buf[..n]);
        }
    }

    /// Canonicality (de-tautologized oracle — the audit target): the accepted set equals
    /// *exactly* the independent X.690 §11.7 predicate, in both directions. No non-canonical encoding
    /// is ever accepted (no differential hole) and no canonical encoding is ever rejected.
    #[kani::proof]
    #[kani::unwind(20)]
    fn accepted_iff_canonical_oracle() {
        let buf: [u8; 19] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 19);
        let result = decode_generalized_time(&buf[..n]);
        assert!(result.is_ok() == is_canonical_der_generalizedtime(&buf[..n]));
        kani::cover!(result.is_ok());
        // Value faithfulness: each decoded field is the ASCII digits at its own byte positions
        // (YYYY MM DD HH MM SS, then the fraction between the '.' and the 'Z'), stated directly on
        // the input rather than as the inverse of `encode` -- so a field read from the wrong
        // position is caught even if `encode` mirrors it.
        if let Ok(t) = result {
            let d = |i: usize| (buf[i] - b'0') as u16;
            assert!(t.year == d(0) * 1000 + d(1) * 100 + d(2) * 10 + d(3));
            assert!(t.month as u16 == d(4) * 10 + d(5));
            assert!(t.day as u16 == d(6) * 10 + d(7));
            assert!(t.hour as u16 == d(8) * 10 + d(9));
            assert!(t.minute as u16 == d(10) * 10 + d(11));
            assert!(t.second as u16 == d(12) * 10 + d(13));
            if n == 15 {
                assert!(t.fraction.is_empty());
            } else {
                assert!(t.fraction == &buf[15..n - 1]);
            }
        }
    }

    /// TOTAL reference for GeneralizedTime content: the exact `Result`, every error variant, with a
    /// precedence taken from the documentation (decoder rustdoc, "Error precedence"), NOT from the
    /// decoder's control flow. The order used:
    ///
    /// 1. `BadLength` (fewer than 15 octets) -- `GeneralizedTimeError::BadLength` doc.
    /// 2. `NonDigit` in a mandatory position `0..=13`, then
    /// 3. `NotZulu` (final octet), then
    /// 4. the first out-of-range field in the documented field order `MonthRange`, `DayRange`,
    ///    `HourRange`, `MinuteRange`, `SecondRange` -- the module's bullet list puts `'Z'` and the
    ///    mandatory digits ahead of the field ranges, and the enum declares them in this order.
    /// 5. The optional fraction, judged only after the mandatory part: `BadFractionSeparator`
    ///    (octet 14 is not `'.'` although more octets follow), `FractionEmpty` (`'.'` directly before
    ///    the final `'Z'`), `NonDigit` (a non-digit among the fraction digits -- the `NonDigit` doc
    ///    names fraction digits too), `FractionTrailingZero`.
    ///
    /// The whole order, including that the fraction-part checks (step 5) come after the field-range
    /// checks and their internal order, is stated in the "Error precedence" section of
    /// `decode_generalized_time`'s rustdoc (it is the module's adopted precedence; the enum
    /// declaration order alone would rank a fraction-digit `NonDigit` ahead of `NotZulu` and the
    /// ranges, which is NOT the documented order).
    ///
    /// Built unlike the decoder: a table of the five ranged fields, computed digit values for every
    /// pair, then one precedence-ordered `if` chain; the fraction facts come from per-position
    /// scans, not an early-return walk.
    fn reference_generalized_time(c: &[u8]) -> Result<GeneralizedTime<'_>, GeneralizedTimeError> {
        // (byte position of the pair, lowest legal value, highest legal value, error if outside).
        const RANGED: [(usize, i32, i32, GeneralizedTimeError); 5] = [
            (4, 1, 12, GeneralizedTimeError::MonthRange),
            (6, 1, 31, GeneralizedTimeError::DayRange),
            (8, 0, 23, GeneralizedTimeError::HourRange),
            (10, 0, 59, GeneralizedTimeError::MinuteRange),
            (12, 0, 59, GeneralizedTimeError::SecondRange),
        ];
        let len = c.len();
        let long_enough = len >= 15;
        let mut mandatory_digits_ok = true;
        let mut pair = [0i32; 7]; // pair[k] = value of the digits at 2k, 2k+1
        let mut zulu = false;
        let mut dot = false; // octet 14 is '.' AND more octets follow
        let mut fraction_digits_ok = true;
        let mut first_bad_field = None;
        if long_enough {
            let mut k = 0;
            while k < 14 {
                if !(c[k] >= 48 && c[k] <= 57) {
                    mandatory_digits_ok = false;
                }
                k += 1;
            }
            let mut f = 0;
            while f < 7 {
                pair[f] = (c[2 * f] as i32 - 48) * 10 + (c[2 * f + 1] as i32 - 48);
                f += 1;
            }
            zulu = c[len - 1] == 90;
            dot = len > 15 && c[14] == 46;
            let mut j = 15;
            while j + 1 < len {
                if !(c[j] >= 48 && c[j] <= 57) {
                    fraction_digits_ok = false;
                }
                j += 1;
            }
            let mut r = 0;
            while r < 5 {
                let (at, lo, hi, err) = RANGED[r];
                let v = pair[at / 2];
                if first_bad_field.is_none() && (v < lo || v > hi) {
                    first_bad_field = Some(err);
                }
                r += 1;
            }
        }
        if !long_enough {
            Err(GeneralizedTimeError::BadLength)
        } else if !mandatory_digits_ok {
            Err(GeneralizedTimeError::NonDigit)
        } else if !zulu {
            Err(GeneralizedTimeError::NotZulu)
        } else if let Some(e) = first_bad_field {
            Err(e)
        } else if len > 15 && !dot {
            Err(GeneralizedTimeError::BadFractionSeparator)
        } else if len == 16 {
            Err(GeneralizedTimeError::FractionEmpty)
        } else if !fraction_digits_ok {
            Err(GeneralizedTimeError::NonDigit)
        } else if len > 16 && c[len - 2] == 48 {
            Err(GeneralizedTimeError::FractionTrailingZero)
        } else {
            Ok(GeneralizedTime {
                year: (pair[0] * 100 + pair[1]) as u16,
                month: pair[2] as u8,
                day: pair[3] as u8,
                hour: pair[4] as u8,
                minute: pair[5] as u8,
                second: pair[6] as u8,
                fraction: if len == 15 { &c[0..0] } else { &c[15..len - 1] },
            })
        }
    }

    /// **Exact-result classification:** over a fully symbolic
    /// 19-octet buffer and every length `0..=19` (the existing bound: up to a three-digit fraction),
    /// `decode_generalized_time(content) == reference_generalized_time(content)` -- the exact
    /// `Result`: a remapped error variant, a changed precedence on overlapping invalidity, or a wrong
    /// field / fraction on `Ok` fails here, not only the accept/reject boundary. Covers: every error
    /// variant and both accepting shapes (with / without fraction) reach the assert, plus inputs where
    /// two invalidity conditions overlap.
    #[kani::proof]
    #[kani::unwind(20)]
    fn decode_is_exactly_the_reference() {
        let buf: [u8; 19] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 19);
        let c = &buf[..n];
        let got = decode_generalized_time(c);
        let want = reference_generalized_time(c);
        assert!(got == want);
        kani::cover(got == Err(GeneralizedTimeError::BadLength), "BadLength reaches the exact-result assert");
        kani::cover(got == Err(GeneralizedTimeError::NonDigit), "NonDigit reaches the exact-result assert");
        kani::cover(got == Err(GeneralizedTimeError::NotZulu), "NotZulu reaches the exact-result assert");
        kani::cover(got == Err(GeneralizedTimeError::MonthRange), "MonthRange reaches the exact-result assert");
        kani::cover(got == Err(GeneralizedTimeError::DayRange), "DayRange reaches the exact-result assert");
        kani::cover(got == Err(GeneralizedTimeError::HourRange), "HourRange reaches the exact-result assert");
        kani::cover(got == Err(GeneralizedTimeError::MinuteRange), "MinuteRange reaches the exact-result assert");
        kani::cover(got == Err(GeneralizedTimeError::SecondRange), "SecondRange reaches the exact-result assert");
        kani::cover(
            got == Err(GeneralizedTimeError::BadFractionSeparator),
            "BadFractionSeparator reaches the exact-result assert",
        );
        kani::cover(got == Err(GeneralizedTimeError::FractionEmpty), "FractionEmpty reaches the exact-result assert");
        kani::cover(
            got == Err(GeneralizedTimeError::FractionTrailingZero),
            "FractionTrailingZero reaches the exact-result assert",
        );
        kani::cover(matches!(got, Ok(t) if t.fraction.is_empty()), "an accepted value without a fraction");
        kani::cover(matches!(got, Ok(t) if !t.fraction.is_empty()), "an accepted value with a fraction");
        kani::cover(
            got == Err(GeneralizedTimeError::NonDigit) && n >= 15 && buf[n - 1] != b'Z',
            "overlap: a non-digit together with a non-'Z' terminator is NonDigit",
        );
        kani::cover(
            got == Err(GeneralizedTimeError::NotZulu) && n >= 15 && buf[4] == b'9' && buf[5] == b'9',
            "overlap: a non-'Z' terminator together with an out-of-range month is NotZulu",
        );
        kani::cover(
            got == Err(GeneralizedTimeError::MonthRange) && n >= 17 && buf[14] != b'.',
            "overlap: an out-of-range month together with a bad fraction separator is MonthRange",
        );
    }

    /// **`require_no_fraction` biconditional.** Over symbolic content decoded by
    /// `decode_generalized_time` (every length `0..=19`), whenever decoding succeeds,
    /// `require_no_fraction(&t)` is true exactly when the input carries no fraction. "No fraction" is
    /// stated from the INPUT, independently of `t.fraction`: the content has exactly 15 octets (the
    /// mandatory 14 digits plus the `'Z'`), i.e. nothing between the seconds and the terminator.
    /// The same biconditional is also asserted on a hand-built `GeneralizedTime` whose `fraction` is
    /// a symbolic slice of length `0..=3`, so the helper is pinned on non-canonical fractions too
    /// (it only looks at emptiness). Covers both polarities for decoded values.
    #[kani::proof]
    #[kani::unwind(20)]
    fn require_no_fraction_iff_no_fraction_octets() {
        let buf: [u8; 19] = kani::any();
        let n: usize = kani::any();
        kani::assume(n <= 19);
        if let Ok(t) = decode_generalized_time(&buf[..n]) {
            let no_fraction_in_input = n == 15;
            assert!(require_no_fraction(&t) == no_fraction_in_input);
            kani::cover(require_no_fraction(&t), "a decoded time without a fraction satisfies the profile");
            kani::cover(!require_no_fraction(&t), "a decoded time with a fraction violates the profile");
        }
        // hand-built value, symbolic fraction slice
        let frac: [u8; 3] = kani::any();
        let fl: usize = kani::any();
        kani::assume(fl <= 3);
        let built = GeneralizedTime {
            year: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
            fraction: &frac[..fl],
        };
        assert!(require_no_fraction(&built) == (fl == 0));
    }

    /// **Total encoder oracle.** Over fully symbolic fields (every `u16` year
    /// and every `u8` per other field, in or out of range), a symbolic fraction slice of length
    /// `0..=3` (arbitrary bytes: non-digits and trailing zeros included) and a symbolic output
    /// capacity `0..=20` over a symbolic 20-octet backing, `encode_generalized_time_into` returns
    /// EXACTLY `Some(total)` when the fields are in range, the fraction is canonical (all digits, no
    /// trailing zero) and the capacity is at least `total` (`15` without a fraction, `16 + len`
    /// with one), and `None` otherwise. On `Some` the emitted octets equal an independently built
    /// `YYYYMMDDHHMMSS[.fff]Z` (digits by a right-to-left remainder loop), and the octets past
    /// `total` are untouched. The documented write contract ("on `None` nothing is written to `out`;
    /// on `Some(n)` only `out[..n]` is written") is asserted for every input: `out` is unchanged on
    /// `None`, `out[n..]` unchanged on `Some(n)`. Every predicate here is spelled from the documented
    /// canonical form.
    /// Covers: success with and without a fraction, a valid value rejected only for capacity, a
    /// non-canonical fraction (non-digit; trailing zero) rejected with ample capacity, and an
    /// out-of-range field rejected with ample capacity.
    #[kani::proof]
    #[kani::unwind(21)]
    fn encode_is_total_exact_oracle() {
        let frac: [u8; 3] = kani::any();
        let fl: usize = kani::any();
        kani::assume(fl <= 3);
        let t = GeneralizedTime {
            year: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
            fraction: &frac[..fl],
        };
        let backing: [u8; 20] = kani::any();
        let mut out = backing;
        let cap: usize = kani::any();
        kani::assume(cap <= 20);
        let r = encode_generalized_time_into(&t, &mut out[..cap]);
        // Rustdoc write contract: `None` => nothing written; `Some(n)` => only `out[..n]` written.
        match r {
            None => assert!(out == backing),
            Some(n) => assert!(out[n..] == backing[n..]),
        }

        let fields_ok = t.year <= 9999
            && (t.month >= 1 && t.month <= 12)
            && (t.day >= 1 && t.day <= 31)
            && t.hour <= 23
            && t.minute <= 59
            && t.second <= 59;
        let mut digits_ok = true;
        let mut k = 0;
        while k < fl {
            if !(frac[k] >= 48 && frac[k] <= 57) {
                digits_ok = false;
            }
            k += 1;
        }
        let frac_ok = digits_ok && (fl == 0 || frac[fl - 1] != 48);
        let total = if fl == 0 { 15 } else { 16 + fl };
        if fields_ok && frac_ok && cap >= total {
            assert!(r == Some(total));
            // independent expected bytes
            let mut want = [0u8; 20];
            let mut v = t.year;
            let mut k = 4;
            while k > 0 {
                k -= 1;
                want[k] = 48 + (v % 10) as u8;
                v /= 10;
            }
            let fields = [t.month, t.day, t.hour, t.minute, t.second];
            let mut f = 0;
            while f < 5 {
                let mut v = fields[f];
                let mut k = 2;
                while k > 0 {
                    k -= 1;
                    want[4 + 2 * f + k] = 48 + v % 10;
                    v /= 10;
                }
                f += 1;
            }
            if fl == 0 {
                want[14] = 90;
            } else {
                want[14] = 46;
                let mut j = 0;
                while j < fl {
                    want[15 + j] = frac[j];
                    j += 1;
                }
                want[15 + fl] = 90;
            }
            assert!(out[..total] == want[..total]);
            assert!(out[total..] == backing[total..]);
        } else {
            assert!(r.is_none());
        }
        kani::cover(r == Some(15), "a valid time without a fraction is encoded");
        kani::cover(matches!(r, Some(w) if w > 15), "a valid time with a fraction is encoded");
        kani::cover(r.is_none() && fields_ok && frac_ok && cap < total, "a valid time into insufficient capacity is None");
        kani::cover(r.is_none() && fields_ok && !digits_ok && cap >= 19, "a non-digit fraction with ample capacity is None");
        kani::cover(
            r.is_none() && fields_ok && digits_ok && fl > 0 && frac[fl - 1] == 48 && cap >= 19,
            "a trailing-zero fraction with ample capacity is None",
        );
        kani::cover(r.is_none() && !fields_ok && frac_ok && cap >= 19, "an out-of-range field with ample capacity is None");
    }

    // --- Error-class correctness (one harness per rejection reason). ---

    /// Any content shorter than 15 octets is `BadLength` (covers the seconds-less BER forms).
    #[kani::proof]
    #[kani::unwind(16)]
    fn short_length_is_bad_length() {
        let buf: [u8; 15] = kani::any();
        let n: usize = kani::any();
        kani::assume(n < 15);
        assert!(decode_generalized_time(&buf[..n]) == Err(GeneralizedTimeError::BadLength));
    }

    /// A non-digit in a mandatory position `0..=13` (15-octet input) is `NonDigit`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn non_digit_is_classified() {
        let mut c = [b'0'; 15];
        c[4] = b'1'; // month 01 so the (unreached) range check would pass anyway
        c[6] = b'1'; // day 01
        c[14] = b'Z';
        let p: usize = kani::any();
        kani::assume(p < 14);
        let bad: u8 = kani::any();
        kani::assume(!bad.is_ascii_digit());
        c[p] = bad;
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::NonDigit));
    }

    /// A 15-octet all-digit-prefix string whose terminator isn't `'Z'` is `NotZulu`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn not_zulu_is_classified() {
        // "20230101000000" (valid mandatory prefix) + terminator.
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', 0,
        ];
        let term: u8 = kani::any();
        kani::assume(term != b'Z');
        c[14] = term;
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::NotZulu));
    }

    /// Out-of-range fields map to their specific error class (checked in decode's order
    /// month→day→hour→minute→second). Each pins an otherwise-canonical 15-octet string.
    #[kani::proof]
    #[kani::unwind(16)]
    fn month_range_is_classified() {
        let mo: u8 = kani::any();
        kani::assume(mo <= 99 && !(mo >= 1 && mo <= 12));
        let mut c = [
            b'2', b'0', b'2', b'3', 0, 0, b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
        ];
        write_two(&mut c, 4, mo);
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::MonthRange));
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn day_range_is_classified() {
        let d: u8 = kani::any();
        kani::assume(d <= 99 && !(d >= 1 && d <= 31));
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', 0, 0, b'0', b'0', b'0', b'0', b'0', b'0', b'Z',
        ];
        write_two(&mut c, 6, d);
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::DayRange));
    }

    /// Hour `24..=99` (including the forbidden midnight `24`) is `HourRange`.
    #[kani::proof]
    #[kani::unwind(16)]
    fn hour_range_is_classified() {
        let h: u8 = kani::any();
        kani::assume(h <= 99 && h > 23);
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', 0, 0, b'0', b'0', b'0', b'0', b'Z',
        ];
        write_two(&mut c, 8, h);
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::HourRange));
    }

    #[kani::proof]
    #[kani::unwind(16)]
    fn minute_range_is_classified() {
        let m: u8 = kani::any();
        kani::assume(m <= 99 && m > 59);
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', 0, 0, b'0', b'0', b'Z',
        ];
        write_two(&mut c, 10, m);
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::MinuteRange));
    }

    /// Second `60..=99` (including the rejected leap second `60`) is `SecondRange` (see `DECISIONS.md`).
    #[kani::proof]
    #[kani::unwind(16)]
    fn second_range_is_classified() {
        let s: u8 = kani::any();
        kani::assume(s <= 99 && s > 59);
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', 0, 0, b'Z',
        ];
        write_two(&mut c, 12, s);
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::SecondRange));
    }

    /// The octet after the mandatory digits being neither `'.'` nor `'Z'` (e.g. a comma) is
    /// `BadFractionSeparator` — the comma-vs-point trap.
    #[kani::proof]
    #[kani::unwind(18)]
    fn bad_fraction_separator_is_classified() {
        // 16 octets: valid 14-digit prefix, a non-'.' separator, then the 'Z' terminator.
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', 0,
            b'Z',
        ];
        let sep: u8 = kani::any();
        kani::assume(sep != b'.');
        c[14] = sep;
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::BadFractionSeparator));
    }

    /// A `'.'` with no fraction digits before `'Z'` (`.Z`) is `FractionEmpty`.
    #[kani::proof]
    #[kani::unwind(18)]
    fn fraction_empty_is_classified() {
        // 16 octets: valid prefix + '.' + 'Z' (no digits between).
        let c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'.',
            b'Z',
        ];
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::FractionEmpty));
    }

    /// A fraction ending in `'0'` (a trailing zero, or an all-zero fraction not omitted) is
    /// `FractionTrailingZero`. Proven for a symbolic-leading-digit two-digit fraction `X0`.
    #[kani::proof]
    #[kani::unwind(18)]
    fn fraction_trailing_zero_is_classified() {
        // 18 octets: valid prefix + '.' + <digit> + '0' + 'Z' → fraction "X0" has a trailing zero.
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'.',
            0, b'0', b'Z',
        ];
        let d: u8 = kani::any();
        kani::assume(d.is_ascii_digit());
        c[15] = d;
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::FractionTrailingZero));
    }

    /// A non-digit *inside the fraction* is `NonDigit` (the second `NonDigit` site — distinct from the
    /// mandatory-position harness above; closes the per-error-class gap a review flagged).
    #[kani::proof]
    #[kani::unwind(18)]
    fn fraction_non_digit_is_classified() {
        // valid prefix + '.' + <non-digit> + '1' + 'Z' (last fraction digit '1' rules out a trailing
        // zero, so the non-digit is the sole failure).
        let mut c = [
            b'2', b'0', b'2', b'3', b'0', b'1', b'0', b'1', b'0', b'0', b'0', b'0', b'0', b'0', b'.',
            0, b'1', b'Z',
        ];
        let bad: u8 = kani::any();
        kani::assume(!bad.is_ascii_digit());
        c[15] = bad;
        assert!(decode_generalized_time(&c) == Err(GeneralizedTimeError::NonDigit));
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_no_fraction() {
        // 20231231235959Z = 2023-12-31 23:59:59 UTC, no fraction
        let t = decode_generalized_time(b"20231231235959Z").unwrap();
        assert_eq!(
            t,
            GeneralizedTime {
                year: 2023,
                month: 12,
                day: 31,
                hour: 23,
                minute: 59,
                second: 59,
                fraction: &[]
            }
        );
    }

    #[test]
    fn decodes_with_fraction() {
        // 20230615120000.52Z = ...12:00:00.52 — canonical fraction (no trailing zero)
        let t = decode_generalized_time(b"20230615120000.52Z").unwrap();
        assert_eq!(t.year, 2023);
        assert_eq!(t.second, 0);
        assert_eq!(t.fraction, b"52");
    }

    #[test]
    fn roundtrips_no_fraction() {
        let t = GeneralizedTime { year: 2023, month: 6, day: 15, hour: 12, minute: 30, second: 45, fraction: &[] };
        let mut out = [0u8; 32];
        let w = encode_generalized_time_into(&t, &mut out).unwrap();
        assert_eq!(&out[..w], b"20230615123045Z");
        assert_eq!(decode_generalized_time(&out[..w]).unwrap(), t);
    }

    #[test]
    fn roundtrips_with_fraction() {
        let t = GeneralizedTime { year: 2023, month: 6, day: 15, hour: 12, minute: 30, second: 45, fraction: b"125" };
        let mut out = [0u8; 32];
        let w = encode_generalized_time_into(&t, &mut out).unwrap();
        assert_eq!(&out[..w], b"20230615123045.125Z");
        assert_eq!(decode_generalized_time(&out[..w]).unwrap(), t);
    }

    #[test]
    fn require_no_fraction_profile() {
        let plain = decode_generalized_time(b"20231231235959Z").unwrap();
        let frac = decode_generalized_time(b"20231231235959.5Z").unwrap();
        assert!(require_no_fraction(&plain)); // RFC 5280 compliant
        assert!(!require_no_fraction(&frac)); // has a fraction -> profile violation
    }

    // --- seeded-bad specimens: each MUST be rejected ---
    #[test]
    fn rejects_missing_seconds() {
        // 202312312359Z — minute-only BER form (13 octets), no seconds. DER requires seconds.
        assert_eq!(decode_generalized_time(b"202312312359Z"), Err(GeneralizedTimeError::BadLength));
    }
    #[test]
    fn rejects_local_time_without_z() {
        // 20231231235959 — no terminator (14 octets).
        assert_eq!(decode_generalized_time(b"20231231235959"), Err(GeneralizedTimeError::BadLength));
    }
    #[test]
    fn rejects_offset_form() {
        // 20231231235959+0500 — a UTC offset. DER forbids offsets; must be Z.
        assert_eq!(
            decode_generalized_time(b"20231231235959+0500"),
            Err(GeneralizedTimeError::NotZulu)
        );
    }
    #[test]
    fn rejects_comma_separator() {
        // 20230615120000,52Z — comma decimal separator. DER requires the point '.'.
        assert_eq!(
            decode_generalized_time(b"20230615120000,52Z"),
            Err(GeneralizedTimeError::BadFractionSeparator)
        );
    }
    #[test]
    fn rejects_trailing_zero_fraction() {
        // 20230615120000.10Z — ".10" has a trailing zero; canonical is ".1".
        assert_eq!(
            decode_generalized_time(b"20230615120000.10Z"),
            Err(GeneralizedTimeError::FractionTrailingZero)
        );
    }
    #[test]
    fn rejects_all_zero_fraction() {
        // 20230615120000.000Z — an all-zero fraction must be omitted entirely (with its '.').
        assert_eq!(
            decode_generalized_time(b"20230615120000.000Z"),
            Err(GeneralizedTimeError::FractionTrailingZero)
        );
    }
    #[test]
    fn rejects_empty_fraction() {
        // 20230615120000.Z — a bare separator with no digits.
        assert_eq!(
            decode_generalized_time(b"20230615120000.Z"),
            Err(GeneralizedTimeError::FractionEmpty)
        );
    }
    #[test]
    fn rejects_hour_24() {
        assert_eq!(decode_generalized_time(b"20231231245959Z"), Err(GeneralizedTimeError::HourRange));
    }
    #[test]
    fn rejects_leap_second_60() {
        // second 60 (leap second) — rejected for the X.509 anti-differential profile (DECISIONS.md).
        assert_eq!(decode_generalized_time(b"20231231235960Z"), Err(GeneralizedTimeError::SecondRange));
    }
    #[test]
    fn rejects_month_13() {
        assert_eq!(decode_generalized_time(b"20231331235959Z"), Err(GeneralizedTimeError::MonthRange));
    }
    #[test]
    fn rejects_day_32() {
        // 20231232120000Z -- day 32 is out of range (01..=31).
        assert_eq!(decode_generalized_time(b"20231232120000Z"), Err(GeneralizedTimeError::DayRange));
    }
    #[test]
    fn rejects_minute_60() {
        // 20231231126000Z -- minute 60 is out of range (00..=59).
        assert_eq!(decode_generalized_time(b"20231231126000Z"), Err(GeneralizedTimeError::MinuteRange));
    }
    #[test]
    fn accepts_leading_zero_fraction() {
        // ".01" is canonical (0.01s): a leading zero is significant, only TRAILING zeros are forbidden.
        let t = decode_generalized_time(b"20230615120000.01Z").unwrap();
        assert_eq!(t.fraction, b"01");
    }

    // --- mutation-killing boundary/regression tests (cargo-mutants survivors) ---

    #[test]
    fn decode_rejects_non_digit_in_mandatory_prefix() {
        // A non-digit (':' = '9' + 1) inside the mandatory 14-digit prefix, placed so the two
        // arithmetic-digit interpretation of the byte still lands in-range for every field
        // (second = 0*10 + 10 = 10, <= 59) -- i.e. a mutation that skipped the mandatory-prefix
        // digit-check loop entirely (`i < 14` -> `i == 14`) would let this decode succeed instead
        // of being rejected as NonDigit.
        let bytes = b"2023010100000:Z";
        assert_eq!(decode_generalized_time(bytes), Err(GeneralizedTimeError::NonDigit));
    }

    #[test]
    fn decode_rejects_non_digit_inside_fraction() {
        // A non-digit ('X') inside the fraction, with the fraction's last byte not '0' (so the
        // trailing-zero check alone would not reject it) -- a mutation that skipped the fraction
        // digit-check loop (`j < frac.len()` -> `j > frac.len()`) would let this decode succeed.
        assert_eq!(
            decode_generalized_time(b"20230615120000.5XZ"),
            Err(GeneralizedTimeError::NonDigit)
        );
    }

    #[test]
    fn encode_rejects_non_digit_fraction() {
        // A fraction containing a non-digit byte, with its last byte not '0' (so only the digit
        // check in `fraction_is_canonical` -- not the trailing-zero check -- can reject it). A
        // mutation that skipped that digit-check loop (`i < frac.len()` -> `i > frac.len()`) would
        // let this encode succeed instead of returning None.
        let t = GeneralizedTime {
            year: 2023,
            month: 6,
            day: 15,
            hour: 12,
            minute: 0,
            second: 0,
            fraction: b"5X",
        };
        let mut out = [0u8; 32];
        assert_eq!(encode_generalized_time_into(&t, &mut out), None);
    }

    #[test]
    fn encode_boundary_buffer_sizes_with_fraction() {
        // Correct total = 14 (mandatory) + 1 ('.') + 3 (fraction) + 1 ('Z') = 19. A one-byte-short
        // buffer must be rejected, and an exact-fit buffer must succeed and produce the exact
        // expected bytes -- pins both the `total` arithmetic and the `out.len() < total` boundary
        // (a `<` -> `<=` mutation would reject the exact-fit buffer).
        let t = GeneralizedTime {
            year: 2023,
            month: 6,
            day: 15,
            hour: 12,
            minute: 30,
            second: 45,
            fraction: b"125",
        };
        let mut too_small = [0u8; 18];
        assert_eq!(encode_generalized_time_into(&t, &mut too_small), None);

        let mut exact = [0u8; 19];
        let w = encode_generalized_time_into(&t, &mut exact).unwrap();
        assert_eq!(w, 19);
        assert_eq!(&exact[..w], b"20230615123045.125Z");
    }

    #[test]
    fn roundtrips_distinguishing_year_digits() {
        // Year 1934: every decimal digit place is non-zero and distinct, so a wrong arithmetic
        // operator (e.g. `+` -> `-`) in any single year-digit computation produces a visibly wrong
        // output byte at that exact position, unlike years whose digits happen to be 0.
        let t = GeneralizedTime {
            year: 1934,
            month: 6,
            day: 15,
            hour: 12,
            minute: 30,
            second: 45,
            fraction: &[],
        };
        let mut out = [0u8; 32];
        let w = encode_generalized_time_into(&t, &mut out).unwrap();
        assert_eq!(&out[..w], b"19340615123045Z");
        assert_eq!(decode_generalized_time(&out[..w]).unwrap(), t);
    }

    // --- encode-side guards (encode_generalized_time_into's None-returning branches) ---
    #[test]
    fn encode_rejects_out_of_range_fields() {
        // month = 13 is out of range -- fields_in_range fails before the fraction/buffer checks.
        let t = GeneralizedTime { year: 2023, month: 13, day: 1, hour: 0, minute: 0, second: 0, fraction: &[] };
        let mut out = [0u8; 32];
        assert_eq!(encode_generalized_time_into(&t, &mut out), None);
    }
    #[test]
    fn encode_rejects_noncanonical_fraction() {
        // a trailing-zero fraction ("10") is not canonical -- fields are in range, but the fraction
        // guard rejects it.
        let t = GeneralizedTime { year: 2023, month: 6, day: 15, hour: 12, minute: 0, second: 0, fraction: b"10" };
        let mut out = [0u8; 32];
        assert_eq!(encode_generalized_time_into(&t, &mut out), None);
    }
    #[test]
    fn encode_rejects_output_buffer_too_small() {
        // a valid no-fraction GeneralizedTime needs 15 bytes; a 14-byte buffer is too small.
        let t = GeneralizedTime { year: 2023, month: 6, day: 15, hour: 12, minute: 30, second: 45, fraction: &[] };
        let mut out = [0u8; 14];
        assert_eq!(encode_generalized_time_into(&t, &mut out), None);
    }
}
