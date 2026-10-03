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
//!   the raw two-digit year itself. [`crate::profile::validate_profile`] is that caller: it enforces
//!   the year-2050 encoding-choice rule and the no-fractional-seconds rule on a parsed
//!   certificate's `validity`.
//! - *Strict, top-to-bottom.* The outer SEQUENCE must consume the entire input (no trailing bytes
//!   after the whole `Validity`); the two `Time` fields must exactly tile the outer content — the
//!   classic parser-differential vector this crate's other modules guard against
//!   (`decode_tlv_strict` / `decode_sequence_tlv_strict`).
//!
//! # Examples
//!
//! ```
//! use der_verified::x509_validity::{parse_validity, Time};
//!
//! // notBefore = UTCTime 1999-01-01, notAfter = UTCTime 1999-12-31 23:59:59Z.
//! #[rustfmt::skip]
//! let validity_der: [u8; 32] = [
//!     0x30, 0x1e,
//!         0x17, 0x0d,
//!             0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
//!         0x17, 0x0d,
//!             0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
//! ];
//! let v = parse_validity(&validity_der).unwrap();
//! assert!(matches!(v.not_before, Time::Utc(_)));
//! ```

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
/// Never panics on any input **up to the harness's 16-octet symbolic bound** (proven by the `parse_never_panics` Kani harness below); returns a
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
    use crate::generalized_time::encode_generalized_time_into;
    use crate::utc_time::encode_utc_time;

    /// Robustness: `parse_validity` never panics on any input up to 16 octets.
    ///
    /// Cover (T6 primary rule): witnesses the Ok tail is reached (a genuine Validity: outer
    /// SEQUENCE strict, both Time CHOICE fields decode and exactly tile) -- not merely that
    /// malformed 16-byte inputs are rejected. Would NOT be SAT if `parse_validity`'s body were a
    /// no-op always returning `Err`.
    ///
    // VACUITY-DISCLOSED: parse_never_panics -> witness parse_validity_ok_path_witnessed
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
        // Symbolic input length so the "up to 16 octets" panic-freedom claim holds at every length
        // in `0..=16`, not just the single length 16 -- control flow is length-dependent. (The `Ok`
        // cover stays a disclosed vacuity: the two Time fields impose a >= 32-octet floor no 16-octet
        // input can reach -- see this harness's own doc.)
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let result = parse_validity(&buf[..len]);
        kani::cover(result.is_ok(), "a well-formed Validity reaches the Ok tail");
        let _ = result;
    }

    /// **Positive-construction companion to `parse_never_panics`** — closes the vacuity gap that
    /// harness's own cover discovered (see its doc comment: the `Ok` cover is UNSATISFIABLE at
    /// `[u8; 16]`, since a genuine `Validity` needs an arithmetic floor of 32 octets). Mirrors
    /// `x509_tbs_certificate::proofs::parse_tbs_certificate_ok_path_witnessed`'s pattern: a fully
    /// CONCRETE, valid specimen, run through the REAL (unstubbed) `parse_validity`, with a
    /// `kani::cover(result.is_ok(), ..)` that IS satisfied.
    ///
    /// Unlike `parse_tbs_certificate` (which needed THREE `#[kani::stub]`s to make its `Ok` tail
    /// tractable — see that harness's doc comment and its two measured dead ends), `Validity`'s own
    /// call graph is shallow: `decode_sequence_tlv_strict` (one `decode_tlv`) followed by up to two
    /// `decode_time_tlv` calls, each itself one `decode_tlv` plus ONE inlined leaf decoder
    /// (`decode_utc_time`'s fixed 12-digit loop or `decode_generalized_time`'s 14-digit-plus-fraction
    /// loop) — no nested SEQUENCE-of-SEQUENCE-of-SET composition (unlike `x509_name`) and no
    /// multi-field outer struct pulling in several OTHER modules' parsers (unlike
    /// `x509_tbs_certificate`). So no stubbing was attempted first; this harness runs the real,
    /// complete `parse_validity` end to end on a concrete 32-octet input, measured cheap (see the
    /// bound comment below) — no modular split needed here, unlike the TBS positive harness.
    ///
    /// The specimen is byte-for-byte identical to `tests::VALIDITY_UTC_UTC` above (`notBefore` =
    /// UTCTime 1999-01-01 00:00:00Z, `notAfter` = UTCTime 1999-12-31 23:59:59Z) — valid-by-
    /// construction (T4), not `assume(validate(x))`, and drawn from this module's own existing test
    /// fixtures per the task's instruction to mirror der's own test specimens.
    ///
    /// `#[kani::unwind(20)]`: same bound as `parse_never_panics` above — covers a maximal-header
    /// `decode_tlv` (~11) plus a full 13-octet UTCTime content walk (12 digit-checks + 1 `Z` check)
    /// with margin; this concrete specimen's real path needs strictly fewer iterations than the
    /// worst case that bound was sized for, so no bound increase was needed.
    ///
    /// **Measured cost: `VERIFICATION: SUCCESSFUL`, `1 of 1 cover properties satisfied` (the gap is
    /// closed), ~0.58 GB peak RSS, ~6 s wall (`/usr/bin/time -v`, isolated single-harness run)** --
    /// far below the ~12 GB shared-box budget, and no stubs were needed: `Validity`'s shallow,
    /// two-leaf-call composition does not hit the composition-depth wall `x509_tbs_certificate`
    /// measured (that harness needed three `#[kani::stub]`s and still cost ~11.3 GB / ~206 s).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_ok_path_witnessed() {
        // Concrete, valid Validity (32 octets) -- byte-for-byte identical to
        // `tests::VALIDITY_UTC_UTC` above: notBefore = UTCTime 1999-01-01 00:00:00Z, notAfter =
        // UTCTime 1999-12-31 23:59:59Z.
        //
        // `30 1e`                                       SEQUENCE, len 30
        //    `17 0d "990101000000Z"`                     UTCTime (notBefore), len 13
        //    `17 0d "991231235959Z"`                     UTCTime (notAfter), len 13
        #[rustfmt::skip]
        const VALIDITY_UTC_UTC: [u8; 32] = [
            0x30, 0x1e,
                0x17, 0x0d,
                    0x39, 0x39, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,
                0x17, 0x0d,
                    0x39, 0x39, 0x31, 0x32, 0x33, 0x31, 0x32, 0x33, 0x35, 0x39, 0x35, 0x39, 0x5a,
        ];

        let result = parse_validity(&VALIDITY_UTC_UTC);
        kani::cover(
            result.is_ok(),
            "parse_validity reaches its Ok tail on a real, fully-concrete, valid Validity -- the \
             existence witness the fully-symbolic [u8; 16] harness's cover could not produce (see \
             that harness's VACUITY FINDING comment)",
        );
        let _ = result;
    }

    /// Structured-symbolic faithful decode: a **fixed TLV skeleton** (outer
    /// SEQUENCE around two UTCTime-arm `Time` fields) built from fully-symbolic, IN-RANGE `UtcTime`
    /// field tuples via the module's own verified [`crate::utc_time::encode_utc_time`] -- so this
    /// harness rides on `utc_time`'s own proven contract (`roundtrip_all_fields`) rather than
    /// re-deriving DER byte layout by hand. Two things `parse_validity_ok_path_witnessed` above
    /// (one CONCRETE specimen) cannot show: (1) that `parse_validity` recovers the EXACT symbolic
    /// field values for *every* in-range `notBefore`/`notAfter` pair, not just one hand-picked date;
    /// (2) the **tiling** guard itself, by also appending a symbolic `0..=3`-byte tail still inside
    /// the outer SEQUENCE's declared content -- `parse_validity` must accept iff there is no such
    /// tail, and reject with `TrailingBytes` otherwise.
    ///
    /// Control: widen the trailing-bytes tiling guard's `na_used != rest.len()` to
    /// `na_used > rest.len()` (structurally `na_used <= rest.len()` always, from `decode_tlv`'s own
    /// no-over-read guarantee, so the widened check can never fire) -> predicted RED on the
    /// `extra_len > 0` branch below (undeclared trailing content would then be silently accepted
    /// instead of rejected as `TrailingBytes`).
    ///
    /// CONTRACT SURFACE / bounded-backing evidence, UTCTime/UTCTime only (the other arm pairs are
    /// the `parse_validity_faithful_*` harnesses below). Backing `[u8; 35]`, in-range symbolic
    /// fields (the assumptions listed in the body), tail `<= 3` octets, `#[kani::unwind(20)]`, no
    /// stubs.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_faithful() {
        let nb = UtcTime {
            year2: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
        };
        kani::assume(nb.year2 <= 99);
        kani::assume(nb.month >= 1 && nb.month <= 12);
        kani::assume(nb.day >= 1 && nb.day <= 31);
        kani::assume(nb.hour <= 23);
        kani::assume(nb.minute <= 59);
        kani::assume(nb.second <= 59);
        let na = UtcTime {
            year2: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
        };
        kani::assume(na.year2 <= 99);
        kani::assume(na.month >= 1 && na.month <= 12);
        kani::assume(na.day >= 1 && na.day <= 31);
        kani::assume(na.hour <= 23);
        kani::assume(na.minute <= 59);
        kani::assume(na.second <= 59);

        let mut nb_content = [0u8; 13];
        assert!(encode_utc_time(&nb, &mut nb_content) == Some(13));
        let mut na_content = [0u8; 13];
        assert!(encode_utc_time(&na, &mut na_content) == Some(13));

        // Symbolic 0..=3 undeclared trailing octets, still inside the outer SEQUENCE's own
        // declared length -- the exact shape `na_used != rest.len()` exists to reject.
        let extra_len: usize = kani::any();
        kani::assume(extra_len <= 3);
        let extra: [u8; 3] = kani::any();

        let inner_len: u8 = 30 + extra_len as u8; // 2 * (2-byte header + 13-byte content) + extra
        let mut buf = [0u8; 35];
        buf[0] = 0x30;
        buf[1] = inner_len;
        buf[2] = 0x17; // UTCTime, primitive, UNIVERSAL 23
        buf[3] = 0x0D; // length 13
        buf[4..17].copy_from_slice(&nb_content);
        buf[17] = 0x17;
        buf[18] = 0x0D;
        buf[19..32].copy_from_slice(&na_content);
        buf[32..35].copy_from_slice(&extra);
        let total_len = 32 + extra_len;
        let input = &buf[..total_len];

        let result = parse_validity(input);
        if extra_len == 0 {
            // Exact tiling: the two Time fields exactly fill the outer content -- decode succeeds
            // and BOTH fields match the exact symbolic value each was built from (not merely "some
            // UtcTime" -- per-field decode equality).
            assert!(result == Ok(Validity { not_before: Time::Utc(nb), not_after: Time::Utc(na) }));
        } else {
            assert!(result == Err(ValidityError::TrailingBytes));
        }
        kani::cover(
            result.is_ok(),
            "a well-tiled two-UTCTime Validity, built from symbolic in-range fields via the \
             verified encoder, reaches Ok with both fields recovered exactly",
        );
        kani::cover(result == Err(ValidityError::TrailingBytes), "TrailingBytes outcome reached");
    }

    // -----------------------------------------------------------------------------------------
    // Arm-pair, identifier, missing-field, content and length harnesses (CONTRACT SURFACE /
    // bounded-backing evidence).
    //
    // Shared domain (disclosed): structured skeletons only -- concrete TLV framing (tags, lengths)
    // with SYMBOLIC content bytes; every symbolic time field satisfies its literal spec range
    // (UTCTime: year2 <= 99, month 1..=12, day 1..=31, hour <= 23, minute <= 59, second <= 59;
    // GeneralizedTime: year <= 9999, same month/day/hour/minute/second ranges, fraction of 0..=3
    // ASCII digits whose last digit is not '0'); outer-SEQUENCE tail <= 3 octets; backing array
    // <= 47 octets; `#[kani::unwind(20)]`; no stubs; no `assume(parser(x).is_ok())`. The encoders
    // (`encode_utc_time`, `encode_generalized_time_into`) are used as constructors and their
    // `Some(len)` results are ASSERTED, not assumed. Content-level time validity is delegated to the
    // `utc_time` / `generalized_time` contracts; the RFC 5280 2050 profile rule is not enforced by
    // this module (any arm pair is accepted); inputs are at most 47 octets.
    // -----------------------------------------------------------------------------------------

    /// A symbolic, IN-RANGE `UtcTime` (literal spec predicates, see the shared domain note).
    fn any_utc() -> UtcTime {
        let t = UtcTime {
            year2: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
        };
        kani::assume(t.year2 <= 99);
        kani::assume(t.month >= 1 && t.month <= 12);
        kani::assume(t.day >= 1 && t.day <= 31);
        kani::assume(t.hour <= 23);
        kani::assume(t.minute <= 59);
        kani::assume(t.second <= 59);
        t
    }

    /// Symbolic in-range `GeneralizedTime` fields plus an owned fraction of `k <= 3` digits
    /// (`frac[..k]`), every digit in `b'0'..=b'9'` and the last digit not `b'0'` when `k > 0`.
    struct GenFields {
        year: u16,
        month: u8,
        day: u8,
        hour: u8,
        minute: u8,
        second: u8,
        frac: [u8; 3],
        k: usize,
    }

    fn any_gen() -> GenFields {
        let g = GenFields {
            year: kani::any(),
            month: kani::any(),
            day: kani::any(),
            hour: kani::any(),
            minute: kani::any(),
            second: kani::any(),
            frac: kani::any(),
            k: kani::any(),
        };
        kani::assume(g.year <= 9999);
        kani::assume(g.month >= 1 && g.month <= 12);
        kani::assume(g.day >= 1 && g.day <= 31);
        kani::assume(g.hour <= 23);
        kani::assume(g.minute <= 59);
        kani::assume(g.second <= 59);
        kani::assume(g.k <= 3);
        kani::assume(g.k < 1 || (g.frac[0] >= b'0' && g.frac[0] <= b'9'));
        kani::assume(g.k < 2 || (g.frac[1] >= b'0' && g.frac[1] <= b'9'));
        kani::assume(g.k < 3 || (g.frac[2] >= b'0' && g.frac[2] <= b'9'));
        kani::assume(g.k == 0 || g.frac[g.k - 1] != b'0');
        g
    }

    fn gen_of(g: &GenFields) -> GeneralizedTime<'_> {
        GeneralizedTime {
            year: g.year,
            month: g.month,
            day: g.day,
            hour: g.hour,
            minute: g.minute,
            second: g.second,
            fraction: &g.frac[..g.k],
        }
    }

    /// Write `tag, len, content` at `buf[off..]`; returns the TLV's total length. (`content` is at
    /// most 19 octets, so a one-octet length suffices.)
    fn put_tlv(buf: &mut [u8; 47], off: usize, tag: u8, content: &[u8]) -> usize {
        buf[off] = tag;
        buf[off + 1] = content.len() as u8;
        let mut i = 0;
        while i < content.len() {
            buf[off + 2 + i] = content[i];
            i += 1;
        }
        2 + content.len()
    }

    /// UTCTime field TLV (`17 0D <13>`) at `off`; the encoder's `Some(13)` is asserted.
    fn put_utc(buf: &mut [u8; 47], off: usize, t: &UtcTime) -> usize {
        let mut c = [0u8; 13];
        assert!(encode_utc_time(t, &mut c) == Some(13));
        put_tlv(buf, off, 0x17, &c)
    }

    /// GeneralizedTime field TLV (`18 <len> <content>`) at `off`; the encoder's result is asserted to
    /// be `Some(15)` for an empty fraction and `Some(16 + k)` otherwise.
    fn put_gen(buf: &mut [u8; 47], off: usize, g: &GenFields) -> usize {
        let mut c = [0u8; 19];
        let n = encode_generalized_time_into(&gen_of(g), &mut c);
        let want = if g.k == 0 { 15 } else { 16 + g.k };
        assert!(n == Some(want));
        put_tlv(buf, off, 0x18, &c[..want])
    }

    /// Fraction borrow identity: a `Time::Generalized` field with `k > 0` borrows its fraction from
    /// `input[field_off + 2 + 15 ..]` (pointer identity, not byte equality); `k == 0` gives an empty
    /// fraction.
    fn check_frac(t: &Time<'_>, k: usize, input: &[u8], field_off: usize) {
        if let Time::Generalized(g) = t {
            if k > 0 {
                assert!(core::ptr::eq(g.fraction.as_ptr(), input[field_off + 2 + 15..].as_ptr()));
                assert!(g.fraction.len() == k);
            } else {
                assert!(g.fraction.is_empty());
            }
        }
    }

    /// Arm-pair case helper for the four `parse_validity_faithful_*` harnesses (`nb_gen` / `na_gen` are CONCRETE arm choices): layout
    /// `30 L | field_nb | field_na | extra[..extra_len]`, `extra_len <= 3`, `L` = sum of the inner
    /// lengths, backing `[u8; 47]`. `extra_len == 0` => exact `Ok(Validity { .. })` built from the
    /// symbolic tuples (plus fraction pointer identity); `extra_len > 0` => `Err(TrailingBytes)`.
    fn arms_case(nb_gen: bool, na_gen: bool) {
        let nb_u = any_utc();
        let na_u = any_utc();
        let nb_g = any_gen();
        let na_g = any_gen();
        let extra_len: usize = kani::any();
        kani::assume(extra_len <= 3);
        let extra: [u8; 3] = kani::any();

        let mut buf = [0u8; 47];
        let nb_off = 2usize;
        let nb_len = if nb_gen { put_gen(&mut buf, nb_off, &nb_g) } else { put_utc(&mut buf, nb_off, &nb_u) };
        let na_off = nb_off + nb_len;
        let na_len = if na_gen { put_gen(&mut buf, na_off, &na_g) } else { put_utc(&mut buf, na_off, &na_u) };
        let tail_off = na_off + na_len;
        let mut i = 0;
        while i < extra_len {
            buf[tail_off + i] = extra[i];
            i += 1;
        }
        let total = tail_off + extra_len;
        buf[0] = 0x30;
        buf[1] = (total - 2) as u8;
        let input = &buf[..total];

        let result = parse_validity(input);
        if extra_len == 0 {
            let enb = if nb_gen { Time::Generalized(gen_of(&nb_g)) } else { Time::Utc(nb_u) };
            let ena = if na_gen { Time::Generalized(gen_of(&na_g)) } else { Time::Utc(na_u) };
            assert!(result == Ok(Validity { not_before: enb, not_after: ena }));
            if let Ok(v) = result {
                check_frac(&v.not_before, nb_g.k, input, nb_off);
                check_frac(&v.not_after, na_g.k, input, na_off);
            }
        } else {
            assert!(result == Err(ValidityError::TrailingBytes));
        }
        kani::cover(result.is_ok(), "arm-pair Validity reaches Ok");
        // `nb_gen` / `na_gen` are concrete. The fraction clause is only demanded of a
        // GeneralizedTime arm (for a UTCTime arm it is trivially true), so every cover is
        // satisfiable in every instantiation -- none is dead by construction.
        kani::cover(
            result.is_ok() && (!nb_gen || nb_g.k > 0),
            "Ok (with a non-empty notBefore fraction when notBefore is a GeneralizedTime)",
        );
        kani::cover(
            result.is_ok() && (!na_gen || na_g.k > 0),
            "Ok (with a non-empty notAfter fraction when notAfter is a GeneralizedTime)",
        );
        kani::cover(result == Err(ValidityError::TrailingBytes), "TrailingBytes outcome reached");
    }

    /// NotBefore UTCTime, notAfter UTCTime, via [`arms_case`] (CONTRACT SURFACE /
    /// bounded-backing evidence; see the shared domain note above).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_faithful_uu() {
        arms_case(false, false);
    }

    /// NotBefore UTCTime, notAfter GeneralizedTime (0..=3 fraction digits).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_faithful_ug() {
        arms_case(false, true);
    }

    /// NotBefore GeneralizedTime (0..=3 fraction digits), notAfter UTCTime.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_faithful_gu() {
        arms_case(true, false);
    }

    /// Both fields GeneralizedTime (0..=3 fraction digits each).
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_faithful_gg() {
        arms_case(true, true);
    }

    /// The 32-octet UTC/UTC skeleton `30 1E | 17 0D <nb> | 17 0D <na>`.
    fn build_uu(nb: &UtcTime, na: &UtcTime) -> [u8; 47] {
        let mut buf = [0u8; 47];
        buf[0] = 0x30;
        buf[1] = 0x1E;
        let a = put_utc(&mut buf, 2, nb);
        let b = put_utc(&mut buf, 2 + a, na);
        assert!(a == 15 && b == 15);
        buf
    }

    /// Outer-identifier rejection precedence (CONTRACT SURFACE / bounded-backing evidence).
    /// UTC/UTC skeleton (32 octets, symbolic in-range fields) with the outer identifier octet `o`
    /// symbolic and low-tag (`o & 0x1F != 0x1F`, a literal assumption). Expected exact result:
    /// `o == 0x30` -> `Ok(Validity { Utc(nb), Utc(na) })`; `o == 0x10` (primitive SEQUENCE) ->
    /// `Err(BadOuterSeq(NotConstructed))`; any other `o` -> `Err(BadOuterSeq(WrongTag))`
    /// (`decode_sequence_tlv`: class/number is checked before the constructed flag). Unwind 20, no
    /// stubs.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_rejects_outer_identifier() {
        let nb = any_utc();
        let na = any_utc();
        let o: u8 = kani::any();
        kani::assume(o & 0x1F != 0x1F);
        let mut buf = build_uu(&nb, &na);
        buf[0] = o;
        let input = &buf[..32];
        let result = parse_validity(input);
        let expected = if o == 0x30 {
            Ok(Validity { not_before: Time::Utc(nb), not_after: Time::Utc(na) })
        } else if o == 0x10 {
            Err(ValidityError::BadOuterSeq(SequenceError::NotConstructed))
        } else {
            Err(ValidityError::BadOuterSeq(SequenceError::WrongTag))
        };
        assert!(result == expected);
        kani::cover(o == 0x30 && result.is_ok(), "outer 0x30 reaches the exact Ok");
        kani::cover(result == Err(ValidityError::BadOuterSeq(SequenceError::NotConstructed)), "NotConstructed outcome");
        kani::cover(result == Err(ValidityError::BadOuterSeq(SequenceError::WrongTag)), "WrongTag outcome");
    }

    /// Per-field identifier rejection precedence (CONTRACT SURFACE / bounded-backing
    /// evidence). UTC/UTC skeleton (32 octets), a symbolic `which` (notBefore or notAfter), and that
    /// field's identifier `t` symbolic and low-tag (`t & 0x1F != 0x1F`). Expected exact result,
    /// wrapped in `NotBefore(_)` / `NotAfter(_)`: `t == 0x17` -> the exact `Ok`; `t == 0x18` ->
    /// `BadGeneralized(BadLength)` (hard-coded: a 13-octet content is below the 15-octet
    /// GeneralizedTime floor, so the expected value does not come from the production decoder); `t` in
    /// `{0x37, 0x38}` -> `Constructed`; any other `t` -> `WrongTag`. Unwind 20, no stubs.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_rejects_field_identifier() {
        let nb = any_utc();
        let na = any_utc();
        let which: bool = kani::any(); // true = notBefore, false = notAfter
        let t: u8 = kani::any();
        kani::assume(t & 0x1F != 0x1F);
        let mut buf = build_uu(&nb, &na);
        let field_off = if which { 2 } else { 17 };
        buf[field_off] = t;
        let input = &buf[..32];
        let result = parse_validity(input);

        let field_err: Option<TimeError> = if t == 0x17 {
            None
        } else if t == 0x18 {
            Some(TimeError::BadGeneralized(GeneralizedTimeError::BadLength))
        } else if t == 0x37 || t == 0x38 {
            Some(TimeError::Constructed)
        } else {
            Some(TimeError::WrongTag)
        };
        let expected = match field_err {
            None => Ok(Validity { not_before: Time::Utc(nb), not_after: Time::Utc(na) }),
            Some(e) => Err(if which { ValidityError::NotBefore(e) } else { ValidityError::NotAfter(e) }),
        };
        assert!(result == expected);
        kani::cover(t == 0x17 && result.is_ok(), "field 0x17 reaches the exact Ok");
        kani::cover(matches!(field_err, Some(TimeError::BadGeneralized(_))) && result == expected, "BadGeneralized outcome");
        kani::cover(matches!(field_err, Some(TimeError::Constructed)) && result == expected, "Constructed outcome");
        kani::cover(matches!(field_err, Some(TimeError::WrongTag)) && result == expected, "WrongTag outcome");
        kani::cover(which && field_err.is_some(), "notBefore-side rejection");
        kani::cover(!which && field_err.is_some(), "notAfter-side rejection");
    }

    /// Missing-field rejections (CONTRACT SURFACE / bounded-backing evidence). Concrete
    /// framing, symbolic content. (i) the empty outer `30 00` -> `Err(MissingNotBefore)`; (ii) the
    /// outer content holding only a notBefore, `30 0F 17 0D <13>` (symbolic in-range fields built by
    /// `encode_utc_time`), -> `Err(MissingNotAfter)`. Unwind 20, no stubs.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_rejects_missing_fields() {
        let empty = [0x30u8, 0x00];
        let r0 = parse_validity(&empty);
        assert!(r0 == Err(ValidityError::MissingNotBefore));
        kani::cover(r0 == Err(ValidityError::MissingNotBefore), "MissingNotBefore outcome");

        let nb = any_utc();
        let mut buf = [0u8; 47];
        buf[0] = 0x30;
        buf[1] = 0x0F;
        let a = put_utc(&mut buf, 2, &nb);
        assert!(a == 15);
        let r1 = parse_validity(&buf[..17]);
        assert!(r1 == Err(ValidityError::MissingNotAfter));
        kani::cover(r1 == Err(ValidityError::MissingNotAfter), "MissingNotAfter outcome");
    }

    /// Field-content rejection (CONTRACT SURFACE / bounded-backing evidence). UTC/UTC skeleton
    /// `30 1E | 17 0D <13> | 17 0D <13>` in which ONE field (`which`: notBefore or notAfter) has
    /// 13 fully symbolic content octets, with NO range assumption, and the other field is a
    /// symbolic in-range `UtcTime` built by the verified encoder. Expected exact result, the
    /// content decision taken from the verified primitive `decode_utc_time`: `Ok(t)` -> the exact
    /// `Ok(Validity { .. })` with `t` in the symbolic slot; `Err(e)` -> `NotBefore(BadUtc(e))` or
    /// `NotAfter(BadUtc(e))`. A notBefore failure precedes everything about notAfter. Backing
    /// `[u8; 47]` (32 used), `#[kani::unwind(20)]`, no stubs. Covers: `Ok`, both `BadUtc` sides.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_rejects_field_content() {
        let which: bool = kani::any(); // true = notBefore carries the symbolic content
        let other = any_utc();
        let content: [u8; 13] = kani::any();
        let mut buf = [0u8; 47];
        buf[0] = 0x30;
        buf[1] = 0x1E;
        let (slot_off, other_off) = if which { (2usize, 17usize) } else { (17usize, 2usize) };
        assert!(put_utc(&mut buf, other_off, &other) == 15);
        buf[slot_off] = 0x17;
        buf[slot_off + 1] = 0x0D;
        let mut i = 0;
        while i < 13 {
            buf[slot_off + 2 + i] = content[i];
            i += 1;
        }
        let input = &buf[..32];
        let result = parse_validity(input);
        let expected = match decode_utc_time(&content) {
            Ok(t) => {
                if which {
                    Ok(Validity { not_before: Time::Utc(t), not_after: Time::Utc(other) })
                } else {
                    Ok(Validity { not_before: Time::Utc(other), not_after: Time::Utc(t) })
                }
            }
            Err(e) => Err(if which {
                ValidityError::NotBefore(TimeError::BadUtc(e))
            } else {
                ValidityError::NotAfter(TimeError::BadUtc(e))
            }),
        };
        assert!(result == expected);
        kani::cover(result.is_ok(), "symbolic content accepted: exact Ok");
        kani::cover(matches!(result, Err(ValidityError::NotBefore(TimeError::BadUtc(_)))), "notBefore BadUtc outcome");
        kani::cover(matches!(result, Err(ValidityError::NotAfter(TimeError::BadUtc(_)))), "notAfter BadUtc outcome");
    }

    /// Field-framing rejection (CONTRACT SURFACE / bounded-backing evidence). UTC/UTC skeleton in
    /// which ONE field (`which`) has its length octet `l` symbolic with `l != 0x0D` (the value
    /// octets stay a valid 13-octet encoding), and the other field is a symbolic in-range
    /// `UtcTime`. Expected exact result, taken from the verified primitives: the TLV decision of
    /// `decode_tlv` on the field's bytes `Err(e)` -> `BadTlv(e)`; otherwise the declared value is
    /// not 13 octets, so `decode_utc_time` on it is an `Err(e)` -> `BadUtc(e)`; wrapped in
    /// `NotBefore(_)` / `NotAfter(_)`. Backing `[u8; 47]` (32 used), `#[kani::unwind(20)]`, no
    /// stubs. Covers: `BadTlv` and `BadUtc` on each side.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_validity_rejects_field_length() {
        let which: bool = kani::any(); // true = notBefore carries the symbolic length octet
        let l: u8 = kani::any();
        kani::assume(l != 0x0D);
        let nb = any_utc();
        let na = any_utc();
        let mut buf = build_uu(&nb, &na);
        let slot_off = if which { 2usize } else { 17usize };
        buf[slot_off + 1] = l;
        let input = &buf[..32];
        let result = parse_validity(input);
        let field_err = match decode_tlv(&input[slot_off..]) {
            Err(e) => TimeError::BadTlv(e),
            Ok((tlv, _)) => TimeError::BadUtc(decode_utc_time(tlv.value).unwrap_err()),
        };
        let expected = Err(if which { ValidityError::NotBefore(field_err) } else { ValidityError::NotAfter(field_err) });
        assert!(result == expected);
        kani::cover(matches!(result, Err(ValidityError::NotBefore(TimeError::BadTlv(_)))), "notBefore BadTlv outcome");
        kani::cover(matches!(result, Err(ValidityError::NotAfter(TimeError::BadTlv(_)))), "notAfter BadTlv outcome");
        kani::cover(matches!(result, Err(ValidityError::NotBefore(TimeError::BadUtc(_)))), "notBefore BadUtc outcome");
        kani::cover(matches!(result, Err(ValidityError::NotAfter(TimeError::BadUtc(_)))), "notAfter BadUtc outcome");
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
