//! SEC1 `ECPrivateKey` (RFC 5915 §3) — a bounded, **structural** consumer that composes this
//! crate's verified primitives.
//!
//! ```text
//! ECPrivateKey ::= SEQUENCE {
//!     version        INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//!     privateKey     OCTET STRING,
//!     parameters [0] ECParameters {{ NamedCurve }} OPTIONAL,   -- [0] EXPLICIT
//!     publicKey  [1] BIT STRING OPTIONAL                        -- [1] EXPLICIT
//! }
//! ```
//! (RFC 5915's ASN.1 module is `DEFINITIONS EXPLICIT TAGS` — both `[0]` and `[1]` below are
//! EXPLICIT context tags, not IMPLICIT.)
//!
//! This module is the sibling of [`crate::pkcs8`] and [`crate::ecdsa_sig_value`]: a
//! **demonstration of composition**, not an expansion of the crate's DER-layer scope (see the
//! crate-level docs). It frames the outer SEQUENCE, the `version` INTEGER, and the `privateKey`
//! OCTET STRING using [`crate::sequence`], [`crate::tlv`], and [`crate::big_integer`] verbatim,
//! peels the two `[n] EXPLICIT` wrappers with [`crate::context_tag::decode_explicit_context`], and
//! decodes the inner `publicKey` BIT STRING with [`crate::bit_string`] — it does not hand-roll any
//! tag/length/TLV parsing of its own.
//!
//! **Two deliberate contrasts with [`crate::pkcs8`], both worth stating explicitly:**
//! 1. **`version` must be exactly `1`** (`ecPrivkeyVer1`), not `0`. Content octets `[0x01]`; a
//!    well-formed INTEGER whose value is anything else is [`EcPrivateKeyError::UnsupportedVersion`]
//!    — a distinct, named error from a structurally malformed INTEGER
//!    ([`EcPrivateKeyError::Version`]), exactly `pkcs8`'s own v1-vs-`UnsupportedVersion` split, just
//!    with a different required value.
//! 2. **`parameters [0]` and `publicKey [1]` are EXPLICIT, not IMPLICIT.** `pkcs8`'s `attributes
//!    [0]` *replaces* the underlying SET's own tag (there is no nested TLV to peel — see
//!    [`crate::context_tag`]'s IMPLICIT/EXPLICIT distinction). Here, by contrast, each `[n]` wraps a
//!    complete, independently-tagged inner TLV (`ECParameters`, a `CHOICE`, and a BIT STRING
//!    respectively), so both fields go through
//!    [`crate::context_tag::decode_explicit_context`] first to peel the wrapper before anything
//!    inside it can be looked at.
//!
//! Otherwise the shape is close to `pkcs8`: an outer SEQUENCE, a required `version` INTEGER, a
//! required opaque OCTET STRING — but where `pkcs8` has *one* optional trailing `[0]`, this module
//! has *two* ordered optional trailing fields, `[0]` then `[1]`.
//!
//! **Scope boundaries (deliberate) — this module proves DER framing and canonicality ONLY:**
//! - **`privateKey` is opaque.** [`EcPrivateKey::private_key`] is the validated OCTET STRING
//!   **content** octets, `&[u8]`, completely uninterpreted: SEC1 §C.4's fixed-length private scalar
//!   is not decoded, range-checked, or otherwise looked at here — exactly `pkcs8`'s own
//!   `private_key` stance. An empty content is structurally valid DER and is accepted (as `pkcs8`
//!   accepts an empty `privateKey`), however unrealistic.
//! - **`parameters` is opaque, but its FRAMING is fully validated.** `ECParameters ::= CHOICE {
//!   namedCurve OBJECT IDENTIFIER, ecParameters SpecifiedECDomain SEQUENCE, implicitCurve NULL }` —
//!   a `CHOICE` has no single universal type, so there is no generic inner decoder this module
//!   could apply without becoming schema-specific. This module therefore peels the `[0] EXPLICIT`
//!   wrapper ([`crate::context_tag::decode_explicit_context`]), then validates that the wrapper's
//!   content is **exactly one well-formed, canonical DER TLV that exactly tiles it** — an EXPLICIT
//!   wrapper contains exactly one nested TLV by definition, so an empty wrapper, a non-canonical
//!   inner encoding (e.g. a non-minimal length), or more than one inner TLV are all rejected as
//!   [`ParametersError`] variants, never silently accepted. What it deliberately does **not** do is
//!   decide *which* `CHOICE` arm was taken, or enforce RFC 5915's `{{ NamedCurve }}` constraint
//!   (that the OID, when present, names a registered curve) — that is Band-B schema/profile
//!   semantics left to the caller, exactly as curve-order range checks are left to a caller by
//!   [`crate::ecdsa_sig_value`]. The validated-but-uninterpreted inner TLV bytes (tag + length +
//!   value, verbatim) are exposed as [`EcPrivateKey::parameters`] (`Option<&'a [u8]>`) — the exact
//!   analogue of `pkcs8`'s opaque `attributes`, and of [`crate::context_tag`]'s own stated design:
//!   the caller applies its own `CHOICE`-arm decoder to the returned bytes. Absent `[0]` is normal
//!   (`parameters` is `OPTIONAL`) and yields `None`, not an error.
//! - **`publicKey` IS decoded as a BIT STRING** — a deliberate asymmetry with `parameters`, worth
//!   justifying: unlike `ECParameters` (a `CHOICE` with no single universal type), `publicKey`'s
//!   inner type is concretely a UNIVERSAL BIT STRING, so peeling the `[1] EXPLICIT` wrapper and then
//!   decoding + canonicality-validating the inner BIT STRING — mirroring
//!   [`crate::x509_spki`]'s `decode_public_key_tlv`, the same universal-type peel — is a clean
//!   structural check squarely within the crate's remit, not a schema-specific judgment call.
//!   Exposed as [`EcPrivateKey::public_key`] (`Option<BitString<'a>>`). This module does **NOT**
//!   require octet-alignment (`unused == 0`) — that is a caller/profile check via
//!   [`crate::bit_string::require_octet_aligned`], the same stance [`crate::ecdsa_sig_value`] takes
//!   on the BIT STRING it is handed. The EC point itself (uncompressed `0x04 || X || Y`, compressed
//!   `0x02`/`0x03` form, curve-membership) is never interpreted.
//! - *Strict/lenient outer-trailing variants, matching the crate's established split
//!   ([`crate::sequence::decode_sequence_tlv`] / [`crate::sequence::decode_sequence_tlv_strict`]).*
//!   [`parse_ec_private_key`] is composable — it does not require `input` to be consumed exactly —
//!   so it can sit inside a larger structure (e.g. as `pkcs8`'s opaque `private_key` payload for the
//!   `id-ecPublicKey` algorithm). [`parse_ec_private_key_strict`] additionally requires `input` to
//!   be consumed exactly — the right choice when a caller already knows the whole byte string is
//!   supposed to be one `ECPrivateKey` and nothing else (e.g. an entire `.der`/`.pem`-decoded EC key
//!   file), guarding the classic trailing-data parser-differential vector.
//!
//! # Examples
//!
//! ```
//! use der_verified::ec_private_key::parse_ec_private_key_strict;
//!
//! // A real openssl-generated P-256 ECPrivateKey (`openssl ecparam -genkey -name prime256v1
//! // -outform DER`), hand-verified with `openssl asn1parse` before trusting it:
//! //   0: 30 77                     SEQUENCE, len 119
//! //   2:   02 01 01                INTEGER version = 1 (ecPrivkeyVer1)
//! //   5:   04 20 <32 octets>       OCTET STRING privateKey
//! //  39:   A0 0a                   [0] EXPLICIT, len 10 (parameters)
//! //  41:     06 08 2a 86 48 ce 3d 03 01 07   OID 1.2.840.10045.3.1.7 (prime256v1)
//! //  51:   A1 44                   [1] EXPLICIT, len 68 (publicKey)
//! //  53:     03 42 00 04 <64 octets> BIT STRING (unused=0; 0x04 uncompressed point marker + X||Y)
//! #[rustfmt::skip]
//! let key_der: [u8; 121] = [
//!     0x30, 0x77,
//!         0x02, 0x01, 0x01,
//!         0x04, 0x20,
//!             0x9b, 0xe3, 0x07, 0xc8, 0xd2, 0x61, 0xee, 0xc4, 0x8a, 0x44, 0xc5, 0x61, 0x45, 0x18,
//!             0x74, 0x17, 0x7e, 0x6b, 0x2d, 0xa1, 0x1b, 0x66, 0x53, 0x1e, 0xe9, 0x5b, 0x5d, 0x14,
//!             0x9a, 0x4f, 0x86, 0xc6,
//!         0xa0, 0x0a,
//!             0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
//!         0xa1, 0x44,
//!             0x03, 0x42, 0x00, 0x04,
//!                 0xa3, 0xdd, 0x8a, 0x22, 0x26, 0x35, 0x66, 0x3b, 0x72, 0x0b, 0xc3, 0x1a, 0xe4, 0x92,
//!                 0xb8, 0xc9, 0xb3, 0x94, 0x8f, 0x05, 0x1c, 0xf9, 0x70, 0x64, 0xfb, 0x63, 0x7c, 0x79,
//!                 0x18, 0x47, 0xe6, 0x86, 0x5a, 0x10, 0xa0, 0xb3, 0xbc, 0x59, 0xc9, 0xd4, 0x11, 0x32,
//!                 0x4d, 0xa5, 0x6c, 0xf5, 0xdc, 0x95, 0x94, 0xeb, 0x5a, 0xc7, 0x69, 0x65, 0xf9, 0xbb,
//!                 0x23, 0x82, 0x5d, 0xfe, 0x82, 0x0f, 0x5f, 0x6c,
//! ];
//! let key = parse_ec_private_key_strict(&key_der).unwrap();
//! assert_eq!(key.private_key.len(), 32); // the OCTET STRING content, still opaque to this crate
//! assert_eq!(key.parameters, Some(&[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07][..]));
//! let public_key = key.public_key.unwrap();
//! assert_eq!(public_key.unused, 0);
//! assert_eq!(public_key.data.len(), 65);
//! assert_eq!(public_key.data[0], 0x04); // uncompressed point marker, uninterpreted
//! ```

use crate::big_integer::{validate_integer_content, BigIntError, TAG as BIG_INTEGER_TAG};
use crate::bit_string::{decode_bit_string, BitString, BitStringError, TAG as BIT_STRING_TAG};
use crate::context_tag::{decode_explicit_context, ContextTagError};
use crate::octet_string::{decode_octet_string, OctetStringError};
use crate::sequence::{decode_sequence_tlv, decode_sequence_tlv_strict, SequenceError};
use crate::tag::{decode_tag, Class};
use crate::tlv::{decode_tlv, TlvError};

/// A structurally-parsed SEC1 `ECPrivateKey`, borrowing from the input it was parsed from.
///
/// See the module docs for the scope of what "parsed" means here: DER framing and canonicality
/// only, `version` restricted to `ecPrivkeyVer1`, `private_key`/`parameters` left opaque, and
/// `public_key` decoded only as far as the generic BIT STRING transfer syntax. There is no
/// `version` field on this struct — a successful parse already guarantees `version ==
/// ecPrivkeyVer1` (see [`EcPrivateKeyError::UnsupportedVersion`]), so there is nothing further for
/// a caller to check.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EcPrivateKey<'a> {
    /// `privateKey`: the validated OCTET STRING **content** octets (not the TLV header), opaque —
    /// see the module docs. Never interpreted; a caller that needs the SEC1 §C.4 scalar decodes it
    /// further.
    pub private_key: &'a [u8],
    /// `parameters` (`[0] EXPLICIT ECParameters OPTIONAL`): the raw inner `ECParameters` TLV bytes
    /// (a single canonical DER TLV, tag + length + value, verbatim) when the `[0]` wrapper is
    /// present — validated to be exactly one well-formed TLV that tiles the wrapper, but the
    /// `CHOICE` arm itself left uninterpreted (see the module docs). `None` when absent (the
    /// normal, common case when the curve is instead named in an enclosing `AlgorithmIdentifier`,
    /// e.g. RFC 5480's PKCS#8-wrapped form).
    pub parameters: Option<&'a [u8]>,
    /// `publicKey` (`[1] EXPLICIT BIT STRING OPTIONAL`): the decoded inner BIT STRING when the
    /// `[1]` wrapper is present — value octets + unused-bit count, the EC point itself opaque (see
    /// the module docs). `None` when absent.
    pub public_key: Option<BitString<'a>>,
}

/// Why the `version` field was rejected as a *structurally* malformed INTEGER (as opposed to
/// [`EcPrivateKeyError::UnsupportedVersion`], a well-formed INTEGER whose value is not
/// `ecPrivkeyVer1`). Shares the shape of [`crate::pkcs8::VersionError`] /
/// [`crate::ecdsa_sig_value::IntegerFieldError`].
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum VersionError {
    /// The field's TLV framing (tag/length octets) was malformed.
    Tlv(TlvError),
    /// The field's identifier was well-framed but not UNIVERSAL 2 (INTEGER).
    WrongTag,
    /// The field's identifier was UNIVERSAL 2 but in the constructed form — INTEGER content is
    /// always primitive.
    Constructed,
    /// The field's content failed canonical-DER minimality (empty, or redundant sign-guard
    /// padding).
    Content(BigIntError),
}

/// Why a confirmed `[0]`-tagged `parameters` wrapper/inner was rejected (as opposed to
/// [`EcPrivateKeyError::TrailingElements`], which covers a trailing element that is not context
/// `[0]` at all).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum ParametersError {
    /// The `[0] EXPLICIT` wrapper's own TLV framing was malformed (bad identifier/length, or the
    /// primitive — non-EXPLICIT — form). See [`crate::context_tag::ContextTagError`].
    Wrapper(ContextTagError),
    /// The wrapper peeled cleanly, but its content was not a single well-formed DER TLV (empty
    /// wrapper, or the inner TLV's own tag/length framing was malformed — e.g. a non-minimal
    /// length). An EXPLICIT wrapper must contain exactly one canonical TLV.
    InnerTlv(TlvError),
    /// Bytes remain inside the `[0]` wrapper after the inner `ECParameters` TLV — an EXPLICIT
    /// wrapper wraps exactly one TLV, so any remainder is unpermitted.
    InnerTrailing,
}

/// Why a confirmed `[1]`-tagged `publicKey` wrapper/inner was rejected (as opposed to
/// [`EcPrivateKeyError::TrailingElements`], which covers a trailing element that is not context
/// `[1]` at all).
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PublicKeyError {
    /// The `[1] EXPLICIT` wrapper's own TLV framing was malformed (bad identifier/length, or the
    /// primitive — non-EXPLICIT — form). See [`crate::context_tag::ContextTagError`].
    Wrapper(ContextTagError),
    /// The wrapper peeled cleanly, but the inner TLV's own tag/length framing was malformed.
    InnerTlv(TlvError),
    /// The inner identifier was well-framed but not UNIVERSAL 3 (BIT STRING).
    WrongTag,
    /// The inner identifier was UNIVERSAL 3 but in the constructed (BER segmented) form —
    /// forbidden in DER.
    Constructed,
    /// Bytes remain inside the `[1]` wrapper after the inner BIT STRING TLV — an EXPLICIT wrapper
    /// wraps exactly one TLV, so any remainder is unpermitted.
    InnerTrailing,
    /// The inner BIT STRING's content failed canonical-DER validation (bad unused-bits count or
    /// non-zero padding).
    Content(BitStringError),
}

/// Why an `ECPrivateKey` was rejected. Every variant names a specific structural cause, wrapping
/// the underlying primitive's/sub-module's error where one exists.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EcPrivateKeyError {
    /// The outer `ECPrivateKey` SEQUENCE envelope was malformed: bad identifier/length, the
    /// primitive (non-constructed) form, or — for [`parse_ec_private_key_strict`] only — trailing
    /// bytes after the whole structure.
    BadOuterSeq(SequenceError),
    /// No `version` is present — the outer SEQUENCE's content is empty.
    MissingVersion,
    /// The `version` field failed to decode as a structurally well-formed INTEGER.
    Version(VersionError),
    /// `version` decoded as a well-formed INTEGER, but its value is not `ecPrivkeyVer1` (content is
    /// not exactly the single octet `0x01`). See the module docs' version-value note.
    UnsupportedVersion,
    /// No `privateKey` is present — the outer SEQUENCE's content ended after `version`.
    MissingPrivateKey,
    /// The `privateKey` OCTET STRING failed to decode.
    PrivateKey(OctetStringError),
    /// A `[0]`-confirmed `parameters` wrapper or its inner content was malformed — either the
    /// `[0] EXPLICIT` wrapper's own TLV framing, or its content was not exactly one canonical DER
    /// TLV. Only reached once the element's own tag has already been classified as context `[0]`
    /// — see [`parse_fields`]'s tag-first discipline. See [`ParametersError`].
    Parameters(ParametersError),
    /// A `[1]`-confirmed `publicKey` wrapper/inner was malformed. See [`PublicKeyError`].
    PublicKey(PublicKeyError),
    /// A trailing element that is neither a valid `[0]` nor a valid `[1]` in the required order, or
    /// bytes remain after a well-formed `publicKey`. The outer SEQUENCE admits nothing beyond
    /// `version`, `privateKey`, an optional `[0]` `parameters`, and an optional `[1]` `publicKey`.
    /// This is a deliberate **umbrella** over several distinct-but-equally-unpermitted trailing
    /// conditions — a non-`[0]`/non-`[1]` tag, an out-of-order `[1]` appearing before `[0]`, a
    /// duplicate `[0]` or `[1]`, an unrecognized context number (e.g. `[2]`), an identifier octet
    /// too malformed to even decode as a tag, or bytes remaining after a well-formed `publicKey` —
    /// the module intentionally does not sub-classify which of these occurred, mirroring
    /// [`crate::pkcs8::Pkcs8Error::TrailingElements`]'s own umbrella stance.
    TrailingElements,
}

/// Decode the `version` INTEGER TLV from the front of `input`, returning its validated content
/// octets and the bytes consumed. Composes [`decode_tlv`] + [`validate_integer_content`], the same
/// shape as [`crate::pkcs8`]'s own `decode_version_tlv`. Does **not** check the `ecPrivkeyVer1`
/// value constraint — that is [`parse_fields`]'s job (see
/// [`EcPrivateKeyError::UnsupportedVersion`]).
fn decode_version_tlv(input: &[u8]) -> Result<(&[u8], usize), VersionError> {
    let (tlv, used) = decode_tlv(input).map_err(VersionError::Tlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != BIG_INTEGER_TAG {
        return Err(VersionError::WrongTag);
    }
    if tlv.tag.constructed {
        return Err(VersionError::Constructed);
    }
    validate_integer_content(tlv.value).map_err(VersionError::Content)?;
    Ok((tlv.value, used))
}

/// Validate the `parameters` inner content peeled from the `[0] EXPLICIT` wrapper: it must be
/// exactly one canonical DER TLV that tiles `inner`. Returns the raw inner TLV bytes unchanged (the
/// `ECParameters` value, still opaque — which `CHOICE` arm it is, and whether it satisfies RFC
/// 5915's `{{ NamedCurve }}` OID constraint, is a caller/profile decision this module does not make).
/// This is pure framing/canonicality validation, exactly the crate's remit — it just does NOT
/// descend into the `CHOICE`.
fn validate_parameters_inner(inner: &[u8]) -> Result<&[u8], ParametersError> {
    let (_tlv, tlv_used) = decode_tlv(inner).map_err(ParametersError::InnerTlv)?;
    if tlv_used != inner.len() {
        return Err(ParametersError::InnerTrailing);
    }
    Ok(inner)
}

/// Decode the `publicKey` inner BIT STRING from `inner` — the content octets already peeled from
/// the `[1] EXPLICIT` wrapper by [`decode_explicit_context`] — requiring the inner TLV to exactly
/// tile `inner` (an EXPLICIT wrapper wraps exactly one TLV). Mirrors
/// [`crate::x509_spki`]'s `decode_public_key_tlv`, adapted to this module's [`PublicKeyError`].
fn decode_public_key_tlv(inner: &[u8]) -> Result<BitString<'_>, PublicKeyError> {
    let (tlv, tlv_used) = decode_tlv(inner).map_err(PublicKeyError::InnerTlv)?;
    if tlv.tag.class != Class::Universal || tlv.tag.number != BIT_STRING_TAG {
        return Err(PublicKeyError::WrongTag);
    }
    if tlv.tag.constructed {
        return Err(PublicKeyError::Constructed);
    }
    if tlv_used != inner.len() {
        return Err(PublicKeyError::InnerTrailing);
    }
    decode_bit_string(tlv.value).map_err(PublicKeyError::Content)
}

/// Decode `version`, `privateKey`, the optional `[0]` `parameters`, and the optional `[1]`
/// `publicKey` from an already-unwrapped outer SEQUENCE `content` slice, requiring the fields to
/// exactly tile it. Shared by both [`parse_ec_private_key`] and [`parse_ec_private_key_strict`] —
/// the only difference between the two entry points is how the outer envelope itself is decoded
/// (composable vs. top-level-strict).
fn parse_fields(outer_content: &[u8]) -> Result<EcPrivateKey<'_>, EcPrivateKeyError> {
    // 1. version: INTEGER, structurally validated, then required to be exactly ecPrivkeyVer1
    //    (content == [0x01]).
    if outer_content.is_empty() {
        return Err(EcPrivateKeyError::MissingVersion);
    }
    let (version_content, version_used) =
        decode_version_tlv(outer_content).map_err(EcPrivateKeyError::Version)?;
    if version_content.len() != 1 || version_content[0] != 0x01 {
        return Err(EcPrivateKeyError::UnsupportedVersion);
    }

    // 2. privateKey: OCTET STRING, opaque.
    let rest = &outer_content[version_used..];
    if rest.is_empty() {
        return Err(EcPrivateKeyError::MissingPrivateKey);
    }
    let (private_key, pk_used) = decode_octet_string(rest).map_err(EcPrivateKeyError::PrivateKey)?;

    // 3. parameters [0] EXPLICIT OPTIONAL — TAG-FIRST classification (the `pkcs8` 2026-08-09 review
    // lesson, replicated here): only a genuinely context-`[0]` element may be blamed on
    // `parameters`. A non-`[0]` tag, or an identifier octet too malformed to even decode as a tag,
    // leaves `parameters = None` and falls through unconsumed to the `publicKey` slot / final
    // tiling check — never misreported as a malformed `[0]` wrapper.
    let rest = &rest[pk_used..];
    let (parameters, rest) = if rest.is_empty() {
        (None, rest)
    } else {
        match decode_tag(rest) {
            Ok((tag, _)) if tag.class == Class::ContextSpecific && tag.number == 0 => {
                // It IS a context-`[0]` attempt: from here, its own wrapper-framing errors, AND its
                // inner content's framing/canonicality errors, are genuinely `Parameters(_)` errors.
                let (inner, used) = decode_explicit_context(0, rest)
                    .map_err(|e| EcPrivateKeyError::Parameters(ParametersError::Wrapper(e)))?;
                let params =
                    validate_parameters_inner(inner).map_err(EcPrivateKeyError::Parameters)?;
                (Some(params), &rest[used..])
            }
            _ => (None, rest),
        }
    };

    // 4. publicKey [1] EXPLICIT OPTIONAL — same tag-first discipline as parameters.
    let (public_key, rest) = if rest.is_empty() {
        (None, rest)
    } else {
        match decode_tag(rest) {
            Ok((tag, _)) if tag.class == Class::ContextSpecific && tag.number == 1 => {
                let (inner, used) = decode_explicit_context(1, rest)
                    .map_err(|e| EcPrivateKeyError::PublicKey(PublicKeyError::Wrapper(e)))?;
                let bs = decode_public_key_tlv(inner).map_err(EcPrivateKeyError::PublicKey)?;
                (Some(bs), &rest[used..])
            }
            _ => (None, rest),
        }
    };

    // 5. exact tiling: nothing beyond version, privateKey, and the two ordered optionals is
    // permitted.
    if !rest.is_empty() {
        return Err(EcPrivateKeyError::TrailingElements);
    }

    Ok(EcPrivateKey { private_key, parameters, public_key })
}

/// Parse one `ECPrivateKey` from the front of `input`.
///
/// Composable, like [`crate::sequence::decode_sequence_tlv`] and
/// [`crate::pkcs8::parse_pkcs8_private_key_info`]: does **not** require `input` to be consumed
/// exactly (trailing bytes after this `ECPrivateKey` are ignored) — a top-level caller checks the
/// returned length itself, or uses [`parse_ec_private_key_strict`] directly.
///
/// Decodes, in order: the outer SEQUENCE envelope ([`decode_sequence_tlv`]); inside it, `version`
/// (INTEGER, required `ecPrivkeyVer1`), `privateKey` (OCTET STRING), the optional `[0] EXPLICIT`
/// `parameters` wrapper, and the optional `[1] EXPLICIT` `publicKey` BIT STRING — requiring the
/// fields to exactly tile the SEQUENCE's content.
///
/// Never panics on any input (proven by the `parse_never_panics` Kani harness below); returns a
/// classified [`EcPrivateKeyError`] on any structural deviation.
pub fn parse_ec_private_key(input: &[u8]) -> Result<(EcPrivateKey<'_>, usize), EcPrivateKeyError> {
    let (outer_content, used) = decode_sequence_tlv(input).map_err(EcPrivateKeyError::BadOuterSeq)?;
    let key = parse_fields(outer_content)?;
    Ok((key, used))
}

/// Parse a complete DER `ECPrivateKey`, requiring it to consume the *entire* `input` (no trailing
/// bytes) — mirrors [`crate::sequence::decode_sequence_tlv_strict`] and
/// [`crate::pkcs8::parse_pkcs8_private_key_info_strict`]'s top-level stance.
///
/// Use this when `input` is known to be exactly one `ECPrivateKey` and nothing else (e.g. an entire
/// `.der`/`.pem`-decoded EC private key file's contents): [`parse_ec_private_key`] deliberately
/// ignores trailing bytes so it can compose inside a larger structure, which is unsafe for a
/// top-level object (the classic trailing-data parser differential).
pub fn parse_ec_private_key_strict(input: &[u8]) -> Result<EcPrivateKey<'_>, EcPrivateKeyError> {
    let outer_content = decode_sequence_tlv_strict(input).map_err(EcPrivateKeyError::BadOuterSeq)?;
    parse_fields(outer_content)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer with a symbolic LENGTH (`0..=16`), matching
// the crate's established symbolic-length convention (`pkcs8.rs`, `ecdsa_sig_value.rs`,
// `x509_tbs_certificate.rs`, `x509_name.rs`): a fixed-length-only proof would leave every shorter
// input UNDISCHARGED, since control flow is length-dependent.
//
// The minimal ECPrivateKey floor is **7 octets**: outer SEQUENCE header (2: `30 05`) + version
// INTEGER (3: `02 01 01`) + an empty privateKey OCTET STRING (2: `04 00`) = 2 + 3 + 2 = 7. 7 <= 16,
// so (unlike `x509_validity::parse_never_panics`, whose Time fields impose a >=32-octet floor that
// provably cannot fit in 16) the Ok cover below is not vacuous at this bound. This is MEASURED, not
// just argued (crate non-vacuity discipline — never claim a cover is satisfied without reading the
// real number): `cargo kani -Z stubbing --harness ec_private_key::` (Kani 0.67.0) reports
// `parse_never_panics` **17 of 17** cover properties satisfied (the `Ok` tail AND all 16 distinct
// reject classes — including the two `Parameters` inner-framing rejects — are each reachable at this
// 16-octet bound), `parse_strict_never_panics` **2 of 2**,
// and `parse_ok_path_witnessed` **1 of 1** — no disclosed-unsatisfiable cover in any of the three
// (contrast pkcs8/x509_validity, which each carry one). A future re-run reporting `0 of 1` for any
// `Ok` cover here is a regression to investigate, not something to accept silently.
//
// The call chain performs up to five independent `decode_tlv`/`decode_tag` calls of its own (outer
// SEQUENCE, version, privateKey, the `[0]` wrapper peel, the `[1]` wrapper peel) plus one more
// `decode_tlv` inside `decode_public_key_tlv` for the inner BIT STRING — no call recurses or loops
// over an unbounded sibling count (this parser reads a fixed four-field schema).
// `#[kani::unwind(20)]` covers a maximal-header `decode_tlv` (~11, per `tlv.rs`) with margin,
// matching `pkcs8`/`ecdsa_sig_value`/`context_tag`'s own bound; if Kani reports an
// unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_ec_private_key` never panics on any input **of any length up to 16
    /// octets** -- the buffer AND its length are both symbolic (see the module's Kani sizing
    /// comment), so this is a bounded claim over the whole `0..=16`-octet domain, not just the
    /// single 16-octet length.
    ///
    /// Cover (T6 primary rule): witnesses the `Ok` tail AND, separately, every distinct structural
    /// rejection variant this module can classify -- not just "some input is accepted, some is
    /// rejected". Would NOT be SAT if `parse_ec_private_key`'s body were a no-op always returning
    /// `Err`, and a `0 of N satisfied` count on any one of these would flag a specific reject class
    /// as structurally unreachable at this bound.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_never_panics() {
        let buf: [u8; 16] = kani::any();
        // Symbolic input length, matching the crate's established convention: so the "any input up
        // to 16 octets" claim above holds at every length in the domain, not just the single
        // length 16.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = parse_ec_private_key(input);

        kani::cover(result.is_ok(), "a well-formed minimal ECPrivateKey reaches the Ok tail");

        kani::cover(
            matches!(result, Err(EcPrivateKeyError::BadOuterSeq(SequenceError::WrongTag))),
            "outer envelope: a non-SEQUENCE tag is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::BadOuterSeq(SequenceError::NotConstructed))),
            "outer envelope: the primitive-form SEQUENCE identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::BadOuterSeq(SequenceError::Tlv(_)))),
            "outer envelope: malformed TLV framing (bad length / truncated) is rejected",
        );

        kani::cover(result == Err(EcPrivateKeyError::MissingVersion), "an empty outer content (no version) is rejected");
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::Version(VersionError::Tlv(_)))),
            "version field: malformed TLV framing (bad length / truncated) is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::Version(VersionError::WrongTag))),
            "version field: a non-INTEGER tag is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::Version(VersionError::Constructed))),
            "version field: the constructed-form INTEGER identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::Version(VersionError::Content(_)))),
            "version field: non-canonical INTEGER content (empty or non-minimal) is rejected",
        );
        kani::cover(
            result == Err(EcPrivateKeyError::UnsupportedVersion),
            "a structurally well-formed but non-ecPrivkeyVer1 version value is rejected",
        );

        kani::cover(
            result == Err(EcPrivateKeyError::MissingPrivateKey),
            "version present but privateKey absent (outer content ends after version) is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::PrivateKey(_))),
            "privateKey: a malformed OCTET STRING is rejected",
        );

        kani::cover(
            matches!(result, Err(EcPrivateKeyError::Parameters(_))),
            "a [0]-confirmed trailing element that is malformed as a parameters wrapper is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::Parameters(ParametersError::InnerTlv(_)))),
            "a [0] parameters wrapper whose inner content is not a single well-formed TLV is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::Parameters(ParametersError::InnerTrailing))),
            "a [0] parameters wrapper with trailing bytes after its inner TLV is rejected",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::PublicKey(_))),
            "a [1]-confirmed trailing element that is malformed as a publicKey wrapper/inner is rejected",
        );
        kani::cover(
            result == Err(EcPrivateKeyError::TrailingElements),
            "a trailing element that is neither a valid [0] nor [1] in order (or bytes after a \
             well-formed publicKey) is rejected",
        );

        let _ = result;
    }

    /// Robustness: `parse_ec_private_key_strict` never panics on any input **of any length up to 16
    /// octets** (buffer and length both symbolic, matching `parse_never_panics` above), and
    /// specifically exercises its one behavioural difference from the composable entry point: a
    /// top-level trailing byte after an otherwise-complete `ECPrivateKey` is rejected.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_strict_never_panics() {
        let buf: [u8; 16] = kani::any();
        // Symbolic input length -- see `parse_never_panics`'s doc comment.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = parse_ec_private_key_strict(input);

        kani::cover(
            result.is_ok(),
            "a well-formed top-level ECPrivateKey (no trailing bytes) reaches the Ok tail",
        );
        kani::cover(
            matches!(result, Err(EcPrivateKeyError::BadOuterSeq(SequenceError::TrailingData))),
            "strict decode rejects a byte trailing the whole ECPrivateKey",
        );

        let _ = result;
    }

    /// Positive-construction companion, on a real openssl-generated P-256 specimen (the same bytes
    /// as the module doc's own example, hand-verified against `openssl asn1parse` before trusting
    /// it — see the module doc). Unlike `x509_validity::parse_never_panics` (whose fully-symbolic
    /// 16-octet buffer cannot reach its own arithmetic floor, a disclosed vacuity), this module's
    /// `parse_never_panics` above DOES witness `Ok` on its own (7-octet floor; measured 17/17 covers,
    /// see the module's sizing comment) — this harness instead exists to machine-check the
    /// *specific*, real-world P-256 shape
    /// the module doc calls out (121 octets total, with both optional fields present), far outside
    /// the 16-octet symbolic harnesses' reach.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_ok_path_witnessed() {
        #[rustfmt::skip]
        const EC_P256: [u8; 121] = [
            0x30, 0x77,
                0x02, 0x01, 0x01,
                0x04, 0x20,
                    0x9b, 0xe3, 0x07, 0xc8, 0xd2, 0x61, 0xee, 0xc4, 0x8a, 0x44, 0xc5, 0x61, 0x45, 0x18,
                    0x74, 0x17, 0x7e, 0x6b, 0x2d, 0xa1, 0x1b, 0x66, 0x53, 0x1e, 0xe9, 0x5b, 0x5d, 0x14,
                    0x9a, 0x4f, 0x86, 0xc6,
                0xa0, 0x0a,
                    0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
                0xa1, 0x44,
                    0x03, 0x42, 0x00, 0x04,
                        0xa3, 0xdd, 0x8a, 0x22, 0x26, 0x35, 0x66, 0x3b, 0x72, 0x0b, 0xc3, 0x1a, 0xe4, 0x92,
                        0xb8, 0xc9, 0xb3, 0x94, 0x8f, 0x05, 0x1c, 0xf9, 0x70, 0x64, 0xfb, 0x63, 0x7c, 0x79,
                        0x18, 0x47, 0xe6, 0x86, 0x5a, 0x10, 0xa0, 0xb3, 0xbc, 0x59, 0xc9, 0xd4, 0x11, 0x32,
                        0x4d, 0xa5, 0x6c, 0xf5, 0xdc, 0x95, 0x94, 0xeb, 0x5a, 0xc7, 0x69, 0x65, 0xf9, 0xbb,
                        0x23, 0x82, 0x5d, 0xfe, 0x82, 0x0f, 0x5f, 0x6c,
        ];

        let result = parse_ec_private_key(&EC_P256);
        kani::cover(
            result.is_ok(),
            "parse_ec_private_key reaches its Ok tail on a real openssl-generated P-256 \
             ECPrivateKey with both optional fields present -- the specific real-world shape the \
             16-octet symbolic harnesses above are too narrow to reach",
        );
        if let Ok((k, _used)) = result {
            assert!(k.private_key.len() == 32);
            const PARAMS_OID_TLV: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
            assert!(k.parameters == Some(&PARAMS_OID_TLV[..]));
            assert!(k.public_key.is_some());
            let bs = k.public_key.unwrap();
            assert!(bs.unused == 0 && bs.data.len() == 65 && bs.data[0] == 0x04);
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A real openssl-generated P-256 `ECPrivateKey` (`openssl ecparam -genkey -name prime256v1
    /// -outform DER`). Same specimen as the module doc's own example and the Kani
    /// `parse_ok_path_witnessed` harness; hand-verified octet-by-octet against `openssl asn1parse`
    /// before trusting it (see the module doc's TLV framing breakdown).
    ///
    /// `30 77`                              SEQUENCE, len 119
    ///    `02 01 01`                        INTEGER version = 1 (ecPrivkeyVer1)
    ///    `04 20 <32 octets>`                OCTET STRING privateKey
    ///    `a0 0a`                            [0] EXPLICIT, len 10 (parameters)
    ///       `06 08 2a 86 48 ce 3d 03 01 07`  OID 1.2.840.10045.3.1.7 (prime256v1)
    ///    `a1 44`                            [1] EXPLICIT, len 68 (publicKey)
    ///       `03 42 00 04 <64 octets>`        BIT STRING (unused=0; 0x04 uncompressed marker + X||Y)
    #[rustfmt::skip]
    const EC_P256: [u8; 121] = [
        0x30, 0x77,
            0x02, 0x01, 0x01,
            0x04, 0x20,
                0x9b, 0xe3, 0x07, 0xc8, 0xd2, 0x61, 0xee, 0xc4, 0x8a, 0x44, 0xc5, 0x61, 0x45, 0x18,
                0x74, 0x17, 0x7e, 0x6b, 0x2d, 0xa1, 0x1b, 0x66, 0x53, 0x1e, 0xe9, 0x5b, 0x5d, 0x14,
                0x9a, 0x4f, 0x86, 0xc6,
            0xa0, 0x0a,
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07,
            0xa1, 0x44,
                0x03, 0x42, 0x00, 0x04,
                    0xa3, 0xdd, 0x8a, 0x22, 0x26, 0x35, 0x66, 0x3b, 0x72, 0x0b, 0xc3, 0x1a, 0xe4, 0x92,
                    0xb8, 0xc9, 0xb3, 0x94, 0x8f, 0x05, 0x1c, 0xf9, 0x70, 0x64, 0xfb, 0x63, 0x7c, 0x79,
                    0x18, 0x47, 0xe6, 0x86, 0x5a, 0x10, 0xa0, 0xb3, 0xbc, 0x59, 0xc9, 0xd4, 0x11, 0x32,
                    0x4d, 0xa5, 0x6c, 0xf5, 0xdc, 0x95, 0x94, 0xeb, 0x5a, 0xc7, 0x69, 0x65, 0xf9, 0xbb,
                    0x23, 0x82, 0x5d, 0xfe, 0x82, 0x0f, 0x5f, 0x6c,
    ];

    /// The raw inner `ECParameters` TLV bytes `EC_P256` carries under its `[0]` wrapper — the
    /// `prime256v1` OID (1.2.840.10045.3.1.7), uninterpreted (see the module docs' opaque-parameters
    /// stance).
    const PARAMS_OID_TLV: [u8; 10] = [0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

    /// The smallest well-formed `ECPrivateKey`: `version = 1`, an EMPTY `privateKey` OCTET STRING
    /// (structurally valid DER — an empty content OCTET STRING is a well-formed, if unrealistic,
    /// value), and neither optional field present — exactly the module's own documented 7-octet
    /// floor. Used as the base specimen for the seeded-bad field-level tests below.
    ///
    /// `30 05`              SEQUENCE, len 5
    ///    `02 01 01`        INTEGER version = 1 (ecPrivkeyVer1)
    ///    `04 00`           OCTET STRING privateKey, empty
    #[rustfmt::skip]
    const EC_MINIMAL: [u8; 7] = [
        0x30, 0x05,
            0x02, 0x01, 0x01,
            0x04, 0x00,
    ];

    #[test]
    fn parses_p256_specimen_composable_and_strict() {
        let (key_c, used) = parse_ec_private_key(&EC_P256).unwrap();
        assert_eq!(used, 121);
        assert_eq!(key_c.private_key.len(), 32);
        assert_eq!(key_c.parameters, Some(&PARAMS_OID_TLV[..]));
        let bs = key_c.public_key.unwrap();
        assert_eq!(bs.data.len(), 65);
        assert_eq!(bs.data[0], 0x04);
        assert_eq!(bs.unused, 0);

        let key_s = parse_ec_private_key_strict(&EC_P256).unwrap();
        assert_eq!(key_s, key_c);
    }

    #[test]
    fn parses_minimal_specimen() {
        let key = parse_ec_private_key_strict(&EC_MINIMAL).unwrap();
        assert_eq!(key.private_key, &[] as &[u8]);
        assert_eq!(key.parameters, None);
        assert_eq!(key.public_key, None);
    }

    #[test]
    fn parses_specimen_with_only_public_key_present() {
        // EC_MINIMAL's version + privateKey, then ONLY a [1] publicKey wrapper (no [0] parameters)
        // -- both fields are independently OPTIONAL. The wrapped BIT STRING is `03 03 00 04 2a`
        // (unused=0, data=[0x04, 0x2a]); the [1] wrapper is `A1 05 <5 bytes>`.
        // Outer content: 3 (version) + 2 (privateKey) + 7 ([1] wrapper) = 12 (0x0c).
        let bytes = [
            0x30, 0x0c,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa1, 0x05, 0x03, 0x03, 0x00, 0x04, 0x2a,
        ];
        let key = parse_ec_private_key_strict(&bytes).unwrap();
        assert_eq!(key.parameters, None);
        let bs = key.public_key.unwrap();
        assert_eq!(bs.unused, 0);
        assert_eq!(bs.data, &[0x04, 0x2a]);
    }

    #[test]
    fn parses_specimen_with_only_parameters_present() {
        // EC_MINIMAL's version + privateKey, then ONLY a [0] parameters wrapper (no [1] publicKey).
        // The wrapper content is an arbitrary opaque 4-byte "OID-shaped" TLV `06 02 2a 03` -- this
        // module never decodes it, so any bytes exercise the same framing a real ECParameters would.
        // Outer content: 3 (version) + 2 (privateKey) + 6 ([0] wrapper) = 11 (0x0b).
        let bytes = [
            0x30, 0x0b,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa0, 0x04, 0x06, 0x02, 0x2a, 0x03,
        ];
        let key = parse_ec_private_key_strict(&bytes).unwrap();
        assert_eq!(key.parameters, Some(&[0x06, 0x02, 0x2a, 0x03][..]));
        assert_eq!(key.public_key, None);
    }

    #[test]
    fn composable_ignores_trailing_bytes() {
        let mut bytes = EC_MINIMAL.to_vec();
        bytes.push(0xFF);
        let (key, used) = parse_ec_private_key(&bytes).unwrap();
        assert_eq!(used, 7);
        assert_eq!(key.private_key, &[] as &[u8]);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn strict_rejects_trailing_byte_after_ec_private_key() {
        let mut bytes = EC_MINIMAL.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            parse_ec_private_key_strict(&bytes),
            Err(EcPrivateKeyError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_wrong_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = EC_MINIMAL;
        bytes[0] = 0x31;
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_primitive_outer_sequence_identifier() {
        // 0x10 = UNIVERSAL 16 primitive. A SEQUENCE is always constructed (X.690 §8.9.1).
        let mut bytes = EC_MINIMAL;
        bytes[0] = 0x10;
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::BadOuterSeq(SequenceError::NotConstructed))
        );
    }

    #[test]
    fn rejects_ber_long_form_length_where_short_form_fits() {
        // Outer SEQUENCE length 5 re-encoded in the BER long form (0x81 0x05) where DER requires
        // the short form (0x05) -- non-minimal (X.690 §8.1.3), forbidden by DER.
        use crate::length::LengthError;
        let mut bytes = vec![0x30, 0x81, 0x05];
        bytes.extend_from_slice(&EC_MINIMAL[2..]);
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_truncated_outer_envelope() {
        // Declares 5 content bytes but only 3 are present.
        let bytes = &EC_MINIMAL[..5];
        assert_eq!(
            parse_ec_private_key(bytes),
            Err(EcPrivateKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_indefinite_length_outer_envelope() {
        // 0x30 0x80 = SEQUENCE with the BER indefinite length form; rejected by the length codec
        // (inherited), surfaced as Tlv(Length(Indefinite)).
        use crate::length::LengthError;
        assert_eq!(
            parse_ec_private_key(&[0x30, 0x80, 0x00, 0x00]),
            Err(EcPrivateKeyError::BadOuterSeq(SequenceError::Tlv(TlvError::Length(
                LengthError::Indefinite
            ))))
        );
    }

    #[test]
    fn rejects_empty_outer_content_missing_version() {
        let bytes = [0x30, 0x00];
        assert_eq!(parse_ec_private_key(&bytes), Err(EcPrivateKeyError::MissingVersion));
    }

    #[test]
    fn rejects_version_wrong_tag() {
        // version's identifier is BOOLEAN (0x01) instead of INTEGER (0x02).
        let mut bytes = EC_MINIMAL;
        bytes[2] = 0x01;
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Version(VersionError::WrongTag))
        );
    }

    #[test]
    fn rejects_version_constructed() {
        // version's identifier is INTEGER's tag number but in the constructed form (0x22 instead
        // of 0x02).
        let mut bytes = EC_MINIMAL;
        bytes[2] = 0x22;
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Version(VersionError::Constructed))
        );
    }

    #[test]
    fn rejects_version_empty_integer() {
        // version's INTEGER has zero content octets -- an INTEGER needs at least one (X.690
        // §8.3.1). `30 04 02 00 04 00` (SEQUENCE { INTEGER <empty>, OCTET STRING <empty> }).
        let bytes = [0x30, 0x04, 0x02, 0x00, 0x04, 0x00];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Version(VersionError::Content(BigIntError::Empty)))
        );
    }

    #[test]
    fn rejects_unsupported_version_zero() {
        // version content is 0x00 -- a structurally well-formed, minimal, single-octet INTEGER, but
        // not ecPrivkeyVer1 (which requires exactly 1). Matches the spec's canonical
        // UnsupportedVersion example.
        let mut bytes = EC_MINIMAL;
        bytes[4] = 0x00;
        assert_eq!(parse_ec_private_key(&bytes), Err(EcPrivateKeyError::UnsupportedVersion));
    }

    #[test]
    fn rejects_unsupported_version_two() {
        // version content is 0x02 -- likewise well-formed but not ecPrivkeyVer1.
        let mut bytes = EC_MINIMAL;
        bytes[4] = 0x02;
        assert_eq!(parse_ec_private_key(&bytes), Err(EcPrivateKeyError::UnsupportedVersion));
    }

    #[test]
    fn rejects_missing_private_key() {
        // Only version is present: 30 03 02 01 01 (SEQUENCE { INTEGER 1 }, nothing else).
        let bytes = [0x30, 0x03, 0x02, 0x01, 0x01];
        assert_eq!(parse_ec_private_key(&bytes), Err(EcPrivateKeyError::MissingPrivateKey));
    }

    #[test]
    fn rejects_private_key_wrong_tag() {
        // privateKey's identifier is BOOLEAN (0x01) instead of OCTET STRING (0x04).
        let mut bytes = EC_MINIMAL;
        bytes[5] = 0x01;
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::PrivateKey(OctetStringError::WrongTag))
        );
    }

    #[test]
    fn rejects_private_key_constructed() {
        // privateKey's identifier is OCTET STRING's tag number but in the constructed (BER
        // segmented) form (0x24 instead of 0x04) -- forbidden in DER.
        let mut bytes = EC_MINIMAL;
        bytes[5] = 0x24;
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::PrivateKey(OctetStringError::Constructed))
        );
    }

    #[test]
    fn rejects_private_key_truncated() {
        // privateKey's OCTET STRING declares 5 content octets but none are present -- caught
        // inside the OCTET STRING's own TLV parse.
        let mut bytes = EC_MINIMAL;
        bytes[6] = 0x05;
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::PrivateKey(OctetStringError::Tlv(TlvError::Truncated)))
        );
    }

    #[test]
    fn rejects_parameters_primitive_form() {
        // A context-specific [0] identifier in the *primitive* form (0x80 instead of 0xA0) --
        // EXPLICIT tagging is always constructed. Outer content: 3 + 2 + 4 = 9 (0x09).
        let bytes = [
            0x30, 0x09,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0x80, 0x02, 0xAA, 0xBB,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Parameters(ParametersError::Wrapper(ContextTagError::NotConstructed)))
        );
    }

    #[test]
    fn rejects_parameters_truncated_wrapper() {
        // A context [0] constructed wrapper that declares 5 content bytes but only 1 (`AA`) is
        // present -- caught by the wrapper's OWN TLV framing (decode_explicit_context's decode_tlv),
        // before the new inner-content validation is even reached. Outer content: 3 + 2 + 3 = 8 (0x08).
        let bytes = [
            0x30, 0x08,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xA0, 0x05, 0xAA,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Parameters(ParametersError::Wrapper(ContextTagError::BadTlv(TlvError::Truncated))))
        );
    }

    #[test]
    fn rejects_parameters_empty_wrapper() {
        // A well-formed, EMPTY [0] EXPLICIT wrapper (`A0 00`) -- the wrapper's own TLV framing is
        // fine, but EXPLICIT must wrap exactly ONE inner TLV, and there is none here: the new
        // inner-content validation (`validate_parameters_inner`) rejects it via `decode_tlv(&[])`.
        // Outer content: 3 + 2 + 2 = 7 (0x07).
        let bytes = [
            0x30, 0x07,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xA0, 0x00,
        ];
        assert!(matches!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Parameters(ParametersError::InnerTlv(_)))
        ));
    }

    #[test]
    fn rejects_parameters_non_canonical_inner_length() {
        // The [0] wrapper's inner TLV is an OID (`06 81 01 2a`) whose length is re-encoded in the
        // BER long form (`81 01`) where the short form (`01`) is required -- non-minimal, forbidden
        // by DER (X.690 §8.1.3), caught by the inner `decode_tlv` call inside
        // `validate_parameters_inner`. Wrapper: `A0 04 06 81 01 2a` (6 bytes).
        // Outer content: 3 + 2 + 6 = 11 (0x0b).
        use crate::length::LengthError;
        let bytes = [
            0x30, 0x0B,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xA0, 0x04, 0x06, 0x81, 0x01, 0x2A,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Parameters(ParametersError::InnerTlv(TlvError::Length(
                LengthError::NonMinimal
            ))))
        );
    }

    #[test]
    fn rejects_parameters_two_inner_tlvs() {
        // The [0] wrapper's content is TWO well-formed TLVs (`06 01 2a` then `05 00`) -- an
        // EXPLICIT wrapper contains exactly one, so the second is unpermitted trailing content
        // inside the wrapper. Wrapper: `A0 05 06 01 2a 05 00` (7 bytes).
        // Outer content: 3 + 2 + 7 = 12 (0x0c).
        let bytes = [
            0x30, 0x0C,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xA0, 0x05, 0x06, 0x01, 0x2A, 0x05, 0x00,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::Parameters(ParametersError::InnerTrailing))
        );
    }

    #[test]
    fn accepts_parameters_null_arm_choice_uninterpreted() {
        // The [0] wrapper's inner TLV is a NULL (`05 00`) -- a structurally valid single canonical
        // DER TLV, so it passes framing validation cleanly, even though it is the `implicitCurve`
        // CHOICE arm rather than `namedCurve`. This documents the deliberate boundary: this module
        // validates FRAMING only (exactly one canonical TLV tiling the wrapper) and does not decide
        // which CHOICE arm was taken, nor enforce RFC 5915's `{{ NamedCurve }}` OID constraint --
        // that is a caller/profile concern (Band-B semantics), consistent with the module docs.
        // Wrapper: `A0 02 05 00` (4 bytes). Outer content: 3 + 2 + 4 = 9 (0x09).
        let bytes = [
            0x30, 0x09,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xA0, 0x02, 0x05, 0x00,
        ];
        let key = parse_ec_private_key_strict(&bytes).unwrap();
        assert_eq!(key.parameters, Some(&[0x05, 0x00][..]));
    }

    #[test]
    fn rejects_public_key_wrapper_primitive() {
        // A context-specific [1] identifier in the *primitive* form (0x81 instead of 0xA1).
        // Outer content: 3 + 2 + 4 = 9 (0x09).
        let bytes = [
            0x30, 0x09,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0x81, 0x02, 0xAA, 0xBB,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::PublicKey(PublicKeyError::Wrapper(ContextTagError::NotConstructed)))
        );
    }

    #[test]
    fn rejects_public_key_inner_wrong_tag() {
        // The [1] wrapper's inner TLV is an INTEGER (0x02) instead of a BIT STRING (0x03).
        // Inner: `02 01 05` (3 bytes); wrapper: `A1 03 <inner>` (5 bytes).
        // Outer content: 3 + 2 + 5 = 10 (0x0a).
        let bytes = [
            0x30, 0x0a,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa1, 0x03, 0x02, 0x01, 0x05,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::PublicKey(PublicKeyError::WrongTag))
        );
    }

    #[test]
    fn rejects_public_key_inner_non_canonical_bit_string() {
        // The inner BIT STRING's unused-bits octet is 8 -- impossible in a single octet (>7).
        // Inner: `03 02 08 ff` (4 bytes); wrapper: `A1 04 <inner>` (6 bytes).
        // Outer content: 3 + 2 + 6 = 11 (0x0b).
        let bytes = [
            0x30, 0x0b,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa1, 0x04, 0x03, 0x02, 0x08, 0xff,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::PublicKey(PublicKeyError::Content(BitStringError::UnusedBitsTooLarge)))
        );
    }

    #[test]
    fn rejects_public_key_inner_trailing() {
        // A well-formed inner BIT STRING TLV (`03 02 00 2a`, 4 bytes), followed by one extra byte
        // still inside the [1] wrapper's own content -- an EXPLICIT wrapper wraps exactly one TLV.
        // Wrapper: `A1 05 <inner 4 bytes> AA` (7 bytes). Outer content: 3 + 2 + 7 = 12 (0x0c).
        let bytes = [
            0x30, 0x0c,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa1, 0x05, 0x03, 0x02, 0x00, 0x2a, 0xAA,
        ];
        assert_eq!(
            parse_ec_private_key(&bytes),
            Err(EcPrivateKeyError::PublicKey(PublicKeyError::InnerTrailing))
        );
    }

    #[test]
    fn rejects_wrong_order_public_key_then_parameters() {
        // [1] publicKey appears BEFORE [0] parameters -- the schema requires [0] then [1] in order.
        // The [0]-slot sees a [1] tag first (not a [0] attempt, so parameters stays None and the
        // tag is not consumed); the publicKey slot then matches and consumes the [1] wrapper; the
        // [0]-shaped bytes that follow are an unpermitted trailing element.
        // publicKey wrapper: `A1 03 03 01 00` (5 bytes, valid empty-ish BIT STRING).
        // trailing element: `A0 02 AA BB` (4 bytes, never reached as a parameters attempt).
        // Outer content: 3 + 2 + 5 + 4 = 14 (0x0e).
        let bytes = [
            0x30, 0x0e,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa1, 0x03, 0x03, 0x01, 0x00,
                0xa0, 0x02, 0xAA, 0xBB,
        ];
        assert_eq!(parse_ec_private_key(&bytes), Err(EcPrivateKeyError::TrailingElements));
    }

    #[test]
    fn rejects_trailing_context_2() {
        // A trailing context-specific [2] element -- not permitted by the schema (only [0] and
        // [1] are defined). Outer content: 3 + 2 + 4 = 9 (0x09).
        let bytes = [
            0x30, 0x09,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa2, 0x02, 0xAA, 0xBB,
        ];
        assert_eq!(parse_ec_private_key(&bytes), Err(EcPrivateKeyError::TrailingElements));
    }

    #[test]
    fn rejects_duplicate_parameters() {
        // Two [0] wrappers in a row -- the first is consumed as parameters (its content, `05 00`,
        // is a single canonical NULL TLV, so it passes the new inner-content validation cleanly);
        // the second is an unpermitted trailing element (the publicKey slot only matches [1], so it
        // stays None and does not consume the second [0]).
        // Each wrapper: `A0 02 05 00` (4 bytes). Outer content: 3 + 2 + 4 + 4 = 13 (0x0d).
        let bytes = [
            0x30, 0x0d,
                0x02, 0x01, 0x01,
                0x04, 0x00,
                0xa0, 0x02, 0x05, 0x00,
                0xa0, 0x02, 0x05, 0x00,
        ];
        assert_eq!(parse_ec_private_key(&bytes), Err(EcPrivateKeyError::TrailingElements));
    }
}
