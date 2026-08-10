//! RFC 5958 §3 `EncryptedPrivateKeyInfo` — a bounded, **structural** consumer that composes this
//! crate's verified primitives.
//!
//! ```text
//! EncryptedPrivateKeyInfo ::= SEQUENCE {
//!     encryptionAlgorithm  AlgorithmIdentifier,
//!     encryptedData        OCTET STRING }
//! ```
//!
//! This module is the sibling of [`crate::pkcs8`] and [`crate::rsa_public_key`]: a **demonstration
//! of composition**, not an expansion of the crate's DER-layer scope (see the crate-level docs). It
//! frames the outer SEQUENCE using [`crate::sequence`] and delegates both fields whole to
//! [`crate::x509_algorithm_identifier::parse_algorithm_identifier`] and
//! [`crate::octet_string::decode_octet_string`] — it does not hand-roll any tag/length/TLV parsing
//! of its own.
//!
//! Structurally this is the *simplest* of this crate's SEQUENCE containers: a fixed, two-field
//! schema with no `version`, no OPTIONAL field, and no variable-count member walk (none of
//! [`crate::rsa_private_key`]'s traps).
//!
//! **Scope boundaries (deliberate) — this module proves DER framing and canonicality ONLY:**
//! - **`encryptionAlgorithm`'s `parameters` stays opaque.** Delegated whole to
//!   [`crate::x509_algorithm_identifier::parse_algorithm_identifier`], which validates the
//!   `AlgorithmIdentifier` SEQUENCE + OID framing but leaves `parameters` (`ANY`) raw and
//!   uninterpreted — see that module's own documented stance. In particular, this module does
//!   **not** validate the `PBES2-params` schema (RFC 8018 §A.4) that a real password-based
//!   `encryptionAlgorithm` commonly carries in `parameters`; it proves TLV framing only, and
//!   introduces no NEW canonicality claim over that nested structure.
//! - **`encryptedData` is opaque ciphertext.** [`EncryptedPrivateKeyInfo::encrypted_data`] is the
//!   validated OCTET STRING **content** octets, completely uninterpreted — correctly so, since it
//!   is encrypted: this module has no way to (and does not attempt to) validate anything about its
//!   plaintext shape. Decrypting it, and interpreting whatever `PrivateKeyInfo`/`OneAsymmetricKey`
//!   DER it presumably contains once decrypted, is a caller's job (e.g. via [`crate::pkcs8`]).
//! - *Strict/lenient outer-trailing variants, matching the crate's established split
//!   ([`crate::sequence::decode_sequence_tlv`] / [`crate::sequence::decode_sequence_tlv_strict`]).*
//!   [`parse_encrypted_private_key_info`] is composable — it does not require `input` to be
//!   consumed exactly — so it can sit inside a larger structure.
//!   [`parse_encrypted_private_key_info_strict`] additionally requires `input` to be consumed
//!   exactly — the right choice when a caller already knows the whole byte string is supposed to be
//!   one `EncryptedPrivateKeyInfo` and nothing else (e.g. an entire `.der` file), guarding the
//!   classic trailing-data parser-differential vector.
//!
//! # Examples
//!
//! ```
//! use der_verified::encrypted_private_key_info::parse_encrypted_private_key_info_strict;
//!
//! // A minimal well-formed EncryptedPrivateKeyInfo: a one-field AlgorithmIdentifier (an arbitrary
//! // single-octet OID content, arc {0, 0}) and a two-octet encryptedData OCTET STRING. (The absolute
//! // floor is 9 octets -- the same shape with an empty `04 00` encryptedData.)
//! let der = [
//!     0x30, 0x09,
//!         0x30, 0x03, 0x06, 0x01, 0x00,
//!         0x04, 0x02, 0xaa, 0xbb,
//! ];
//! let info = parse_encrypted_private_key_info_strict(&der).unwrap();
//! assert_eq!(info.encryption_algorithm.algorithm_oid, &[0x00]);
//! assert_eq!(info.encrypted_data, &[0xaa, 0xbb]);
//! ```

use crate::octet_string::{decode_octet_string, OctetStringError};
use crate::sequence::{decode_sequence_tlv, decode_sequence_tlv_strict, SequenceError};
use crate::x509_algorithm_identifier::{parse_algorithm_identifier, AlgIdError, AlgorithmIdentifier};

/// A structurally-parsed RFC 5958 `EncryptedPrivateKeyInfo`, borrowing from the input it was
/// parsed from.
///
/// See the module docs for the scope of what "parsed" means here: DER framing and canonicality
/// only, with `encryption_algorithm.parameters` and `encrypted_data` both left opaque.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct EncryptedPrivateKeyInfo<'a> {
    /// `encryptionAlgorithm`: the already-parsed [`AlgorithmIdentifier`], delegated whole to
    /// [`crate::x509_algorithm_identifier::parse_algorithm_identifier`]. Its `parameters` field
    /// (e.g. a real-world `PBES2-params`) stays raw — see the module docs.
    pub encryption_algorithm: AlgorithmIdentifier<'a>,
    /// `encryptedData`: the validated OCTET STRING **content** octets (not the TLV header) — opaque
    /// ciphertext, never interpreted. A caller decrypts it (using whatever `encryption_algorithm`
    /// names) to recover the plaintext, itself presumably further DER.
    pub encrypted_data: &'a [u8],
}

/// Why an `EncryptedPrivateKeyInfo` was rejected. Every variant names a specific structural cause,
/// wrapping the underlying primitive's/sub-module's error where one exists.
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum EncryptedPrivateKeyInfoError {
    /// The outer `EncryptedPrivateKeyInfo` SEQUENCE envelope was malformed: bad identifier/length,
    /// the primitive (non-constructed) form, or — for
    /// [`parse_encrypted_private_key_info_strict`] only — trailing bytes after the whole structure.
    BadOuterSeq(SequenceError),
    /// The outer SEQUENCE content is empty: the mandatory `encryptionAlgorithm` field is absent.
    /// Distinguished from a present-but-malformed `AlgorithmIdentifier` ([`Self::EncryptionAlgorithm`])
    /// so a caller can tell "no field" from "bad field" — mirrors `pkcs8`'s `MissingVersion` etc.
    MissingEncryptionAlgorithm,
    /// The `encryptionAlgorithm` `AlgorithmIdentifier` was present but failed to decode.
    EncryptionAlgorithm(AlgIdError),
    /// The `encryptionAlgorithm` was present and well-formed, but the mandatory `encryptedData`
    /// field is absent: no bytes remain in the SEQUENCE content after it.
    MissingEncryptedData,
    /// The `encryptedData` OCTET STRING was present but failed to decode.
    EncryptedData(OctetStringError),
    /// The `EncryptedPrivateKeyInfo` SEQUENCE has more than its two permitted fields
    /// (`encryptionAlgorithm`, `encryptedData`): bytes remain in its content after the
    /// `encryptedData` TLV.
    TrailingElements,
}

/// Decode `encryptionAlgorithm` then `encryptedData` from an already-unwrapped outer SEQUENCE
/// `content` slice, requiring the two fields to exactly tile it. Shared by both
/// [`parse_encrypted_private_key_info`] and [`parse_encrypted_private_key_info_strict`] — the only
/// difference between the two entry points is how the outer envelope itself is decoded (composable
/// vs. top-level-strict).
fn parse_fields(outer_content: &[u8]) -> Result<EncryptedPrivateKeyInfo<'_>, EncryptedPrivateKeyInfoError> {
    // 1. encryptionAlgorithm: AlgorithmIdentifier, delegated whole (composable; ignores trailing).
    // An empty content means the field is absent, classified distinctly from a malformed one (so the
    // delegated `EncryptionAlgorithm(_)` error only ever witnesses a present-but-malformed field) --
    // mirrors `pkcs8::parse_fields`'s `is_empty` guards.
    if outer_content.is_empty() {
        return Err(EncryptedPrivateKeyInfoError::MissingEncryptionAlgorithm);
    }
    let (encryption_algorithm, alg_used) = parse_algorithm_identifier(outer_content)
        .map_err(EncryptedPrivateKeyInfoError::EncryptionAlgorithm)?;

    // 2. encryptedData: OCTET STRING, opaque, required to exactly tile whatever remains.
    let rest = &outer_content[alg_used..];
    if rest.is_empty() {
        return Err(EncryptedPrivateKeyInfoError::MissingEncryptedData);
    }
    let (encrypted_data, data_used) =
        decode_octet_string(rest).map_err(EncryptedPrivateKeyInfoError::EncryptedData)?;
    if data_used != rest.len() {
        return Err(EncryptedPrivateKeyInfoError::TrailingElements);
    }

    Ok(EncryptedPrivateKeyInfo { encryption_algorithm, encrypted_data })
}

/// Parse one `EncryptedPrivateKeyInfo` from the front of `input`.
///
/// Composable, like [`crate::sequence::decode_sequence_tlv`] and [`crate::pkcs8`]'s own
/// composable entry point: does **not** require `input` to be consumed exactly (trailing bytes
/// after this `EncryptedPrivateKeyInfo` are ignored) — a top-level caller checks the returned
/// length itself, or uses [`parse_encrypted_private_key_info_strict`] directly.
///
/// Decodes, in order: the outer SEQUENCE envelope ([`decode_sequence_tlv`]); inside it,
/// `encryptionAlgorithm` (delegated to
/// [`crate::x509_algorithm_identifier::parse_algorithm_identifier`]) then `encryptedData` (OCTET
/// STRING), requiring the two fields to exactly tile the SEQUENCE's content.
///
/// Never panics on any input **up to the harness's 16-octet symbolic bound** (proven by the
/// `parse_never_panics` Kani harness below over a fully-symbolic `0..=16`-octet domain); returns a
/// classified [`EncryptedPrivateKeyInfoError`] on any structural deviation.
pub fn parse_encrypted_private_key_info(
    input: &[u8],
) -> Result<(EncryptedPrivateKeyInfo<'_>, usize), EncryptedPrivateKeyInfoError> {
    let (outer_content, used) =
        decode_sequence_tlv(input).map_err(EncryptedPrivateKeyInfoError::BadOuterSeq)?;
    let info = parse_fields(outer_content)?;
    Ok((info, used))
}

/// Parse a complete DER `EncryptedPrivateKeyInfo`, requiring it to consume the *entire* `input` (no
/// trailing bytes) — mirrors [`crate::sequence::decode_sequence_tlv_strict`] and
/// [`crate::pkcs8::parse_pkcs8_private_key_info_strict`]'s top-level stance.
///
/// Use this when `input` is known to be exactly one `EncryptedPrivateKeyInfo` and nothing else
/// (e.g. a whole `.der` file's contents): [`parse_encrypted_private_key_info`] deliberately ignores
/// trailing bytes so it can compose inside a larger structure, which is unsafe for a top-level
/// object (the classic trailing-data parser differential).
pub fn parse_encrypted_private_key_info_strict(
    input: &[u8],
) -> Result<EncryptedPrivateKeyInfo<'_>, EncryptedPrivateKeyInfoError> {
    let outer_content =
        decode_sequence_tlv_strict(input).map_err(EncryptedPrivateKeyInfoError::BadOuterSeq)?;
    parse_fields(outer_content)
}

// ---------------------------------------------------------------------------
// Kani proof harnesses.
// ---------------------------------------------------------------------------
//
// Buffer sizing / unwind: a 16-octet symbolic buffer with a symbolic LENGTH (`0..=16`), matching
// the crate's established symbolic-length convention (`pkcs8.rs`, `rsa_public_key.rs`,
// `ecdsa_sig_value.rs`): a fixed-length-only proof would leave every shorter input UNDISCHARGED,
// since control flow is length-dependent.
//
// The minimal EncryptedPrivateKeyInfo floor is 9 octets: outer SEQUENCE header (2: `30 07`) + a
// minimal one-field AlgorithmIdentifier (5: `30 03 06 01 00` — a single-octet OID, since
// `crate::oid::validate_oid` accepts the one-octet content `00`, arc {0, 0}) + an empty
// encryptedData OCTET STRING (2: `04 00`) = 2+5+2 = 9. A 16-octet symbolic buffer therefore has 7
// spare octets of slack over that floor — comfortably more slack than `pkcs8`'s own 12-octet floor
// — so the `Ok` cover is NOT expected to be vacuous by the same arithmetic argument; run and read
// the actual satisfaction count rather than trusting this arithmetic alone (crate non-vacuity
// discipline — never claim a cover is satisfied without reading the real number).
//
// The call chain is a fixed two-field schema: `decode_sequence_tlv` + `parse_algorithm_identifier`
// (itself up to three `decode_tlv` calls plus `validate_oid`'s own bounded content walk) +
// `decode_octet_string` (one more `decode_tlv` call) — no call recurses or loops over an unbounded
// sibling count. `#[kani::unwind(20)]` covers a maximal-header `decode_tlv` (~11, per `tlv.rs`)
// with margin, matching `pkcs8`/`x509_algorithm_identifier`'s own bound; if Kani reports an
// unwinding-assertion failure, raise this bound (do not weaken scope).
#[cfg(kani)]
mod proofs {
    use super::*;

    /// Robustness: `parse_encrypted_private_key_info` never panics on any input **of any length up
    /// to 16 octets** -- the buffer AND its length are both symbolic (see the module's Kani sizing
    /// comment), so this is a bounded claim over the whole `0..=16`-octet domain, not just the
    /// single 16-octet length.
    ///
    /// Cover (T6 primary rule): witnesses the `Ok` tail AND, separately, every distinct structural
    /// rejection variant this module can classify -- not just "some input is accepted, some is
    /// rejected". Would NOT be SAT if `parse_encrypted_private_key_info`'s body were a no-op always
    /// returning `Err`, and a `0 of N satisfied` count on any one of these would flag a specific
    /// reject class as structurally unreachable at this bound.
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
        let result = parse_encrypted_private_key_info(input);

        kani::cover(result.is_ok(), "a well-formed minimal EncryptedPrivateKeyInfo reaches the Ok tail");

        kani::cover(
            matches!(result, Err(EncryptedPrivateKeyInfoError::BadOuterSeq(SequenceError::WrongTag))),
            "outer envelope: a non-SEQUENCE tag is rejected",
        );
        kani::cover(
            matches!(
                result,
                Err(EncryptedPrivateKeyInfoError::BadOuterSeq(SequenceError::NotConstructed))
            ),
            "outer envelope: the primitive-form SEQUENCE identifier is rejected",
        );
        kani::cover(
            matches!(result, Err(EncryptedPrivateKeyInfoError::BadOuterSeq(SequenceError::Tlv(_)))),
            "outer envelope: malformed TLV framing (bad length / truncated) is rejected",
        );

        kani::cover(
            result == Err(EncryptedPrivateKeyInfoError::MissingEncryptionAlgorithm),
            "an empty outer content (encryptionAlgorithm absent) is rejected",
        );
        // Delegated-field arms use a GENERIC `Field(_)` cover (mirroring `pkcs8`'s
        // `Algorithm(_)`/`PrivateKey(_)` covers): this module CLASSIFIES the failure to the field;
        // the specific AlgIdError/OctetStringError sub-variants are each exercised by the composed
        // module's OWN harness. The `is_empty` guards above ensure this cover witnesses only a
        // present-but-malformed field, never an absent one.
        kani::cover(
            matches!(result, Err(EncryptedPrivateKeyInfoError::EncryptionAlgorithm(_))),
            "encryptionAlgorithm: a present-but-malformed AlgorithmIdentifier is rejected",
        );

        kani::cover(
            result == Err(EncryptedPrivateKeyInfoError::MissingEncryptedData),
            "a valid encryptionAlgorithm with no bytes after it (encryptedData absent) is rejected",
        );
        kani::cover(
            matches!(result, Err(EncryptedPrivateKeyInfoError::EncryptedData(_))),
            "encryptedData: a valid encryptionAlgorithm followed by a present-but-malformed OCTET STRING is rejected",
        );

        kani::cover(
            result == Err(EncryptedPrivateKeyInfoError::TrailingElements),
            "a valid encryptionAlgorithm + encryptedData followed by >= 1 trailing octet in the \
             SEQUENCE is rejected",
        );

        let _ = result;
    }

    /// Robustness: `parse_encrypted_private_key_info_strict` never panics on any input **of any
    /// length up to 16 octets** (buffer and length both symbolic, matching `parse_never_panics`
    /// above), and specifically exercises its one behavioural difference from the composable entry
    /// point: a top-level trailing byte after an otherwise-complete `EncryptedPrivateKeyInfo` is
    /// rejected.
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_strict_never_panics() {
        let buf: [u8; 16] = kani::any();
        // Symbolic input length -- see `parse_never_panics`'s doc comment.
        let len: usize = kani::any();
        kani::assume(len <= buf.len());
        let input = &buf[..len];
        let result = parse_encrypted_private_key_info_strict(input);

        kani::cover(
            result.is_ok(),
            "a well-formed top-level EncryptedPrivateKeyInfo (no trailing bytes) reaches the Ok tail",
        );
        kani::cover(
            matches!(
                result,
                Err(EncryptedPrivateKeyInfoError::BadOuterSeq(SequenceError::TrailingData))
            ),
            "strict decode rejects a byte trailing the whole EncryptedPrivateKeyInfo",
        );

        let _ = result;
    }

    /// Positive-construction companion, on a concrete minimal specimen (the module's own documented
    /// 9-octet floor plus a two-octet ciphertext payload, hand-verified below). Machine-checks the
    /// specific accepted shape and its decoded fields, complementing the fully-symbolic harnesses
    /// above.
    ///
    /// `30 09`                       SEQUENCE, len 9
    ///    `30 03 06 01 00`           AlgorithmIdentifier { OID content = 00 (arc {0, 0}) }
    ///    `04 02 aa bb`              OCTET STRING encryptedData = { aa bb }
    #[kani::proof]
    #[kani::unwind(20)]
    fn parse_ok_path_witnessed() {
        #[rustfmt::skip]
        const MINIMAL_EPKI: [u8; 11] = [
            0x30, 0x09,
                0x30, 0x03, 0x06, 0x01, 0x00,
                0x04, 0x02, 0xaa, 0xbb,
        ];

        let result = parse_encrypted_private_key_info(&MINIMAL_EPKI);
        kani::cover(
            result.is_ok(),
            "parse_encrypted_private_key_info reaches its Ok tail on the concrete minimal specimen",
        );
        if let Ok((info, used)) = result {
            assert!(used == 11);
            assert!(info.encryption_algorithm.algorithm_oid == [0x00]);
            assert!(info.encrypted_data == [0xaa, 0xbb]);
        }
    }
}

// ---------------------------------------------------------------------------
// Concrete tests, incl. seeded-bad specimens.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    /// A minimal well-formed `EncryptedPrivateKeyInfo`: a one-field AlgorithmIdentifier (arbitrary
    /// single-octet OID content, arc {0, 0}) and a two-octet `encryptedData` OCTET STRING (the
    /// absolute floor is 9 octets, with an empty `04 00` encryptedData). Same specimen as the module
    /// doc's own example and the Kani `parse_ok_path_witnessed` harness.
    ///
    /// `30 09`                       SEQUENCE, len 9
    ///    `30 03 06 01 00`           AlgorithmIdentifier { OID content = 00 (arc {0, 0}) }
    ///    `04 02 aa bb`              OCTET STRING encryptedData = { aa bb }
    #[rustfmt::skip]
    const MINIMAL_EPKI: [u8; 11] = [
        0x30, 0x09,
            0x30, 0x03, 0x06, 0x01, 0x00,
            0x04, 0x02, 0xaa, 0xbb,
    ];

    /// A real openssl-generated `EncryptedPrivateKeyInfo` (RFC 5958 §3): an Ed25519 `PrivateKeyInfo`
    /// encrypted with PBES2/PBKDF2/AES-128-CBC (`v2prf hmacWithSHA256`), hand-verified octet-by-octet
    /// against the tool's own ASN.1 dump before trusting it.
    ///
    /// `30 81 a3`                                     SEQUENCE, len 163 (long form, 1 length octet)
    ///    `30 5f`                                      AlgorithmIdentifier SEQUENCE, len 95
    ///       `06 09 2a 86 48 86 f7 0d 01 05 0d`         OID 1.2.840.113549.1.5.13 (PBES2)
    ///       `30 52`                                    PBES2-params SEQUENCE, len 82 (left opaque
    ///                                                   by this module -- see the module docs)
    ///    `04 40 <64 octets>`                            OCTET STRING encryptedData, len 64
    #[rustfmt::skip]
    const REAL_EPKI: [u8; 166] = [
        0x30, 0x81, 0xa3, 0x30, 0x5f, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7,
        0x0d, 0x01, 0x05, 0x0d, 0x30, 0x52, 0x30, 0x31, 0x06, 0x09, 0x2a, 0x86,
        0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0c, 0x30, 0x24, 0x04, 0x10, 0xb9,
        0x79, 0xf5, 0x98, 0x70, 0xf0, 0x89, 0xab, 0x12, 0xd8, 0x73, 0x15, 0xd0,
        0xfe, 0x5a, 0xae, 0x02, 0x02, 0x08, 0x00, 0x30, 0x0c, 0x06, 0x08, 0x2a,
        0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x09, 0x05, 0x00, 0x30, 0x1d, 0x06,
        0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x01, 0x02, 0x04, 0x10,
        0xb1, 0x27, 0x56, 0xa6, 0xa0, 0x46, 0x8f, 0x08, 0x3c, 0xcd, 0x57, 0xd3,
        0x85, 0x69, 0x3c, 0xc5, 0x04, 0x40, 0xeb, 0x25, 0x8c, 0xf3, 0xe2, 0xd7,
        0x68, 0x23, 0x27, 0x5b, 0x07, 0xed, 0x67, 0x2a, 0x06, 0x48, 0x87, 0x31,
        0x79, 0xfd, 0x94, 0x6a, 0x16, 0x7b, 0x91, 0x29, 0xeb, 0x79, 0x0a, 0x6c,
        0xf1, 0x29, 0x15, 0x45, 0x59, 0xae, 0x38, 0x7e, 0xc1, 0x10, 0x86, 0x89,
        0xd9, 0x59, 0xba, 0xe0, 0x44, 0x42, 0x69, 0x7b, 0x6f, 0xa5, 0x4b, 0x83,
        0x1e, 0x76, 0x93, 0x40, 0x9a, 0x13, 0xe1, 0x17, 0xd3, 0xc5,
    ];

    #[test]
    fn parses_minimal_specimen() {
        let (info_c, used) = parse_encrypted_private_key_info(&MINIMAL_EPKI).unwrap();
        assert_eq!(used, 11);
        assert_eq!(info_c.encryption_algorithm.algorithm_oid, &[0x00]);
        assert_eq!(info_c.encrypted_data, &[0xaa, 0xbb]);

        let info_s = parse_encrypted_private_key_info_strict(&MINIMAL_EPKI).unwrap();
        assert_eq!(info_s, info_c);
    }

    #[test]
    fn parses_real_openssl_specimen() {
        let (info_c, used) = parse_encrypted_private_key_info(&REAL_EPKI).unwrap();
        assert_eq!(used, 166);
        assert_eq!(
            info_c.encryption_algorithm.algorithm_oid,
            &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x05, 0x0d] // 1.2.840.113549.1.5.13 (PBES2)
        );
        assert_eq!(info_c.encrypted_data.len(), 64);

        let info_s = parse_encrypted_private_key_info_strict(&REAL_EPKI).unwrap();
        assert_eq!(info_s, info_c);
    }

    #[test]
    fn composable_ignores_trailing_bytes() {
        let mut bytes = MINIMAL_EPKI.to_vec();
        bytes.push(0xFF);
        let (info, used) = parse_encrypted_private_key_info(&bytes).unwrap();
        assert_eq!(used, 11);
        assert_eq!(info.encrypted_data, &[0xaa, 0xbb]);
    }

    // --- seeded-bad specimens: each MUST be rejected ---

    #[test]
    fn strict_rejects_trailing_byte_after_epki() {
        let mut bytes = MINIMAL_EPKI.to_vec();
        bytes.push(0xFF);
        assert_eq!(
            parse_encrypted_private_key_info_strict(&bytes),
            Err(EncryptedPrivateKeyInfoError::BadOuterSeq(SequenceError::TrailingData))
        );
    }

    #[test]
    fn rejects_non_sequence_outer_tag() {
        // Replace the outer SEQUENCE tag (0x30) with SET (0x31).
        let mut bytes = MINIMAL_EPKI;
        bytes[0] = 0x31;
        assert_eq!(
            parse_encrypted_private_key_info(&bytes),
            Err(EncryptedPrivateKeyInfoError::BadOuterSeq(SequenceError::WrongTag))
        );
    }

    #[test]
    fn rejects_encryption_algorithm_not_a_sequence() {
        // The encryptionAlgorithm field's identifier is SET (0x31) instead of SEQUENCE (0x30).
        let mut bytes = MINIMAL_EPKI;
        bytes[2] = 0x31;
        assert_eq!(
            parse_encrypted_private_key_info(&bytes),
            Err(EncryptedPrivateKeyInfoError::EncryptionAlgorithm(AlgIdError::BadSeq(
                SequenceError::WrongTag
            )))
        );
    }

    #[test]
    fn rejects_missing_encryption_algorithm() {
        // An outer SEQUENCE with empty content: the mandatory encryptionAlgorithm field is absent.
        // Classified distinctly from a present-but-malformed AlgorithmIdentifier.
        let bytes = [0x30, 0x00];
        assert_eq!(
            parse_encrypted_private_key_info(&bytes),
            Err(EncryptedPrivateKeyInfoError::MissingEncryptionAlgorithm)
        );
    }

    #[test]
    fn rejects_missing_encrypted_data() {
        // A well-formed encryptionAlgorithm exactly tiles the outer content, leaving nothing for the
        // mandatory encryptedData field: absent, not malformed.
        let bytes = [
            0x30, 0x05,
                0x30, 0x03, 0x06, 0x01, 0x00,
        ];
        assert_eq!(
            parse_encrypted_private_key_info(&bytes),
            Err(EncryptedPrivateKeyInfoError::MissingEncryptedData)
        );
    }

    #[test]
    fn rejects_encrypted_data_wrong_tag() {
        // encryptedData's identifier is BOOLEAN (0x01) instead of OCTET STRING (0x04).
        let mut bytes = MINIMAL_EPKI;
        bytes[7] = 0x01;
        assert_eq!(
            parse_encrypted_private_key_info(&bytes),
            Err(EncryptedPrivateKeyInfoError::EncryptedData(OctetStringError::WrongTag))
        );
    }

    #[test]
    fn rejects_trailing_byte_after_encrypted_data() {
        // encryptionAlgorithm + encryptedData are both complete and well-formed, but one extra byte
        // remains inside the outer SEQUENCE's content. Outer content grows from 9 (0x09) to
        // 9 + 1 = 10 (0x0a).
        let bytes = [
            0x30, 0x0a,
                0x30, 0x03, 0x06, 0x01, 0x00,
                0x04, 0x02, 0xaa, 0xbb,
                0xFF,
        ];
        assert_eq!(
            parse_encrypted_private_key_info(&bytes),
            Err(EncryptedPrivateKeyInfoError::TrailingElements)
        );
    }
}
