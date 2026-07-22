//! Standalone extraction target for Charon/Aeneas (the L4 Lean lid on `tlv`).
//!
//! Re-exposes `der-verified`'s TLV (tag-length-value) reader (X.690's fundamental structural
//! unit) as a crate that Charon can drive with its OWN pinned nightly, WITHOUT importing
//! der-verified (whose `rust-toolchain.toml` pins `stable` and whose Kani harnesses must stay
//! untouched). We `#[path]`-include the *same* three source files — single source of truth, so
//! the Lean lid provably concerns the exact bytes the Kani floor proves.
//!
//! `tlv.rs` composes `crate::tag::{decode_tag, encode_tag, Tag, TagError}` and
//! `crate::length::{decode_length, encode_length, LengthError}`, so both dependency modules are
//! re-exposed here as sibling modules at the crate root — mirroring der-verified's own module
//! layout exactly, so the `crate::tag` / `crate::length` paths inside tlv.rs resolve unchanged.
//!
//! The `#[cfg(kani)]` and `#[cfg(test)]` modules in all three files are inactive here (no
//! `--cfg kani`, no `--test`), so Charon sees only the codecs themselves.
#[path = "../../../der-verified/src/tag.rs"]
pub mod tag;
#[path = "../../../der-verified/src/length.rs"]
pub mod length;
#[path = "../../../der-verified/src/tlv.rs"]
pub mod tlv;
