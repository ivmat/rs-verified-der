//! Standalone extraction target for Charon/Aeneas (the L5 Lean lid on `sequence`).
//!
//! Re-exposes `der-verified`'s SEQUENCE/SET child-walk reader (X.690 §8.9/§8.10's iteration over
//! an unbounded number of children — the crate's first UNBOUNDED-loop consumer, unlike `tlv`'s
//! own loop-free `decode_tlv`) as a crate that Charon can drive with its OWN pinned nightly,
//! WITHOUT importing der-verified (whose `rust-toolchain.toml` pins `stable` and whose Kani
//! harnesses must stay untouched). We `#[path]`-include the *same* four source files — single
//! source of truth, so the Lean lid provably concerns the exact bytes the Kani floor proves.
//!
//! `sequence.rs` composes `crate::tag::{Class, Tag}` and `crate::tlv::{decode_tlv, encode_tlv_into,
//! Tlv, TlvError}` (which itself composes `crate::length`), so all three dependency modules are
//! re-exposed here as sibling modules at the crate root — mirroring der-verified's own module
//! layout exactly, so the `crate::tag`/`crate::length`/`crate::tlv` paths inside sequence.rs
//! resolve unchanged.
//!
//! The `#[cfg(kani)]` and `#[cfg(test)]` modules in all four files are inactive here (no
//! `--cfg kani`, no `--test`), so Charon sees only the codecs themselves.
#[path = "../../../der-verified/src/tag.rs"]
pub mod tag;
#[path = "../../../der-verified/src/length.rs"]
pub mod length;
#[path = "../../../der-verified/src/tlv.rs"]
pub mod tlv;
#[path = "../../../der-verified/src/sequence.rs"]
pub mod sequence;
