//! Standalone extraction target for Charon/Aeneas (the L4 Lean lid).
//!
//! Re-exposes `der-verified`'s length codec (X.690 §8.1.3) as a crate that
//! Charon can drive with its OWN pinned nightly, WITHOUT importing der-verified
//! (whose `rust-toolchain.toml` pins `stable` and whose Kani harnesses must stay
//! untouched). We `#[path]`-include the *same* source file — single source of
//! truth, so the Lean lid provably concerns the exact bytes the Kani floor proves.
//!
//! The `#[cfg(kani)]` and `#[cfg(test)]` modules in `length.rs` are inactive here
//! (no `--cfg kani`, no `--test`), so Charon sees only the codec itself.
#[path = "../../../der-verified/src/length.rs"]
pub mod length;
