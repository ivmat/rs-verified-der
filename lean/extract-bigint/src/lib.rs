//! Standalone extraction target for Charon/Aeneas (the L4 Lean lid on `big_integer`).
//!
//! Re-exposes `der-verified`'s arbitrary-magnitude INTEGER codec (X.690 §8.3) as a
//! crate that Charon can drive with its OWN pinned nightly, WITHOUT importing
//! der-verified (whose `rust-toolchain.toml` pins `stable` and whose Kani harnesses
//! must stay untouched). We `#[path]`-include the *same* source file — single source
//! of truth, so the Lean lid provably concerns the exact bytes the Kani floor proves.
//!
//! The `#[cfg(kani)]` and `#[cfg(test)]` modules in `big_integer.rs` are inactive here
//! (no `--cfg kani`, no `--test`), so Charon sees only the codec itself.
#[path = "../../../der-verified/src/big_integer.rs"]
pub mod big_integer;
