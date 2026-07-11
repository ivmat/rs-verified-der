//! Standalone extraction target for Charon/Aeneas (the L4 Lean lid on `oid`).
//!
//! Re-exposes `der-verified`'s OBJECT IDENTIFIER canonical-form validator (X.690 §8.19) as
//! a crate that Charon can drive with its OWN pinned nightly, WITHOUT importing der-verified
//! (whose `rust-toolchain.toml` pins `stable` and whose Kani harnesses must stay untouched).
//! We `#[path]`-include the *same* source file — single source of truth, so the Lean lid
//! provably concerns the exact bytes the Kani floor proves.
//!
//! The `#[cfg(kani)]` and `#[cfg(test)]` modules in `oid.rs` are inactive here (no `--cfg
//! kani`, no `--test`), so Charon sees only the validator itself.
#[path = "../../../der-verified/src/oid.rs"]
pub mod oid;
