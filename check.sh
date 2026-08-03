#!/usr/bin/env sh
# der-verified verification gate (re-runnable; the L3 proof floor).
# Captures the proofs and hygiene checks as a re-runnable check, never a one-off.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "== hygiene gate (doc links; pure stdlib) =="
python3 "$ROOT/gates/check_links.py"
echo "== proof-manifest gate: self-test (the gate's own gate; pure stdlib) =="
# Runs BEFORE the gate it tests. Both directions are covered: the gate must not fail an honest
# third party whose toolchain differs from ours, and must still fail on a drifted count or pin.
python3 "$ROOT/gates/test_gen_proof_manifest.py"
echo "== proof-manifest gate (PROOF_MANIFEST.md vs source; pure stdlib) =="
# The manifest is the crate's honest proof envelope, and its numbers are DERIVED, never typed:
# this fails closed if a harness, bound, stub, cover or `pub fn` changed without the manifest
# following, or if a count-claim in README/docs drifted. Regenerate with
# `python3 gates/gen_proof_manifest.py --write`.
python3 "$ROOT/gates/gen_proof_manifest.py" --check
echo "== verification-map gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_gen_verification_map.py"
echo "== verification-map gate (README.md's mermaid map vs source; pure stdlib) =="
# The map's green/blue are DERIVED (the Lean lid set + gates/tiers.txt) and its yellow/red/gray are
# DECLARED human judgements (gates/map_declared.txt); this fails closed if either drifts from what's
# committed in README.md. Regenerate with `python3 gates/gen_verification_map.py --write`.
python3 "$ROOT/gates/gen_verification_map.py" --check
echo "== cargo test (workspace) =="
cargo test --manifest-path "$ROOT/Cargo.toml"
echo "== tier-parity gate (+ its self-test): the LIGHT/HEAVY split is data, so gate it =="
python3 "$ROOT/gates/check_tier_parity.py" --selftest
python3 "$ROOT/gates/check_tier_parity.py"

echo "== cargo kani :: der-verified (L3 proof floor) =="
# -Z stubbing: three never-panics harnesses are MODULAR proofs — x509_name (stubs validate_rdn),
# x509_tbs_certificate (stubs validate_name, validate_extensions), and x509_certificate (stubs
# parse_tbs_certificate). Each stubbed sub-parser is independently proven panic-free at its own
# harness (over symbolic input length), so CBMC can verify the composition glue tractably (see those
# modules' Kani comments and PROOF_MANIFEST.md). The flag only enables the feature; harnesses without
# #[kani::stub] are unaffected.
cargo kani -Z stubbing --manifest-path "$ROOT/der-verified/Cargo.toml"
echo "== lean lid :: der-verified length/big_integer/oid codecs (L4, unbounded; guarded) =="
sh "$ROOT/lean/check_lean.sh"
echo "== check.sh: PASS =="
