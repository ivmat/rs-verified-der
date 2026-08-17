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
echo "== doctest-count gate: self-test (the gate's own gate; pure stdlib except its own two real-cargo tests) =="
python3 "$ROOT/gates/test_check_doctest_count.py"
echo "== doctest-count gate (gen_proof_manifest.py's static scan vs cargo's own count — structural backstop against any doc-attribute shape the static regexes don't recognise) =="
# Also present in check_fast.sh (runs on every commit); repeated here so the release path's own
# guarantee — a fresh full check.sh run at final HEAD before publish — independently covers it.
python3 "$ROOT/gates/check_doctest_count.py"
echo "== tier-parity gate (+ its self-test): the LIGHT/HEAVY split is data, so gate it =="
python3 "$ROOT/gates/check_tier_parity.py" --selftest
python3 "$ROOT/gates/check_tier_parity.py"

echo "== cargo kani :: der-verified (L3 proof floor) =="
# -Z stubbing: several never-panics harnesses are MODULAR proofs — the x509 certificate chain
# (x509_name stubs validate_rdn; x509_tbs_certificate stubs validate_name/validate_extensions;
# x509_certificate stubs parse_tbs_certificate) and rsa_private_key (stubs validate_other_prime_infos /
# validate_other_prime_info). PROOF_MANIFEST.md §8.4 has the authoritative, generated list. Each
# stubbed sub-parser is independently proven panic-free at its own harness (over symbolic input
# length), so CBMC can verify the composition glue tractably (see those modules' Kani comments). The
# flag only enables the feature; harnesses without #[kani::stub] are unaffected.
cargo kani -Z stubbing --manifest-path "$ROOT/der-verified/Cargo.toml"
echo "== lean lid :: der-verified length/big_integer/oid codecs (L4, unbounded; guarded) =="
sh "$ROOT/lean/check_lean.sh"
echo "== lid-staleness gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_check_lid_staleness.py"
echo "== lid-staleness gate --strict (after the Lean gate, which just refreshed the state on green) =="
python3 "$ROOT/gates/check_lid_staleness.py" --strict
echo "== check.sh: PASS =="
