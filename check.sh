#!/usr/bin/env sh
# der-verified verification gate (re-runnable; the L3 proof floor).
# Captures the proofs and hygiene checks as a re-runnable check, never a one-off.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "== hygiene gate (doc links; pure stdlib) =="
python3 "$ROOT/gates/check_links.py"
echo "== content-leak gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_check_content_leaks.py"
echo "== content-leak gate (credentials / absolute paths / private vocabulary in tracked files; pure stdlib) =="
# Also present in check_fast.sh (runs on every commit); repeated here so the release path's own
# record is complete without leaning on the fast layer having run.
python3 "$ROOT/gates/check_content_leaks.py"
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
echo "== acceptance-manifest gate (acceptance.toml vs the PINNED vendored validator; pure stdlib) =="
# Also present in check_fast.sh (runs on every commit); repeated here so the release path's own
# record is complete. The root acceptance.toml is this crate's machine-readable certificate and is
# GENERATED — this re-validates it with the validator vendored in gates/vendor/ (verifying that
# validator's own bytes against their recorded hashes first), and checks the projected evidence
# store in BOTH directions: every cited record resolves inside the store, and no projection sits
# there uncited.
python3 "$ROOT/gates/check_acceptance_manifest.py"
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
echo "== lean-lid skip-guard gate: self-test (the gate's own gate; pure stdlib) =="
# Runs BEFORE the lean stage it guards. lean/check_lean.sh is GUARDED: with no Aeneas/Lean
# toolchain it skips and exits 0, and until 2026-08-25 this script then printed an unqualified
# `check.sh: PASS` -- so a green gate did not witness that L4 ran at all. This self-test exercises
# the SKIP and FAIL directions of that guard (the PASS direction is witnessed by the real run
# below, which now prints its own status token).
python3 "$ROOT/gates/test_check_lean_skip.py"
echo "== lean lid :: der-verified length/big_integer/oid codecs (L4, unbounded; guarded) =="
# Capture the lean stage's OWN verdict rather than inferring it from an exit code that cannot
# distinguish PASS from SKIP. Not piped: `sh` here has no `pipefail`, so a pipe would hand us tee's
# exit status and silently swallow a lean-stage failure -- the script writes the token to a file
# instead, which keeps live progress output AND lets `set -e` propagate a real failure.
LID_STATUS_FILE="$(mktemp)"
DER_LID_STATUS_FILE="$LID_STATUS_FILE"
export DER_LID_STATUS_FILE
sh "$ROOT/lean/check_lean.sh"
LID_STATUS="$(cat "$LID_STATUS_FILE" 2>/dev/null || echo UNKNOWN)"
rm -f "$LID_STATUS_FILE"
[ -n "$LID_STATUS" ] || LID_STATUS=UNKNOWN
echo "== lid-staleness gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_check_lid_staleness.py"
echo "== lid-staleness gate --strict (after the Lean gate, which just refreshed the state on green) =="
python3 "$ROOT/gates/check_lid_staleness.py" --strict
# The summary line NAMES the L4 state instead of hiding it behind a bare PASS. `L4 lean lid: PASS`
# is the only spelling that witnesses the unbounded Lean proofs; anything else means the L3 Kani
# floor is all this run establishes, and no CONTRACT+L4 claim may cite it.
if [ "$LID_STATUS" = "PASS" ]; then
  echo "== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: PASS) =="
else
  echo "== !! L4 NOT WITNESSED BY THIS RUN !! ================================================="
  echo "   The Lean lid reported: $LID_STATUS (not PASS)."
  echo "   This run establishes the L3 Kani floor ONLY. Every CONTRACT+L4 row in the docs is"
  echo "   UNSUPPORTED by this run -- do not cite it as an L4 witness, and do not mint a publish"
  echo "   receipt from it. Re-run with the Aeneas/Lean toolchain installed, and set"
  echo "   DER_REQUIRE_LEAN=1 to make an absent toolchain a hard failure rather than a skip."
  echo "   ======================================================================================"
  echo "== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: $LID_STATUS -- NOT WITNESSED) =="
fi
