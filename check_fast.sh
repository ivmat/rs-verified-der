#!/usr/bin/env sh
# der-verified FAST verification layer — the subset cheap enough to run on EVERY commit
# (~sub-second incremental): the stdlib hygiene gates + cargo test.
#
# The SLOW proof floor — `cargo kani` (the L3 proof) + the Lean lid — deliberately stays in check.sh:
# run it at milestones / before a release, NOT per commit. Minutes-long formal proofs in a blocking hook
# would breed `git commit --no-verify`. check.sh remains the full gate; this is its fast front.
#
# One SLOW-gate blind spot IS covered here: the Lean lid's six Aeneas-extracted sources
# (lean/lid-source-state.txt) can drift on ANY edit, including docs-only, without the full Lean
# gate running to notice — gates/check_lid_staleness.py is the cheap per-commit tripwire for that.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "== hygiene gate (doc links; pure stdlib) =="
python3 "$ROOT/gates/check_links.py"
echo "== content-leak gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_check_content_leaks.py"
echo "== content-leak gate (credentials / absolute paths / private vocabulary in tracked files; pure stdlib) =="
python3 "$ROOT/gates/check_content_leaks.py"
echo "== proof-manifest gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_gen_proof_manifest.py"
echo "== proof-manifest gate (PROOF_MANIFEST.md vs source; pure stdlib) =="
python3 "$ROOT/gates/gen_proof_manifest.py" --check
echo "== verification-map gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_gen_verification_map.py"
echo "== verification-map gate (README.md's mermaid map vs source; pure stdlib) =="
python3 "$ROOT/gates/gen_verification_map.py" --check
echo "== lid-staleness gate: self-test (the gate's own gate; pure stdlib) =="
python3 "$ROOT/gates/test_check_lid_staleness.py"
echo "== lid-staleness gate (Lean-lid source drift since the last green Lean run; pure stdlib, fast) =="
python3 "$ROOT/gates/check_lid_staleness.py"
echo "== cargo test (workspace) =="
cargo test --manifest-path "$ROOT/Cargo.toml"
echo "== doctest-count gate: self-test (the gate's own gate; pure stdlib except its own two real-cargo tests) =="
python3 "$ROOT/gates/test_check_doctest_count.py"
echo "== doctest-count gate (gen_proof_manifest.py's static scan vs cargo's own count — structural backstop against any doc-attribute shape the static regexes don't recognise; ~0.1-0.4s, warm right after the cargo test step above) =="
python3 "$ROOT/gates/check_doctest_count.py"
echo "== clippy (workspace; -D warnings — MATCHES the CI 'test + clippy' job) =="
# Cheap and per-commit-worthy: without this, a clippy-only lint (e.g. a doc bullet
# continuation) passes local test but fails CI, which this gate exists to prevent.
cargo clippy --manifest-path "$ROOT/Cargo.toml" --all-targets -- -D warnings
echo "== check_fast.sh: PASS (Kani + Lean NOT run here — run check.sh at milestones) =="
