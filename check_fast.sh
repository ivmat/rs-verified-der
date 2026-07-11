#!/usr/bin/env sh
# der-verified FAST verification layer — the subset cheap enough to run on EVERY commit
# (~sub-second incremental): the stdlib hygiene gates + cargo test.
#
# The SLOW proof floor — `cargo kani` (the L3 proof) + the Lean lid — deliberately stays in check.sh:
# run it at milestones / before a release, NOT per commit. Minutes-long formal proofs in a blocking hook
# would breed `git commit --no-verify`. check.sh remains the full gate; this is its fast front.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "== hygiene gates (doc links + provenance; pure stdlib) =="
python3 "$ROOT/gates/check_links.py"
python3 "$ROOT/gates/check_provenance.py"
echo "== cargo test (workspace) =="
cargo test --manifest-path "$ROOT/Cargo.toml"
echo "== check_fast.sh: PASS (Kani + Lean NOT run here — run check.sh at milestones) =="
