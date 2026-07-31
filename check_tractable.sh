#!/usr/bin/env sh
# der-verified's TRACTABLE proof floor -- the share of the Kani gate that runs on an ordinary
# machine (~7 GB), rather than the >=24 GB the full ./check.sh floor needs.
#
# Why this exists: the re-runnable evidence IS the product of this crate, and a 24 GB requirement
# is an adoption barrier. A third party who cannot reproduce the floor has to take the numbers on
# trust, which is exactly what this crate is built to avoid. This script reproduces the same set
# GitHub CI verifies -- the LIGHT tier -- so "I ran the proofs myself" is available to anyone.
#
# What it does NOT do, stated plainly: it skips the HEAVY tier (see gates/tiers.txt), so a green
# result here is NOT the full floor. It is the CI-sized share. The heavy modules are verified by
# ./check.sh on a large-memory box, and the split itself is gated by gates/check_tier_parity.py.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"

echo "== tier parity gate (the split is data, so gate it) =="
python3 "$ROOT/gates/check_tier_parity.py" --selftest
python3 "$ROOT/gates/check_tier_parity.py"

# Build --harness filters from the single source of truth. Module names are matched as a
# fully-qualified-name PREFIX (`<module>::`), the same selector CI uses.
FILTERS=""
while read -r tier mod; do
    [ "$tier" = "LIGHT" ] || continue
    FILTERS="$FILTERS --harness ${mod}::"
done <<EOT
$(grep '^LIGHT ' "$ROOT/gates/tiers.txt")
EOT

echo "== cargo kani :: der-verified (LIGHT tier only) =="
echo "   filters:$FILTERS"
# -Z stubbing for the same reason as check.sh: three never-panics harnesses are modular proofs.
# shellcheck disable=SC2086
cargo kani -Z stubbing --manifest-path "$ROOT/der-verified/Cargo.toml" $FILTERS

# What you will see, so it is not a surprise: this tier reports ONE harness with
# `0 of 1 cover properties satisfied`. That is expected and disclosed -- PROOF_MANIFEST.md §8.2
# lists three such harnesses crate-wide, of which one is LIGHT and two are HEAVY. Kani reports an
# unsatisfiable cover as SUCCESSFUL, so this does NOT fail the run and is not meant to; §8.2 is
# where the crate accounts for it. If you see MORE than one here, that is a real finding.
echo "== check_tractable.sh: PASS (LIGHT tier only -- the HEAVY tier was NOT run; see gates/tiers.txt) =="
echo "   note: 1 disclosed unsatisfied cover is expected in this tier (PROOF_MANIFEST.md 8.2); more would be new."
