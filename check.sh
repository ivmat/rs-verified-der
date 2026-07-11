#!/usr/bin/env sh
# der-verified verification gate (re-runnable; the L3 proof floor).
# Captures the proofs and hygiene checks as a re-runnable check, never a one-off.
set -eu
ROOT="$(cd "$(dirname "$0")" && pwd)"
echo "== hygiene gates (doc links + provenance; pure stdlib) =="
python3 "$ROOT/gates/check_links.py"
python3 "$ROOT/gates/check_provenance.py"
echo "== cargo test (workspace) =="
cargo test --manifest-path "$ROOT/Cargo.toml"
echo "== cargo kani :: der-verified (L3 proof floor) =="
# -Z stubbing: x509_tbs_certificate's never-panics harness is a MODULAR proof — it stubs the two
# heaviest sub-parsers (validate_name, validate_extensions), each independently proven at its own
# harness, so CBMC can verify the TBS composition glue tractably (see that module's Kani comment).
# The flag only enables the feature; harnesses without #[kani::stub] are unaffected.
cargo kani -Z stubbing --manifest-path "$ROOT/der-verified/Cargo.toml"
echo "== lean lid :: der-verified length/big_integer/oid codecs (L4, unbounded; guarded) =="
sh "$ROOT/lean/check_lean.sh"
echo "== check.sh: PASS =="
