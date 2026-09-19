#!/bin/bash
# Self-contained contract + observed-red control run for one composed module with a SINGLE
# mutation (used for ec_private_key, encrypted_private_key_info, and each module's control-1
# tiling leg). Committed as the campaign driver -- this script IS the mutation specification,
# never re-derived from prose.
#
# args: SRC FAITHFUL_HARNESS NEVERPANICS_HARNESS OLD_STR NEW_STR COPY OUTDIR
#   SRC       path (relative to the crate checkout root) to the module source file
#   FAITH     fully-qualified `*_parse_faithful` harness name
#   NP        fully-qualified `*_parse_never_panics` harness name
#   OLD/NEW   the exact-string mutation; the driver ABORTS unless OLD occurs exactly once
#   COPY      a pristine copy of SRC to restore from before/after mutation
#   OUT       output directory for this leg's logs + SUMMARY.txt
set -u
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.." || exit 2   # crate checkout root (two levels above evidence/<campaign>/)
SRC="$1"; FAITH="$2"; NP="$3"; OLD="$4"; NEW="$5"; COPY="$6"; OUT="$7"
mkdir -p "$OUT"
rm -f "$OUT/.done"
cp "$COPY" "$SRC"   # pristine campaign harness in place
# baseline (expect SUCCESSFUL)
cargo kani --harness "$FAITH" > "$OUT/baseline-faithful.log" 2>&1
# mutate exactly one occurrence
python3 - "$SRC" "$OLD" "$NEW" > "$OUT/mutation-info.txt" 2>&1 <<'PY'
import sys
p,old,new=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(p).read(); c=s.count(old)
assert c==1, f"FATAL expected exactly 1 occurrence of {old!r}, found {c}"
open(p,'w').write(s.replace(old,new,1))
print(f"mutated 1 occurrence: {old!r} -> {new!r}")
PY
# control legs: faithful (expect FAILED), never_panics (expect SUCCESSFUL)
cargo kani --harness "$FAITH" > "$OUT/control-faithful-red.log" 2>&1
cargo kani --harness "$NP"    > "$OUT/control-neverpanics-green.log" 2>&1
cp "$COPY" "$SRC"   # restore pristine
{
  echo "=== $SRC ($(date -u +%FT%TZ)) ==="
  echo "mutation:            $(cat "$OUT/mutation-info.txt")"
  echo "baseline_faithful:   $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/baseline-faithful.log" | tail -1)   [want SUCCESSFUL]"
  echo "control_faithful:    $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/control-faithful-red.log" | tail -1)   [want FAILED = observed red]"
  echo "control_neverpanics: $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/control-neverpanics-green.log" | tail -1)   [want SUCCESSFUL]"
  echo "failed_check:        $(grep -E 'Status: FAILURE' -A1 "$OUT/control-faithful-red.log" 2>/dev/null | grep Description | head -1)"
} | tee "$OUT/SUMMARY.txt"
touch "$OUT/.done"
