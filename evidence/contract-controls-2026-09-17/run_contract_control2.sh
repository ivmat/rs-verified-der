#!/bin/bash
# Contract + observed-red control run for one module, with an OPTIONAL second mutation
# (used for pkcs8, ecdsa_sig_value, rsa_public_key: tiling control1 + a review-added-conjunct
# control2 -- classification for pkcs8, INTEGER minimality for ecdsa/rsa).
#
# args: SRC FAITH NP OLD NEW COPY OUT [OLD2 NEW2]
set -u
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.." || exit 2   # crate checkout root
SRC="$1"; FAITH="$2"; NP="$3"; OLD="$4"; NEW="$5"; COPY="$6"; OUT="$7"; OLD2="${8:-}"; NEW2="${9:-}"
mkdir -p "$OUT"; rm -f "$OUT/.done"
mutate() { # file old new  -> assert exactly one replacement
  python3 - "$1" "$2" "$3" <<'PY'
import sys
p,old,new=sys.argv[1],sys.argv[2],sys.argv[3]
s=open(p).read(); c=s.count(old)
assert c==1, f"FATAL expected exactly 1 occurrence of {old!r}, found {c}"
open(p,'w').write(s.replace(old,new,1)); print(f"mutated: {old!r} -> {new!r}")
PY
}
cp "$COPY" "$SRC"
cargo kani --harness "$FAITH" > "$OUT/baseline-faithful.log" 2>&1
# control 1 (tiling)
mutate "$SRC" "$OLD" "$NEW" > "$OUT/mutation-1.txt" 2>&1
cargo kani --harness "$FAITH" > "$OUT/control1-faithful-red.log" 2>&1
cargo kani --harness "$NP"    > "$OUT/control1-neverpanics-green.log" 2>&1
cp "$COPY" "$SRC"
# control 2 (added-conjunct) if provided
if [ -n "$OLD2" ]; then
  mutate "$SRC" "$OLD2" "$NEW2" > "$OUT/mutation-2.txt" 2>&1
  cargo kani --harness "$FAITH" > "$OUT/control2-faithful-red.log" 2>&1
  cp "$COPY" "$SRC"
fi
{
  echo "=== $SRC ($(date -u +%FT%TZ)) ==="
  echo "baseline_faithful:     $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/baseline-faithful.log"|tail -1)   [want SUCCESSFUL]"
  echo "control1 (tiling):     $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/control1-faithful-red.log"|tail -1)   [want FAILED]"
  echo "  mutation1:           $(cat "$OUT/mutation-1.txt")"
  echo "  failed_check1:       $(grep -E 'Status: FAILURE' -A1 "$OUT/control1-faithful-red.log" 2>/dev/null|grep Description|head -1)"
  echo "control1 neverpanics:  $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/control1-neverpanics-green.log"|tail -1)   [want SUCCESSFUL]"
  if [ -n "$OLD2" ]; then
    echo "control2 (conjunct):   $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/control2-faithful-red.log"|tail -1)   [want FAILED]"
    echo "  mutation2:           $(cat "$OUT/mutation-2.txt")"
    echo "  failed_check2:       $(grep -E 'Status: FAILURE' -A1 "$OUT/control2-faithful-red.log" 2>/dev/null|grep Description|head -1)"
  fi
} | tee "$OUT/SUMMARY.txt"
touch "$OUT/.done"
