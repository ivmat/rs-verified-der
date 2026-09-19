#!/bin/bash
# pkcs8 [0]-attributes classification observed-red control (clean re-run; strings in-file,
# no shell escaping). This is control2 for pkcs8's `parse_faithful` contract: the review-added
# conjunct beyond exact tiling (control1, run_contract_control2.sh).
#
# args: COPY OUT   (COPY = pristine der-verified/src/pkcs8.rs; OUT = output directory)
set -u
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")/../.." || exit 2   # crate checkout root
SRC=der-verified/src/pkcs8.rs
COPY="${1:?usage: pkcs8_control2_classify.sh COPY OUT}"
OUT="${2:?usage: pkcs8_control2_classify.sh COPY OUT}"
mkdir -p "$OUT"
cp "$COPY" "$SRC"
python3 - "$SRC" > "$OUT/mutation-2.txt" 2>&1 <<'PY'
import sys
p=sys.argv[1]
old='if tag.class != Class::ContextSpecific || tag.number != 0 {'
new='if tag.class != Class::ContextSpecific || false {'
s=open(p).read(); c=s.count(old)
assert c==1, f"FATAL expected 1 occurrence, found {c}"
open(p,'w').write(s.replace(old,new,1)); print(f"mutated (classification): {old!r} -> {new!r}")
PY
cargo kani --harness pkcs8::proofs::parse_faithful > "$OUT/control2-faithful-red.log" 2>&1
cp "$COPY" "$SRC"
{
  echo "=== pkcs8 control2 (classification, clean re-run $(date -u +%FT%TZ)) ==="
  echo "mutation2:      $(cat "$OUT/mutation-2.txt")"
  echo "control2:       $(grep -E 'VERIFICATION:- (SUCCESSFUL|FAILED)' "$OUT/control2-faithful-red.log"|tail -1)   [want FAILED]"
  echo "failed_check2:  $(grep -E 'Status: FAILURE' -A1 "$OUT/control2-faithful-red.log" 2>/dev/null|grep Description|head -1)"
} | tee "$OUT/SUMMARY-control2.txt"
touch "$OUT/.control2-done"
