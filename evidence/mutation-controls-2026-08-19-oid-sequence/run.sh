#!/usr/bin/env bash
# DER-MUT-2026-08-19 — oid + sequence mutation controls, run ON THE VM as root.
#
# Mirrors the F1 campaign's protocol (rs-verified-der evidence/MUTATION-CONTROLS-2026-08-18.md):
# per module, plant one subtly-wrong implementation (a real defect class, not a no-op), run the
# harness(es) whose documented job is to catch that class, observe VERIFICATION:- FAILED, revert,
# confirm the source file is byte-identical to its pre-mutation sha256, and re-run to confirm
# VERIFICATION:- SUCCESSFUL again.
#
# PREDICTIONS are written into verdicts.tsv BEFORE the run reads any log (the prediction is
# recorded separately from the measurement, which is the whole point of a control).
set -uo pipefail
export HOME=/root
export PATH="/root/.cargo/bin:$PATH"

DER=/root/der
OUT=/var/dermut
LOG=$OUT/logs
mkdir -p "$LOG"
exec > >(tee -a "$LOG/driver.log") 2>&1
echo "[dermut] run begin $(date -u)"

cd "$DER" || { echo "[dermut] FATAL no $DER"; exit 1; }
git rev-parse HEAD | tee "$OUT/der-sha.txt"
cargo kani --version | tee "$OUT/kani-version.txt"
cbmc --version | tee "$OUT/cbmc-version.txt"

OID=der-verified/src/oid.rs
SEQ=der-verified/src/sequence.rs
OID_SHA="$(sha256sum $OID | awk '{print $1}')"
SEQ_SHA="$(sha256sum $SEQ | awk '{print $1}')"
echo "baseline sha256 oid.rs      $OID_SHA" | tee "$OUT/baseline-sha256.txt"
echo "baseline sha256 sequence.rs $SEQ_SHA" | tee -a "$OUT/baseline-sha256.txt"

VERDICTS="$OUT/verdicts.tsv"
printf 'run_id\tmutation\tharness\tpredicted\tobserved\tlog\n' > "$VERDICTS"

# run <run_id> <mutation-label> <harness-fq> <predicted RED|GREEN>
run() {
  rid="$1"; mut="$2"; h="$3"; pred="$4"
  f="$LOG/$rid.log"
  echo "== [$rid] mutation=$mut harness=$h predicted=$pred =="
  ( cd "$DER" && /usr/bin/time -v cargo kani --manifest-path der-verified/Cargo.toml \
        --harness "$h" --exact -Z stubbing ) > "$f" 2>&1
  rc=$?
  if grep -q 'VERIFICATION:- SUCCESSFUL' "$f"; then obs=GREEN
  elif grep -q 'VERIFICATION:- FAILED' "$f"; then obs=RED
  else obs="NO-VERDICT(rc=$rc)"; fi
  printf '%s\t%s\t%s\t%s\t%s\t%s\n' "$rid" "$mut" "$h" "$pred" "$obs" "logs/$rid.log" >> "$VERDICTS"
  echo "== [$rid] observed=$obs (predicted=$pred) =="
}

# mutate <file> <python-heredoc-marker...> — exact-string replacement, fails loudly if absent.
mutate() {
  python3 - "$1" "$2" "$3" <<'PY'
import sys
path, old, new = sys.argv[1], sys.argv[2], sys.argv[3]
s = open(path).read()
if s.count(old) != 1:
    print("!! mutation anchor not unique/absent in %s (count=%d)" % (path, s.count(old)))
    sys.exit(1)
open(path, "w").write(s.replace(old, new, 1))
print("mutation applied to %s" % path)
PY
}

revert() { # revert <file> <expected-sha>
  ( cd "$DER" && git checkout -- "$1" )
  got="$(sha256sum "$DER/$1" | awk '{print $1}')"
  if [ "$got" = "$2" ]; then
    echo "== revert $1: sha256 byte-identical to baseline ($got) =="
  else
    echo "!! revert $1: SHA MISMATCH got=$got want=$2" ; exit 1
  fi
}

# ---------------------------------------------------------------------------------------------
# 0. Baselines (unmutated GREEN)
# ---------------------------------------------------------------------------------------------
run 00-base-oid-leading   none "oid::proofs::leading_0x80_is_non_minimal"   GREEN
run 01-base-oid-later     none "oid::proofs::later_0x80_is_non_minimal"     GREEN
run 02-base-seq-tiling    none "sequence::proofs::ok_implies_exact_tiling"  GREEN
run 03-base-seq-roundtrip none "sequence::proofs::roundtrip_two_children"   GREEN

# ---------------------------------------------------------------------------------------------
# 1. OID-A — accept a non-minimal arc encoding (minimality check removed outright)
# ---------------------------------------------------------------------------------------------
OID_A_OLD='        if at_subid_start && b == 0x80 {
            return Err(OidError::NonMinimalSubid);
        }'
OID_A_NEW='        // if at_subid_start && b == 0x80 {
        //     return Err(OidError::NonMinimalSubid);
        // }'
mutate "$DER/$OID" "$OID_A_OLD" "$OID_A_NEW" || exit 1
( cd "$DER" && git diff -- "$OID" ) > "$LOG/oidA.diff"
run 04-oidA-leading OID-A "oid::proofs::leading_0x80_is_non_minimal" RED
run 05-oidA-later   OID-A "oid::proofs::later_0x80_is_non_minimal"   RED
revert "$OID" "$OID_SHA" || exit 1
run 06-oidA-reverted OID-A-reverted "oid::proofs::leading_0x80_is_non_minimal" GREEN

# ---------------------------------------------------------------------------------------------
# 2. OID-B — minimality checked at offset 0 only (a non-minimal LATER arc is accepted).
#    The subtler defect: the first-position harness cannot see it; the later-position one must.
# ---------------------------------------------------------------------------------------------
OID_B_OLD='        if at_subid_start && b == 0x80 {'
OID_B_NEW='        if at_subid_start && i == 0 && b == 0x80 {'
mutate "$DER/$OID" "$OID_B_OLD" "$OID_B_NEW" || exit 1
( cd "$DER" && git diff -- "$OID" ) > "$LOG/oidB.diff"
run 07-oidB-later   OID-B "oid::proofs::later_0x80_is_non_minimal"   RED
run 08-oidB-leading OID-B "oid::proofs::leading_0x80_is_non_minimal" GREEN
revert "$OID" "$OID_SHA" || exit 1
run 09-oidB-reverted OID-B-reverted "oid::proofs::later_0x80_is_non_minimal" GREEN

# ---------------------------------------------------------------------------------------------
# 3. SEQ-A — off-by-one the child count
# ---------------------------------------------------------------------------------------------
SEQ_A_OLD='    Ok(count)
}'
SEQ_A_NEW='    Ok(count + 1)
}'
mutate "$DER/$SEQ" "$SEQ_A_OLD" "$SEQ_A_NEW" || exit 1
( cd "$DER" && git diff -- "$SEQ" ) > "$LOG/seqA.diff"
run 10-seqA-tiling    SEQ-A "sequence::proofs::ok_implies_exact_tiling" RED
run 11-seqA-roundtrip SEQ-A "sequence::proofs::roundtrip_two_children"  RED
revert "$SEQ" "$SEQ_SHA" || exit 1
run 12-seqA-reverted SEQ-A-reverted "sequence::proofs::ok_implies_exact_tiling" GREEN

# ---------------------------------------------------------------------------------------------
# 4. SEQ-B — accept a malformed child (stop the walk instead of rejecting): a SEQUENCE whose
#    children do NOT tile the content is reported Ok. The DER rule is exact tiling.
# ---------------------------------------------------------------------------------------------
SEQ_B_OLD='            Err(e) => return Err(SequenceError::Element(e)),'
SEQ_B_NEW='            Err(_e) => break,'
mutate "$DER/$SEQ" "$SEQ_B_OLD" "$SEQ_B_NEW" || exit 1
( cd "$DER" && git diff -- "$SEQ" ) > "$LOG/seqB.diff"
run 13-seqB-tiling    SEQ-B "sequence::proofs::ok_implies_exact_tiling" RED
run 14-seqB-roundtrip SEQ-B "sequence::proofs::roundtrip_two_children"  GREEN
revert "$SEQ" "$SEQ_SHA" || exit 1
run 15-seqB-reverted SEQ-B-reverted "sequence::proofs::ok_implies_exact_tiling" GREEN

# ---------------------------------------------------------------------------------------------
# 5. Final tree state
# ---------------------------------------------------------------------------------------------
( cd "$DER" && git status --porcelain ) | tee "$OUT/final-git-status.txt"
( cd "$DER" && git diff --stat ) | tee "$OUT/final-git-diff-stat.txt"
sha256sum "$DER/$OID" "$DER/$SEQ" | tee "$OUT/final-sha256.txt"

echo "[dermut] run complete $(date -u)"
column -t -s $'\t' "$VERDICTS" || cat "$VERDICTS"
touch "$OUT/RUN_DONE"
