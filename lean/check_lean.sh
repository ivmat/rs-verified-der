#!/usr/bin/env sh
# L4/L5 "Lean lid" gate — re-runnable (the L3 Kani floor's unbounded companion).
#
# Re-extracts the length + big_integer + oid + tlv + sequence codecs through
# Charon -> Aeneas and machine-checks the unbounded (any-length, and for `sequence`
# ALSO any-child-count) Lean proofs (LengthProofs.lean, BigIntProofs.lean,
# OidProofs.lean, TlvProofs.lean, SequenceProofs.lean).
#
# GUARDED: this no-ops (exit 0) when the Aeneas/Lean toolchain is not installed.
# The always-on gate is the L3 Kani floor in ../check.sh; this lid is additive.
# Install path + isolation contract: see ../README.md and ../DECISIONS.md (D7).
#
# Override the tools location with VERIFIED_RS_TOOLS (default ~/Downloads/verified_rs_tools).
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
TOOLS="${VERIFIED_RS_TOOLS:-$HOME/Downloads/verified_rs_tools}"
AENEAS="$TOOLS/aeneas"
CHARON_BIN="$AENEAS/charon/bin/charon"
AENEAS_BIN="$AENEAS/bin/aeneas"

if ! command -v lake >/dev/null 2>&1 || [ ! -x "$AENEAS_BIN" ] || [ ! -x "$CHARON_BIN" ]; then
  echo "== lean lid: SKIP (Aeneas/Lean toolchain absent; the L3 Kani floor is the gate) =="
  exit 0
fi

export PATH="$AENEAS/charon/bin:$AENEAS/bin:$PATH"

# 0) Guard against a cfg-split of the codec fns. The Kani floor compiles with
#    --cfg kani; extraction compiles without it. A `#[cfg(kani)]` / `#[cfg(not(kani))]`
#    pair of `decode_length`/`encode_length` would silently let the two lineages
#    prove *different* code, defeating "same source of truth" (review L4-lean-lid-02).
LEN_RS="$HERE/../der-verified/src/length.rs"
for fn in decode_length encode_length; do
  cnt="$(grep -cE "^pub fn ${fn}\b" "$LEN_RS" || true)"
  if [ "$cnt" != "1" ]; then
    echo "!! lean lid: FAIL - expected exactly one 'pub fn ${fn}' in length.rs (found ${cnt});" >&2
    echo "   a cfg-split would let the Kani floor and the Lean lid prove different code." >&2
    exit 1
  fi
done
BIGINT_RS="$HERE/../der-verified/src/big_integer.rs"
for fn in validate_integer_content is_negative encode_minimal_integer_into; do
  cnt="$(grep -cE "^pub fn ${fn}\b" "$BIGINT_RS" || true)"
  if [ "$cnt" != "1" ]; then
    echo "!! lean lid: FAIL - expected exactly one 'pub fn ${fn}' in big_integer.rs (found ${cnt});" >&2
    echo "   a cfg-split would let the Kani floor and the Lean lid prove different code." >&2
    exit 1
  fi
done
OID_RS="$HERE/../der-verified/src/oid.rs"
for fn in validate_oid; do
  cnt="$(grep -cE "^pub fn ${fn}\b" "$OID_RS" || true)"
  if [ "$cnt" != "1" ]; then
    echo "!! lean lid: FAIL - expected exactly one 'pub fn ${fn}' in oid.rs (found ${cnt});" >&2
    echo "   a cfg-split would let the Kani floor and the Lean lid prove different code." >&2
    exit 1
  fi
done
TLV_RS="$HERE/../der-verified/src/tlv.rs"
for fn in decode_tlv decode_tlv_strict encode_tlv_into; do
  cnt="$(grep -cE "^pub fn ${fn}\b" "$TLV_RS" || true)"
  if [ "$cnt" != "1" ]; then
    echo "!! lean lid: FAIL - expected exactly one 'pub fn ${fn}' in tlv.rs (found ${cnt});" >&2
    echo "   a cfg-split would let the Kani floor and the Lean lid prove different code." >&2
    exit 1
  fi
done
SEQ_RS="$HERE/../der-verified/src/sequence.rs"
for fn in decode_sequence decode_sequence_tlv decode_sequence_tlv_strict encode_sequence_into; do
  cnt="$(grep -cE "^pub fn ${fn}\b" "$SEQ_RS" || true)"
  if [ "$cnt" != "1" ]; then
    echo "!! lean lid: FAIL - expected exactly one 'pub fn ${fn}' in sequence.rs (found ${cnt});" >&2
    echo "   a cfg-split would let the Kani floor and the Lean lid prove different code." >&2
    exit 1
  fi
done
TAG_RS="$HERE/../der-verified/src/tag.rs"
for fn in decode_tag encode_tag; do
  cnt="$(grep -cE "^pub fn ${fn}\b" "$TAG_RS" || true)"
  if [ "$cnt" != "1" ]; then
    echo "!! lean lid: FAIL - expected exactly one 'pub fn ${fn}' in tag.rs (found ${cnt});" >&2
    echo "   a cfg-split would let the Kani floor and the Lean lid prove different code." >&2
    exit 1
  fi
done

# 0b) Pin the extraction/proof toolchain revision (review L4-lean-lid-03). The
#    DerLengthExtract.lean diff below catches *textual* model drift, but not a
#    same-text/changed-meaning bump of the Aeneas Std library. So assert the exact
#    Aeneas + Charon commits the proofs were verified against.
EXPECT_AENEAS="45061fa1a5b4bad876f17c03d3a5544d818622e6"
EXPECT_CHARON="40ee060a8df43f4e7e0842d3f05387b0a4426aaf"
GOT_AENEAS="$(git -C "$AENEAS" rev-parse HEAD 2>/dev/null || echo '?')"
GOT_CHARON="$(git -C "$AENEAS/charon" rev-parse HEAD 2>/dev/null || echo '?')"
if [ "$GOT_AENEAS" != "$EXPECT_AENEAS" ] || [ "$GOT_CHARON" != "$EXPECT_CHARON" ]; then
  echo "!! lean lid: FAIL - Aeneas/Charon toolchain revision drift." >&2
  echo "   expected  aeneas=$EXPECT_AENEAS  charon=$EXPECT_CHARON" >&2
  echo "   got       aeneas=$GOT_AENEAS  charon=$GOT_CHARON" >&2
  echo "   Proofs are checked against a specific Aeneas Std semantics; re-verify then update these pins." >&2
  exit 1
fi

# 1) Re-extract from the SAME length.rs and fail on drift, so the lid provably
#    concerns the shipped source rather than a stale generated snapshot.
echo "== lean lid: re-extract (charon -> aeneas) + drift check =="
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

# ⚠ EXTRACTION FAILURE AND MODEL DRIFT ARE DIFFERENT FINDINGS, AND THIS GATE MUST NOT CONFLATE THEM.
#
# Until 2026-08-03 the length/bigint/oid/tag extractions sent charon and aeneas output to /dev/null
# and went straight to `diff -q`. That made a TOOL failure indistinguishable from a SOURCE change in
# two ways, both of which lie about the cause:
#
#   * aeneas exits 0 but writes no model -> `diff -q` fails on the missing file -> the lid announces
#     "regenerated model differs ... length.rs changed", blaming a source file that never moved.
#   * charon or aeneas exits non-zero -> `set -e` aborts the script mid-pipeline with its output
#     already discarded, so `check.sh` fails with NO diagnostic at all.
#
# So each stage is now checked on its own terms: the tool's exit status, then the existence of the
# artifact it was supposed to produce, and only then the diff. A failure of the first two says
# EXTRACTION FAILURE and reprints the captured tool output; only the third says MODEL DRIFT and names
# a source file. Both directions are exercised deliberately — see evidence/lid-drift-faults-*.log.
extract_model() {
  _dir="$1"; _llbc="$2"; _model="$3"; shift 3
  _log="$TMP/extract-$_model.log"
  if ! ( cd "$HERE/$_dir" && "$CHARON_BIN" cargo --preset=aeneas "$@" --dest "$TMP" ) >"$_log" 2>&1; then
    _fail_extraction "$_model" "charon exited non-zero" "$_log"
  fi
  if [ ! -f "$TMP/$_llbc" ]; then
    _fail_extraction "$_model" "charon exited 0 but produced no $_llbc" "$_log"
  fi
  if ! "$AENEAS_BIN" -backend lean "$TMP/$_llbc" -dest "$TMP" >"$_log" 2>&1; then
    _fail_extraction "$_model" "aeneas exited non-zero" "$_log"
  fi
  if [ ! -f "$TMP/$_model.lean" ]; then
    _fail_extraction "$_model" "aeneas exited 0 but produced no $_model.lean" "$_log"
  fi
}

_fail_extraction() {
  echo "!! lean lid: FAIL - EXTRACTION FAILURE for $1: $2." >&2
  echo "   This is a TOOLCHAIN failure, NOT a source change. No claim is made about whether the" >&2
  echo "   shipped source drifted -- the model could not be regenerated, so it was never compared." >&2
  echo "   Captured tool output:" >&2
  if [ -s "$3" ]; then sed 's/^/   | /' "$3" >&2; else echo "   | (tool produced no output)" >&2; fi
  exit 1
}

# Only reached when extraction SUCCEEDED and a model file exists, so a difference here really is a
# difference between the shipped source and the committed model.
check_drift() {
  _model="$1"; _srcs="$2"
  if ! diff -q "$TMP/$_model.lean" "$HERE/$_model.lean" >/dev/null; then
    echo "!! lean lid: FAIL - MODEL DRIFT: regenerated model differs from committed $_model.lean." >&2
    echo "   Extraction succeeded, so this is a real difference: $_srcs changed;" >&2
    echo "   re-extract and re-prove before committing." >&2
    exit 1
  fi
}

extract_model extract der_length_extract.llbc DerLengthExtract
check_drift DerLengthExtract "length.rs"
extract_model extract-bigint der_bigint_extract.llbc DerBigintExtract
check_drift DerBigintExtract "big_integer.rs"
extract_model extract-oid der_oid_extract.llbc DerOidExtract
check_drift DerOidExtract "oid.rs"
# tag: --opaque on tag::encode_tag — its Rust parameter named `tag` shadows the `tag` module in
# Aeneas's Lean dot-notation resolution ("Invalid field" elaboration errors), the SAME
# parameter-shadowing workaround the tlv/sequence lids below use; `decode_tag` (what this lid
# proves) never calls `encode_tag`, so this loses nothing. `decode_tag` itself now extracts WITH
# A BODY (the D25-style single-loop/depth-1-return refactor — see tag.rs's own doc comment on
# `decode_tag`), so `aeneas` exits 0 here (no more disclosed bodyless-axiom "error").
extract_model extract-tag der_tag_extract.llbc DerTagExtract \
    --opaque "der_tag_extract::tag::encode_tag"
check_drift DerTagExtract "tag.rs"
# tlv: --opaque on tag::encode_tag + tlv::encode_tlv_into — both have a Rust parameter named
# `tag` shadowing the `tag` module in Aeneas's Lean dot-notation resolution ("Invalid field"
# elaboration errors), a pre-existing Aeneas naming limitation independent of this lid's own
# map_err fix; neither function is needed for the `decode_tlv` structural property this lid
# proves, so marking them opaque (bodyless axioms) is honest and lossless for this lid's scope.
# `tag.rs`'s `decode_tag` now extracts WITH A BODY (the D25-style refactor, see `extract-tag`'s
# comment above), so `aeneas` exits 0 here too (no more disclosed bodyless-axiom "error").
extract_model extract-tlv der_tlv_extract.llbc DerTlvExtract \
    --opaque "der_tlv_extract::tag::encode_tag" \
    --opaque "der_tlv_extract::tlv::encode_tlv_into"
check_drift DerTlvExtract "tag.rs/length.rs/tlv.rs"
# sequence: same --opaque carve-out as tlv (tag::encode_tag / tlv::encode_tlv_into, the
# parameter-shadowing issue); `aeneas` exits 0 here too (decode_tag extracts with a body).
extract_model extract-sequence der_sequence_extract.llbc DerSequenceExtract \
    --opaque "der_sequence_extract::tag::encode_tag" \
    --opaque "der_sequence_extract::tlv::encode_tlv_into"
# POST-EXTRACTION PATCH (not raw Aeneas output — see the committed DerSequenceExtract.lean's
# own docstring on the patched `Elements` Iterator instance for the full justification): Aeneas
# does not fill the `Iterator` trait's `step_by`/`enumerate`/`take` fields for a hand-written
# `impl Iterator` that only defines `next` (a genuine Aeneas codegen gap for user-defined
# iterators — library iterators like `Vec`'s get hand-specialized adapters in Aeneas's own Std;
# a user type gets none). Apply the identical patch here so the diff below compares like-for-
# like against the committed (patched) file, not raw Aeneas output.
python3 - "$TMP/DerSequenceExtract.lean" <<'PYEOF'
import sys
path = sys.argv[1]
with open(path) as f:
    content = f.read()
needle = (
    "def sequence.Elements.Insts.CoreIterTraitsIteratorIteratorResultTlvTlvError :\n"
    "  core.iter.traits.iterator.Iterator sequence.Elements (core.result.Result\n"
    "  tlv.Tlv tlv.TlvError) := {\n"
    "  next :=\n"
    "    sequence.Elements.Insts.CoreIterTraitsIteratorIteratorResultTlvTlvError.next\n"
    "}"
)
replacement = (
    "def sequence.Elements.Insts.CoreIterTraitsIteratorIteratorResultTlvTlvError :\n"
    "  core.iter.traits.iterator.Iterator sequence.Elements (core.result.Result\n"
    "  tlv.Tlv tlv.TlvError) := {\n"
    "  next :=\n"
    "    sequence.Elements.Insts.CoreIterTraitsIteratorIteratorResultTlvTlvError.next\n"
    "  step_by :=\n"
    "    core.iter.traits.iterator.Iterator.step_by.default (Self := sequence.Elements)\n"
    "  enumerate :=\n"
    "    core.iter.traits.iterator.Iterator.enumerate.default (Self := sequence.Elements)\n"
    "  take :=\n"
    "    core.iter.traits.iterator.Iterator.take.default (Self := sequence.Elements)\n"
    "}"
)
if needle not in content:
    print("!! lean lid: FAIL - patch anchor not found in regenerated DerSequenceExtract.lean", file=sys.stderr)
    print("   (the Iterator instance's shape changed; update check_lean.sh's patch)", file=sys.stderr)
    sys.exit(1)
content = content.replace(needle, replacement, 1)
with open(path, "w") as f:
    f.write(content)
PYEOF
check_drift DerSequenceExtract "tag.rs/length.rs/tlv.rs/sequence.rs"

# 2) Machine-check the unbounded proofs (reuses the prebuilt Aeneas+mathlib oleans).
echo "== lean lid: lake build (checking unbounded any-length proofs) =="
# Capture with `set -e` temporarily OFF: otherwise a failing `lake build` aborts the
# whole script at this assignment (a command-substitution non-zero status trips `set -e`),
# swallowing the build error AND skipping the STATUS/sorry checks below. We want the
# opposite — surface the build output and fail with a diagnostic.
set +e
BUILD_OUT="$( cd "$HERE" && lake build DerVerified 2>&1 )"
STATUS=$?
set -e
printf '%s\n' "$BUILD_OUT"
if [ "$STATUS" -ne 0 ]; then
  echo "!! lean lid: FAIL - lake build did not succeed (see output above)." >&2
  exit 1
fi

# 2b) Sorry-gate ratchet: a green `lake build` is NOT sufficient — `sorry` is only a
#     WARNING in Lean 4, so a proof resting on it still "builds". The sorry-free claim
#     (D7 trust accounting) must be a GATE, not an eyeball check. Any proof change forces
#     re-elaboration, which re-emits both the `declaration uses 'sorry'` warning and the
#     `#print axioms` disclosure lines, so a smuggled `sorry` surfaces as `sorryAx` in the
#     axiom set. Fail closed on either marker. (None of the DISCLOSED axioms — propext,
#     Classical.choice, Quot.sound, first_spec, core.slice.Slice.first, *.bv_decide.ax_* —
#     contain the substring "sorry", so this match is specific to an actual sorry.)
#
# ⚠ THE WARNING ARM WAS DEAD FROM THE DAY IT WAS WRITTEN UNTIL 2026-08-03. It matched
#   `declaration uses 'sorry'` with ASCII SINGLE QUOTES; Lean 4 emits BACKTICKS:
#   ``declaration uses `sorry` ``. So the pattern matched nothing, ever, and the whole
#   gate rested on the sorryAx arm alone. That arm only sees declarations carrying an
#   explicit `#print axioms` line, and those cover a SUBSET (LengthProofs.lean: 17
#   disclosures over 42 theorems). MEASURED hole, not a theoretical one: a `sorry` put
#   into `decode_reserved` — a theorem with no `#print axioms` — produced
#   `== lean lid: PASS (sorry-free) ==`, rc=0, while ``LengthProofs.lean:93:8:
#   declaration uses `sorry` `` sat in the very same build output.
#
# The warning arm CANNOT simply be widened to every sorry warning: Aeneas's own Std
# ships sorries we neither own nor can fix (Aeneas/Std/Slice.lean, Aeneas/Std/
# StringIter.lean), and matching those would pin this lid permanently red. So it is
# scoped to files OUTSIDE the dependency tree — exactly the set whose sorry-freedom
# this lid claims. A dependency's sorries are reported for the record, not failed on.
SORRY_WARNS="$(printf '%s\n' "$BUILD_OUT" | sed 's/^warning: //' \
  | grep -E 'declaration uses .sorry.' || true)"
FOREIGN_SORRIES="$(printf '%s\n' "$SORRY_WARNS" \
  | grep -E '^(\.lake/|Aeneas/|Mathlib/|Batteries/|Init/|Std/)' || true)"
OUR_SORRIES="$(printf '%s\n' "$SORRY_WARNS" | grep -E '\.lean:[0-9]+:[0-9]+' \
  | grep -Ev '^(\.lake/|Aeneas/|Mathlib/|Batteries/|Init/|Std/)' || true)"
if [ -n "$FOREIGN_SORRIES" ]; then
  echo "-- lean lid: NOTE - $(printf '%s\n' "$FOREIGN_SORRIES" | grep -c .) sorry warning(s) in DEPENDENCY"
  echo "   files (Aeneas/Mathlib Std). Not ours, not failed on, disclosed so the count is visible:"
  printf '%s\n' "$FOREIGN_SORRIES" | sed 's/^/   | /'
fi
if [ -n "$OUR_SORRIES" ]; then
  echo "!! lean lid: FAIL - a proof in a file THIS repo owns depends on 'sorry':" >&2
  printf '%s\n' "$OUR_SORRIES" | sed 's/^/   | /' >&2
  echo "   The unbounded proofs must be sorry-free." >&2
  exit 1
fi
if printf '%s\n' "$BUILD_OUT" | grep -q "sorryAx"; then
  echo "!! lean lid: FAIL - a proof depends on 'sorry' (sorryAx in a '#print axioms' axiom set)." >&2
  printf '%s\n' "$BUILD_OUT" | grep -B4 "sorryAx" | sed 's/^/   | /' >&2
  echo "   The unbounded proofs must be sorry-free." >&2
  exit 1
fi
echo "== lean lid: PASS (sorry-free) =="

# 3) Refresh the fast gate's staleness tripwire (gates/check_lid_staleness.py, run every commit via
#    check_fast.sh). Only reached here because `set -eu` already aborted the whole script above on
#    ANY failure -- extraction, drift, lake build, or a smuggled sorry -- so a full green run is
#    exactly the event that should clear PENDING markers and re-baseline the six hashes. Reuses the
#    SAME six path variables named in the check_drift() calls above, not a second hand-kept list
#    (lean/lid-source-state.txt's own header documents this contract; see DECISIONS.md D29).
echo "== lean lid: checking lean/lid-source-state.txt (fast-gate tripwire) for changes =="
STATE_FILE="$HERE/lid-source-state.txt"
COMMIT="$(git -C "$HERE" rev-parse HEAD 2>/dev/null || echo '?')"
STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
NEW_HASHES="$(
  for f in "$LEN_RS" "$BIGINT_RS" "$OID_RS" "$TAG_RS" "$TLV_RS" "$SEQ_RS"; do
    rel="der-verified/src/$(basename "$f")"
    sha="$(sha256sum "$f" | awk '{print $1}')"
    printf '%s  %s\n' "$sha" "$rel"
  done
)"
OLD_HASHES="$(grep -v '^#' "$STATE_FILE" 2>/dev/null | grep -v '^[[:space:]]*$' || true)"
if [ "$NEW_HASHES" = "$OLD_HASHES" ]; then
  echo "== lean lid: lid-source-state.txt unchanged (hashes identical) =="
else
  {
    cat <<HDR
# lean/lid-source-state.txt — Lean-lid source-drift tripwire (fast-gate state).
#
# ONE-LINE CONTRACT, read by gates/check_lid_staleness.py (per-commit, via check_fast.sh) and
# refreshed ONLY by lean/check_lean.sh (the full gate, on a green run; check.sh --strict):
#   <sha256>  <repo-relative-path>          -- matches the shipped source's current sha256.
#   PENDING <sha256>  <repo-relative-path>  -- drift ACKNOWLEDGED but not yet re-verified through
#                                              Lean; the hash is the file's CURRENT content, so a
#                                              further edit re-triggers FAIL. Acknowledge with:
#                                              python3 gates/check_lid_staleness.py --ack <path>
#
# WHICH files: derived from lean/check_lean.sh's own check_drift() sources -- never a second
# hand-maintained list. gates/check_lid_staleness.py PARSES check_lean.sh's check_drift(...)
# calls to derive the expected source set and fails if this file's set doesn't match (either
# direction) -- so check_lean.sh stays the single source of truth for WHICH files, this file
# carries only their hashes.
#
# Contract: Aeneas embeds source LINE SPANS in what it extracts, so ANY edit to a lid-covered file
# -- including a docs-only \`//!\` line -- can silently break the extracted Lean model. This file
# is the cheap (six sha256 reads) per-commit tripwire for that; it cannot re-verify anything
# through Lean itself, so a matching hash means only "unchanged since the last green Lean run",
# not "still proves". Toolchain drift (Aeneas/Charon pin mismatch) is exclusively the full gate's
# job (see this script's own pin check above).
#
# State as of: $STAMP, commit $COMMIT (rewritten only when hashes change; a green run that
# changes nothing leaves this file untouched).
HDR
    printf '%s\n' "$NEW_HASHES"
  } > "$STATE_FILE"
  echo "== lean lid: lid-source-state.txt refreshed (hashes changed) -- COMMIT this refreshed"
  echo "   file; gates/check_lid_staleness.py --strict will correctly FAIL until it is staged" \
       "or committed (working-tree/index divergence is expected right after a rewrite)."
fi
