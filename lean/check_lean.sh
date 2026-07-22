#!/usr/bin/env sh
# L4 "Lean lid" gate — re-runnable (the L3 Kani floor's unbounded companion).
#
# Re-extracts the length + big_integer + oid codecs through Charon -> Aeneas and
# machine-checks the unbounded (any-length) Lean proofs (LengthProofs.lean,
# BigIntProofs.lean, OidProofs.lean).
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
( cd "$HERE/extract" && "$CHARON_BIN" cargo --preset=aeneas --dest "$TMP" >/dev/null 2>&1 )
"$AENEAS_BIN" -backend lean "$TMP/der_length_extract.llbc" -dest "$TMP" >/dev/null 2>&1
if ! diff -q "$TMP/DerLengthExtract.lean" "$HERE/DerLengthExtract.lean" >/dev/null; then
  echo "!! lean lid: FAIL - regenerated model differs from committed DerLengthExtract.lean." >&2
  echo "   length.rs changed; re-extract and re-prove before committing." >&2
  exit 1
fi
( cd "$HERE/extract-bigint" && "$CHARON_BIN" cargo --preset=aeneas --dest "$TMP" >/dev/null 2>&1 )
"$AENEAS_BIN" -backend lean "$TMP/der_bigint_extract.llbc" -dest "$TMP" >/dev/null 2>&1
if ! diff -q "$TMP/DerBigintExtract.lean" "$HERE/DerBigintExtract.lean" >/dev/null; then
  echo "!! lean lid: FAIL - regenerated model differs from committed DerBigintExtract.lean." >&2
  echo "   big_integer.rs changed; re-extract and re-prove before committing." >&2
  exit 1
fi
( cd "$HERE/extract-oid" && "$CHARON_BIN" cargo --preset=aeneas --dest "$TMP" >/dev/null 2>&1 )
"$AENEAS_BIN" -backend lean "$TMP/der_oid_extract.llbc" -dest "$TMP" >/dev/null 2>&1
if ! diff -q "$TMP/DerOidExtract.lean" "$HERE/DerOidExtract.lean" >/dev/null; then
  echo "!! lean lid: FAIL - regenerated model differs from committed DerOidExtract.lean." >&2
  echo "   oid.rs changed; re-extract and re-prove before committing." >&2
  exit 1
fi
# tlv: --opaque on tag::encode_tag + tlv::encode_tlv_into — both have a Rust parameter named
# `tag` shadowing the `tag` module in Aeneas's Lean dot-notation resolution ("Invalid field"
# elaboration errors), a pre-existing Aeneas naming limitation independent of this lid's own
# map_err fix; neither function is needed for the `decode_tlv` structural property this lid
# proves, so marking them opaque (bodyless axioms) is honest and lossless for this lid's scope.
# `aeneas` itself EXPECTEDLY exits non-zero here (tag.rs's decode_tag has an early-return-in-a-
# loop, so Aeneas emits it as a disclosed bodyless axiom and reports that as an "error" even
# though the rest of the file — including tlv.decode_tlv, the function this lid actually proves
# about — extracts correctly). So this call runs with `set -e` OFF, same pattern as the `lake
# build` step below; the diff check right after is what actually gates on drift/regression.
set +e
( cd "$HERE/extract-tlv" && "$CHARON_BIN" cargo --preset=aeneas \
    --opaque "der_tlv_extract::tag::encode_tag" \
    --opaque "der_tlv_extract::tlv::encode_tlv_into" \
    --dest "$TMP" >/dev/null 2>&1 )
"$AENEAS_BIN" -backend lean "$TMP/der_tlv_extract.llbc" -dest "$TMP" >/dev/null 2>&1
set -e
if [ ! -f "$TMP/DerTlvExtract.lean" ]; then
  echo "!! lean lid: FAIL - tlv re-extraction produced no DerTlvExtract.lean at all (a" >&2
  echo "   genuine extraction failure, not the expected decode_tag bodyless-axiom warning)." >&2
  exit 1
fi
if ! diff -q "$TMP/DerTlvExtract.lean" "$HERE/DerTlvExtract.lean" >/dev/null; then
  echo "!! lean lid: FAIL - regenerated model differs from committed DerTlvExtract.lean." >&2
  echo "   tag.rs/length.rs/tlv.rs changed; re-extract and re-prove before committing." >&2
  exit 1
fi

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
if printf '%s\n' "$BUILD_OUT" | grep -Eiq "sorryAx|declaration uses '?sorry'?|uses 'sorry'"; then
  echo "!! lean lid: FAIL - a proof depends on 'sorry' (sorryAx in the axiom set or a" >&2
  echo "   'declaration uses sorry' warning). The unbounded proofs must be sorry-free." >&2
  exit 1
fi
echo "== lean lid: PASS (sorry-free) =="
