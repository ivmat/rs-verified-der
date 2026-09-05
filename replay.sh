#!/usr/bin/env sh
# replay.sh — the ten-minute replay. See REPLAY.md for what this does and does not cover.
#
# Six base steps, each printing a `== ... ==` header; S1-S5 also print a `RESULT:` line:
#   S1  cargo test (the crate's test suite)                          — expect ACCEPT
#   S2  the vendored acceptance-manifest validator, strict mode      — expect ACCEPT
#   S3  ONE Kani harness (boolean::proofs::one_octet_is_canonical)   — expect ACCEPT
#   S4  negative control A: the SAME harness against a seeded        — expect REJECT
#       one-line code mutation, in a throwaway temp copy
#   S5  negative control B: the SAME validator against a tampered    — expect REJECT
#       evidence record, in a throwaway temp copy
#   S6  summary table
# Optional `--with-lean` adds L1 before S6: re-extract and check all six Lean lids with the
# pinned Charon/Aeneas/Lean toolchain. It is fail-closed and never turns an absent toolchain
# into a skip. L1 is accept-only: it re-executes the Lean baseline but seeds no Lean fault. S2
# validates every recorded evidence projection, including the historical Lean control records.
#
# Every Kani invocation runs under a hard virtual-memory cap (`ulimit -v`) and a wall-clock
# timeout, per this repo's memory-blowup lesson (see evidence/*.md and the README's "needs
# ~24 GB RAM" note for the FULL floor — this script never runs the full floor).
#
# Default mode mutates no tracked file. S4 and S5 each work in their own `mktemp -d` copy of
# `der-verified/` and are torn down on every exit path, including failure. `--with-lean`
# delegates to lean/check_lean.sh, which can refresh tracked lean/lid-source-state.txt after a
# green run when the recorded source hashes changed. Lean build state stays under ignored .lake/.
set -eu

ROOT="$(cd "$(dirname "$0")" && pwd)"
HARNESS="boolean::proofs::one_octet_is_canonical"
MODULE="boolean"
MEM_CAP_KB=8000000        # ~8 GB
KANI_TIMEOUT_S=300        # 5 minutes
WITH_LEAN=0

usage() {
    echo "usage: ./replay.sh [--with-lean]"
    echo
    echo "  default      laptop-sized tests, manifest validation, one Kani harness, and controls"
    echo "  --with-lean  also re-extract and check all six Lean lids; missing tools are a failure"
}

while [ "$#" -gt 0 ]; do
    case "$1" in
        --with-lean)
            if [ "$WITH_LEAN" -eq 1 ]; then
                echo "replay.sh: --with-lean was supplied more than once" >&2
                usage >&2
                exit 64
            fi
            WITH_LEAN=1
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "replay.sh: unknown option: $1" >&2
            usage >&2
            exit 64
            ;;
    esac
    shift
done

BASE_TMP="$(mktemp -d)"
RESULTS="$BASE_TMP/results.tsv"
: > "$RESULTS"
MISSING_KANI=0

cleanup() {
    rc=$?
    cd "$ROOT" 2>/dev/null || cd /
    rm -rf "$BASE_TMP" "${S4_DIR:-}" "${S5_DIR:-}" 2>/dev/null || true
    exit "$rc"
}
trap cleanup EXIT INT TERM HUP

have_time=0
if command -v /usr/bin/time >/dev/null 2>&1; then
    have_time=1
fi

# run_timed <step-tag> -- <command...>
# Times the command (wall clock + peak RSS if /usr/bin/time -v is available), without letting
# `set -e` abort the script on a nonzero exit — the caller decides whether that exit was expected.
# Sets: RC, WALL_S, RSS_KB, OUTLOG (path to captured stdout+stderr).
run_timed() {
    tag="$1"; shift
    OUTLOG="$BASE_TMP/${tag}.out"
    timelog="$BASE_TMP/${tag}.timelog"
    start=$(date +%s)
    set +e
    if [ "$have_time" = "1" ]; then
        /usr/bin/time -v -o "$timelog" -- "$@" >"$OUTLOG" 2>&1
    else
        "$@" >"$OUTLOG" 2>&1
    fi
    RC=$?
    set -e
    end=$(date +%s)
    WALL_S=$((end - start))
    if [ "$have_time" = "1" ] && [ -f "$timelog" ]; then
        RSS_KB=$(grep 'Maximum resident set size' "$timelog" 2>/dev/null | sed 's/.*: *//')
        [ -n "$RSS_KB" ] || RSS_KB="n/a"
    else
        RSS_KB="n/a"
    fi
}

# run_kani_capped <step-tag> -- <cargo kani command...>
# Same as run_timed, but wraps the command in a subshell that sets `ulimit -v` before exec'ing
# it, and bounds wall time with `timeout`. The memory cap is mandatory for every Kani call in
# this script — see the repo memory note this script exists partly to demonstrate respecting.
run_kani_capped() {
    tag="$1"; shift
    OUTLOG="$BASE_TMP/${tag}.out"
    timelog="$BASE_TMP/${tag}.timelog"
    start=$(date +%s)
    set +e
    if [ "$have_time" = "1" ]; then
        ( ulimit -v "$MEM_CAP_KB"
          exec timeout -k 10 "$KANI_TIMEOUT_S" /usr/bin/time -v -o "$timelog" -- "$@" ) >"$OUTLOG" 2>&1
    else
        ( ulimit -v "$MEM_CAP_KB"
          exec timeout -k 10 "$KANI_TIMEOUT_S" "$@" ) >"$OUTLOG" 2>&1
    fi
    RC=$?
    set -e
    end=$(date +%s)
    WALL_S=$((end - start))
    if [ "$have_time" = "1" ] && [ -f "$timelog" ]; then
        RSS_KB=$(grep 'Maximum resident set size' "$timelog" 2>/dev/null | sed 's/.*: *//')
        [ -n "$RSS_KB" ] || RSS_KB="n/a"
    else
        RSS_KB="n/a"
    fi
}

record() {
    # record <step> <expected> <observed> <wall_s> <rss_kb>
    printf '%s\t%s\t%s\t%ss\t%s\n' "$1" "$2" "$3" "$4" "$5" >>"$RESULTS"
}

result_line() {
    # result_line <step> <expected> <observed>
    echo "RESULT: $1 $3 (expected $2)"
}

kani_available() {
    command -v cargo-kani >/dev/null 2>&1
}

kani_install_hint() {
    echo "Install the pinned Kani (0.67.0) with:"
    echo "  cargo install --locked kani-verifier --version 0.67.0"
    echo "  cargo kani setup"
}

# ---------------------------------------------------------------------------
echo "== S1: cargo test -p der-verified --lib =="
run_timed s1 cargo test -p der-verified --lib --manifest-path "$ROOT/Cargo.toml"
if [ "$RC" -eq 0 ]; then
    observed="ACCEPT"
else
    observed="REJECT"
fi
tail -n 5 "$OUTLOG"
result_line "S1 (cargo test)" "ACCEPT" "$observed"
record "S1 cargo test" "ACCEPT" "$observed" "$WALL_S" "$RSS_KB"
if [ "$RC" -ne 0 ]; then
    echo "S1 FAILED: the crate's own test suite did not pass on a clean checkout — that is not" >&2
    echo "an expected negative control, it means something is actually broken. See $OUTLOG." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
echo
echo "== S2: acceptance-manifest gate (der-verified/acceptance.toml, strict mode, pinned vendored validator) =="
run_timed s2 python3 "$ROOT/gates/check_acceptance_manifest.py"
if [ "$RC" -eq 0 ]; then
    observed="ACCEPT"
else
    observed="REJECT"
fi
tail -n 3 "$OUTLOG"
result_line "S2 (acceptance manifest, clean)" "ACCEPT" "$observed"
record "S2 acceptance manifest (clean)" "ACCEPT" "$observed" "$WALL_S" "$RSS_KB"
if [ "$RC" -ne 0 ]; then
    echo "S2 FAILED: the shipped acceptance.toml did not validate against the pinned validator on" >&2
    echo "a clean checkout — that is not an expected negative control. See $OUTLOG." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
echo
echo "== S3: one Kani harness ($MODULE::proofs — $HARNESS), memory-capped at ~8 GB, 5 min timeout =="
if ! kani_available; then
    echo "SKIPPED: Kani (cargo-kani) is not installed."
    kani_install_hint
    MISSING_KANI=1
else
    run_kani_capped s3 cargo kani --manifest-path "$ROOT/der-verified/Cargo.toml" \
        --harness "$HARNESS" --exact
    if [ "$RC" -eq 0 ] && grep -q 'VERIFICATION:- SUCCESSFUL' "$OUTLOG"; then
        observed="ACCEPT"
    else
        observed="REJECT"
    fi
    tail -n 8 "$OUTLOG"
    result_line "S3 (kani, clean $MODULE)" "ACCEPT" "$observed"
    record "S3 kani clean ($MODULE)" "ACCEPT" "$observed" "$WALL_S" "$RSS_KB"
    if [ "$observed" != "ACCEPT" ]; then
        echo "S3 FAILED: the unmutated $HARNESS harness did not verify — that is not an expected" >&2
        echo "negative control, it means the crate's own proof floor is broken. See $OUTLOG." >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
echo
echo "== S4: negative control A — seeded code fault ($MODULE, temp copy, never touches tracked files) =="
if ! kani_available; then
    echo "SKIPPED: Kani (cargo-kani) is not installed."
    kani_install_hint
    MISSING_KANI=1
else
    S4_DIR="$(mktemp -d)"
    cp -r "$ROOT/der-verified" "$S4_DIR/der-verified"
    cp "$ROOT/rust-toolchain.toml" "$S4_DIR/der-verified/rust-toolchain.toml"
    # The seeded fault: widen the canonical-TRUE match arm to also accept the BER (non-DER)
    # encoding 0x01, alongside the canonical 0xFF. Documented and previously observed to be
    # caught by exactly this harness: evidence/MUTATION-CONTROLS-2026-08-23-fivemodule.md,
    # evidence/mutation-controls-2026-08-23-fivemodule/booleanA.diff.
    target="$S4_DIR/der-verified/src/boolean.rs"
    before_sha="$(sha256sum "$target" | cut -d' ' -f1)"
    python3 - "$target" <<'PYEOF'
import pathlib, sys
p = pathlib.Path(sys.argv[1])
t = p.read_text()
old = "        0xFF => Ok(true),\n"
new = "        0xFF | 0x01 => Ok(true),\n"
if old not in t:
    sys.exit("seeded-fault anchor line not found; boolean.rs shape changed under this script")
p.write_text(t.replace(old, new, 1))
PYEOF
    after_sha="$(sha256sum "$target" | cut -d' ' -f1)"
    if [ "$before_sha" = "$after_sha" ]; then
        echo "S4 FAILED: the seeded mutation did not change $target — the control would be a no-op." >&2
        exit 1
    fi

    run_kani_capped s4 cargo kani --manifest-path "$S4_DIR/der-verified/Cargo.toml" \
        --harness "$HARNESS" --exact
    if [ "$RC" -ne 0 ] && grep -q 'VERIFICATION:- FAILED' "$OUTLOG"; then
        observed="REJECT"
    else
        observed="ACCEPT"
    fi
    tail -n 12 "$OUTLOG"
    result_line "S4 (kani, mutated $MODULE)" "REJECT" "$observed"
    record "S4 kani mutated ($MODULE, seeded fault)" "REJECT" "$observed" "$WALL_S" "$RSS_KB"
    if [ "$observed" != "REJECT" ]; then
        echo "S4 FAILED LOUDLY: the seeded code fault (accepting 0x01 as canonical TRUE) did NOT" >&2
        echo "make $HARNESS fail. A negative control that cannot fail is worthless — see $OUTLOG" >&2
        echo "and the diff applied at $target." >&2
        exit 3
    fi
    rm -rf "$S4_DIR"
    S4_DIR=""
fi

# ---------------------------------------------------------------------------
echo
echo "== S5: negative control B — tampered evidence record (temp copy, never touches tracked files) =="
S5_DIR="$(mktemp -d)"
cp -r "$ROOT/der-verified" "$S5_DIR/der-verified"
rec="$S5_DIR/der-verified/evidence/acceptance-records/check-402719a-big-integer-proofs-empty-is-empty.json"
if [ ! -f "$rec" ]; then
    echo "S5 FAILED: expected evidence record not found at $rec — acceptance.toml's evidence" >&2
    echo "store layout changed under this script." >&2
    exit 1
fi
before_sha="$(sha256sum "$rec" | cut -d' ' -f1)"
python3 - "$rec" <<'PYEOF'
import sys
p = sys.argv[1]
data = bytearray(open(p, "rb").read())
data[10] ^= 0xFF   # flip one byte inside the record; this changes its content hash
open(p, "wb").write(data)
PYEOF
after_sha="$(sha256sum "$rec" | cut -d' ' -f1)"
if [ "$before_sha" = "$after_sha" ]; then
    echo "S5 FAILED: the byte flip did not change $rec — the control would be a no-op." >&2
    exit 1
fi

run_timed s5 python3 "$ROOT/gates/vendor/acceptance-format/check_acceptance.py" \
    --strict --strict-weight "$S5_DIR/der-verified/acceptance.toml"
if [ "$RC" -ne 0 ] && grep -q 'record_hash MISMATCH' "$OUTLOG"; then
    observed="REJECT"
else
    observed="ACCEPT"
fi
tail -n 5 "$OUTLOG"
result_line "S5 (validator, tampered record)" "REJECT" "$observed"
record "S5 validator tampered evidence" "REJECT" "$observed" "$WALL_S" "$RSS_KB"
if [ "$observed" != "REJECT" ]; then
    echo "S5 FAILED LOUDLY: a one-byte-flipped evidence record did NOT make the strict validator" >&2
    echo "reject acceptance.toml. A negative control that cannot fail is worthless — see $OUTLOG" >&2
    echo "and the tampered file at $rec." >&2
    exit 3
fi
rm -rf "$S5_DIR"
S5_DIR=""

# ---------------------------------------------------------------------------
if [ "$WITH_LEAN" -eq 1 ] && [ "$MISSING_KANI" -eq 0 ]; then
    echo
    echo "== L1: all six Charon -> Aeneas -> Lean lids (required, no skip) =="
    run_timed l1 env DER_REQUIRE_LEAN=1 sh "$ROOT/lean/check_lean.sh"
    if [ "$RC" -eq 0 ] \
        && grep -qF '== lean lid: PASS (sorry-free) ==' "$OUTLOG" \
        && grep -qF 'lean-lid-status: PASS' "$OUTLOG"; then
        observed="ACCEPT"
    else
        observed="REJECT"
    fi
    tail -n 20 "$OUTLOG"
    result_line "L1 (Lean lids)" "ACCEPT" "$observed"
    record "L1 Lean lids (all six)" "ACCEPT" "$observed" "$WALL_S" "$RSS_KB"
    if [ "$observed" != "ACCEPT" ]; then
        cat "$OUTLOG" >&2
        echo "L1 FAILED: --with-lean requires lean/check_lean.sh to exit 0 AND print both PASS" >&2
        echo "markers (exit was $RC). The complete L1 output is above." >&2
        exit 1
    fi
fi

# ---------------------------------------------------------------------------
echo
echo "== S6: summary =="
printf '%-42s %-9s %-9s %-8s %s\n' "step" "expected" "observed" "wall" "peak RSS (KB)"
while IFS="$(printf '\t')" read -r step expected observed wall rss; do
    printf '%-42s %-9s %-9s %-8s %s\n' "$step" "$expected" "$observed" "$wall" "$rss"
done <"$RESULTS"

if [ "$MISSING_KANI" -eq 1 ]; then
    echo >&2
    if [ "$WITH_LEAN" -eq 1 ]; then
        echo "L1 NOT RUN: --with-lean cannot make an incomplete Kani replay complete." >&2
        echo "Install Kani before paying the cost of the Lean replay." >&2
    fi
    echo "FAILED: Kani is not installed, so S3/S4 could not run — this replay is INCOMPLETE, not" >&2
    echo "a pass." >&2
    kani_install_hint >&2
    exit 2
fi

echo
if [ "$WITH_LEAN" -eq 1 ]; then
    echo "replay.sh: all six base steps plus the requested Lean replay observed their expected verdict."
else
    echo "replay.sh: all six steps observed their expected verdict."
fi
