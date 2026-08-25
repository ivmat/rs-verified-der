#!/usr/bin/env python3
"""Self-test for lean/check_lean.sh's toolchain guard — the gate's own gate.

WHY THIS EXISTS
---------------
`lean/check_lean.sh` is guarded: with no Aeneas/Lean toolchain it prints a SKIP line and exits 0.
Until 2026-08-25 that skip was indistinguishable, to its caller, from a real pass — both were
exit 0 — so `check.sh` printed an unqualified `== check.sh: PASS ==` for a run in which the
unbounded L4 proofs had never been checked at all. Two of the crate's own three recent clean-room
runs were in exactly that state.

That is a ONE-WAY ALARM: a check that can only ever say "fine" is not evidence, and its silence was
being read as a pass. The fix gives the script a machine-readable outcome (`lean-lid-status: PASS |
SKIP | FAIL`, plus $DER_LID_STATUS_FILE) that `check.sh` names in its own summary.

A guard is only worth having if it can be watched to fail, so this self-test drives all three
reachable states rather than asserting the happy one:

  1. SKIP        — toolchain absent, permissive default: exit 0, and NO false PASS anywhere.
  2. FAIL-CLOSED — toolchain absent + DER_REQUIRE_LEAN=1: non-zero exit, status FAIL.
  3. FAIL        — toolchain "present" (stubs), so the guard does NOT fire: the run proceeds past
                   the guard and fails downstream. This is the positive control: it proves the SKIP
                   token is emitted because the toolchain is missing, not unconditionally.

The PASS state is deliberately NOT simulated here — faking it would mean faking the very proofs it
attests. It is witnessed by the real gate run, which now prints `lean-lid-status: PASS`.
"""

import os
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "lean" / "check_lean.sh"

failures = []


def check(label, cond, detail=""):
    if cond:
        print(f"   ok   {label}")
    else:
        print(f"   FAIL {label} {detail}")
        failures.append(f"{label} {detail}".strip())


def run(env_extra, tools_dir, status_path, extra_path=None):
    """Run check_lean.sh with a controlled environment; return (rc, output, status_token)."""
    env = dict(os.environ)
    # Scrub anything that could let the real toolchain leak in and make the result environmental.
    env.pop("DER_REQUIRE_LEAN", None)
    env["VERIFIED_RS_TOOLS"] = str(tools_dir)
    env["DER_LID_STATUS_FILE"] = str(status_path)
    if extra_path:
        env["PATH"] = f"{extra_path}:{env.get('PATH', '')}"
    env.update(env_extra)
    proc = subprocess.run(
        ["sh", str(SCRIPT)],
        capture_output=True,
        text=True,
        env=env,
        cwd=str(ROOT),
        timeout=300,
    )
    token = ""
    if Path(status_path).exists():
        token = Path(status_path).read_text().strip()
    return proc.returncode, proc.stdout + proc.stderr, token


def main():
    print("== test_check_lean_skip.py: lean-lid guard self-test (3 states) ==")

    with tempfile.TemporaryDirectory() as td:
        td = Path(td)
        empty_tools = td / "no-tools"          # exists but contains no aeneas/charon binaries
        empty_tools.mkdir()
        status = td / "status.txt"

        # --- 1. SKIP: toolchain absent, permissive default. ---
        print("-- state 1: toolchain absent (permissive default) --")
        rc, out, token = run({}, empty_tools, status)
        check("exits 0", rc == 0, f"(got {rc})")
        check("stdout carries the machine-readable token", "lean-lid-status: SKIP" in out)
        check("status file says SKIP", token == "SKIP", f"(got {token!r})")
        check("announces the skip in prose", "lean lid: SKIP" in out)
        # The trap this whole gate exists to close: a skip must never look like a pass.
        check("does NOT claim a sorry-free pass", "lean lid: PASS" not in out)
        check("does NOT emit a PASS token", "lean-lid-status: PASS" not in out)

        # --- 2. FAIL-CLOSED: same, but the caller demands L4. ---
        print("-- state 2: toolchain absent + DER_REQUIRE_LEAN=1 (fail-closed) --")
        status.unlink(missing_ok=True)
        rc, out, token = run({"DER_REQUIRE_LEAN": "1"}, empty_tools, status)
        check("exits non-zero", rc != 0, f"(got {rc})")
        check("status file says FAIL", token == "FAIL", f"(got {token!r})")
        check("explains the fail-closed switch", "DER_REQUIRE_LEAN" in out)
        check("does NOT emit a SKIP token", "lean-lid-status: SKIP" not in out)
        check("does NOT claim a sorry-free pass", "lean lid: PASS" not in out)

        # --- 3. POSITIVE CONTROL: guard does not fire when the toolchain looks present. ---
        # Without this, states 1 and 2 would also pass if the script emitted SKIP unconditionally.
        print("-- state 3: stub toolchain present (guard must NOT fire) --")
        fake_tools = td / "tools"
        for rel in ("aeneas/bin/aeneas", "aeneas/charon/bin/charon"):
            p = fake_tools / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text("#!/bin/sh\nexit 0\n")
            p.chmod(0o755)
        fake_bin = td / "bin"
        fake_bin.mkdir()
        lake = fake_bin / "lake"
        lake.write_text("#!/bin/sh\nexit 0\n")
        lake.chmod(0o755)

        status.unlink(missing_ok=True)
        rc, out, token = run({}, fake_tools, status, extra_path=str(fake_bin))
        check("guard did NOT fire (no SKIP token)", "lean-lid-status: SKIP" not in out)
        check("ran past the guard and failed downstream", rc != 0, f"(got {rc})")
        check("status file says FAIL, not SKIP or PASS", token == "FAIL", f"(got {token!r})")
        check("does NOT claim a sorry-free pass", "lean lid: PASS" not in out)

    print()
    if failures:
        print(f"!! test_check_lean_skip.py: FAIL - {len(failures)} check(s) failed:")
        for f in failures:
            print(f"   | {f}")
        return 1
    print("== test_check_lean_skip.py: PASS (SKIP / fail-closed / guard-discriminates) ==")
    return 0


if __name__ == "__main__":
    sys.exit(main())
