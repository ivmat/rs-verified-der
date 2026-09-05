#!/usr/bin/env python3
"""Fast structural checks for replay.sh's optional fail-closed Lean mode.

L1 PASS and FAIL are not simulated here because either path first runs the base replay. The real
combined replay is a milestone check. The absent-toolchain failure is exercised separately by
test_check_lean_skip.py state 2.
"""

from __future__ import annotations

import subprocess
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "replay.sh"


def run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["sh", str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )


class ReplayCliTests(unittest.TestCase):
    def test_help_documents_the_optional_lean_mode(self):
        result = run("--help")
        self.assertEqual(result.returncode, 0)
        self.assertIn("--with-lean", result.stdout)
        self.assertIn("missing tools are a failure", result.stdout)
        self.assertNotIn("== S1:", result.stdout)
        self.assertNotIn("L1 NOT RUN", result.stdout + result.stderr)

    def test_unknown_option_fails_before_replay_starts(self):
        result = run("--not-a-replay-mode")
        self.assertEqual(result.returncode, 64)
        self.assertIn("unknown option", result.stderr)
        self.assertNotIn("== S1:", result.stdout + result.stderr)

    def test_duplicate_lean_option_fails_before_replay_starts(self):
        result = run("--with-lean", "--with-lean")
        self.assertEqual(result.returncode, 64)
        self.assertIn("supplied more than once", result.stderr)
        self.assertNotIn("== S1:", result.stdout + result.stderr)

    def test_lean_guard_shape_is_intact(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertIn('run_timed l1 env DER_REQUIRE_LEAN=1 sh "$ROOT/lean/check_lean.sh"', source)
        accept_guard = r'''    if [ "$RC" -eq 0 ] \
        && grep -qF '== lean lid: PASS (sorry-free) ==' "$OUTLOG" \
        && grep -qF 'lean-lid-status: PASS' "$OUTLOG"; then
        observed="ACCEPT"
    else
        observed="REJECT"
    fi'''
        fail_closed = '''    if [ "$observed" != "ACCEPT" ]; then
        cat "$OUTLOG" >&2
        echo "L1 FAILED: --with-lean requires lean/check_lean.sh to exit 0 AND print both PASS" >&2
        echo "markers (exit was $RC). The complete L1 output is above." >&2
        exit 1
    fi'''
        self.assertIn(accept_guard, source)
        self.assertIn(fail_closed, source)

    def test_missing_kani_reports_summary_before_skipping_lean(self):
        source = SCRIPT.read_text(encoding="utf-8")
        self.assertLess(source.index('echo "== S6: summary =="'), source.index('echo "L1 NOT RUN:'))


if __name__ == "__main__":
    unittest.main()
