#!/usr/bin/env python3
"""Observed-red tests for check_req_map.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "gates" / "check_req_map.py"

RUST = """
#[cfg(kani)]
mod proofs {
    #[kani::proof]
    fn proves_a() {}
}

#[cfg(test)]
mod tests {
    #[test]
    fn accepts_a() {}
}
"""

LEAN = """
theorem lean_a : True := by trivial
"""

INVENTORY = """
[inventory]
id = "test"
title = "test"
source = "test"

[[group]]
id = "DER"
title = "root"

[[item]]
id = "A"
title = "active"
parent = "DER"
force = "contract"
side = "both"
source = "test"
disposition = "in"

[[item]]
id = "X"
title = "excluded"
parent = "DER"
force = "contract"
side = "both"
source = "test"
disposition = "excluded"
reason = "test"
"""

TEST_ENTRY = """
[[entry]]
kind = "test"
file = "der-verified/src/sample.rs"
name = "accepts_a"
accept = []
reject = []
prove = []
bounded = ""
none = "not assigned"
"""

KANI_ENTRY = """
[[entry]]
kind = "kani"
file = "der-verified/src/sample.rs"
name = "proves_a"
accept = []
reject = []
prove = []
bounded = ""
none = "not assigned"
"""

LEAN_ENTRY = """
[[entry]]
kind = "lean"
file = "lean/MiniProofs.lean"
name = "lean_a"
accept = []
reject = []
prove = []
bounded = ""
none = "not assigned"
"""


class CheckerTests(unittest.TestCase):
    def make_tree(
        self,
        base: Path,
        *,
        rust: str = RUST,
        lean: str = LEAN,
        inventory: str = INVENTORY,
        rust_map: str = TEST_ENTRY + KANI_ENTRY,
        lean_map: str = LEAN_ENTRY,
    ) -> None:
        (base / "der-verified" / "src").mkdir(parents=True)
        (base / "lean").mkdir()
        evidence = base / "docs" / "requirements" / "evidence"
        evidence.mkdir(parents=True)
        (base / "der-verified" / "src" / "sample.rs").write_text(
            textwrap.dedent(rust), encoding="utf-8"
        )
        (base / "lean" / "MiniProofs.lean").write_text(
            textwrap.dedent(lean), encoding="utf-8"
        )
        (base / "docs" / "requirements" / "der.inventory.toml").write_text(
            textwrap.dedent(inventory), encoding="utf-8"
        )
        (evidence / "sample.toml").write_text(textwrap.dedent(rust_map), encoding="utf-8")
        (evidence / "lean.toml").write_text(textwrap.dedent(lean_map), encoding="utf-8")

    def run_tree(self, base: Path, *extra: str) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, str(CHECKER), "--root", str(base), *extra],
            text=True,
            capture_output=True,
            check=False,
        )

    def run_case(self, **changes: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.make_tree(base, **changes)
            return self.run_tree(base)

    def assert_red(self, needle: str, **changes: str) -> None:
        result = self.run_case(**changes)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(needle, result.stdout)

    def test_passing_minimal_tree(self) -> None:
        result = self.run_case()
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_unreadable_input_is_exit_two(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            result = self.run_tree(Path(directory))
        self.assertEqual(result.returncode, 2, result.stdout + result.stderr)

    def test_toml_parse_failure(self) -> None:
        self.assert_red("TOML parse failure", rust_map="not = [valid")

    def test_missing_entry(self) -> None:
        self.assert_red("missing test entry accepts_a", rust_map=KANI_ENTRY)

    def test_missing_kani_entry(self) -> None:
        self.assert_red("missing kani entry proves_a", rust_map=TEST_ENTRY)

    def test_missing_lean_entry(self) -> None:
        self.assert_red("missing lean entry lean_a", lean_map="")

    def test_duplicate_entry(self) -> None:
        self.assert_red("duplicate test entry accepts_a", rust_map=TEST_ENTRY + TEST_ENTRY + KANI_ENTRY)

    def test_stale_entry(self) -> None:
        stale = TEST_ENTRY.replace('name = "accepts_a"', 'name = "absent"')
        self.assert_red("stale test entry absent", rust_map=TEST_ENTRY + KANI_ENTRY + stale)

    def test_missing_map_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.make_tree(base)
            (base / "docs" / "requirements" / "evidence" / "lean.toml").unlink()
            result = self.run_tree(base)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("missing map file lean.toml", result.stdout)

    def test_stale_map_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.make_tree(base)
            (base / "docs" / "requirements" / "evidence" / "old.toml").write_text("", encoding="utf-8")
            result = self.run_tree(base)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn("stale map file old.toml", result.stdout)

    def test_unknown_requirement_id(self) -> None:
        entry = TEST_ENTRY.replace("accept = []", 'accept = ["NOPE"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        self.assert_red("absent from inventory items", rust_map=entry + KANI_ENTRY)

    def test_non_in_requirement_id(self) -> None:
        entry = TEST_ENTRY.replace("reject = []", 'reject = ["X"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        self.assert_red("disposition 'excluded', not 'in'", rust_map=entry + KANI_ENTRY)

    def test_test_may_not_prove(self) -> None:
        entry = TEST_ENTRY.replace("prove = []", 'prove = ["A"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        self.assert_red("test entries may not use prove", rust_map=entry + KANI_ENTRY)

    def test_lean_uses_only_prove(self) -> None:
        entry = LEAN_ENTRY.replace("accept = []", 'accept = ["A"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        self.assert_red("lean entries may use only prove", lean_map=entry)

    def test_kani_prove_requires_bound(self) -> None:
        entry = KANI_ENTRY.replace("prove = []", 'prove = ["A"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        self.assert_red("Kani prove entries require bounded", rust_map=TEST_ENTRY + entry)

    def test_documented_unbounded_kani_may_omit_bound(self) -> None:
        rust = RUST.replace("    #[kani::proof]\n    fn proves_a", "    /// This harness is unbounded.\n    #[kani::proof]\n    fn proves_a")
        entry = KANI_ENTRY.replace("prove = []", 'prove = ["A"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        result = self.run_case(rust=rust, rust_map=TEST_ENTRY + entry)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_kani_scan_anchors_on_fn_with_attribute_order_variation(self) -> None:
        rust = RUST.replace(
            "    #[kani::proof]\n    fn proves_a",
            "    #[kani::unwind(3)]\n    #[kani::proof_for_contract(target)]\n    fn proves_a",
        )
        result = self.run_case(rust=rust)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)

    def test_empty_lists_require_none(self) -> None:
        entry = TEST_ENTRY.replace('none = "not assigned"', 'none = ""')
        self.assert_red("require a nonempty none", rust_map=entry + KANI_ENTRY)

    def test_citation_requires_empty_none(self) -> None:
        entry = TEST_ENTRY.replace("accept = []", 'accept = ["A"]')
        self.assert_red("none must be empty", rust_map=entry + KANI_ENTRY)

    def test_aggregate_key_is_forbidden(self) -> None:
        self.assert_red("aggregate-like key 'count'", rust_map="count = 1\n" + TEST_ENTRY + KANI_ENTRY)

    def test_malformed_entry_field(self) -> None:
        entry = TEST_ENTRY.replace("accept = []", 'accept = "A"')
        self.assert_red("accept must be a list", rust_map=entry + KANI_ENTRY)

    def test_report_lists_counts_and_kinds(self) -> None:
        test = TEST_ENTRY.replace("accept = []", 'accept = ["A"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        kani = KANI_ENTRY.replace("reject = []", 'reject = ["A"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        lean = LEAN_ENTRY.replace("prove = []", 'prove = ["A"]').replace(
            'none = "not assigned"', 'none = ""'
        )
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            self.make_tree(base, rust_map=test + kani, lean_map=lean)
            result = self.run_tree(base, "--report")
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("A: accept=1 reject=1 prove=1 kinds=kani,lean,test", result.stdout)

    def test_real_files(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER)],
            cwd=ROOT,
            text=True,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
