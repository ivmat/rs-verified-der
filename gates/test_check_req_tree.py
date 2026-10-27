#!/usr/bin/env python3
"""Observed-red tests for check_req_tree.py."""

from __future__ import annotations

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
CHECKER = ROOT / "gates" / "check_req_tree.py"
REAL_INVENTORY = ROOT / "docs" / "requirements" / "der.inventory.toml"

MINIMAL = """
[inventory]
id = "x"
title = "x"
source = "x"

[[group]]
id = "DER"
title = "root"

[[item]]
id = "A"
title = "leaf"
ref = "r"
parent = "DER"
force = "contract"
side = "both"
source = "primary"
disposition = "in"
modules = []
"""

SECOND_ITEM = """

[[item]]
id = "B"
title = "second leaf"
ref = "r2"
parent = "DER"
force = "contract"
side = "both"
source = "primary"
disposition = "in"
modules = []
"""


class CheckerTests(unittest.TestCase):
    def run_case(self, inventory: str) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            inv = base / "inventory.toml"
            inv.write_text(textwrap.dedent(inventory), encoding="utf-8")
            return subprocess.run(
                [sys.executable, str(CHECKER), "--inventory", str(inv)],
                text=True, capture_output=True, check=False,
            )

    def assert_red(self, inventory: str, needle: str) -> None:
        result = self.run_case(inventory)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn(needle, result.stdout)

    def test_passing_minimal_tree(self) -> None:
        self.assertEqual(self.run_case(MINIMAL).returncode, 0)

    def test_unreadable_input(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER), "--inventory", "/definitely/absent"],
            text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 2)

    def test_toml_parse_failure(self) -> None:
        self.assert_red("not = [valid", "TOML parse failure")

    def test_missing_inventory_header(self) -> None:
        self.assert_red(MINIMAL.replace("[inventory]", "[wrong]"), "missing [inventory]")

    def test_empty_inventory_field(self) -> None:
        self.assert_red(MINIMAL.replace('title = "x"', 'title = ""', 1), "title must be")

    def test_invalid_id(self) -> None:
        self.assert_red(MINIMAL.replace('id = "A"', 'id = "bad id"') + SECOND_ITEM, "invalid syntax")

    def test_duplicate_across_item_and_group(self) -> None:
        self.assert_red(MINIMAL.replace('id = "A"', 'id = "DER"'), "duplicate id")

    def test_wrong_root(self) -> None:
        self.assert_red(MINIMAL.replace('id = "DER"', 'id = "ROOT"').replace('parent = "DER"', 'parent = "ROOT"'), "exactly one root")

    def test_second_root(self) -> None:
        extra = MINIMAL + '\n[[group]]\nid="OTHER"\ntitle="other"\n[[item]]\nid="C"\ntitle="c"\nref="c"\nparent="OTHER"\nforce="contract"\nside="both"\nsource="primary"\ndisposition="in"\nmodules=[]\n'
        self.assert_red(extra, "exactly one root")

    def test_group_parent_must_be_group(self) -> None:
        bad = MINIMAL + '\n[[group]]\nid="G"\ntitle="g"\nparent="A"\n[[item]]\nid="C"\ntitle="c"\nref="c"\nparent="G"\nforce="contract"\nside="both"\nsource="primary"\ndisposition="in"\nmodules=[]\n'
        self.assert_red(bad, "G: parent")

    def test_item_parent_must_exist(self) -> None:
        self.assert_red(MINIMAL.replace('parent = "DER"', 'parent = "missing"') + SECOND_ITEM, "A: parent")

    def test_group_cycle(self) -> None:
        bad = MINIMAL + '\n[[group]]\nid="G1"\ntitle="g1"\nparent="G2"\n[[group]]\nid="G2"\ntitle="g2"\nparent="G1"\n[[item]]\nid="B"\ntitle="b"\nref="b"\nparent="G1"\nforce="contract"\nside="both"\nsource="primary"\ndisposition="in"\nmodules=[]\n'
        self.assert_red(bad, "cycle detected")

    def test_group_requires_descendant_item(self) -> None:
        bad = MINIMAL + '\n[[group]]\nid="EMPTY"\ntitle="empty"\nparent="DER"\n'
        self.assert_red(bad, "EMPTY: group has no descendant item")

    def test_invalid_firmness(self) -> None:
        self.assert_red(MINIMAL.replace('force = "contract"', 'firmness="soft"\nforce = "contract"'), "invalid firmness")

    def test_invalid_force(self) -> None:
        self.assert_red(MINIMAL.replace('force = "contract"', 'force = "may"'), "invalid force")

    def test_invalid_side(self) -> None:
        self.assert_red(MINIMAL.replace('side = "both"', 'side = "caller"'), "invalid side")

    def test_invalid_disposition(self) -> None:
        self.assert_red(MINIMAL.replace('disposition = "in"', 'disposition = "maybe"'), "invalid disposition")

    def test_non_in_requires_reason(self) -> None:
        self.assert_red(MINIMAL.replace('disposition = "in"', 'disposition = "excluded"'), "requires a nonempty reason")

    def test_aggregate_exact_key(self) -> None:
        self.assert_red(MINIMAL.replace('source = "x"', 'source = "x"\ncount = 1'), "aggregate-like key")

    def test_aggregate_n_prefix(self) -> None:
        self.assert_red(MINIMAL.replace('source = "x"', 'source = "x"\nn_items = 1'), "aggregate-like key")

    def test_real_inventory(self) -> None:
        result = subprocess.run(
            [sys.executable, str(CHECKER), "--inventory", str(REAL_INVENTORY)],
            cwd=ROOT, text=True, capture_output=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
