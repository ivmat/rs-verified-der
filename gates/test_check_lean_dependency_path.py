#!/usr/bin/env python3
"""Tests for check_lean_dependency_path.py."""

from __future__ import annotations

import unittest

import check_lean_dependency_path as gate


LAKEFILE = '''
name = "der-verified-lean"
[[require]]
name = "Aeneas"
path = ".lake/packages/Aeneas"
'''
MANIFEST = '''
{"packages": [{"name": "Aeneas", "dir": ".lake/packages/Aeneas"}]}
'''
SCRIPT = '''
AENEAS_LAKE_LINK="$HERE/.lake/packages/Aeneas"
ln -s "$AENEAS_LEAN" "$AENEAS_LAKE_LINK"
'''


class DependencyPathTests(unittest.TestCase):
    def test_matching_location_independent_paths_pass(self):
        self.assertEqual(gate.check_paths(LAKEFILE, MANIFEST, SCRIPT), [])

    def test_absolute_lakefile_path_fails(self):
        text = LAKEFILE.replace(gate.EXPECTED, "/opt/example/aeneas")
        self.assertTrue(gate.check_paths(text, MANIFEST, SCRIPT))

    def test_stale_manifest_path_fails(self):
        text = MANIFEST.replace(gate.EXPECTED, "../../../Downloads/aeneas")
        self.assertTrue(gate.check_paths(LAKEFILE, text, SCRIPT))

    def test_duplicate_aeneas_requirement_fails(self):
        duplicate = LAKEFILE + '''
[[require]]
name = "Aeneas"
path = ".lake/packages/Aeneas"
'''
        self.assertTrue(gate.check_paths(duplicate, MANIFEST, SCRIPT))

    def test_missing_wrapper_binding_fails(self):
        self.assertTrue(gate.check_paths(LAKEFILE, MANIFEST, ""))


if __name__ == "__main__":
    unittest.main()
