#!/usr/bin/env python3
"""Observed-red tests for check_no_alloc.py (the gate's own gate).

Each rule of the gate has one fixture that must fail, plus fixtures that must stay green (comments,
strings, test and proof modules) and a run on the real source tree.
"""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_no_alloc  # noqa: E402

GATE = ROOT / "gates" / "check_no_alloc.py"


def run_on(files: dict[str, str]) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "der-verified" / "src"
        src.mkdir(parents=True)
        for name, text in files.items():
            (src / name).write_text(text)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = check_no_alloc.main(["--root", tmp])
        return code, buffer.getvalue()


# One fixture per rule: (rule name, a function body that uses it).
RED_FIXTURES = {
    "Vec": "pub fn f() -> usize { let v: Vec<u8> = Default::default(); v.len() }",
    "Box": "pub fn f() { let _b: Box<u8>; }",
    "String": "pub fn f() { let _s: String; }",
    "vec!": "pub fn f() { let _v = vec![1u8, 2]; }",
    "format!": "pub fn f() { let _s = format!(\"{}\", 1); }",
    "to_vec": "pub fn f(x: &[u8]) { let _v = x.to_vec(); }",
    "to_owned": "pub fn f(x: &[u8]) { let _v = x.to_owned(); }",
    "to_string": "pub fn f(x: u8) { let _v = x.to_string(); }",
    "collect": "pub fn f(x: &[u8]) { let _v = x.iter().collect(); }",
    "alloc::": "use alloc::vec::Foo;\npub fn f() {}",
    "extern crate alloc": "extern crate alloc;\npub fn f() {}",
    "Rc": "pub fn f() { let _r: Rc<u8>; }",
    "Arc": "pub fn f() { let _r: Arc<u8>; }",
}


class RuleFixtures(unittest.TestCase):
    def test_every_rule_has_a_fixture(self):
        self.assertEqual({name for name, _ in check_no_alloc.RULES}, set(RED_FIXTURES))

    def test_each_rule_fails_on_its_fixture(self):
        for rule, body in RED_FIXTURES.items():
            with self.subTest(rule=rule):
                code, out = run_on({"a.rs": body + "\n"})
                self.assertEqual(code, 1, out)
                self.assertIn(f"`{rule}`", out)
                self.assertIn("a.rs:", out)

    def test_clean_source_passes(self):
        code, out = run_on({"a.rs": "pub fn f(x: &[u8]) -> usize { x.len() }\n"})
        self.assertEqual(code, 0, out)

    def test_word_boundaries(self):
        # `Vector`, `Boxed`, `my_collect` and `Arch` are not the banned tokens.
        body = "pub fn f() { let Vector = 1; let Boxed = 2; let my_collect = 3; let Arch = 4; }\n"
        self.assertEqual(run_on({"a.rs": body})[0], 0)


class NotShippedCode(unittest.TestCase):
    def assertGreen(self, text: str):
        code, out = run_on({"a.rs": text})
        self.assertEqual(code, 0, out)

    def test_comments_are_ignored(self):
        self.assertGreen("// Vec in a line comment\n/// Box in a doc comment\n//! String in a module doc\n"
                         "/* vec![1] in a block /* nested Rc */ still Arc */\npub fn f() {}\n")

    def test_string_and_char_literals_are_ignored(self):
        self.assertGreen('pub fn f() { let _a = "Vec<u8> and format!"; let _b = r#"Box "quoted" String"#; '
                         "let _c = b\"to_vec\"; let _d = '\\''; let _e = '\"'; }\n")

    def test_lifetimes_are_not_char_literals(self):
        # A lifetime must not swallow the code after it: the Vec after the lifetime is still seen.
        code, out = run_on({"a.rs": "pub fn f<'a>(x: &'a [u8]) -> usize { let v: Vec<u8>; x.len() }\n"})
        self.assertEqual(code, 1, out)

    def test_cfg_test_module_is_skipped(self):
        self.assertGreen("pub fn f() {}\n#[cfg(test)]\nmod tests {\n    fn g() { let _v = vec![1u8]; let _s = format!(\"x\"); }\n}\n")

    def test_cfg_kani_module_is_skipped(self):
        self.assertGreen("pub fn f() {}\n#[cfg(kani)]\nmod proofs {\n    fn g() { let _v: Vec<u8>; }\n}\n")

    def test_cfg_any_kani_test_is_skipped(self):
        self.assertGreen("#[cfg(any(kani, test))]\nfn helper() -> Vec<u8> { Default::default() }\npub fn f() {}\n")

    def test_cfg_skips_only_its_own_item(self):
        # The code after the test module is shipped again and is scanned.
        code, out = run_on({"a.rs": "#[cfg(test)]\nmod tests { fn g() { let _v: Vec<u8>; } }\npub fn f() { let _b: Box<u8>; }\n"})
        self.assertEqual(code, 1, out)
        self.assertIn("`Box`", out)
        self.assertNotIn("`Vec`", out)

    def test_cfg_not_test_stays_scanned(self):
        code, out = run_on({"a.rs": "#[cfg(not(test))]\nfn g() { let _v: Vec<u8>; }\n"})
        self.assertEqual(code, 1, out)

    def test_cfg_on_a_semicolon_item_with_array_type(self):
        # `[u8; 3]` holds a semicolon that is not the end of the item.
        code, out = run_on({"a.rs": "#[cfg(test)]\nconst X: [u8; 3] = [1, 2, 3];\npub fn f() { let _s: String; }\n"})
        self.assertEqual(code, 1, out)
        self.assertIn("`String`", out)


class InputErrors(unittest.TestCase):
    def test_missing_source_tree_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                code = check_no_alloc.main(["--root", tmp])
            self.assertEqual(code, 2)

    def test_empty_source_tree_exits_2(self):
        self.assertEqual(run_on({})[0], 2)


class RealTree(unittest.TestCase):
    def test_real_tree_is_clean(self):
        done = subprocess.run([sys.executable, "-I", str(GATE)], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
        self.assertIn(" source files, ", done.stdout)

    def test_real_tree_scan_reads_code(self):
        # Guard against a vacuous pass: the reader must keep real code and drop the test modules.
        code = check_no_alloc.shipped_code(ROOT / "der-verified" / "src" / "x509_spki.rs")
        self.assertIn("pub fn parse_subject_public_key_info", code)
        self.assertNotIn("mod tests", code)
        self.assertNotIn("mod proofs", code)
        self.assertNotIn("fn rejects_public_key_identifier_04", code)


if __name__ == "__main__":
    unittest.main()
