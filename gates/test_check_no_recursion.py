#!/usr/bin/env python3
"""Observed-red tests for check_no_recursion.py (the gate's own gate).

Each cycle shape the gate resolves has one fixture that must fail; fixtures that must stay green
cover acyclic code, same-named functions in different files, test and proof code, and comments. The
last class runs the gate on the real source tree.
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
import check_no_recursion  # noqa: E402

GATE = ROOT / "gates" / "check_no_recursion.py"


def run_on(files: dict[str, str], *extra: str) -> tuple[int, str]:
    with tempfile.TemporaryDirectory() as tmp:
        src = Path(tmp) / "der-verified" / "src"
        src.mkdir(parents=True)
        for name, text in files.items():
            (src / name).write_text(text)
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = check_no_recursion.main(["--root", tmp, *extra])
        return code, buffer.getvalue()


class RedFixtures(unittest.TestCase):
    def assertCycle(self, files: dict[str, str], *labels: str):
        code, out = run_on(files)
        self.assertEqual(code, 1, out)
        self.assertIn("call cycle", out)
        for label in labels:
            self.assertIn(label, out)

    def test_self_call(self):
        self.assertCycle({"a.rs": "pub fn f(n: u8) -> u8 { if n == 0 { 0 } else { f(n - 1) } }\n"}, "a::f")

    def test_mutual_recursion(self):
        self.assertCycle(
            {"a.rs": "fn f(n: u8) -> u8 { g(n) }\nfn g(n: u8) -> u8 { f(n) }\n"}, "a::f", "a::g"
        )

    def test_three_cycle_behind_an_acyclic_entry(self):
        text = (
            "pub fn entry() { a1() }\nfn a1() { a2() }\nfn a2() { a3() }\nfn a3() { a1() }\n"
        )
        code, out = run_on({"a.rs": text})
        self.assertEqual(code, 1, out)
        self.assertNotIn("a::entry", out)  # the entry reaches the cycle but is not on it
        for name in ("a1", "a2", "a3"):
            self.assertIn(f"a::{name}", out)

    def test_cycle_across_files_through_a_module_path(self):
        self.assertCycle(
            {"a.rs": "pub fn f() { b::g() }\n", "b.rs": "pub fn g() { crate::a::f() }\n"}, "a::f", "b::g"
        )

    def test_cycle_across_files_through_a_use_import(self):
        self.assertCycle(
            {
                "a.rs": "use crate::b::g;\npub fn f() { g() }\n",
                "b.rs": "use crate::a::{f};\npub fn g() { f() }\n",
            },
            "a::f",
            "b::g",
        )

    def test_cycle_through_a_uniquely_named_free_function(self):
        self.assertCycle(
            {"a.rs": "pub fn f() { only_here() }\n", "b.rs": "pub fn only_here() { f() }\n"}, "a::f", "b::only_here"
        )

    def test_method_calling_itself_through_self_path(self):
        text = "struct S;\nimpl S {\n    fn f(&self) { Self::f(self) }\n}\n"
        self.assertCycle({"a.rs": text}, "a::S::f")

    def test_method_cycle_through_self_receiver(self):
        text = "struct S;\nimpl S {\n    fn f(&self) { self.g() }\n    fn g(&self) { self.f() }\n}\n"
        self.assertCycle({"a.rs": text}, "a::S::f", "a::S::g")

    def test_method_cycle_through_a_type_path(self):
        text = "struct S;\nstruct T;\nimpl S { fn f() { T::g() } }\nimpl T { fn g() { S::f() } }\n"
        self.assertCycle({"a.rs": text}, "a::S::f", "a::T::g")

    def test_method_cycle_through_a_uniquely_named_method(self):
        text = "struct S;\nimpl S { fn step(&self, o: &S) { o.walk() } fn walk(&self) { self.step(self) } }\n"
        self.assertCycle({"a.rs": text}, "a::S::step", "a::S::walk")

    def test_trait_impl_method_is_a_node(self):
        text = "struct S;\nimpl Iterator for S {\n    type Item = u8;\n    fn next(&mut self) -> Option<u8> { self.next() }\n}\n"
        self.assertCycle({"a.rs": text}, "a::S::next")

    def test_cycle_inside_a_closure_counts_for_the_enclosing_function(self):
        self.assertCycle({"a.rs": "pub fn f(x: Option<u8>) { x.map(|v| { f(Some(v)); }); }\n"}, "a::f")

    def test_call_in_a_macro_argument_counts(self):
        self.assertCycle({"a.rs": "pub fn f(n: u8) { assert!(n == 0 || f(n - 1) == ()); }\n"}, "a::f")

    def test_nested_fn_cycle_is_found_and_outer_is_not_blamed(self):
        text = "pub fn outer() { fn inner() { inner() } inner() }\n"
        code, out = run_on({"a.rs": text})
        self.assertEqual(code, 1, out)
        self.assertIn("a::inner", out)
        self.assertNotIn("a::outer (line", out)

    def test_generic_function_self_call(self):
        self.assertCycle({"a.rs": "pub fn f<T: Copy>(x: T) -> T { f::<T>(x) }\n"}, "a::f")


class GreenFixtures(unittest.TestCase):
    def assertGreen(self, files: dict[str, str]):
        code, out = run_on(files)
        self.assertEqual(code, 0, out)
        self.assertIn("no cycle", out)

    def test_acyclic_chain(self):
        self.assertGreen({"a.rs": "pub fn f() { g() }\nfn g() { h() }\nfn h() {}\n"})

    def test_diamond_is_not_a_cycle(self):
        self.assertGreen({"a.rs": "fn top() { l(); r() }\nfn l() { bot() }\nfn r() { bot() }\nfn bot() {}\n"})

    def test_same_name_in_two_files_is_not_conflated(self):
        # a::decode calls b::decode by path. If the two `decode`s shared one node this would look
        # like a self call; keyed by file they are two nodes and the graph is acyclic.
        self.assertGreater(
            run_on({"a.rs": "pub fn decode() { crate::b::decode() }\n", "b.rs": "pub fn decode() {}\n"}, "--graph")[1].count("a::decode -> b::decode"),
            0,
        )
        self.assertGreen({"a.rs": "pub fn decode() { crate::b::decode() }\n", "b.rs": "pub fn decode() {}\n"})

    def test_method_with_the_same_name_as_a_free_function(self):
        text = "fn next() {}\nstruct S;\nimpl S { fn next(&self) { next() } }\n"
        self.assertGreen({"a.rs": text})

    def test_recursion_only_in_test_code_is_ignored(self):
        text = "pub fn f() {}\n#[cfg(test)]\nmod tests {\n    fn r(n: u8) { r(n) }\n}\n"
        self.assertGreen({"a.rs": text})

    def test_recursion_only_in_proof_code_is_ignored(self):
        text = "pub fn f() {}\n#[cfg(kani)]\nmod proofs {\n    fn r(n: u8) { r(n) }\n}\n"
        self.assertGreen({"a.rs": text})

    def test_recursion_in_comments_and_strings_is_ignored(self):
        text = '// fn f() { f() }\n/// f() calls f()\npub fn f() { let _s = "f()"; }\n'
        self.assertGreen({"a.rs": text})

    def test_ambiguous_method_name_is_skipped(self):
        # Two methods named `step`: `.step()` is not resolvable, so no edge and no cycle is claimed.
        text = "struct S;\nstruct T;\nimpl S { fn step(&self, t: &T) { t.step() } }\nimpl T { fn step(&self) {} }\n"
        # Both are named `step`, so the unique-name rule skips the call; T::step has no body calls.
        self.assertGreen({"a.rs": text})

    def test_constructors_and_variants_are_not_calls(self):
        text = "struct W(u8);\nenum E { A(u8) }\npub fn f() -> W { let _e = E::A(1); W(2) }\n"
        self.assertGreen({"a.rs": text})


class Reader(unittest.TestCase):
    def test_graph_flag_prints_edges(self):
        code, out = run_on({"a.rs": "pub fn f() { g() }\nfn g() {}\n"}, "--graph")
        self.assertEqual(code, 0)
        self.assertIn("a::f -> a::g", out)

    def test_missing_source_tree_exits_2(self):
        with tempfile.TemporaryDirectory() as tmp:
            buffer = io.StringIO()
            with contextlib.redirect_stdout(buffer):
                self.assertEqual(check_no_recursion.main(["--root", tmp]), 2)

    def test_tarjan_does_not_recurse_on_a_long_chain(self):
        # 3000 functions in a line, closed into a ring at the end: found without a recursion error.
        n = 3000
        lines = [f"fn f{i}() {{ f{i + 1}() }}" for i in range(n - 1)] + [f"fn f{n - 1}() {{ f0() }}"]
        code, out = run_on({"a.rs": "\n".join(lines) + "\n"})
        self.assertEqual(code, 1, out[:200])


class RealTree(unittest.TestCase):
    def test_real_tree_has_no_cycle(self):
        done = subprocess.run([sys.executable, "-I", str(GATE)], capture_output=True, text=True, cwd=ROOT)
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_real_graph_is_not_vacuous(self):
        graph, status = check_no_recursion.build_graph(ROOT)
        self.assertEqual(status, 0)
        self.assertGreater(len(graph.funcs), 100)
        self.assertGreater(graph.edge_count, 100)
        edges = {(graph.funcs[i].label, graph.funcs[j].label) for i in range(len(graph.funcs)) for j in graph.funcs[i].edges}
        # Bare call resolved through `use`, a module-path call, and a unique method call.
        self.assertIn(("x509_spki::decode_public_key_tlv", "tlv::decode_tlv"), edges)
        self.assertIn(("x509_spki::parse_subject_public_key_info", "x509_algorithm_identifier::parse_algorithm_identifier"), edges)
        self.assertIn(("x509_spki::parse_subject_public_key_info", "x509_spki::decode_public_key_tlv"), edges)
        self.assertIn(("set_of::decode_set_of", "sequence::Elements::next"), edges)
        # Test and proof functions are not nodes.
        labels = {f.label for f in graph.funcs}
        self.assertNotIn("x509_spki::parse_never_panics", labels)
        self.assertNotIn("x509_spki::spki_with_key_identifier", labels)


if __name__ == "__main__":
    unittest.main()
