#!/usr/bin/env python3
"""Gate: no function in the shipped code can recurse (requirement SAFE-resource-2).

WHAT IT CHECKS
--------------
The composition depth of the decoders is statically bounded if the static call graph of the shipped
code has no cycle: every call chain is then a path in a finite acyclic graph, so its length is at
most the number of functions. This gate builds that graph from the source text of
`der-verified/src/*.rs` and fails on any cycle, a function that calls itself included.

How the graph is built (comments, strings, and the `#[cfg(test)]` / `#[cfg(kani)]` items are removed
first, with the same reader as check_no_alloc.py):

  * Nodes are functions, keyed by file and qualified name (`Type::method` inside an `impl`, the bare
    name otherwise). A function nested in another function is its own node; its body is not counted
    as part of the outer function.
  * Bare call `f(...)`: the free function `f` of the same file; else the function brought in by a
    `use crate::module::{f}` of that file; else the single free function `f` of the whole crate.
  * Path call `Self::f(...)`: the method `f` of the enclosing impl type.
  * Path call `module::f(...)` or `crate::module::f(...)`: the free function `f` of that module.
  * Path call `Type::f(...)`: the method `f` of the impl type `Type`, in any file.
  * Method call `.f(...)`: the method `f`, only when exactly one method named `f` is defined in the
    whole crate (uniquely resolvable). A name defined more than once is skipped.

A cycle is a strongly connected component with more than one node, or a node with a self edge
(Tarjan's algorithm, written without recursion).

LIMITS (stated, not hidden)
---------------------------
This is a syntactic check, not a type-checked call graph. It does not resolve:
  * calls made through macros: the text of a macro invocation is scanned like any other code, but a
    macro_rules! definition that expands into a call is not expanded;
  * function pointers and closures stored and called later: a function used as a value, such as
    `map_err(wrap_error)`, is not an edge, and neither is a call through a stored `fn` value;
  * dynamic dispatch and trait-method calls: `.f()` on a trait object, and implicit calls such as
    `Iterator::next` made by a `for` loop, are not resolved;
  * a method name defined more than once in the crate, and a bare name that resolves to several
    functions in different files with no `use` to choose between them.
The crate has no dependencies, so no call leaves the graph through another crate. Because of the
limits above, a pass means no cycle among the calls this reader can resolve. It is the structural
check for SAFE-resource-2, to be read with the Kani unwind bounds that already cap every loop.

Usage:  python3 -I gates/check_no_recursion.py [--root DIR] [--graph]
Exit codes: 0 acyclic, 1 a cycle was found, 2 unreadable input. Pure stdlib.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_no_alloc  # noqa: E402  (shares the Rust reader and the source-file listing)

ROOT = Path(__file__).resolve().parents[1]

FN_RE = re.compile(r"\bfn\s+([A-Za-z_]\w*)")
IMPL_RE = re.compile(r"\bimpl\b")
TRAIT_RE = re.compile(r"\btrait\s+([A-Za-z_]\w*)")
CALL_RE = re.compile(r"(?<![\w.])((?:[A-Za-z_]\w*\s*::\s*)*[A-Za-z_]\w*)\s*(?:::\s*<[^<>]*(?:<[^<>]*>[^<>]*)*>\s*)?\(")
METHOD_RE = re.compile(r"\.\s*([A-Za-z_]\w*)\s*(?:::\s*<[^<>]*(?:<[^<>]*>[^<>]*)*>\s*)?\(")
USE_RE = re.compile(r"\buse\s+crate\s*::\s*([A-Za-z_]\w*)\s*::\s*(\{[^}]*\}|[A-Za-z_]\w*(?:\s+as\s+[A-Za-z_]\w*)?)\s*;")
KEYWORDS = {
    "if", "while", "for", "match", "loop", "return", "fn", "let", "in", "as", "else", "impl", "where",
    "Some", "Ok", "Err", "None", "Self", "self", "super", "crate", "mut", "ref", "move", "dyn", "pub",
    "assert", "assert_eq", "assert_ne", "debug_assert", "debug_assert_eq", "matches", "unreachable",
    "panic", "write", "writeln", "todo", "unimplemented", "cfg",
}


@dataclass
class Func:
    file: str
    qual: str  # `name` or `Type::name`
    name: str
    owner: str  # impl type, "" for a free function
    start: int  # offset of the `fn` keyword
    body: tuple[int, int]  # offsets of `{` and just past `}`
    line: int
    calls_text: str = ""
    edges: set[int] = field(default_factory=set)

    @property
    def label(self) -> str:
        return f"{self.file}::{self.qual}"


def _skip_angles(text: str, start: int) -> int:
    """Index just past the `<...>` group that begins at text[start] (a `<`)."""
    depth = 0
    k = start
    while k < len(text):
        if text[k] == "<":
            depth += 1
        elif text[k] == ">" and not (k > 0 and text[k - 1] == "-"):
            depth -= 1
            if depth == 0:
                return k + 1
        k += 1
    return len(text)


def _impl_owner(header: str) -> str:
    """The type name an `impl` header is for (`impl<T> Tr for Ty<T> where ...` gives `Ty`)."""
    header = re.sub(r"\bwhere\b.*", "", header, flags=re.S)
    out, depth = [], 0
    for ch in header:
        if ch == "<":
            depth += 1
        elif ch == ">" and depth:
            depth -= 1
        elif not depth:
            out.append(ch)
    flat = "".join(out)
    flat = re.sub(r"^\s*impl\b", "", flat)
    if re.search(r"\bfor\b", flat):
        flat = re.split(r"\bfor\b", flat)[-1]
    flat = re.sub(r"\b(?:dyn|mut|const)\b|[&*]", " ", flat)
    names = re.findall(r"[A-Za-z_]\w*", flat)
    return names[-1] if names else ""


def parse_functions(file: str, code: str) -> list[Func]:
    """Find every function with a body in `code`, with its enclosing impl type."""
    owners: list[tuple[int, int, str]] = []  # (open brace, end, type) for impl and trait blocks
    for m in IMPL_RE.finditer(code):
        brace = code.find("{", m.end())
        semi = code.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        owners.append((brace, check_no_alloc._match_bracket(code, brace, "{", "}"), _impl_owner(code[m.start() : brace])))
    for m in TRAIT_RE.finditer(code):
        brace = code.find("{", m.end())
        semi = code.find(";", m.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        owners.append((brace, check_no_alloc._match_bracket(code, brace, "{", "}"), m.group(1)))

    funcs: list[Func] = []
    for m in FN_RE.finditer(code):
        depth = 0
        k = m.end()
        body = None
        while k < len(code):
            c = code[k]
            if c in "([":
                depth += 1
            elif c in ")]":
                depth -= 1
            elif c == "<" and depth == 0:
                k = _skip_angles(code, k)
                continue
            elif c == "{" and depth == 0:
                body = (k, check_no_alloc._match_bracket(code, k, "{", "}"))
                break
            elif c == ";" and depth == 0:
                break
            k += 1
        if body is None:
            continue
        inner = [o for o in owners if o[0] < m.start() < o[1]]
        owner = min(inner, key=lambda o: o[1] - o[0])[2] if inner else ""
        name = m.group(1)
        funcs.append(
            Func(file, f"{owner}::{name}" if owner else name, name, owner, m.start(), body, code.count("\n", 0, m.start()) + 1)
        )
    # A function's own text excludes the bodies of functions nested inside it.
    for f in funcs:
        text = list(code[f.body[0] : f.body[1]])
        for g in funcs:
            if g is not f and f.body[0] < g.start and g.body[1] <= f.body[1]:
                for k in range(g.start - f.body[0], g.body[1] - f.body[0]):
                    if text[k] != "\n":
                        text[k] = " "
        f.calls_text = "".join(text)
    return funcs


def parse_imports(code: str) -> dict[str, str]:
    """Names a file imports with `use crate::module::{a, b as c}`, mapped to the module."""
    imports: dict[str, str] = {}
    for m in USE_RE.finditer(code):
        module, names = m.group(1), m.group(2)
        for part in names.strip("{} \n").split(","):
            part = part.strip()
            if not part or part == "self":
                continue
            local = part.split(" as ")[-1].strip()
            original = part.split(" as ")[0].strip()
            imports[local] = f"{module}\0{original}"
    return imports


@dataclass
class Graph:
    funcs: list[Func]
    edge_count: int


def build_graph(root: Path) -> tuple[Graph | None, int]:
    files = check_no_alloc.source_files(root)
    if files is None:
        return None, 2
    funcs: list[Func] = []
    imports_by_file: dict[str, dict[str, str]] = {}
    for path in files:
        code = check_no_alloc.shipped_code(path)
        if code is None:
            return None, 2
        imports_by_file[path.stem] = parse_imports(code)
        funcs.extend(parse_functions(path.stem, code))

    free_by_file: dict[tuple[str, str], list[int]] = {}
    free_by_name: dict[str, list[int]] = {}
    method_by_owner: dict[tuple[str, str], list[int]] = {}
    method_by_name: dict[str, list[int]] = {}
    for index, f in enumerate(funcs):
        if f.owner:
            method_by_owner.setdefault((f.owner, f.name), []).append(index)
            method_by_name.setdefault(f.name, []).append(index)
        else:
            free_by_file.setdefault((f.file, f.name), []).append(index)
            free_by_name.setdefault(f.name, []).append(index)
    modules = {f.file for f in funcs} | {p.stem for p in files}

    def resolve_bare(f: Func, name: str) -> list[int]:
        if (f.file, name) in free_by_file:
            return free_by_file[(f.file, name)]
        imported = imports_by_file[f.file].get(name)
        if imported:
            module, original = imported.split("\0")
            if (module, original) in free_by_file:
                return free_by_file[(module, original)]
        if len(free_by_name.get(name, [])) == 1:
            return free_by_name[name]
        return []

    for index, f in enumerate(funcs):
        text = f.calls_text
        text = text[text.index("{") :]
        for m in CALL_RE.finditer(text):
            path = [seg.strip() for seg in re.split(r"\s*::\s*", m.group(1))]
            name = path[-1]
            if len(path) == 1:
                if name in KEYWORDS:
                    continue
                # `Name(...)` with a capital letter is a tuple-struct or enum-variant constructor.
                if name[0].isupper():
                    continue
                targets = resolve_bare(f, name)
            else:
                qual = path[-2]
                if qual == "Self":
                    targets = method_by_owner.get((f.owner, name), []) if f.owner else []
                elif qual in modules:
                    targets = free_by_file.get((qual, name), [])
                elif qual[:1].isupper():
                    targets = method_by_owner.get((qual, name), [])
                else:
                    targets = []
            f.edges.update(targets)
        for m in METHOD_RE.finditer(text):
            if f.owner and re.search(r"\bself\s*$", text[: m.start()]) and (f.owner, m.group(1)) in method_by_owner:
                f.edges.update(method_by_owner[(f.owner, m.group(1))])  # `self.f()` stays in the impl
                continue
            candidates = method_by_name.get(m.group(1), [])
            if len(candidates) == 1:
                f.edges.add(candidates[0])
    return Graph(funcs, sum(len(f.edges) for f in funcs)), 0


def find_cycles(funcs: list[Func]) -> list[list[int]]:
    """Strongly connected components that are cycles (size > 1, or one node with a self edge).

    Tarjan's algorithm with an explicit stack, so the gate for 'no recursion' does not recurse.
    """
    index_of: dict[int, int] = {}
    low: dict[int, int] = {}
    on_stack: set[int] = set()
    stack: list[int] = []
    cycles: list[list[int]] = []
    counter = 0
    for root in range(len(funcs)):
        if root in index_of:
            continue
        work = [(root, iter(sorted(funcs[root].edges)))]
        index_of[root] = low[root] = counter
        counter += 1
        stack.append(root)
        on_stack.add(root)
        while work:
            node, it = work[-1]
            advanced = False
            for succ in it:
                if succ not in index_of:
                    index_of[succ] = low[succ] = counter
                    counter += 1
                    stack.append(succ)
                    on_stack.add(succ)
                    work.append((succ, iter(sorted(funcs[succ].edges))))
                    advanced = True
                    break
                if succ in on_stack:
                    low[node] = min(low[node], index_of[succ])
            if advanced:
                continue
            work.pop()
            if work:
                parent = work[-1][0]
                low[parent] = min(low[parent], low[node])
            if low[node] == index_of[node]:
                component = []
                while True:
                    member = stack.pop()
                    on_stack.discard(member)
                    component.append(member)
                    if member == node:
                        break
                if len(component) > 1 or node in funcs[node].edges:
                    cycles.append(sorted(component))
    return cycles


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--graph", action="store_true", help="print every resolved edge")
    args = parser.parse_args(argv)
    graph, status = build_graph(args.root.resolve())
    if graph is None:
        return status
    funcs = graph.funcs
    if args.graph:
        for f in funcs:
            for target in sorted(f.edges):
                print(f"{f.label} -> {funcs[target].label}")
    cycles = find_cycles(funcs)
    if cycles:
        print("FAIL check_no_recursion:")
        for component in cycles:
            print("  call cycle: " + " <-> ".join(f"{funcs[i].label} (line {funcs[i].line})" for i in component))
        return 1
    print(f"check_no_recursion: OK ({len(funcs)} functions, {graph.edge_count} resolved call edges, no cycle)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
