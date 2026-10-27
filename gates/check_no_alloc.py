#!/usr/bin/env python3
"""Gate: the decode paths allocate no heap memory (requirement SAFE-resource-1).

WHAT IT CHECKS
--------------
Every `der-verified/src/*.rs` file is read as source text. Comments, string literals and character
literals are blanked first, then every item guarded by a `#[cfg(...)]` attribute that names `test`
or `kani` (the `#[cfg(test)]` test modules and the `#[cfg(kani)]` proof modules) is blanked too.
What is left is the code that ships. The gate fails if that code contains any of these tokens:

    Vec  Box  String  Rc  Arc            (heap-owning types)
    vec!  format!                          (allocating macros)
    to_vec  to_owned  to_string  collect   (allocating methods)
    alloc::  extern crate alloc            (the `alloc` crate)

The crate reaches the same result by construction (it keeps no `alloc` dependency), and this gate
turns that into a fixed, re-runnable structural check: a later edit that brings in an allocating
type fails here, in the per-commit `check_fast.sh`.

LIMITS (stated, not hidden)
---------------------------
  * It is a token scan, not a type check. An allocation that does not name one of the tokens above
    (for example a call into another crate that allocates, or a type alias to `Vec` declared
    elsewhere) is not seen. The crate has no dependencies, so the first case cannot arise today.
  * A token inside a macro_rules! body is scanned like any other code.
  * `#[cfg(...)]` predicates are read by word: an item whose predicate names `test` or `kani`
    outside a `not(...)` is treated as test or proof code and is skipped. `cfg(not(test))` stays
    scanned.
  * Doc comments and doctests are comments. They are not shipped code and are not scanned.

Usage:  python3 -I gates/check_no_alloc.py [--root DIR]
Exit codes: 0 clean, 1 an allocating token was found, 2 unreadable input. Pure stdlib.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

# (rule name, pattern). Each rule has one observed-red fixture in test_check_no_alloc.py.
RULES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("Vec", re.compile(r"\bVec\b")),
    ("Box", re.compile(r"\bBox\b")),
    ("String", re.compile(r"\bString\b")),
    ("vec!", re.compile(r"\bvec\s*!")),
    ("format!", re.compile(r"\bformat\s*!")),
    ("to_vec", re.compile(r"\bto_vec\b")),
    ("to_owned", re.compile(r"\bto_owned\b")),
    ("to_string", re.compile(r"\bto_string\b")),
    ("collect", re.compile(r"\bcollect\b")),
    ("alloc::", re.compile(r"\balloc\s*::")),
    ("extern crate alloc", re.compile(r"\bextern\s+crate\s+alloc\b")),
    ("Rc", re.compile(r"\bRc\b")),
    ("Arc", re.compile(r"\bArc\b")),
)

RAW_STRING_RE = re.compile(r'(?:br|r)(#*)"')
CFG_ATTR_RE = re.compile(r"#\s*\[\s*cfg\s*\(")


def _blank(text: str, start: int, end: int) -> str:
    """Replace text[start:end] by spaces, keeping newlines so line numbers survive."""
    return text[:start] + re.sub(r"[^\n]", " ", text[start:end]) + text[end:]


def strip_rust(text: str) -> str:
    """Blank comments and the interior of string and character literals; keep line structure.

    Handles nested block comments, raw strings (`r"..."`, `r#"..."#`, `br"..."`), byte strings,
    escapes, and the lifetime-versus-character-literal ambiguity of `'`.
    """
    out = list(text)
    n = len(text)
    i = 0

    def blank(a: int, b: int) -> None:
        for k in range(a, min(b, n)):
            if out[k] != "\n":
                out[k] = " "

    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = text.find("\n", i)
            j = n if j < 0 else j
            blank(i, j)
            i = j
        elif c == "/" and nxt == "*":
            depth = 1
            j = i + 2
            while j < n and depth:
                if text.startswith("/*", j):
                    depth += 1
                    j += 2
                elif text.startswith("*/", j):
                    depth -= 1
                    j += 2
                else:
                    j += 1
            blank(i, j)
            i = j
        elif c in "rb" and (i == 0 or not (text[i - 1].isalnum() or text[i - 1] == "_")):
            m = RAW_STRING_RE.match(text, i)
            if m:
                closer = '"' + m.group(1)
                j = text.find(closer, m.end())
                j = n if j < 0 else j + len(closer)
                blank(m.end(), j - len(closer))
                i = j
            else:
                i += 1  # a plain identifier, or a b"..." / b'...' literal handled on the next pass
        elif c == '"':
            j = i + 1
            while j < n and text[j] != '"':
                j += 2 if text[j] == "\\" else 1
            blank(i + 1, j)
            i = j + 1
        elif c == "'":
            if nxt == "\\":
                j = text.find("'", i + 2)
                if j >= 0 and j - i <= 12:
                    blank(i + 1, j)
                    i = j + 1
                else:
                    i += 1
            elif i + 2 < n and text[i + 2] == "'" and nxt != "'":
                blank(i + 1, i + 2)
                i += 3
            else:
                i += 1  # a lifetime such as 'a
        else:
            i += 1
    return "".join(out)


def _match_bracket(text: str, start: int, open_ch: str, close_ch: str) -> int:
    """Index just past the bracket that closes the one at text[start]; len(text) if unbalanced."""
    depth = 0
    for k in range(start, len(text)):
        if text[k] == open_ch:
            depth += 1
        elif text[k] == close_ch:
            depth -= 1
            if depth == 0:
                return k + 1
    return len(text)


def _is_test_or_proof_predicate(pred: str) -> bool:
    """True if a cfg predicate names `test` or `kani` outside any `not(...)`."""
    if re.search(r"\bnot\s*\(", pred):
        return False
    return bool(re.search(r"\b(?:test|kani)\b", pred))


def _item_end(text: str, start: int) -> int:
    """End of the item or statement that begins at `start` (after its attributes)."""
    n = len(text)
    k = start
    while k < n and text[k].isspace():
        k += 1
    while text.startswith("#", k) and text[k + 1 : k + 3].lstrip().startswith("["):
        k = _match_bracket(text, text.index("[", k), "[", "]")
        while k < n and text[k].isspace():
            k += 1
    depth = 0  # () and [] nesting
    while k < n:
        c = text[k]
        if c in "([":
            depth += 1
        elif c in ")]":
            depth -= 1
        elif c == "{" and depth == 0:
            return _match_bracket(text, k, "{", "}")
        elif c == ";" and depth == 0:
            return k + 1
        k += 1
    return n


def drop_cfg_items(stripped: str) -> str:
    """Blank every item or statement guarded by a cfg attribute that names `test` or `kani`."""
    text = stripped
    pos = 0
    while True:
        m = CFG_ATTR_RE.search(text, pos)
        if not m:
            return text
        open_paren = m.end() - 1
        close = _match_bracket(text, open_paren, "(", ")")
        attr_end = text.find("]", close)
        attr_end = len(text) if attr_end < 0 else attr_end + 1
        if _is_test_or_proof_predicate(text[open_paren:close]):
            end = _item_end(text, attr_end)
            text = _blank(text, m.start(), end)
            pos = end
        else:
            pos = attr_end


def shipped_code(path: Path) -> str | None:
    """The comment-free, test-free, proof-free code of one source file, or None if unreadable."""
    try:
        raw = path.read_text(encoding="utf-8")
    except (OSError, UnicodeError) as exc:
        print(f"{path.name}: unreadable input: {exc}")
        return None
    return drop_cfg_items(strip_rust(raw))


def source_files(root: Path) -> list[Path] | None:
    src = root / "der-verified" / "src"
    if not src.is_dir():
        print(f"source tree: unreadable input: {src} is missing")
        return None
    files = sorted(src.glob("*.rs"))
    if not files:
        print(f"source tree: unreadable input: {src} has no .rs files")
        return None
    return files


def scan(root: Path) -> tuple[list[str] | None, int]:
    """Return (findings, file count), or (None, 0) on unreadable input."""
    files = source_files(root)
    if files is None:
        return None, 0
    findings: list[str] = []
    for path in files:
        code = shipped_code(path)
        if code is None:
            return None, 0
        for number, line in enumerate(code.splitlines(), 1):
            for name, pattern in RULES:
                if pattern.search(line):
                    findings.append(f"{path.name}:{number}: heap allocation token `{name}`: {line.strip()}")
    return findings, len(files)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    findings, count = scan(args.root.resolve())
    if findings is None:
        return 2
    if findings:
        print("FAIL check_no_alloc:")
        for finding in findings:
            print(f"  {finding}")
        return 1
    print(f"check_no_alloc: OK ({count} source files, no heap-allocation token in shipped code)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
