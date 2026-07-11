#!/usr/bin/env python3
"""Gate: every relative markdown link among the repo docs resolves to a real file.

Broken cross-references silently rot the docs. Re-runnable; non-zero on any dangling reference. External
(http/mailto) links and pure `#anchor` fragments are not checked. Fenced code blocks (``` … ```) are
stripped before scanning so link-shaped pseudocode isn't misread as a link. The vendored Lean subproject
(`lean/**`, whose docs live under `.lake`), `target/`, `node_modules/`, `lake-packages/`, and dot-dirs
are skipped.

Usage:  python3 gates/check_links.py    (run from repo root)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
SKIP_PREFIX = ("lean/",)
SKIP_DIR_ANY = {"target", "node_modules", "lake-packages"}
MD_LINK = re.compile(r"\[[^\]]*\]\(([^)]+)\)")  # [text](target)


def skipped(rel: pathlib.PurePosixPath) -> bool:
    if rel.as_posix().startswith(SKIP_PREFIX):
        return True
    return any(p.startswith(".") or p in SKIP_DIR_ANY for p in rel.parts[:-1])


def strip_code_fences(text: str) -> str:
    out, in_fence = [], False
    for ln in text.splitlines():
        if ln.lstrip().startswith("```"):
            in_fence = not in_fence
            out.append("")
            continue
        out.append("" if in_fence else ln)
    return "\n".join(out)


def resolvable(md_file: pathlib.Path, target: str) -> bool:
    t = target.split("#", 1)[0].strip()
    if not t or t.startswith(("http://", "https://", "mailto:")):
        return True
    return (md_file.parent / t).resolve().exists()


def main() -> int:
    problems = []
    md_files = []
    for p in sorted(ROOT.rglob("*.md")):
        rel = pathlib.PurePosixPath(p.relative_to(ROOT).as_posix())
        if skipped(rel):
            continue
        md_files.append(p)
        body = strip_code_fences(p.read_text())
        for m in MD_LINK.finditer(body):
            if not resolvable(p, m.group(1)):
                problems.append((rel, f"broken link -> {m.group(1)}"))

    if problems:
        print("FAIL check_links:")
        for rel, msg in problems:
            print(f"  {rel}: {msg}")
        return 1

    print(f"PASS check_links: {len(md_files)} curated doc files, all relative links resolve")
    return 0


if __name__ == "__main__":
    sys.exit(main())
