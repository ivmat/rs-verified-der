#!/usr/bin/env python3
"""Gate: the published tree contains no development-provenance leakage.

This crate was developed in a private repository with internal tooling and review process. Publication
strips those references (see the redaction pass in the initial public commit). This gate makes the strip
*re-runnable and enforced* rather than a one-time manual sweep: it fails the build if any known private
token reappears in a source, proof, doc, or script file. An unrun check is vacuous.

The token list is intentionally specific (private identifiers and absolute home paths), not generic
English, so it does not collide with legitimate crate vocabulary (e.g. "allocation-free" is fine;
"allocation council" is not).

Usage:  python3 gates/check_provenance.py    (run from repo root)
"""
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

# Files/dirs never scanned: build output, vendored toolchains, git, and THIS gate (which necessarily
# contains the token patterns literally).
SKIP_DIR_ANY = {"target", ".lake", ".git", "node_modules", "lake-packages"}
SELF = pathlib.Path(__file__).resolve()
SCAN_SUFFIX = {".rs", ".lean", ".md", ".sh", ".toml", ".py", ".yml", ".yaml", ".lock"}

# Private tokens that must not appear in the public tree. Case-insensitive.
# Each is a distinct dev-process identifier or private path fragment.
BANNED = [
    r"foundry",
    r"\bcouncil\b",
    r"\bfable\b",
    r"\bgemini\b",
    r"\bdeepseek\b",
    r"\bopenai\b",
    r"gpt-?5",
    r"same-lineage",
    r"\bskeptic",
    r"_calibration",
    r"\bcalibration\b",
    r"allocation[ -]council",
    r"engagement[ _-]?ring",
    r"publication[ _-]?sprint",
    r"\brestack\b",
    r"rick[ -]rule",
    r"\bproductivity\b",
    r"\bs01\b",
    r"/Users/",
    # AI-model tiers and the old private repo name — dev-process provenance.
    r"\bopus\b",
    r"\bsonnet\b",
    r"\bhaiku\b",
    r"verified-rs",
]
PATTERNS = [(p, re.compile(p, re.IGNORECASE)) for p in BANNED]


def scan_file(path: pathlib.Path):
    try:
        text = path.read_text(errors="replace")
    except (OSError, UnicodeError):
        return []
    hits = []
    for lineno, line in enumerate(text.splitlines(), 1):
        for pat, rx in PATTERNS:
            if rx.search(line):
                hits.append((lineno, pat, line.strip()[:120]))
    return hits


def main() -> int:
    problems = []
    scanned = 0
    for p in sorted(ROOT.rglob("*")):
        if not p.is_file() or p.resolve() == SELF:
            continue
        rel = p.relative_to(ROOT)
        if any(part in SKIP_DIR_ANY or part.startswith(".") for part in rel.parts[:-1]):
            continue
        # Scan by suffix, plus extensionless scripts with a shell/script shebang (e.g. hooks/pre-commit).
        if p.suffix not in SCAN_SUFFIX:
            if p.suffix == "":
                try:
                    first = p.open("r", errors="replace").readline()
                except OSError:
                    continue
                if not first.startswith("#!"):
                    continue
            else:
                continue
        scanned += 1
        for lineno, pat, snippet in scan_file(p):
            problems.append((rel.as_posix(), lineno, pat, snippet))

    if problems:
        print("FAIL check_provenance: private-development tokens found in the public tree:")
        for rel, lineno, pat, snippet in problems:
            print(f"  {rel}:{lineno}: /{pat}/  ->  {snippet}")
        return 1

    print(f"PASS check_provenance: {scanned} files scanned, no private-development tokens present")
    return 0


if __name__ == "__main__":
    sys.exit(main())
