#!/usr/bin/env python3
"""Applicability check for the leaf-sweep mutation controls (no Kani, no writes to the tree).

usage: check_applicability.py TREE [--spec SPEC.json ...] [--md] [--strict-stale]

TREE is a checkout of the crate repo (the dir that contains `der-verified/`), e.g.
`~/repo_tmp/der-coverage-w1-r2` or the final integration worktree. For every control it checks,
exactly as `run_controls.py` and the harness set require:

  1. the spec entry is well formed (keys, id/module charset, unique ids, old != new,
     red non-empty, red and green disjoint, src repo-relative);
  2. `src` exists in TREE and `old` occurs EXACTLY ONCE in it (runner rule: count over the whole
     file, `str.count`, so overlapping/duplicate text in `mod proofs` also fails it);
  3. every `red`/`green` harness `<module>::proofs::<fn>` exists as `fn <fn>` inside the
     `#[cfg(kani)] mod proofs` block of `der-verified/src/<module>.rs` and carries a
     `#[kani::proof...]` attribute.

Default specs: `spec-leaf-sweep.json` (runnable: status applicable / re-anchored) and
`spec-leaf-sweep-stale.json` (status stale; never fed to the runner) next to this script.
Exit code: 0 when every non-stale control is applicable; 1 otherwise. A stale control that has
become applicable again is reported (WARN) and, with --strict-stale, also exits 1.
`--md` prints the applicability table as markdown (used in README.md).
Python 3 stdlib only.
"""
import argparse
import json
import os
import re
import sys

ID_RE = re.compile(r"^[A-Za-z0-9_.-]+$")
HERE = os.path.dirname(os.path.abspath(__file__))
REQUIRED = ("id", "module", "src", "old", "new", "red")


def proofs_block(text):
    """Return text from the first `#[cfg(kani)]` line that precedes `mod proofs` to EOF
    (the proofs block is the last item of each leaf file)."""
    m = re.search(r"^#\[cfg\(kani\)\]\s*\nmod proofs\s*\{", text, re.M)
    return None if m is None else text[m.start():]


def harness_ok(tree, harness, cache):
    """Return (ok, reason)."""
    parts = harness.split("::")
    if len(parts) != 3 or parts[1] != "proofs":
        return False, "harness id not `<module>::proofs::<fn>`"
    module, _, fn = parts
    path = os.path.join(tree, "der-verified", "src", module + ".rs")
    if path not in cache:
        cache[path] = open(path, encoding="utf-8").read() if os.path.exists(path) else None
    text = cache[path]
    if text is None:
        return False, f"no file der-verified/src/{module}.rs"
    block = proofs_block(text)
    if block is None:
        return False, f"{module}.rs has no `#[cfg(kani)] mod proofs`"
    m = re.search(r"^[ \t]*(?:pub\s+)?fn\s+" + re.escape(fn) + r"\s*[(<]", block, re.M)
    if m is None:
        return False, f"fn {fn} not in {module}::proofs"
    # walk back over attributes / doc comments / blank lines to find #[kani::proof]
    lines = block[:m.start()].splitlines()
    saw_proof = False
    for ln in reversed(lines):
        s = ln.strip()
        if s.startswith("#[kani::proof"):
            saw_proof = True
        if s.startswith("#[") or s.startswith("//") or s == "":
            continue
        break
    if not saw_proof:
        return False, f"fn {fn} has no #[kani::proof] attribute"
    return True, ""


def check_control(c, tree, cache, seen_ids):
    problems = []
    for k in REQUIRED:
        if k not in c:
            problems.append(f"missing key {k!r}")
    if problems:
        return problems, 0
    if not ID_RE.match(c["id"]) or not ID_RE.match(c["module"]):
        problems.append("id/module charset")
    if c["id"] in seen_ids:
        problems.append("duplicate id")
    seen_ids.add(c["id"])
    if c["old"] == c["new"]:
        problems.append("old == new")
    if not c["red"]:
        problems.append("red empty")
    if set(c["red"]) & set(c.get("green", [])):
        problems.append("harness in both red and green")
    if os.path.isabs(c["src"]) or ".." in c["src"].split("/"):
        problems.append("src not repo-relative")
    n = 0
    sp = os.path.join(tree, c["src"])
    if not os.path.exists(sp):
        problems.append(f"src missing: {c['src']}")
    else:
        if sp not in cache:
            cache[sp] = open(sp, encoding="utf-8").read()
        n = cache[sp].count(c["old"])
        if n != 1:
            problems.append(f"`old` occurs {n} times (need exactly 1)")
    for h in list(c["red"]) + list(c.get("green", [])):
        ok, why = harness_ok(tree, h, cache)
        if not ok:
            problems.append(f"harness {h}: {why}")
    return problems, n


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("tree")
    ap.add_argument("--spec", action="append", default=None)
    ap.add_argument("--md", action="store_true")
    ap.add_argument("--strict-stale", action="store_true")
    a = ap.parse_args()
    tree = os.path.abspath(os.path.expanduser(a.tree))
    if not os.path.isdir(os.path.join(tree, "der-verified", "src")):
        print(f"{tree}: no der-verified/src", file=sys.stderr)
        return 2
    specs = a.spec or [os.path.join(HERE, "spec-leaf-sweep.json"),
                       os.path.join(HERE, "spec-leaf-sweep-stale.json")]
    cache, seen = {}, set()
    rows, bad, warn = [], 0, 0
    for sp in specs:
        if not os.path.exists(sp):
            continue
        for c in json.load(open(sp, encoding="utf-8")):
            status = c.get("status", "applicable")
            problems, n = check_control(c, tree, cache, seen)
            if status == "stale":
                verdict = "stale (confirmed)" if problems else "WARN stale-but-applicable"
                if not problems:
                    warn += 1
            else:
                verdict = "OK" if not problems else "FAIL"
                if problems:
                    bad += 1
            rows.append((c.get("id", "?"), c.get("module", "?"), status, n,
                         len(c.get("red", [])) + len(c.get("green", [])), verdict, problems,
                         bool(c.get("profile_flag"))))
    if a.md:
        print("| id | module | status | `old` count | harnesses | check | profile-flag |")
        print("|---|---|---|---|---|---|---|")
        for r in rows:
            print(f"| {r[0]} | {r[1]} | {r[2]} | {r[3]} | {r[4]} | {r[5]} | {'yes' if r[7] else ''} |")
    else:
        for r in rows:
            print(f"{r[5]:<26} {r[0]:<34} {r[1]:<18} status={r[2]:<12} old_count={r[3]}")
            for p in r[6]:
                print(f"    - {p}")
    ok_n = sum(1 for r in rows if r[5] == "OK")
    print(f"\ntree: {tree}\ncontrols: {len(rows)}  OK: {ok_n}  FAIL: {bad}  "
          f"stale-confirmed: {sum(1 for r in rows if r[5].startswith('stale'))}  warn: {warn}",
          file=sys.stderr if a.md else sys.stdout)
    if bad or (a.strict_stale and warn):
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
