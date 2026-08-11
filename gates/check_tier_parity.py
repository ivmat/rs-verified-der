#!/usr/bin/env python3
"""check_tier_parity.py -- the tractability split is DATA, so gate it.

`gates/tiers.txt` says which Kani modules are LIGHT (fit a ~7 GB runner; run by CI and by
./check_tractable.sh) and which are HEAVY (need up to ~24 GB; run only by ./check.sh). Three
things can silently rot, and each one is checked here:

  1. CI's shard filters drift away from the LIGHT set -- then check_tractable.sh stops being
     "the same share CI runs", which is the only reason to trust it as a stand-in.
  2. A NEW harnessed module lands in NEITHER tier. That is the dangerous one: it would be absent
     from CI *and* absent from the heavy list, so nothing would ever flag that it is unverified.
  3. A module listed in a tier no longer exists (renamed/removed), leaving a filter that silently
     matches nothing -- a Kani `--harness` filter with no match is not an error.

Pure stdlib, no network, sub-second -- same contract as this repo's other gates.

Exit 0 = pass, 1 = fail.  `--selftest` runs the positive controls: a gate that cannot fail is
vacuous, so each of the three checks is shown catching a planted fault.
"""
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TIERS = ROOT / "gates" / "tiers.txt"
CI = ROOT / ".github" / "workflows" / "ci.yml"
SRC = ROOT / "der-verified" / "src"

BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
LINE_COMMENT = re.compile(r"//[^\n]*")
PROOF_ATTR = re.compile(r"#\[\s*kani::proof")


def strip_comments(text: str) -> str:
    """Remove comments so a `kani::proof` MENTIONED in prose is not counted as a harness.
    This repo has already published three wrong counts from naive greps; do not add a fourth."""
    return LINE_COMMENT.sub("", BLOCK_COMMENT.sub("", text))


def read_tiers(path: Path = TIERS):
    light, heavy = [], []
    for lineno, raw in enumerate(path.read_text().splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        if len(parts) != 2 or parts[0] not in ("LIGHT", "HEAVY"):
            raise SystemExit(f"FAIL check_tier_parity: {path.name}:{lineno}: "
                             f"expected '<LIGHT|HEAVY> <module>', got {raw!r}")
        (light if parts[0] == "LIGHT" else heavy).append(parts[1])
    return light, heavy


def _block_under(text: str, key_re: str):
    """The lines strictly nested under the FIRST line matching `key_re` (indented more than it), up to
    the next line at the same-or-lesser indent. Shared by the kani-job and matrix-include scoping."""
    lines, out, base_indent = text.splitlines(), [], None
    for l in lines:
        m = re.match(key_re, l)
        if base_indent is None:
            if m:
                base_indent, out = len(m.group(1)), []
            continue
        if l.strip() and (len(l) - len(l.lstrip())) <= base_indent:
            break
        out.append(l)
    return "\n".join(out)


def _kani_job_text(text: str):
    """The body of the `kani:` job only -- so a `filters:` key in ANOTHER job cannot supply a phantom
    module to the parity set (which would mask that module's omission from the real Kani matrix). A
    trailing `# comment` on the `kani:` header is tolerated."""
    return _block_under(text, r"(\s*)kani:\s*(#.*)?$")


def _matrix_include_text(text: str):
    """The kani job's `matrix:` -> `include:` list block -- so a `filters:`-looking line inside some
    OTHER block scalar (a `run: |` step body, a description) is not read as a matrix key. Scoped
    THROUGH `matrix:` first, then `include:` within it, so even a stray bare `include:` in a step body
    (not nested under `matrix:`) is excluded. The real shard filters are list items directly under the
    matrix's `include:`; nothing else is."""
    matrix = _block_under(_kani_job_text(text), r"(\s*)matrix:\s*(#.*)?$")
    return _block_under(matrix, r"(\s*)include:\s*(#.*)?$")


def _strip_inline_comment(line: str):
    """Drop a trailing YAML `# ...` comment. A `--harness <mod>::` filter never contains `#`, so a
    ` #`-preceded run is always a comment -- e.g. `filters: >-  # --harness phantom::` must not leak
    `phantom` into the set."""
    return re.sub(r"\s+#.*$", "", line)


def _filters_blocks(text: str):
    """The text of every `filters:` scalar in the kani matrix's `include:` list (the shard filters),
    as (folded or inline) YAML block values. Scoping to the `kani:` job's `matrix: include:` block AND
    to `filters:` keys within it is what stops a stray `--harness` ANYWHERE else -- another job, an
    `echo`/`run:` step body, a prose or inline comment -- from being miscounted as a shard filter.
    Commented-out lines (the kani-heavy job) are dropped first."""
    lines = [_strip_inline_comment(l) for l in _matrix_include_text(text).splitlines()
             if not l.lstrip().startswith("#")]
    blocks, i = [], 0
    while i < len(lines):
        m = re.match(r"(\s*)filters:\s*(.*)$", lines[i])
        if not m:
            i += 1
            continue
        key_indent, buf, i = len(m.group(1)), [m.group(2)], i + 1
        # A block scalar continues while its lines are indented MORE than the `filters:` key.
        while i < len(lines):
            if lines[i].strip() == "":
                i += 1
                continue
            if len(lines[i]) - len(lines[i].lstrip()) <= key_indent:
                break
            buf.append(lines[i])
            i += 1
        blocks.append("\n".join(buf))
    return blocks


def ci_filter_modules(text: str):
    """Modules named by `--harness <mod>::` inside the kani job's `filters:` scalars only (NOT the
    whole workflow -- see `_filters_blocks`)."""
    joined = "\n".join(_filters_blocks(text))
    return sorted(set(re.findall(r"--harness\s+([A-Za-z0-9_]+)::", joined)))


def harnessed_modules(src: Path):
    """Every module with at least one real (non-comment) #[kani::proof...] attribute."""
    out = set()
    for f in sorted(src.glob("*.rs")):
        if PROOF_ATTR.search(strip_comments(f.read_text())):
            out.add(f.stem)
    return out


def check(tiers_path=TIERS, ci_text=None, src=SRC):
    errs = []
    light, heavy = read_tiers(tiers_path)
    ci_text = CI.read_text() if ci_text is None else ci_text

    dupes = sorted(set(light) & set(heavy))
    if dupes:
        errs.append(f"module(s) in BOTH tiers: {dupes}")

    ci_mods = set(ci_filter_modules(ci_text))
    if ci_mods != set(light):
        only_ci = sorted(ci_mods - set(light))
        only_tier = sorted(set(light) - ci_mods)
        errs.append("CI shard filters != LIGHT tier"
                    + (f"; in ci.yml only: {only_ci}" if only_ci else "")
                    + (f"; in tiers.txt only: {only_tier}" if only_tier else ""))

    declared = set(light) | set(heavy)
    actual = harnessed_modules(src)
    missing = sorted(actual - declared)
    if missing:
        errs.append(f"harnessed module(s) in NEITHER tier (would be silently unverified): {missing}")
    stale = sorted(declared - actual)
    if stale:
        errs.append(f"tier lists module(s) with no harnesses (filter matches nothing): {stale}")

    return errs, len(light), len(heavy), len(actual)


def selftest():
    """Each check must be shown FAILING on a planted fault, and passing on the real tree."""
    import tempfile
    ok = []

    errs, nl, nh, na = check()
    assert not errs, f"clean tree must pass, got: {errs}"
    ok.append("clean tree passes")

    with tempfile.TemporaryDirectory() as d:
        # 1. CI drift: drop a module from ci.yml's filters.
        real_ci = CI.read_text()
        drifted = real_ci.replace("--harness utf8_string::", "", 1)
        errs, *_ = check(ci_text=drifted)
        assert any("CI shard filters" in e for e in errs), "CI drift not caught"
        ok.append("CI-drift caught")

        # 2. A harnessed module in neither tier.
        p = Path(d) / "tiers_missing.txt"
        p.write_text("\n".join(l for l in TIERS.read_text().splitlines()
                               if not l.startswith("LIGHT utf8_string")))
        errs, *_ = check(tiers_path=p)
        assert any("NEITHER tier" in e for e in errs), "untiered module not caught"
        ok.append("untiered-module caught")

        # 3. A tier entry that matches no module.
        p2 = Path(d) / "tiers_stale.txt"
        p2.write_text(TIERS.read_text() + "\nHEAVY module_that_does_not_exist\n")
        errs, *_ = check(tiers_path=p2)
        assert any("no harnesses" in e for e in errs), "stale tier entry not caught"
        ok.append("stale-entry caught")

        # 4. A stray `--harness` OUTSIDE the filters blocks (an echo in another step) must NOT be
        #    scraped as a shard filter -- otherwise a phantom module fails the LIGHT-set comparison.
        real_ci = CI.read_text()
        polluted = real_ci + '\n  bogus-step:\n    run: echo "--harness phantom_module::"\n'
        assert "phantom_module" not in ci_filter_modules(polluted), \
            "a --harness outside a filters: block was miscounted as a shard filter"
        errs, *_ = check(ci_text=polluted)
        assert not any("phantom_module" in e for e in errs), "stray --harness leaked into parity check"
        ok.append("stray-harness-outside-filters ignored")

        # 5. A `filters:` key in ANOTHER job must NOT leak -- it could mask a module dropped from the
        #    real kani matrix. The kani job is last, so a later same-indent job ends its block.
        other_job = real_ci + '\n  unrelated_job:\n    filters: "--harness phantom_job::"\n'
        assert "phantom_job" not in ci_filter_modules(other_job), \
            "a filters: key in a non-kani job leaked into the shard set"
        ok.append("filters-in-other-job ignored")

        # 6. An inline YAML comment after `filters:` must NOT be scraped (a `--harness` in a comment
        #    is not a real filter).
        commented = ('jobs:\n  kani:\n    strategy:\n      matrix:\n        include:\n'
                     '          - shard: x\n            filters: >-  # --harness phantom_comment::\n'
                     '              --harness real_mod::\n')
        cm = ci_filter_modules(commented)
        assert "phantom_comment" not in cm and "real_mod" in cm, \
            f"inline-comment contamination or real-filter loss: {cm}"
        ok.append("inline-comment-in-filters ignored")

        # 7. A `filters:`-looking line inside a `run: |` step body (NOT under matrix.include) must NOT
        #    leak, and a real matrix filter alongside it must still be read. Also exercises a `kani:`
        #    header carrying a trailing comment.
        run_body = ('jobs:\n  kani:  # the proof job\n    steps:\n      - run: |\n'
                    '          filters: --harness phantom_run::\n'
                    '    strategy:\n      matrix:\n        include:\n'
                    '          - shard: x\n            filters: "--harness real_mod2::"\n')
        rm = ci_filter_modules(run_body)
        assert "phantom_run" not in rm and "real_mod2" in rm, \
            f"a filters: line inside a run: body leaked, or a real matrix filter was lost: {rm}"
        ok.append("filters-in-run-body ignored (+commented kani header)")

        # 8. A stray bare `include:` in a step body (NOT under `matrix:`) must not be mistaken for the
        #    matrix's include list -- extraction is scoped THROUGH `matrix:` first.
        fake_include = ('jobs:\n  kani:\n    steps:\n      - run: |\n          include:\n'
                        '            filters: "--harness phantom_include::"\n'
                        '    strategy:\n      matrix:\n        include:\n'
                        '          - shard: x\n            filters: "--harness real_mod3::"\n')
        fm = ci_filter_modules(fake_include)
        assert "phantom_include" not in fm and "real_mod3" in fm, \
            f"a bare include: in a step body was mistaken for the matrix include: {fm}"
        ok.append("bare-include-in-step-body ignored")

    print("check_tier_parity.py: SELFTEST PASS -- " + ", ".join(ok) + ".")


if __name__ == "__main__":
    if "--selftest" in sys.argv:
        selftest()
        raise SystemExit(0)
    errors, n_light, n_heavy, n_actual = check()
    if errors:
        print("FAIL check_tier_parity:", file=sys.stderr)
        for e in errors:
            print("  " + e, file=sys.stderr)
        raise SystemExit(1)
    print(f"check_tier_parity.py: PASS -- {n_light} LIGHT + {n_heavy} HEAVY = {n_actual} harnessed "
          f"modules, and CI's shard filters match the LIGHT tier exactly.")
