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


def ci_filter_modules(text: str):
    """Modules named by `--harness <mod>::` in the ci.yml kani matrix, ignoring the commented-out
    kani-heavy job (its lines start with '#')."""
    live = "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))
    return sorted(set(re.findall(r"--harness\s+([A-Za-z0-9_]+)::", live)))


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
