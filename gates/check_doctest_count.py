#!/usr/bin/env python3
"""Gate: cargo's OWN doctest count must agree with `gen_proof_manifest.py`'s static derivation.

WHY THIS EXISTS
---------------
`gen_proof_manifest.py`'s `count_doctests()` is a STATIC, syntactic scan over `///`/`//!` fence
lines and a handful of `UNPARSEABLE_DOCTEST_FORM_CHECKS` regexes -- deliberately not a full
Rust/rustdoc parser (see that script's own header). Every regex it uses is a finite approximation
of what rustdoc actually recognises as a doctest, and this is not hypothetical: a release review
found five real false negatives across two rounds --

    # [doc = "..."]                          (whitespace between `#` and `[`)
    #! [doc = "..."]                         (whitespace in the inner-attribute form)
    #[cfg_attr(all(), doc = "...")]          (`doc = ` nested inside `cfg_attr(...)`)
    #[cfg_attr/*c*/(all(), doc = "...")]     (a comment as a token separator)
    #[r#cfg_attr(all(), doc = "...")]        (the `r#`-raw-identifier spelling of `cfg_attr`)

each fixed by teaching the static scanner one more shape. That is fundamentally a game of
whack-a-mole: Rust's tokenizer accepts an ARBITRARY run of whitespace/comments between any two
tokens and an `r#`-raw-identifier spelling of (almost) any name, so the space of valid spellings
for "an attribute that sets doc text" is open-ended and cannot be enumerated by regex in advance.

This gate ends that game structurally rather than adding a sixth regex round. It asks the only
component that actually implements rustdoc's grammar -- `cargo test --doc -- --list`, i.e. rustdoc
itself -- how many doctests it discovers, and FAILS if that number disagrees with what the static
scanner in `gen_proof_manifest.py` derived. A future unknown-shape false negative (or a false
positive) can no longer under-count (or over-count) silently: it fails HERE even if every static
regex missed it, because this check does not depend on recognising the shape at all.

WHAT THIS IS NOT
----------------
This does not replace the static scanner, and is not a substitute for it:

  - `PROOF_MANIFEST.md`'s per-module inventory needs the count broken down BY MODULE, not just a
    crate-wide total -- `cargo test --doc -- --list` gives a flat list and a total, not a
    per-module breakdown gate-checkable the way `gen_proof_manifest.py`'s regions are.
  - `gen_proof_manifest.py` itself is deliberately "pure stdlib, no network, no cargo invocation
    (so it is safe to run inside any gate)" (see its own header) -- a reader without a Rust
    toolchain installed at all can still run `gen_proof_manifest.py --check` and get a real
    answer about the manifest's internal consistency. This gate does NOT preserve that property
    (it requires `cargo` and a working build), which is exactly why it lives in its OWN script
    rather than being folded into `gen_proof_manifest.py --check` -- see the placement note below.
  - It is a crate-wide BACKSTOP: if it fails, it says "the static scan and cargo's own count
    disagree", not which module's row is wrong or which regex needs teaching. A human still reads
    the diff and fixes the static scanner (or the source, if the *test* was the mistake).

PLACEMENT (measured, not guessed)
----------------------------------
Measured on this box: `cargo test --doc -p der-verified -- --list` (discovery only -- it compiles
but does not EXECUTE the doctests) takes ~0.1-0.2s warm (i.e. right after `check_fast.sh`'s own
earlier `cargo test` step, which already built everything this needs) and ~0.4s even cold (timed
immediately after `cargo clean -p der-verified`). Both are comfortably inside "a few seconds", the
threshold for wiring this directly into a per-commit gate.

That measured cost argues for direct inclusion, but `gen_proof_manifest.py --check` itself is not
where this lives -- its documented "no cargo invocation" contract (see WHAT THIS IS NOT above) is
an architectural property this script does not want to spend on a sub-second speed gain. Instead:
this is its own gate script, invoked as an EXTRA step in `check_fast.sh` (the per-commit gate,
right after its `cargo test` step, so the build is already warm) -- catching a false-negative
count on the very next commit, not just before a release. It is ALSO wired into the full
`check.sh`, so the release path's "a fresh full `check.sh` run at final HEAD before publish"
guarantee (already relied on elsewhere in this repo's release process) independently covers it
even if `check_fast.sh`'s pre-commit hook were ever bypassed for a given commit.

Usage:  python3 gates/check_doctest_count.py    (run from anywhere; uses --manifest-path)
"""
import importlib.util
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
WORKSPACE_MANIFEST = os.path.join(ROOT, 'Cargo.toml')

_spec = importlib.util.spec_from_file_location('gen_proof_manifest',
                                               os.path.join(HERE, 'gen_proof_manifest.py'))
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)

# `cargo test ... -- --list` prints one line per discovered test, then a summary line of exactly
# this shape (verified against the installed toolchain): "33 tests, 0 benchmarks", "1 test, 0
# benchmarks" (singular at N=1), "0 tests, 0 benchmarks" (none). Anchored with `re.M` so it matches
# regardless of what precedes it on earlier lines (build progress, the "Doc-tests <crate>" banner).
# Group 2 (the benchmark count) is captured too, not just matched -- `cargo_measured_doctest_count`
# requires it to be exactly 0 (this repo has no `#[bench]`s; a nonzero benchmark count would mean
# either a real benchmark got mixed into what this gate reads as "doctests", or the output shape
# changed in a way this regex is misreading -- either way, silently accepting it is wrong).
SUMMARY_RE = re.compile(r'^(\d+)\s+tests?,\s+(\d+)\s+benchmarks?\s*$', re.M)

TIMEOUT_S = 120


class CargoListError(Exception):
    """Cargo's own doctest count could not be obtained -- this gate fails closed on this, it does
    not silently skip the check (an unavailable ground truth is not the same as an agreeing one)."""


def cargo_measured_doctest_count(manifest_path=WORKSPACE_MANIFEST):
    """Ask cargo itself how many doctests it discovers for `der-verified` -- the ground truth this
    gate checks the static scanner's total against. `--list` only DISCOVERS/COMPILES; it does not
    execute the doctests (matching `count_doctests()`'s own job: "is this a doctest at all", not
    "does it pass").
    """
    try:
        proc = subprocess.run(
            ['cargo', 'test', '--doc', '-p', 'der-verified',
             '--manifest-path', manifest_path, '--', '--list'],
            capture_output=True, text=True, timeout=TIMEOUT_S)
    except FileNotFoundError as exc:
        raise CargoListError('cargo is not on PATH: %s' % exc)
    except subprocess.TimeoutExpired as exc:
        raise CargoListError(
            'cargo test --doc -p der-verified -- --list did not finish within %ds: %s'
            % (TIMEOUT_S, exc))
    if proc.returncode != 0:
        raise CargoListError(
            'cargo test --doc -p der-verified -- --list exited %d\n--- stdout ---\n%s\n'
            '--- stderr ---\n%s' % (proc.returncode, proc.stdout, proc.stderr))
    matches = SUMMARY_RE.findall(proc.stdout)
    if not matches:
        raise CargoListError(
            'could not find a "N tests, M benchmarks" summary line in cargo\'s --list output -- '
            'the output shape may have changed on this cargo version.\n--- stdout ---\n%s'
            % proc.stdout)
    if len(matches) > 1:
        # `.search()` silently takes the FIRST match -- if cargo's output ever contained more than
        # one summary-shaped line (a second `--list` invocation's output concatenated in, a
        # workspace with more than one doc-test binary, stray/malformed output that happens to
        # look like a second summary), that would read as whichever one happened to come first
        # rather than raising. Ambiguous ground truth must fail closed, not silently pick one.
        raise CargoListError(
            'found %d "N tests, M benchmarks" summary lines in cargo\'s --list output, expected '
            'exactly one -- ambiguous, refusing to guess which is authoritative.\n'
            '--- stdout ---\n%s' % (len(matches), proc.stdout))
    test_count_s, bench_count_s = matches[0]
    bench_count = int(bench_count_s)
    if bench_count != 0:
        # This crate has no `#[bench]`s; a nonzero benchmark count here means either a real
        # benchmark slipped into what this gate treats as "doctests" (which would silently inflate
        # the ground truth it's compared against) or the output is not what this regex thinks it
        # is. Either way, fail closed rather than accept a benchmark count this gate never checked.
        raise CargoListError(
            'cargo\'s --list summary reports %d benchmark(s), expected exactly 0 -- this gate only '
            'validates the doctest COUNT, not benchmarks, so a nonzero figure here is unaccounted '
            'for and must not be silently ignored.\n--- stdout ---\n%s' % (bench_count, proc.stdout))
    return int(test_count_s)


def static_doctest_count():
    """The count `gen_proof_manifest.py`'s regexes derive, exactly as fed into
    `PROOF_MANIFEST.md`'s inventory row -- same code path, not a second copy of the logic."""
    return gen.collect()['totals']['doctests']


def check():
    try:
        measured = cargo_measured_doctest_count()
    except CargoListError as exc:
        print('FAIL check_doctest_count: could not obtain cargo\'s own doctest count: %s' % exc,
              file=sys.stderr)
        return 1

    static = static_doctest_count()
    if measured != static:
        print('FAIL check_doctest_count: gen_proof_manifest.py\'s STATIC scan says %d doctest(s); '
              'cargo test --doc -p der-verified -- --list (ground truth, from rustdoc itself) '
              'says %d.' % (static, measured), file=sys.stderr)
        print('  This means count_doctests() in gates/gen_proof_manifest.py missed (or over-'
              'counted) a real doctest -- a doc-comment fence or attribute SHAPE it does not '
              'recognise. Teach it about the shape (DOC_FENCE_RE / '
              'UNPARSEABLE_DOCTEST_FORM_CHECKS / RUST_DOCTEST_ATTRS) rather than letting this '
              'drift; this gate exists precisely so a shape neither of us has thought of yet '
              'still gets caught.', file=sys.stderr)
        return 1

    print('PASS check_doctest_count: static scan (%d) matches cargo\'s own doctest count (ground '
          'truth, via `cargo test --doc -p der-verified -- --list`)' % measured)
    return 0


def main():
    return check()


if __name__ == '__main__':
    sys.exit(main())
