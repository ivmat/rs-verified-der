#!/usr/bin/env python3
"""gen_proof_manifest.py — derive PROOF_MANIFEST.md's factual regions from the source tree.

WHY THIS EXISTS
---------------
`PROOF_MANIFEST.md` is this crate's honest proof envelope: the document an external reader
consults *instead of* reading 164 harnesses and 6 Lean lids. A hand-typed count in it drifts
silently, and a drifted count in the proof envelope is the most expensive kind of overclaim.
So every *number* in the manifest is generated from source by this script, and `--check`
(wired into `check.sh`) fails the gate if the committed manifest disagrees with the tree.

An uncaptured check is vacuous. This is the capture.

WHAT THIS IS NOT
----------------
This script derives **static inventory** — how much verification exists, and where. It runs
no proofs. Inventory is *not* coverage: "164 harnesses" is a fact about harnesses, never a
statement about how much of the crate is verified. The manifest's prose is the claim; these
numbers only sit underneath it as evidence. Two consequences are deliberate:

  * Entry-point "harnessed?" is a *syntactic* fact (does any harness in this module's
    `mod proofs` name this `pub fn`?). It is a lower bound on attention, not a proof that
    the entry point's behaviour is characterised.
  * The pass/fail verdict of the proofs themselves is NOT derivable here. It comes from a
    committed run log (`evidence/`), or the manifest says plainly that there is none.

MODES
-----
    python3 gates/gen_proof_manifest.py --check    # gate: regions + guarded counts vs source
    python3 gates/gen_proof_manifest.py --write    # regenerate the manifest's marked regions
    python3 gates/gen_proof_manifest.py --json     # dump the derived facts

Pure stdlib, no network, no cargo invocation (so it is safe to run inside any gate).
"""

import argparse
import difflib
import json
import os
import re
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SRC = os.path.join(ROOT, 'der-verified', 'src')
LEAN = os.path.join(ROOT, 'lean')
MANIFEST = os.path.join(ROOT, 'PROOF_MANIFEST.md')
EVIDENCE = os.path.join(ROOT, 'evidence')
# The paths a committed run's verdicts actually speak for. A change OUTSIDE these (docs, gates, CI)
# cannot invalidate a proof run; a change INSIDE them can, and does so silently unless derived.
VERIFIED_PATHS = ['der-verified/src', 'lean']

BEGIN = '<!-- BEGIN GENERATED:%s (gates/gen_proof_manifest.py) -->'
END = '<!-- END GENERATED:%s -->'

# Per-region cap on the diff `--check` prints. A truncated diff is announced, never silent:
# "the gate showed me everything" is exactly the wrong thing for a reader to assume here.
DIFF_LINES = 20

# A DISCLOSED non-vacuity gap: a harness whose `kani::cover` is known-UNSATISFIABLE at its
# bound, left in place (rather than deleted) because a cover reporting "0 of 1 satisfied" IS
# the machine-checked record of the gap. Prose alone is not countable, so each finding also
# carries one declarative line in the module:
#
#   // VACUITY-DISCLOSED: <harness> -> witness <harness>
#
# next to the narrative. This script counts those lines; DOCS-SYNC.md requires one per
# finding. Kani does NOT fail a harness for an unsatisfied cover, so without this registry
# the gaps are invisible to the gate.
VACUITY_RE = re.compile(r'//\s*VACUITY-DISCLOSED:\s*([A-Za-z0-9_]+)\s*->\s*witness\s+([A-Za-z0-9_]+)')

COMMENT_RE = re.compile(r'^\s*(///|//!|//|\*|/\*)')


# --------------------------------------------------------------------------------------
# source-derived facts
# --------------------------------------------------------------------------------------

def read_text(path, errors='strict'):
    """Read a whole file and close it. (A leaked handle is a ResourceWarning under `unittest`.)"""
    with open(path, encoding='utf-8', errors=errors) as fh:
        return fh.read()


def strip_comments(lines):
    """Drop comment lines. Prose that *mentions* `kani::cover` must never be counted as one."""
    return [l for l in lines if not COMMENT_RE.match(l)]


def split_regions(lines):
    """Split a module into (top-level, `mod proofs`, `mod tests`) by line range.

    Every module in this crate places `#[cfg(kani)] mod proofs` before `#[cfg(test)] mod
    tests`, both at the end of the file; the ordering is asserted below so a future
    reshuffle fails loudly instead of silently miscounting.
    """
    pi = ti = None
    for i, l in enumerate(lines):
        if pi is None and re.match(r'\s*mod proofs\s*\{', l):
            pi = i
        if ti is None and re.match(r'\s*mod tests\s*\{', l):
            ti = i
    if pi is not None and ti is not None and pi > ti:
        raise SystemExit('gen_proof_manifest: `mod tests` precedes `mod proofs`; '
                         'region splitting assumes the reverse — fix this script.')
    end_top = min(x for x in (pi, ti, len(lines)) if x is not None)
    proofs = lines[pi:ti if ti is not None else len(lines)] if pi is not None else []
    tests = lines[ti:] if ti is not None else []
    return lines[:end_top], proofs, tests, (pi, ti)


IMPL_RE = re.compile(r'impl(?:<[^>]*>)?\s+(?:(?P<trait>[A-Za-z0-9_:]+)(?:<[^>]*>)?\s+for\s+)?'
                     r'(?P<ty>[A-Za-z0-9_]+)')


def entry_points_of(path, lines, bounds):
    """Public entry points: free `pub fn`s, public inherent-impl methods, AND trait-impl methods.

    Three passes' worth of corrections live in this function, each found by review rather than by
    intent, and each in the same direction — undercounting the API surface, which understates the
    "no harness names this entry point" gap and so overclaims by omission:

      1. Column-0 `pub fn` only  ->  missed the four public methods on `Charset` and `Elements`.
      2. Only the region above `mod proofs`  ->  missed a `pub fn` declared after the test module.
      3. `pub fn` only  ->  missed trait-impl methods, which carry no `pub` keyword but ARE public
         API when both trait and type are public (`Iterator::next` on `Elements`).

    Anything indented that is neither in `mod proofs`/`mod tests` nor inside an `impl` block would be
    a nested module, which this scheme cannot attribute — that case fails the gate loudly rather than
    quietly miscounting.
    """
    pi, ti = bounds
    end = min(x for x in (pi, ti, len(lines)) if x is not None)
    out, trait_methods, impl_ty, in_trait_impl, in_impl = [], [], None, False, False
    for i, l in enumerate(lines[:end]):
        m = IMPL_RE.match(l)
        if m:
            impl_ty, in_impl = m.group('ty'), True
            in_trait_impl = bool(m.group('trait'))
        elif re.match(r'\}\s*$', l):
            in_impl = in_trait_impl = False
        m = re.match(r'pub (?:const |unsafe )?fn ([A-Za-z0-9_]+)', l)
        if m:
            out.append(m.group(1))
            continue
        m = re.match(r'\s+(?:pub )?(?:const |unsafe )?fn ([A-Za-z0-9_]+)', l)
        if m:
            if not in_impl:
                # A non-pub indented fn outside an impl is a private helper — ignore it. A `pub` one
                # would be a nested module's API, which cannot be attributed: fail.
                if l.lstrip().startswith('pub '):
                    raise SystemExit(
                        'gen_proof_manifest: %s:%d has an indented `pub fn` that is not inside an '
                        '`impl` block:\n  %s\nEntry-point detection cannot attribute it (a nested '
                        'module?). Teach the script about it rather than letting the count drift.'
                        % (path, i + 1, l.rstrip()))
                continue
            if not in_trait_impl and not l.lstrip().startswith('pub '):
                continue                      # private inherent method
            name = '%s::%s' % (impl_ty or '?', m.group(1))
            out.append(name)
            if in_trait_impl:
                trait_methods.append(name)
    return out, trait_methods


def balanced_args(lines, call):
    """Extract each `call(...)` argument text, following the parens across line breaks."""
    text = '\n'.join(lines)
    out, i = [], 0
    while True:
        j = text.find(call, i)
        if j < 0:
            return out
        k = j + len(call)
        depth, start = 1, k
        while k < len(text) and depth:
            if text[k] == '(':
                depth += 1
            elif text[k] == ')':
                depth -= 1
            k += 1
        out.append(' '.join(text[start:k - 1].split()))
        i = k


# An assumption is a "range bound" if it only relates identifiers, integer literals and `.len()`
# with comparisons and conjunction — i.e. it narrows the input's SIZE or an integer's RANGE. Anything
# else narrows the input's *content*, which is a materially stronger restriction on what the proof
# covers, so those are listed individually rather than folded into a count.
RANGE_BOUND_RE = re.compile(r'^[A-Za-z0-9_\s().<>=&|!+\-]*$')
CALL_RE = re.compile(r'\b([A-Za-z_][A-Za-z0-9_]*)\s*\(')


def is_range_bound(expr):
    if not RANGE_BOUND_RE.match(expr):
        return False
    if '||' in expr or '!' in expr.replace('!=', ''):
        return False
    calls = {c for c in CALL_RE.findall(expr)}
    return not (calls - {'len'})


def const_widths(lines):
    """`const N: usize = 20;` — some harnesses size their buffer through a named const."""
    out = {}
    for l in lines:
        m = re.match(r'\s*(?:pub )?const ([A-Z_][A-Z0-9_]*)\s*:\s*usize\s*=\s*(\d+)', l)
        if m:
            out[m.group(1)] = int(m.group(2))
    return out


def parse_harnesses(proofs, consts):
    """Split `mod proofs` into per-harness blocks keyed by harness fn name.

    Anchored on the `fn` line, not on `#[kani::proof]`: attribute order varies across this
    crate (`#[kani::unwind]` sits above `#[kani::proof]` in some modules and below it in
    others), and anchoring on the attribute silently drops the ones above it.

    A block = the contiguous attribute/doc run above the `fn` line, plus the body up to the
    next function's run. Helper fns inside `mod proofs` (the hand-written stub bodies) are
    *not* harnesses; their `kani::assume`s are counted at the region level instead, because
    they constrain a stub's return value rather than a harness's input domain — a materially
    different kind of assumption that the manifest states separately.
    """
    fns = [i for i, l in enumerate(proofs) if re.match(r'\s*fn ([A-Za-z0-9_]+)', l)]
    blocks = []
    helper_assumes = []
    for n, fi in enumerate(fns):
        top = fi
        while top > 0 and re.match(r'\s*(#\[|///|//)', proofs[top - 1]):
            top -= 1
        stop = fns[n + 1] if n + 1 < len(fns) else len(proofs)
        # trim the next function's own attribute/doc run off the tail of this body
        if n + 1 < len(fns):
            while stop > fi and re.match(r'\s*(#\[|///|//)', proofs[stop - 1]):
                stop -= 1
        blocks.append((re.match(r'\s*fn ([A-Za-z0-9_]+)', proofs[fi]).group(1),
                       proofs[top:fi], proofs[fi:stop]))

    out = []
    for name, attrs, body in blocks:
        code = strip_comments(body)
        if not any(re.match(r'\s*#\[kani::proof(_for_contract)?', a) for a in attrs):
            ha = balanced_args(code, 'kani::assume(')
            if ha:
                helper_assumes.append((name, ha))
            continue
        out.append({
            'name': name,
            'unwind': [int(m.group(1)) for l in attrs
                       for m in [re.match(r'\s*#\[kani::unwind\((\d+)\)\]', l)] if m],
            'stubs': [m.group(1).strip() for l in attrs
                      for m in [re.match(r'\s*#\[kani::stub\(([^,]+),', l)] if m],
            'covers': sum(l.count('kani::cover(') for l in code),
            'assumes': sum(l.count('kani::assume(') for l in code),
            'assume_exprs': balanced_args(code, 'kani::assume('),
            'asserts': sum(l.count('assert!(') + l.count('assert_eq!(') +
                           l.count('assert_ne!(') for l in code),
            # The other half of "harness bounds": how wide the symbolic input buffer is. An
            # unwind depth alone does not tell a reader what input domain was proved over.
            'buffers': sorted({int(m.group(1)) if m.group(1).isdigit() else consts[m.group(1)]
                               for l in code
                               for m in re.finditer(r'\[\s*u8\s*;\s*([A-Za-z0-9_]+)\s*\]', l)
                               if m.group(1).isdigit() or m.group(1) in consts}),
        })
    return out, helper_assumes


def module_facts(path):
    lines = read_text(path).split('\n')
    _top, proofs, tests, bounds = split_regions(lines)
    entry_points, trait_methods = entry_points_of(path, lines, bounds)
    # A `pub fn` declared AFTER the proof/test modules is still a public entry point; scanning only
    # the region above `mod proofs` made it invisible (negative-tested). Picked up here.
    pi, ti = bounds
    tail = lines[ti:] if ti is not None else (lines[pi:] if pi is not None else [])
    entry_points += [m.group(1) for l in tail
                     for m in [re.match(r'pub (?:const |unsafe )?fn ([A-Za-z0-9_]+)', l)] if m]
    harnesses, helper_assumes = parse_harnesses(proofs, const_widths(lines))
    proof_code = strip_comments(proofs)
    proof_text = '\n'.join(proof_code)
    # Match on the short name: an entry point recorded as `Charset::contains` is called as
    # `charset.contains(b)` in a harness, so searching for the qualified name would report it
    # unharnessed. This makes an already-loose syntactic check looser still, which is why §4 states
    # plainly that "named by a harness" is not evidence of verification.
    harnessed = [e for e in entry_points
                 if re.search(r'\b%s\b' % re.escape(e.split('::')[-1]), proof_text)]
    unwinds = sorted({u for h in harnesses for u in h['unwind']})
    n_harness_assumes = sum(h['assumes'] for h in harnesses)
    n_region_assumes = sum(l.count('kani::assume(') for l in proof_code)
    return {
        'module': os.path.basename(path)[:-3],
        'entry_points': entry_points,
        'trait_impl_methods': trait_methods,
        'harnessed_entry_points': harnessed,
        'unharnessed_entry_points': [e for e in entry_points if e not in harnessed],
        'harnesses': harnesses,
        'n_harnesses': len(harnesses),
        'unwinds': unwinds,
        'buffers': sorted({b for h in harnesses for b in h['buffers']}),
        'no_unwind': [h['name'] for h in harnesses if not h['unwind']],
        'n_assumes': n_harness_assumes,
        'n_stub_assumes': n_region_assumes - n_harness_assumes,
        'n_covers': sum(h['covers'] for h in harnesses),
        # Non-vacuity audit, in two tiers.
        #
        # `assume_without_cover` — narrowed by `assume`, no `cover`. Mostly benign: a harness
        # that asserts an exact functional outcome (a biconditional, a round-trip, an exact
        # `Err` variant) is its own post-state witness, and a cover would be redundant.
        #
        # `implicit_only` — the tier that actually matters: NO `cover` and NO `assert`, so the
        # harness's only checks are Kani's implicit panic/overflow/memory-safety ones. If the
        # symbolic construction never reaches the deep code the harness claims to exercise, it
        # is green-but-shallow with nothing to say so. This set should stay empty.
        'assume_without_cover': [h['name'] for h in harnesses
                                 if h['assumes'] and not h['covers']],
        'implicit_only': [h['name'] for h in harnesses
                          if not h['covers'] and not h['asserts']],
        # Assumptions that restrict input CONTENT rather than size/range. These are the ones a
        # reader must inspect individually, so they are named rather than counted.
        'content_assumes': [(h['name'], e) for h in harnesses for e in h['assume_exprs']
                            if not is_range_bound(e)],
        'stubs': [(h['name'], h['stubs']) for h in harnesses if h['stubs']],
        'disclosed_vacuities': [m.groups() for l in lines for m in [VACUITY_RE.search(l)] if m],
        # Which harnesses use a stub matters for how a *witness* should be read: a cover satisfied
        # inside a stub-bearing harness witnesses the caller's glue given a FABRICATED sub-parser
        # `Ok`, not that the real sub-parser ever accepts. Recorded so the manifest can label the
        # difference instead of presenting all witnesses uniformly.
        'stub_harness_names': [h['name'] for h in harnesses if h['stubs']],
        # Assumptions outside a harness body, attributed to the helper that contains them. Two very
        # different kinds share this position and must not be reported together: one inside a
        # `stub_*` body constrains what the STUB IS ALLOWED TO RETURN (and so must be discharged by a
        # separate harness, or it is an unsound hole); one inside an input generator merely narrows a
        # nondeterministic selector, which is ordinary harness setup.
        'helper_assumes': [(name, e) for name, exprs in helper_assumes for e in exprs],
        # Every non-harness function declared in `mod proofs`: the hand-written helper surface the
        # harnesses are written against — reference predicates ("oracles") and stub bodies. A wrong
        # oracle yields a machine-checked proof of the WRONG property, so this surface is part of the
        # trust base. Derived by exclusion (all fns minus the harnesses) rather than by a naming
        # convention, so a helper cannot hide by being named something else.
        'proof_helpers': sorted({m.group(1) for l in proofs
                                 for m in [re.match(r'\s+fn ([a-z0-9_]+)\(', l)] if m}
                                - {h['name'] for h in harnesses}),
        'oracle_harnesses': sorted({h['name'] for h in harnesses
                                    if 'oracle' in h['name'] or '_iff_' in h['name']}),
        # strip_comments first: `//!   Tested (`#[test]`) only so far` is prose, not a test.
        # Counting it inflated the total by one against what `cargo test` actually runs.
        'n_tests': sum(l.count('#[test]') for l in strip_comments(tests)),
    }


def lean_facts():
    lids = []
    for f in sorted(os.listdir(LEAN)):
        if not f.endswith('Proofs.lean'):
            continue
        text = read_text(os.path.join(LEAN, f))
        lines = text.split('\n')
        thms = [m.group(2) for l in lines
                for m in [re.match(r'(theorem|lemma) ([A-Za-z0-9_.\']+)', l)] if m]
        axioms = [m.group(1) for l in lines
                  for m in [re.match(r'axiom ([A-Za-z0-9_]+)', l)] if m]
        lids.append({
            'file': 'lean/' + f,
            'codec': f[:-len('Proofs.lean')].lower(),
            'theorems': len(thms),
            'headline': thms[-1] if thms else '—',
            'declared_axioms': sorted(set(axioms)),
            'print_axioms': text.count('#print axioms'),
        })
    return lids


# Lid file stem -> source module. `lean/check_lean.sh` is the gate that ties each lid to the
# shipped `.rs` (it re-extracts and fails on drift); this map only names the pairing for the
# manifest's per-module table, and fails loudly if a new lid arrives unmapped.
LID_TO_MODULE = {'length': 'length', 'bigint': 'big_integer', 'oid': 'oid',
                 'tag': 'tag', 'tlv': 'tlv', 'sequence': 'sequence'}


def toolchain_facts():
    def read(p):
        try:
            return read_text(os.path.join(ROOT, p))
        except OSError:
            return ''

    rt = read('rust-toolchain.toml')
    ci = read('.github/workflows/ci.yml')
    cl = read('lean/check_lean.sh')

    def grab(pat, text, default='?'):
        m = re.search(pat, text)
        return m.group(1) if m else default

    def observed(cmd):
        try:
            out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            return (out.stdout + out.stderr).strip().split('\n')[0] or '—'
        except Exception:
            return 'not installed on this machine'

    tools = os.environ.get('VERIFIED_RS_TOOLS', os.path.expanduser('~/Downloads/verified_rs_tools'))

    def rev(p):
        try:
            out = subprocess.run(['git', '-C', p, 'rev-parse', 'HEAD'],
                                 capture_output=True, text=True, timeout=30)
            return out.stdout.strip() or 'absent'
        except Exception:
            return 'absent'

    return {
        'declared': {
            'rust_channel': grab(r'channel\s*=\s*"([^"]+)"', rt),
            'kani_ci': grab(r"kani-version:\s*'?([0-9.]+)'?", ci),
            'lean': read('lean/lean-toolchain').strip() or '?',
            'aeneas': grab(r'EXPECT_AENEAS="([0-9a-f]+)"', cl),
            'charon': grab(r'EXPECT_CHARON="([0-9a-f]+)"', cl),
            'extract_nightly': grab(r'channel\s*=\s*"(nightly-[0-9-]+)"',
                                    read('lean/extract/rust-toolchain.toml')),
        },
        'observed': {
            'rustc': observed(['rustc', '--version']),
            'kani': observed(['cargo', 'kani', '--version']),
            'aeneas_rev': rev(os.path.join(tools, 'aeneas')),
            'charon_rev': rev(os.path.join(tools, 'aeneas', 'charon')),
        },
    }


def evidence_facts():
    """Read the committed L3/L4 run evidence, if any. Absence is itself reported."""
    out = []
    if os.path.isdir(EVIDENCE):
        for f in sorted(os.listdir(EVIDENCE)):
            p = os.path.join(EVIDENCE, f)
            if not os.path.isfile(p):
                continue
            # Only a Kani run log, by the `check*.log` naming this directory has always used.
            # This filter is not tidiness. Every column below is a REGEX COUNT over the file's
            # text, and the table it feeds is gate-enforced -- so a prose note dropped in here
            # that merely *quotes* `0 of 1 cover properties satisfied`, or that mentions
            # `VERIFICATION: SUCCESSFUL` while explaining what one means, is counted as if it
            # were a run and silently moves a published number. That happened on 2026-08-03:
            # a written record of a floor run reported "1 unsatisfied cover" from its own prose.
            # A run log earns a row; writing *about* runs does not.
            if not (f.startswith('check') and f.endswith('.log')):
                continue
            text = read_text(p, errors='replace')
            commit = (re.search(r'^#\s*commit:\s*([0-9a-f]{7,40})', text, re.M) or
                      [None, 'unrecorded'])[1]
            out.append({
                'file': 'evidence/' + f,
                'commit': commit,
                # Whether this run still speaks for HEAD is a DERIVED fact, not a judgement: it does
                # exactly when no path the run verified has changed since. Docs/gates/CI commits
                # landing after a run therefore do not invalidate it, and a source commit does --
                # automatically, with no prose to update. `unknown` when git cannot answer (a
                # tarball, a shallow clone, an unrecorded commit).
                'covers_head_source': verified_source_unchanged_since(commit),
                'successful': len(re.findall(r'VERIFICATION:- ?SUCCESSFUL|VERIFICATION: SUCCESSFUL', text)),
                'failed': len(re.findall(r'VERIFICATION:- ?FAILED|VERIFICATION: FAILED', text)),
                'covers_unsatisfied': len(re.findall(r'0 of \d+ cover propert', text)),
            })
    return out


def verified_source_unchanged_since(commit):
    """True/False if git can answer whether VERIFIED_PATHS changed since `commit`; else None."""
    if not commit or commit == 'unrecorded':
        return None
    try:
        # `commit` (no `..HEAD`), so the comparison is against the WORKING TREE, not the last
        # commit. This region is written and `--check`ed by the pre-commit hook, i.e. while the
        # change being made is still uncommitted -- so `commit..HEAD` answers about the tree as it
        # was BEFORE the commit, and the sentence lands one commit stale. On 2026-08-03 that
        # published a false claim: a commit that regenerated all six extracted Lean models (a
        # VERIFIED_PATHS path) shipped a manifest still asserting "`evidence/check-ea8dad4-
        # remainder.log` still speaks for HEAD", because at hook time HEAD did not yet contain
        # them. Found by a second model. Diffing the working tree also fails in the safe
        # direction: an uncommitted edit to verified source now reads as superseding a run,
        # which it does. On a clean tree the two forms are identical, so CI is unaffected.
        out = subprocess.run(['git', '-C', ROOT, 'diff', '--name-only', commit, '--']
                             + VERIFIED_PATHS, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            return None
        return out.stdout.strip() == ''
    except Exception:
        return None


def head_commit():
    try:
        out = subprocess.run(['git', '-C', ROOT, 'rev-parse', '--short', 'HEAD'],
                             capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or 'unknown'
    except Exception:
        return 'unknown'


def collect():
    mods = []
    for f in sorted(os.listdir(SRC)):
        if f.endswith('.rs') and f != 'lib.rs':
            mods.append(module_facts(os.path.join(SRC, f)))
    lib = read_text(os.path.join(SRC, 'lib.rs'))
    lib_lines = lib.split('\n')

    lids = lean_facts()
    unmapped = [l['codec'] for l in lids if l['codec'] not in LID_TO_MODULE]
    if unmapped:
        raise SystemExit('gen_proof_manifest: lid(s) %s have no LID_TO_MODULE entry — add them.'
                         % ', '.join(unmapped))
    l4_modules = {LID_TO_MODULE[l['codec']] for l in lids}
    for m in mods:
        m['l4'] = m['module'] in l4_modules

    unwind_hist = {}
    for m in mods:
        for h in m['harnesses']:
            for u in h['unwind']:
                unwind_hist[u] = unwind_hist.get(u, 0) + 1

    return {
        'head': head_commit(),
        'modules': mods,
        'lids': lids,
        'toolchain': toolchain_facts(),
        'evidence': evidence_facts(),
        'unwind_hist': unwind_hist,
        'totals': {
            'modules': len(mods),
            'modules_with_kani': sum(1 for m in mods if m['n_harnesses']),
            'entry_points': sum(len(m['entry_points']) for m in mods),
            'harnessed_entry_points': sum(len(m['harnessed_entry_points']) for m in mods),
            'unharnessed_entry_points': sum(len(m['unharnessed_entry_points']) for m in mods),
            'harnesses': sum(m['n_harnesses'] for m in mods),
            'assumes': sum(m['n_assumes'] for m in mods),
            'stub_assumes': sum(m['n_stub_assumes'] for m in mods),
            'covers': sum(m['n_covers'] for m in mods),
            'stubs': sum(len(s[1]) for m in mods for s in m['stubs']),
            'stub_harnesses': sum(len(m['stubs']) for m in mods),
            'disclosed_vacuities': sum(len(m['disclosed_vacuities']) for m in mods),
            'modules_with_covers': sum(1 for m in mods if m['n_covers']),
            'assume_without_cover': sum(len(m['assume_without_cover']) for m in mods),
            'implicit_only': sum(len(m['implicit_only']) for m in mods),
            'content_assumes': sum(len(m['content_assumes']) for m in mods),
            'tests': sum(m['n_tests'] for m in mods)
            + sum(l.count('#[test]') for l in strip_comments(lib_lines)),
            # `cargo test` also runs the crate-doc examples; they are tests a reader will see in
            # the output, so they are named rather than folded into the `#[test]` figure.
            'doctests': lib.count('```') // 2,
            'lids': len(lids),
            'forbid_unsafe': '#![forbid(unsafe_code)]' in lib,
            'unsafe_blocks': sum(len(re.findall(r'\bunsafe\s*\{', l))
                                 for f in sorted(os.listdir(SRC)) if f.endswith('.rs')
                                 for l in strip_comments(
                                     read_text(os.path.join(SRC, f)).split('\n'))),
        },
    }


# --------------------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------------------

def r_pins(f):
    # Declared pins only — every value here is read from an in-tree file, so it is a property of
    # the crate and stays gate-enforced. What the local machine *observes* moved to r_pins_observed.
    d = f['toolchain']['declared']
    L = ['| Tool | Pin (declared, and where the pin lives) | Enforced by |',
         '|---|---|---|',
         '| rustc | `%s` channel — `rust-toolchain.toml` pins the *channel*, not a version: it '
         'floats to whatever stable is installed. Only `cargo test`/`cargo build` use it; Kani '
         'bundles its own toolchain. | not enforced (deliberate — see the note below) |'
         % d['rust_channel'],
         '| Kani | `%s` — `.github/workflows/ci.yml` (`kani-version:`) | CI installs exactly this |'
         % d['kani_ci'],
         '| Lean 4 | `%s` — `lean/lean-toolchain` | elan, per-project |' % d['lean'],
         '| Aeneas | `%s` | `lean/check_lean.sh` fails closed on drift |' % d['aeneas'],
         '| Charon | `%s` | `lean/check_lean.sh` fails closed on drift |' % d['charon'],
         '| extract shims | `%s` (Charon\'s nightly; `lean/extract*/rust-toolchain.toml`) — drives '
         'extraction only, never the shipped build | pinned in-tree |' % d['extract_nightly'],
         '',
         'Because the rustc pin is a floating channel, **the rustc version is a property of the '
         'run, not of the crate**: a reader reproducing these results on a different stable will '
         'be checking the same source with a different compiler. The Kani harnesses are insulated '
         'from this (Kani ships its own toolchain); `cargo test` is not.']
    return L


def r_pins_observed(f):
    """ADVISORY region (see ADVISORY): what the *regenerating machine* had installed.

    Every value here is a probe of the ambient environment, not a property of the crate: a
    reader with a different stable rustc, or with no Kani/Aeneas checkout at all, legitimately
    observes different values while checking out byte-identical source. Byte-comparing this in
    `--check` made `./check.sh` fail for any third party before a single proof ran, and pointed
    them at `--write`, which would have rewritten the recorded pins and produced a spurious diff.
    The *declared* pins above stay gate-enforced — those are read from in-tree files.
    """
    o = f['toolchain']['observed']
    return ['Observed on the machine that last regenerated this section — a provenance note, '
            '**not** a gate-enforced pin (your values will differ, and that is fine): rustc `%s`, '
            'Kani `%s`, Aeneas `%s`, Charon `%s`.'
            % (o['rustc'], o['kani'], o['aeneas_rev'][:40], o['charon_rev'][:40])]


def r_inventory(f):
    t = f['totals']
    return [
        # NOT the commit hash: putting it here makes the region stale the instant a commit lands,
        # so `--check` could never be green on a clean tree (found by running the gate right after
        # committing). The manifest is regenerated from whatever is checked out; `git log` says when.
        '| Inventory (static, derived from `der-verified/src` + `lean/`) | Count |',
        '|---|---:|',
        '| source modules (excl. `lib.rs`) | %d |' % t['modules'],
        '| …of which carry at least one `#[kani::proof]` | %d |' % t['modules_with_kani'],
        '| public entry points (free `pub fn`s + public `impl` methods) | %d |' % t['entry_points'],
        '| …named by at least one Kani harness | %d |' % t['harnessed_entry_points'],
        '| …named by **no** Kani harness | **%d** |' % t['unharnessed_entry_points'],
        '| `#[kani::proof]` harnesses | %d |' % t['harnesses'],
        '| `kani::assume` harness preconditions (narrow the proved domain) | %d |' % t['assumes'],
        '| `kani::assume` inside stub bodies (constrain a stub\'s *return*, not an input) | %d |'
        % t['stub_assumes'],
        '| `kani::cover` **statements** (satisfaction is observed at a run, is not gate-enforced, '
        'and its currency versus HEAD is derived in §3.4, not asserted here) | %d |' % t['covers'],
        '| …harnesses whose cover is **known-unsatisfiable and disclosed** — i.e. known '
        '*non*-witnesses | **%d** |' % t['disclosed_vacuities'],
        '| `#[kani::stub]` applications / harnesses using them | %d / %d |'
        % (t['stubs'], t['stub_harnesses']),
        '| `#[test]` unit + regression tests | %d |' % t['tests'],
        '| crate-doc examples run as doc-tests | %d |' % t['doctests'],
        '| Lean lids (`lean/*Proofs.lean`) | %d |' % t['lids'],
        '| `unsafe` blocks in `der-verified/src` | %d (crate is `#![forbid(unsafe_code)]`: %s) |'
        % (t['unsafe_blocks'], 'yes' if t['forbid_unsafe'] else 'NO'),
    ]


def _rng(xs):
    if not xs:
        return '—'
    return str(xs[0]) if len(xs) == 1 else '%d..%d' % (xs[0], xs[-1])


def r_per_module(f):
    L = ['| Module | entry points | named by a harness | Kani | symbolic `[u8; N]` | unwind | '
         '`assume` | `cover` | stubs | L4 |',
         '|---|---:|---:|---:|---|---|---:|---:|---:|:--:|']
    for m in f['modules']:
        L.append('| `%s` | %d | %d | %d | %s | %s | %d | %d | %d | %s |' % (
            m['module'], len(m['entry_points']), len(m['harnessed_entry_points']),
            m['n_harnesses'], _rng(m['buffers']), _rng(m['unwinds']),
            m['n_assumes'], m['n_covers'],
            sum(len(s[1]) for s in m['stubs']), '✅' if m['l4'] else ''))
    return L


def r_unharnessed(f):
    L = []
    for m in f['modules']:
        if m['unharnessed_entry_points']:
            L.append('- **`%s`** — %s' % (m['module'], ', '.join(
                '`%s`' % e for e in m['unharnessed_entry_points'])))
    if not L:
        L = ['- none: every `pub fn` is named by at least one harness.']
    return L


def r_bounds(f):
    hist = f['unwind_hist']
    L = ['| `#[kani::unwind(N)]` | harnesses |', '|---:|---:|']
    for u in sorted(hist):
        L.append('| %d | %d |' % (u, hist[u]))
    total = sum(hist.values())
    nun = [(m['module'], n) for m in f['modules'] for n in m['no_unwind']]
    L += ['| **total bounded** | **%d** |' % total, '',
          '%d harnesses declare no `#[kani::unwind]`, so no unwind bound is imposed on them and '
          'CBMC must unroll to completion every loop they reach. For those harnesses the loop depth '
          'is therefore *not* a limit on the claim: a loop CBMC could not fully unroll would fail an '
          'unwinding assertion rather than pass quietly. Their input domains are still bounded by '
          'buffer width like every other harness. Listed so a reader can check each one: %s.'
          % (len(nun), ', '.join('`%s::%s`' % (a, b) for a, b in nun) or 'none')]
    return L


def r_stubs(f):
    L = ['| Harness | `#[kani::stub]`-replaced function(s) |', '|---|---|']
    for m in f['modules']:
        for name, stubs in m['stubs']:
            L.append('| `%s::%s` | %s |' % (m['module'], name,
                                            ', '.join('`%s`' % s for s in stubs)))
    stub_side = [(m['module'], fn, e) for m in f['modules'] for fn, e in m['helper_assumes']
                 if fn.startswith('stub_')]
    gen_side = [(m['module'], fn, e) for m in f['modules'] for fn, e in m['helper_assumes']
                if not fn.startswith('stub_')]
    L += ['', 'Every `kani::assume` inside a **stub body** — each constrains what the stub is allowed '
          'to *return*, so each must be discharged by a separate harness or it is an unsound hole:', '']
    L += ['- `%s::%s` — `assume(%s)`' % r for r in stub_side] or ['- none: no stub constrains its '
                                                                 'return value.']
    if gen_side:
        L += ['', 'For contrast, the other `kani::assume`s outside harness bodies live in input '
              'generators and narrow a nondeterministic selector — ordinary harness setup, nothing '
              'to discharge:', '']
        L += ['- `%s::%s` — `assume(%s)`' % r for r in gen_side]
    return L


def r_nonvacuity(f):
    t = f['totals']
    io = [(m['module'], n) for m in f['modules'] for n in m['implicit_only']]
    awc = [(m['module'], n) for m in f['modules'] for n in m['assume_without_cover']]
    L = ['| Non-vacuity audit (derived from source) | Count |', '|---|---:|',
         '| harnesses | %d |' % t['harnesses'],
         '| `kani::cover` witnesses | %d, in %d of the %d modules that have harnesses |'
         % (t['covers'], t['modules_with_covers'], t['modules_with_kani']),
         '| harnesses whose ONLY checks are Kani\'s implicit panic/overflow/memory-safety ones '
         '(no `cover`, no `assert`) | **%d** |' % t['implicit_only'],
         '| harnesses narrowed by `assume` with no `cover` (their `assert` is the post-state '
         'witness instead) | %d |' % t['assume_without_cover'],
         '| harnesses whose `cover` is known-UNSATISFIABLE and disclosed | %d |'
         % t['disclosed_vacuities'], '']
    if io:
        L += ['Harnesses with implicit checks only — each needs a justification, or a cover:',
              ''] + ['- `%s::%s`' % (a, b) for a, b in io]
    else:
        L += ['**The row that carries the weight is "implicit checks only", and it is %d.** Every '
              'harness in the crate either witnesses a post-state effect with `kani::cover` or '
              'asserts a functional outcome with `assert!`; none relies on Kani\'s implicit checks '
              'alone. That much is a static fact this script re-derives on every run, not a claim.'
              % t['implicit_only']]
    L += ['', 'What the remaining %d `assume`-narrowed-without-a-`cover` harnesses give you is a '
          '*different* kind of witness, not automatically a better one. The static, derived fact is '
          'that each of them contains an `assert!`. The judgement — that these particular assertions '
          'are functional outcomes (a biconditional, a round-trip, an exact `Err` variant) whose '
          'passing requires the code to have produced a specific correct result — is per-harness and '
          'human; this script cannot grade an assertion\'s strength. '
          'But an assertion is not interchangeable with a cover: `assert!(r.is_err())` can be '
          'satisfied by a shallow rejection path while a deeper one is never reached, whereas a '
          'cover can pin a specific deep effect. Neither subsumes the other, and this manifest does '
          'not claim the assertions make covers unnecessary — only that no harness is left with '
          'nothing but Kani\'s implicit checks. The one case where even that is weaker than it '
          'looks is named in the prose below.' % t['assume_without_cover']]
    ca = [(m['module'], h, e) for m in f['modules'] for h, e in m['content_assumes']]
    L += ['', '**What the %d harness assumptions actually restrict.** %d of them are size or range '
          'bounds — they relate lengths, indices and integer values with comparisons and `&&`, and '
          'nothing else — which narrows *how big* an input may be, not *what it may contain*. The '
          'remaining %d restrict input CONTENT, which is the materially stronger kind of narrowing, '
          'so every one is named here rather than folded into a count:'
          % (t['assumes'], t['assumes'] - len(ca), len(ca))]
    if ca:
        L += ['', 'Two things to hold in mind reading it. First, the classifier is deliberately '
              'conservative: anything it cannot show is a pure size/range bound is listed, so some '
              'entries below *are* range constraints in a shape it does not recognise (a negated '
              'range such as `!(mo >= 1 && mo <= 12)`, for instance). It errs toward disclosing. '
              'Second, content narrowing is usually the **point** of the harness rather than a '
              'weakness in it: a rejection-classification harness exists precisely to pin a '
              'malformed shape and assert the exact error it must produce, and it must narrow to '
              'that shape to do so. What the list gives you is the ability to check that judgement '
              'yourself, harness by harness, instead of taking a count on trust.', '']
        L += ['- `%s::%s` — `assume(%s)`' % (a, b, c) for a, b, c in ca]
    else:
        L += ['', '- none: every assumption in the crate is a size or range bound.']
    return L


def r_vacuities(f):
    L = ['| Harness whose `cover` is UNSATISFIABLE at its bound | Companion witness harness | Does '
         'the witness itself use `#[kani::stub]`? |', '|---|---|---|']
    n, stubbed = 0, []
    for m in f['modules']:
        for harness, witness in m['disclosed_vacuities']:
            uses = witness in m['stub_harness_names']
            if uses:
                stubbed.append('%s::%s' % (m['module'], witness))
            L.append('| `%s::%s` | `%s::%s` | %s |'
                     % (m['module'], harness, m['module'], witness,
                        '**yes — read it as glue-reachability only**' if uses else 'no'))
            n += 1
    if not n:
        return ['- none disclosed.']
    L += ['', '**The third column is the one that changes what a witness means.** A cover satisfied '
          'inside a stub-bearing harness shows that the caller\'s glue is reachable *given a '
          'fabricated `Ok` from the stubbed sub-parser*. It is not evidence that the real '
          'sub-parser ever returns `Ok`, and therefore not evidence that the real composition '
          'accepts anything.']
    if stubbed:
        L += ['So for %s the "gap closed" claim is narrower than for the unstubbed rows: what is '
              'witnessed is the glue, under stub semantics.'
              % ', '.join('`%s`' % s for s in stubbed)]
    return L


def r_properties(f):
    L = []
    for m in f['modules']:
        if not m['harnesses']:
            L.append('- **`%s`** — no `#[kani::proof]` harness.' % m['module'])
            continue
        L.append('- **`%s`** (%d): %s' % (m['module'], m['n_harnesses'], ', '.join(
            '`%s`' % h['name'] for h in m['harnesses'])))
    return L


def r_l4(f):
    L = ['| Lid | Codec | Theorems + lemmas | Assumed Aeneas-Std specs (`axiom`) |',
         '|---|---|---:|---:|']
    for l in f['lids']:
        L.append('| `%s` | `%s` | %d | %d |' % (
            l['file'], l['codec'], l['theorems'], len(l['declared_axioms'])))
    L += ['', 'The `axiom` column counts the *assumed Aeneas-Std specs declared in the lid file '
          'itself* — the trust surface a reader can audit by opening the file. It excludes Lean\'s '
          'own `propext`/`Classical.choice`/`Quot.sound` and `bv_decide`\'s certificate axiom. '
          'Separately, the lids carry %d `#print axioms` commands: that is a count of *audit '
          'commands* (roughly one per theorem whose dependency set is disclosed at build time), '
          '**not** a count of axioms — do not compare it with the column.'
          % sum(l['print_axioms'] for l in f['lids']),
          '',
          'One limitation to name explicitly: a declared `axiom` characterising an Aeneas-Std '
          'primitive and a bespoke assumption about this crate\'s own code are syntactically '
          'identical, and the latter would be an unsound hole. Nothing in this repository '
          'mechanically distinguishes them — the argument that each is an upstream-primitive spec '
          'is made in the lid docstrings and rests on review, not on a gate.']
    return L


def r_oracles(f):
    rows = [(m['module'], m['proof_helpers'], m['oracle_harnesses'])
            for m in f['modules'] if m['proof_helpers'] or m['oracle_harnesses']]
    if not rows:
        return ['- none: `mod proofs` declares no helper functions anywhere in the crate.']
    L = ['| Module | Hand-written helpers in `mod proofs` (oracles + stub bodies) | Harnesses that '
         'assert an equivalence against one |', '|---|---|---|']
    nh = 0
    for mod, helpers, harnesses in rows:
        nh += len(helpers)
        L.append('| `%s` | %s | %s |' % (mod, ', '.join('`%s`' % o for o in helpers) or '—',
                                        ', '.join('`%s`' % h for h in harnesses) or '—'))
    L += ['', '%d hand-written helper functions in total. Derived by exclusion — every `fn` in a '
          '`mod proofs` block that is not itself a harness — so a helper cannot escape this list by '
          'being named something unexpected.' % nh]
    return L


def r_evidence(f):
    ev = f['evidence']
    if not ev:
        return [
            '**No raw proof-run log is committed in this repository.** Every full-suite verdict '
            'quoted here and in `DER-REMAINING-WORK.md` is a prose transcription of a run on the '
            'maintainer\'s machine. That is the weakest form of evidence in this document, and '
            'committing raw logs under `evidence/` — which this script then reads and reports in '
            'this table — is an open item (`TODO.md`).',
            '',
            'It does not follow that no third-party-inspectable evidence exists: the repository\'s '
            'public CI runs `cargo test`, clippy and the memory-tractable share of the Kani floor '
            'on every push, and those logs are machine-readable and public. What CI covers, and '
            'what it does not, is stated below — the point of this note is only that nothing is '
            'committed *in-tree*.',
        ]
    L = ['| Committed log | At commit | `SUCCESSFUL` | `FAILED` | harnesses reporting an '
         'unsatisfied cover |', '|---|---|---:|---:|---:|']
    for e in ev:
        L.append('| `%s` | `%s` | %d | %d | %d |' % (e['file'], e['commit'], e['successful'],
                                                     e['failed'], e['covers_unsatisfied']))
    L += ['',
          'Every column here is read out of the committed log itself, so this table is reproducible '
          'from the tree alone and is gate-enforced. Whether a given run still speaks for HEAD needs '
          '`git`, which a tarball or shallow clone may not have — that question is answered '
          'separately just below, and is advisory for exactly that reason.']
    return L


def r_evidence_coverage(f):
    """ADVISORY region: does a committed run still speak for HEAD's verified source?

    Derived with `git`, therefore NOT byte-compared. This distinction is the same one `pins` versus
    `pins-observed` draws, and for the same reason: a reader with no git history legitimately cannot
    reproduce it, and making `./check.sh` depend on that is how the gate previously became
    unrunnable by third parties. Keeping it OUT of the enforced set is deliberate.

    It exists because the alternative -- hand-written prose saying "the run at X still covers HEAD"
    -- silently rots the moment a source commit lands, and rots in the direction of over-claiming.
    """
    ev = f['evidence']
    if not ev:
        return ['No committed run log, so nothing to date against HEAD.']
    live = [e for e in ev if e['covers_head_source'] and not e['failed']]
    stale = [e for e in ev if e['covers_head_source'] is False]
    unknown = [e for e in ev if e['covers_head_source'] is None]
    L = []
    if live:
        L.append('**`%s` still speaks for HEAD.** No path it verified has changed since its commit: '
                 '`git diff %s..HEAD -- %s` is empty. Run that command rather than trusting this '
                 'sentence.' % (live[0]['file'], live[0]['commit'], ' '.join(VERIFIED_PATHS)))
    else:
        L.append('**No committed run currently speaks for HEAD\'s verified source.** Re-run '
                 '`./check.sh` and commit the log, or treat every full-suite verdict in this '
                 'document as a transcription again.')
    for e in stale:
        L.append('- `%s` (at `%s`) is superseded: verified source changed after it. It is kept as a '
                 'dated record, not as a current claim.' % (e['file'], e['commit']))
    for e in unknown:
        L.append('- `%s` (at `%s`): `git` could not answer, so no currency claim is made either '
                 'way. Absence of an answer is reported rather than defaulted to yes.'
                 % (e['file'], e['commit']))
    return L


REGIONS = {
    'pins': r_pins,
    'pins-observed': r_pins_observed,
    'inventory': r_inventory,
    'per-module': r_per_module,
    'unharnessed-entry-points': r_unharnessed,
    'bounds': r_bounds,
    'stubs': r_stubs,
    'oracles': r_oracles,
    'non-vacuity': r_nonvacuity,
    'disclosed-vacuities': r_vacuities,
    'properties': r_properties,
    'l4': r_l4,
    'evidence': r_evidence,
    'evidence-coverage': r_evidence_coverage,
}

# Regions `--write` regenerates but `--check` does NOT byte-compare. The bar for membership is
# narrow and should stay narrow: the region's content is a fact about the *machine that ran the
# generator*, so it cannot be reproduced by a reader checking out the same source. Everything
# derived from the tree — every count, and every declared pin — stays enforced. Marker presence
# is still enforced for these, so an advisory region cannot silently vanish from the manifest.
# `evidence-coverage` joins on the SAME test as `pins-observed`: its content is a probe of the
# environment (it needs git history), not a fact readable from the tree. Everything derived from the
# tree -- including every count in the `evidence` table -- stays enforced.
ADVISORY = {'pins-observed', 'evidence-coverage'}


# --------------------------------------------------------------------------------------
# guarded count-claims in prose (docs may repeat a number; it must be the right one)
# --------------------------------------------------------------------------------------

WORDNUM = {'one': 1, 'two': 2, 'three': 3, 'four': 4, 'five': 5, 'six': 6,
           'seven': 7, 'eight': 8, 'nine': 9, 'ten': 10, 'eleven': 11, 'twelve': 12,
           'thirteen': 13, 'fourteen': 14, 'fifteen': 15, 'sixteen': 16}

# Only documents that make *current-state* claims are guarded. CHANGELOG.md, DECISIONS.md and
# DER-REMAINING-WORK.md are dated, append-only, point-in-time records: a historical count in
# them is correct *as history* and must not be rewritten.
GUARDED_DOCS = ['PROOF_MANIFEST.md', 'README.md', 'der-verified/README.md',
                'docs/why-verified.md', 'docs/verification-cost.md', 'der-verified/src/lib.rs']

# A count, numeric or spelled. The lookbehind matters: without it, "X.509 harnesses" reads as
# the number 509 and the guard fires on a phantom drift.
#
# The trailing `(?:\*\*|\*|`)?` closes a MEASURED hole (2026-08-03). `README.md`'s headline line reads
# `- **309** unit and regression tests`, and the emphasis markers sit between the number and the
# whitespace, so `\s+` could not match and the guard never fired. That line went stale by 11 tests
# while this gate reported PASS — in the repo's most-read file, on the count the crate's pitch leads
# with. Verified by re-staling it deliberately: rc=0 before this change, rc=1 after.
NUM = r'(?<![\w.])(\d+|%s)(?:\*\*|\*|`)?' % '|'.join(WORDNUM)

GUARDS = [
    ('harnesses', NUM + r'\s+Kani harnesses'),
    ('harnesses', NUM + r'\s+proof harnesses'),
    ('harnesses', NUM + r'\s+`#\[kani::proof\]` harnesses'),
    ('harnesses', r'All\s+' + NUM + r'\s+harnesses'),
    ('harnesses', r'of the\s+' + NUM + r'\s+harnesses'),
    ('tests', NUM + r'\s+unit and regression tests'),
    # `docs/why-verified.md` says "concrete and regression tests" for the same number. A guard is a
    # fixed phrase list, so a synonym is invisible to it — that line was the second stale count this
    # gate passed on 2026-08-03. Adding the variant is the narrow fix; the general lesson is that the
    # PASS line below counts DOCUMENTS scanned, not claims covered, and must not be read as coverage.
    ('tests', NUM + r'\s+concrete and regression tests'),
    ('tests', r'#\s*' + NUM + r'\s+tests'),
    ('tests', NUM + r'\s+tests\b'),
    ('assumes', r'\(' + NUM + r'\s+across the crate\)'),
    ('covers', NUM + r'\s+`kani::cover`'),
    ('lids', NUM + r'\s+(?:L4/L5\s+)?lids'),
    ('lids', NUM + r'\s+codecs'),
    ('modules_with_kani', r'across\s+' + NUM + r'\s+modules'),
    ('modules_with_kani', r'harnesses over\s+' + NUM),
    # prose counts inside the manifest itself, so its two halves can never disagree
    ('stub_harnesses', NUM + r'\s+(?:X\.509\s+)?harnesses are \*\*modular'),
    ('disclosed_vacuities', NUM + r'\s+harnesses have a cover'),
    ('unharnessed_entry_points', r'one of the\s+' + NUM + r'\s+above'),
]


def guard_violations(f):
    t = f['totals']
    bad = []
    for doc in GUARDED_DOCS:
        p = os.path.join(ROOT, doc)
        if not os.path.exists(p):
            continue
        for lineno, line in enumerate(read_text(p).split('\n'), 1):
            for key, pat in GUARDS:
                for m in re.finditer(pat, line):
                    raw = m.group(1)
                    got = WORDNUM.get(raw.lower(), None)
                    got = int(raw) if got is None else got
                    if got != t[key]:
                        bad.append((doc, lineno, key, got, t[key], m.group(0).strip()))
    return bad


# --------------------------------------------------------------------------------------
# region rewrite / check
# --------------------------------------------------------------------------------------

def render(f, name):
    return '\n'.join(REGIONS[name](f))


def split_region(text, name):
    """(prefix, committed body incl. its surrounding newlines, suffix), or None if unmarked."""
    b, e = BEGIN % name, END % name
    if b not in text or e not in text:
        return None
    pre, rest = text.split(b, 1)
    body, post = rest.split(e, 1)
    return pre, body, post


def rewrite(text, f):
    missing = []
    for name in REGIONS:
        parts = split_region(text, name)
        if parts is None:
            missing.append(name)
            continue
        pre, _, post = parts
        text = pre + (BEGIN % name) + '\n' + render(f, name) + '\n' + (END % name) + post
    return text, missing


def region_diffs(text, f):
    """Enforced regions whose committed body disagrees with what the source now generates.

    ADVISORY regions are skipped: they record the regenerating machine's environment, which a
    reader cannot reproduce and is not being asked to. Skipping them here (rather than comparing
    the whole file) is what keeps `./check.sh` runnable by a stranger with a different rustc.
    """
    out = []
    for name in REGIONS:
        if name in ADVISORY:
            continue
        parts = split_region(text, name)
        if parts is None:
            continue  # reported as a missing marker instead
        committed, generated = parts[1], '\n' + render(f, name) + '\n'
        if committed != generated:
            # Split, never strip: the newlines bracketing a region body are part of the enforced
            # format, so stripping them would report a difference and then print an EMPTY diff
            # whenever that difference is only in those newlines — a gate that fails without
            # saying why is worse than the blanket message this replaced.
            out.append((name, committed.split('\n'), generated.split('\n')))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    f = collect()

    if args.json:
        print(json.dumps(f, indent=2, sort_keys=True))
        return 0

    text = read_text(MANIFEST)
    new, missing = rewrite(text, f)

    if args.write:
        if missing:
            print('gen_proof_manifest: WARNING missing region markers: %s' % ', '.join(missing),
                  file=sys.stderr)
        if new != text:
            with open(MANIFEST, 'w', encoding='utf-8') as fh:
                fh.write(new)
            print('gen_proof_manifest: PROOF_MANIFEST.md regenerated')
        else:
            print('gen_proof_manifest: PROOF_MANIFEST.md already current')
        bad = guard_violations(f)
        for doc, lineno, key, got, want, snippet in bad:
            print('  count-claim to fix by hand: %s:%d  %r says %s=%d, source says %d'
                  % (doc, lineno, snippet, key, got, want), file=sys.stderr)
        return 1 if bad else 0

    if args.check:
        fail = False
        if missing:
            print('!! proof-manifest gate: FAIL - missing generated region marker(s): %s'
                  % ', '.join(missing), file=sys.stderr)
            fail = True
        diffs = region_diffs(text, f)
        if diffs:
            print('!! proof-manifest gate: FAIL - %d generated region(s) of PROOF_MANIFEST.md '
                  'disagree with the source tree: %s'
                  % (len(diffs), ', '.join(n for n, _, _ in diffs)), file=sys.stderr)
            for name, committed, generated in diffs:
                d = list(difflib.unified_diff(
                    committed, generated, lineterm='', n=1,
                    fromfile='PROOF_MANIFEST.md region %r (committed)' % name,
                    tofile='generated from source now'))
                for line in d[:DIFF_LINES]:
                    print('   %s' % line, file=sys.stderr)
                if len(d) > DIFF_LINES:
                    print('   … and %d further diff line(s) in region %r, not shown'
                          % (len(d) - DIFF_LINES, name), file=sys.stderr)
            print('   Fix: python3 gates/gen_proof_manifest.py --write — the manifest follows the '
                  'source, never the reverse. If you did not change the source, do NOT run '
                  '--write; read the diff above and report it as a gate bug.', file=sys.stderr)
            fail = True
        for doc, lineno, key, got, want, snippet in guard_violations(f):
            print('!! proof-manifest gate: FAIL - %s:%d claims %s=%d, source says %d (%r)'
                  % (doc, lineno, key, got, want, snippet), file=sys.stderr)
            fail = True
        if fail:
            return 1
        print('== proof-manifest gate: PASS (generated regions + %d guarded count-claims current) =='
              % len(GUARDED_DOCS))
        return 0

    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
