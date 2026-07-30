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

BEGIN = '<!-- BEGIN GENERATED:%s (gates/gen_proof_manifest.py) -->'
END = '<!-- END GENERATED:%s -->'

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


def entry_points_of(path, lines, bounds):
    """Public entry points: free `pub fn`s AND public inherent-impl methods.

    Free functions sit at column 0; methods are indented inside an `impl Type` block. The first
    version of this scanned column 0 only, which silently missed four public methods
    (`Charset::{tag_number,identifier,contains}`, `Elements::new`) — an undercount of the
    unharnessed-entry-point gap, i.e. an overclaim by omission. The cross-family review flagged the
    column-0 assumption as a latent bug; adding the check found it was already an active one.

    Anything indented that is neither in `mod proofs`/`mod tests` nor inside an `impl` block would be
    a nested module, which this scheme cannot attribute — so that case fails the gate loudly rather
    than quietly miscounting.
    """
    pi, ti = bounds
    end = min(x for x in (pi, ti, len(lines)) if x is not None)
    out, impl, depth_in_impl = [], None, False
    for i, l in enumerate(lines[:end]):
        m = re.match(r'impl(?:<[^>]*>)?\s+([A-Za-z0-9_]+)', l)
        if m:
            impl, depth_in_impl = m.group(1), True
        elif re.match(r'\}\s*$', l):
            depth_in_impl = False
        m = re.match(r'pub (?:const |unsafe )?fn ([A-Za-z0-9_]+)', l)
        if m:
            out.append(m.group(1))
            continue
        m = re.match(r'\s+pub (?:const |unsafe )?fn ([A-Za-z0-9_]+)', l)
        if m:
            if not depth_in_impl:
                raise SystemExit(
                    'gen_proof_manifest: %s:%d has an indented `pub fn` that is not inside an '
                    '`impl` block:\n  %s\nEntry-point detection cannot attribute it (a nested '
                    'module?). Teach the script about it rather than letting the count drift.'
                    % (path, i + 1, l.rstrip()))
            out.append('%s::%s' % (impl or '?', m.group(1)))
    return out


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
        if not any(re.match(r'\s*#\[kani::proof(_for_contract)?', a) for a in attrs):
            continue
        code = strip_comments(body)
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
    return out


def module_facts(path):
    lines = open(path, encoding='utf-8').read().split('\n')
    _top, proofs, tests, bounds = split_regions(lines)
    entry_points = entry_points_of(path, lines, bounds)
    # A `pub fn` declared AFTER the proof/test modules is still a public entry point; scanning only
    # the region above `mod proofs` made it invisible (negative-tested). Picked up here.
    pi, ti = bounds
    tail = lines[ti:] if ti is not None else (lines[pi:] if pi is not None else [])
    entry_points += [m.group(1) for l in tail
                     for m in [re.match(r'pub (?:const |unsafe )?fn ([A-Za-z0-9_]+)', l)] if m]
    harnesses = parse_harnesses(proofs, const_widths(lines))
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
        # strip_comments first: `//!   Tested (`#[test]`) only so far` is prose, not a test.
        # Counting it inflated the total by one against what `cargo test` actually runs.
        'n_tests': sum(l.count('#[test]') for l in strip_comments(tests)),
    }


def lean_facts():
    lids = []
    for f in sorted(os.listdir(LEAN)):
        if not f.endswith('Proofs.lean'):
            continue
        text = open(os.path.join(LEAN, f), encoding='utf-8').read()
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
            return open(os.path.join(ROOT, p), encoding='utf-8').read()
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
            text = open(p, encoding='utf-8', errors='replace').read()
            out.append({
                'file': 'evidence/' + f,
                'commit': (re.search(r'^#\s*commit:\s*([0-9a-f]{7,40})', text, re.M) or
                           [None, 'unrecorded'])[1],
                'successful': len(re.findall(r'VERIFICATION:- ?SUCCESSFUL|VERIFICATION: SUCCESSFUL', text)),
                'failed': len(re.findall(r'VERIFICATION:- ?FAILED|VERIFICATION: FAILED', text)),
                'covers_unsatisfied': len(re.findall(r'0 of \d+ cover propert', text)),
            })
    return out


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
    lib = open(os.path.join(SRC, 'lib.rs'), encoding='utf-8').read()
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
                                     open(os.path.join(SRC, f), encoding='utf-8').read().split('\n'))),
        },
    }


# --------------------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------------------

def r_pins(f):
    d, o = f['toolchain']['declared'], f['toolchain']['observed']
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
         'Observed on the machine that last regenerated this section: rustc `%s`, Kani `%s`, '
         'Aeneas `%s`, Charon `%s`.'
         % (o['rustc'], o['kani'], o['aeneas_rev'][:40], o['charon_rev'][:40]),
         '',
         'Because the rustc pin is a floating channel, **the rustc version is a property of the '
         'run, not of the crate**: a reader reproducing these results on a different stable will '
         'be checking the same source with a different compiler. The Kani harnesses are insulated '
         'from this (Kani ships its own toolchain); `cargo test` is not.']
    return L


def r_inventory(f):
    t = f['totals']
    return [
        '| Inventory (static, derived from source at `%s`) | Count |' % f['head'],
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
        '| `kani::cover` non-vacuity witnesses | %d |' % t['covers'],
        '| …harnesses whose cover is **known-unsatisfiable and disclosed** | **%d** |'
        % t['disclosed_vacuities'],
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
          '*different* kind of witness, not automatically a better one. Each asserts a functional '
          'outcome — a biconditional, a round-trip, or an exact `Err` variant — which can only hold '
          'if the code produced a specific correct result, so the harness cannot be silently empty. '
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
    L = ['| Harness whose `cover` is UNSATISFIABLE at its bound | Positive-construction witness '
         'that closes the gap |', '|---|---|']
    n = 0
    for m in f['modules']:
        for harness, witness in m['disclosed_vacuities']:
            L.append('| `%s::%s` | `%s::%s` |' % (m['module'], harness, m['module'], witness))
            n += 1
    if not n:
        return ['- none disclosed.']
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
    L += ['', 'Every lid discloses its full non-standard axiom set via `#print axioms` (%d such '
          'disclosures across the lids). The `axiom` column counts only the *assumed Aeneas-Std '
          'specs declared in the lid file itself* — the honest trust surface a reader should '
          'audit; it excludes Lean\'s own `propext`/`Classical.choice`/`Quot.sound` and '
          '`bv_decide`\'s certificate axiom.' % sum(l['print_axioms'] for l in f['lids'])]
    return L


def r_evidence(f):
    ev = f['evidence']
    if not ev:
        return [
            '**There is no committed raw proof-run log in this repository.** The verdicts quoted '
            'in this manifest and in `DER-REMAINING-WORK.md` are prose transcriptions of runs made '
            'on the maintainer\'s machine, not machine-readable artifacts a third party can '
            'inspect. Treat them accordingly: the *re-runnable gate* (`./check.sh`) is the real '
            'evidence offer, and a reader who wants the verdict should run it. Committing raw logs '
            'under `evidence/` (which this script then reads and reports here) is an open item.',
        ]
    L = ['| Committed log | At commit | `SUCCESSFUL` | `FAILED` | harnesses reporting an '
         'unsatisfied cover |', '|---|---|---:|---:|---:|']
    for e in ev:
        L.append('| `%s` | `%s` | %d | %d | %d |' % (e['file'], e['commit'], e['successful'],
                                                     e['failed'], e['covers_unsatisfied']))
    return L


REGIONS = {
    'pins': r_pins,
    'inventory': r_inventory,
    'per-module': r_per_module,
    'unharnessed-entry-points': r_unharnessed,
    'bounds': r_bounds,
    'stubs': r_stubs,
    'non-vacuity': r_nonvacuity,
    'disclosed-vacuities': r_vacuities,
    'properties': r_properties,
    'l4': r_l4,
    'evidence': r_evidence,
}


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
NUM = r'(?<![\w.])(\d+|%s)' % '|'.join(WORDNUM)

GUARDS = [
    ('harnesses', NUM + r'\s+Kani harnesses'),
    ('harnesses', NUM + r'\s+proof harnesses'),
    ('harnesses', NUM + r'\s+`#\[kani::proof\]` harnesses'),
    ('harnesses', r'All\s+' + NUM + r'\s+harnesses'),
    ('harnesses', r'of the\s+' + NUM + r'\s+harnesses'),
    ('tests', NUM + r'\s+unit and regression tests'),
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
        for lineno, line in enumerate(open(p, encoding='utf-8').read().split('\n'), 1):
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


def rewrite(text, f):
    missing = []
    for name in REGIONS:
        b, e = BEGIN % name, END % name
        if b not in text or e not in text:
            missing.append(name)
            continue
        pre, rest = text.split(b, 1)
        _, post = rest.split(e, 1)
        text = pre + b + '\n' + render(f, name) + '\n' + e + post
    return text, missing


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

    text = open(MANIFEST, encoding='utf-8').read()
    new, missing = rewrite(text, f)

    if args.write:
        if missing:
            print('gen_proof_manifest: WARNING missing region markers: %s' % ', '.join(missing),
                  file=sys.stderr)
        if new != text:
            open(MANIFEST, 'w', encoding='utf-8').write(new)
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
        if new != text:
            print('!! proof-manifest gate: FAIL - PROOF_MANIFEST.md\'s generated regions are stale '
                  '(source and manifest disagree).', file=sys.stderr)
            print('   Fix: python3 gates/gen_proof_manifest.py --write', file=sys.stderr)
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
