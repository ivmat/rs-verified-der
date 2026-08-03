#!/usr/bin/env python3
"""gen_verification_map.py — derive README.md's mermaid "verification map" from the source tree.

WHY THIS EXISTS
---------------
A hand-drawn diagram of "which modules are proven how far" is exactly the kind of claim that
rots the moment coverage changes and nobody remembers to redraw it. This script exists so the
diagram in `README.md` cannot rot: it is regenerated from the same sources the rest of the
gate suite already trusts, and `--check` (wired into `check.sh`/`check_fast.sh`) fails if the
committed diagram disagrees with what the tree now says.

TWO KINDS OF COLOUR, ONE HONEST SPLIT
--------------------------------------
  * DERIVED (green, blue) — read straight from the tree, and can never silently drift:
      - green = L4/L5: a module carrying an Aeneas -> Lean lid. Derived via
        `gen_proof_manifest.l4_module_set()` — IMPORTED, not re-derived, so this script's
        green set can never quietly diverge from `PROOF_MANIFEST.md`'s own L4 column.
      - blue  = L3: every harnessed module in `gates/tiers.txt`, minus the green set.
        `gates/tiers.txt` is a memory-cost split (LIGHT/HEAVY), not an evidence axis — it is
        used here only as the roster of "this module is Kani-harnessed", exactly the role
        `gates/check_tier_parity.py` already holds it to.
  * DECLARED (yellow, red, gray) — NOT derivable from code, so they are human judgements,
    recorded in `gates/map_declared.txt` with a source citation per row. This script only
    validates and renders them; it does not (and cannot) derive them.

MODES
-----
    python3 gates/gen_verification_map.py --check   # gate: README.md's map region vs source
    python3 gates/gen_verification_map.py --write   # regenerate the map region
    python3 gates/gen_verification_map.py --json    # dump the derived facts

Pure stdlib, no network, no cargo invocation — safe inside any gate.
"""

import argparse
import difflib
import json
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

if HERE not in sys.path:
    sys.path.insert(0, HERE)
import gen_proof_manifest as gpm      # noqa: E402  (reuses l4_module_set(), region-marker plumbing)
import check_tier_parity as ctp       # noqa: E402  (reuses tiers.txt parsing)

README = os.path.join(ROOT, 'README.md')
DECLARED = os.path.join(HERE, 'map_declared.txt')
TIERS = ctp.TIERS

NAME = 'map'
DIFF_LINES = gpm.DIFF_LINES

# Deliberately NOT `gen_proof_manifest.BEGIN`/`.END`: those hardcode "(gates/gen_proof_manifest.py)"
# as the attribution, so reusing them here would stamp README's map region with the wrong
# generator's name. Marker *parsing* (`split_region`) is still the same shape, and is small enough
# to keep local rather than force gen_proof_manifest.py to parameterise its own constants.
BEGIN = '<!-- BEGIN GENERATED:%s (gates/gen_verification_map.py) -->'
END = '<!-- END GENERATED:%s -->'

# The three base X.690 framing primitives — a closed set by definition (this is the crate's
# bottom layer; a fourth "framing" primitive would be a new ASN.1 metalanguage feature, not an
# ordinary codec addition). A NEW content codec or a NEW x509_* module needs no change here —
# see `layer_of` below, which is a total function over the whole roster.
FRAMING = {'tag', 'length', 'tlv'}
PROFILE_MODULES = {'profile'}
STRUCTURAL_PREFIX = 'x509_'

COLORS = {'yellow', 'red', 'gray'}
LAYERS = ['crypto', 'profile', 'structural', 'codecs', 'framing']
LAYER_TITLES = {
    'crypto': 'cryptographic layer — outside the fence, not verified',
    'profile': 'RFC 5280 profile rules',
    'structural': 'X.509 structural composition',
    'codecs': 'DER content codecs',
    'framing': 'tag / length / TLV framing base',
}

ID_RE = re.compile(r'^[a-z][a-z0-9_]*$')


# --------------------------------------------------------------------------------------
# derivation
# --------------------------------------------------------------------------------------

def roster_from_tiers(path=TIERS):
    """Every module `gates/tiers.txt` declares harnessed (LIGHT + HEAVY), as a set."""
    light, heavy = ctp.read_tiers(path)
    return set(light) | set(heavy)


def derive_colors(roster, l4):
    """Pure split: green = the L4 subset actually on the roster; blue = the rest of the roster.

    Kept pure (no I/O) so a lid gain/loss can be tested by handing this function a modified `l4`
    set directly, instead of monkeypatching `gen_proof_manifest`.
    """
    green = sorted(roster & l4)
    blue = sorted(roster - l4)
    return green, blue


def layer_of(module):
    """Which diagram subgraph a DERIVED (roster) module belongs in. Total over the roster: every
    module lands somewhere, including one never seen before — `codecs` is the catch-all, so a
    brand-new content codec needs no change here to show up in the picture."""
    if module in FRAMING:
        return 'framing'
    if module in PROFILE_MODULES:
        return 'profile'
    if module.startswith(STRUCTURAL_PREFIX):
        return 'structural'
    return 'codecs'


def read_declared(path=DECLARED):
    """Parse `gates/map_declared.txt`: TAB-separated `color / id / layer / label / source`.

    Every row must cite a source (the file's whole point is auditability), every id must be a
    mermaid-safe identifier, and ids must be unique within the file. Cross-checking against the
    DERIVED roster (collision, coverage) is `parity_errors`'s job, not this function's — this one
    only validates the file's own internal shape.
    """
    rows = []
    text = gpm.read_text(path)
    for lineno, raw in enumerate(text.split('\n'), 1):
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        parts = raw.split('\t')
        if len(parts) != 5:
            raise SystemExit(
                'gen_verification_map: %s:%d: expected 5 tab-separated fields '
                '(color, id, layer, label, source), got %d: %r' % (path, lineno, len(parts), raw))
        color, id_, layer, label, source = (p.strip() for p in parts)
        if color not in COLORS:
            raise SystemExit('gen_verification_map: %s:%d: color %r not in %s'
                             % (path, lineno, color, sorted(COLORS)))
        if layer not in LAYERS:
            raise SystemExit('gen_verification_map: %s:%d: layer %r not in %s'
                             % (path, lineno, layer, LAYERS))
        if not ID_RE.match(id_):
            raise SystemExit('gen_verification_map: %s:%d: id %r is not a mermaid-safe identifier '
                             '(must match %s)' % (path, lineno, id_, ID_RE.pattern))
        if not label:
            raise SystemExit('gen_verification_map: %s:%d: row has no label' % (path, lineno))
        if not source:
            raise SystemExit(
                'gen_verification_map: %s:%d: declared row %r has no source reference — a '
                'declared judgement without a citation cannot be audited; leave the row out '
                'instead of adding it unsourced.' % (path, lineno, id_))
        rows.append({'color': color, 'id': id_, 'layer': layer, 'label': label, 'source': source})

    ids = [r['id'] for r in rows]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise SystemExit('gen_verification_map: %s: duplicate declared id(s): %s' % (path, dupes))
    return rows


def parity_errors(roster, green, blue, declared):
    """Two failure modes this exists to catch, mirroring `check_tier_parity.py`'s intent:

      1. A declared id colliding with a derived module name — the declared node would silently
         shadow (or be shadowed by) the real one in the rendered diagram.
      2. A roster module in NEITHER the derived set (green/blue) NOR the declared set — i.e. a
         module that would silently vanish from the picture instead of being drawn at all.
    """
    errs = []
    declared_ids = {d['id'] for d in declared}
    collisions = sorted(declared_ids & roster)
    if collisions:
        errs.append('declared id(s) collide with a derived module name in gates/tiers.txt: %s'
                    % collisions)
    covered = set(green) | set(blue) | declared_ids
    missing = sorted(roster - covered)
    if missing:
        errs.append('module(s) in gates/tiers.txt absent from the rendered map (neither derived '
                    'nor declared, so they would silently vanish from the picture): %s' % missing)
    return errs


def compute():
    """Everything the render needs, derived from the real tree. Raises SystemExit (not a return
    code) on any parity failure — mirrors `gen_proof_manifest.collect()`'s own idiom for an
    unmapped lid: a structural inconsistency here is a bug in the generator or its inputs, not an
    ordinary drift `--check` should merely report and move past."""
    roster = roster_from_tiers()
    l4 = gpm.l4_module_set()
    off_roster = sorted(l4 - roster)
    if off_roster:
        raise SystemExit(
            'gen_verification_map: Lean lid(s) exist for module(s) not in gates/tiers.txt (not '
            'even Kani-harnessed?): %s' % off_roster)
    green, blue = derive_colors(roster, l4)
    declared = read_declared()
    errs = parity_errors(roster, green, blue, declared)
    if errs:
        raise SystemExit('gen_verification_map: ' + '; '.join(errs))
    return roster, green, blue, declared


# --------------------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------------------

def _node_line(id_, label, color):
    safe_label = label.replace('"', "'")
    return '        %s["%s"]:::%s' % (id_, safe_label, color)


def render_map():
    _roster, green, blue, declared = compute()

    nodes_by_layer = {l: [] for l in LAYERS}
    for m in green:
        nodes_by_layer[layer_of(m)].append((m, m, 'green'))
    for m in blue:
        nodes_by_layer[layer_of(m)].append((m, m, 'blue'))
    for d in declared:
        nodes_by_layer[d['layer']].append((d['id'], d['label'], d['color']))

    lines = [
        '```mermaid',
        'flowchart TB',
        '    classDef green fill:#1b7f4d,stroke:#0a3d22,color:#ffffff',
        '    classDef blue fill:#2f6fb0,stroke:#173a5e,color:#ffffff',
        '    classDef yellow fill:#b58a1a,stroke:#5c4610,color:#ffffff',
        '    classDef red fill:#b3382a,stroke:#5c1a10,color:#ffffff',
        '    classDef gray fill:#6b6b6b,stroke:#333333,color:#ffffff',
        '',
    ]
    for layer in LAYERS:
        lines.append('    subgraph %s_layer["%s"]' % (layer, LAYER_TITLES[layer]))
        if layer == 'crypto':
            lines.append('        style %s_layer stroke-dasharray: 6 4' % layer)
        for id_, label, color in sorted(nodes_by_layer[layer]):
            lines.append(_node_line(id_, label, color))
        lines.append('    end')
    lines += [
        '',
        '    crypto_layer -.-> profile_layer --> structural_layer --> codecs_layer --> framing_layer',
        '',
        '    subgraph legend["Legend"]',
        '        legend_green["green = L4/L5 (Aeneas → Lean lid), DERIVED"]:::green',
        '        legend_blue["blue = L3 (Kani-harnessed), DERIVED"]:::blue',
        '        legend_yellow["yellow = planned, DECLARED"]:::yellow',
        '        legend_red["red = a wall we hit, DECLARED"]:::red',
        '        legend_gray["gray = deliberately not planned, DECLARED"]:::gray',
        '    end',
        '```',
    ]
    return lines


def render():
    return '\n'.join(render_map())


# --------------------------------------------------------------------------------------
# region rewrite / check (same marker-region idiom as gen_proof_manifest.py)
# --------------------------------------------------------------------------------------

def split_region(text, name):
    """(prefix, committed body incl. surrounding newlines, suffix), or None if unmarked. Same
    shape as `gen_proof_manifest.split_region`, kept local because it closes over THIS module's
    `BEGIN`/`END` (which name this generator, not `gen_proof_manifest.py`)."""
    b, e = BEGIN % name, END % name
    if b not in text or e not in text:
        return None
    pre, rest = text.split(b, 1)
    body, post = rest.split(e, 1)
    return pre, body, post


def region_diff(text):
    """None if the committed `map` region already matches source, else (committed, generated)."""
    parts = split_region(text, NAME)
    if parts is None:
        return None
    committed, generated = parts[1], '\n' + render() + '\n'
    if committed == generated:
        return None
    return committed.split('\n'), generated.split('\n')


def rewrite(text):
    parts = split_region(text, NAME)
    if parts is None:
        return text, True
    pre, _, post = parts
    new = pre + (BEGIN % NAME) + '\n' + render() + '\n' + (END % NAME) + post
    return new, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument('--write', action='store_true')
    ap.add_argument('--check', action='store_true')
    ap.add_argument('--json', action='store_true')
    args = ap.parse_args()

    if args.json:
        roster, green, blue, declared = compute()
        print(json.dumps({'roster': sorted(roster), 'green': green, 'blue': blue,
                          'declared': declared}, indent=2, sort_keys=True))
        return 0

    text = gpm.read_text(README)

    if args.write:
        new, missing = rewrite(text)
        if missing:
            print('gen_verification_map: WARNING missing generated region marker: %s' % NAME,
                  file=sys.stderr)
            return 1
        if new != text:
            with open(README, 'w', encoding='utf-8') as fh:
                fh.write(new)
            print('gen_verification_map: README.md verification map regenerated')
        else:
            print('gen_verification_map: README.md verification map already current')
        return 0

    if args.check:
        parts = split_region(text, NAME)
        if parts is None:
            print('!! verification-map gate: FAIL - missing generated region marker: %s' % NAME,
                  file=sys.stderr)
            return 1
        diff = region_diff(text)
        if diff is not None:
            committed, generated = diff
            print('!! verification-map gate: FAIL - the "map" region of README.md disagrees with '
                  'the source tree (gates/tiers.txt, the Lean lid set, gates/map_declared.txt):',
                  file=sys.stderr)
            d = list(difflib.unified_diff(
                committed, generated, lineterm='', n=1,
                fromfile='README.md region "map" (committed)', tofile='generated from source now'))
            for line in d[:DIFF_LINES]:
                print('   %s' % line, file=sys.stderr)
            if len(d) > DIFF_LINES:
                print('   … and %d further diff line(s), not shown' % (len(d) - DIFF_LINES),
                      file=sys.stderr)
            print('   Fix: python3 gates/gen_verification_map.py --write — the map follows the '
                  'source, never the reverse.', file=sys.stderr)
            return 1
        print('== verification-map gate: PASS (README.md verification map current) ==')
        return 0

    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
