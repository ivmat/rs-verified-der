#!/usr/bin/env python3
"""gen_verification_map.py — derive README.md's mermaid "verification map" from the acceptance manifest.

WHY THIS EXISTS
---------------
A hand-drawn diagram of "which modules are proven how far" is exactly the kind of claim that
rots the moment coverage changes and nobody remembers to redraw it. This script exists so the
diagram in `README.md` cannot rot: it is regenerated from the same sources the rest of the
gate suite already trusts, and `--check` (wired into `check.sh`/`check_fast.sh`) fails if the
committed diagram disagrees with what the tree now says.

WHAT THE COLOUR MEANS — AND WHY IT CHANGED (2026-09-05)
------------------------------------------------------
The first version of this map coloured by TOOL: green for a module carrying an Aeneas -> Lean lid,
blue for every other Kani-harnessed module. Both colours read as "done" to any reader, and most of
this crate's claims are NOT done by the bar the project sets for itself: they carry no control that
was watched to fail, so they sit at band A0 or A1. A picture where nearly every box is green or blue
while two thirds of the claims are uncontrolled is an overclaim, whatever the caption underneath
says.

Colour is therefore the **assurance BAND**, read from the acceptance/0 manifest
(`der-verified/acceptance.toml`, itself GENERATED and gate-validated against a pinned validator):

  * A4 — unbounded functional proof, kernel-checked, with a red mutation control.
  * A3 — bounded functional contract, with a red mutation control.
  * A2 — memory safety on the unsafe surface, with a control. (None in this crate.)
  * A1 — non-vacuous but not state-exhaustive; no functional control.
  * A0 — ran or asserted; NO control was watched to fail. Harness count is irrelevant here.

A band above A0 requires an observed-red control — a deliberate fault the oracle had to reject — so
a module with sixteen harnesses and no such control is A0, and is drawn grey. GRADE (contract /
probe / ungraded) is a SEPARATE axis and is printed in each group's own label rather than folded
into the colour, because a probe-grade claim can be perfectly honest without being a contract.

Two kinds of node, one honest split, unchanged in spirit from the first version:

  * DERIVED — every band/grade node. Read from the manifest, never hand-set here. The lid set the
    manifest declares (its `PM/lean-*` claims) is cross-checked against
    `gen_proof_manifest.l4_module_set()`, so the manifest and the source tree cannot tell a reader
    two different stories about which codecs carry a Lean lid.
  * DECLARED — the white dashed "no claim exists" nodes (planned / wall / out of scope). Not
    derivable from code: they are a human's read of the project's own prose, recorded in
    `gates/map_declared.txt` with a source citation per row. This script validates and renders
    them; it does not (and cannot) derive them.

The module ROSTER is still `gates/tiers.txt` (held against the source tree by
`gates/check_tier_parity.py`). A roster module with no claim in the manifest is drawn as `unrated`,
never as a band — the failure direction that cannot overclaim. A manifest claim that maps to no
rendered node is a hard error: the picture would be hiding something the manifest says.

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
import tomllib

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

if HERE not in sys.path:
    sys.path.insert(0, HERE)
import gen_proof_manifest as gpm      # noqa: E402  (reuses l4_module_set(), region-marker plumbing)
import check_tier_parity as ctp       # noqa: E402  (reuses tiers.txt parsing)

README = os.path.join(ROOT, 'README.md')
DECLARED = os.path.join(HERE, 'map_declared.txt')
ACCEPTANCE = os.path.join(ROOT, 'der-verified', 'acceptance.toml')
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

# Declared (non-derivable) node classes, i.e. "the manifest has no claim here, and here is why".
# These are NOT bands: nothing was measured, so nothing may be coloured as if it had been. They all
# render as white dashed boxes and differ only in the reason printed on the box.
DECLARED_CLASSES = {
    'planned': 'no claim — planned',
    'wall': 'no claim — a wall we hit',
    'out-of-scope': 'no claim — deliberately out of scope',
}

LAYERS = ['crypto', 'profile', 'structural', 'codecs', 'framing']
LAYER_TITLES = {
    'crypto': 'cryptographic layer — outside the fence, not verified',
    'profile': 'RFC 5280 profile rules',
    'structural': 'X.509 structural composition',
    'codecs': 'DER content codecs',
    'framing': 'tag / length / TLV framing base',
}
LID_LAYER_TITLE = ('unbounded Lean-lid claims — SEPARATE claims (PM/lean-*), '
                   'each proven over inputs of ANY length')

# Descending strength. A3.5 is reserved in the format (its tool is not adopted); it is accepted
# here so an unexpected band never crashes the picture into silence.
BAND_ORDER = ['A4', 'A3.5', 'A3', 'A2', 'A1', 'A0']
BAND_AT_OR_ABOVE_TARGET = {'A4', 'A3.5', 'A3'}    # the project's stated target: A3 or better
TARGET_BAND = 'A3'

# Colour ramp: strength descends green -> amber -> grey. Deliberately NOT a traffic light with a
# large green plateau — A3 is a lighter green than A4 because bounded is not unbounded, and A0 is
# grey rather than red because "nobody watched this oracle fail" is an absence, not a defect.
BAND_STYLE = {
    'A4': 'fill:#12633c,stroke:#08301d,color:#ffffff',
    'A3.5': 'fill:#5fa877,stroke:#2f6146,color:#ffffff',
    'A3': 'fill:#9ed0a8,stroke:#3f7a4c,color:#0d2a15',
    'A2': 'fill:#d99b1c,stroke:#6f4f0c,color:#241a04',
    'A1': 'fill:#f2dda6,stroke:#8a6d2f,color:#3a2c08',
    'A0': 'fill:#9b9b9b,stroke:#4d4d4d,color:#111111',
}
BAND_MEANING = {
    'A4': 'unbounded functional proof, kernel-checked, red mutation control',
    'A3.5': 'refinement-shaped invariants (reserved band; tool not adopted)',
    'A3': 'bounded functional contract, red mutation control',
    'A2': 'memory safety on the unsafe surface, with a control',
    'A1': 'non-vacuous but not state-exhaustive, and no functional control',
    'A0': 'ran or asserted, with NO control watched to fail — the claim is not done',
}
# The ladder always printed in the legend, present or not: a reader has to be able to see the rung
# this crate is NOT standing on.
LEGEND_LADDER = ['A4', 'A3', 'A2', 'A1', 'A0']

UNRATED_STYLE = 'fill:#ffffff,stroke:#4d4d4d,stroke-dasharray: 3 3,color:#111111'
NOCLAIM_STYLE = 'fill:#ffffff,stroke:#8a8a8a,stroke-dasharray: 5 4,color:#333333'

ID_RE = re.compile(r'^[a-z][a-z0-9_]*$')


# --------------------------------------------------------------------------------------
# derivation
# --------------------------------------------------------------------------------------

def roster_from_tiers(path=TIERS):
    """Every module `gates/tiers.txt` declares harnessed (LIGHT + HEAVY), as a set."""
    light, heavy = ctp.read_tiers(path)
    return set(light) | set(heavy)


def read_manifest(path=ACCEPTANCE):
    """The acceptance/0 manifest's judged state, reduced to what this picture needs.

    Returns `(claims, provenance)`. `claims` is a list of dicts with `id`, `band`, `grade`,
    `weight`; `provenance` names the subject commit, the generation time and whether the subject
    tree was dirty, so the diagram can say WHICH run it draws rather than implying "now".

    A claim with no `band` is read as A0 and a claim with no `weight` as `unweighted`: the manifest
    omits both exactly where nothing was earned, and the conservative reading is the only safe
    default for a picture whose failure mode is overclaiming.
    """
    try:
        with open(path, 'rb') as fh:
            data = tomllib.load(fh)
    except OSError as exc:
        raise SystemExit('gen_verification_map: cannot read the acceptance manifest %s: %s '
                         '(the map is coloured by assurance band, which only that file records)'
                         % (path, exc))
    except tomllib.TOMLDecodeError as exc:
        raise SystemExit('gen_verification_map: %s is not valid TOML: %s' % (path, exc))

    claims = []
    for c in data.get('claim', []):
        cid = c.get('id')
        if not cid:
            raise SystemExit('gen_verification_map: %s has a claim with no id' % path)
        band = c.get('band') or 'A0'
        if band not in BAND_ORDER:
            raise SystemExit(
                'gen_verification_map: claim %r carries band %r, which this renderer has no colour '
                'for (known: %s) — add it to BAND_ORDER/BAND_STYLE rather than drawing it as '
                'something it is not.' % (cid, band, ', '.join(BAND_ORDER)))
        claims.append({
            'id': cid,
            'band': band,
            'grade': c.get('grade') or 'ungraded',
            'weight': c.get('weight') or 'unweighted',
        })
    if not claims:
        raise SystemExit('gen_verification_map: %s declares no claims' % path)

    subject = data.get('subject', {})
    fmt = data.get('format', {})
    commit = str(subject.get('commit', ''))
    provenance = {
        'commit': commit[:7] if commit else 'unknown',
        'generated_at': str(fmt.get('generated_at', 'unknown')),
        'dirty': bool(subject.get('dirty', False)),
        'claims_total': len(claims),
    }
    return claims, provenance


def lid_module(claim_id):
    """`PM/lean-bigint` -> `big_integer`, via gen_proof_manifest's own lid map (never a second
    copy). None for any claim id that is not a lid claim."""
    if not claim_id.startswith('PM/lean-'):
        return None
    return gpm.LID_TO_MODULE.get(claim_id[len('PM/lean-'):])


def split_claims(claims, roster):
    """(module claims by module, lid claims by module, unmapped claim ids).

    Unmapped is the fail-closed direction: a claim the picture cannot place is a claim the picture
    would silently hide.
    """
    by_module, by_lid, unmapped = {}, {}, []
    for c in claims:
        lid = lid_module(c['id'])
        if lid is not None:
            by_lid[lid] = c
            continue
        module = c['id'][3:] if c['id'].startswith('PM/') else None
        if module in roster:
            by_module[module] = c
        else:
            unmapped.append(c['id'])
    return by_module, by_lid, sorted(unmapped)


def band_counts(claims):
    """band -> number of claims, over EVERY claim in the manifest (module and lid alike)."""
    counts = {}
    for c in claims:
        counts[c['band']] = counts.get(c['band'], 0) + 1
    return counts


def target_progress(claims):
    """(claims at or above the target band, total claims) — the numbers the goal line states."""
    at = sum(1 for c in claims if c['band'] in BAND_AT_OR_ABOVE_TARGET)
    return at, len(claims)


def layer_of(module):
    """Which diagram subgraph a roster module belongs in. Total over the roster: every module
    lands somewhere, including one never seen before — `codecs` is the catch-all, so a brand-new
    content codec needs no change here to show up in the picture."""
    if module in FRAMING:
        return 'framing'
    if module in PROFILE_MODULES:
        return 'profile'
    if module.startswith(STRUCTURAL_PREFIX):
        return 'structural'
    return 'codecs'


def read_declared(path=DECLARED):
    """Parse `gates/map_declared.txt`: TAB-separated `class / id / layer / label / source`.

    Every row must cite a source (the file's whole point is auditability), every id must be a
    mermaid-safe identifier, and ids must be unique within the file. Cross-checking against the
    module roster (collision, coverage) is `parity_errors`'s job, not this function's — this one
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
                '(class, id, layer, label, source), got %d: %r' % (path, lineno, len(parts), raw))
        klass, id_, layer, label, source = (p.strip() for p in parts)
        if klass not in DECLARED_CLASSES:
            raise SystemExit('gen_verification_map: %s:%d: class %r not in %s (a declared row is a '
                             'reason there is NO claim; it is never a band)'
                             % (path, lineno, klass, sorted(DECLARED_CLASSES)))
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
        rows.append({'class': klass, 'id': id_, 'layer': layer, 'label': label, 'source': source})

    ids = [r['id'] for r in rows]
    dupes = sorted({i for i in ids if ids.count(i) > 1})
    if dupes:
        raise SystemExit('gen_verification_map: %s: duplicate declared id(s): %s' % (path, dupes))
    return rows


def parity_errors(roster, drawn, declared):
    """Two failure modes this exists to catch, mirroring `check_tier_parity.py`'s intent:

      1. A declared id colliding with a module name — the declared node would silently shadow
         (or be shadowed by) the real one in the rendered diagram.
      2. A roster module drawn in NEITHER a band/unrated group NOR the declared set — i.e. a
         module that would silently vanish from the picture instead of being drawn at all.

    `drawn` is the set of roster modules the render will draw, with a band or as `unrated`.
    """
    errs = []
    declared_ids = {d['id'] for d in declared}
    collisions = sorted(declared_ids & roster)
    if collisions:
        errs.append('declared id(s) collide with a module name in gates/tiers.txt: %s'
                    % collisions)
    missing = sorted(roster - (set(drawn) | declared_ids))
    if missing:
        errs.append('module(s) in gates/tiers.txt absent from the rendered map (neither banded '
                    'nor declared, so they would silently vanish from the picture): %s' % missing)
    return errs


def compute():
    """Everything the render needs, derived from the real tree plus the manifest. Raises SystemExit
    (not a return code) on any parity failure — mirrors `gen_proof_manifest.collect()`'s own idiom
    for an unmapped lid: a structural inconsistency here is a bug in the generator or its inputs,
    not an ordinary drift `--check` should merely report and move past."""
    roster = roster_from_tiers()
    claims, provenance = read_manifest()
    by_module, by_lid, unmapped = split_claims(claims, roster)

    if unmapped:
        raise SystemExit(
            'gen_verification_map: acceptance manifest claim(s) %s map to no node in the map '
            '(not a roster module, not a known Lean lid) — the picture would hide them. '
            'Extend the renderer rather than leaving a claim undrawn.' % unmapped)

    manifest_lids = set(by_lid)
    tree_lids = gpm.l4_module_set()
    if manifest_lids != tree_lids:
        raise SystemExit(
            'gen_verification_map: the acceptance manifest and the source tree disagree about '
            'which codecs carry a Lean lid (manifest PM/lean-*: %s; tree: %s). One of the two is '
            'stale; regenerate the manifest rather than redrawing the map around it.'
            % (sorted(manifest_lids), sorted(tree_lids)))
    off_roster = sorted(tree_lids - roster)
    if off_roster:
        raise SystemExit(
            'gen_verification_map: Lean lid(s) exist for module(s) not in gates/tiers.txt (not '
            'even Kani-harnessed?): %s' % off_roster)

    declared = read_declared()
    errs = parity_errors(roster, roster, declared)
    if errs:
        raise SystemExit('gen_verification_map: ' + '; '.join(errs))
    return {'roster': roster, 'claims': claims, 'by_module': by_module, 'by_lid': by_lid,
            'declared': declared, 'provenance': provenance}


# --------------------------------------------------------------------------------------
# rendering
# --------------------------------------------------------------------------------------

def _node_line(id_, label, klass):
    safe_label = label.replace('"', "'")
    return '        %s["%s"]:::%s' % (id_, safe_label, klass)


# How many member names share one <br/>-delimited line inside a group node before wrapping —
# purely cosmetic (keeps a group box roughly square instead of one long strip), never drops a name.
NAMES_PER_LINE = 4


def _group_label(header, names):
    """A group node's text: the band/grade header first (so colour is never the ONLY carrier of the
    meaning), then every member name — ' · ' within a chunk of `NAMES_PER_LINE`, '<br/>' between
    chunks. Every name passed in still appears verbatim in the output; this only controls
    line-wrapping."""
    chunks = [names[i:i + NAMES_PER_LINE] for i in range(0, len(names), NAMES_PER_LINE)]
    return '<br/>'.join([header] + [' · '.join(chunk) for chunk in chunks])


def _safe(token):
    return re.sub(r'[^a-z0-9]+', '_', str(token).lower()).strip('_') or 'x'


def _band_group_key(claim):
    """Nodes are grouped by (band, grade, weight): band drives the colour, grade and weight are
    printed. Grouping on all three keeps the picture honest if a band ever holds claims of mixed
    grade — they get separate boxes rather than one box labelled with whichever grade came first."""
    return (claim['band'], claim['grade'], claim['weight'])


def _band_header(key):
    band, grade, weight = key
    return '%s · grade: %s · %s' % (band, grade, weight)


def _sorted_group_keys(keys):
    return sorted(keys, key=lambda k: (BAND_ORDER.index(k[0]), k[1], k[2]))


def render_map(facts=None):
    f = facts or compute()
    roster, by_module, by_lid = f['roster'], f['by_module'], f['by_lid']
    declared, prov, claims = f['declared'], f['provenance'], f['claims']

    # (layer, group key) -> [module name, ...]; plus the unrated and declared groups per layer.
    banded, unrated = {}, {}
    for m in sorted(roster):
        claim = by_module.get(m)
        layer = layer_of(m)
        if claim is None:
            unrated.setdefault(layer, []).append(m)
        else:
            banded.setdefault((layer, _band_group_key(claim)), []).append(m)
    declared_groups = {}
    for d in declared:
        declared_groups.setdefault((d['layer'], d['class']), []).append(d['label'])

    lines = ['```mermaid', 'flowchart TB']
    for band in BAND_ORDER:
        lines.append('    classDef %s %s' % (_safe(band), BAND_STYLE[band]))
    lines.append('    classDef unrated %s' % UNRATED_STYLE)
    lines.append('    classDef noclaim %s' % NOCLAIM_STYLE)
    lines.append('')

    for layer in LAYERS:
        lines.append('    subgraph %s_layer["%s"]' % (layer, LAYER_TITLES[layer]))
        lines.append('        direction LR')
        if layer == 'crypto':
            lines.append('        style %s_layer stroke-dasharray: 6 4' % layer)
        for key in _sorted_group_keys([k for (lyr, k) in banded if lyr == layer]):
            names = sorted(banded[(layer, key)])
            node_id = '%s_%s_%s_%s' % (layer, _safe(key[0]), _safe(key[1]), _safe(key[2]))
            lines.append(_node_line(node_id, _group_label(_band_header(key), names), _safe(key[0])))
        if layer in unrated:
            lines.append(_node_line(
                '%s_unrated' % layer,
                _group_label('no claim in the manifest — unrated', sorted(unrated[layer])),
                'unrated'))
        for klass in sorted(DECLARED_CLASSES):
            labels = declared_groups.get((layer, klass))
            if not labels:
                continue
            lines.append(_node_line('%s_%s' % (layer, _safe(klass)),
                                    _group_label(DECLARED_CLASSES[klass], sorted(labels)),
                                    'noclaim'))
        lines.append('    end')

    if by_lid:
        lid_groups = {}
        for module, claim in by_lid.items():
            lid_groups.setdefault(_band_group_key(claim), []).append(module)
        lines.append('    subgraph lid_layer["%s"]' % LID_LAYER_TITLE)
        lines.append('        direction LR')
        for key in _sorted_group_keys(lid_groups):
            node_id = 'lid_%s_%s_%s' % (_safe(key[0]), _safe(key[1]), _safe(key[2]))
            lines.append(_node_line(node_id, _group_label(_band_header(key),
                                                          sorted(lid_groups[key])), _safe(key[0])))
        lines.append('    end')

    counts = band_counts(claims)
    legend = ['colour = assurance BAND: what a reader may assume without re-running anything']
    for band in LEGEND_LADDER:
        legend.append('%s %s — %d claim(s)' % (band, BAND_MEANING[band], counts.get(band, 0)))
    for band in BAND_ORDER:
        if band not in LEGEND_LADDER and counts.get(band):
            legend.append('%s %s — %d claim(s)' % (band, BAND_MEANING[band], counts[band]))
    legend += [
        'white dashed = no claim in the manifest (planned · wall · out of scope), DECLARED',
        'grade is a SEPARATE axis: contract = decides a functional postcondition · '
        'probe = spot-check, typically panic-freedom · ungraded = no graded oracle',
    ]

    lines += [
        '',
        '    crypto_layer -.-> profile_layer --> structural_layer --> codecs_layer --> framing_layer',
        '',
        '    subgraph legend["Legend"]',
        _node_line('legend_all', '<br/>'.join(legend), 'unrated'),
        '    end',
        '```',
    ]

    at, total = target_progress(claims)
    head = [
        '**Colour is the assurance BAND, not the tool.** Target: band **%s** or better on every '
        'claim. Today **%d of %d** claims reach %s or better, and **%d** do not — so this crate is '
        'not done, and the picture is drawn to show that rather than to hide it.'
        % (TARGET_BAND, at, total, TARGET_BAND, total - at),
        '',
    ]
    tail = [
        '',
        'Bands, grades and claim ids come from '
        '[`der-verified/acceptance.toml`](der-verified/acceptance.toml) — the generated acceptance/0 '
        'manifest for subject commit `%s`%s, generated `%s`. A band above A0 needs a control that '
        'was watched to fail, so nothing here can be raised by adding harnesses alone.'
        % (prov['commit'], ' (subject tree DIRTY)' if prov['dirty'] else '',
           prov['generated_at']),
    ]
    return head + lines + tail


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
        f = compute()
        at, total = target_progress(f['claims'])
        print(json.dumps({
            'roster': sorted(f['roster']),
            'claims': {c['id']: {'band': c['band'], 'grade': c['grade'], 'weight': c['weight']}
                       for c in f['claims']},
            'band_counts': band_counts(f['claims']),
            'target_band': TARGET_BAND,
            'claims_at_or_above_target': at,
            'claims_total': total,
            'declared': f['declared'],
            'provenance': f['provenance'],
        }, indent=2, sort_keys=True))
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
                  'its sources (gates/tiers.txt, der-verified/acceptance.toml, '
                  'gates/map_declared.txt):', file=sys.stderr)
            d = list(difflib.unified_diff(
                committed, generated, lineterm='', n=1,
                fromfile='README.md region "map" (committed)', tofile='generated from source now'))
            for line in d[:DIFF_LINES]:
                print('   %s' % line, file=sys.stderr)
            if len(d) > DIFF_LINES:
                print('   … and %d further diff line(s), not shown' % (len(d) - DIFF_LINES),
                      file=sys.stderr)
            print('   Fix: python3 gates/gen_verification_map.py --write — the map follows the '
                  'manifest, never the reverse.', file=sys.stderr)
            return 1
        print('== verification-map gate: PASS (README.md verification map current) ==')
        return 0

    ap.print_help()
    return 2


if __name__ == '__main__':
    sys.exit(main())
