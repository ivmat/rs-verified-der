#!/usr/bin/env python3
"""Full-run log grammar and exact nonsemantic output projections (no trust registration)."""
import base64
import json
from pathlib import Path
import re
import tempfile
import gen_proof_manifest as gpm
import check_lid_staleness as lid
from proof_run_common import ProofRunError, git, digest, canonical


KANI_START = '== cargo kani :: der-verified (L3 proof floor) =='



KANI_END = "== lean-lid skip-guard gate: self-test (the gate's own gate; pure stdlib) =="



FULL_PASS = '== check.sh: PASS (L3 kani floor: GREEN; L4 lean lid: PASS) =='



STATE_PATH = 'lean/lid-source-state.txt'



FLOOR_PATH = 'docs/proof-floor.json'



PROJECTION_PATH = 'PROOF_MANIFEST.md'



FLOOR_REGIONS = ('evidence', 'evidence-coverage')



def harness_roster(root):
    names = []
    for path in sorted((root / 'der-verified/src').glob('*.rs')):
        if path.name != 'lib.rs':
            facts = gpm.module_facts(str(path))
            names.extend(path.stem + '::proofs::' + h['name'] for h in facts['harnesses'])
    if not names or len(names) != len(set(names)):
        raise ProofRunError('missing or duplicate harness roster')
    return sorted(names)



def cover_roster(root):
    names = []
    for path in sorted((root / 'der-verified/src').glob('*.rs')):
        if path.name != 'lib.rs':
            for harness in gpm.module_facts(str(path))['harnesses']:
                if harness['covers'] + harness['covers_via_helpers']:
                    names.append(path.stem + '::proofs::' + harness['name'])
    return sorted(names)



def floor_output(source, raw_hash, counts, started, finished):
    data = {'commit': source, 'raw_sha256': raw_hash, **counts, 'file': FLOOR_PATH,
            'check_exit': 0, 'lean_lid': 'PASS', 'memory_cap': 'not measured by recorder',
            'peak_memory': 'not measured by recorder', 'started_ns': started, 'finished_ns': finished,
            'provenance': 'Derived from an isolated completed full run by proof_runs.py; local trust registration is separate.'}
    raw = canonical(data)
    return {'sha256': digest(raw), 'content_base64': base64.b64encode(raw).decode()}



def projected_manifest(original, floor):
    """Only floor-dependent named regions change; preserve every other original byte."""
    text = original.decode('utf-8')
    facts = {'evidence': [{**floor, 'covers_head_source': True, 'source_anchor': floor['commit']}]}
    for name in FLOOR_REGIONS:
        begin, end = gpm.BEGIN % name, gpm.END % name
        if text.count(begin) != 1 or text.count(end) != 1:
            raise ProofRunError('missing or duplicate floor projection region')
        prefix, body, suffix = gpm.split_region(text, name)
        text = prefix + begin + '\n' + gpm.render(facts, name) + '\n' + end + suffix
    data = text.encode('utf-8')
    return {'sha256': digest(data), 'content_base64': base64.b64encode(data).decode()}


def validate_projection_invariants(original, projected):
    """Authenticate captured bytes without today's renderer or mutable Git references.

    The owner-only receipt pins the rendered region bytes; source bytes outside the
    two permitted bodies must remain identical, including the markers themselves.
    """
    def skeleton(raw):
        text = raw.decode('utf-8')
        for name in FLOOR_REGIONS:
            begin, end = gpm.BEGIN % name, gpm.END % name
            if text.count(begin) != 1 or text.count(end) != 1:
                raise ProofRunError('missing or duplicate floor projection region')
            prefix, body, suffix = gpm.split_region(text, name)
            text = prefix + begin + '\n' + end + suffix
        return text
    try:
        if skeleton(original) != skeleton(projected):
            raise ProofRunError('captured proof manifest changes outside floor projection bodies')
    except UnicodeError as exc:
        raise ProofRunError('invalid proof-manifest encoding') from exc



def validate_floor_declaration(data, source):
    try:
        value = json.loads(data)
    except (ValueError, UnicodeError) as exc:
        raise ProofRunError('invalid proof-floor declaration') from exc
    if (not isinstance(value, dict) or value.get('commit') != source
            or not isinstance(value.get('raw_sha256'), str)
            or not re.fullmatch(r'[0-9a-f]{64}', value['raw_sha256'])
            or type(value.get('check_exit')) is not int or value['check_exit'] != 0 or value.get('lean_lid') != 'PASS'
            or any(type(value.get(k)) is not int or value[k] < 0
                   for k in ('successful', 'failed', 'covers_unsatisfied'))
            or value['failed'] != 0 or value['successful'] == 0):
        raise ProofRunError('proof-floor declaration has invalid subject/log/result binding')
    return value



def validate_floor_for_source(root, source, data):
    value = validate_floor_declaration(data, source)
    with tempfile.TemporaryDirectory(prefix='der-source-count-') as box:
        scratch = Path(box)
        paths = git(root, 'ls-tree', '-r', '--name-only', '-z', source, '--', 'der-verified/src').decode().rstrip('\0').split('\0')
        for name in paths:
            if name.endswith('.rs'):
                dest = scratch / name
                dest.parent.mkdir(parents=True, exist_ok=True)
                dest.write_bytes(git(root, 'show', source + ':' + name))
        if value['successful'] != len(harness_roster(scratch)):
            raise ProofRunError('proof-floor count differs from the subject harness roster')
    return value



def validate_log(data, expected, expected_covers=(), expected_unsatisfied=None):
    try:
        lines = data.decode('utf-8').splitlines()
    except UnicodeError as exc:
        raise ProofRunError('log is not UTF-8') from exc
    if not lines or lines[-1] != FULL_PASS or lines.count(KANI_START) != 1 or lines.count(KANI_END) != 1:
        raise ProofRunError('log lacks unique Kani stage or final full Kani+Lean success')
    start, end = lines.index(KANI_START), lines.index(KANI_END)
    if start >= end or 'lean-lid-status: PASS' not in lines[end:]:
        raise ProofRunError('Lean completion or Kani stage ordering missing')
    results, current, covers = {}, None, {}
    for line in lines[start + 1:end]:
        match = re.fullmatch(r'Checking harness (?:der_verified::)?([A-Za-z0-9_:]+)\.\.\.', line)
        if match:
            if current is not None:
                raise ProofRunError('harness started before previous verdict')
            current = match[1]
            if current in results:
                raise ProofRunError('duplicate harness execution in full floor')
        elif (cover := re.fullmatch(r'\s*\*\* (\d+) of (\d+) cover propert(?:y|ies) satisfied\s*', line)):
            if current is None or current in covers or int(cover[1]) > int(cover[2]):
                raise ProofRunError('unknown or duplicate cover-summary grammar')
            covers[current] = int(cover[2]) - int(cover[1])
        elif 'cover properties satisfied' in line:
            raise ProofRunError('unknown cover-summary grammar')
        elif re.match(r'^VERIFICATION:', line):
            if current is None or not re.fullmatch(r'VERIFICATION:\s*-?\s*SUCCESSFUL', line):
                raise ProofRunError('failed, unmatched or unknown Kani verdict')
            results[current], current = True, None
    if current is not None or sorted(results) != sorted(expected):
        raise ProofRunError('full run does not cover the exact expected harness roster')
    if set(expected_covers) - set(covers):
        raise ProofRunError('source has covers whose log summary is unavailable')
    unsatisfied = {name for name, count in covers.items() if count}
    if expected_unsatisfied is not None and unsatisfied != set(expected_unsatisfied):
        added = sorted(unsatisfied - set(expected_unsatisfied))
        resolved = sorted(set(expected_unsatisfied) - unsatisfied)
        details = []
        if added:
            details.append('newly unsatisfied: ' + ', '.join(added))
        if resolved:
            details.append('disclosed but now satisfied: ' + ', '.join(resolved))
        raise ProofRunError('unsatisfied-cover harnesses differ from the disclosed-vacuity registry'
                            + (': ' + '; '.join(details) if details else ''))
    return {'successful': len(results), 'failed': 0, 'covers_unsatisfied': sum(covers.values())}



def _validated_state_data(data, script, read_source):
    try:
        lid.validate_source_state(data.decode(), script, read_source)
    except (lid.ParseError, UnicodeError, OSError) as exc:
        raise ProofRunError('invalid generated Lean state: ' + str(exc)) from exc
    return {'sha256': digest(data), 'content_base64': base64.b64encode(data).decode()}



def validated_state(root):
    root = Path(root)
    return _validated_state_data((root / STATE_PATH).read_bytes(),
            (root / 'lean/check_lean.sh').read_text(), lambda name: (root / name).read_bytes())

