#!/usr/bin/env python3
"""Explicit release preparation; historical acceptance is never silently made current.

The producer is external. This tool validates/stages its bundle; it does not invent
claims, run proofs, change a version, create a tag or publish a package.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import tomllib

import proof_runs

ROOT = Path(__file__).resolve().parents[1]
FORMAT = 'der-release-validation/1'
PREFIX = 'der-verified/'
MANIFEST = 'acceptance.toml'
MIRROR = 'der.inventory.toml.vendored-copy'
STORE = 'evidence/acceptance-records'


class ReleaseEvidenceError(ValueError):
    pass


def git(root, *args):
    try:
        return proof_runs.git(Path(root), *args)
    except (OSError, ValueError) as exc:
        raise ReleaseEvidenceError(str(exc)) from exc


def head(root):
    return git(root, 'rev-parse', '--verify', 'HEAD^{commit}').decode().strip()


def subject(package):
    data = tomllib.loads((Path(package) / MANIFEST).read_text())
    result = data.get('subject', {})
    if (not re.fullmatch('[0-9a-f]{40}', str(result.get('commit', '')))
            or result.get('dirty') is not False):
        raise ReleaseEvidenceError('recorded subject must be a clean full Git commit')
    return result['commit']


def artifact_files(package):
    """Exact flat release bundle; no symlink can hide an input behind a data path."""
    package = Path(package).resolve()
    paths = [package / MANIFEST, package / MIRROR]
    paths += sorted((package / STORE).glob('*.json'))
    if len(paths) < 3:
        raise ReleaseEvidenceError('release bundle has no evidence records')
    result = {}
    for path in paths:
        if not path.is_file() or any(p.is_symlink() for p in (path, *path.parents) if p != package.parent):
            raise ReleaseEvidenceError(f'missing or symlinked bundle file: {path.name}')
        result[PREFIX + path.relative_to(package).as_posix()] = hashlib.sha256(path.read_bytes()).hexdigest()
    return result


def _snapshot(root, package):
    from check_acceptance_manifest import validate_snapshot
    if validate_snapshot(root, package):
        raise ReleaseEvidenceError('recorded acceptance integrity failed')
    return artifact_files(package)


def _current_inventory(root, package):
    if (Path(package) / MIRROR).read_bytes() != (Path(root) / 'docs/requirements/der.inventory.toml').read_bytes():
        raise ReleaseEvidenceError('recorded inventory differs from current requirements')


def _allowed_artifacts(root, source, target, files):
    # Removed, superseded records are data too. Enumerate their exact committed
    # names; never turn the entire evidence directory into an unconstrained glob.
    return set(files) | set(_committed_artifacts(root, source, required=False))


def applicability(root=ROOT, package=None):
    """Applicability is source equality, not a fresh proof or a consumer decision."""
    root = Path(root).resolve()
    package = Path(package).resolve() if package else root / 'der-verified'
    try:
        source, target = subject(package), head(root)
        proof_runs.commit_id(root, source)
        artifacts = artifact_files(package)
    except (OSError, ValueError) as exc:
        return {'state': 'UNKNOWN', 'reason': f'subject history or identity unavailable: {exc}'}
    try:
        git(root, 'merge-base', '--is-ancestor', source, target)
        _current_inventory(root, package)
        proof_runs.verify_applicability_inputs(root, source, target,
                                              allowed_artifacts=_allowed_artifacts(root, source, target, artifacts))
        dirty = git(root, 'diff', '--name-only', '--no-renames', '-z', 'HEAD', '--')
        dirty += git(root, 'ls-files', '--others', '--exclude-standard', '-z')
        paths = set(dirty.decode('utf-8').rstrip('\0').split('\0')) if dirty else set()
        if paths:
            proof_runs.supported_input_model(root, target)
        blocked = sorted(p for p in paths if p not in artifacts and not proof_runs.is_prose_path(p))
        if blocked:
            raise ReleaseEvidenceError('working inputs changed: ' + ', '.join(blocked))
    except (OSError, ValueError) as exc:
        return {'state': 'CHANGED', 'subject': source, 'head': target,
                'reason': f'recorded acceptance does not cover current inputs: {exc}'}
    return {'state': 'APPLICABLE', 'subject': source, 'head': target,
            'reason': f'source inputs match recorded subject {source} under recorded tool assumptions; no new run or acceptance decision'}


def clean_head(root):
    target = head(root)
    if git(root, 'status', '--porcelain', '--untracked-files=all').strip():
        raise ReleaseEvidenceError('release operation requires a clean committed checkout')
    return target


def version_at(root, target):
    return tomllib.loads(git(root, 'show', target + ':der-verified/Cargo.toml').decode())['package']['version']


def release_ref(version):
    if not isinstance(version, str) or not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[0-9A-Za-z.-]+)?', version):
        raise ReleaseEvidenceError('expected an explicit release version, such as 0.3.0')
    return 'refs/tags/v' + version


def prepare(root, version, bundle, output):
    """Stage a producer bundle in a new directory, leaving the checkout untouched."""
    if Path(output).is_symlink():
        raise ReleaseEvidenceError('output must not be a symlink')
    root, bundle, output = Path(root).resolve(), Path(bundle).resolve(), Path(output).resolve()
    target = clean_head(root)
    release_ref(version)
    if version_at(root, target) != version:
        raise ReleaseEvidenceError('release version must already match Cargo.toml; bump before the proof run')
    if output.exists() or output.is_relative_to(root) or output.is_relative_to(bundle):
        raise ReleaseEvidenceError('output must be a new directory outside the checkout and bundle')
    files = _snapshot(root, bundle)
    actual = {p.relative_to(bundle).as_posix() for p in bundle.rglob('*') if p.is_file() or p.is_symlink()}
    if actual != {p.removeprefix(PREFIX) for p in files}:
        raise ReleaseEvidenceError('producer bundle contains files outside the acceptance artifact set')
    source = subject(bundle)
    if files != _committed_artifacts(root, target, required=False):
        proof_runs.supported_input_model(root, target)
    run = proof_runs.verify_trusted_run(root, source)
    _current_inventory(root, bundle)
    proof_runs.verify_source_inputs(root, source, target,
        allowed_artifacts=_allowed_artifacts(root, source, target, files), _verified_run=run)
    if clean_head(root) != target:
        raise ReleaseEvidenceError('checkout changed during preparation')
    output.parent.mkdir(parents=True, exist_ok=True)
    staging = Path(tempfile.mkdtemp(prefix='release-stage-', dir=output.parent))
    try:
        for path, expected in files.items():
            relative = path.removeprefix(PREFIX)
            raw = (bundle / relative).read_bytes()
            if hashlib.sha256(raw).hexdigest() != expected:
                raise ReleaseEvidenceError('producer bundle changed during preparation')
            dest = staging / relative
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
        generated = run.get('generated_outputs', {})
        for path, item in generated.items():
            if path not in {'lean/lid-source-state.txt', 'docs/proof-floor.json', 'PROOF_MANIFEST.md'}:
                raise ReleaseEvidenceError('unsupported generated proof metadata')
            raw = base64.b64decode(item['content_base64'], validate=True)
            if hashlib.sha256(raw).hexdigest() != item['sha256']:
                raise ReleaseEvidenceError('trusted generated metadata digest mismatch')
            dest = staging / 'proof-generated' / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_bytes(raw)
        (staging / 'release-preparation.json').write_text(json.dumps({
            'format': 'der-release-preparation/1', 'release': version,
            'source_commit': source, 'reviewed_at_commit': target,
            'proof_receipt_sha256': run['receipt_sha256'], 'artifacts': files,
            'generated_outputs': {p: value['sha256'] for p, value in generated.items()},
            'notice': 'Preparation only. Review and commit the bundle, then validate that commit. No release was made.',
        }, indent=2, sort_keys=True) + '\n')
        staging.rename(output)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return {'output': str(output), 'source_commit': source, 'release': version}


def _receipt_path(root, target):
    return proof_runs.common_dir(root) / 'release-evidence' / (target + '.json')


def _committed_artifacts(root, target, required=True):
    raw = git(root, 'ls-tree', '-r', '-z', target, '--', PREFIX + MANIFEST, PREFIX + MIRROR, PREFIX + STORE)
    result = {}
    for entry in raw.split(b'\0'):
        if not entry:
            continue
        metadata, path = entry.split(b'\t', 1)
        mode, kind, oid = metadata.split()
        name = path.decode('utf-8')
        if mode not in (b'100644', b'100755') or kind != b'blob':
            raise ReleaseEvidenceError('release artifact is not a regular file')
        if name not in (PREFIX + MANIFEST, PREFIX + MIRROR):
            if not re.fullmatch(re.escape(PREFIX + STORE) + r'/[^/]+\.json', name):
                raise ReleaseEvidenceError('unexpected committed evidence-store file')
        result[name] = hashlib.sha256(git(root, 'cat-file', 'blob', oid.decode())).hexdigest()
    if required and (not {PREFIX + MANIFEST, PREFIX + MIRROR} <= set(result) or len(result) < 3):
        raise ReleaseEvidenceError('committed bundle incomplete')
    return result


def check_packed_commit(root, unpacked, target):
    """A release package must carry the committed Rust and evidence bytes, not local extras."""
    unpacked = Path(unpacked)
    paths = git(root, 'ls-tree', '-r', '--name-only', target, '--', 'der-verified/src').decode().splitlines()
    sources = {p for p in paths if p.endswith('.rs')}
    actual = {PREFIX + p.relative_to(unpacked).as_posix() for p in (unpacked / 'src').rglob('*.rs')}
    if sources != actual:
        raise ReleaseEvidenceError('packed Rust source inventory differs from the committed source')
    for path in sources | set(_committed_artifacts(root, target)):
        local = unpacked / path.removeprefix(PREFIX)
        if local.is_symlink() or local.read_bytes() != git(root, 'show', target + ':' + path):
            raise ReleaseEvidenceError('packed bytes differ from release commit: ' + path)
    if (unpacked / 'Cargo.toml.orig').read_bytes() != git(root, 'show', target + ':der-verified/Cargo.toml'):
        raise ReleaseEvidenceError('packed original Cargo manifest differs from release commit')
    if tomllib.loads((unpacked / 'Cargo.toml').read_text())['package']['version'] != version_at(root, target):
        raise ReleaseEvidenceError('packed package version differs from release commit')
    vcs = json.loads((unpacked / '.cargo_vcs_info.json').read_text())
    if vcs.get('git', {}).get('sha1') != target or vcs.get('git', {}).get('dirty', False) is not False:
        raise ReleaseEvidenceError('packed Git identity is not the clean release commit')


def _package_check(root):
    subprocess.run([sys.executable, '-B', str(root / 'gates/test_package_acceptance.py'), '--require-current'],
                   cwd=root, check=True, env={**proof_runs.git_env(), 'PYTHONDONTWRITEBYTECODE': '1'})


def _require_generated_outputs(root, target, run):
    """A release publishes every exact captured output, including unchanged paths."""
    generated = run.get('generated_outputs', {})
    expected = {proof_runs.STATE_PATH, proof_runs.FLOOR_PATH, proof_runs.PROJECTION_PATH}
    if set(generated) != expected:
        raise ReleaseEvidenceError('trusted run lacks the complete captured metadata outputs')
    for path, output in generated.items():
        raw = base64.b64decode(output['content_base64'], validate=True)
        if (hashlib.sha256(raw).hexdigest() != output['sha256']
                or git(root, 'show', target + ':' + path) != raw):
            raise ReleaseEvidenceError('release commit lacks exact captured metadata: ' + path)


def validate_release(root, version, source):
    """Validate artifact commit T against captured run S; never label it GREEN@T."""
    root = Path(root).resolve()
    target, ref = clean_head(root), release_ref(version)
    if version_at(root, target) != version:
        raise ReleaseEvidenceError('release version does not match committed package')
    package = root / 'der-verified'
    files = _snapshot(root, package)
    if subject(package) != source:
        raise ReleaseEvidenceError('manifest subject differs from the requested proof source')
    run = proof_runs.verify_trusted_run(root, source)
    _require_generated_outputs(root, target, run)
    _current_inventory(root, package)
    proof_runs.verify_source_inputs(root, source, target,
        allowed_artifacts=_allowed_artifacts(root, source, target, files), _verified_run=run)
    state = applicability(root, package)
    if state['state'] != 'APPLICABLE':
        raise ReleaseEvidenceError(state['reason'])
    _package_check(root)
    if clean_head(root) != target or _committed_artifacts(root, target) != files:
        raise ReleaseEvidenceError('checkout/artifacts changed during release validation')
    proof_runs.verify_trusted_run(root, source, receipt_sha256=run['receipt_sha256'])
    data = {'format': FORMAT, 'target_commit': target, 'source_commit': source,
            'ref': ref, 'release': version, 'proof_receipt_sha256': run['receipt_sha256'],
            'artifacts': files, 'repository': str(proof_runs.common_dir(root))}
    path = _receipt_path(root, target)
    path.parent.mkdir(mode=0o700, exist_ok=True)
    if (path.is_symlink() or path.parent.is_symlink() or path.parent.stat().st_mode & 0o077
            or path.parent.stat().st_uid != os.geteuid()):
        raise ReleaseEvidenceError('release receipt directory must be owner-only and not symlinked')
    fd, name = tempfile.mkstemp(prefix='validation-', dir=path.parent)
    with os.fdopen(fd, 'w') as stream:
        json.dump(data, stream, indent=2, sort_keys=True)
        stream.write('\n')
    os.replace(name, path)
    return verify_release(root, target, ref)


def verify_release(root, target, ref):
    """Read-only tag gate: a release-validation receipt is not a fresh full run."""
    root = Path(root).resolve()
    target = proof_runs.commit_id(root, target)
    path = _receipt_path(root, target)
    if (path.parent.is_symlink() or path.is_symlink() or not path.is_file()
            or path.stat().st_uid != os.geteuid() or path.stat().st_mode & 0o077
            or path.parent.stat().st_mode & 0o077 or path.parent.stat().st_uid != os.geteuid()):
        raise ReleaseEvidenceError('no owner-only release-validation receipt for this commit')
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ReleaseEvidenceError('duplicate receipt key')
            out[k] = v
        return out
    data = json.loads(path.read_text(), object_pairs_hook=unique)
    if not isinstance(data, dict):
        raise ReleaseEvidenceError('release-validation receipt must be an object')
    if (data.get('format') != FORMAT or data.get('target_commit') != target
            or data.get('ref') != ref or release_ref(data.get('release', '')) != ref
            or data.get('repository') != str(proof_runs.common_dir(root))
            or version_at(root, target) != data.get('release')):
        raise ReleaseEvidenceError('release-validation identity mismatch')
    bound_receipt = data.get('proof_receipt_sha256')
    if not isinstance(bound_receipt, str) or not re.fullmatch(r'[0-9a-f]{64}', bound_receipt):
        raise ReleaseEvidenceError('release validation lacks an exact proof receipt binding')
    run = proof_runs.verify_trusted_run(root, data.get('source_commit'), receipt_sha256=bound_receipt)
    _require_generated_outputs(root, target, run)
    files = _committed_artifacts(root, target)
    if files != data.get('artifacts'):
        raise ReleaseEvidenceError('committed artifact hashes differ from release validation')
    manifest = tomllib.loads(git(root, 'show', target + ':' + PREFIX + MANIFEST).decode())
    if manifest.get('subject', {}).get('commit') != data['source_commit']:
        raise ReleaseEvidenceError('committed subject differs from captured source')
    proof_runs.verify_source_inputs(root, data['source_commit'], target,
        allowed_artifacts=_allowed_artifacts(root, data['source_commit'], target, files), _verified_run=run)
    return {'mode': 'release-validation', 'target_commit': target, 'run_commit': data['source_commit'],
            'release': data['release'], 'receipt_sha256': hashlib.sha256(path.read_bytes()).hexdigest()}


def verify_release_commit(root, target, allow_prose_descendants=False):
    """Branch fallback through strictly checked release T and prose-only T→U."""
    target = proof_runs.commit_id(Path(root), target)
    if not allow_prose_descendants:
        return verify_release(root, target, release_ref(version_at(root, target)))
    proof_runs.supported_input_model(root, target)
    for ancestor in git(root, 'rev-list', target).decode().splitlines():
        if not _receipt_path(root, ancestor).exists():
            continue
        result = verify_release(root, ancestor, release_ref(version_at(root, ancestor)))
        changed = git(root, 'diff', '--name-only', '--no-renames', '-z', ancestor, target, '--')
        paths = changed.decode().rstrip('\0').split('\0') if changed else []
        if not all(proof_runs.is_prose_path(path) for path in paths):
            raise ReleaseEvidenceError('changes after validated release include artifacts or proof inputs')
        return {**result, 'mode': 'release-validation' if target == ancestor else 'release-carry-over',
                'release_commit': ancestor, 'target_commit': target, 'prose_paths': paths}
    raise ReleaseEvidenceError('no validated release ancestor')


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest='command', required=True)
    sub.add_parser('status', help='report source applicability without generating evidence')
    prep = sub.add_parser('prepare', help='stage an external producer bundle for an explicit release')
    prep.add_argument('--release', required=True)
    prep.add_argument('--bundle', required=True, type=Path)
    prep.add_argument('--output', required=True, type=Path)
    valid = sub.add_parser('validate', help='validate clean artifact commit T against captured run S')
    valid.add_argument('--release', required=True)
    valid.add_argument('--source', required=True)
    args = parser.parse_args(argv)
    try:
        if args.command == 'status':
            _snapshot(ROOT, ROOT / 'der-verified')
            result = applicability()
        elif args.command == 'prepare':
            result = prepare(ROOT, args.release, args.bundle, args.output)
        else:
            result = validate_release(ROOT, args.release, args.source)
        print(json.dumps(result, indent=2, sort_keys=True))
        return 0
    except (OSError, ValueError, subprocess.CalledProcessError) as exc:
        print(f'REFUSED release evidence: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
