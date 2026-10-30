#!/usr/bin/env python3
"""Capture full runs locally; verify fresh evidence or explicitly named prose-only carry-over.

The local owner and installed recorder are the trust root. No artifact/import command can
register an old run. Transcribed proof-floor declarations and legacy text receipts are not
trusted registrations. The private Git-common-dir store is not a signature against a
compromised local account, nor does a hash establish that an unregistered log was executed.
"""
import argparse
import base64
import contextlib
import datetime
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import time
import tomllib
import uuid

import ci_changes
import gen_proof_manifest as gpm
import check_lid_staleness as lid
from check_no_alloc import strip_rust

import proof_run_common
import proof_run_tools
import proof_run_metadata
from proof_run_common import ProofRunError, git_env, git, commit_id, common_dir, digest, canonical
from proof_run_tools import (observe_tools, supported_environment, capture_environment, CAPTURE_ENV_NAMES,
    ENVIRONMENT_POLICY, effective_binary, tree_fingerprint, checkout_bytes_match, no_checkout_filters)
from proof_run_metadata import (KANI_START, KANI_END, FULL_PASS, STATE_PATH, FLOOR_PATH, PROJECTION_PATH,
    FLOOR_REGIONS, harness_roster, cover_roster, floor_output, projected_manifest,
    validate_floor_declaration, validate_floor_for_source, validate_log, _validated_state_data, validated_state,
    validate_projection_invariants)

ROOT = Path(__file__).resolve().parent.parent
FORMAT = 'der-local-proof-run/1'
TOOL_KEYS = {'rustc', 'cargo', 'kani', 'lean', 'aeneas', 'charon', 'python'}
PROTECTED_INPUTS = set(gpm.L3_BUILD_INPUTS) | {FLOOR_PATH, 'ASSUMPTIONS.md', PROJECTION_PATH}
CHECKOUT_PREFIX = 'der-proof-checkout-'
RUN_ID_RE = re.compile(r'[0-9a-f]{32}')
PROTECTED_PREFIXES = ('der-verified/src/', 'lean/', 'gates/', '.github/', '.cargo/', 'docs/requirements/')


def store_root(root):
    return common_dir(root) / 'der-proof-runs'


def _require_local_store_platform():
    if not hasattr(os, 'geteuid'):
        raise ProofRunError('local proof capture/store verification requires a POSIX host')


def _read(path):
    _require_local_store_platform()
    if path.is_symlink() or not path.is_file():
        raise ProofRunError(f'missing or symlinked local evidence: {path.name}')
    stat = path.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        raise ProofRunError(f'local evidence must be owner-only: {path.name}')
    return path.read_bytes()


def _json(path):
    def unique(pairs):
        out = {}
        for k, v in pairs:
            if k in out:
                raise ProofRunError('duplicate key in local evidence')
            out[k] = v
        return out
    try:
        return json.loads(_read(path), object_pairs_hook=unique)
    except (OSError, ValueError) as exc:
        raise ProofRunError(f'invalid local evidence: {path.name}') from exc


def _write(path, data):
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    fd = os.open(temp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as stream:
        stream.write(data)
    os.replace(temp, path)


def _store(root, create=False):
    _require_local_store_platform()
    store = store_root(root)
    if create and not store.exists():
        store.mkdir(mode=0o700)
    if store.is_symlink() or not store.is_dir():
        raise ProofRunError('no local trusted proof-run store; a real captured run is required')
    stat = store.stat()
    if stat.st_uid != os.geteuid() or stat.st_mode & 0o077:
        raise ProofRunError('proof-run store must be owner-only and not symlinked')
    identity = store / 'repository.json'
    if create and not identity.exists():
        _write(identity, canonical({'id': uuid.uuid4().hex, 'common_dir': str(common_dir(root))}))
    repo = _json(identity)
    if repo.get('common_dir') != str(common_dir(root)):
        raise ProofRunError('proof-run store belongs to another repository location')
    return store, repo


def is_prose_path(path):
    # These documents define proof/TCB claims, not merely presentation.
    return (path not in PROTECTED_INPUTS and not path.startswith(PROTECTED_PREFIXES)
            and ci_changes.documentation_only([path]))


def _compare_inputs(root, source, target, allowed_artifacts=(), trusted_metadata=True, _verified_run=None):
    """Compare complete committed trees. Release callers must validate each extra artifact.

    All non-prose changes are refused unless a release validator supplies their exact
    paths. Proof/build/tool/policy inputs cannot be exempted even by that caller.
    """
    source, target = commit_id(root, source), commit_id(root, target)
    git(root, 'merge-base', '--is-ancestor', source, target)
    raw = git(root, 'diff', '--name-only', '--no-renames', '-z', source, target, '--')
    try:
        paths = raw.decode('utf-8').rstrip('\0').split('\0') if raw else []
    except UnicodeError as exc:
        raise ProofRunError('unrecognised path encoding in source diff') from exc
    changed = set(paths)
    if FLOOR_PATH in changed and PROJECTION_PATH not in changed:
        raise ProofRunError('floor metadata changed without the proof-manifest projection')
    supported_input_model(root, source)
    supported_input_model(root, target)
    allowed = set(allowed_artifacts)
    protected, prefixes = PROTECTED_INPUTS, PROTECTED_PREFIXES
    prose, artifacts = [], []
    run_cache = _verified_run
    if run_cache is not None and run_cache.get('run_commit') != source:
        raise ProofRunError('verified run context names another source commit')
    def metadata_run():
        nonlocal run_cache
        if run_cache is None:
            run_cache = verify_trusted_run(root, source)
        return run_cache
    for path in paths:
        if path == PROJECTION_PATH:
            data = git(root, 'show', target + ':' + path)
            if trusted_metadata:
                output = metadata_run()['generated_outputs'].get(PROJECTION_PATH)
            else:
                floor = validate_floor_for_source(root, source, git(root, 'show', target + ':' + FLOOR_PATH))
                output = projected_manifest(git(root, 'show', source + ':' + path), floor)
            if not output or digest(data) != output['sha256']:
                raise ProofRunError('proof manifest differs from the exact floor-dependent projection')
            artifacts.append(path)
        elif path == FLOOR_PATH:
            data = git(root, 'show', target + ':' + path)
            validate_floor_for_source(root, source, data)
            if trusted_metadata:
                output = metadata_run()['generated_outputs'].get(FLOOR_PATH)
                if not output or digest(data) != output['sha256']:
                    raise ProofRunError('floor declaration differs from exact captured output')
            artifacts.append(path)
        elif path == STATE_PATH:
            data = git(root, 'show', target + ':' + path)
            if trusted_metadata:
                run = metadata_run()
                output = run['generated_outputs'].get(STATE_PATH)
                if not output or digest(data) != output['sha256']:
                    raise ProofRunError('Lean source-state change does not equal trusted run output')
            else:
                _validated_state_data(data, git(root, 'show', target + ':lean/check_lean.sh').decode(),
                                      lambda name: git(root, 'show', target + ':' + name))
            artifacts.append(path)
        elif path in protected or path.startswith(prefixes):
            raise ProofRunError(f'changed proof/build/tool/policy or unapproved path: {path}')
        elif is_prose_path(path):
            prose.append(path)
        elif (path in allowed and path not in protected and not path.startswith(prefixes)
              and not path.endswith(('.rs', '.lean', '.py', '.sh', '.yml', '.yaml'))):
            artifacts.append(path)
        else:
            raise ProofRunError(f'changed proof/build/tool/policy or unapproved path: {path}')
    return {'source': source, 'target': target, 'changed_paths': paths,
            'prose_paths': prose, 'artifact_paths': artifacts}


def supported_input_model(root, commit):
    """The current one-member, dependency-free source crate; unknown inputs refuse reuse."""
    entries = git(root, 'ls-tree', '-r', '-z', commit).decode().rstrip('\0').split('\0')
    paths = []
    for entry in entries:
        if not entry:
            continue
        metadata, path = entry.split('\t', 1)
        mode = metadata.split()[0]
        if mode == '160000':
            raise ProofRunError('gitlinks/submodules are not supported proof inputs')
        if mode == '120000':
            target = git(root, 'show', commit + ':' + path).decode()
            licenses = {'der-verified/LICENSE-MIT': '../LICENSE-MIT',
                        'der-verified/LICENSE-APACHE': '../LICENSE-APACHE'}
            if licenses.get(path) != target:
                raise ProofRunError('symlinked source/tool/config inputs are unsupported')
        if path in {'.cargo/config', '.cargo/config.toml', 'der-verified/.cargo/config', 'der-verified/.cargo/config.toml'}:
            raise ProofRunError('custom Cargo configuration needs an explicit supported-input policy')
        if path.endswith('.gitattributes'):
            raise ProofRunError('checkout attribute transformations are outside the supported proof profile')
        paths.append(path)
    if 'der-verified/build.rs' in paths or 'build.rs' in paths:
        raise ProofRunError('custom build scripts prevent proving prose/artifact input independence')
    def dependencies(table):
        return any((key in ('dependencies', 'dev-dependencies', 'build-dependencies') and bool(value))
                   or (isinstance(value, dict) and dependencies(value)) for key, value in table.items())
    for name in ('Cargo.toml', 'der-verified/Cargo.toml'):
        if name in paths:
            try:
                config = tomllib.loads(git(root, 'show', commit + ':' + name).decode())
            except (ValueError, UnicodeError) as exc:
                raise ProofRunError('invalid Cargo input configuration') from exc
            if config.get('package', {}).get('build') not in (None, False) or dependencies(config):
                raise ProofRunError('build scripts/dependencies are outside the supported proof input profile')
            if 'workspace' in config and config['workspace'].get('members') != ['der-verified']:
                raise ProofRunError('only the DER workspace member is supported')
    for name in paths:
        if name.startswith('der-verified/') and name.endswith('.rs'):
            text = strip_rust(git(root, 'show', commit + ':' + name).decode())
            if (not name.startswith('der-verified/src/')
                    or re.search(r'\binclude(?:_str|_bytes)?\s*!|#\s*!?\s*\[\s*(?:path\b|cfg_attr\s*\([^]]*\bpath\s*=)', text)
                    or re.search(r'\b(?:fs|env|process)\s*::|::\s*(?:fs|env|process)\b|\buse\b[^;]*\b(?:fs|env|process)\b|\b(?:env|option_env)\s*!', text)):
                raise ProofRunError('external compile/runtime input access is outside the supported proof profile')


def verify_source_inputs(root, source, target, allowed_artifacts=(), *, _verified_run=None):
    """Strict push/release comparison: generated metadata must match the trusted run exactly."""
    return _compare_inputs(root, source, target, allowed_artifacts, trusted_metadata=True,
                           _verified_run=_verified_run)


def verify_applicability_inputs(root, source, target, allowed_artifacts=()):
    """Snapshot source comparison only: validates metadata cache hashes, never proves a run."""
    return _compare_inputs(root, source, target, allowed_artifacts, trusted_metadata=False)


def _only_generated_change(root):
    changed = git(root, 'diff', '--name-only', '--no-renames', '-z', 'HEAD', '--').decode().rstrip('\0')
    if changed and set(changed.split('\0')) - {STATE_PATH}:
        raise ProofRunError('isolated run changed a path other than verified Lean metadata')
    if git(root, 'ls-files', '--others', '--exclude-standard', '-z'):
        raise ProofRunError('isolated run created an untracked input/output outside ignored build paths')


def stage_state(root, lean_status):
    """Only the recorder's linked checkout may stage the verified nonsemantic output."""
    root = Path(root).resolve()
    context_path = Path(os.environ.get('DER_PROOF_CAPTURE_CONTEXT', ''))
    store, _ = _store(root)
    if (context_path.parent != store or not re.fullmatch(r'capture-[0-9a-f]{32}\.json', context_path.name)
            or lean_status != 'PASS'):
        raise ProofRunError('no valid capture context or Lean did not pass')
    context = _json(context_path)
    gitdir = git(root, 'rev-parse', '--absolute-git-dir').decode().strip()
    if (context.get('root') != str(root) or context.get('git_dir') != gitdir
            or Path(gitdir).resolve() == common_dir(root)
            or context.get('source') != git(root, 'rev-parse', 'HEAD').decode().strip()):
        raise ProofRunError('capture context is not this isolated commit checkout')
    _only_generated_change(root)
    validated_state(root)
    git(root, 'add', '--', STATE_PATH)


def record(root):
    """Execute a fixed full check in an isolated commit checkout; never import an old log."""
    _require_local_store_platform()
    try:
        import fcntl
    except ImportError as exc:
        raise ProofRunError('local proof capture requires POSIX locking') from exc
    root = Path(root).resolve()
    source = git(root, 'rev-parse', 'HEAD').decode().strip()
    supported_input_model(root, source)
    no_checkout_filters(root)
    policy_modules = {'proof_runs.py': Path(__file__), 'ci_changes.py': Path(ci_changes.__file__),
                      'gen_proof_manifest.py': Path(gpm.__file__), 'check_lid_staleness.py': Path(lid.__file__),
                      'check_tier_parity.py': Path(gpm.ctp.__file__),
                      'check_no_alloc.py': Path(sys.modules[strip_rust.__module__].__file__),
                      'proof_run_common.py': Path(proof_run_common.__file__),
                      'proof_run_tools.py': Path(proof_run_tools.__file__),
                      'proof_run_metadata.py': Path(proof_run_metadata.__file__)}
    for name, path in policy_modules.items():
        if digest(git(root, 'show', source + ':gates/' + name)) != digest(path.read_bytes()):
            raise ProofRunError('capture requires committed recorder/helper policy: ' + name)
    store, repo = _store(root, create=True)
    lockfd = os.open(store / 'record.lock', os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(lockfd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProofRunError('another proof capture is active in this repository') from exc
        stale = stale_checkouts(root)
        if stale:  # Only the lock holder may judge a container stale: no other capture is live.
            raise ProofRunError('stale capture checkout(s) left by an interrupted run; refusing to start: '
                                + ', '.join(path.name for path in stale)
                                + '; remove them with: python3 gates/proof_runs.py clean-stale')
        if (store / 'index.json').exists():
            trusted_runs(root)  # Check existing trust integrity before any expensive work.
        run_id = uuid.uuid4().hex
        container = tempfile.TemporaryDirectory(prefix=CHECKOUT_PREFIX, dir=common_dir(root))
        target = Path(container.name) / 'checkout'
        added = False
        try:
            git(root, 'worktree', 'add', '--detach', str(target), source)
            added = True
            checkout_bytes_match(target, source)
            roster = harness_roster(target)
            cover_names = cover_roster(target)
            # The registry depends only on the source: validate it before the multi-hour run.
            disclosed = _disclosed_vacuity_roster(root, source, roster)
            before = observe_tools(target)
            if git(target, 'status', '--porcelain', '--untracked-files=all').strip():
                raise ProofRunError('isolated proof checkout is not clean')
            started = time.time_ns()
            env = capture_environment(target)
            context_path = store / ('capture-' + run_id + '.json')
            _write(context_path, canonical({'root': str(target.resolve()), 'source': source,
                   'git_dir': git(target, 'rev-parse', '--absolute-git-dir').decode().strip()}))
            env['DER_PROOF_CAPTURE_CONTEXT'] = str(context_path)
            log_path = store / (run_id + '.log')
            fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, 'wb') as log:
                with subprocess.Popen(['sh', 'check.sh'], cwd=target, env=env,
                                      stdout=subprocess.PIPE, stderr=subprocess.STDOUT) as process:
                    for chunk in iter(lambda: process.stdout.read1(65536), b''):
                        log.write(chunk)
                        sys.stdout.buffer.write(chunk)
                        sys.stdout.buffer.flush()
                    code = process.wait()
            finished = time.time_ns()
            if code != 0:
                raise ProofRunError(f'full run exited {code}; log retained, no trusted receipt created')
            if git(target, 'rev-parse', 'HEAD').decode().strip() != source:
                raise ProofRunError('proof checkout HEAD changed during run')
            _only_generated_change(target)
            checkout_bytes_match(target, source, allowed_outputs={STATE_PATH})
            generated = {STATE_PATH: validated_state(target)}
            if observe_tools(target) != before:
                raise ProofRunError('tool identity changed during run')
            data = _read(log_path)
            counts = validate_log(data, roster, cover_names, disclosed)
            generated[FLOOR_PATH] = floor_output(source, digest(data), counts, started, finished)
            floor = json.loads(base64.b64decode(generated[FLOOR_PATH]['content_base64']))
            generated[PROJECTION_PATH] = projected_manifest((target / PROJECTION_PATH).read_bytes(), floor)
            receipt = {'format': FORMAT, 'run_id': run_id, 'repository_id': repo['id'],
                       'source_commit': source, 'source_tree': git(root, 'rev-parse', source + '^{tree}').decode().strip(),
                       'command': ['sh', 'check.sh'], 'require_lean': True, 'exit_code': 0,
                       'environment_policy': ENVIRONMENT_POLICY, 'environment': env,
                       'input_profile': 'der-source-only/1',
                       'started_ns': started, 'finished_ns': finished, 'harnesses': roster, 'cover_harnesses': cover_names,
                       'disclosed_vacuity_harnesses': disclosed,
                       'log_sha256': digest(data), 'tools': before, 'generated_outputs': generated,
                       'recorder_sha256': digest(Path(__file__).read_bytes())}
            receipt_data = canonical(receipt)
            _write(store / (run_id + '.json'), receipt_data)
            git(root, 'update-ref', 'refs/der-proof-runs/' + run_id, source, '0' * 40)
            index_path = store / 'index.json'
            index = _json(index_path) if index_path.exists() else {}
            index[run_id] = digest(receipt_data)
            _write(index_path, canonical(index))
            return verify_trusted_run(root, source)
        finally:
            context = store / ('capture-' + run_id + '.json')
            context.unlink(missing_ok=True)
            try:
                if added:
                    git(root, 'worktree', 'remove', '--force', str(target))
            finally:
                container.cleanup()


def _disclosed_vacuity_roster(root, source, roster):
    """Read the committed VACUITY-DISCLOSED registry and bind it to full harness names."""
    names = []
    raw = git(root, 'ls-tree', '-r', '--name-only', '-z', source, '--', 'der-verified/src')
    for path in raw.decode().rstrip('\0').split('\0') if raw else []:
        if not path.endswith('.rs') or path.endswith('/lib.rs'):
            continue
        module = Path(path).stem
        text = git(root, 'show', source + ':' + path).decode()
        if any('VACUITY-DISCLOSED' in line and not gpm.VACUITY_RE.search(line) for line in text.splitlines()):
            raise ProofRunError('malformed disclosed-vacuity registry line in ' + path)
        for match in gpm.VACUITY_RE.finditer(text):
            harness = module + '::proofs::' + match[1]
            witness = module + '::proofs::' + match[2]
            if harness not in roster or witness not in roster:
                raise ProofRunError('disclosed-vacuity registry names an unknown harness or witness')
            names.append(harness)
    if len(names) != len(set(names)):
        raise ProofRunError('duplicate disclosed-vacuity registry entry')
    return sorted(names)


def _verify_entry(root, store, repo, run_id, pin):
    if not isinstance(run_id, str) or not isinstance(pin, str) or not re.fullmatch(r'[0-9a-f]{32}', run_id) or not re.fullmatch(r'[0-9a-f]{64}', pin):
        raise ProofRunError('invalid trusted run index')
    path = store / (run_id + '.json')
    data = _read(path)
    if digest(data) != pin:
        raise ProofRunError('local receipt hash mismatch')
    receipt = _json(path)
    if not isinstance(receipt, dict):
        raise ProofRunError('receipt must be an object')
    if (receipt.get('format') != FORMAT or receipt.get('run_id') != run_id
            or receipt.get('repository_id') != repo['id']
            or receipt.get('command') != ['sh', 'check.sh'] or receipt.get('require_lean') is not True
            or type(receipt.get('exit_code')) is not int or receipt['exit_code'] != 0
            or receipt.get('environment_policy') != ENVIRONMENT_POLICY
            or receipt.get('input_profile') != 'der-source-only/1'
            or set(receipt.get('tools', {})) != TOOL_KEYS
            or not all(receipt['tools'].values())):
        raise ProofRunError('incomplete, foreign or incompatible full-run receipt')
    environment = receipt.get('environment')
    fixed = {'GIT_NO_REPLACE_OBJECTS': '1', 'GIT_CONFIG_NOSYSTEM': '1',
             'GIT_CONFIG_GLOBAL': os.devnull, 'GIT_CONFIG_SYSTEM': os.devnull,
             'DER_REQUIRE_LEAN': '1', 'CARGO_TERM_COLOR': 'never', 'NO_COLOR': '1',
             'PYTHONDONTWRITEBYTECODE': '1'}
    if (not isinstance(environment, dict) or not {'PATH', 'HOME', 'DER_PROOF_CAPTURE_CONTEXT'} <= set(environment)
            or set(environment) - CAPTURE_ENV_NAMES - set(fixed) - {'DER_PROOF_CAPTURE_CONTEXT'}
            or any(environment.get(k) != v for k, v in fixed.items())
            or not all(isinstance(v, str) for v in environment.values())
            or environment['DER_PROOF_CAPTURE_CONTEXT'] != str(store / ('capture-' + run_id + '.json'))):
        raise ProofRunError('invalid captured environment provenance')
    source_name = receipt.get('source_commit')
    ref = 'refs/der-proof-runs/' + run_id
    try:
        retained = git(root, 'rev-parse', '--verify', ref + '^{commit}').decode().strip()
    except ProofRunError as exc:
        raise ProofRunError('recorded source ref is missing or its commit was pruned: ' + ref) from exc
    if retained != source_name:
        raise ProofRunError('recorded source ref does not match its receipt: ' + ref)
    source = commit_id(root, source_name)
    # The committed recorder and immutable receipt attest the historical input
    # profile. Current policy is applied when comparing a candidate for reuse.
    if receipt.get('recorder_sha256') != digest(git(root, 'show', source + ':gates/proof_runs.py')):
        raise ProofRunError('receipt recorder identity differs from its committed policy')
    if git(root, 'rev-parse', source + '^{tree}').decode().strip() != receipt.get('source_tree'):
        raise ProofRunError('receipt source-tree identity mismatch')
    if not (type(receipt.get('started_ns')) is int and type(receipt.get('finished_ns')) is int
            and 0 < receipt['started_ns'] <= receipt['finished_ns']):
        raise ProofRunError('invalid run completion times')
    log = _read(store / (run_id + '.log'))
    if digest(log) != receipt.get('log_sha256'):
        raise ProofRunError('raw log digest mismatch')
    outputs = receipt.get('generated_outputs', {})
    if not isinstance(outputs, dict) or set(outputs) != {STATE_PATH, FLOOR_PATH, PROJECTION_PATH}:
        raise ProofRunError('missing or unexpected generated-output record')
    try:
        for output in outputs.values():
            output_data = base64.b64decode(output['content_base64'], validate=True)
            if digest(output_data) != output['sha256']:
                raise ProofRunError('generated-output digest mismatch')
    except (KeyError, TypeError, ValueError) as exc:
        raise ProofRunError('invalid generated-output record') from exc
    roster = receipt.get('harnesses')
    if (not isinstance(roster, list) or not roster
            or not all(isinstance(name, str) and re.fullmatch(r'[A-Za-z0-9_:]+', name) for name in roster)
            or len(set(roster)) != len(roster)):
        raise ProofRunError('invalid captured harness roster')
    cover_names = receipt.get('cover_harnesses')
    if not isinstance(cover_names, list) or not all(isinstance(n, str) and n in roster for n in cover_names):
        raise ProofRunError('invalid expected-cover roster')
    disclosed = receipt.get('disclosed_vacuity_harnesses')
    if (not isinstance(disclosed, list) or disclosed != sorted(set(disclosed))
            or not all(isinstance(n, str) and n in roster for n in disclosed)
            or disclosed != _disclosed_vacuity_roster(root, source, roster)):
        raise ProofRunError('invalid or source-mismatched disclosed-vacuity registry')
    counts = validate_log(log, roster, cover_names, disclosed)
    floor = validate_floor_declaration(base64.b64decode(outputs[FLOOR_PATH]['content_base64']), source)
    bindings = {**counts, 'raw_sha256': digest(log), 'started_ns': receipt['started_ns'],
                'finished_ns': receipt['finished_ns'], 'file': FLOOR_PATH,
                'memory_cap': 'not measured by recorder', 'peak_memory': 'not measured by recorder'}
    if any(floor.get(key) != value for key, value in bindings.items()):
        raise ProofRunError('captured floor output does not bind this completed run')
    validate_projection_invariants(git(root, 'show', source + ':' + PROJECTION_PATH),
                                  base64.b64decode(outputs[PROJECTION_PATH]['content_base64']))
    _validated_state_data(base64.b64decode(outputs[STATE_PATH]['content_base64']),
                          git(root, 'show', source + ':lean/check_lean.sh').decode(),
                          lambda name: git(root, 'show', source + ':' + name))
    return {'mode': 'fresh', 'run_commit': source, 'run_id': run_id,
            'receipt_sha256': pin, 'log_sha256': receipt['log_sha256'],
            'tools': receipt['tools'], 'tool_scope': 'historical captured tools, not a run with current host tools', 'generated_outputs': outputs, 'finished_ns': receipt['finished_ns']}


def trusted_runs(root):
    store, repo = _store(root)
    index = _json(store / 'index.json')
    if not isinstance(index, dict) or not index:
        raise ProofRunError('no registered completed full runs')
    if set(index) & set(_retired(store)):
        raise ProofRunError('a retired (quarantined) run is present in the active index; refusing')
    # Corruption is a refusal, not a reason to silently select another receipt.
    return sorted((_verify_entry(root, store, repo, key, value) for key, value in index.items()),
                  key=lambda item: item['finished_ns'], reverse=True)


def stale_checkouts(root):
    """Capture containers left in the common dir by a killed run (the lock holder calls this)."""
    return sorted(common_dir(root).glob(CHECKOUT_PREFIX + '*'))


@contextlib.contextmanager
def _capture_lock(root, store):
    import fcntl
    lockfd = os.open(store / 'record.lock', os.O_RDWR | os.O_CREAT, 0o600)
    with os.fdopen(lockfd, 'w') as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise ProofRunError('another proof capture is active in this repository') from exc
        yield


def clean_stale(root):
    """Remove only stale capture checkout directories (and their worktree registrations)."""
    _require_local_store_platform()
    root = Path(root).resolve()
    base = common_dir(root)
    # No store means no capture has ever run here, so nothing can be live.
    store = _store(root)[0] if store_root(root).exists() else None
    context = _capture_lock(root, store) if store is not None else contextlib.nullcontext()
    removed = []
    with context:
        for path in stale_checkouts(root):
            if path.parent != base or path.is_symlink() or not path.is_dir():
                raise ProofRunError('unexpected non-directory stale capture entry; remove it by hand: ' + path.name)
            checkout = path / 'checkout'
            if checkout.is_dir() and not checkout.is_symlink():
                with contextlib.suppress(ProofRunError):
                    git(root, 'worktree', 'remove', '--force', str(checkout))
            shutil.rmtree(path)
            removed.append(path.name)
        if removed:
            with contextlib.suppress(ProofRunError):
                git(root, 'worktree', 'prune')
    return {'removed': removed}


def _retired(store):
    path = store / 'quarantine' / 'retired.json'
    if path.is_symlink():
        raise ProofRunError('quarantine registry must not be a symlink')
    if not path.exists():
        return {}
    data = _json(path)
    if not isinstance(data, dict):
        raise ProofRunError('invalid quarantine registry')
    return data


def retire(root, run_id, reason):
    """Explicitly quarantine ONE registered run so a single bad entry cannot block record/verify.

    The entry is never verified or trusted again: it leaves the active index, its files move to
    store/quarantine/, and a reason and timestamp are logged. A retired run id that reappears in
    the active index is refused. The refs/der-proof-runs/<id> source ref is left in place.
    """
    _require_local_store_platform()
    if not isinstance(run_id, str) or not RUN_ID_RE.fullmatch(run_id):
        raise ProofRunError('invalid run id; expected 32 lowercase hex characters')
    reason = (reason or '').strip()
    if not reason or len(reason) > 500 or any(ch in reason for ch in '\r\n\0'):
        raise ProofRunError('a non-empty single-line reason (at most 500 characters) is required')
    root = Path(root).resolve()
    store, _ = _store(root)
    with _capture_lock(root, store):
        index_path = store / 'index.json'
        index = _json(index_path) if index_path.exists() else None
        if not isinstance(index, dict) or run_id not in index:
            raise ProofRunError('unknown run id (not in the active index): ' + run_id)
        quarantine = store / 'quarantine'
        if not quarantine.exists():
            quarantine.mkdir(mode=0o700)
        if quarantine.is_symlink() or not quarantine.is_dir() or quarantine.stat().st_mode & 0o077:
            raise ProofRunError('quarantine area must be an owner-only directory')
        stamp = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds')
        retired = _retired(store)
        retired[run_id] = {'pin': index[run_id] if isinstance(index[run_id], str) else None,
                           'reason': reason, 'retired_at': stamp}
        _write(quarantine / 'retired.json', canonical(retired))
        fd = os.open(quarantine / 'retired.log', os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, 'a') as log:
            log.write(f'{stamp}\t{run_id}\t{reason}\n')
        for suffix in ('.json', '.log'):
            source = store / (run_id + suffix)
            if source.is_symlink() or source.exists():
                os.replace(source, quarantine / (run_id + suffix))
        remaining = {key: value for key, value in index.items() if key != run_id}
        if remaining:
            _write(index_path, canonical(remaining))
        else:
            index_path.unlink()
    return {'retired': run_id, 'reason': reason, 'retired_at': stamp, 'remaining': sorted(remaining)}


def verify_trusted_run(root, source_commit, receipt_sha256=None):
    """Select the newest source run, or the exact registered run bound by a release."""
    source = commit_id(root, source_commit)
    if receipt_sha256 is not None and (not isinstance(receipt_sha256, str)
            or not re.fullmatch(r'[0-9a-f]{64}', receipt_sha256)):
        raise ProofRunError('invalid bound proof receipt digest')
    for run in trusted_runs(root):
        if (run['run_commit'] == source
                and (receipt_sha256 is None or run['receipt_sha256'] == receipt_sha256)):
            return run
    raise ProofRunError('no trusted completed full run at requested source commit and receipt binding')


def verify(root, target, ref):
    target = commit_id(root, target)
    git(root, 'check-ref-format', ref)
    if ref.startswith('refs/tags/'):
        try:
            from release_evidence import verify_release
            return verify_release(Path(root), target, ref)
        except (ImportError, ValueError, KeyError, UnicodeError) as exc:
            raise ProofRunError(f'release validation required: {exc}') from exc
    if not ref.startswith('refs/heads/'):
        raise ProofRunError('unsupported remote ref; expected branch or release tag')
    for run in trusted_runs(root):
        try:
            comparison = _compare_inputs(root, run['run_commit'], target, _verified_run=run)
        except ProofRunError:
            continue
        # A release between S and U must not be bypassed by reverting all of its
        # artifacts back to S. A later actual capture at/after T remains usable.
        from release_evidence import _receipt_path, verify_release_commit
        later = git(root, 'rev-list', target, '^' + run['run_commit']).decode().splitlines()
        if any(_receipt_path(root, ancestor).exists() for ancestor in later):
            try:
                return verify_release_commit(Path(root), target, allow_prose_descendants=True)
            except (ImportError, ValueError, KeyError, UnicodeError) as exc:
                raise ProofRunError(f'release carry-over required but invalid: {exc}') from exc
        return {**run, 'target_commit': target, 'ref': ref,
                'mode': 'fresh' if target == run['run_commit'] else 'carry-over', **comparison}
    try:
        from release_evidence import verify_release_commit
        return verify_release_commit(Path(root), target, allow_prose_descendants=True)
    except (ImportError, ValueError, KeyError, UnicodeError) as exc:
        raise ProofRunError('no trusted ancestor with unchanged inputs or validated release ancestor: ' + str(exc)) from exc


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest='command', required=True)
    stage = commands.add_parser('stage-state', help=argparse.SUPPRESS)
    stage.add_argument('--lean-status', required=True)
    commands.add_parser('record', help='EXPENSIVE: run the complete Kani+Lean gate in an isolated HEAD checkout')
    commands.add_parser('clean-stale', help='remove capture checkouts left behind by a killed record run')
    quarantine = commands.add_parser('retire', help='quarantine ONE registered run (logged); never accepted again')
    quarantine.add_argument('--run-id', required=True)
    quarantine.add_argument('--reason', required=True)
    check = commands.add_parser('verify', help='read-only branch proof receipt validation')
    check.add_argument('--commit', required=True)
    check.add_argument('--ref', required=True)
    args = parser.parse_args()
    try:
        if args.command == 'stage-state':
            stage_state(ROOT, args.lean_status)
            return 0
        if args.command == 'record':
            result = record(ROOT)
        elif args.command == 'clean-stale':
            result = clean_stale(ROOT)
        elif args.command == 'retire':
            result = retire(ROOT, args.run_id, args.reason)
        else:
            result = verify(ROOT, args.commit, args.ref)
    except (ValueError, KeyError, UnicodeError, OSError) as exc:
        print(f'FAIL proof_runs: {exc}', file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == '__main__':
    sys.exit(main())
