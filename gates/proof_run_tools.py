#!/usr/bin/env python3
"""Supported proof environment, effective tools and isolated checkout byte identity."""
import os
import hashlib
from pathlib import Path
import re
import shutil
import subprocess
import sys
from proof_run_common import ProofRunError, git, git_env, common_dir, digest

CAPTURE_ENV_NAMES = frozenset({'PATH', 'HOME', 'TMPDIR', 'LANG', 'LC_ALL', 'LC_CTYPE',
    'CARGO_HOME', 'RUSTUP_HOME', 'KANI_HOME', 'ELAN_HOME', 'VERIFIED_RS_TOOLS'})
ENVIRONMENT_POLICY = 'supported-pinned-environment/2'


def capture_environment(root):
    """Only reviewed path/locale inputs reach proof tools; no arbitrary caller variables."""
    supported_environment(root)
    env = {name: os.environ[name] for name in sorted(CAPTURE_ENV_NAMES) if name in os.environ}
    env.setdefault('PATH', os.defpath)
    env.setdefault('HOME', str(Path.home()))
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_NOSYSTEM='1',
               GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull,
               DER_REQUIRE_LEAN='1', CARGO_TERM_COLOR='never', NO_COLOR='1',
               PYTHONDONTWRITEBYTECODE='1')
    return env


def _probe(root, command):
    try:
        value = subprocess.check_output(command, cwd=root, env=capture_environment(root),
                                        stderr=subprocess.STDOUT, timeout=60).decode().strip()
    except (OSError, UnicodeError, subprocess.SubprocessError) as exc:
        raise ProofRunError(f'tool version unavailable: {command[0]}') from exc
    if not value:
        raise ProofRunError(f'empty tool identity: {command[0]}')
    return value



def supported_environment(root):
    """Support the normal pinned setup, not arbitrary compiler/loader/search overrides."""
    exact = {'RUSTFLAGS', 'CARGO_ENCODED_RUSTFLAGS', 'RUSTDOCFLAGS', 'CARGO_ENCODED_RUSTDOCFLAGS',
             'RUSTC', 'RUSTDOC', 'RUSTC_WRAPPER', 'RUSTC_WORKSPACE_WRAPPER', 'RUSTUP_TOOLCHAIN',
             'LEAN_PATH', 'LEAN_SRC_PATH', 'LEAN_SYSROOT', 'ELAN_TOOLCHAIN', 'LD_PRELOAD',
             'LD_LIBRARY_PATH', 'PYTHONPATH', 'PYTHONHOME', 'PYTHONOPTIMIZE'}
    prefixes = ('CARGO_BUILD_', 'CARGO_TARGET_', 'DYLD_', 'LAKE_')
    bad = sorted(k for k, v in os.environ.items() if v and
                 (k in exact or k.startswith(prefixes) or (k.startswith('KANI_') and k != 'KANI_HOME')))
    if sys.flags.optimize:
        raise ProofRunError('optimized Python cannot capture proof evidence')
    if bad:
        raise ProofRunError('unsupported proof-environment override(s): ' + ', '.join(bad))
    cargo_home = Path(os.environ.get('CARGO_HOME', str(Path.home() / '.cargo')))
    # The isolated checkout's own configuration is committed and compared. Cargo
    # also searches ancestors and CARGO_HOME; refuse those uncommitted inputs.
    configs = [cargo_home / name for name in ('config', 'config.toml')]
    configs += [parent / '.cargo' / name for parent in Path(root).resolve().parents
                for name in ('config', 'config.toml')]
    if any(path.exists() for path in configs):
        raise ProofRunError('external user/ancestor Cargo configuration is unsupported; use committed configuration')



def effective_binary(name, root, manager, manager_args):
    """Direct system installations work; only actual manager proxies need resolution."""
    found = shutil.which(name)
    if not found:
        raise ProofRunError(f'{name} launcher unavailable')
    launcher = Path(found).resolve()
    managed = shutil.which(manager)
    manager_path = Path(managed).resolve() if managed else None
    proxy = launcher.name == manager or (manager_path is not None and
            (launcher.samefile(manager_path) or digest(launcher.read_bytes()) == digest(manager_path.read_bytes())))
    backend = Path(_probe(root, [str(manager_path or launcher), *manager_args])).resolve() if proxy else launcher
    if not backend.is_file():
        raise ProofRunError(f'{name} effective binary unavailable')
    return launcher, backend


def python_launcher():
    launcher = shutil.which('python3')
    if not launcher or not Path(launcher).samefile(sys.executable):
        raise ProofRunError('python3 launcher differs from the recorder Python')
    return Path(launcher)


def require_lean_version(observed, pin):
    version = re.match(r'^Lean \(version ([^,\s)]+)(?:,|\s|\))', observed)
    if not version or version[1] != pin:
        raise ProofRunError('observed Lean version differs from declared pin')



def tree_fingerprint(path):
    """Hash relevant installed tool files, following aliases but refusing symlink cycles."""
    path = Path(path)
    if not path.exists():
        raise ProofRunError('required tool component unavailable: ' + path.name)
    result = hashlib.sha256()
    def walk(current, relative, ancestors):
        resolved = current.resolve()
        result.update(relative.encode() + b'\0' + str(current.stat().st_mode & 0o777).encode() + b'\0')
        if current.is_dir():
            if resolved in ancestors:
                raise ProofRunError('tool component has a symlink cycle')
            for child in sorted(current.iterdir()):
                walk(child, relative + '/' + child.name, ancestors | {resolved})
        elif current.is_file():
            with current.open('rb') as stream:
                for chunk in iter(lambda: stream.read(1024 * 1024), b''):
                    result.update(chunk)
        else:
            raise ProofRunError('unsupported tool component file type')
    walk(path, '.', set())
    return result.hexdigest()



def observe_tools(root):
    """Historical effective-tool identity; equal observations are required before/after capture."""
    root = Path(root)
    supported_environment(root)
    python = python_launcher()
    tools = {'python': {'version': sys.version, 'optimize': sys.flags.optimize,
                        'binary_sha256': tree_fingerprint(Path(sys.executable)),
                        'launcher_sha256': tree_fingerprint(Path(python))}}
    for name in ('rustc', 'cargo'):
        launcher, binary = effective_binary(name, root, 'rustup', ['which', name])
        args = ['--version', '--verbose'] if name == 'rustc' else ['--version']
        tools[name] = {'version': _probe(root, [str(binary), *args]),
                       'launcher_sha256': tree_fingerprint(launcher),
                       'binary_sha256': tree_fingerprint(binary)}
    rust_sysroot = Path(_probe(root, [str(effective_binary('rustc', root, 'rustup', ['which', 'rustc'])[1]),
                                     '--print', 'sysroot']))
    tools['rustc']['rustlib_sha256'] = tree_fingerprint(rust_sysroot / 'lib/rustlib')
    drivers = sorted(set(rust_sysroot.glob('lib/librustc_driver*')) |
                     set(rust_sysroot.glob('lib/*/librustc_driver*')))
    tools['rustc']['drivers'] = {str(p.relative_to(rust_sysroot)): tree_fingerprint(p) for p in drivers}
    tools['kani'] = {'version': _probe(root, ['cargo', 'kani', '--version'])}
    pin = re.search(r"kani-version:\s*'([0-9.]+)'", (root / '.github/workflows/ci.yml').read_text())
    if not pin or not re.search(r'\b' + re.escape(pin[1]) + r'\b', tools['kani']['version']):
        raise ProofRunError('observed Kani version differs from declared CI pin')
    launcher = shutil.which('cargo-kani')
    if not launcher:
        raise ProofRunError('effective cargo-kani launcher unavailable')
    tools['kani']['launcher_sha256'] = tree_fingerprint(Path(launcher))
    bundle = Path(os.environ.get('KANI_HOME', str(Path.home() / '.kani'))) / ('kani-' + pin[1])
    tools['kani']['components'] = {name: tree_fingerprint(bundle / name) for name in
        ('bin', 'lib', 'library', 'no_core', 'playback', 'scripts', 'toolchain/bin', 'toolchain/lib', 'rustc-version', 'rust-toolchain-version')}
    for name in ('kani-compiler', 'cbmc', 'goto-instrument', 'kissat'):
        if not (bundle / 'bin' / name).is_file():
            raise ProofRunError('Kani bundle lacks required component: ' + name)
    tools['kani']['cbmc_version'] = _probe(root, [str(bundle / 'bin/cbmc'), '--version'])
    lean_launcher, lean = effective_binary('lean', root / 'lean', 'elan', ['which', 'lean'])
    lake_launcher, lake = effective_binary('lake', root / 'lean', 'elan', ['which', 'lake'])
    if lean.parent != lake.parent:
        raise ProofRunError('Lean and Lake effective binaries do not share a toolchain')
    tools['lean'] = {'version': _probe(root / 'lean', [str(lean), '--version']),
                     'lake_version': _probe(root / 'lean', [str(lake), '--version']),
                     'launcher_sha256': tree_fingerprint(lean_launcher),
                     'lake_launcher_sha256': tree_fingerprint(lake_launcher),
                     'lean_sha256': tree_fingerprint(lean), 'lake_sha256': tree_fingerprint(lake),
                     'library_sha256': tree_fingerprint(lean.parent.parent / 'lib/lean')}
    lean_pin = (root / 'lean/lean-toolchain').read_text().strip().split(':')[-1].removeprefix('v')
    require_lean_version(tools['lean']['version'], lean_pin)
    tool_root = Path(os.environ.get('VERIFIED_RS_TOOLS', str(Path.home() / 'Downloads/verified_rs_tools')))
    script = (root / 'lean/check_lean.sh').read_text()
    for name, repo, binary in (
        ('aeneas', tool_root / 'aeneas', tool_root / 'aeneas/bin/aeneas'),
        ('charon', tool_root / 'aeneas/charon', tool_root / 'aeneas/charon/bin/charon'),
    ):
        pin = re.search(r'EXPECT_' + name.upper() + r'="([0-9a-f]{40})"', script)
        actual = git(repo, 'rev-parse', 'HEAD').decode().strip()
        if not pin or actual != pin[1] or git(repo, 'status', '--porcelain', '--untracked-files=all').strip():
            raise ProofRunError(f'{name} pin mismatch or dirty tool checkout')
        if not binary.is_file():
            raise ProofRunError(f'{name} binary unavailable')
        tools[name] = {'commit': actual, 'binary_sha256': tree_fingerprint(binary)}
    return tools



def checkout_bytes_match(root, source, allowed_outputs=()):
    """Git's clean status can hide CRLF/smudge normalization; compare the actual bytes."""
    for entry in git(root, 'ls-tree', '-r', '-z', source).decode().rstrip('\0').split('\0'):
        if not entry:
            continue
        metadata, relative = entry.split('\t', 1)
        if relative in allowed_outputs:
            continue
        mode = metadata.split()[0]
        path = Path(root) / relative
        original = git(root, 'show', source + ':' + relative)
        if mode == '120000':
            if not path.is_symlink() or os.readlink(path).encode() != original:
                raise ProofRunError('checkout symlink differs from committed input')
        elif (path.is_symlink() or not path.is_file() or path.read_bytes() != original
              or bool(path.stat().st_mode & 0o111) != (mode == '100755')):
            raise ProofRunError('checkout bytes/mode differ from committed input: ' + relative)



def no_checkout_filters(root):
    info = common_dir(root) / 'info/attributes'
    if info.exists() and info.read_bytes().strip():
        raise ProofRunError('local Git attributes are unsupported for isolated proof capture')
    result = subprocess.run(['git', '--no-replace-objects', '-C', str(root),
                             'config', '--get-regexp', r'^filter\.'], env=git_env(),
                            capture_output=True, timeout=30)
    if result.returncode != 1:
        raise ProofRunError('Git checkout filters or unreadable configuration are unsupported')

