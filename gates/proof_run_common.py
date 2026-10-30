#!/usr/bin/env python3
"""Git identity and byte helpers shared by local proof capture and release validation."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess


class ProofRunError(ValueError):
    pass



def git_env():
    env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}
    env.update(GIT_NO_REPLACE_OBJECTS='1', GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_GLOBAL=os.devnull,
               GIT_CONFIG_SYSTEM=os.devnull)
    return env



def git(root, *args):
    command = ['git', '--no-replace-objects', '-c', f'core.hooksPath={os.devnull}', '-C', str(root)]
    try:
        probe = subprocess.run(command + ['rev-parse', '--path-format=absolute', '--git-common-dir'],
                               env=git_env(), capture_output=True, timeout=30)
        if probe.returncode == 0:
            grafts = Path(probe.stdout.decode().strip()) / 'info/grafts'
            if grafts.exists() and grafts.read_bytes().strip():
                raise ProofRunError('legacy Git grafts prevent reliable source identity')
        return subprocess.check_output(command + list(args), env=git_env(),
                                       stderr=subprocess.PIPE, timeout=30)
    except (OSError, subprocess.SubprocessError) as exc:
        raise ProofRunError(f'Git identity/history check failed: {args[0]}') from exc



def commit_id(root, value):
    if not isinstance(value, str) or not re.fullmatch(r'[0-9a-f]{40}', value):
        raise ProofRunError('expected a full 40-hex Git object identity')
    return git(root, 'rev-parse', '--verify', value + '^{commit}').decode().strip()



def common_dir(root):
    return Path(git(root, 'rev-parse', '--path-format=absolute', '--git-common-dir').decode().strip()).resolve()



def digest(data):
    return hashlib.sha256(data).hexdigest()



def canonical(data):
    return (json.dumps(data, sort_keys=True, indent=2) + '\n').encode()

