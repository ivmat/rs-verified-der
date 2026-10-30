#!/usr/bin/env python3
"""Skip Kani only for a known documentation-only pull request.

Compare the PR base with the checked merge commit, not just the last pushed commit.
Pushes always run Kani: a preceding source-changing run may have been cancelled.
Unknown paths, missing history and malformed events all select the full CI proof tier.
This is job selection, not a proof receipt or evidence carry-over decision.
"""
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parent.parent
DOC_FILES = {
    'README.md', 'ARCHITECTURE.md', 'ASSUMPTIONS.md', 'CHANGELOG.md', 'COVERAGE.md',
    'DECISIONS.md', 'DER-REMAINING-WORK.md', 'DOCS-SYNC.md', 'PROOF_MANIFEST.md',
    'REPLAY.md', 'SECURITY.md', 'TODO.md', 'der-verified/README.md',
    'docs/why-verified.md', 'docs/verification-cost.md', 'docs/STATUS-2026-09-28.md',
    'evidence/README.md', 'docs/ci.md', 'docs/release.md',
}


def documentation_only(paths):
    """An explicit allowlist; requirements, source docs, gates and unknown files run Kani."""
    return bool(paths) and all(path in DOC_FILES or (
        path.startswith('docs/archive/') and path.endswith('.md')
        and all(part not in ('', '.', '..') for part in path.split('/'))
    ) for path in paths)


def run_kani(root, event_name, event):
    if event_name != 'pull_request':
        return True
    try:
        base = event['pull_request']['base']['sha']
        if not isinstance(base, str) or not re.fullmatch(r'[0-9a-f]{40}', base):
            return True
        def git(*args):
            return subprocess.check_output(
                ['git', '-C', str(root), *args], stderr=subprocess.DEVNULL, timeout=30)
        # The default PR checkout is the tested merge. Missing/non-ancestor bases
        # cannot establish that this diff covers the whole PR.
        git('merge-base', '--is-ancestor', base, 'HEAD')
        # Disable rename detection so BOTH source and destination paths are considered.
        raw = git('diff', '--name-only', '--no-renames', '-z', base, 'HEAD', '--')
        paths = raw.decode('utf-8', errors='strict').rstrip('\0').split('\0') if raw else []
        return not documentation_only(paths)
    except (KeyError, TypeError, ValueError, OSError, subprocess.SubprocessError):
        return True


def main():
    try:
        event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    except (KeyError, OSError, ValueError):
        event = {}
    required = run_kani(ROOT, os.environ.get('GITHUB_EVENT_NAME', ''), event)
    value = 'true' if required else 'false'
    print(f'run_kani={value}: ' + ('run the CI proof tier' if required else
          'known documentation-only PR; Kani is not run and no proof result is claimed'))
    if output := os.environ.get('GITHUB_OUTPUT'):
        with open(output, 'a', encoding='utf-8') as stream:
            stream.write(f'run_kani={value}\n')


if __name__ == '__main__':
    main()
