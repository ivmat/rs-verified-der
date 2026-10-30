#!/usr/bin/env python3
"""Real Git histories exercise CI selection, including cancelled-run and rename traps."""
from pathlib import Path
import subprocess
import json
import os
import sys
import textwrap
import tempfile
import unittest
from unittest.mock import patch

import ci_changes as ci


class Selection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        # Pre-commit may pass GIT_INDEX_FILE for a partial commit. Fixtures must
        # never inherit the caller's index, worktree, config injection or hooks.
        self.env = {key: value for key, value in os.environ.items()
                    if not key.startswith('GIT_')}
        self.env.update(GIT_CONFIG_NOSYSTEM='1', GIT_CONFIG_SYSTEM=os.devnull,
                        GIT_CONFIG_GLOBAL=os.devnull)
        self.git('init', '-q')
        self.git('config', 'user.name', 'CI selection test')
        self.git('config', 'user.email', 'ci-selection@example.invalid')
        self.write('README.md', 'initial')
        self.write('der-verified/src/lib.rs', 'initial')
        self.base = self.commit()
        self.event = {'pull_request': {'base': {'sha': self.base}}}

    def git(self, *args):
        return subprocess.check_output(
            ['git', '-c', f'core.hooksPath={os.devnull}', '-C', str(self.root), *args],
            env=self.env, stderr=subprocess.DEVNULL).decode().strip()

    def write(self, path, value):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(value)

    def commit(self):
        self.git('add', '-A')
        self.git('commit', '-qm', 'fixture')
        return self.git('rev-parse', 'HEAD')

    def selected(self, event_name='pull_request', event=None):
        with patch.dict(os.environ, self.env, clear=True):
            return ci.run_kani(self.root, event_name, self.event if event is None else event)

    def test_inherited_index_is_untouched(self):
        index = Path(self.tmp.name) / 'caller-index'
        sentinel = b'not a Git index: caller-owned sentinel'
        index.write_bytes(sentinel)
        # Exclude the sentinel itself from the fixture commit's changed paths.
        with (self.root / '.git/info/exclude').open('a') as stream:
            stream.write('\ncaller-index\n')
        with patch.dict(os.environ, {'GIT_INDEX_FILE': str(index)}):
            self.write('README.md', 'changed under inherited-index environment')
            self.commit()
            self.assertFalse(self.selected())
        self.assertEqual(index.read_bytes(), sentinel)
        self.assertIn('changed under', self.git('show', 'HEAD:README.md'))

    def test_known_docs_only_pr_skips_but_main_push_does_not(self):
        self.write('README.md', 'updated')
        self.commit()
        self.assertFalse(self.selected())
        self.assertTrue(self.selected('push'))

    def test_whole_pr_includes_source_before_last_docs_commit(self):
        self.write('der-verified/src/lib.rs', 'changed')
        self.commit()
        self.write('README.md', 'updated afterwards')
        self.commit()
        self.assertTrue(self.selected())

    def test_deleted_source_runs(self):
        (self.root / 'der-verified/src/lib.rs').unlink()
        self.commit()
        self.assertTrue(self.selected())

    def test_rename_source_into_docs_runs(self):
        self.git('mv', 'der-verified/src/lib.rs', 'TODO.md')
        self.commit()
        self.assertTrue(self.selected())

    def test_rename_docs_to_unknown_runs(self):
        self.git('mv', 'README.md', 'new-name.md')
        self.commit()
        self.assertTrue(self.selected())

    def test_known_document_deletion_skips(self):
        (self.root / 'README.md').unlink()
        self.commit()
        self.assertFalse(self.selected())

    def test_missing_nonancestor_or_malformed_base_runs(self):
        for base in ('0' * 40, '--help', None):
            with self.subTest(base=base):
                self.assertTrue(self.selected(event={'pull_request': {'base': {'sha': base}}}))
        self.git('checkout', '--orphan', 'unrelated')
        self.write('README.md', 'unrelated')
        self.commit()
        self.assertTrue(self.selected())

    def test_empty_diff_unknown_event_missing_event_and_git_error_run(self):
        self.assertTrue(self.selected())
        self.assertTrue(self.selected('workflow_dispatch'))
        self.assertTrue(self.selected(event={}))
        with patch('ci_changes.subprocess.check_output', side_effect=OSError('git missing')):
            self.assertTrue(self.selected())

    def workflow_guard(self, event_name='pull_request', base=None):
        workflow = (ci.ROOT / '.github/workflows/ci.yml').read_text()
        script = textwrap.dedent('          # Selection-policy' +
            workflow.split('          # Selection-policy', 1)[1].split('\n  test:', 1)[0])
        output = self.root / '.git/selection-output'
        output.write_text('')
        env = dict(self.env, GITHUB_EVENT_NAME=event_name, CI_BASE=self.base if base is None else base,
                   GITHUB_OUTPUT=str(output))
        result = subprocess.run(['bash', '-e', '-o', 'pipefail', '-c', script],
                                cwd=self.root, env=env, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output.read_text()

    def prepare_guard(self):
        # A deliberately permissive selector makes it observable whether the
        # independent workflow guard prevents edited policy from running.
        self.write('gates/ci_changes.py',
                   "import os\nfrom pathlib import Path\n"
                   "Path('.git/selector-ran').write_text('yes')\n"
                   "Path(os.environ['GITHUB_OUTPUT']).write_text('run_kani=false\\n')\n")
        self.write('.github/workflows/ci.yml', 'baseline workflow')
        self.base = self.commit()
        self.write('README.md', 'docs change')
        self.commit()

    def test_workflow_guard_blocks_edited_selector(self):
        self.prepare_guard()
        self.assertEqual(self.workflow_guard(), 'run_kani=false\n')
        marker = self.root / '.git/selector-ran'
        self.assertTrue(marker.exists())
        marker.unlink()
        with (self.root / 'gates/ci_changes.py').open('a') as stream:
            stream.write('# allowlist changed\n')
        self.commit()
        self.assertEqual(self.workflow_guard(), 'run_kani=true\n')
        self.assertFalse(marker.exists())

    def test_workflow_guard_blocks_changed_workflow_or_unknown_base(self):
        self.prepare_guard()
        for event, base in (('push', self.base), ('pull_request', '0' * 40),
                            ('pull_request', '--help')):
            self.assertEqual(self.workflow_guard(event, base), 'run_kani=true\n')
        self.write('.github/workflows/ci.yml', 'changed workflow')
        self.commit()
        self.assertEqual(self.workflow_guard(), 'run_kani=true\n')
        self.assertFalse((self.root / '.git/selector-ran').exists())

    def test_proof_build_requirements_and_unknown_paths_run(self):
        for path in ('der-verified/src/lib.rs', 'lean/README.md', 'lean/TagProofs.lean',
                     'Cargo.toml', 'Cargo.lock', 'der-verified/Cargo.toml',
                     'der-verified/build.rs', 'rust-toolchain.toml', '.cargo/config.toml',
                     '.github/workflows/ci.yml', 'gates/map_declared.txt', 'check.sh',
                     'docs/requirements/README.md', 'docs/proof-floor.json',
                     'der-verified/acceptance.toml', 'unknown.md', 'new\nfile.md'):
            with self.subTest(path=path):
                self.assertFalse(ci.documentation_only(['README.md', path]))
        self.assertTrue(ci.documentation_only(['docs/archive/old.md', 'TODO.md']))
        self.assertFalse(ci.documentation_only(['docs/archive/../requirements/spec.md']))


class AggregateResult(unittest.TestCase):
    def test_actual_workflow_aggregate_rejects_all_incomplete_results(self):
        workflow = (ci.ROOT / '.github/workflows/ci.yml').read_text()
        code = textwrap.dedent(workflow.split("python3 - <<'PYTHON'\n", 1)[1]
                               .split('          PYTHON', 1)[0])
        good = {name: {'result': 'success'} for name in ('changes', 'test', 'msrv', 'kani')}
        def run(results):
            env = dict(os.environ, JOB_RESULTS=json.dumps(results))
            env.pop("GITHUB_STEP_SUMMARY", None)
            return subprocess.run([sys.executable, '-c', code], env=env,
                                  capture_output=True, text=True).returncode
        self.assertEqual(run(good), 0)
        for name in good:
            for result in ('failure', 'cancelled', 'skipped'):
                with self.subTest(job=name, result=result):
                    self.assertNotEqual(run({**good, name: {'result': result}}), 0)
        self.assertNotEqual(run({}), 0)
        self.assertNotEqual(run({k: v for k, v in good.items() if k != 'kani'}), 0)

    def test_actual_workflow_summary_distinguishes_skipped_from_run(self):
        workflow = (ci.ROOT / '.github/workflows/ci.yml').read_text()
        code = textwrap.dedent(workflow.split("python3 - <<'PYTHON'\n", 1)[1]
                               .split('          PYTHON', 1)[0])
        good = {name: {'result': 'success'} for name in ('changes', 'test', 'msrv', 'kani')}
        with tempfile.TemporaryDirectory() as tmp:
            summary = Path(tmp) / 'summary'
            for selected, expected in (('false', 'Kani NOT RUN (docs-only PR)'),
                                       ('true', 'CI LIGHT-tier Kani completed')):
                summary.write_text('')
                env = dict(os.environ, JOB_RESULTS=json.dumps(good), RUN_KANI=selected,
                           GITHUB_STEP_SUMMARY=str(summary))
                result = subprocess.run([sys.executable, '-c', code], env=env,
                                        capture_output=True, text=True)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn(expected, result.stdout)
                self.assertIn(expected, summary.read_text())


if __name__ == '__main__':
    unittest.main()
