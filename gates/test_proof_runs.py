#!/usr/bin/env python3
"""Local evidence-policy tests. Tiny fixture check.sh emits test-only verdicts, never real proofs."""
import base64
import contextlib
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import proof_runs as runs

TOOLS = {key: {'fixture_identity': key} for key in runs.TOOL_KEYS}


class BytesOutput:
    buffer = io.BytesIO()


class Evidence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        home = Path(self.tmp.name) / 'home'
        cargo_home = Path(self.tmp.name) / 'cargo-home'
        home.mkdir()
        cargo_home.mkdir()
        self.environment = patch.dict(os.environ, {
            'PATH': os.environ.get('PATH', os.defpath), 'HOME': str(home),
            'CARGO_HOME': str(cargo_home), 'LANG': 'C.UTF-8',
        }, clear=True)
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.root = Path(self.tmp.name) / 'repo'
        self.root.mkdir()
        runs.git(self.root, 'init', '-q')
        runs.git(self.root, 'config', 'user.name', 'Proof policy fixture')
        runs.git(self.root, 'config', 'user.email', 'fixture@example.invalid')
        for name in ('proof_runs.py', 'ci_changes.py', 'gen_proof_manifest.py',
                     'check_tier_parity.py', 'check_lid_staleness.py', 'check_no_alloc.py',
                     'proof_run_common.py', 'proof_run_tools.py', 'proof_run_metadata.py'):
            self.write('gates/' + name, (runs.ROOT / 'gates' / name).read_text())
        self.write('.gitignore', '__pycache__/\nevidence/push-receipts/\n')
        self.write('README.md', 'fixture')
        self.write('PROOF_MANIFEST.md', 'Normative fixture text.\n' + ''.join(
            (runs.gpm.BEGIN % name) + '\nold projection\n' + (runs.gpm.END % name) + '\n'
            for name in runs.FLOOR_REGIONS) + 'Unrelated normative ending.\n')
        self.write('der-verified/src/leaf.rs', 'mod proofs {\n#[kani::proof]\nfn one() {}\n}\n')
        self.write('lean/check_lean.sh', 'check_drift Dummy "leaf.rs"\n')
        self.state = runs.digest((self.root / 'der-verified/src/leaf.rs').read_bytes()) + '  der-verified/src/leaf.rs\n'
        self.write(runs.STATE_PATH, self.state)
        self.log = ('\n'.join((runs.KANI_START, 'Checking harness leaf::proofs::one...',
                    'SUMMARY:', ' ** 0 of 4 failed', 'VERIFICATION:- SUCCESSFUL',
                    runs.KANI_END, 'lean-lid-status: PASS', runs.FULL_PASS)) + '\n')
        self.write('check.sh', '#!/bin/sh\ncat <<\'FIXTURE\'\n' + self.log + 'FIXTURE\n')
        self.source = self.commit()

    def write(self, path, data):
        p = self.root / path
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(data)

    def commit(self):
        runs.git(self.root, 'add', '-A')
        runs.git(self.root, 'commit', '-qm', 'test fixture')
        return runs.git(self.root, 'rev-parse', 'HEAD').decode().strip()

    def record(self):
        with patch('proof_runs.observe_tools', return_value=TOOLS), patch('proof_runs.sys.stdout', BytesOutput()):
            return runs.record(self.root)

    def verify(self, target=None):
        return runs.verify(self.root, target or self.source, 'refs/heads/main')

    def test_actual_capture_then_docs_carry_over_has_distinct_identity(self):
        captured = self.record()
        self.assertEqual(self.verify()['mode'], 'fresh')
        self.write('README.md', 'docs only')
        target = self.commit()
        verdict = self.verify(target)
        self.assertEqual(verdict['mode'], 'carry-over')
        self.assertEqual(verdict['run_commit'], self.source)
        self.assertEqual(verdict['target_commit'], target)
        self.assertEqual(verdict['receipt_sha256'], captured['receipt_sha256'])
        self.assertEqual(runs.git(self.root, 'status', '--porcelain'), b'')

    def test_recorded_source_refs_survive_rewrite_and_gc(self):
        old = self.record()
        self.write('README.md', 'amended source')
        runs.git(self.root, 'add', '-A')
        runs.git(self.root, 'commit', '--amend', '-qm', 'replacement source')
        self.source = runs.git(self.root, 'rev-parse', 'HEAD').decode().strip()
        current = self.record()
        runs.git(self.root, 'reflog', 'expire', '--expire=now', '--all')
        runs.git(self.root, 'gc', '--prune=now')
        self.assertEqual(self.verify()['run_id'], current['run_id'])
        self.assertEqual(runs.git(self.root, 'rev-parse', '--verify',
                         'refs/der-proof-runs/' + old['run_id'] + '^{commit}').decode().strip(),
                         old['run_commit'])

    def test_deleted_old_source_ref_and_pruned_commit_refuses_clearly(self):
        old = self.record()
        self.write('README.md', 'amended source')
        runs.git(self.root, 'add', '-A')
        runs.git(self.root, 'commit', '--amend', '-qm', 'replacement source')
        self.source = runs.git(self.root, 'rev-parse', 'HEAD').decode().strip()
        self.record()
        runs.git(self.root, 'update-ref', '-d', 'refs/der-proof-runs/' + old['run_id'])
        runs.git(self.root, 'reflog', 'expire', '--expire=now', '--all')
        runs.git(self.root, 'gc', '--prune=now')
        with self.assertRaisesRegex(runs.ProofRunError, 'recorded source ref is missing or its commit was pruned'):
            self.verify()

    def test_capture_checkout_is_under_git_common_dir_and_cleaned(self):
        actual = runs.tempfile.TemporaryDirectory
        calls = []
        def temporary(*args, **kwargs):
            calls.append(kwargs.copy())
            return actual(*args, **kwargs)
        with patch('proof_runs.tempfile.TemporaryDirectory', side_effect=temporary):
            self.record()
        self.assertEqual(len(calls), 1)
        self.assertEqual(Path(calls[0]['dir']).resolve(), runs.common_dir(self.root))
        self.assertFalse(any(runs.common_dir(self.root).glob('der-proof-checkout-*')))

    def test_unknown_caller_environment_never_reaches_fixed_runner(self):
        self.write('check.sh', '#!/bin/sh\n'
            '[ "${UNREVIEWED_CAPTURE_INPUT+x}" != x ] || exit 91\n'
            '[ "${CARGO_PROFILE_DEV_DEBUG_ASSERTIONS+x}" != x ] || exit 92\n'
            '[ "${RUSTC_BOOTSTRAP+x}" != x ] || exit 93\n'
            "cat <<'FIXTURE'\n" + self.log + 'FIXTURE\n')
        self.source = self.commit()
        with patch.dict(os.environ, {'UNREVIEWED_CAPTURE_INPUT': 'SECRET-SENTINEL',
                    'CARGO_PROFILE_DEV_DEBUG_ASSERTIONS': 'false', 'RUSTC_BOOTSTRAP': '1'}):
            captured = self.record()
        receipt = runs._json(runs.store_root(self.root) / (captured['run_id'] + '.json'))
        self.assertEqual(receipt['environment_policy'], 'supported-pinned-environment/2')
        self.assertIn('PATH', receipt['environment'])
        self.assertIn('DER_REQUIRE_LEAN', receipt['environment'])
        self.assertNotIn('SECRET-SENTINEL', json.dumps(receipt))
        self.assertNotIn('CARGO_PROFILE_DEV_DEBUG_ASSERTIONS', receipt['environment'])

    def test_captured_projection_survives_ref_and_renderer_changes(self):
        self.record()
        self.write('README.md', 'later docs')
        target = self.commit()
        runs.git(self.root, 'update-ref', 'refs/remotes/origin/main', target)
        with patch.object(runs.gpm, 'anchor_commit', side_effect=AssertionError('live anchor consulted')), \
             patch('proof_runs.projected_manifest', side_effect=AssertionError('current renderer consulted')), \
             patch('proof_runs.floor_output', side_effect=AssertionError('current floor renderer consulted')):
            self.assertEqual(self.verify(target)['mode'], 'carry-over')
        floor = json.loads(base64.b64decode(self.record()['generated_outputs'][runs.FLOOR_PATH]['content_base64']))
        with patch.object(runs.gpm, 'anchor_commit', side_effect=AssertionError('live anchor consulted')):
            runs.projected_manifest((self.root / runs.PROJECTION_PATH).read_bytes(), floor)

    def test_protected_paths_win_even_if_prose_policy_broadens(self):
        self.record()
        for path in ('lean/README.md', 'docs/requirements/README.md', 'gates/README.md'):
            runs.git(self.root, 'reset', '--hard', self.source)
            self.write(path, 'would look like prose')
            target = self.commit()
            with patch.object(runs.ci_changes, 'documentation_only', return_value=True):
                with self.assertRaises(runs.ProofRunError):
                    self.verify(target)

    def test_dirty_caller_and_inherited_index_cannot_enter_isolated_capture(self):
        self.write('README.md', 'caller uncommitted work')
        sentinel = Path(self.tmp.name) / 'caller-index'
        sentinel.write_bytes(b'caller index must not be touched')
        with patch.dict(os.environ, {'GIT_INDEX_FILE': str(sentinel)}):
            self.record()
        self.assertEqual(sentinel.read_bytes(), b'caller index must not be touched')
        self.assertEqual((self.root / 'README.md').read_text(), 'caller uncommitted work')
        self.assertEqual(self.verify()['mode'], 'fresh')

    def test_code_harness_config_policy_and_unknown_changes_refuse(self):
        self.record()
        for path in ('der-verified/src/leaf.rs', 'lean/Proof.lean', 'Cargo.toml', 'Cargo.lock',
                     'rust-toolchain.toml', '.cargo/config.toml', '.github/workflows/ci.yml',
                     'gates/pre-push', 'check.sh', 'docs/requirements/spec.toml', 'docs/proof-floor.json',
                     'unknown.txt'):
            with self.subTest(path=path):
                runs.git(self.root, 'reset', '--hard', self.source)
                self.write(path, 'changed')
                target = self.commit()
                with self.assertRaises(runs.ProofRunError):
                    self.verify(target)

    def test_deleted_and_renamed_source_refuse(self):
        self.record()
        source = self.root / 'der-verified/src/leaf.rs'
        source.rename(self.root / 'TODO.md')
        target = self.commit()
        with self.assertRaises(runs.ProofRunError):
            self.verify(target)

    def test_release_paths_need_explicit_validation_and_cannot_exempt_code(self):
        self.record()
        self.write('der-verified/acceptance.toml', 'candidate bundle')
        target = self.commit()
        with self.assertRaises(runs.ProofRunError):
            self.verify(target)
        compared = runs.verify_source_inputs(self.root, self.source, target,
                                             allowed_artifacts={'der-verified/acceptance.toml'})
        self.assertEqual(compared['artifact_paths'], ['der-verified/acceptance.toml'])
        self.write('der-verified/src/leaf.rs', 'changed source')
        target = self.commit()
        with self.assertRaises(runs.ProofRunError):
            runs.verify_source_inputs(self.root, self.source, target,
                allowed_artifacts={'der-verified/acceptance.toml', 'der-verified/src/leaf.rs'})

    def test_old_text_receipt_and_transcription_do_not_register_trust(self):
        self.write('evidence/push-receipts/' + self.source + '.receipt',
                   'full-suite: GREEN @ ' + self.source)
        self.write('docs/proof-floor.json', json.dumps({'commit': self.source, 'check_exit': 0}))
        with self.assertRaises(runs.ProofRunError):
            self.verify()
        self.assertFalse(runs.store_root(self.root).exists())

    def test_missing_history_unrelated_ancestor_and_release_ref_refuse(self):
        self.record()
        with self.assertRaises(runs.ProofRunError):
            self.verify('0' * 40)
        runs.git(self.root, 'checkout', '--orphan', 'unrelated')
        self.write('README.md', 'different history')
        unrelated = self.commit()
        with self.assertRaises(runs.ProofRunError):
            self.verify(unrelated)
        with self.assertRaises((runs.ProofRunError, ValueError)):
            runs.verify(self.root, self.source, 'refs/tags/v1.0.0')

    def test_tampered_log_or_receipt_or_foreign_store_refuses(self):
        result = self.record()
        store = runs.store_root(self.root)
        log = store / (result['run_id'] + '.log')
        old = log.read_bytes()
        log.write_bytes(old + b'tampered\n')
        with self.assertRaises(runs.ProofRunError): self.verify()
        log.write_bytes(old)
        receipt = store / (result['run_id'] + '.json')
        receipt.write_bytes(receipt.read_bytes() + b' ')
        with self.assertRaises(runs.ProofRunError): self.verify()
        other = Path(self.tmp.name) / 'other'
        other.mkdir()
        runs.git(other, 'init', '-q')
        shutil.copytree(store, runs.store_root(other))
        with self.assertRaises(runs.ProofRunError): runs.trusted_runs(other)

    def test_unregistered_receipt_is_not_discovered(self):
        result = self.record()
        runs._write(runs.store_root(self.root) / 'index.json', b'{}\n')
        with self.assertRaises(runs.ProofRunError): self.verify()

    def test_failure_missing_harness_skipped_lean_and_tool_mismatch_do_not_register(self):
        for log, code in ((self.log, 1),
                          (self.log.replace('VERIFICATION:- SUCCESSFUL', 'VERIFICATION:- FAILED'), 0),
                          (self.log.replace('leaf::proofs::one', 'leaf::proofs::other'), 0),
                          (self.log.replace('lean-lid-status: PASS', 'lean-lid-status: SKIP'), 0)):
            with self.subTest(code=code, log=log[:50]):
                self.write('check.sh', "cat <<'FIXTURE'\n" + log + 'FIXTURE\nexit ' + str(code) + '\n')
                self.source = self.commit()
                with self.assertRaises(runs.ProofRunError): self.record()
                self.assertFalse((runs.store_root(self.root) / 'index.json').exists())
        self.write('check.sh', "cat <<'FIXTURE'\n" + self.log + 'FIXTURE\n')
        self.source = self.commit()
        with patch('proof_runs.observe_tools', side_effect=[TOOLS, {**TOOLS, 'rustc': {'changed': True}}]), patch('proof_runs.sys.stdout', BytesOutput()):
            with self.assertRaises(runs.ProofRunError): runs.record(self.root)
        with patch('proof_runs.observe_tools', side_effect=runs.ProofRunError('version unavailable')):
            with self.assertRaises(runs.ProofRunError): runs.record(self.root)
        self.assertFalse((runs.store_root(self.root) / 'index.json').exists())

    def test_only_exact_generated_state_can_travel_to_later_commit(self):
        self.write(runs.STATE_PATH, 'PENDING ' + self.state)
        script = ("#!/bin/sh\nprintf '%s\\n' '" + self.state.strip() + "' > " + runs.STATE_PATH +
                  "\npython3 gates/proof_runs.py stage-state --lean-status PASS\n" +
                  "cat <<'FIXTURE'\n" + self.log + 'FIXTURE\n')
        self.write('check.sh', script)
        self.source = self.commit()
        index_before = (self.root / '.git/index').read_bytes()
        result = self.record()
        self.assertEqual((self.root / '.git/index').read_bytes(), index_before)
        data = base64.b64decode(result['generated_outputs'][runs.STATE_PATH]['content_base64'])
        self.assertEqual(data.decode(), self.state)
        self.write(runs.STATE_PATH, data.decode())
        target = self.commit()
        self.assertEqual(self.verify(target)['mode'], 'carry-over')
        self.write(runs.STATE_PATH, '# invented metadata\n' + self.state)
        target = self.commit()
        with self.assertRaises(runs.ProofRunError): self.verify(target)

    def test_staging_requires_live_isolated_context_and_lean_pass(self):
        with patch.dict(os.environ, {'DER_PROOF_CAPTURE_CONTEXT': ''}):
            with self.assertRaises(runs.ProofRunError): runs.stage_state(self.root, 'PASS')
        self.record()
        store, _ = runs._store(self.root)
        context = store / ('capture-' + '0' * 32 + '.json')
        runs._write(context, runs.canonical({'root': str(self.root), 'source': self.source,
                   'git_dir': str(self.root / '.git')}))
        for status in ('FAIL', 'SKIP', 'PASS'):
            with patch.dict(os.environ, {'DER_PROOF_CAPTURE_CONTEXT': str(context)}):
                with self.assertRaises(runs.ProofRunError): runs.stage_state(self.root, status)
        self.write(runs.STATE_PATH, '0' * 64 + '  der-verified/src/leaf.rs\n')
        with self.assertRaises(runs.ProofRunError): runs.validated_state(self.root)
        self.write(runs.STATE_PATH, self.state + '0' * 64 + '  der-verified/src/extra.rs\n')
        with self.assertRaises(runs.ProofRunError): runs.validated_state(self.root)

    def test_exact_floor_projection_and_valid_cache_need_no_second_run(self):
        captured = self.record()
        for name, output in captured['generated_outputs'].items():
            self.write(name, base64.b64decode(output['content_base64']).decode())
        target = self.commit()
        self.assertEqual(self.verify(target)['mode'], 'carry-over')
        floor = json.loads((self.root / runs.FLOOR_PATH).read_text())
        self.assertEqual(floor['commit'], self.source)
        self.assertEqual(floor['successful'], 1)
        self.assertEqual(floor['memory_cap'], 'not measured by recorder')
        # Public snapshot applicability is useful without this machine's local trust.
        shutil.rmtree(runs.store_root(self.root))
        runs.verify_applicability_inputs(self.root, self.source, target)
        with self.assertRaises(runs.ProofRunError): self.verify(target)
        self.write('PROOF_MANIFEST.md', (self.root / 'PROOF_MANIFEST.md').read_text().replace(
            'Normative fixture text.', 'Different normative claim.'))
        bad = self.commit()
        with self.assertRaises(runs.ProofRunError):
            runs.verify_applicability_inputs(self.root, self.source, bad)

    def test_unrelated_projection_and_cache_edits_refuse(self):
        self.record()
        self.write('PROOF_MANIFEST.md', (self.root / 'PROOF_MANIFEST.md').read_text() +
                   '<!-- BEGIN GENERATED:bounds -->changed<!-- END GENERATED:bounds -->')
        target = self.commit()
        with self.assertRaises(runs.ProofRunError): self.verify(target)
        runs.git(self.root, 'reset', '--hard', self.source)
        self.write(runs.STATE_PATH, '0' * 64 + '  der-verified/src/leaf.rs\n')
        target = self.commit()
        with self.assertRaises(runs.ProofRunError):
            runs.verify_applicability_inputs(self.root, self.source, target)

    def test_floor_change_without_manifest_projection_refuses(self):
        captured = self.record()
        floor = base64.b64decode(captured['generated_outputs'][runs.FLOOR_PATH]['content_base64']).decode()
        self.write(runs.FLOOR_PATH, floor)
        target = self.commit()
        with self.assertRaises(runs.ProofRunError):
            self.verify(target)

    def test_currency_helper_allows_only_a_valid_state_cache(self):
        self.write(runs.STATE_PATH, 'PENDING ' + self.state)
        self.source = self.commit()
        self.write(runs.STATE_PATH, self.state)
        with patch.object(runs.gpm, 'ROOT', str(self.root)), patch.dict(os.environ, runs.git_env(), clear=True):
            self.assertTrue(runs.gpm.verified_source_unchanged_since(self.source))
            self.write(runs.STATE_PATH, '0' * 64 + '  der-verified/src/leaf.rs\n')
            self.assertFalse(runs.gpm.verified_source_unchanged_since(self.source))
            self.write(runs.STATE_PATH, self.state)
            self.write('der-verified/src/leaf.rs', 'changed source')
            self.assertFalse(runs.gpm.verified_source_unchanged_since(self.source))

    def test_cover_summaries_are_required_and_counted_from_log(self):
        with self.assertRaises(runs.ProofRunError):
            runs.validate_log(self.log.encode(), ['leaf::proofs::one'], ['leaf::proofs::one'])
        log = self.log.replace('VERIFICATION:- SUCCESSFUL',
                ' ** 1 of 3 cover properties satisfied\nVERIFICATION:- SUCCESSFUL')
        counts = runs.validate_log(log.encode(), ['leaf::proofs::one'], ['leaf::proofs::one'])
        self.assertEqual(counts['covers_unsatisfied'], 2)
        with self.assertRaises(runs.ProofRunError):
            runs.validate_log(log.replace('1 of 3', '4 of 3').encode(), ['leaf::proofs::one'])

    def test_registration_requires_exact_disclosed_vacuity_set(self):
        source = ('mod proofs {\n'
                  '    #[kani::proof]\n    fn one() { kani::cover!(true); }\n'
                  '    #[kani::proof]\n    fn witness() { kani::cover!(true); }\n}\n')
        log = ('\n'.join((runs.KANI_START, 'Checking harness leaf::proofs::one...',
               ' ** 0 of 1 cover properties satisfied', 'VERIFICATION:- SUCCESSFUL',
               'Checking harness leaf::proofs::witness...',
               ' ** 1 of 1 cover property satisfied', 'VERIFICATION:- SUCCESSFUL',
               runs.KANI_END, 'lean-lid-status: PASS', runs.FULL_PASS)) + '\n')
        self.write('der-verified/src/leaf.rs', source)
        self.write('check.sh', "cat <<'FIXTURE'\n" + log + 'FIXTURE\n')
        self.state = runs.digest((self.root / 'der-verified/src/leaf.rs').read_bytes()) + '  der-verified/src/leaf.rs\n'
        self.write(runs.STATE_PATH, self.state)
        self.source = self.commit()
        with self.assertRaisesRegex(runs.ProofRunError, 'newly unsatisfied'):
            self.record()
        disclosed = source.replace('mod proofs {',
            'mod proofs {\n    // VACUITY-DISCLOSED: one -> witness witness')
        self.write('der-verified/src/leaf.rs', disclosed)
        self.state = runs.digest((self.root / 'der-verified/src/leaf.rs').read_bytes()) + '  der-verified/src/leaf.rs\n'
        self.write(runs.STATE_PATH, self.state)
        self.source = self.commit()
        self.assertEqual(self.record()['run_commit'], self.source)
        self.write('check.sh', "cat <<'FIXTURE'\n" +
                   log.replace('0 of 1 cover properties', '1 of 1 cover property') + 'FIXTURE\n')
        self.source = self.commit()
        with self.assertRaisesRegex(runs.ProofRunError, 'disclosed but now satisfied'):
            self.record()

    def test_compilation_input_escape_and_dependencies_refuse(self):
        self.write('der-verified/src/leaf.rs',
                   '// fs env process include_str!("example")\nmod proofs {\n#[kani::proof]\nfn one() {}\n}\n')
        self.source = self.commit()
        runs.supported_input_model(self.root, self.source)
        for extra in ('const X: &str = include_str!("../../../ignored");',
                      '#[path="../../../outside.rs"] mod outside;',
                      '#[cfg_attr(unix, path = "../../../outside.rs")] mod outside;',
                      '#[cfg_attr(\n    unix,\n    path = "../../../outside.rs"\n)]\nmod outside;',
                      '#  [ cfg_attr (\r\n unix ,\n\tpath\n= "o.rs" ) ]\nmod o;',
                      '#[cfg_attr(/* c */ unix, // x\n  /* y */ path /* z */ = "o.rs")]\nmod o;',
                      '#[cfg_attr(unix, allow(dead_code),\n  path = "o.rs")]\nmod o;', 'use std::fs;',
                      'fn read() { std::env::var("SECRET"); }'):
            self.write('der-verified/src/leaf.rs', extra)
            target = self.commit()
            with self.assertRaises(runs.ProofRunError): runs.supported_input_model(self.root, target)
        runs.git(self.root, 'reset', '--hard', self.source)
        # Control: a multi-line cfg_attr without a path argument is not an input escape.
        self.write('der-verified/src/leaf.rs', '#[cfg_attr(\n    unix,\n    derive(Debug)\n)]\nstruct S { path: u8 }\n')
        runs.supported_input_model(self.root, self.commit())
        runs.git(self.root, 'reset', '--hard', self.source)
        self.write('der-verified/Cargo.toml', '[dependencies]\nother="1"\n')
        target = self.commit()
        with self.assertRaises(runs.ProofRunError): runs.supported_input_model(self.root, target)

    def test_git_replacements_cannot_relabel_captured_source_and_grafts_refuse(self):
        original = self.source
        self.write('README.md', 'replacement tree')
        replacement = self.commit()
        runs.git(self.root, 'replace', original, replacement)
        runs.git(self.root, 'checkout', '--detach', original)
        self.assertEqual(runs.git(self.root, 'show', original + ':README.md'), b'fixture')
        captured = self.record()
        self.assertEqual(captured['run_commit'], original)
        self.assertEqual(self.verify()['mode'], 'fresh')
        grafts = self.root / '.git/info/grafts'
        grafts.write_text(original + '\n')
        with self.assertRaises(runs.ProofRunError): self.verify()

    def test_checkout_filters_and_normalized_bytes_refuse(self):
        runs.git(self.root, 'config', 'filter.example.smudge', 'cat')
        with self.assertRaises(runs.ProofRunError): self.record()
        runs.git(self.root, 'config', '--unset', 'filter.example.smudge')
        (self.root / 'README.md').write_bytes(b'fixture\r\n')
        with self.assertRaises(runs.ProofRunError): runs.checkout_bytes_match(self.root, self.source)

    def test_dirty_imported_policy_cannot_authorize_capture(self):
        other = Path(self.tmp.name) / 'ci_changes.py'
        other.write_text('changed helper policy')
        with patch.object(runs.ci_changes, '__file__', str(other)):
            with self.assertRaises(runs.ProofRunError): self.record()

    def prepare_hook(self):
        self.write('gates/pre-push', (runs.ROOT / 'gates/pre-push').read_text())
        self.write('gates/release_evidence.py', (runs.ROOT / 'gates/release_evidence.py').read_text())
        self.write('gates/check_links.py', 'pass\n')
        self.write('gates/gen_verification_map.py', 'pass\n')
        # Fixture-only cheap document gate; importing it must not exit the verifier.
        self.source = self.commit()
        fakebin = Path(self.tmp.name) / 'bin'
        fakebin.mkdir()
        gh = fakebin / 'gh'
        gh.write_text('#!/bin/sh\nprintf PUBLIC\n')
        gh.chmod(0o755)
        python = fakebin / 'python3'
        python.write_text('#!/bin/sh\ncase "$*" in\n'
            '  "gates/gen_proof_manifest.py --check") exit 0 ;;\n'
            'esac\nexec "' + __import__('sys').executable + '" "$@"\n')
        python.chmod(0o755)
        self.hookenv = dict(runs.git_env(), PATH=str(fakebin) + os.pathsep + os.environ['PATH'])
        self.hookenv.pop('FV_PUSH_GATE_OVERRIDE', None)

    def hook(self, pairs, url='https://github.com/ivmat/rs-verified-der.git'):
        payload = ''.join('HEAD ' + sha + ' ' + ref + ' ' + '0' * 40 + '\n' for sha, ref in pairs)
        return subprocess.run(['bash', 'gates/pre-push', 'origin', url], cwd=self.root,
                              env=self.hookenv, input=payload, text=True, capture_output=True)

    def receipt(self, sha, line=None, age=1):
        path = self.root / 'evidence/push-receipts' / (sha + '.receipt')
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text((line or ('full-suite: GREEN @ ' + sha)) + '\n')
        committed = int(runs.git(self.root, 'show', '-s', '--format=%ct', sha + '^{commit}').decode())
        os.utime(path, (committed + age, committed + age))
        return path

    def test_hook_exact_destinations_and_spoof_hosts(self):
        self.prepare_hook()
        for url in ('https://github.com/ivmat/rs-verified-der.git',
                    'git@github.com:ivmat/rs-verified-der.git',
                    'ssh://git@github.com/ivmat/rs-verified-der.git'):
            self.assertEqual(self.hook([], url).returncode, 0, url)
        for url in ('https://github.com.evil.example/ivmat/rs-verified-der.git',
                    'https://evilgithub.com/ivmat/rs-verified-der.git',
                    'https://github.com@evil.example/ivmat/rs-verified-der.git',
                    'https://github.com/other/repo.git'):
            self.assertNotEqual(self.hook([], url).returncode, 0, url)

    def set_visibility(self, value):
        gh = Path(self.tmp.name) / 'bin' / 'gh'
        gh.write_text('#!/bin/sh\nprintf ' + value + '\n')

    def test_hook_no_payload_needs_no_evidence_but_deletions_only_gate_head(self):
        self.prepare_hook()
        # Up-to-date no-op push: no ref lines at all.
        self.assertEqual(self.hook([]).returncode, 0)
        self.assertFalse(runs.store_root(self.root).exists())
        # A deletions-only push still has ref lines: as at HEAD of the hook, HEAD is gated.
        deleted = self.hook([('0' * 40, 'refs/tags/v1.0.0')])
        self.assertNotEqual(deleted.returncode, 0, deleted.stdout + deleted.stderr)
        self.assertIn('no full-suite receipt', deleted.stdout)
        self.assertIn(self.source, deleted.stdout)
        # With HEAD evidence in place the same deletions-only push clears.
        self.record()
        self.receipt(self.source)
        cleared = self.hook([('0' * 40, 'refs/tags/v1.0.0')])
        self.assertEqual(cleared.returncode, 0, cleared.stdout + cleared.stderr)

    def test_hook_never_pushes_local_proof_run_refs_to_any_destination(self):
        self.prepare_hook()
        self.record()
        self.receipt(self.source)
        ref = 'refs/der-proof-runs/' + '0' * 32
        for visibility in ('PUBLIC', 'PRIVATE'):
            self.set_visibility(visibility)
            for pairs in ([(self.source, ref)], [('0' * 40, ref)],
                          [(self.source, 'refs/heads/main'), (self.source, ref)]):
                for override in (False, True):
                    self.hookenv['FV_PUSH_GATE_OVERRIDE'] = '1' if override else '0'
                    result = self.hook(pairs)
                    self.assertNotEqual(result.returncode, 0, (visibility, pairs, override, result.stdout))
                    self.assertIn('refs/der-proof-runs/* is local-only', result.stdout)
        # Not-allowed destinations: rule 1 is override-clearable, the proof-ref refusal is not.
        log = self.root / 'evidence/push-receipts/overrides.log'
        before = log.read_text() if log.exists() else ''
        self.hookenv['FV_PUSH_GATE_OVERRIDE'] = '1'
        for url in ('/var/tmp/elsewhere.git', 'https://github.com/ivmat/other.git'):
            for pairs in ([(self.source, ref)], [('0' * 40, ref)],
                          [(self.source, 'refs/heads/main'), (self.source, ref)]):
                result = self.hook(pairs, url=url)
                self.assertNotEqual(result.returncode, 0, (url, pairs, result.stdout))
                self.assertIn('refs/der-proof-runs/* is local-only', result.stdout)
                self.assertNotIn('OVERRIDE USED', result.stdout)
        self.assertEqual(log.read_text() if log.exists() else '', before)
        self.hookenv.pop('FV_PUSH_GATE_OVERRIDE')
        self.assertEqual(self.hook([(self.source, 'refs/heads/main')]).returncode, 0)

    def test_hook_summary_says_what_ran_for_private_destination(self):
        self.prepare_hook()
        self.set_visibility('PRIVATE')
        private = self.hook([(self.source, 'refs/heads/main')])
        self.assertEqual(private.returncode, 0, private.stdout + private.stderr)
        self.assertNotIn('evidence gates green', private.stdout)
        self.assertIn('did NOT run', private.stdout)
        self.assertIn('document gates green', private.stdout)

    def test_hook_receipt_staleness_peels_annotated_tag_and_rejects_non_numeric_time(self):
        self.prepare_hook()
        runs.git(self.root, 'tag', '-a', 'v1.0.0', '-m', 'annotated test', self.source)
        tag_object = runs.git(self.root, 'rev-parse', 'refs/tags/v1.0.0').decode().strip()
        self.assertNotEqual(tag_object, self.source)
        self.receipt(tag_object, age=-1)
        stale = self.hook([(tag_object, 'refs/tags/v1.0.0')])
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn('receipt is OLDER than the commit', stale.stdout)
        self.assertNotIn('integer expression expected', stale.stderr)
        # A fresh receipt for the tag object is not falsely called stale (rule 4 may still refuse).
        self.receipt(tag_object, age=1)
        fresh = self.hook([(tag_object, 'refs/tags/v1.0.0')])
        self.assertNotIn('OLDER', fresh.stdout)
        self.assertNotIn('timestamps', fresh.stdout)
        # A timestamp that is not a plain integer refuses instead of passing silently.
        shim = Path(self.tmp.name) / 'statbin'
        shim.mkdir()
        (shim / 'stat').write_text('#!/bin/sh\nprintf "not-a-number\\n"\n')
        (shim / 'stat').chmod(0o755)
        self.hookenv['PATH'] = str(shim) + os.pathsep + self.hookenv['PATH']
        self.receipt(self.source)
        garbage = self.hook([(self.source, 'refs/heads/main')])
        self.assertNotEqual(garbage.returncode, 0)
        self.assertIn('could not read numeric commit/receipt timestamps', garbage.stdout)

    def test_hook_branch_carryover_and_remote_tag_promotion_are_distinct(self):
        self.prepare_hook()
        self.record()
        self.write('README.md', 'only docs')
        target = self.commit()
        self.receipt(target)
        branch = self.hook([(target, 'refs/heads/main')])
        self.assertEqual(branch.returncode, 0, branch.stdout + branch.stderr)
        self.assertIn('carry-over', branch.stdout)
        mixed = self.hook([(target, 'refs/heads/main'), (target, 'refs/tags/v1.0.0')])
        self.assertNotEqual(mixed.returncode, 0)
        self.assertIn('refs/tags/v1.0.0', mixed.stdout)
        self.assertIn('release validation required', mixed.stderr)
        runs.git(self.root, 'tag', '-a', 'v1.0.0', '-m', 'annotated test', target)
        tag_object = runs.git(self.root, 'rev-parse', 'refs/tags/v1.0.0').decode().strip()
        self.assertNotEqual(tag_object, target)
        promoted = self.hook([(tag_object, 'refs/tags/v1.0.0')])
        self.assertNotEqual(promoted.returncode, 0)
        self.assertIn('release validation required', promoted.stderr)

    def test_hook_requires_exact_fresh_receipt_and_valid_proof_evidence(self):
        self.prepare_hook()
        self.record()
        missing = self.hook([(self.source, 'refs/heads/main')])
        self.assertNotEqual(missing.returncode, 0)
        self.assertIn('no full-suite receipt', missing.stdout)
        self.receipt(self.source, 'full-suite: GREEN @ ' + '0' * 40)
        wrong = self.hook([(self.source, 'refs/heads/main')])
        self.assertNotEqual(wrong.returncode, 0)
        self.assertIn("does not contain the line 'full-suite: GREEN @", wrong.stdout)
        self.receipt(self.source, age=-1)
        stale = self.hook([(self.source, 'refs/heads/main')])
        self.assertNotEqual(stale.returncode, 0)
        self.assertIn('receipt is OLDER than the commit', stale.stdout)
        self.receipt(self.source)
        accepted = self.hook([(self.source, 'refs/heads/main')])
        self.assertEqual(accepted.returncode, 0, accepted.stdout + accepted.stderr)
        self.assertIn('trusted evidence gates green', accepted.stdout)

    def test_hook_uses_verifier_from_pushed_commit(self):
        self.prepare_hook()
        self.receipt(self.source)
        self.write('gates/proof_runs.py', '#!/usr/bin/env python3\nraise SystemExit(0)\n')
        result = self.hook([(self.source, 'refs/heads/main')])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('trusted proof/release evidence FAILED', result.stdout)

    def test_pinned_but_incomplete_receipt_is_rejected(self):
        captured = self.record()
        store = runs.store_root(self.root)
        path = store / (captured['run_id'] + '.json')
        receipt = json.loads(path.read_text())
        receipt.pop('tools')
        data = runs.canonical(receipt)
        runs._write(path, data)
        runs._write(store / 'index.json', runs.canonical({captured['run_id']: runs.digest(data)}))
        with self.assertRaises(runs.ProofRunError): self.verify()

    def test_corrupt_store_refuses_before_starting_another_run(self):
        captured = self.record()
        log = runs.store_root(self.root) / (captured['run_id'] + '.log')
        log.write_bytes(log.read_bytes() + b'corrupt')
        with patch('proof_runs.observe_tools') as tools:
            with self.assertRaises(runs.ProofRunError): runs.record(self.root)
            tools.assert_not_called()

    def check_sh_launches(self):
        """Patch Popen so that launches of the fixed full check can be counted (git still runs)."""
        actual, launches = subprocess.Popen, []
        def spy(args, *a, **kw):
            if list(args) == ['sh', 'check.sh']:
                launches.append(args)
            return actual(args, *a, **kw)
        return patch('proof_runs.subprocess.Popen', side_effect=spy), launches

    def corrupt_log(self, captured):
        log = runs.store_root(self.root) / (captured['run_id'] + '.log')
        log.write_bytes(log.read_bytes() + b'corrupt')

    def test_retire_unblocks_a_store_with_one_broken_entry_and_is_logged(self):
        broken = self.record()
        self.corrupt_log(broken)
        with self.assertRaises(runs.ProofRunError): self.record()
        with self.assertRaises(runs.ProofRunError): self.verify()
        result = runs.retire(self.root, broken['run_id'], 'log corrupted on disk')
        self.assertEqual(result['retired'], broken['run_id'])
        store = runs.store_root(self.root)
        self.assertTrue((store / 'quarantine' / (broken['run_id'] + '.json')).is_file())
        self.assertTrue((store / 'quarantine' / (broken['run_id'] + '.log')).is_file())
        self.assertFalse((store / (broken['run_id'] + '.json')).exists())
        line = (store / 'quarantine' / 'retired.log').read_text().splitlines()
        self.assertEqual(len(line), 1)
        stamp, run_id, reason = line[0].split('\t')
        self.assertEqual((run_id, reason), (broken['run_id'], 'log corrupted on disk'))
        self.assertRegex(stamp, r'^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d')
        fresh = self.record()
        self.assertNotEqual(fresh['run_id'], broken['run_id'])
        self.assertEqual(self.verify()['run_id'], fresh['run_id'])

    def test_retired_run_is_never_accepted_as_evidence(self):
        retired = self.record()
        runs.retire(self.root, retired['run_id'], 'superseded by policy change')
        with self.assertRaises(runs.ProofRunError): self.verify()
        with self.assertRaises(runs.ProofRunError):
            runs.verify_trusted_run(self.root, self.source, receipt_sha256=retired['receipt_sha256'])
        # Putting the entry back into the active index (even with its files) is refused.
        store = runs.store_root(self.root)
        for suffix in ('.json', '.log'):
            os.replace(store / 'quarantine' / (retired['run_id'] + suffix), store / (retired['run_id'] + suffix))
        runs._write(store / 'index.json', runs.canonical({retired['run_id']: retired['receipt_sha256']}))
        with self.assertRaisesRegex(runs.ProofRunError, 'retired'): self.verify()
        # A second, healthy run stays usable next to the retired record.
        os.unlink(store / 'index.json')
        for suffix in ('.json', '.log'):
            os.replace(store / (retired['run_id'] + suffix), store / 'quarantine' / (retired['run_id'] + suffix))
        healthy = self.record()
        self.assertEqual(self.verify()['run_id'], healthy['run_id'])

    def test_retire_refuses_unknown_invalid_and_reasonless_requests(self):
        captured = self.record()
        before = (runs.store_root(self.root) / 'index.json').read_bytes()
        for run_id, reason in (('0' * 32, 'x'), ('../../etc', 'x'), ('NOT-HEX', 'x'),
                               (captured['run_id'], ''), (captured['run_id'], 'two\nlines')):
            with self.assertRaises(runs.ProofRunError, msg=(run_id, reason)):
                runs.retire(self.root, run_id, reason)
        with self.assertRaisesRegex(runs.ProofRunError, 'unknown run id'):
            runs.retire(self.root, '1' * 32, 'unknown on purpose')
        self.assertEqual((runs.store_root(self.root) / 'index.json').read_bytes(), before)
        self.assertEqual(self.verify()['run_id'], captured['run_id'])

    def test_retire_cli_subcommand_reports_json_and_refuses_unknown(self):
        captured = self.record()
        script = str(runs.ROOT / 'gates' / 'proof_runs.py')
        with patch.object(runs, 'ROOT', self.root):
            with patch('sys.argv', [script, 'retire', '--run-id', '2' * 32, '--reason', 'nope']), \
                 patch('sys.stderr', io.StringIO()) as err:
                self.assertEqual(runs.main(), 1)
            self.assertIn('unknown run id', err.getvalue())
            with patch('sys.argv', [script, 'retire', '--run-id', captured['run_id'], '--reason', 'cli']), \
                 patch('sys.stdout', io.StringIO()) as out:
                self.assertEqual(runs.main(), 0)
            self.assertEqual(json.loads(out.getvalue())['retired'], captured['run_id'])

    def test_disclosed_vacuity_registry_is_validated_before_the_expensive_run(self):
        source = 'mod proofs {\n    #[kani::proof]\n    fn one() {}\n    #[kani::proof]\n    fn witness() {}\n}\n'
        for registry, message in (('// VACUITY-DISCLOSED: one -> witness nosuch', 'unknown harness or witness'),
                                  ('// VACUITY-DISCLOSED: one => witness witness', 'malformed disclosed-vacuity'),
                                  ('// VACUITY-DISCLOSED: one -> witness witness\n    '
                                   '// VACUITY-DISCLOSED: one -> witness witness', 'duplicate')):
            runs.git(self.root, 'reset', '--hard', self.source)
            self.write('der-verified/src/leaf.rs', source.replace('mod proofs {', 'mod proofs {\n    ' + registry))
            self.write(runs.STATE_PATH, runs.digest((self.root / 'der-verified/src/leaf.rs').read_bytes())
                       + '  der-verified/src/leaf.rs\n')
            self.commit()
            spy, launches = self.check_sh_launches()
            with spy, patch('proof_runs.observe_tools') as tools:
                with self.assertRaisesRegex(runs.ProofRunError, message):
                    runs.record(self.root)
                self.assertEqual(launches, [])
                tools.assert_not_called()
            self.assertFalse(any(runs.common_dir(self.root).glob('der-proof-checkout-*')))

    def test_stale_capture_checkout_blocks_record_until_clean_stale(self):
        common = runs.common_dir(self.root)
        stale = common / 'der-proof-checkout-killed1'
        (stale / 'checkout' / 'target').mkdir(parents=True)
        (stale / 'checkout' / 'target' / 'big.o').write_text('x')
        unrelated = common / 'keep-me'
        unrelated.mkdir()
        spy, launches = self.check_sh_launches()
        with patch('proof_runs.observe_tools') as tools, spy:
            with self.assertRaisesRegex(runs.ProofRunError, 'stale capture checkout.*der-proof-checkout-killed1.*clean-stale'):
                runs.record(self.root)
            tools.assert_not_called()
            self.assertEqual(launches, [])
        self.assertTrue(stale.exists())
        result = runs.clean_stale(self.root)
        self.assertEqual(result['removed'], ['der-proof-checkout-killed1'])
        self.assertFalse(stale.exists())
        self.assertTrue(unrelated.exists())
        self.assertTrue((runs.store_root(self.root) / 'repository.json').exists())
        self.assertEqual(self.record()['run_commit'], self.source)

    def test_clean_stale_removes_only_stale_directories_and_refuses_symlinks_and_live_capture(self):
        common = runs.common_dir(self.root)
        outside = Path(self.tmp.name) / 'outside'
        outside.mkdir()
        (outside / 'precious').write_text('keep')
        (common / 'der-proof-checkout-link').symlink_to(outside)
        with self.assertRaisesRegex(runs.ProofRunError, 'non-directory'):
            runs.clean_stale(self.root)
        self.assertTrue((outside / 'precious').exists())
        (common / 'der-proof-checkout-link').unlink()
        self.assertEqual(runs.clean_stale(self.root), {'removed': []})
        # A live capture (lock held) is never judged stale.
        self.record()
        (common / 'der-proof-checkout-live').mkdir()
        import fcntl
        with open(runs.store_root(self.root) / 'record.lock', 'w') as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            with self.assertRaisesRegex(runs.ProofRunError, 'another proof capture is active'):
                runs.clean_stale(self.root)
        self.assertTrue((common / 'der-proof-checkout-live').exists())

    def test_one_verification_does_not_reread_log_for_each_metadata_path(self):
        captured = self.record()
        for name, output in captured['generated_outputs'].items():
            self.write(name, base64.b64decode(output['content_base64']).decode())
        target = self.commit()
        self.receipt(target)
        reads = []
        original_read = runs._read
        def counted(path):
            if path.suffix == '.log': reads.append(path)
            return original_read(path)
        with patch('proof_runs._read', side_effect=counted):
            self.verify(target)
        self.assertEqual(len(reads), 1)

    def test_normal_check_has_no_staging_opt_in(self):
        text = (runs.ROOT / 'check.sh').read_text()
        block = '# The isolated proof recorder' + text.split('# The isolated proof recorder', 1)[1].split('echo "== lid-staleness', 1)[0]
        marker = Path(self.tmp.name) / 'called'
        fake = Path(self.tmp.name) / 'python3'
        fake.write_text('#!/bin/sh\ntouch "' + str(marker) + '"\n')
        fake.chmod(0o755)
        env = dict(runs.git_env(), PATH=str(fake.parent) + os.pathsep + os.environ['PATH'])
        env.pop('DER_PROOF_CAPTURE_CONTEXT', None)
        subprocess.run(['sh', '-eu', '-c', block], env=env, check=True)
        self.assertFalse(marker.exists())

    def test_staging_failure_is_explicit_even_without_errexit(self):
        text = (runs.ROOT / 'check.sh').read_text()
        block = '# The isolated proof recorder' + text.split('# The isolated proof recorder', 1)[1].split('echo "== lid-staleness', 1)[0]
        fake = Path(self.tmp.name) / 'python3'
        fake.write_text('#!/bin/sh\nexit 9\n')
        fake.chmod(0o755)
        env = dict(runs.git_env(), PATH=str(fake.parent) + os.pathsep + os.environ['PATH'],
                   DER_PROOF_CAPTURE_CONTEXT='fixture', ROOT=str(self.root), LID_STATUS='PASS')
        result = subprocess.run(['sh', '-c', block + '\necho should-not-run'], env=env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn('stage-state refused', result.stderr)
        self.assertNotIn('should-not-run', result.stdout)

    def test_real_capture_snapshot_release_and_successful_tag_hook_with_tamper_controls(self):
        import release_evidence as R
        import re
        self.prepare_hook()
        for name in ('release_evidence.py', 'check_acceptance_manifest.py'):
            self.write('gates/' + name, (runs.ROOT / 'gates' / name).read_text())
        shutil.copytree(runs.ROOT / 'gates/vendor', self.root / 'gates/vendor')
        self.write('ASSUMPTIONS.md', (runs.ROOT / 'ASSUMPTIONS.md').read_text())
        self.write('docs/requirements/der.inventory.toml',
                   (runs.ROOT / 'docs/requirements/der.inventory.toml').read_text())
        self.write('Cargo.toml', '[workspace]\nmembers=["der-verified"]\n')
        self.write('der-verified/Cargo.toml', '[package]\nname="der-verified"\nversion="1.2.3"\n')
        self.source = self.commit()
        captured = self.record()  # Fixed subprocess runner; only installed-tool probes are stubbed.
        bundle = Path(self.tmp.name) / 'producer-bundle'
        bundle.mkdir()
        original = runs.ROOT / 'der-verified'
        shutil.copyfile(original / R.MIRROR, bundle / R.MIRROR)
        shutil.copytree(original / R.STORE, bundle / R.STORE)
        # Test-only producer projection with genuine snapshot payloads/hashes.
        # This synthetic subject is never evidence for the actual DER repository.
        manifest = re.sub(r'(?m)^commit = "[0-9a-f]{40}"$', 'commit = "' + self.source + '"',
                          (original / R.MANIFEST).read_text(), count=1)
        (bundle / R.MANIFEST).write_text(manifest)
        with contextlib.redirect_stdout(io.StringIO()):
            R._snapshot(self.root, bundle)  # Real closure + strict snapshot validation.
            prepared = Path(self.tmp.name) / 'prepared'
            R.prepare(self.root, '1.2.3', bundle, prepared)
        for name in (R.MANIFEST, R.MIRROR):
            shutil.copyfile(prepared / name, self.root / 'der-verified' / name)
        shutil.copytree(prepared / R.STORE, self.root / 'der-verified' / R.STORE)
        for path in captured['generated_outputs']:
            dest = self.root / path
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(prepared / 'proof-generated' / path, dest)
        target = self.commit()
        with patch.object(R, '_package_check') as package, contextlib.redirect_stdout(io.StringIO()):
            result = R.validate_release(self.root, '1.2.3', self.source)
            package.assert_called_once_with(self.root)
        self.assertEqual(result['target_commit'], target)
        self.receipt(target)
        tag = self.hook([(target, 'refs/tags/v1.2.3')])
        self.assertEqual(tag.returncode, 0, tag.stdout + tag.stderr)
        self.assertIn('release-validation', tag.stdout)
        self.write('README.md', 'post-release prose only')
        docs = self.commit()
        self.receipt(docs)
        branch = self.hook([(docs, 'refs/heads/main')])
        self.assertEqual(branch.returncode, 0, branch.stdout + branch.stderr)
        self.assertIn('release-carry-over', branch.stdout)
        release_receipt = R._receipt_path(self.root, target)
        release_bytes = release_receipt.read_bytes()
        release_receipt.write_bytes(b'{not-json')
        try:
            refused = self.hook([(docs, 'refs/heads/main')])
            self.assertNotEqual(refused.returncode, 0)
            self.assertNotIn('Traceback', refused.stderr)
            self.assertIn('FAIL proof_runs:', refused.stderr)
        finally:
            release_receipt.write_bytes(release_bytes)
        # A second real fixture capture at S must not revoke T's original binding
        # or cause the metadata comparator to silently select the newer S run.
        runs.git(self.root, 'checkout', '--detach', self.source)
        newer = self.record()
        self.assertNotEqual(newer['receipt_sha256'], captured['receipt_sha256'])
        self.assertNotEqual(newer['generated_outputs'][runs.FLOOR_PATH],
                            captured['generated_outputs'][runs.FLOOR_PATH])
        runs.git(self.root, 'checkout', '--detach', docs)
        self.assertEqual(runs.verify_trusted_run(self.root, self.source)['receipt_sha256'],
                         newer['receipt_sha256'])
        bound = runs.verify_trusted_run(self.root, self.source,
                                       receipt_sha256=captured['receipt_sha256'])
        self.assertEqual(bound['run_id'], captured['run_id'])
        self.assertEqual(R.verify_release(self.root, target, 'refs/tags/v1.2.3')['target_commit'], target)
        for sha, ref in ((target, 'refs/tags/v1.2.3'), (docs, 'refs/heads/main')):
            result = self.hook([(sha, ref)])
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        # Neither corruption nor removal/unregistration may fall back to newer S.
        store = runs.store_root(self.root)
        receipt_path = store / (captured['run_id'] + '.json')
        original_receipt = receipt_path.read_bytes()
        index_path = store / 'index.json'
        original_index = index_path.read_bytes()
        for mutation in ('corrupt', 'delete', 'unregister'):
            with self.subTest(bound_receipt=mutation):
                try:
                    if mutation == 'corrupt':
                        receipt_path.write_bytes(original_receipt + b' ')
                    elif mutation == 'delete':
                        receipt_path.unlink()
                    else:
                        index = json.loads(original_index)
                        index.pop(captured['run_id'])
                        runs._write(index_path, runs.canonical(index))
                    for sha, ref in ((target, 'refs/tags/v1.2.3'), (docs, 'refs/heads/main')):
                        self.assertNotEqual(self.hook([(sha, ref)]).returncode, 0,
                                            mutation + ' ' + ref)
                finally:
                    runs._write(receipt_path, original_receipt)
                    runs._write(index_path, original_index)
        self.write('der-verified/' + R.MANIFEST, manifest + '\n# artifact mutation\n')
        changed_artifact = self.commit()
        self.assertNotEqual(self.hook([(changed_artifact, 'refs/heads/main')]).returncode, 0)
        self.assertNotEqual(self.hook([(changed_artifact, 'refs/tags/v1.2.3')]).returncode, 0)
        runs.git(self.root, 'reset', '--hard', target)
        # Reverting the entire artifact bundle to S must not bypass T's boundary.
        for path in R._committed_artifacts(self.root, target):
            (self.root / path).unlink()
        reverted = self.commit()
        self.assertNotEqual(self.hook([(reverted, 'refs/heads/main')]).returncode, 0)
        runs.git(self.root, 'reset', '--hard', target)
        for name in (captured['run_id'] + '.log', 'index.json'):
            path = runs.store_root(self.root) / name
            old = path.read_bytes()
            path.write_bytes(old + (b'corruption' if name.endswith('.log') else b' invalid'))
            try:
                self.assertNotEqual(self.hook([(target, 'refs/tags/v1.2.3')]).returncode, 0, name)
            finally:
                path.write_bytes(old)
        # Same S→T artifact bundle with the captured metadata omitted cannot validate.
        for path in captured['generated_outputs']:
            if path == runs.FLOOR_PATH:
                (self.root / path).unlink()
            else:
                (self.root / path).write_bytes(runs.git(self.root, 'show', self.source + ':' + path))
        stale = self.commit()
        with patch.object(R, '_package_check'), contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaisesRegex(ValueError, 'exact captured metadata|history check failed'):
                R.validate_release(self.root, '1.2.3', self.source)
        self.assertFalse(R._receipt_path(self.root, stale).exists())


class ToolPolicy(unittest.TestCase):
    def test_python_path_binding_and_exact_lean_version(self):
        import proof_run_tools as tools
        with patch.object(tools.shutil, 'which', return_value=runs.sys.executable):
            self.assertEqual(tools.python_launcher(), Path(runs.sys.executable))
        with tempfile.TemporaryDirectory() as tmp:
            other = Path(tmp) / 'python3'
            other.write_text('different Python launcher')
            with patch.object(tools.shutil, 'which', return_value=str(other)):
                with self.assertRaises(runs.ProofRunError): tools.python_launcher()
        tools.require_lean_version('Lean (version 4.30.0-rc2, x86_64, commit fixture, Release)', '4.30.0-rc2')
        for version in ('4.30.0-rc20', '4.30.0-rc2-extra', '14.30.0-rc2'):
            with self.assertRaises(runs.ProofRunError):
                tools.require_lean_version('Lean (version ' + version + ', fixture)', '4.30.0-rc2')

    def test_real_kani_log_grammar_fixture(self):
        import re
        data = (runs.ROOT / 'gates/fixtures/proof-log-grammar.txt').read_bytes()
        names = [name.decode() for name in re.findall(rb'^Checking harness ([A-Za-z0-9_:]+)\.\.\.$', data, re.M)]
        self.assertEqual(len(names), 2)
        counts = runs.validate_log(data, names, names)
        self.assertEqual(counts['successful'], 2)
        self.assertEqual(counts['covers_unsatisfied'], 1)

    def test_direct_binary_and_manager_proxy_are_distinguished(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            direct, manager, backend = (root / name for name in ('rustc', 'rustup', 'real-rustc'))
            direct.write_bytes(b'direct compiler')
            backend.write_bytes(b'manager backend')
            manager.write_bytes(b'manager launcher')
            mapping = {'rustc': str(direct), 'rustup': str(manager)}
            with patch('proof_run_tools.shutil.which', side_effect=mapping.get), patch('proof_run_tools._probe') as probe:
                self.assertEqual(runs.effective_binary('rustc', root, 'rustup', ['which', 'rustc']), (direct, direct))
                probe.assert_not_called()
            direct.unlink()
            direct.symlink_to(manager)
            with patch('proof_run_tools.shutil.which', side_effect=mapping.get), patch('proof_run_tools._probe', return_value=str(backend)) as probe:
                self.assertEqual(runs.effective_binary('rustc', root, 'rustup', ['which', 'rustc']), (manager, backend))
                probe.assert_called_once()

    def test_override_and_external_config_refusals_do_not_print_values(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp) / 'repo'
            root.mkdir()
            home = Path(tmp) / 'cargo-home'
            home.mkdir()
            for name in ('RUSTFLAGS', 'RUSTC_WRAPPER', 'CARGO_ENCODED_RUSTFLAGS', 'LEAN_PATH', 'PYTHONOPTIMIZE'):
                with patch.dict(os.environ, {'CARGO_HOME': str(home), name: 'SECRET-VALUE'}, clear=True):
                    with self.assertRaises(runs.ProofRunError) as error: runs.supported_environment(root)
                    self.assertNotIn('SECRET-VALUE', str(error.exception))
            (home / 'config.toml').write_text('[build]\nrustflags=[]\n')
            with patch.dict(os.environ, {'CARGO_HOME': str(home)}, clear=True):
                with self.assertRaises(runs.ProofRunError): runs.supported_environment(root)

    def test_tool_component_hash_changes_and_cycles_refuse(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            binary = root / 'cbmc'
            binary.write_bytes(b'one')
            before = runs.tree_fingerprint(root)
            binary.write_bytes(b'two')
            self.assertNotEqual(before, runs.tree_fingerprint(root))
            (root / 'loop').symlink_to(root, target_is_directory=True)
            with self.assertRaises(runs.ProofRunError): runs.tree_fingerprint(root)


if __name__ == '__main__':
    unittest.main()
