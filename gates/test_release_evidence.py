#!/usr/bin/env python3
"""Release lifecycle controls; proof execution is never simulated as trusted evidence."""
import contextlib
import base64
import io
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import release_evidence as R
import proof_runs as P


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix='release-lifecycle-')
        self.addCleanup(self.temp.cleanup)
        self.base = Path(self.temp.name)
        self.root = self.base / 'repo'
        self.root.mkdir()
        self.git('init', '-q')
        self.git('config', 'user.name', 'test')
        self.git('config', 'user.email', 'test@localhost')
        self.git('config', 'core.hooksPath', '/dev/null')
        self.write('Cargo.toml', '[workspace]\nmembers=["der-verified"]\n')
        self.write('der-verified/Cargo.toml', '[package]\nname="der-verified"\nversion="1.2.3"\n')
        self.write('der-verified/src/lib.rs', 'pub fn value() -> u8 { 1 }\n')
        self.write('docs/requirements/der.inventory.toml', 'inventory\n')
        self.write('README.md', 'Example\n')
        self.source = self.commit('source')
        self.bundle(self.root / 'der-verified', self.source)
        self.target = self.commit('acceptance artifacts')
        self.run = {'run_commit': self.source, 'receipt_sha256': 'a' * 64,
                    'generated_outputs': {}}

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], env=P.git_env()).decode().strip()

    def write(self, relative, text):
        path = self.root / relative
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text)

    def commit(self, message):
        self.git('add', '-A')
        self.git('commit', '-qm', message)
        return self.git('rev-parse', 'HEAD')

    def bundle(self, package, source):
        package.mkdir(parents=True, exist_ok=True)
        (package / R.MANIFEST).write_text('[subject]\ncommit="' + source + '"\ndirty=false\n')
        (package / R.MIRROR).write_text('inventory\n')
        (package / R.STORE).mkdir(parents=True, exist_ok=True)
        (package / R.STORE / 'record.json').write_text('{}\n')

    @contextlib.contextmanager
    def isolated_validation(self):
        # Only lifecycle unit tests use these stubs. The real snapshot/hash and
        # package validators run separately below and in the public fast suite.
        require_outputs = R._require_generated_outputs
        with patch.object(R, '_snapshot', side_effect=lambda root, package: R.artifact_files(package)), \
             patch.object(P, 'verify_trusted_run', return_value=self.run), \
             patch.object(R, '_require_generated_outputs', side_effect=lambda root, target, run:
                 require_outputs(root, target, run) if run['generated_outputs'] else None), \
             patch.object(R, '_package_check') as package_check:
            yield package_check

    def test_artifact_commit_and_prose_are_applicable_without_rewriting_subject(self):
        self.assertEqual(R.applicability(self.root)['state'], 'APPLICABLE')
        self.write('README.md', 'Updated prose\n')
        self.commit('prose')
        self.assertEqual(R.applicability(self.root)['state'], 'APPLICABLE')
        self.assertEqual(R.subject(self.root / 'der-verified'), self.source)

    def test_source_gate_inventory_and_untracked_changes_are_not_current(self):
        for path in ('der-verified/src/lib.rs', 'gates/check.sh', 'docs/requirements/der.inventory.toml', 'unknown.txt'):
            with self.subTest(path=path):
                self.write(path, 'changed\n')
                self.assertEqual(R.applicability(self.root)['state'], 'CHANGED')
                self.git('reset', '--hard', self.target)
                self.git('clean', '-fdq')

    def test_superseded_record_deletions_are_exact_data_paths(self):
        self.source = self.target
        package = self.root / 'der-verified'
        (package / R.MANIFEST).write_text('[subject]\ncommit="' + self.source + '"\ndirty=false\n')
        (package / R.STORE / 'record.json').unlink()
        (package / R.STORE / 'replacement.json').write_text('{}\n')
        self.target = self.commit('replace recorded bundle')
        self.assertEqual(R.applicability(self.root)['state'], 'APPLICABLE')

    def test_comment_and_string_words_are_not_external_inputs(self):
        self.write('der-verified/src/lib.rs', '// fs env process include_str!("example")\npub const TEXT: &str = "fs env process";\npub fn process(env: u8) -> u8 { env }\n')
        self.source = self.commit('source with ordinary words')
        self.bundle(self.root / 'der-verified', self.source)
        self.target = self.commit('issued snapshot')
        self.assertEqual(R.applicability(self.root)['state'], 'APPLICABLE')

    def test_artifacts_cannot_be_compile_time_or_external_source_inputs(self):
        self.write('der-verified/src/lib.rs', 'const DATA: &str = include_str!("../acceptance.toml");\n')
        self.source = self.commit('source reads acceptance data')
        self.bundle(self.root / 'der-verified', self.source)
        self.target = self.commit('new data')
        status = R.applicability(self.root)
        self.assertEqual(status['state'], 'CHANGED')

    def test_updating_both_inventories_does_not_hide_requirement_drift(self):
        self.write('docs/requirements/der.inventory.toml', 'changed inventory\n')
        self.write('der-verified/' + R.MIRROR, 'changed inventory\n')
        self.commit('changed requirements and mirror')
        self.assertEqual(R.applicability(self.root)['state'], 'CHANGED')

    def test_published_state_cache_needs_no_local_trust_but_stale_cache_fails(self):
        import hashlib
        digest = hashlib.sha256((self.root / 'der-verified/src/lib.rs').read_bytes()).hexdigest()
        self.write('lean/check_lean.sh', 'check_drift Model "lib.rs"\n')
        self.write('lean/lid-source-state.txt', 'PENDING ' + digest + '  der-verified/src/lib.rs\n')
        self.source = self.commit('source with pending metadata')
        self.bundle(self.root / 'der-verified', self.source)
        self.write('lean/lid-source-state.txt', digest + '  der-verified/src/lib.rs\n')
        self.target = self.commit('published artifacts and generated cache')
        clone = self.base / 'public-clone'
        subprocess.run(['git', 'clone', '--no-hardlinks', '-q', str(self.root), str(clone)], check=True, env=P.git_env())
        self.assertFalse(P.store_root(clone).exists())
        self.assertEqual(R.applicability(clone)['state'], 'APPLICABLE')
        with self.assertRaises(ValueError):
            P.verify_source_inputs(clone, self.source, self.target,
                                   allowed_artifacts=R._allowed_artifacts(clone, self.source, self.target, R.artifact_files(clone / 'der-verified')))
        self.write('lean/lid-source-state.txt', '0' * 64 + '  der-verified/src/lib.rs\n')
        self.commit('stale cache')
        self.assertEqual(R.applicability(self.root)['state'], 'CHANGED')

    def test_source_to_release_metadata_and_bundle_without_a_second_run(self):
        import base64, hashlib
        self.write('der-verified/src/leaf.rs', '#[cfg(kani)]\nmod proofs {\n#[kani::proof]\nfn one() { assert!(true); }\n}\n')
        self.write('der-verified/src/lib.rs', 'mod leaf;\npub fn value() -> u8 { 1 }\n')
        source_text = 'Normative scope stays fixed.\n' + ''.join(
            (P.gpm.BEGIN % name) + '\nold generated text\n' + (P.gpm.END % name) + '\n'
            for name in (*P.FLOOR_REGIONS, 'unrelated'))
        digest = hashlib.sha256((self.root / 'der-verified/src/lib.rs').read_bytes()).hexdigest()
        self.write('lean/check_lean.sh', 'check_drift Model "lib.rs"\n')
        self.write('lean/lid-source-state.txt', 'PENDING ' + digest + '  der-verified/src/lib.rs\n')
        self.write('PROOF_MANIFEST.md', source_text)
        self.source = self.commit('source and projection templates')
        state = (digest + '  der-verified/src/lib.rs\n').encode()
        floor = P.floor_output(self.source, 'b' * 64,
                              {'successful': 1, 'failed': 0, 'covers_unsatisfied': 0}, 1, 2)
        projection = P.projected_manifest(source_text.encode(), json.loads(base64.b64decode(floor['content_base64'])))
        self.run = {'run_commit': self.source, 'receipt_sha256': 'a' * 64, 'generated_outputs': {
            P.STATE_PATH: {'sha256': hashlib.sha256(state).hexdigest(), 'content_base64': base64.b64encode(state).decode()},
            P.FLOOR_PATH: floor, P.PROJECTION_PATH: projection}}
        self.bundle(self.root / 'der-verified', self.source)
        for path, output in self.run['generated_outputs'].items():
            self.write(path, base64.b64decode(output['content_base64']).decode())
        self.target = self.commit('exact captured outputs and bundle')
        with self.isolated_validation() as package:
            result = R.validate_release(self.root, '1.2.3', self.source)
            self.assertEqual((result['run_commit'], result['target_commit']), (self.source, self.target))
            package.assert_called_once()
        clone = self.base / 'fresh-release-clone'
        subprocess.run(['git', 'clone', '--no-hardlinks', '-q', str(self.root), str(clone)], check=True, env=P.git_env())
        self.assertFalse(P.store_root(clone).exists())
        self.assertEqual(R.applicability(clone)['state'], 'APPLICABLE')
        projected = (self.root / P.PROJECTION_PATH).read_text()
        for changed in (projected.replace('Normative scope stays fixed.', 'Changed scope.'),
                        projected.replace('old generated text', 'unrelated change')):
            self.write(P.PROJECTION_PATH, changed)
            self.commit('unapproved proof manifest change')
            self.assertEqual(R.applicability(self.root)['state'], 'CHANGED')
            with self.isolated_validation():
                with self.assertRaises(ValueError):
                    R.validate_release(self.root, '1.2.3', self.source)
            self.git('reset', '--hard', self.target)

    def test_missing_history_is_unknown_not_applicable(self):
        self.bundle(self.root / 'der-verified', '0' * 40)
        self.assertEqual(R.applicability(self.root)['state'], 'UNKNOWN')

    def test_present_but_diverged_subject_is_changed(self):
        self.git('checkout', '--orphan', 'diverged')
        self.write('README.md', 'Independent branch history\n')
        self.commit('diverged current tree')
        result = R.applicability(self.root)
        self.assertEqual(result['state'], 'CHANGED')
        self.assertEqual(result['subject'], self.source)

    def test_release_requires_all_captured_metadata_even_if_unchanged_since_source(self):
        with self.assertRaisesRegex(ValueError, 'complete captured metadata'):
            R._require_generated_outputs(self.root, self.target, self.run)

    def test_no_trusted_run_means_no_preparation(self):
        candidate = self.base / 'candidate'
        self.bundle(candidate, self.source)
        with patch.object(R, '_snapshot', side_effect=lambda root, package: R.artifact_files(package)):
            with self.assertRaises(ValueError):
                R.prepare(self.root, '1.2.3', candidate, self.base / 'prepared')
        self.assertFalse((self.base / 'prepared').exists())

    def test_prepare_stages_only_and_does_not_modify_source(self):
        candidate = self.base / 'candidate'
        self.bundle(candidate, self.source)
        with self.isolated_validation():
            result = R.prepare(self.root, '1.2.3', candidate, self.base / 'prepared')
        self.assertEqual(result['source_commit'], self.source)
        self.assertEqual(self.git('status', '--porcelain'), '')
        self.assertTrue((self.base / 'prepared/release-preparation.json').is_file())
        self.assertFalse(R._receipt_path(self.root, self.target).exists())

    def test_prepare_stages_exact_recorder_metadata_outside_source(self):
        import base64, hashlib
        raw = b'captured source-state bytes\n'
        self.run['generated_outputs'] = {name: {
            'sha256': hashlib.sha256(raw).hexdigest(),
            'content_base64': base64.b64encode(raw).decode(),
        } for name in ('lean/lid-source-state.txt', 'docs/proof-floor.json', 'PROOF_MANIFEST.md')}
        candidate = self.base / 'candidate'
        self.bundle(candidate, self.source)
        with self.isolated_validation():
            R.prepare(self.root, '1.2.3', candidate, self.base / 'prepared')
        for name in self.run['generated_outputs']:
            self.assertEqual((self.base / 'prepared/proof-generated' / name).read_bytes(), raw)
        self.assertFalse((self.root / 'lean/lid-source-state.txt').exists())
        self.assertEqual(self.git('status', '--porcelain'), '')

    def test_prepare_rejects_wrong_version_dirty_checkout_and_extra_payload(self):
        candidate = self.base / 'candidate'
        self.bundle(candidate, self.source)
        with self.isolated_validation():
            with self.assertRaisesRegex(ValueError, 'version'):
                R.prepare(self.root, '2.0.0', candidate, self.base / 'prepared')
            (candidate / 'unrelated.py').write_text('')
            with self.assertRaisesRegex(ValueError, 'outside the acceptance'):
                R.prepare(self.root, '1.2.3', candidate, self.base / 'prepared')
            (candidate / 'unrelated.py').unlink()
            self.write('README.md', 'dirty')
            with self.assertRaisesRegex(ValueError, 'clean'):
                R.prepare(self.root, '1.2.3', candidate, self.base / 'prepared')

    def test_release_validation_is_bound_to_artifact_commit_tag_and_full_run(self):
        with self.isolated_validation() as package:
            result = R.validate_release(self.root, '1.2.3', self.source)
            self.assertEqual(result['mode'], 'release-validation')
            self.assertEqual(R.verify_release_commit(self.root, self.target)['mode'], 'release-validation')
            self.assertEqual(result['target_commit'], self.target)
            self.assertEqual(result['run_commit'], self.source)
            package.assert_called_once_with(self.root)
            with self.assertRaisesRegex(ValueError, 'identity'):
                R.verify_release(self.root, self.target, 'refs/tags/v9.0.0')
            self.write('README.md', 'later')
            later = self.commit('later')
            with self.assertRaisesRegex(ValueError, 'receipt'):
                R.verify_release(self.root, later, 'refs/tags/v1.2.3')

    def test_release_carry_over_rechecks_supported_input_model(self):
        with self.isolated_validation():
            R.validate_release(self.root, '1.2.3', self.source)
            readme = self.root / 'README.md'
            readme.unlink()
            readme.symlink_to('/etc/passwd')
            self.commit('unsupported prose symlink')
            with self.assertRaisesRegex(ValueError, 'symlinked source/tool/config inputs'):
                R.verify_release_commit(self.root, self.git('rev-parse', 'HEAD'),
                                        allow_prose_descendants=True)

    def test_failed_package_validation_creates_no_receipt(self):
        with self.isolated_validation() as package:
            package.side_effect = ValueError('package failed')
            with self.assertRaisesRegex(ValueError, 'package failed'):
                R.validate_release(self.root, '1.2.3', self.source)
        self.assertFalse(R._receipt_path(self.root, self.target).exists())

    def test_changed_source_and_forged_artifact_hash_are_refused(self):
        with self.isolated_validation():
            R.validate_release(self.root, '1.2.3', self.source)
            path = R._receipt_path(self.root, self.target)
            data = json.loads(path.read_text())
            data['artifacts'][R.PREFIX + R.MANIFEST] = '0' * 64
            path.write_text(json.dumps(data))
            with self.assertRaisesRegex(ValueError, 'hashes'):
                R.verify_release(self.root, self.target, 'refs/tags/v1.2.3')
            self.write('der-verified/src/lib.rs', 'pub fn value() -> u8 { 2 }\n')
            self.commit('source changed')
            with self.assertRaises(ValueError):
                R.validate_release(self.root, '1.2.3', self.source)

    def test_release_package_must_match_committed_source_and_artifacts(self):
        unpacked = self.base / 'unpacked'
        shutil.copytree(self.root / 'der-verified', unpacked)
        shutil.copyfile(unpacked / 'Cargo.toml', unpacked / 'Cargo.toml.orig')
        (unpacked / '.cargo_vcs_info.json').write_text(json.dumps({'git': {'sha1': self.target, 'dirty': False}}))
        R.check_packed_commit(self.root, unpacked, self.target)
        (unpacked / 'src/lib.rs').write_text('different source')
        with self.assertRaisesRegex(ValueError, 'packed bytes'):
            R.check_packed_commit(self.root, unpacked, self.target)
        shutil.copyfile(self.root / 'der-verified/src/lib.rs', unpacked / 'src/lib.rs')
        (unpacked / 'src/extra.rs').write_text('extra source')
        with self.assertRaisesRegex(ValueError, 'inventory'):
            R.check_packed_commit(self.root, unpacked, self.target)

    def test_symlink_artifacts_and_public_receipts_are_refused(self):
        record = self.root / 'der-verified' / R.STORE / 'record.json'
        record.unlink()
        record.symlink_to(self.root / 'README.md')
        with self.assertRaisesRegex(ValueError, 'symlink'):
            R.artifact_files(self.root / 'der-verified')
        self.git('reset', '--hard', self.target)
        with self.isolated_validation():
            R.validate_release(self.root, '1.2.3', self.source)
            path = R._receipt_path(self.root, self.target)
            path.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'owner-only'):
                R.verify_release(self.root, self.target, 'refs/tags/v1.2.3')


class SnapshotIntegrityTests(unittest.TestCase):
    def test_record_hash_or_inventory_hash_corruption_never_becomes_development_pass(self):
        from check_acceptance_manifest import validate_snapshot
        with tempfile.TemporaryDirectory(prefix='release-snapshot-') as td:
            package = Path(td) / 'bundle'
            package.mkdir()
            original = R.ROOT / 'der-verified'
            for name in (R.MANIFEST, R.MIRROR):
                shutil.copyfile(original / name, package / name)
            shutil.copytree(original / R.STORE, package / R.STORE)
            with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
                self.assertEqual(validate_snapshot(R.ROOT, package), 0)
                record = next((package / R.STORE).glob('*.json'))
                raw = record.read_bytes()
                record.write_bytes(raw + b' ')
                self.assertNotEqual(validate_snapshot(R.ROOT, package), 0)
                record.write_bytes(raw)
                mirror = package / R.MIRROR
                mirror.write_bytes(mirror.read_bytes() + b'\n')
                self.assertNotEqual(validate_snapshot(R.ROOT, package), 0)


if __name__ == '__main__':
    unittest.main()
