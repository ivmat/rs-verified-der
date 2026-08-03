#!/usr/bin/env python3
"""test_gen_proof_manifest.py — the gate's own gate.

`gen_proof_manifest.py` is what stops a hand-typed count from drifting in the proof envelope.
Nothing was stopping *it* from drifting: an over-strict `--check` blocks an honest third party
before a single proof runs, and an over-lenient one silently stops enforcing the counts. Both
failure directions are cheap to test, and neither is visible by reading the script.

Run:  python3 gates/test_gen_proof_manifest.py      (pure stdlib; wired into check.sh/check_fast.sh)

The tests are structured in opposing pairs on purpose. Every leniency test ("this must NOT fail
the gate") is paired with a strictness test ("this MUST still fail the gate"), because the easy
way to make a gate stop complaining is to make it stop checking.
"""

import contextlib
import copy
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

_spec = importlib.util.spec_from_file_location('gen_proof_manifest',
                                               os.path.join(HERE, 'gen_proof_manifest.py'))
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def facts():
    """Derived facts, collected once — `collect()` shells out to rustc/kani/git."""
    if not hasattr(facts, '_cache'):
        facts._cache = gen.collect()
    return copy.deepcopy(facts._cache)


def manifest():
    with open(gen.MANIFEST, encoding='utf-8') as fh:
        return fh.read()


class ThirdPartyEnvironment(unittest.TestCase):
    """A reader with a different toolchain checks out identical source. The gate must pass.

    This is the regression these tests were opened for: the observed-toolchain line lived inside
    the byte-compared `pins` region, so `./check.sh` failed at the manifest gate for anyone whose
    rustc differed from the machine that last ran `--write` — and told them to run `--write`,
    which would have rewritten the recorded pins for a source change that never happened.
    """

    def test_different_rustc_does_not_fail_check(self):
        f = facts()
        f['toolchain']['observed']['rustc'] = 'rustc 1.93.1 (0000000000 2026-01-01)'
        self.assertEqual([n for n, _, _ in gen.region_diffs(manifest(), f)], [])

    def test_absent_kani_and_aeneas_do_not_fail_check(self):
        # What a reader who has cloned the crate but installed none of the proof tooling sees.
        f = facts()
        f['toolchain']['observed'].update({
            'rustc': 'rustc 1.90.0 (deadbeef01 2025-09-01)',
            'kani': 'not installed on this machine',
            'aeneas_rev': 'absent',
            'charon_rev': 'absent',
        })
        self.assertEqual([n for n, _, _ in gen.region_diffs(manifest(), f)], [])

    def test_manifest_recorded_on_another_machine_does_not_fail_check(self):
        # The mirror image: the *committed* observed line came from someone else's machine.
        text = manifest()
        parts = gen.split_region(text, 'pins-observed')
        self.assertIsNotNone(parts, 'the pins-observed region markers are missing')
        pre, body, post = parts
        foreign = pre + (gen.BEGIN % 'pins-observed') + \
            '\nObserved on some other machine entirely: rustc `1.0.0`, Kani `absent`.\n' + \
            (gen.END % 'pins-observed') + post
        self.assertNotEqual(foreign, text, 'the substitution did not change the manifest')
        self.assertEqual([n for n, _, _ in gen.region_diffs(foreign, facts())], [])


class StillEnforced(unittest.TestCase):
    """The counter-tests. Loosening the gate for the environment must loosen nothing else."""

    def test_drifted_harness_count_still_fails_check(self):
        f = facts()
        f['totals']['harnesses'] += 1
        self.assertIn('inventory', [n for n, _, _ in gen.region_diffs(manifest(), f)])

    def test_drifted_declared_toolchain_pin_still_fails_check(self):
        # The declared pins share a section with the advisory line but are read from in-tree
        # files (ci.yml, lean/check_lean.sh, rust-toolchain.toml) — crate properties, enforced.
        for key, value in [('kani_ci', '0.99.0'), ('aeneas', 'f' * 40), ('charon', 'e' * 40),
                           ('rust_channel', 'beta'), ('lean', 'leanprover/lean4:v0.0.0')]:
            with self.subTest(pin=key):
                f = facts()
                f['toolchain']['declared'][key] = value
                self.assertIn('pins', [n for n, _, _ in gen.region_diffs(manifest(), f)])

    def test_advisory_set_stays_narrow(self):
        # A one-line tripwire: widening ADVISORY is how this gate would quietly stop enforcing.
        # Widened once, deliberately: `evidence-coverage` needs git history, which is an
        # environment probe exactly like `pins-observed`. Anything tree-derived stays enforced.
        self.assertEqual(gen.ADVISORY, {'pins-observed', 'evidence-coverage'})


class CommentStripping(unittest.TestCase):
    """The trap that produced three published wrong counts: prose mentions counted as code.

    DOCS-SYNC.md tells maintainers not to hand-grep because the naive greps count `#[test]`,
    `#[kani::unwind(..)]` and `kani::cover` *mentioned inside doc comments*. That promise is the
    script's, so it belongs in the script's tests rather than only in the prose asserting it.
    """

    def test_mentions_inside_comments_are_not_counted_as_code(self):
        lines = [
            '/// A doc comment mentioning #[test] and kani::cover and #[kani::unwind(16)].',
            '// A line comment mentioning #[kani::proof] too.',
            '    //! inner doc: #[test]',
            '#[test]',
            'fn real() { kani::cover!(true); }',
        ]
        kept = gen.strip_comments(lines)
        self.assertEqual(kept, ['#[test]', 'fn real() { kani::cover!(true); }'])


class RegionPlumbing(unittest.TestCase):
    def test_advisory_region_is_still_generated_and_still_marker_checked(self):
        # Advisory means "not byte-compared", NOT "not maintained": --write must still write it,
        # and a missing marker must still fail, so the provenance note cannot silently vanish.
        rendered = gen.render(facts(), 'pins-observed')
        self.assertIn('Observed on the machine', rendered)
        self.assertIn('rustc', rendered)

        text = manifest().replace(gen.BEGIN % 'pins-observed', '')
        _, missing = gen.rewrite(text, facts())
        self.assertIn('pins-observed', missing)

    def test_write_is_idempotent(self):
        once, missing = gen.rewrite(manifest(), facts())
        self.assertEqual(missing, [])
        twice, _ = gen.rewrite(once, facts())
        self.assertEqual(once, twice)

    def test_every_advisory_name_is_a_real_region(self):
        self.assertEqual(gen.ADVISORY - set(gen.REGIONS), set())


class GateExitCode(unittest.TestCase):
    """End-to-end: `check.sh` consults the *exit code* of `--check`, not `region_diffs`.

    Without this class every test above could pass while `main()` ignored its own findings and
    returned 0 — the gate would be green and vacuous, which is the failure mode this repo cares
    about most. So: drive `main()` itself, and assert on the exit code and the message.
    """

    def _check(self, text):
        """Run `--check` against `text` as if it were the committed manifest."""
        with tempfile.NamedTemporaryFile('w', suffix='.md', delete=False, encoding='utf-8') as fh:
            fh.write(text)
            path = fh.name
        real_manifest, real_argv = gen.MANIFEST, sys.argv
        try:
            gen.MANIFEST = path
            sys.argv = ['gen_proof_manifest.py', '--check']
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = gen.main()
            return code, err.getvalue()
        finally:
            gen.MANIFEST, sys.argv = real_manifest, real_argv
            os.unlink(path)

    def test_committed_manifest_exits_zero(self):
        code, err = self._check(manifest())
        self.assertEqual(code, 0, err)

    def test_drifted_count_exits_one_and_names_the_region_and_the_lines(self):
        n = facts()['totals']['harnesses']
        old = '| `#[kani::proof]` harnesses | %d |' % n
        text = manifest()
        self.assertIn(old, text, 'inventory row not found — this test needs updating')
        code, err = self._check(text.replace(old, '| `#[kani::proof]` harnesses | %d |' % (n + 7)))
        self.assertEqual(code, 1)
        self.assertIn('inventory', err)          # names the disagreeing region…
        self.assertIn(str(n + 7), err)           # …and shows both sides, so the reader can judge
        self.assertIn(str(n), err)               # whether the source or the manifest is wrong.

    def test_foreign_observed_line_exits_zero(self):
        pre, _, post = gen.split_region(manifest(), 'pins-observed')
        foreign = pre + (gen.BEGIN % 'pins-observed') + \
            "\nObserved elsewhere: rustc `0.0.0`, Kani `not installed on this machine`.\n" + \
            (gen.END % 'pins-observed') + post
        code, err = self._check(foreign)
        self.assertEqual(code, 0, err)

    def test_a_newline_only_difference_still_prints_a_diff(self):
        # A failure that prints no diff is worse than the blanket message this replaced, and it is
        # exactly what stripping the region's bracketing newlines before diffing would produce.
        b = gen.BEGIN % 'inventory'
        text = manifest().replace(b + '\n', b, 1)   # delete the newline after the BEGIN marker
        self.assertNotEqual(text, manifest())
        code, err = self._check(text)
        self.assertEqual(code, 1)
        self.assertIn('inventory', err)
        # Not just the header: an actual +/- line from the unified diff must be there.
        body = [l for l in err.split('\n') if l.strip().startswith(('+', '-'))
                and not l.strip().startswith(('+++', '---'))]
        self.assertTrue(body, 'gate reported a disagreement but printed no diff:\n' + err)

    def test_missing_region_marker_exits_one(self):
        code, err = self._check(manifest().replace(gen.BEGIN % 'pins-observed', ''))
        self.assertEqual(code, 1)
        self.assertIn('pins-observed', err)


class MutationKill(unittest.TestCase):
    """Are the tests above worth anything? Break the gate on purpose and demand they notice.

    A test suite that passes against a gutted gate is the vacuity this crate spends most of its
    care avoiding, and "I checked once by hand" is not a check (DOCS-SYNC.md). So the check runs
    here, every time: each mutant below is a plausible way this gate could be weakened — reverting
    the fix, widening the advisory set to quiet a complaint, or short-circuiting the comparison —
    and each must be killed by a NAMED test, not merely by "something failed".
    """

    SUBJECTS = None  # filled in below, after the classes exist

    def _kills(self, mutate, restore):
        mutate()
        try:
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                                       for c in self.SUBJECTS)
            res = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        finally:
            restore()
        # subTest ids carry a " (pin='...')" suffix; the test's own name is what we assert on.
        return {tc.id().split('.')[-1].split(' ')[0] for tc, _ in res.failures + res.errors}

    def test_reverting_the_fix_is_caught(self):
        # Deliberately NOT requiring `test_committed_manifest_exits_zero` here: whether the
        # reverted gate fails on the committed manifest depends on whether THIS machine's rustc
        # happens to match the recorded one — on the machine that last ran `--write`, the buggy
        # gate is green. That is precisely why the bug reached a third party in the first place,
        # and why the required kills below are tests that inject a foreign toolchain themselves.
        original = set(gen.ADVISORY)   # capture, never hardcode -- see the note below
        killed = self._kills(lambda: setattr(gen, 'ADVISORY', set()),
                             lambda: setattr(gen, 'ADVISORY', original))
        self.assertLessEqual({'test_different_rustc_does_not_fail_check',
                              'test_absent_kani_and_aeneas_do_not_fail_check',
                              'test_manifest_recorded_on_another_machine_does_not_fail_check',
                              'test_foreign_observed_line_exits_zero'}, killed)

    def test_gutting_the_comparison_is_caught(self):
        real = gen.region_diffs
        killed = self._kills(lambda: setattr(gen, 'region_diffs', lambda text, f: []),
                             lambda: setattr(gen, 'region_diffs', real))
        self.assertLessEqual({'test_drifted_harness_count_still_fails_check',
                              'test_drifted_declared_toolchain_pin_still_fails_check',
                              'test_drifted_count_exits_one_and_names_the_region_and_the_lines'},
                             killed)

    def test_widening_the_advisory_set_is_caught(self):
        # Restore the value that was ACTUALLY there, not a hardcoded literal: a hardcoded restore
        # silently reverts a legitimate change to ADVISORY and corrupts every test that runs after
        # this one, which is order-dependent and exactly the kind of failure a test suite should not
        # have. (It did: adding `evidence-coverage` made a later test fail here, not in the code.)
        original = set(gen.ADVISORY)
        killed = self._kills(
            lambda: setattr(gen, 'ADVISORY', {'pins-observed', 'pins', 'inventory'}),
            lambda: setattr(gen, 'ADVISORY', original))
        self.assertLessEqual({'test_drifted_harness_count_still_fails_check',
                              'test_drifted_declared_toolchain_pin_still_fails_check'}, killed)


MutationKill.SUBJECTS = (ThirdPartyEnvironment, StillEnforced, RegionPlumbing, GateExitCode)



class HeadCoverageFact(unittest.TestCase):
    """Whether a committed run still speaks for HEAD is DERIVED from git, and rendered in its own
    ADVISORY region so a git-less clone can still pass `--check`. Both directions matter: it must not
    under-claim once a run log at HEAD exists, and it must stop claiming the moment verified source
    moves. Neither is checkable by eye, so gate both -- including that the region stays advisory,
    which is the regression that motivated the split."""

    def test_verified_paths_are_the_proof_bearing_ones(self):
        # If this list ever silently widened to include docs, a docs commit would invalidate a run
        # log and the manifest would start disclaiming for no reason.
        self.assertEqual(sorted(gen.VERIFIED_PATHS), ['der-verified/src', 'lean'])

    @contextlib.contextmanager
    def _throwaway_repo(self):
        """A disposable git repo carrying the VERIFIED_PATHS layout, with `gen.ROOT` pointed at it.

        These two tests MUST NOT read the developer's own checkout. `verified_source_unchanged_since`
        compares the commit against the WORKING TREE, not against HEAD (31b0994, so the manifest
        stops claiming currency the moment verified source is edited rather than one commit later).
        Against the real repo, "HEAD vs HEAD" is therefore false whenever anything under
        `der-verified/src` or `lean/` is uncommitted -- which is true during *every* commit that
        touches proof-bearing source, i.e. exactly when this gate runs from the pre-commit hook.

        That is not hypothetical. 31b0994 changed the semantics without changing this test, and the
        pair went unnoticed because no commit touched a VERIFIED_PATH in between. The next one that
        did was blocked by its own gate, with a self-test failure that pointed at nothing real.
        """
        with tempfile.TemporaryDirectory() as tmp:
            def run(*args):
                return subprocess.run(['git', '-C', tmp, *args],
                                      capture_output=True, text=True, check=True).stdout.strip()
            run('init', '-q')
            run('config', 'user.email', 'test@example.invalid')
            run('config', 'user.name', 'test')
            for rel in gen.VERIFIED_PATHS:
                os.makedirs(os.path.join(tmp, rel), exist_ok=True)
                with open(os.path.join(tmp, rel, 'seed.txt'), 'w', encoding='utf-8') as fh:
                    fh.write('seed\n')
            run('add', '-A')
            run('commit', '-qm', 'seed')
            original_root = gen.ROOT
            gen.ROOT = tmp
            try:
                yield tmp, run
            finally:
                gen.ROOT = original_root

    def test_unchanged_since_head_is_true(self):
        # Clean tree, HEAD vs HEAD: nothing has changed.
        with self._throwaway_repo() as (_tmp, run):
            self.assertTrue(gen.verified_source_unchanged_since(run('rev-parse', 'HEAD')))

    def test_uncommitted_edit_to_verified_source_reads_as_changed(self):
        # The direction 31b0994 actually bought, and the one nothing covered: an UNCOMMITTED edit
        # under a VERIFIED_PATH must already read as superseding a run, because the pre-commit hook
        # writes this region while the change is still uncommitted.
        with self._throwaway_repo() as (tmp, run):
            head = run('rev-parse', 'HEAD')
            with open(os.path.join(tmp, gen.VERIFIED_PATHS[-1], 'seed.txt'), 'a',
                      encoding='utf-8') as fh:
                fh.write('an uncommitted edit\n')
            self.assertFalse(gen.verified_source_unchanged_since(head))

    def test_unrecorded_commit_is_unknown_not_true(self):
        # Fail-open would silently upgrade an unverifiable log to "covers HEAD".
        self.assertIsNone(gen.verified_source_unchanged_since('unrecorded'))
        self.assertIsNone(gen.verified_source_unchanged_since(''))

    def test_coverage_region_claims_head_when_a_live_log_exists(self):
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': True, 'failed': 0}]}
        self.assertIn('still speaks for HEAD', '\n'.join(gen.r_evidence_coverage(f)))

    def test_coverage_region_disclaims_when_the_log_predates_a_source_change(self):
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': False, 'failed': 0}]}
        out = '\n'.join(gen.r_evidence_coverage(f))
        self.assertIn('No committed run currently speaks for HEAD', out)
        self.assertIn('superseded', out)

    def test_coverage_region_ignores_a_log_that_recorded_failures(self):
        # A run with FAILED verdicts must never be read as establishing anything.
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': True, 'failed': 2}]}
        self.assertIn('No committed run currently speaks for HEAD',
                      '\n'.join(gen.r_evidence_coverage(f)))

    def test_coverage_region_reports_unknown_rather_than_defaulting_to_yes(self):
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': None, 'failed': 0}]}
        out = '\n'.join(gen.r_evidence_coverage(f))
        self.assertIn('could not answer', out)
        self.assertNotIn('still speaks for HEAD', out)

    def test_no_evidence_says_so(self):
        self.assertIn('No committed run log', '\n'.join(gen.r_evidence_coverage({'evidence': []})))

    def test_coverage_region_is_advisory_so_a_git_less_clone_still_passes(self):
        # The regression this whole split exists to prevent.
        self.assertIn('evidence-coverage', gen.ADVISORY)

if __name__ == '__main__':
    # Default warning filters on purpose: nothing is suppressed, so a future DeprecationWarning in
    # the generator surfaces here. (The ResourceWarning flood this used to silence is gone — the
    # generator's reads now go through `read_text`, which closes the handle.)
    unittest.main(verbosity=2, argv=[sys.argv[0]] + sys.argv[1:])
