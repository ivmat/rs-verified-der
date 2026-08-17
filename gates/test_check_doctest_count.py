#!/usr/bin/env python3
"""test_check_doctest_count.py — the measured-doctest-count gate's own gate.

`check_doctest_count.py` is the structural backstop against `gen_proof_manifest.py`'s static
doctest scanner missing (or over-recognising) some doc-comment SHAPE -- see that script's own
header for why a purely regex-based approach cannot close this class of bug by itself. Nothing was
stopping *this* gate from getting its own parsing wrong, or from being silently skipped, or from
comparing against the wrong reference -- both directions are tested here, same discipline as
`test_gen_proof_manifest.py`.

Run:  python3 gates/test_check_doctest_count.py      (pure stdlib except real cargo calls in the
                                                        two tests explicitly marked "against the
                                                        real repo"; wired into check_fast.sh/check.sh)
"""
import contextlib
import importlib.util
import io
import os
import subprocess
import unittest
import unittest.mock as mock

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load('check_doctest_count', 'check_doctest_count.py')


def _completed(stdout='', returncode=0):
    return subprocess.CompletedProcess(args=['cargo'], returncode=returncode,
                                       stdout=stdout, stderr='')


class SummaryLineParsing(unittest.TestCase):
    """`SUMMARY_RE` against every shape cargo's own `--list` output actually takes (verified
    against the installed toolchain -- see `check_doctest_count.py`'s module docstring)."""

    def _count(self, stdout):
        m = gate.SUMMARY_RE.search(stdout)
        self.assertIsNotNone(m, 'summary line not found in: %r' % stdout)
        return int(m.group(1))

    def test_plural_count(self):
        self.assertEqual(self._count('33 tests, 0 benchmarks\n'), 33)

    def test_singular_count_at_one(self):
        # cargo prints "1 test," (no trailing 's') when the count is exactly one -- a regex
        # anchored on "tests," (plural only) would miss this and silently treat 1 doctest as if
        # cargo reported none, which is exactly the under-triggering this gate must not do to
        # itself.
        self.assertEqual(self._count('1 test, 0 benchmarks\n'), 1)

    def test_zero_count(self):
        self.assertEqual(self._count('0 tests, 0 benchmarks\n'), 0)

    def test_summary_line_amid_other_output(self):
        # Real `--list` output has a build banner and one line per discovered test before the
        # summary; the regex must find the summary line regardless of what precedes it.
        stdout = (
            '    Finished `test` profile [unoptimized + debuginfo] target(s) in 0.02s\n'
            '   Doc-tests der_verified\n'
            'src/lib.rs - (line 154): test\n'
            'src/lib.rs - big_integer (line 30): test\n'
            '\n33 tests, 0 benchmarks\n'
        )
        self.assertEqual(self._count(stdout), 33)

    def test_no_summary_line_is_not_found(self):
        # Leniency counter-check: prose that merely MENTIONS a number near the word "tests" must
        # not be misread as the summary line.
        m = gate.SUMMARY_RE.search('this crate has roughly 33 tests, or so the README claims\n')
        self.assertIsNone(m)


class CargoInvocation(unittest.TestCase):
    """`cargo_measured_doctest_count` against a mocked `subprocess.run` -- every failure mode
    must raise `CargoListError` (fail closed), never silently return a number that isn't real."""

    def test_parses_a_successful_run(self):
        with mock.patch.object(gate.subprocess, 'run',
                               return_value=_completed('33 tests, 0 benchmarks\n')):
            self.assertEqual(gate.cargo_measured_doctest_count(), 33)

    def test_cargo_not_on_path_raises(self):
        with mock.patch.object(gate.subprocess, 'run', side_effect=FileNotFoundError('cargo')):
            with self.assertRaises(gate.CargoListError):
                gate.cargo_measured_doctest_count()

    def test_timeout_raises(self):
        with mock.patch.object(gate.subprocess, 'run',
                               side_effect=subprocess.TimeoutExpired(cmd='cargo', timeout=120)):
            with self.assertRaises(gate.CargoListError):
                gate.cargo_measured_doctest_count()

    def test_nonzero_exit_raises(self):
        with mock.patch.object(gate.subprocess, 'run',
                               return_value=_completed('error: could not compile', returncode=101)):
            with self.assertRaises(gate.CargoListError):
                gate.cargo_measured_doctest_count()

    def test_unparsable_output_raises_rather_than_defaulting(self):
        # A future cargo version changing the summary line's wording must not silently read as
        # "zero doctests" or be swallowed -- it must raise, so a human notices the format changed.
        with mock.patch.object(gate.subprocess, 'run',
                               return_value=_completed('some entirely different output shape\n')):
            with self.assertRaises(gate.CargoListError):
                gate.cargo_measured_doctest_count()

    def test_duplicate_summary_lines_raise_rather_than_take_the_first(self):
        # Release-review round 5 regression: `.search()` silently takes the FIRST match, so
        # output containing "33 tests, 0 benchmarks" followed later by "34 tests, 0 benchmarks"
        # used to read as 33 without any indication the output was ambiguous. Two summary-shaped
        # lines must raise, not silently pick either one.
        with mock.patch.object(gate.subprocess, 'run',
                               return_value=_completed(
                                   '33 tests, 0 benchmarks\n34 tests, 0 benchmarks\n')):
            with self.assertRaises(gate.CargoListError):
                gate.cargo_measured_doctest_count()

    def test_nonzero_benchmark_count_raises(self):
        # Release-review round 5 regression: the old regex matched but never checked the
        # benchmark count, so "33 tests, 2 benchmarks" was silently accepted as 33 doctests with
        # the 2 benchmarks unaccounted for. This crate has no #[bench]s; a nonzero count here must
        # raise rather than be silently ignored.
        with mock.patch.object(gate.subprocess, 'run',
                               return_value=_completed('33 tests, 2 benchmarks\n')):
            with self.assertRaises(gate.CargoListError):
                gate.cargo_measured_doctest_count()

    def test_single_summary_zero_benchmarks_still_passes(self):
        # The paired leniency check: the ordinary, expected shape (exactly one summary line,
        # zero benchmarks) must still parse cleanly -- the two checks above must not have made
        # the happy path collateral damage.
        with mock.patch.object(gate.subprocess, 'run',
                               return_value=_completed('33 tests, 0 benchmarks\n')):
            self.assertEqual(gate.cargo_measured_doctest_count(), 33)

    def test_invocation_uses_list_not_execute(self):
        # This gate's job is "how many doctests exist", not "do they pass" -- --list must never be
        # dropped, or this gate would start actually EXECUTING every doctest on every commit.
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['cmd'] = cmd
            return _completed('33 tests, 0 benchmarks\n')

        with mock.patch.object(gate.subprocess, 'run', side_effect=fake_run):
            gate.cargo_measured_doctest_count()
        self.assertIn('--list', captured['cmd'])
        self.assertIn('--doc', captured['cmd'])


class CheckOutcome(unittest.TestCase):
    """`check()`'s exit code and message -- driven with both `cargo_measured_doctest_count` and
    `static_doctest_count` mocked, so this class does not need a real cargo invocation at all."""

    def _run_check(self):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = gate.check()
        return code, out.getvalue(), err.getvalue()

    def test_agreement_passes(self):
        with mock.patch.object(gate, 'cargo_measured_doctest_count', return_value=33), \
             mock.patch.object(gate, 'static_doctest_count', return_value=33):
            code, out, err = self._run_check()
        self.assertEqual(code, 0)
        self.assertIn('PASS', out)
        self.assertEqual(err, '')

    def test_static_undercount_fails(self):
        # The exact bug class this gate exists for: the static scanner missed a real doctest
        # (a shape none of its regexes recognise), so it reports FEWER than cargo's ground truth.
        with mock.patch.object(gate, 'cargo_measured_doctest_count', return_value=36), \
             mock.patch.object(gate, 'static_doctest_count', return_value=33):
            code, out, err = self._run_check()
        self.assertEqual(code, 1)
        self.assertIn('FAIL', err)
        self.assertIn('33', err)
        self.assertIn('36', err)

    def test_static_overcount_also_fails(self):
        # The mirror-image bug (a false POSITIVE in the static scanner, e.g. a `cfg_attr(...)`
        # that merely LOOKS like it sets doc text but doesn't) must be caught too -- this gate
        # checks for disagreement in EITHER direction, not just under-counting.
        with mock.patch.object(gate, 'cargo_measured_doctest_count', return_value=30), \
             mock.patch.object(gate, 'static_doctest_count', return_value=33):
            code, out, err = self._run_check()
        self.assertEqual(code, 1)
        self.assertIn('FAIL', err)

    def test_cargo_error_fails_rather_than_skips(self):
        # If ground truth cannot be obtained at all, this must still FAIL -- silently skipping the
        # check when cargo is unavailable would defeat the entire point of a backstop.
        with mock.patch.object(gate, 'cargo_measured_doctest_count',
                               side_effect=gate.CargoListError('cargo not on PATH')):
            code, out, err = self._run_check()
        self.assertEqual(code, 1)
        self.assertIn('FAIL', err)


class AgainstTheRealRepo(unittest.TestCase):
    """Ground-truth end-to-end tests -- these DO invoke real cargo against the real repo, mirroring
    `test_gen_proof_manifest.py`'s own `test_crate_total_doctests_matches_the_measured_cargo_test_doc_count`.
    Slower than the mocked tests above (a real `cargo test --doc -- --list`), but this is the test
    that actually proves the gate's two halves (the static scan and cargo's own count) currently
    agree on the committed tree, not just that the mocking is wired up correctly.
    """

    def test_static_and_measured_counts_agree_on_head(self):
        self.assertEqual(gate.static_doctest_count(), gate.cargo_measured_doctest_count())

    def test_check_passes_on_head(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            code = gate.check()
        self.assertEqual(code, 0, out.getvalue())


if __name__ == '__main__':
    unittest.main(verbosity=2)
