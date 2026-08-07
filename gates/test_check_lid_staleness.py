#!/usr/bin/env python3
"""test_check_lid_staleness.py — the lid-staleness gate's own gate.

`check_lid_staleness.py` is the per-commit tripwire for Aeneas/Lean-lid source drift; nothing was
stopping *it* from silently stopping to check. Both failure directions matter here in a way that's
easy to get backwards: the gate must FAIL when a lid-covered source drifts silently, and must NOT
fail (merely notice, loudly) when the drift was already acknowledged via PENDING -- get that
inverted and either every third-party clone breaks on nothing, or real drift ships unnoticed.

Runs entirely against temp-dir fixtures with the module's ROOT/STATE_FILE monkeypatched -- no
mutation of the real repo tree or its real lean/lid-source-state.txt.

Run:  python3 gates/test_check_lid_staleness.py      (pure stdlib; wired into check_fast.sh/check.sh)
"""
import contextlib
import hashlib
import importlib.util
import io
import os
import pathlib
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gate = _load("check_lid_staleness", "check_lid_staleness.py")


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@contextlib.contextmanager
def fixture(state_text, files):
    """A throwaway repo root: `files` = {relpath: content}. Writes lean/lid-source-state.txt."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "lean").mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            fp = root / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(content)
        state_file = root / "lean" / "lid-source-state.txt"
        state_file.write_text(state_text, encoding="utf-8")

        old_root, old_state = gate.ROOT, gate.STATE_FILE
        gate.ROOT, gate.STATE_FILE = root, state_file
        try:
            yield root, state_file
        finally:
            gate.ROOT, gate.STATE_FILE = old_root, old_state


def run_check(**kwargs):
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        rc = gate.check(**kwargs)
    return rc, buf_out.getvalue(), buf_err.getvalue()


class MatchingState(unittest.TestCase):
    def test_matching_hash_passes(self):
        content = b"pub fn decode_length() {}\n"
        state = f"{sha256(content)}  der-verified/src/length.rs\n"
        with fixture(state, {"der-verified/src/length.rs": content}):
            rc, out, err = run_check()
        self.assertEqual(rc, 0, err)
        self.assertIn("PASS check_lid_staleness", out)


class SilentDrift(unittest.TestCase):
    def test_changed_file_fails_and_names_it(self):
        content = b"pub fn decode_length() {}\n"
        stale_hash = sha256(b"pub fn decode_length_OLD() {}\n")
        state = f"{stale_hash}  der-verified/src/length.rs\n"
        with fixture(state, {"der-verified/src/length.rs": content}):
            rc, out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("length.rs", err)
        self.assertIn("drifted", err)

    def test_strict_mode_still_fails_on_silent_drift(self):
        content = b"pub fn decode_length() {}\n"
        stale_hash = sha256(b"pub fn decode_length_OLD() {}\n")
        state = f"{stale_hash}  der-verified/src/length.rs\n"
        with fixture(state, {"der-verified/src/length.rs": content}):
            rc, _out, err = run_check(strict=True)
        self.assertEqual(rc, 1)
        self.assertIn("length.rs", err)


class PendingAcknowledgment(unittest.TestCase):
    def test_valid_pending_passes_nonstrict_with_notice(self):
        content = b"pub fn decode_tag() {}\n"
        state = f"PENDING {sha256(content)}  der-verified/src/tag.rs\n"
        with fixture(state, {"der-verified/src/tag.rs": content}):
            rc, out, err = run_check()
        self.assertEqual(rc, 0, err)
        self.assertIn("STALE:", out)
        self.assertIn("tag.rs", out)

    def test_valid_pending_fails_strict(self):
        content = b"pub fn decode_tag() {}\n"
        state = f"PENDING {sha256(content)}  der-verified/src/tag.rs\n"
        with fixture(state, {"der-verified/src/tag.rs": content}):
            rc, _out, err = run_check(strict=True)
        self.assertEqual(rc, 1)
        self.assertIn("tag.rs", err)

    def test_stale_pending_fails_even_nonstrict(self):
        # Acknowledged at an old hash, then the file moved AGAIN -- the acknowledgment itself is stale.
        acked_content = b"pub fn decode_tag() {}\n"
        newer_content = b"pub fn decode_tag() { /* changed again */ }\n"
        state = f"PENDING {sha256(acked_content)}  der-verified/src/tag.rs\n"
        with fixture(state, {"der-verified/src/tag.rs": newer_content}):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("tag.rs", err)
        self.assertIn("itself", err)


class FailClosed(unittest.TestCase):
    def test_malformed_line_fails(self):
        with fixture("not-a-valid-line\n", {}):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("malformed", err)

    def test_duplicate_path_fails(self):
        content = b"x\n"
        h = sha256(content)
        state = f"{h}  der-verified/src/length.rs\n{h}  der-verified/src/length.rs\n"
        with fixture(state, {"der-verified/src/length.rs": content}):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("duplicate", err.lower())

    def test_missing_listed_file_fails(self):
        h = sha256(b"anything\n")
        state = f"{h}  der-verified/src/nonexistent.rs\n"
        with fixture(state, {}):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("nonexistent.rs", err)

    def test_empty_state_file_fails(self):
        with fixture("# only comments, no entries\n", {}):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)

    def test_missing_state_file_fails(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            old_root, old_state = gate.ROOT, gate.STATE_FILE
            gate.ROOT, gate.STATE_FILE = root, root / "lean" / "lid-source-state.txt"
            try:
                rc, _out, err = run_check()
            finally:
                gate.ROOT, gate.STATE_FILE = old_root, old_state
        self.assertEqual(rc, 1)
        self.assertIn("missing", err)


class Acknowledge(unittest.TestCase):
    def test_ack_rewrites_the_line_pending_at_current_hash(self):
        old_hash = sha256(b"old content\n")
        new_content = b"new content\n"
        state = f"{old_hash}  der-verified/src/tag.rs\n"
        with fixture(state, {"der-verified/src/tag.rs": new_content}) as (root, state_file):
            rc = gate.cmd_ack("der-verified/src/tag.rs")
            self.assertEqual(rc, 0)
            rewritten = state_file.read_text(encoding="utf-8")
            self.assertIn(f"PENDING {sha256(new_content)}  der-verified/src/tag.rs", rewritten)
            # And the gate now passes non-strict (with a notice) on the acknowledged file.
            rc2, out, err = run_check()
            self.assertEqual(rc2, 0, err)
            self.assertIn("STALE:", out)


if __name__ == "__main__":
    unittest.main()
