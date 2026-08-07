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
import subprocess
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


def _basenames_from_state_text(state_text):
    """Best-effort extraction of the path basenames a (possibly malformed) state fixture names --
    used only to auto-generate a matching lean/check_lean.sh so single-file fixtures that don't
    care about the expected-set check keep working unchanged."""
    names = []
    for raw in state_text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("PENDING "):
            line = line[len("PENDING "):].strip()
        parts = line.split(None, 1)
        if len(parts) == 2:
            names.append(os.path.basename(parts[1].strip()))
    return names


@contextlib.contextmanager
def fixture(state_text, files, check_lean_sh=None):
    """A throwaway repo root: `files` = {relpath: content}. Writes lean/lid-source-state.txt and,
    unless `check_lean_sh` is given explicitly, a lean/check_lean.sh whose check_drift(...) calls
    match the state fixture's own paths one-for-one (so the new expected-set check is a no-op for
    fixtures that aren't specifically testing it)."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        (root / "lean").mkdir(parents=True, exist_ok=True)
        for rel, content in files.items():
            fp = root / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            fp.write_bytes(content)
        state_file = root / "lean" / "lid-source-state.txt"
        state_file.write_text(state_text, encoding="utf-8")

        if check_lean_sh is None:
            names = _basenames_from_state_text(state_text)
            check_lean_sh = "".join(
                f'check_drift Model{i} "{name}"\n' for i, name in enumerate(names)
            )
        check_lean_file = root / "lean" / "check_lean.sh"
        check_lean_file.write_text(check_lean_sh, encoding="utf-8")

        old_root, old_state, old_check_lean = gate.ROOT, gate.STATE_FILE, gate.CHECK_LEAN_SH
        gate.ROOT, gate.STATE_FILE, gate.CHECK_LEAN_SH = root, state_file, check_lean_file
        try:
            yield root, state_file
        finally:
            gate.ROOT, gate.STATE_FILE, gate.CHECK_LEAN_SH = old_root, old_state, old_check_lean


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


class ExpectedSourceSet(unittest.TestCase):
    def test_missing_expected_source_fails_naming_it(self):
        content = b"pub fn decode_tag() {}\n"
        state = f"{sha256(content)}  der-verified/src/tag.rs\n"
        # check_lean.sh declares TWO sources; the state file only lists one.
        check_lean_sh = (
            'check_drift DerTagExtract "tag.rs"\n'
            'check_drift DerLengthExtract "length.rs"\n'
        )
        with fixture(state, {"der-verified/src/tag.rs": content}, check_lean_sh=check_lean_sh):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("missing", err)
        self.assertIn("length.rs", err)

    def test_extra_unexpected_source_fails_naming_it(self):
        tag_content = b"pub fn decode_tag() {}\n"
        extra_content = b"pub fn extra() {}\n"
        state = (
            f"{sha256(tag_content)}  der-verified/src/tag.rs\n"
            f"{sha256(extra_content)}  der-verified/src/extra.rs\n"
        )
        # check_lean.sh only declares tag.rs; extra.rs is not a real check_drift source.
        check_lean_sh = 'check_drift DerTagExtract "tag.rs"\n'
        with fixture(
            state,
            {"der-verified/src/tag.rs": tag_content, "der-verified/src/extra.rs": extra_content},
            check_lean_sh=check_lean_sh,
        ):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("unexpected", err)
        self.assertIn("extra.rs", err)

    def test_check_lean_sh_missing_fails_closed(self):
        content = b"pub fn decode_tag() {}\n"
        state = f"{sha256(content)}  der-verified/src/tag.rs\n"
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            (root / "lean").mkdir(parents=True)
            (root / "der-verified" / "src").mkdir(parents=True)
            (root / "der-verified" / "src" / "tag.rs").write_bytes(content)
            state_file = root / "lean" / "lid-source-state.txt"
            state_file.write_text(state, encoding="utf-8")
            # Deliberately no lean/check_lean.sh written.
            old_root, old_state, old_check_lean = gate.ROOT, gate.STATE_FILE, gate.CHECK_LEAN_SH
            gate.ROOT, gate.STATE_FILE = root, state_file
            gate.CHECK_LEAN_SH = root / "lean" / "check_lean.sh"
            try:
                rc, _out, err = run_check()
            finally:
                gate.ROOT, gate.STATE_FILE, gate.CHECK_LEAN_SH = old_root, old_state, old_check_lean
        self.assertEqual(rc, 1)
        self.assertIn("check_lean.sh", err)

    def test_check_lean_sh_with_no_check_drift_calls_fails_closed(self):
        content = b"pub fn decode_tag() {}\n"
        state = f"{sha256(content)}  der-verified/src/tag.rs\n"
        with fixture(
            state, {"der-verified/src/tag.rs": content}, check_lean_sh="# nothing here\n"
        ):
            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("check_drift", err)


def _run_git(root, *args, check=True):
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="test", GIT_AUTHOR_EMAIL="test@example.com",
        GIT_COMMITTER_NAME="test", GIT_COMMITTER_EMAIL="test@example.com",
    )
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=check, env=env,
    )


class GitIndexWorktreeDivergence(unittest.TestCase):
    def test_staged_source_with_unstaged_ack_fails(self):
        old_content = b"pub fn decode_tag() {}\n"
        new_content = b"pub fn decode_tag() { /* edited */ }\n"
        state = f"{sha256(old_content)}  der-verified/src/tag.rs\n"
        check_lean_sh = 'check_drift DerTagExtract "tag.rs"\n'
        with fixture(
            state, {"der-verified/src/tag.rs": old_content}, check_lean_sh=check_lean_sh
        ) as (root, state_file):
            _run_git(root, "init", "-q")
            _run_git(root, "add", "-A")
            _run_git(root, "commit", "-q", "-m", "baseline")

            # Stage a lid-source edit (the commit-to-be will carry the NEW content)...
            (root / "der-verified" / "src" / "tag.rs").write_bytes(new_content)
            _run_git(root, "add", "der-verified/src/tag.rs")
            # ...and "--ack" it in the working tree only (mirrors cmd_ack, which never stages).
            state_file.write_text(f"PENDING {sha256(new_content)}  der-verified/src/tag.rs\n", encoding="utf-8")

            rc, _out, err = run_check()
        self.assertEqual(rc, 1)
        self.assertIn("index/worktree divergence", err)
        self.assertIn("lid-source-state.txt", err)

    def test_fully_staged_and_committed_state_passes(self):
        content = b"pub fn decode_tag() {}\n"
        state = f"{sha256(content)}  der-verified/src/tag.rs\n"
        check_lean_sh = 'check_drift DerTagExtract "tag.rs"\n'
        with fixture(
            state, {"der-verified/src/tag.rs": content}, check_lean_sh=check_lean_sh
        ) as (root, _state_file):
            _run_git(root, "init", "-q")
            _run_git(root, "add", "-A")
            _run_git(root, "commit", "-q", "-m", "baseline")
            rc, _out, err = run_check()
        self.assertEqual(rc, 0, err)


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
