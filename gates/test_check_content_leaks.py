#!/usr/bin/env python3
"""test_check_content_leaks.py — the content-leak gate's own gate.

Every check here is a negative fixture first: a planted violation must be OBSERVED refused, layer
by layer (credential / absolute path / hashed vocabulary), in tree mode and in commit-message
mode, before the passing cases mean anything. A content gate that cannot be shown to fire is
indistinguishable from no gate — which is exactly the state this repo was in before it.

Vocabulary tests use an injected fixture token, never the real (private) list: writing a real
vocabulary word into this tracked test file would be the leak the gate exists to prevent. The
real hash list is only checked structurally (non-empty, well-formed hex).

Runs against throwaway `git init` repos in temp dirs with the module's ROOT monkeypatched — no
mutation of the real repo tree.

Run:  python3 gates/test_check_content_leaks.py      (pure stdlib; wired into check_fast.sh/check.sh)
"""
import contextlib
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


gate = _load("check_content_leaks", "check_content_leaks.py")

# Planted-violation material, built by concatenation so this file itself (scanned when SKIP_PATHS
# is not in play, e.g. by grep-happy humans) carries no directly matching string.
FAKE_AWS = "AKIA" + "ABCDEFGHIJKLMNOP"
FAKE_KEY_BLOCK = "-----BEGIN " + "RSA PRIVATE KEY-----\nMIIfake\n-----END RSA PRIVATE KEY-----\n"
FAKE_GHP = "ghp_" + "a" * 36
FAKE_HOME_PATH = "/ho" + "me/someuser/secret-checkout/notes.txt"
FAKE_USERS_PATH = "/Us" + "ers/someuser/work/notes.txt"
FAKE_TILDE_REPO = "~/re" + "po/some-private-name"
FIXTURE_VOCAB_TOKEN = "zzz_fixture_private_reponame"


def _run_git(root, *args, check=True):
    env = dict(os.environ)
    env.update(
        GIT_AUTHOR_NAME="test", GIT_AUTHOR_EMAIL="test@example.com",
        GIT_COMMITTER_NAME="test", GIT_COMMITTER_EMAIL="test@example.com",
    )
    return subprocess.run(
        ["git", "-C", str(root), *args], capture_output=True, text=True, check=check, env=env,
    )


@contextlib.contextmanager
def repo_fixture(files, extra_vocab_hashes=frozenset()):
    """A throwaway TRACKED tree: `files` = {relpath: text}, all git-added. Monkeypatches gate.ROOT
    and (additively) gate.VOCAB_HASHES so fixture tokens can be planted without real vocabulary."""
    with tempfile.TemporaryDirectory() as tmp:
        root = pathlib.Path(tmp)
        _run_git(root, "init", "-q")
        for rel, content in files.items():
            fp = root / rel
            fp.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, bytes):
                fp.write_bytes(content)
            else:
                fp.write_text(content, encoding="utf-8")
        _run_git(root, "add", "-A")
        old_root, old_vocab = gate.ROOT, gate.VOCAB_HASHES
        gate.ROOT = root
        gate.VOCAB_HASHES = old_vocab | set(extra_vocab_hashes)
        try:
            yield root
        finally:
            gate.ROOT, gate.VOCAB_HASHES = old_root, old_vocab


def run_tree():
    buf_out, buf_err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
        rc = gate.check_tree()
    return rc, buf_out.getvalue(), buf_err.getvalue()


def run_message(text):
    with tempfile.NamedTemporaryFile("w", suffix=".txt", delete=False, encoding="utf-8") as f:
        f.write(text)
        path = f.name
    try:
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = gate.check_message(path)
        return rc, buf_out.getvalue(), buf_err.getvalue()
    finally:
        os.unlink(path)


class CleanTreePasses(unittest.TestCase):
    def test_clean_repo_passes(self):
        with repo_fixture({"src/lib.rs": "pub fn f() {}\n", "README.md": "a der crate\n"}):
            rc, out, err = run_tree()
        self.assertEqual(rc, 0, err)
        self.assertIn("PASS check_content_leaks", out)


class PlantedCredentialsRefused(unittest.TestCase):
    def test_aws_key_in_source_fails_naming_file_and_layer(self):
        with repo_fixture({"src/lib.rs": f"const K: &str = \"{FAKE_AWS}\";\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("src/lib.rs", err)
        self.assertIn("credential:aws-akia", err)

    def test_private_key_block_in_docs_fails(self):
        with repo_fixture({"docs/example.md": FAKE_KEY_BLOCK}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("credential:private-key", err)

    def test_github_pat_fails(self):
        with repo_fixture({"notes.txt": FAKE_GHP + "\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("credential:github-pat", err)

    def test_credential_in_evidence_log_STILL_fails(self):
        # the evidence/ exemption is for paths only — key material is a leak anywhere
        with repo_fixture({"evidence/run-1234.log": f"captured: {FAKE_AWS}\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("evidence/run-1234.log", err)
        self.assertIn("credential:aws-akia", err)


class PlantedPathsRefused(unittest.TestCase):
    def test_home_path_in_source_fails(self):
        with repo_fixture({"src/lib.rs": f"// see {FAKE_HOME_PATH}\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("path:abs-home", err)

    def test_users_path_in_docs_fails(self):
        with repo_fixture({"docs/build.md": f"built at {FAKE_USERS_PATH}\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("path:abs-users", err)

    def test_tilde_repo_fails(self):
        with repo_fixture({"TODO.md": f"sync from {FAKE_TILDE_REPO}\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("path:tilde-repo", err)

    def test_path_in_evidence_log_exempt_passes(self):
        with repo_fixture({"evidence/check-abc.log": f"Compiling at {FAKE_HOME_PATH}\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 0, err)

    def test_path_in_evidence_md_exempt_passes(self):
        # the exemption is the whole directory (verbatim-capture write-ups are .md), not *.log
        with repo_fixture({"evidence/FLOOR.md": f"ran `{FAKE_HOME_PATH}` sequentially\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 0, err)


class PlantedVocabularyRefused(unittest.TestCase):
    def test_fixture_token_fails_without_printing_the_word(self):
        h = gate.hash_token(FIXTURE_VOCAB_TOKEN)
        with repo_fixture(
            {"src/lib.rs": f"// borrowed from {FIXTURE_VOCAB_TOKEN}\n"}, extra_vocab_hashes={h}
        ):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("vocabulary:hashed-token", err)
        self.assertNotIn(FIXTURE_VOCAB_TOKEN, err)  # firing must not re-leak the word

    def test_fixture_token_case_insensitive(self):
        h = gate.hash_token(FIXTURE_VOCAB_TOKEN)
        with repo_fixture(
            {"notes.md": FIXTURE_VOCAB_TOKEN.upper() + "\n"}, extra_vocab_hashes={h}
        ):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("vocabulary:hashed-token", err)

    def test_vocab_fires_even_inside_evidence(self):
        # path exemption must not bleed into the vocabulary layer
        h = gate.hash_token(FIXTURE_VOCAB_TOKEN)
        with repo_fixture(
            {"evidence/run.log": f"cloned {FIXTURE_VOCAB_TOKEN} first\n"}, extra_vocab_hashes={h}
        ):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("vocabulary:hashed-token", err)

    def test_real_hash_list_is_nonempty_wellformed_hex(self):
        self.assertGreater(len(gate.VOCAB_HASHES), 0)
        for h in gate.VOCAB_HASHES:
            self.assertRegex(h, r"^[0-9a-f]{64}$")


class ScopeIsTrackedFilesOnly(unittest.TestCase):
    def test_untracked_violation_passes_scope_documented(self):
        with repo_fixture({"src/lib.rs": "pub fn f() {}\n"}) as root:
            (root / "scratch.txt").write_text(f"{FAKE_AWS}\n", encoding="utf-8")  # never git-added
            rc, _out, err = run_tree()
        self.assertEqual(rc, 0, err)

    def test_binary_file_skipped_without_crash(self):
        with repo_fixture({"data.bin": b"\x00\xff\xfe" + bytes(range(256))}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 0, err)

    def test_gate_and_test_skipped_by_exact_relpath_only(self):
        # same basename OUTSIDE gates/ must NOT inherit the skip
        with repo_fixture({"src/check_content_leaks.py": f"# {FAKE_HOME_PATH}\n"}):
            rc, _out, err = run_tree()
        self.assertEqual(rc, 1)
        self.assertIn("path:abs-home", err)

    def test_not_a_git_repo_fails_closed(self):
        with tempfile.TemporaryDirectory() as tmp:
            old_root = gate.ROOT
            gate.ROOT = pathlib.Path(tmp)  # plain dir, no .git
            try:
                rc, _out, err = run_tree()
            finally:
                gate.ROOT = old_root
        self.assertEqual(rc, 1)
        self.assertIn("cannot list tracked files", err)


class CommitMessageMode(unittest.TestCase):
    def test_clean_message_passes(self):
        rc, out, err = run_message("gate: add doc link check\n\nroutine wiring.\n")
        self.assertEqual(rc, 0, err)
        self.assertIn("commit message clean", out)

    def test_credential_in_message_fails(self):
        rc, _out, err = run_message(f"debug: key was {FAKE_AWS}\n")
        self.assertEqual(rc, 1)
        self.assertIn("credential:aws-akia", err)

    def test_path_in_message_fails_no_evidence_exemption(self):
        rc, _out, err = run_message(f"ran from {FAKE_HOME_PATH}\n")
        self.assertEqual(rc, 1)
        self.assertIn("path:abs-home", err)

    def test_vocab_in_message_fails(self):
        h = gate.hash_token(FIXTURE_VOCAB_TOKEN)
        old = gate.VOCAB_HASHES
        gate.VOCAB_HASHES = old | {h}
        try:
            rc, _out, err = run_message(f"port the {FIXTURE_VOCAB_TOKEN} trick\n")
        finally:
            gate.VOCAB_HASHES = old
        self.assertEqual(rc, 1)
        self.assertIn("vocabulary:hashed-token", err)
        self.assertNotIn(FIXTURE_VOCAB_TOKEN, err)

    def test_git_comment_lines_not_scanned(self):
        # git strips '#' lines before recording; a path in the status template must not block
        rc, _out, err = run_message(f"clean subject\n# On branch main {FAKE_HOME_PATH}\n")
        self.assertEqual(rc, 0, err)

    def test_missing_message_file_fails_closed(self):
        buf_out, buf_err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(buf_out), contextlib.redirect_stderr(buf_err):
            rc = gate.check_message("/nonexistent/COMMIT_EDITMSG")
        self.assertEqual(rc, 1)
        self.assertIn("cannot read", buf_err.getvalue())


class HashMaintenanceMode(unittest.TestCase):
    def test_hash_token_normalizes(self):
        self.assertEqual(gate.hash_token("  MiXeD-Case  "), gate.hash_token("mixed-case"))


if __name__ == "__main__":
    unittest.main()
