#!/usr/bin/env python3
"""Content-leak gate — the one gate that reads WHAT is committed, not whether it proves.

Every other gate in this repo checks proof/doc structure; none of them would notice a hard-coded
credential, a private absolute path, or a private working-vocabulary word sitting in tracked
source. This gate closes that class, in three layers, plus a commit-message mode (`--message`)
because message content otherwise never passes through any gate at all:

  1. credentials  — key-material / token patterns; scanned in EVERY tracked file, no exemptions.
  2. absolute paths — `/home/`, `/Users/`, `~/repo`; scanned in tracked files EXCEPT `evidence/`,
     which carries verbatim tool output (build logs and their write-ups) where machine paths are
     established precedent, not leaks. The exemption is the whole directory, deliberately:
     `evidence/FLOOR-2026-08-03.md` is a .md that quotes verbatim tool output, so an extension-based
     carve-out would be a lie about the real boundary.
  3. private vocabulary — a fixed list of estate-private names. The list is stored as SHA-256
     hashes of the normalized tokens, because a plaintext list in this public repo would itself be
     the leak this gate exists to prevent. Content is tokenized (lowercase, runs of [a-z0-9_-])
     and each token hashed and compared. Residual, stated loudly: hashes hide the words from
     casual reading only — they do not resist someone hashing a dictionary of candidate names.
     The plaintext list and its maintenance procedure live outside this repo; add a token here
     with `--hash <token>` (prints the hash to embed, never writes the word anywhere).

Scope, stated loudly: scans the WORKING-TREE content of `git ls-files`-tracked files (matching
this repo's other gates, which also read the working tree) — an untracked scratch file is out of
scope by design, and an index/worktree divergence is caught at the pre-push full run if not here.
Skips itself and its test by exact relpath (both legitimately contain the patterns as source).
Prints PASS/FAIL, exits 0/1, fails closed on git errors. Pure stdlib.

Run:  python3 gates/check_content_leaks.py                 (tree scan; wired into check_fast.sh/check.sh)
      python3 gates/check_content_leaks.py --message FILE  (commit-message scan; wired into hooks/commit-msg)
      python3 gates/check_content_leaks.py --hash TOKEN    (maintenance: print a vocab hash)
"""
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent

CREDENTIAL_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
    ("aws-akia", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("openai-sk", re.compile(r"\bsk-[A-Za-z0-9]{32,}\b")),
    ("anthropic-sk", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b")),
    ("github-pat", re.compile(r"\bghp_[A-Za-z0-9]{36}\b")),
    ("github-fine-pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]

PATH_PATTERNS = [
    ("abs-home", re.compile(r"/home/[A-Za-z0-9_.-]")),
    ("abs-users", re.compile(r"/Users/[A-Za-z0-9_.-]")),
    ("tilde-repo", re.compile(r"~/repo\b")),
]
# Whole-directory allowlist for the PATH layer only (credentials + vocabulary still scan it):
# evidence/ holds verbatim tool-output captures where machine paths are precedent, not leaks.
PATH_EXEMPT_DIRS = ("evidence/",)

# SHA-256 of normalized (strip+lowercase) private-vocabulary tokens — see module docstring for
# why hashes and where the plaintext list lives. Regenerate/extend with `--hash <token>`.
VOCAB_HASHES = {
    "d555360f87d16151970add911e4c5785cce147eaa6c909e8c1c7b06e776843fb",
    "f0435255497c74aefda7f8efb9029dc06eb3063175104cf766e89452ebc22919",
    "71a9989a4fd2b33bbcdf286980b04800a3714b165e227311bdbfbe3f3864ce94",
    "554eabe6f71c7f467dd1a2d2697617e1cb6f3f5a8911b6c1650a2cd4a1018cdf",
    "349cf9765467015a1e3cc89163cfdf471451ad5c4c63c7faed080ab58bd713c3",
    "fd65e22d139c4255e091534e8825ce34684cb03f609696049df50c2449da5902",
    "5e5b62b6117ba77578a671150ace15cea220d00dedba186ab56c816b107ccbcc",
    "4d7d4ebc2bc65ec026b2453cc0bb8fefa28fde42f4b41fc5557c7f17ea463f48",
    "ea4161e784fde57e47ab3cd34824175c45ca9bb75d97db0d822756f812a77167",
    "b6d3157581a116fd3a7da6c81ef6e6db00c2fea50757fced88bbb852d7d7fcf9",
    "78ee8eaaf7f07b7f64bfa844be7536878d2b0f9611ff395097d4deb306fecb49",
}

TOKEN_RE = re.compile(r"[a-z0-9_-]+")

# This gate and its test contain every pattern above as source/fixtures; exact relpaths only,
# so a violation cannot be smuggled by reusing the basename elsewhere in the tree.
SKIP_PATHS = {"gates/check_content_leaks.py", "gates/test_check_content_leaks.py"}


def hash_token(token):
    return hashlib.sha256(token.strip().lower().encode("utf-8")).hexdigest()


def scan_text(text, relpath=None, path_exempt=False):
    """All findings in one string: list of (relpath-or-None, layer:name, evidence)."""
    findings = []
    for name, rx in CREDENTIAL_PATTERNS:
        if rx.search(text):
            findings.append((relpath, f"credential:{name}", ""))
    if not path_exempt:
        for name, rx in PATH_PATTERNS:
            m = rx.search(text)
            if m:
                findings.append((relpath, f"path:{name}", m.group(0)))
    hits = {t for t in TOKEN_RE.findall(text.lower()) if hash_token(t) in VOCAB_HASHES}
    for _ in sorted(hits):
        # deliberately do NOT print the matched word (that would re-leak it into logs the
        # moment the gate fires in CI output someone pastes); the file+layer is enough to find it
        findings.append((relpath, "vocabulary:hashed-token", ""))
    return findings


def tracked_files():
    out = subprocess.run(
        ["git", "-C", str(ROOT), "ls-files", "-z"],
        capture_output=True, check=True,
    )
    return [p for p in out.stdout.decode("utf-8").split("\0") if p]


def check_tree():
    try:
        files = tracked_files()
    except (subprocess.CalledProcessError, OSError) as e:
        print(f"FAIL check_content_leaks: cannot list tracked files ({e})", file=sys.stderr)
        return 1
    bad, n = [], 0
    for rel in files:
        if rel in SKIP_PATHS:
            continue
        p = ROOT / rel
        try:
            text = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue  # binary or deleted-in-worktree; the full pre-push run re-covers deletions
        n += 1
        exempt = rel.startswith(PATH_EXEMPT_DIRS)
        bad.extend((rel, layer, ev) for _rel, layer, ev in scan_text(text, rel, path_exempt=exempt))
    if bad:
        lines = "\n  ".join(f"{rel}: {layer}" + (f" ({ev})" if ev else "") for rel, layer, ev in bad)
        print(f"FAIL check_content_leaks:\n  {lines}", file=sys.stderr)
        return 1
    print(
        f"PASS check_content_leaks: {n} tracked files scanned "
        f"(credentials+vocabulary everywhere; paths exempt under {', '.join(PATH_EXEMPT_DIRS)})"
    )
    return 0


def check_message(msg_path):
    try:
        text = pathlib.Path(msg_path).read_text(encoding="utf-8")
    except OSError as e:
        print(f"FAIL check_content_leaks --message: cannot read {msg_path} ({e})", file=sys.stderr)
        return 1
    # comment lines are stripped by git before the message is recorded — don't scan them
    text = "\n".join(l for l in text.splitlines() if not l.startswith("#"))
    bad = scan_text(text, path_exempt=False)  # no exemptions: a message is never a build log
    if bad:
        lines = "\n  ".join(f"commit message: {layer}" + (f" ({ev})" if ev else "") for _r, layer, ev in bad)
        print(f"FAIL check_content_leaks (commit message):\n  {lines}", file=sys.stderr)
        return 1
    print("PASS check_content_leaks: commit message clean")
    return 0


def main(argv):
    if len(argv) == 3 and argv[1] == "--message":
        return check_message(argv[2])
    if len(argv) == 3 and argv[1] == "--hash":
        print(hash_token(argv[2]))
        return 0
    if len(argv) == 1:
        return check_tree()
    print(__doc__, file=sys.stderr)
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv))
