#!/usr/bin/env python3
"""Gate: the six Aeneas/Lean-lid source files have not drifted since the last green Lean run.

Aeneas embeds source LINE SPANS in what it extracts, so even a docs-only edit to one of the six
lid-covered files (see `lean/check_lean.sh`'s own `check_drift` calls) breaks the extracted model
-- but that gate is minutes-long and lives only in the full `check.sh`, not the per-commit
`check_fast.sh`. This is the missing per-commit signal: cheap (six sha256 reads, pure stdlib), it
cannot re-verify anything through Lean, so it only ever claims "source changed since the last
green Lean run" or "source unchanged" -- never "still proves". Toolchain drift (Aeneas/Charon pin
mismatch) stays exclusively the full gate's job; this gate does not touch it.

State lives in `lean/lid-source-state.txt` (committed; see its own header for the line format).
`lean/check_lean.sh` is the ONLY writer on a full green run -- this script only reads it, so the
list of which files matter is never a second hand-maintained copy.

Usage:
    python3 gates/check_lid_staleness.py             # normal: PENDING lines pass (with a notice)
    python3 gates/check_lid_staleness.py --strict     # PENDING lines also FAIL (used by check.sh)
    python3 gates/check_lid_staleness.py --ack PATH   # admin: mark PATH's line PENDING at its
                                                       # CURRENT hash (documented remedy 2)
"""
import hashlib
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
STATE_FILE = ROOT / "lean" / "lid-source-state.txt"
CHECK_LEAN_SH = ROOT / "lean" / "check_lean.sh"

_HEXDIGITS = frozenset("0123456789abcdef")
_CHECK_DRIFT_RE = re.compile(r'check_drift\s+\S+\s+"([^"]+)"')


class ParseError(Exception):
    pass


def sha256_of(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_state(text: str):
    """Return a list of {'pending', 'hash', 'path', 'lineno'} dicts, or raise ParseError."""
    entries = []
    seen_paths = set()
    for lineno, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        pending = False
        rest = line
        if rest.startswith("PENDING "):
            pending = True
            rest = rest[len("PENDING "):].strip()
        parts = rest.split(None, 1)
        if len(parts) != 2:
            raise ParseError(f"line {lineno}: malformed (want '<sha256>  <path>'): {raw!r}")
        digest, path = parts[0].strip().lower(), parts[1].strip()
        if len(digest) != 64 or set(digest) - _HEXDIGITS:
            raise ParseError(f"line {lineno}: not a sha256 hex digest: {parts[0]!r}")
        if not path:
            raise ParseError(f"line {lineno}: empty path")
        if path in seen_paths:
            raise ParseError(f"line {lineno}: duplicate entry for {path!r}")
        seen_paths.add(path)
        entries.append({"pending": pending, "hash": digest, "path": path, "lineno": lineno})
    if not entries:
        raise ParseError("state file has no lid-source entries")
    return entries


def derive_expected_paths():
    """Return the set of repo-relative lid-source paths derived from `lean/check_lean.sh`'s own
    `check_drift <Model> "<file>"` calls -- check_lean.sh stays the single source of truth for
    WHICH files are lid-covered (see DECISIONS.md D29); this gate must never grow a second,
    silently-driftable hand-maintained list. Raises ParseError (fail closed) if check_lean.sh is
    missing or no check_drift(...) calls can be found in it -- an empty derived set is never
    treated as "nothing to check".
    """
    if not CHECK_LEAN_SH.exists():
        raise ParseError(f"cannot derive expected lid sources: missing {CHECK_LEAN_SH}")
    text = CHECK_LEAN_SH.read_text(encoding="utf-8")
    basenames = set()
    for match in _CHECK_DRIFT_RE.finditer(text):
        for part in match.group(1).split("/"):
            part = part.strip()
            if part:
                basenames.add(part)
    if not basenames:
        raise ParseError(
            f"cannot derive expected lid sources: no check_drift(...) calls found in {CHECK_LEAN_SH}"
        )
    return {f"der-verified/src/{name}" for name in basenames}


def _in_git_checkout() -> bool:
    try:
        proc = subprocess.run(
            ["git", "-C", str(ROOT), "rev-parse", "--is-inside-work-tree"],
            capture_output=True, text=True,
        )
    except FileNotFoundError:
        return False
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def git_diverged_paths(rel_paths):
    """Repo-relative `rel_paths` (relative to ROOT) whose git INDEX content differs from the
    current WORKING TREE content right now -- i.e. an unstaged change against what a `git commit`
    would actually record. Returns None if ROOT is not inside a git checkout (or git itself is
    unavailable): callers must degrade gracefully in that case -- the hash check still runs
    regardless, this is an additional signal, not a replacement for it.

    This is what closes the index/worktree lying scenario: stage a lid-source edit, `--ack` it
    (which only touches the WORKING TREE), and commit without `git add`-ing the state file too --
    the commit would then carry drifted source alongside the OLD (unstaged) baseline. If the state
    file (or any covered source) still differs between the index and the working tree, that
    divergence would survive into the commit unexamined, so this fails loudly instead.
    """
    if not _in_git_checkout():
        return None
    proc = subprocess.run(
        ["git", "-C", str(ROOT), "diff", "--name-only", "--", *rel_paths],
        capture_output=True, text=True,
    )
    if proc.returncode != 0:
        return None
    changed = {line.strip() for line in proc.stdout.splitlines() if line.strip()}
    return sorted(p for p in rel_paths if p in changed)


def check(strict: bool = False) -> int:
    if not STATE_FILE.exists():
        print(f"FAIL check_lid_staleness: state file missing: {STATE_FILE}", file=sys.stderr)
        return 1

    try:
        entries = parse_state(STATE_FILE.read_text(encoding="utf-8"))
    except ParseError as exc:
        print(f"FAIL check_lid_staleness: malformed {STATE_FILE.name}: {exc}", file=sys.stderr)
        return 1

    problems = []

    try:
        expected_paths = derive_expected_paths()
    except ParseError as exc:
        print(f"FAIL check_lid_staleness: {exc}", file=sys.stderr)
        return 1

    state_paths = {e["path"] for e in entries}
    missing = sorted(expected_paths - state_paths)
    extra = sorted(state_paths - expected_paths)
    if missing or extra:
        problems.append(
            f"{STATE_FILE.name}'s source set doesn't match lean/check_lean.sh's check_drift(...) sources"
        )
        for p in missing:
            problems.append(f"  missing from {STATE_FILE.name} (a check_drift source with no line): {p}")
        for p in extra:
            problems.append(f"  unexpected in {STATE_FILE.name} (not a check_drift source): {p}")

    state_rel_path = str(STATE_FILE.relative_to(ROOT))
    covered_paths = sorted(state_paths | {state_rel_path})
    diverged = git_diverged_paths(covered_paths)
    if diverged is None:
        pass  # not a git checkout (or git unavailable): index/worktree divergence check skipped
    elif diverged:
        problems.append(
            "index/worktree divergence on " + ", ".join(diverged) + " -- unstaged changes on a "
            "covered path would NOT be included in a `git commit` right now, so the commit could "
            "land with drifted source alongside an old (or stale-ack'd) baseline. `git add` "
            + ", ".join(diverged) + " too before committing. (If this fires right after a green "
            "lean/check_lean.sh run and the diverged path is lean/lid-source-state.txt itself, "
            "that is the expected, correct failure: check_lean.sh only rewrites that file when the "
            "hashes actually changed, so `git add` it and commit -- this is not a false positive.)"
        )
    stale_notices = []
    strict_pending = []

    for e in entries:
        p = ROOT / e["path"]
        if not p.exists():
            problems.append(
                f"{e['path']}: listed as a lid source (line {e['lineno']}) but the file is gone"
            )
            continue
        current = sha256_of(p)
        if e["pending"]:
            if current != e["hash"]:
                problems.append(
                    f"{e['path']}: PENDING acknowledgment is itself stale (line {e['lineno']}) -- "
                    "the file changed again after being acknowledged"
                )
            else:
                stale_notices.append(e["path"])
                if strict:
                    strict_pending.append(e["path"])
        else:
            if current != e["hash"]:
                problems.append(
                    f"{e['path']}: drifted from the recorded Lean-lid hash (line {e['lineno']})"
                )

    if problems:
        print("FAIL check_lid_staleness:", file=sys.stderr)
        for msg in problems:
            print(f"  {msg}", file=sys.stderr)
        print("", file=sys.stderr)
        print("  remedy 1 (preferred): run `sh lean/check_lean.sh` -- a full green run", file=sys.stderr)
        print("  re-verifies through Lean and rewrites lean/lid-source-state.txt itself.", file=sys.stderr)
        print("  remedy 2 (acknowledge the drift, Lean re-verification still owed):", file=sys.stderr)
        print("    python3 gates/check_lid_staleness.py --ack <repo-relative-path>", file=sys.stderr)
        return 1

    if strict_pending:
        print("FAIL check_lid_staleness --strict: PENDING lid(s) not allowed here:", file=sys.stderr)
        for path in strict_pending:
            print(f"  {path}", file=sys.stderr)
        print("  (this mode runs right after a green Lean run, which clears PENDING itself --", file=sys.stderr)
        print("   a PENDING line surviving to here means the debt was never actually paid down)", file=sys.stderr)
        return 1

    for path in stale_notices:
        print(f"STALE: {path} is PENDING Lean re-verification (drift acknowledged, not yet re-proved)")

    print(f"PASS check_lid_staleness: {len(entries)} lid-covered source(s) match the recorded state")
    return 0


def cmd_ack(rel_path: str) -> int:
    p = ROOT / rel_path
    if not p.exists():
        print(f"error: no such file: {rel_path}", file=sys.stderr)
        return 1
    if not STATE_FILE.exists():
        print(f"error: state file missing: {STATE_FILE}", file=sys.stderr)
        return 1

    text = STATE_FILE.read_text(encoding="utf-8")
    out_lines = []
    found = False
    for raw in text.splitlines(keepends=True):
        stripped = raw.strip()
        body = stripped
        if body.startswith("PENDING "):
            body = body[len("PENDING "):].strip()
        parts = body.split(None, 1)
        if len(parts) == 2 and parts[1].strip() == rel_path:
            found = True
            digest = sha256_of(p)
            out_lines.append(f"PENDING {digest}  {rel_path}\n")
        else:
            out_lines.append(raw)

    if not found:
        print(f"error: {rel_path!r} is not a listed lid source in {STATE_FILE}", file=sys.stderr)
        return 1

    STATE_FILE.write_text("".join(out_lines), encoding="utf-8")
    print(f"acknowledged: {rel_path} marked PENDING at its current hash (Lean re-verification still owed)")
    return 0


def main(argv) -> int:
    if "--ack" in argv:
        idx = argv.index("--ack")
        if idx + 1 >= len(argv):
            print("usage: check_lid_staleness.py --ack <repo-relative-path>", file=sys.stderr)
            return 2
        return cmd_ack(argv[idx + 1])
    return check(strict="--strict" in argv)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
