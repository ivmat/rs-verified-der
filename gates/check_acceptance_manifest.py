#!/usr/bin/env python3
"""Validate the generated acceptance manifest against the pinned closure.

The validator is fully vendored so the gate is reproducible offline. Before it
runs, the closure verifier checks CLOSURE.json, every manifested source file,
the source commit, and clean export provenance. The manifest's generated
header must name the same protocol commit.
"""
import os
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "der-verified"
MANIFEST = PACKAGE / "acceptance.toml"
VENDOR = ROOT / "gates" / "vendor" / "acceptance"
EXPORTER = VENDOR / "export_closure.py"
VALIDATOR = VENDOR / "format_acceptance" / "tools" / "check_acceptance.py"
CLOSURE = VENDOR / "CLOSURE.json"
VENDOR_DOC = ROOT / "gates" / "vendor" / "VENDOR.md"
STORE = PACKAGE / "evidence" / "acceptance-records"
# Public ivmat/acceptance-format commit the vendored closure is pinned to (family
# version 0.3.2; this commit carries no git tag in that repository).
PINNED_PROTOCOL_COMMIT = "455ca4f84ada3fc51eed30942696f34d118e1a59"
_MANIFEST_PIN_RE = re.compile(
    r"^# Checked against acceptance 0\.3\.2, ivmat/acceptance-format commit "
    r"([0-9a-f]{40})$",
    re.MULTILINE,
)


def fail(message):
    print(f"FAIL check_acceptance_manifest: {message}", file=sys.stderr)
    return 1


def run_vendored(command):
    env = os.environ.copy()
    env["PYTHONDONTWRITEBYTECODE"] = "1"
    return subprocess.run(command, capture_output=True, text=True, env=env)


def main():
    for path, label in (
        (MANIFEST, "manifest"),
        (EXPORTER, "vendored closure verifier"),
        (VALIDATOR, "vendored validator"),
        (CLOSURE, "closure manifest"),
        (VENDOR_DOC, "vendor note"),
        (STORE, "projected evidence store"),
    ):
        if not path.exists():
            return fail(f"{label} missing at {path.relative_to(ROOT)}")

    vendor_note = VENDOR_DOC.read_text(encoding="utf-8")
    if PINNED_PROTOCOL_COMMIT not in vendor_note:
        return fail(
            f"gates/vendor/VENDOR.md does not record pinned protocol commit "
            f"{PINNED_PROTOCOL_COMMIT!r}"
        )

    verified = run_vendored([
        sys.executable, "-B", str(EXPORTER), "verify", "--dest", str(VENDOR),
        "--expect-commit", PINNED_PROTOCOL_COMMIT, "--require-clean",
    ])
    verified_output = (verified.stdout + verified.stderr).strip()
    if verified.returncode != 0:
        return fail(f"vendored closure verification failed:\n{verified_output}")

    text = MANIFEST.read_text(encoding="utf-8")
    match = _MANIFEST_PIN_RE.search(text)
    if not match:
        return fail(
            "acceptance.toml does not declare its acceptance 0.3.2 protocol commit in "
            "the generated header"
        )
    declared = match.group(1)
    if declared != PINNED_PROTOCOL_COMMIT:
        return fail(
            f"acceptance.toml was generated against protocol commit {declared!r} but "
            f"the verified closure is pinned to {PINNED_PROTOCOL_COMMIT!r}; re-emit the "
            "manifest or re-vendor the closure rather than editing either to agree"
        )

    first_line = next((line for line in text.splitlines() if line.strip()), "")
    if "DO NOT HAND-EDIT" not in first_line.upper():
        return fail(
            "acceptance.toml does not open with its generated-file banner; it is emitted, "
            "never hand-written"
        )

    cited = set()
    for record_match in re.finditer(r'^\s*record\s*=\s*"([^"]+)"', text, re.MULTILINE):
        relative = record_match.group(1)
        path = (MANIFEST.parent / relative).resolve()
        if not path.is_file():
            return fail(f"acceptance.toml cites a record that does not resolve: {relative!r}")
        try:
            path.relative_to(STORE.resolve())
        except ValueError:
            return fail(
                f"acceptance.toml cites a record outside the published evidence store: "
                f"{relative!r}"
            )
        cited.add(path)
    if not cited:
        return fail("acceptance.toml cites no evidence records")

    orphans = sorted(path.name for path in {p.resolve() for p in STORE.glob("*.json")} - cited)
    if orphans:
        return fail(
            f"{len(orphans)} projected record(s) are not cited by acceptance.toml: "
            f"{orphans[:5]}{' ...' if len(orphans) > 5 else ''}"
        )

    result = run_vendored([
        sys.executable, "-B", str(VALIDATOR), "--strict", "--strict-weight", str(MANIFEST),
    ])
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        return fail(f"vendored validator rejected acceptance.toml:\n{output}")
    summary = output.splitlines()[-1] if output else "(no output)"
    print(f"PASS check_acceptance_manifest: {summary}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
