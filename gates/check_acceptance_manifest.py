#!/usr/bin/env python3
"""Validate the generated acceptance manifest against the pinned closure.

The validator is fully vendored so the gate is reproducible offline. Before it
runs, the closure verifier checks CLOSURE.json, every manifested source file,
the source commit, the family version, and clean export provenance. The manifest's
generated header must name the same protocol commit.

The manifest has one claim per requirement. Its `[spec].inventory` is a mirror of
docs/requirements/der.inventory.toml kept beside the manifest (core.md B6: a pointer
must stay inside the repository, and a package unpacked from der-verified/ must still
resolve it). The mirror is hash-validated as part of the recorded snapshot. Equality with the
current canonical inventory belongs to the separate applicability/release check.
"""
import argparse
import os
import pathlib
import re
import subprocess
import sys
import tomllib

ROOT = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = ROOT / "der-verified"
MANIFEST = PACKAGE / "acceptance.toml"
VENDOR = ROOT / "gates" / "vendor" / "acceptance"
EXPORTER = VENDOR / "export_closure.py"
VALIDATOR = VENDOR / "format_acceptance" / "tools" / "check_acceptance.py"
CLOSURE = VENDOR / "CLOSURE.json"
VENDOR_DOC = ROOT / "gates" / "vendor" / "VENDOR.md"
STORE = PACKAGE / "evidence" / "acceptance-records"
INVENTORY = ROOT / "docs" / "requirements" / "der.inventory.toml"
INVENTORY_MIRROR = PACKAGE / "der.inventory.toml.vendored-copy"
# Public ivmat/acceptance-format commit the vendored closure is pinned to (family
# version 0.4.0; tag v0.4.0 in that repository).
PINNED_PROTOCOL_COMMIT = "3dbd403d0929a5398c43f93bd41a31e3365e82cd"
PINNED_FAMILY_VERSION = "0.4.0"
_MANIFEST_PIN_RE = re.compile(
    r"^# Checked against acceptance 0\.4\.0, ivmat/acceptance-format commit "
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


def validate_snapshot(root=ROOT, package=None):
    """Check the issued snapshot, independently of current-source applicability."""
    root = pathlib.Path(root).resolve()
    ROOT = root
    PACKAGE = pathlib.Path(package).resolve() if package else root / "der-verified"
    MANIFEST = PACKAGE / "acceptance.toml"
    VENDOR = root / "gates/vendor/acceptance"
    EXPORTER = VENDOR / "export_closure.py"
    VALIDATOR = VENDOR / "format_acceptance/tools/check_acceptance.py"
    CLOSURE = VENDOR / "CLOSURE.json"
    VENDOR_DOC = root / "gates/vendor/VENDOR.md"
    STORE = PACKAGE / "evidence/acceptance-records"
    INVENTORY = root / "docs/requirements/der.inventory.toml"
    INVENTORY_MIRROR = PACKAGE / "der.inventory.toml.vendored-copy"
    for path, label in (
        (MANIFEST, "manifest"),
        (EXPORTER, "vendored closure verifier"),
        (VALIDATOR, "vendored validator"),
        (CLOSURE, "closure manifest"),
        (VENDOR_DOC, "vendor note"),
        (STORE, "projected evidence store"),
        (INVENTORY, "canonical requirements inventory"),
        (INVENTORY_MIRROR, "requirements inventory mirror"),
    ):
        if not path.exists():
            return fail(f"{label} missing at {os.path.relpath(path, ROOT)}")

    vendor_note = VENDOR_DOC.read_text(encoding="utf-8")
    if PINNED_PROTOCOL_COMMIT not in vendor_note:
        return fail(
            f"gates/vendor/VENDOR.md does not record pinned protocol commit "
            f"{PINNED_PROTOCOL_COMMIT!r}"
        )

    verified = run_vendored([
        sys.executable, "-B", str(EXPORTER), "verify", "--dest", str(VENDOR),
        "--expect-commit", PINNED_PROTOCOL_COMMIT, "--require-clean",
        "--expect-family-version", PINNED_FAMILY_VERSION,
    ])
    verified_output = (verified.stdout + verified.stderr).strip()
    if verified.returncode != 0:
        return fail(f"vendored closure verification failed:\n{verified_output}")

    text = MANIFEST.read_text(encoding="utf-8")
    match = _MANIFEST_PIN_RE.search(text)
    if not match:
        return fail(
            "acceptance.toml does not declare its acceptance 0.4.0 protocol commit in "
            "the generated header"
        )
    declared = match.group(1)
    if declared != PINNED_PROTOCOL_COMMIT:
        return fail(
            f"acceptance.toml was generated against protocol commit {declared!r} but "
            f"the verified closure is pinned to {PINNED_PROTOCOL_COMMIT!r}; re-emit the "
            "manifest or re-vendor the closure rather than editing either to agree"
        )

    manifest = tomllib.loads(text)
    spec = manifest.get("spec", {})
    assumptions = (ROOT / "ASSUMPTIONS.md").read_text(encoding="utf-8")
    published_ids = set(re.findall(r"^- (A-[0-9]+):", assumptions, re.MULTILINE))
    used_ids = {a for claim in manifest["claim"] for a in claim.get("assumptions", [])}
    used_ids.update(re.findall(r"see (A-[0-9]+)", text))
    if used_ids - published_ids:
        return fail(f"assumption ids have no public definition: {sorted(used_ids - published_ids)}")
    if "requirements inventory coverage rule of acceptance 0.4.0" not in text:
        return fail("the generated header does not explain B19")
    for key in ("inventory", "path"):
        pointed = (MANIFEST.parent / spec.get(key, "")).resolve()
        if pointed != INVENTORY_MIRROR.resolve():
            return fail(
                f"acceptance.toml [spec].{key} is {spec.get(key)!r}, not the inventory mirror "
                f"{INVENTORY_MIRROR.name!r}"
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
        if re.search(r"(?:^|[-/])s6(?:[-/]|$)|light-leaf|stubbed", relative):
            return fail(f"record name is not neutral: {relative!r}")
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
        sys.executable, "-B", str(VALIDATOR), "--strict", "--strict-weight", "--root", str(PACKAGE), str(MANIFEST),
    ])
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0:
        return fail(f"vendored validator rejected acceptance.toml:\n{output}")
    summary = output.splitlines()[-1] if output else "(no output)"
    print(f"PASS recorded acceptance integrity: {summary}")
    return 0


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--require-current', action='store_true',
                        help='refuse unless the recorded subject still covers current inputs')
    args = parser.parse_args(argv)
    result = validate_snapshot()
    if result:
        return result
    from release_evidence import applicability
    status = applicability(ROOT)
    print(f"ACCEPTANCE {status['state']}: {status['reason']}")
    if args.require_current and status['state'] != 'APPLICABLE':
        return fail('release requires applicable evidence; no acceptance generation was run')
    return 0


if __name__ == "__main__":
    sys.exit(main())
