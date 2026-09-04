#!/usr/bin/env python3
"""Keep Lake's Aeneas path dependency location-independent and internally consistent."""

from __future__ import annotations

import json
import pathlib
import sys
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent
EXPECTED = ".lake/packages/Aeneas"
BINDING_LINES = (
    'AENEAS_LAKE_LINK="$HERE/.lake/packages/Aeneas"',
    'ln -s "$AENEAS_LEAN" "$AENEAS_LAKE_LINK"',
)


def aeneas_lakefile_paths(text: str) -> list[str]:
    document = tomllib.loads(text)
    return [
        item.get("path")
        for item in document.get("require", [])
        if item.get("name") == "Aeneas"
    ]


def aeneas_manifest_paths(text: str) -> list[str]:
    document = json.loads(text)
    return [
        item.get("dir")
        for item in document.get("packages", [])
        if item.get("name") == "Aeneas"
    ]


def check_paths(lakefile_text: str, manifest_text: str, script_text: str) -> list[str]:
    errors = []
    lakefile_paths = aeneas_lakefile_paths(lakefile_text)
    manifest_paths = aeneas_manifest_paths(manifest_text)
    if lakefile_paths != [EXPECTED]:
        errors.append(
            f"lean/lakefile.toml must require Aeneas exactly once at {EXPECTED!r}; "
            f"found {lakefile_paths!r}"
        )
    if manifest_paths != [EXPECTED]:
        errors.append(
            f"lean/lake-manifest.json must resolve Aeneas exactly once at {EXPECTED!r}; "
            f"found {manifest_paths!r}"
        )
    for line in BINDING_LINES:
        if script_text.count(line) != 1:
            errors.append(
                f"lean/check_lean.sh must contain the local binding line exactly once: {line!r}"
            )
    return errors


def main() -> int:
    errors = check_paths(
        (ROOT / "lean" / "lakefile.toml").read_text(encoding="utf-8"),
        (ROOT / "lean" / "lake-manifest.json").read_text(encoding="utf-8"),
        (ROOT / "lean" / "check_lean.sh").read_text(encoding="utf-8"),
    )
    for error in errors:
        print(f"FAIL check_lean_dependency_path: {error}", file=sys.stderr)
    if errors:
        return 1
    print(
        "PASS check_lean_dependency_path: Lake files agree on the "
        f"location-independent Aeneas path {EXPECTED!r}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
