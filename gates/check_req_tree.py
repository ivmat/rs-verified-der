#!/usr/bin/env python3
"""Validate the DER requirements-tree inventory."""

from __future__ import annotations

import argparse
import re
import sys
import tomllib
from pathlib import Path
from typing import Any


ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]*$")
FIRMNESS = {"draft", "firm"}
FORCE = {
    "shall", "shall-not", "must", "must-not", "required", "should",
    "should-not", "recommended", "declarative", "structure", "contract",
}
SIDE = {"decoder", "encoder", "both", "issuer", "relying-party"}
DISPOSITION = {"in", "excluded", "not-applicable"}
AGGREGATE_KEYS = {
    "count", "total", "percent", "percentage", "coverage", "score",
    "conformance_level",
}


def parse_file(path: Path, label: str) -> tuple[dict[str, Any] | None, int]:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        print(f"{label}: unreadable input: {exc}")
        return None, 2
    try:
        value = tomllib.loads(raw.decode("utf-8"))
    except (UnicodeError, tomllib.TOMLDecodeError) as exc:
        print(f"{label}: TOML parse failure: {exc}")
        return None, 1
    return value, 0


def nonempty(value: Any) -> bool:
    return isinstance(value, str) and bool(value.strip())


def aggregate_errors(value: Any, path: str = "document") -> list[str]:
    errors: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            lowered = key.lower()
            aggregate_suffix = any(
                lowered.endswith("_" + token)
                for token in ("count", "total", "percent", "percentage", "coverage", "score")
            )
            if lowered in AGGREGATE_KEYS or lowered.startswith("n_") or aggregate_suffix:
                errors.append(f"{path}: aggregate-like key {key!r} is forbidden")
            errors.extend(aggregate_errors(child, f"{path}.{key}"))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            errors.extend(aggregate_errors(child, f"{path}[{index}]"))
    return errors


def validate(doc: dict[str, Any], legacy: dict[str, Any]) -> list[str]:
    errors = aggregate_errors(doc)
    header = doc.get("inventory")
    if not isinstance(header, dict):
        errors.append("inventory: missing [inventory] table")
    else:
        for field in ("id", "title", "source"):
            if not nonempty(header.get(field)):
                errors.append(f"inventory: {field} must be a nonempty string")

    groups = doc.get("group", [])
    items = doc.get("item", [])
    if not isinstance(groups, list):
        errors.append("group: [[group]] must be an array of tables")
        groups = []
    if not isinstance(items, list):
        errors.append("item: [[item]] must be an array of tables")
        items = []

    seen: dict[str, str] = {}
    group_by_id: dict[str, dict[str, Any]] = {}
    item_by_id: dict[str, dict[str, Any]] = {}
    for kind, rows, destination in (
        ("group", groups, group_by_id), ("item", items, item_by_id)
    ):
        for index, row in enumerate(rows):
            label = f"{kind}[{index}]"
            if not isinstance(row, dict):
                errors.append(f"{label}: row must be a table")
                continue
            ident = row.get("id")
            if not isinstance(ident, str) or not ID_RE.fullmatch(ident):
                errors.append(f"{label}: id {ident!r} has invalid syntax")
                continue
            if ident in seen:
                errors.append(f"{ident}: duplicate id (already used by {seen[ident]})")
            else:
                seen[ident] = kind
            destination.setdefault(ident, row)

    roots: list[str] = []
    for ident, row in group_by_id.items():
        if "parent" not in row:
            roots.append(ident)
        else:
            parent = row.get("parent")
            if not nonempty(parent) or parent not in group_by_id:
                errors.append(f"{ident}: parent {parent!r} is not an existing group")
    if len(roots) != 1 or roots != ["DER"]:
        errors.append(f"DER: exactly one root group is required and must be DER; found {roots!r}")

    for ident, row in item_by_id.items():
        parent = row.get("parent")
        if not nonempty(parent) or parent not in group_by_id:
            errors.append(f"{ident}: parent {parent!r} is not an existing group")
        firmness = row.get("firmness")
        if firmness is not None and firmness not in FIRMNESS:
            errors.append(f"{ident}: invalid firmness {firmness!r}")
        force = row.get("force")
        if force not in FORCE:
            errors.append(f"{ident}: invalid force {force!r}")
        side = row.get("side")
        if side not in SIDE:
            errors.append(f"{ident}: invalid side {side!r}")
        disposition = row.get("disposition")
        if disposition not in DISPOSITION:
            errors.append(f"{ident}: invalid disposition {disposition!r}")
        elif disposition != "in" and not nonempty(row.get("reason")):
            errors.append(f"{ident}: non-in disposition requires a nonempty reason")

    for start in group_by_id:
        visited: set[str] = set()
        current = start
        while current in group_by_id and "parent" in group_by_id[current]:
            if current in visited:
                errors.append(f"{start}: group-parent cycle detected")
                break
            visited.add(current)
            parent = group_by_id[current].get("parent")
            if not isinstance(parent, str):
                break
            current = parent

    children: dict[str, list[str]] = {ident: [] for ident in group_by_id}
    direct_items: dict[str, int] = {ident: 0 for ident in group_by_id}
    for ident, row in group_by_id.items():
        parent = row.get("parent")
        if isinstance(parent, str) and parent in children:
            children[parent].append(ident)
    for row in item_by_id.values():
        parent = row.get("parent")
        if isinstance(parent, str) and parent in direct_items:
            direct_items[parent] += 1

    memo: dict[str, bool] = {}
    active: set[str] = set()

    def has_item(ident: str) -> bool:
        if ident in memo:
            return memo[ident]
        if ident in active:
            return False
        active.add(ident)
        result = direct_items[ident] > 0 or any(has_item(child) for child in children[ident])
        active.remove(ident)
        memo[ident] = result
        return result

    for ident in group_by_id:
        if not has_item(ident):
            errors.append(f"{ident}: group has no descendant item")

    legacy_rows = legacy.get("clause", legacy.get("item", []))
    if not isinstance(legacy_rows, list):
        errors.append("legacy: expected [[clause]] or [[item]] rows")
    else:
        for index, row in enumerate(legacy_rows):
            ident = row.get("id") if isinstance(row, dict) else None
            if not isinstance(ident, str):
                errors.append(f"legacy[{index}]: missing string id")
            elif ident not in item_by_id:
                errors.append(f"{ident}: legacy id is missing from inventory items")
    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--inventory", type=Path, default=Path("docs/requirements/der.inventory.toml"))
    parser.add_argument("--legacy", type=Path, default=Path("docs/requirements/x690-der.clauses.toml"))
    args = parser.parse_args(argv)
    inventory, status = parse_file(args.inventory, "inventory")
    if inventory is None:
        return status
    legacy, legacy_status = parse_file(args.legacy, "legacy")
    if legacy is None:
        return legacy_status
    errors = validate(inventory, legacy)
    for error in errors:
        print(error)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
