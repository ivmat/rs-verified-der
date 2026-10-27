#!/usr/bin/env python3
"""Validate requirement-evidence maps against Rust, Lean, and the inventory."""

from __future__ import annotations

import argparse
import json
import re
import tomllib
from collections import Counter, defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable


ROOT = Path(__file__).resolve().parents[1]
AGGREGATE_KEYS = {
    "count", "total", "percent", "percentage", "coverage", "score",
    "conformance_level",
}
KINDS = {"test", "kani", "lean"}
ROLES = ("accept", "reject", "prove")
ENTRY_KEYS = {"kind", "file", "name", "path", *ROLES, "bounded", "none"}
FN_RE = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?(?:const\s+|unsafe\s+|async\s+)*fn\s+([A-Za-z_][A-Za-z0-9_]*)")
MOD_RE = re.compile(r"\s*(?:pub(?:\([^)]*\))?\s+)?mod\s+([A-Za-z_][A-Za-z0-9_]*)\s*\{")
LEAN_THEOREM_RE = re.compile(r"^theorem\s+([A-Za-z_][A-Za-z0-9_.']*)\b")


@dataclass(frozen=True, order=True)
class Decl:
    kind: str
    file: str
    name: str
    path: str = ""
    unbounded: bool = False

    def label(self) -> str:
        suffix = f" path={self.path}" if self.path else ""
        return f"{self.file}: {self.kind} {self.name}{suffix}"


@dataclass
class MapEntry:
    source_map: Path
    index: int
    value: dict[str, Any]
    decl: Decl | None = None

    def label(self) -> str:
        return f"{self.source_map.name}: entry[{self.index}]"


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


def read_toml(path: Path, label: str) -> tuple[dict[str, Any] | None, int]:
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


def read_source(path: Path, label: str) -> tuple[str | None, int]:
    try:
        return path.read_text(encoding="utf-8"), 0
    except (OSError, UnicodeError) as exc:
        print(f"{label}: unreadable input: {exc}")
        return None, 2


def _rust_code_lines(text: str) -> list[str]:
    """Remove Rust comments and string/character contents, preserving line boundaries."""
    lines: list[str] = []
    line: list[str] = []
    i = 0
    block_depth = 0
    in_string = False
    in_char = False
    escaped = False
    while i < len(text):
        char = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if char == "\n":
            lines.append("".join(line))
            line = []
            if not in_string and not in_char:
                escaped = False
            i += 1
            continue
        if block_depth:
            if char == "/" and nxt == "*":
                block_depth += 1
                line.extend("  ")
                i += 2
            elif char == "*" and nxt == "/":
                block_depth -= 1
                line.extend("  ")
                i += 2
            else:
                line.append(" ")
                i += 1
            continue
        if in_string or in_char:
            line.append(" ")
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif in_string and char == '"':
                in_string = False
            elif in_char and char == "'":
                in_char = False
            i += 1
            continue
        if char == "/" and nxt == "/":
            while i < len(text) and text[i] != "\n":
                line.append(" ")
                i += 1
            continue
        if char == "/" and nxt == "*":
            block_depth = 1
            line.extend("  ")
            i += 2
            continue
        if char == '"':
            in_string = True
            line.append(" ")
        elif char == "'" and nxt and (nxt.isalnum() or nxt == "\\"):
            # A lifetime (`'a`) has no closing quote. Treat only character-literal-looking text
            # as a character literal; braces in lifetimes are not possible.
            closing = text.find("'", i + 1, min(len(text), i + 8))
            if closing >= 0 and "\n" not in text[i + 1:closing]:
                in_char = True
            line.append(" ")
        else:
            line.append(char)
        i += 1
    lines.append("".join(line))
    return lines


def scan_rust_file(path: Path, relative: str) -> tuple[list[Decl] | None, int]:
    text, status = read_source(path, relative)
    if text is None:
        return None, status
    raw_lines = text.splitlines()
    code_lines = _rust_code_lines(text)
    declarations: list[Decl] = []
    modules: list[tuple[str, int]] = []
    depth = 0
    pending_raw: list[str] = []
    pending_attrs: list[str] = []

    for number, code in enumerate(code_lines):
        raw = raw_lines[number] if number < len(raw_lines) else ""
        while modules and depth <= modules[-1][1]:
            modules.pop()

        fn_match = FN_RE.match(code)
        if fn_match:
            attrs = "\n".join(pending_attrs)
            kind = None
            if re.search(r"#\s*\[\s*test\s*\]", attrs):
                kind = "test"
            if re.search(r"#\s*\[\s*kani::proof(?:_for_contract)?\b", attrs):
                if kind is not None:
                    print(f"{relative}:{number + 1}: function has both test and Kani proof attributes")
                    return None, 1
                kind = "kani"
            if kind is not None:
                docs = "\n".join(pending_raw).lower()
                documented_unbounded = "unbounded" in docs and not any(
                    phrase in docs for phrase in ("not unbounded", "no unbounded", "non-unbounded")
                )
                declarations.append(Decl(
                    kind, relative, fn_match.group(1), "::".join(name for name, _ in modules),
                    kind == "kani" and documented_unbounded,
                ))
            pending_raw = []
            pending_attrs = []
        elif re.match(r"\s*#\s*\[", code):
            pending_raw.append(raw)
            pending_attrs.append(code)
        elif raw.lstrip().startswith(("///", "//!", "//")) or not raw.strip():
            if pending_raw or raw.lstrip().startswith("///"):
                pending_raw.append(raw)
        else:
            pending_raw = []
            pending_attrs = []

        mod_match = MOD_RE.match(code)
        opens = code.count("{")
        closes = code.count("}")
        if mod_match and opens:
            modules.append((mod_match.group(1), depth))
        depth += opens - closes
    return declarations, 0


def scan_sources(root: Path) -> tuple[list[Decl] | None, list[Path] | None, int]:
    source_dir = root / "der-verified" / "src"
    lean_dir = root / "lean"
    try:
        rust_files = sorted(source_dir.glob("*.rs"))
        lean_files = sorted(lean_dir.glob("*Proofs.lean"))
    except OSError as exc:
        print(f"source tree: unreadable input: {exc}")
        return None, None, 2
    if not source_dir.is_dir() or not lean_dir.is_dir():
        print("source tree: unreadable input: der-verified/src or lean is missing")
        return None, None, 2
    if not rust_files:
        print("source tree: unreadable input: no der-verified/src/*.rs files")
        return None, None, 2

    declarations: list[Decl] = []
    for path in rust_files:
        relative = path.relative_to(root).as_posix()
        found, status = scan_rust_file(path, relative)
        if found is None:
            return None, None, status
        declarations.extend(found)
    for path in lean_files:
        relative = path.relative_to(root).as_posix()
        text, status = read_source(path, relative)
        if text is None:
            return None, None, status
        declarations.extend(
            Decl("lean", relative, match.group(1))
            for line in text.splitlines()
            for match in [LEAN_THEOREM_RE.match(line)]
            if match
        )
    return declarations, rust_files, 0


def expected_map_names(rust_files: Iterable[Path]) -> set[str]:
    return {path.with_suffix(".toml").name for path in rust_files} | {"lean.toml"}


def load_maps(evidence_dir: Path, expected_names: set[str]) -> tuple[list[MapEntry] | None, list[str], int]:
    if not evidence_dir.is_dir():
        print(f"evidence: unreadable input: {evidence_dir} is not a directory")
        return None, [], 2
    try:
        actual_paths = sorted(evidence_dir.glob("*.toml"))
    except OSError as exc:
        print(f"evidence: unreadable input: {exc}")
        return None, [], 2
    actual_names = {path.name for path in actual_paths}
    errors = [f"evidence: missing map file {name}" for name in sorted(expected_names - actual_names)]
    errors.extend(f"evidence: stale map file {name}" for name in sorted(actual_names - expected_names))
    entries: list[MapEntry] = []
    for path in actual_paths:
        doc, status = read_toml(path, path.name)
        if doc is None:
            return None, errors, status
        errors.extend(aggregate_errors(doc, path.name))
        rows = doc.get("entry", [])
        if not isinstance(rows, list):
            errors.append(f"{path.name}: [[entry]] must be an array of tables")
            continue
        for index, row in enumerate(rows):
            if not isinstance(row, dict):
                errors.append(f"{path.name}: entry[{index}]: row must be a table")
                continue
            entries.append(MapEntry(path, index, row))
    return entries, errors, 0


def inventory_rows(path: Path) -> tuple[list[dict[str, Any]] | None, int]:
    doc, status = read_toml(path, "inventory")
    if doc is None:
        return None, status
    rows = doc.get("item", [])
    if not isinstance(rows, list):
        print("inventory: [[item]] must be an array of tables")
        return None, 1
    return [row for row in rows if isinstance(row, dict)], 0


def _entry_shape_errors(entry: MapEntry) -> list[str]:
    row = entry.value
    label = entry.label()
    errors: list[str] = []
    kind = row.get("kind")
    if kind not in KINDS:
        errors.append(f"{label}: kind must be one of {sorted(KINDS)!r}")
    for field in ("file", "name"):
        if not nonempty(row.get(field)):
            errors.append(f"{label}: {field} must be a nonempty string")
    if "path" in row and not nonempty(row.get("path")):
        errors.append(f"{label}: path, when present, must be a nonempty string")
    for role in ROLES:
        value = row.get(role)
        if not isinstance(value, list) or not all(nonempty(item) for item in value):
            errors.append(f"{label}: {role} must be a list of nonempty strings")
        elif len(value) != len(set(value)):
            errors.append(f"{label}: {role} contains a duplicate id")
    for field in ("bounded", "none"):
        if not isinstance(row.get(field), str):
            errors.append(f"{label}: {field} must be a string")
    return errors


def validate(
    declarations: list[Decl], entries: list[MapEntry], inventory: list[dict[str, Any]],
) -> list[str]:
    errors: list[str] = []
    by_short: dict[tuple[str, str, str], list[Decl]] = defaultdict(list)
    by_full: dict[tuple[str, str, str, str], Decl] = {}
    for decl in declarations:
        by_short[(decl.file, decl.kind, decl.name)].append(decl)
        by_full[(decl.file, decl.kind, decl.name, decl.path)] = decl

    matched: Counter[Decl] = Counter()
    for entry in entries:
        errors.extend(_entry_shape_errors(entry))
        row = entry.value
        kind, file_name, name = row.get("kind"), row.get("file"), row.get("name")
        if kind not in KINDS or not nonempty(file_name) or not nonempty(name):
            continue
        expected_map = "lean.toml" if kind == "lean" else Path(file_name).with_suffix(".toml").name
        if entry.source_map.name != expected_map:
            errors.append(
                f"{entry.label()}: entry for {file_name} belongs in {expected_map}, not {entry.source_map.name}"
            )
        path_value = row.get("path")
        candidates = by_short.get((file_name, kind, name), [])
        if path_value is not None:
            decl = by_full.get((file_name, kind, name, path_value))
            if decl is None:
                errors.append(f"{file_name}: stale {kind} entry {name} path={path_value}")
                continue
        elif len(candidates) == 1:
            decl = candidates[0]
        elif len(candidates) > 1:
            errors.append(f"{entry.label()}: {file_name}: {kind} {name} is ambiguous; add path")
            continue
        else:
            errors.append(f"{file_name}: stale {kind} entry {name}")
            continue
        entry.decl = decl
        matched[decl] += 1

    for decl in declarations:
        count = matched[decl]
        if count == 0:
            errors.append(f"{decl.file}: missing {decl.kind} entry {decl.name}" + (f" path={decl.path}" if decl.path else ""))
        elif count > 1:
            errors.append(f"{decl.file}: duplicate {decl.kind} entry {decl.name}" + (f" path={decl.path}" if decl.path else ""))

    item_by_id = {
        row.get("id"): row for row in inventory
        if isinstance(row.get("id"), str)
    }
    for entry in entries:
        row = entry.value
        kind = row.get("kind")
        lists_are_valid = all(
            isinstance(row.get(role), list) and all(isinstance(item, str) for item in row[role])
            for role in ROLES
        )
        if not lists_are_valid:
            continue
        cited = [ident for role in ROLES for ident in row[role]]
        for role in ROLES:
            for ident in row[role]:
                inv = item_by_id.get(ident)
                if inv is None:
                    errors.append(f"{entry.label()}: {role} id {ident!r} is absent from inventory items")
                elif inv.get("disposition") != "in":
                    errors.append(
                        f"{entry.label()}: {role} id {ident!r} has disposition {inv.get('disposition')!r}, not 'in'"
                    )
        if kind == "test" and row["prove"]:
            errors.append(f"{entry.label()}: test entries may not use prove")
        if kind == "lean" and (row["accept"] or row["reject"]):
            errors.append(f"{entry.label()}: lean entries may use only prove")
        if kind == "kani" and row["prove"] and not nonempty(row.get("bounded")):
            if entry.decl is None or not entry.decl.unbounded:
                errors.append(f"{entry.label()}: Kani prove entries require bounded, unless source docs say unbounded")
        none_value = row.get("none")
        if not cited and not nonempty(none_value):
            errors.append(f"{entry.label()}: empty accept/reject/prove lists require a nonempty none")
        if cited and none_value != "":
            errors.append(f"{entry.label()}: none must be empty when an id is cited")
        if kind in {"test", "lean"} and row.get("bounded") != "":
            errors.append(f"{entry.label()}: bounded must be empty for {kind} entries")
    return errors


def print_report(entries: list[MapEntry], inventory: list[dict[str, Any]]) -> None:
    counts: dict[str, Counter[str]] = defaultdict(Counter)
    kinds: dict[str, set[str]] = defaultdict(set)
    for entry in entries:
        kind = entry.value.get("kind")
        if kind not in KINDS:
            continue
        for role in ROLES:
            values = entry.value.get(role, [])
            if not isinstance(values, list):
                continue
            for ident in set(value for value in values if isinstance(value, str)):
                counts[ident][role] += 1
                kinds[ident].add(kind)
    for row in inventory:
        if row.get("disposition") != "in" or not isinstance(row.get("id"), str):
            continue
        ident = row["id"]
        kind_text = ",".join(sorted(kinds[ident])) or "-"
        print(
            f"{ident}: accept={counts[ident]['accept']} reject={counts[ident]['reject']} "
            f"prove={counts[ident]['prove']} kinds={kind_text}"
        )


def _toml_string(value: str) -> str:
    return json.dumps(value, ensure_ascii=False)


def write_skeleton(root: Path, declarations: list[Decl], rust_files: list[Path], evidence_dir: Path) -> int:
    evidence_dir.mkdir(parents=True, exist_ok=True)
    groups: dict[str, list[Decl]] = defaultdict(list)
    for decl in declarations:
        map_name = "lean.toml" if decl.kind == "lean" else Path(decl.file).with_suffix(".toml").name
        groups[map_name].append(decl)
    duplicates = Counter((decl.file, decl.kind, decl.name) for decl in declarations)
    for map_name in sorted(expected_map_names(rust_files)):
        parts = ["# Generated by: python3 gates/check_req_map.py --write-skeleton", ""]
        for decl in sorted(groups[map_name], key=lambda item: (item.file, item.kind, item.name, item.path)):
            parts.extend([
                "[[entry]]",
                f"kind = {_toml_string(decl.kind)}",
                f"file = {_toml_string(decl.file)}",
                f"name = {_toml_string(decl.name)}",
            ])
            if duplicates[(decl.file, decl.kind, decl.name)] > 1:
                parts.append(f"path = {_toml_string(decl.path)}")
            parts.extend([
                "accept = []",
                "reject = []",
                "prove = []",
                'bounded = ""',
                'none = "phase B assigns requirement ids"',
                "",
            ])
        target = evidence_dir / map_name
        try:
            target.write_text("\n".join(parts), encoding="utf-8")
        except OSError as exc:
            print(f"{target}: unreadable input: {exc}")
            return 2
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--report", action="store_true")
    parser.add_argument("--write-skeleton", action="store_true")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    inventory_path = args.inventory or root / "docs" / "requirements" / "der.inventory.toml"
    evidence_dir = args.evidence_dir or root / "docs" / "requirements" / "evidence"

    declarations, rust_files, status = scan_sources(root)
    if declarations is None or rust_files is None:
        return status
    if args.write_skeleton:
        return write_skeleton(root, declarations, rust_files, evidence_dir)

    inventory, status = inventory_rows(inventory_path)
    if inventory is None:
        return status
    entries, errors, status = load_maps(evidence_dir, expected_map_names(rust_files))
    if entries is None:
        return status
    errors.extend(validate(declarations, entries, inventory))
    for error in errors:
        print(error)
    if errors:
        return 1
    if args.report:
        print_report(entries, inventory)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
