#!/usr/bin/env python3
"""gen_req_gaps.py - derive docs/requirements/test-gaps.md from the requirements tree.

WHY THIS EXISTS
---------------
The owner's bar is that every requirement is covered by TESTS first, "so we know we covered
all use cases". Proofs come after. The evidence maps (`docs/requirements/evidence/*.toml`) say
which test, Kani harness or Lean theorem cites which requirement. This script turns those maps
into a per-requirement test-gap report. It is a working report for step S4 (write the missing
tests). It is NOT an acceptance manifest and it does not claim any assurance band.

HOW IT WORKS
------------
For each `in` row of `docs/requirements/der.inventory.toml` (umbrella rows are skipped, because
their sentence rows carry the evidence) the script:

  1. Works out which roles the row needs (the OBLIGATION, below).
  2. Counts the evidence for the row by role (accept, reject, prove) and by kind
     (test, kani, lean).
  3. Gives each needed role a status and the row an overall status.

OBLIGATION RULE (default, applied to every non-umbrella `in` row)
-----------------------------------------------------------------
  * `SAFE-*`            needs `prove` (at least one Kani harness or Lean theorem). Tests are
                        shown, but a test cannot discharge a SAFE row.
  * `API-*`             needs `review`. There is no test obligation.
  * `CODEC-*-reject-nonder` and `CODEC-*-unique`   need a `reject` test.
  * `CODEC-*-encode-decode` and `CODEC-*-decode-encode`   need an `accept` test.
  * `PROF-*`            needs `accept` and `reject`.
  * every other row (the standards rows) uses the `side` field:
      - side decoder, both, relying-party, or issuer: DECODER obligation. It needs at least
        one `accept` test AND at least one `reject` test.
      - side encoder or both: ENCODER obligation, only if at least one of the row's modules
        has an encoder. A module has an encoder if its source has a `pub fn encode...`
        (derived from the source files, not typed). The obligation needs at least one
        `accept` test.

LIMIT OF THE ENCODER OBLIGATION (v1). The maps do not say which tests call the encoder. So
the encoder obligation is only "at least one `accept` test exists in a module that has an
encoder". The status for a row whose accept tests all live in modules without an encoder is
MISSING-ENC. This is a lower bound: a test in an encoder module might still not call the
encoder. A later version should read the test bodies.

OVERRIDES. `docs/requirements/obligations.toml` holds `[[override]]` rows with `id`, `needs`
(a subset of accept, reject, prove, review, gate) and `reason` (not empty). An override replaces the
default `needs` for that row completely. No encoder check is added to an overridden row. An
override that names an unknown id, a row that is not `in`, an umbrella row, or that has an
empty reason or an unknown role is an ERROR.

THE `gate` ROLE. A requirement that no test or proof harness can decide, but that a static source
gate under `gates/` decides on every commit (for example "no heap allocation"), may say
`needs = ["gate"]` together with `gate = "gates/<file>.py"`. The role is MET when that file exists
AND `check_fast.sh` runs it (a line of `check_fast.sh`, not a comment, names the path). Otherwise it
is MISSING. It is an ERROR if `gate` is in `needs` and the `gate` key is absent, empty or not of the
form `gates/<file>.py`, or if the `gate` key is present without `gate` in `needs`.

STATUS
------
Role status:   MET (at least one test in that role), PROOF-ONLY (only Kani or Lean in that
               role), MISSING, MISSING-ENC (accept tests exist, none in an encoder module),
               REVIEW (a review need; not evidence-driven).
               For `prove`: MET if at least one Kani or Lean entry proves the row.
               For `gate`: MET if the named gate file exists and check_fast.sh runs it.
Overall:       COVERED    every needed role is MET
               PARTIAL    some needed role is MET, not all
               PROOF-ONLY no needed role is MET, but Kani or Lean evidence exists on the row
               NONE       no evidence in any needed role (tests in other roles may exist)
               REVIEW     the row only needs a human review
               NOT-REQUIRED   the row has no obligation at all

MODES
-----
    python3 gates/gen_req_gaps.py            # write docs/requirements/test-gaps.md
    python3 gates/gen_req_gaps.py --check    # exit 1 if the file differs from regeneration

Exit codes: 0 ok, 1 error or drift, 2 unreadable input. Pure stdlib.
"""

from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))
import check_req_map  # noqa: E402  (shares loading and Rust comment stripping)

ROOT = Path(__file__).resolve().parents[1]
ROLES = ("accept", "reject", "prove")
NEEDS = ("accept", "reject", "prove", "review", "gate")
KINDS = ("test", "kani", "lean")
STATUSES = ("COVERED", "PARTIAL", "PROOF-ONLY", "NONE", "REVIEW", "NOT-REQUIRED")
ENCODE_RE = re.compile(r"\bpub\s+(?:const\s+|unsafe\s+)*fn\s+encode[A-Za-z0-9_]*")
DECODER_SIDES = {"decoder", "both", "relying-party", "issuer"}
ENCODER_SIDES = {"encoder", "both"}
OVERRIDE_KEYS = {"id", "needs", "reason", "gate"}
GATE_PATH_RE = re.compile(r"gates/[A-Za-z0-9_]+\.py")
TITLE_MAX = 58
BRANCH_ORDER = ("STD", "SAFE", "CODEC", "PROF", "API")
BRANCH_TITLES = {
    "STD": "External standards",
    "SAFE": "Safety contracts",
    "CODEC": "Codec laws",
    "PROF": "Profile decisions",
    "API": "Public API commitments",
}


@dataclass
class Obligation:
    needs: tuple[str, ...]
    enc_accept: bool = False
    overridden: bool = False
    gate: str = ""  # the gate file of a `gate` need, relative to the repository root
    gate_active: bool = False  # the gate file exists and check_fast.sh runs it


@dataclass
class RowResult:
    row: dict[str, Any]
    branch: str
    group: str
    obligation: Obligation
    counts: dict[str, dict[str, int]]  # role -> kind -> entries citing the row in that role
    kind_totals: dict[str, int]  # kind -> distinct entries citing the row in any role
    enc_accept_tests: int
    role_status: dict[str, str] = field(default_factory=dict)
    overall: str = "NONE"
    missing: list[str] = field(default_factory=list)

    @property
    def known_gap(self) -> bool:
        return str(self.row.get("note", "")).startswith("gap:")


def is_umbrella(row: dict[str, Any]) -> bool:
    return "umbrella" in str(row.get("note", "")).lower()


def encoder_modules(root: Path) -> tuple[set[str] | None, int]:
    """Modules (source file stems) whose code has a `pub fn encode...`."""
    source_dir = root / "der-verified" / "src"
    if not source_dir.is_dir():
        print(f"source tree: unreadable input: {source_dir} is missing")
        return None, 2
    found: set[str] = set()
    for path in sorted(source_dir.glob("*.rs")):
        text, status = check_req_map.read_source(path, path.name)
        if text is None:
            return None, status
        code = "\n".join(check_req_map._rust_code_lines(text))
        if ENCODE_RE.search(code):
            found.add(path.stem)
    return found, 0


def load_overrides(path: Path) -> tuple[list[dict[str, Any]] | None, int]:
    doc, status = check_req_map.read_toml(path, path.name)
    if doc is None:
        return None, status
    rows = doc.get("override", [])
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        print(f"{path.name}: [[override]] must be an array of tables")
        return None, 1
    return rows, 0


def check_overrides(overrides: list[dict[str, Any]], rows_by_id: dict[str, dict[str, Any]]) -> list[str]:
    errors: list[str] = []
    seen: set[str] = set()
    for index, ov in enumerate(overrides):
        label = f"obligations: override[{index}]"
        for key in sorted(set(ov) - OVERRIDE_KEYS):
            errors.append(f"{label}: unknown key {key!r}")
        ident = ov.get("id")
        if not isinstance(ident, str) or not ident:
            errors.append(f"{label}: id must be a non-empty string")
            continue
        label = f"obligations: override {ident}"
        if ident in seen:
            errors.append(f"{label}: duplicate override")
        seen.add(ident)
        row = rows_by_id.get(ident)
        if row is None:
            errors.append(f"{label}: unknown id")
        elif row.get("disposition") != "in":
            errors.append(f"{label}: row is not an `in` row")
        elif is_umbrella(row):
            errors.append(f"{label}: row is an umbrella row and has no obligation")
        reason = ov.get("reason")
        if not isinstance(reason, str) or not reason.strip():
            errors.append(f"{label}: reason must not be empty")
        needs = ov.get("needs")
        if not isinstance(needs, list) or not all(isinstance(n, str) for n in needs):
            errors.append(f"{label}: needs must be a list of role names")
        else:
            for need in needs:
                if need not in NEEDS:
                    errors.append(f"{label}: unknown role {need!r}")
        gate = ov.get("gate")
        wants_gate = isinstance(needs, list) and "gate" in needs
        if wants_gate:
            if not isinstance(gate, str) or not gate.strip():
                errors.append(f"{label}: role `gate` needs a non-empty `gate` key")
            elif not GATE_PATH_RE.fullmatch(gate):
                errors.append(f"{label}: gate {gate!r} must have the form gates/<file>.py")
        elif "gate" in ov:
            errors.append(f"{label}: `gate` key is set but `gate` is not in needs")
    return errors


def gate_is_active(root: Path, gate: str) -> bool:
    """True if the gate file exists and a non-comment line of check_fast.sh names its path."""
    if not (root / gate).is_file():
        return False
    try:
        script = (root / "check_fast.sh").read_text(encoding="utf-8")
    except (OSError, UnicodeError):
        return False
    pattern = re.compile(r"(?<![\w.-])" + re.escape(gate) + r"(?![\w.-])")
    return any(pattern.search(line) for line in script.splitlines() if not line.lstrip().startswith("#"))


def default_obligation(row: dict[str, Any], enc_modules: set[str]) -> Obligation:
    ident = row["id"]
    if ident.startswith("SAFE-"):
        return Obligation(("prove",))
    if ident.startswith("API-"):
        return Obligation(("review",))
    if ident.startswith("CODEC-"):
        if ident.endswith(("-reject-nonder", "-unique")):
            return Obligation(("reject",))
        if ident.endswith(("-encode-decode", "-decode-encode")):
            return Obligation(("accept",))
    if ident.startswith("PROF-"):
        return Obligation(("accept", "reject"))
    side = row.get("side")
    modules = row.get("modules") or []
    has_encoder = any(m in enc_modules for m in modules)
    needs: list[str] = []
    enc_accept = False
    if side in DECODER_SIDES:
        needs.extend(("accept", "reject"))
    if side in ENCODER_SIDES and has_encoder:
        if "accept" not in needs:
            needs.append("accept")
        enc_accept = True
    return Obligation(tuple(needs), enc_accept)


def branch_of(row: dict[str, Any], groups: dict[str, dict[str, Any]]) -> tuple[str, str]:
    """Top-level branch and (for STD) the source group, from the parent chain."""
    chain: list[str] = []
    parent = row.get("parent")
    guard = 0
    while isinstance(parent, str) and parent in groups and guard < 50:
        chain.append(parent)
        parent = groups[parent].get("parent")
        guard += 1
    top = [g for g in chain if groups[g].get("parent") == "DER"]
    branch = top[0] if top else row["id"].split("-")[0]
    group = ""
    if branch == "STD":
        sources = [g for g in chain if groups[g].get("parent") == "STD"]
        group = sources[0].removeprefix("STD.") if sources else row["id"].split("-")[0]
    return branch, group


def load_evidence(evidence_dir: Path) -> tuple[list[dict[str, Any]] | None, int]:
    if not evidence_dir.is_dir():
        print(f"evidence: unreadable input: {evidence_dir} is not a directory")
        return None, 2
    entries: list[dict[str, Any]] = []
    for path in sorted(evidence_dir.glob("*.toml")):
        doc, status = check_req_map.read_toml(path, path.name)
        if doc is None:
            return None, status
        rows = doc.get("entry", [])
        if isinstance(rows, list):
            entries.extend(r for r in rows if isinstance(r, dict))
    return entries, 0


def collect_counts(entries: list[dict[str, Any]], enc_modules: set[str]):
    counts: dict[str, dict[str, dict[str, int]]] = defaultdict(
        lambda: {role: {kind: 0 for kind in KINDS} for role in ROLES}
    )
    enc_accept: dict[str, int] = defaultdict(int)
    per_kind: dict[str, dict[str, int]] = defaultdict(lambda: {kind: 0 for kind in KINDS})
    for entry in entries:
        kind = entry.get("kind")
        if kind not in KINDS:
            continue
        module = Path(str(entry.get("file", ""))).stem
        cited: set[str] = set()
        for role in ROLES:
            ids = entry.get(role, [])
            if not isinstance(ids, list):
                continue
            for ident in {i for i in ids if isinstance(i, str)}:
                cited.add(ident)
                counts[ident][role][kind] += 1
                if role == "accept" and kind == "test" and module in enc_modules:
                    enc_accept[ident] += 1
        for ident in cited:
            per_kind[ident][kind] += 1
    return counts, enc_accept, per_kind


def judge(result: RowResult) -> None:
    ob = result.obligation
    counts = result.counts
    total_proofs = sum(counts[r][k] for r in ROLES for k in ("kani", "lean"))
    for need in ob.needs:
        if need == "review":
            result.role_status[need] = "REVIEW"
            continue
        if need == "gate":
            result.role_status[need] = "MET" if ob.gate_active else "MISSING"
            continue
        tests = counts[need]["test"]
        proofs = counts[need]["kani"] + counts[need]["lean"]
        if need == "prove":
            status = "MET" if proofs else "MISSING"
        elif tests:
            status = "MET"
            if need == "accept" and ob.enc_accept and not result.enc_accept_tests:
                status = "MISSING-ENC"
        elif proofs:
            status = "PROOF-ONLY"
        else:
            status = "MISSING"
        result.role_status[need] = status
    graded = [n for n in ob.needs if n != "review"]
    if not graded:
        result.overall = "REVIEW" if ob.needs else "NOT-REQUIRED"
        return
    met = [n for n in graded if result.role_status[n] == "MET"]
    if len(met) == len(graded):
        result.overall = "COVERED"
    elif met:
        result.overall = "PARTIAL"
    elif total_proofs:
        result.overall = "PROOF-ONLY"
    else:
        result.overall = "NONE"
    for need in graded:
        status = result.role_status[need]
        if status == "MET":
            continue
        if need == "gate":
            result.missing.append(f"gate {ob.gate} (file present and run by check_fast.sh)")
        elif need == "prove":
            result.missing.append("proof (Kani or Lean)")
        elif status == "MISSING-ENC":
            result.missing.append("accept test in a module with an encoder")
        elif status == "PROOF-ONLY":
            result.missing.append(f"{need} test (only a proof exists)")
        else:
            result.missing.append(f"{need} test")


def build(root: Path, inventory_path: Path, evidence_dir: Path, obligations_path: Path):
    """Return (results, skipped_umbrella, errors, status)."""
    inventory, status = check_req_map.inventory_rows(inventory_path)
    if inventory is None:
        return None, 0, [], status
    inv_doc, status = check_req_map.read_toml(inventory_path, "inventory")
    if inv_doc is None:
        return None, 0, [], status
    groups = {g["id"]: g for g in inv_doc.get("group", []) if isinstance(g, dict) and "id" in g}
    enc_modules, status = encoder_modules(root)
    if enc_modules is None:
        return None, 0, [], status
    overrides, status = load_overrides(obligations_path)
    if overrides is None:
        return None, 0, [], status
    entries, status = load_evidence(evidence_dir)
    if entries is None:
        return None, 0, [], status

    rows_by_id = {r["id"]: r for r in inventory if isinstance(r.get("id"), str)}
    errors = check_overrides(overrides, rows_by_id)
    if errors:
        return None, 0, errors, 1
    override_needs = {ov["id"]: tuple(ov["needs"]) for ov in overrides}
    override_gate = {ov["id"]: ov["gate"] for ov in overrides if "gate" in ov}
    counts, enc_accept, per_kind = collect_counts(entries, enc_modules)

    results: list[RowResult] = []
    skipped = 0
    for row in inventory:
        if row.get("disposition") != "in" or not isinstance(row.get("id"), str):
            continue
        if is_umbrella(row):
            skipped += 1
            continue
        ident = row["id"]
        if ident in override_needs:
            ob = Obligation(override_needs[ident], overridden=True)
            if "gate" in ob.needs:
                ob.gate = override_gate[ident]
                ob.gate_active = gate_is_active(root, ob.gate)
        else:
            ob = default_obligation(row, enc_modules)
        branch, group = branch_of(row, groups)
        kind_totals = dict(per_kind[ident]) if ident in per_kind else {k: 0 for k in KINDS}
        result = RowResult(
            row=row,
            branch=branch,
            group=group,
            obligation=ob,
            counts=counts[ident] if ident in counts else {r: {k: 0 for k in KINDS} for r in ROLES},
            kind_totals=kind_totals,
            enc_accept_tests=enc_accept.get(ident, 0),
        )
        judge(result)
        results.append(result)
    return results, skipped, [], 0


def short_title(title: str) -> str:
    text = " ".join(str(title).split()).replace("|", "/")
    if len(text) > TITLE_MAX:
        text = text[: TITLE_MAX - 3].rstrip() + "..."
    return text


def role_cell(result: RowResult) -> str:
    return ", ".join(f"{n}:{result.role_status[n]}" for n in result.obligation.needs) or "-"


def render(results: list[RowResult], skipped: int, overrides_count: int) -> str:
    totals = {s: 0 for s in STATUSES}
    for r in results:
        totals[r.overall] += 1
    gaps_not_covered = sum(1 for r in results if r.overall != "COVERED" and r.known_gap)
    lines: list[str] = []
    out = lines.append
    out("# Test-gap report")
    out("")
    out("This file is generated. Do not edit it by hand.")
    out("Regenerate it with `python3 gates/gen_req_gaps.py`.")
    out("`python3 gates/gen_req_gaps.py --check` fails if this file is stale.")
    out("")
    out("## What this report is")
    out("")
    out("The owner ruled that every requirement must first be covered by tests. Proofs come")
    out("after. This report judges TEST coverage for each `in` row of")
    out("`docs/requirements/der.inventory.toml`. Kani and Lean evidence is shown next to the")
    out("tests. It never replaces a test that a row needs. This is a working report for step S4.")
    out("It is not an acceptance manifest and it claims no assurance band.")
    out("")
    out("Inputs: the inventory, `docs/requirements/evidence/*.toml`,")
    out("`docs/requirements/obligations.toml`, the `pub fn encode` functions in")
    out("`der-verified/src`, and `check_fast.sh` (for the role `gate`).")
    out("")
    out("## Obligation rule")
    out("")
    out("- `SAFE-*` rows need a proof (Kani or Lean). Tests are shown but cannot discharge them.")
    out("- `API-*` rows need a human review. They have no test obligation.")
    out("- `CODEC-*-reject-nonder` and `CODEC-*-unique` rows need a `reject` test.")
    out("- `CODEC-*-encode-decode` and `CODEC-*-decode-encode` rows need an `accept` test.")
    out("- `PROF-*` rows need an `accept` test and a `reject` test.")
    out("- Standards rows use the `side` field. A decoder side (decoder, both, relying-party,")
    out("  issuer) needs an `accept` test and a `reject` test.")
    out("- An encoder side (encoder, both) needs an `accept` test in a module that has an")
    out("  encoder. This applies only if one of the row's modules has a `pub fn encode`.")
    out("  Limit: the maps do not show which tests call the encoder. The check is a lower bound.")
    out("- Umbrella rows are skipped. Their sentence rows carry the evidence.")
    out("- An override may use the role `gate` with `gate = \"gates/<file>.py\"`. It is for a rule that a")
    out("  static source gate decides on every commit. The role is MET if the file exists and")
    out("  `check_fast.sh` runs it, and MISSING otherwise.")
    out(f"- `docs/requirements/obligations.toml` has {overrides_count} override rows. Each has a reason.")
    out("")
    out("Role status: MET (a test exists), PROOF-ONLY (only Kani or Lean exists in that role),")
    out("MISSING, MISSING-ENC (accept tests exist but none is in an encoder module), REVIEW.")
    out("For the role `gate`: MET (the gate file exists and `check_fast.sh` runs it) or MISSING.")
    out("")
    out("## Totals")
    out("")
    out(f"Rows judged: {len(results)}. Umbrella rows skipped: {skipped}.")
    out("")
    out("| status | rows | meaning |")
    out("|---|---|---|")
    meanings = {
        "COVERED": "every needed role has a test (or, for the role `gate`, a gate that check_fast.sh runs)",
        "PARTIAL": "some needed role has a test, not all",
        "PROOF-ONLY": "no needed role has a test, but Kani or Lean evidence exists",
        "NONE": "no evidence in any needed role",
        "REVIEW": "only a human review is needed",
        "NOT-REQUIRED": "the row has no obligation",
    }
    for s in STATUSES:
        if totals[s] or s in ("COVERED", "PARTIAL", "PROOF-ONLY", "NONE"):
            out(f"| {s} | {totals[s]} | {meanings[s]} |")
    out("")
    out(f"Rows that are not COVERED and carry a known gap (`gap:` note): {gaps_not_covered}.")
    out("")

    by_branch: dict[str, list[RowResult]] = defaultdict(list)
    for r in results:
        by_branch[r.branch].append(r)
    header = [
        "| id | title | needs | role status | status | test/kani/lean | known gap |",
        "|---|---|---|---|---|---|---|",
    ]

    def row_line(r: RowResult) -> str:
        t, k, l = (r.kind_totals[x] for x in KINDS)
        needs = ", ".join(r.obligation.needs) or "-"
        return (
            f"| {r.row['id']} | {short_title(r.row.get('title', ''))} | {needs} | {role_cell(r)} "
            f"| {r.overall} | {t}/{k}/{l} | {'yes' if r.known_gap else ''} |"
        )

    order = [b for b in BRANCH_ORDER if b in by_branch] + sorted(b for b in by_branch if b not in BRANCH_ORDER)
    for branch in order:
        rows = by_branch[branch]
        out(f"## {branch}: {BRANCH_TITLES.get(branch, branch)}")
        out("")
        if branch == "STD":
            groups_order: list[str] = []
            for r in rows:
                if r.group not in groups_order:
                    groups_order.append(r.group)
            for grp in groups_order:
                sub = [r for r in rows if r.group == grp]
                out(f"### STD source {grp}")
                out("")
                lines.extend(header)
                lines.extend(row_line(r) for r in sub)
                out("")
        else:
            lines.extend(header)
            lines.extend(row_line(r) for r in rows)
            out("")

    out("## Work list for S4")
    out("")
    out("Every row that is not COVERED, grouped by its first listed module.")
    out("Each line says which test role is missing.")
    out("")
    todo = [r for r in results if r.overall not in ("COVERED", "REVIEW", "NOT-REQUIRED")]
    grouped: dict[str, list[RowResult]] = defaultdict(list)
    for r in todo:
        modules = r.row.get("modules") or []
        grouped[modules[0] if modules else "(no module)"].append(r)
    if not todo:
        out("No rows. Every judged row is COVERED.")
        out("")
    for module in sorted(grouped, key=lambda m: (m == "(no module)", m)):
        rows = grouped[module]
        out(f"### {module} ({len(rows)} {'row' if len(rows) == 1 else 'rows'})")
        out("")
        for r in rows:
            gap = " Known gap." if r.known_gap else ""
            out(f"- {r.row['id']} [{r.overall}]: missing {'; missing '.join(r.missing)}.{gap}")
        out("")
    reviews = [r for r in results if r.overall in ("REVIEW", "NOT-REQUIRED")]
    if reviews:
        out("### Review-only rows (no test obligation)")
        out("")
        for r in reviews:
            out(f"- {r.row['id']} [{r.overall}]: {short_title(r.row.get('title', ''))}")
        out("")
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--inventory", type=Path)
    parser.add_argument("--evidence-dir", type=Path)
    parser.add_argument("--obligations", type=Path)
    parser.add_argument("--out", type=Path)
    parser.add_argument("--check", action="store_true", help="exit 1 if the report file is stale")
    args = parser.parse_args(argv)
    root = args.root.resolve()
    req = root / "docs" / "requirements"
    inventory_path = args.inventory or req / "der.inventory.toml"
    evidence_dir = args.evidence_dir or req / "evidence"
    obligations_path = args.obligations or req / "obligations.toml"
    out_path = args.out or req / "test-gaps.md"

    results, skipped, errors, status = build(root, inventory_path, evidence_dir, obligations_path)
    if results is None:
        for error in errors:
            print(error)
        return status
    overrides, _ = load_overrides(obligations_path)
    text = render(results, skipped, len(overrides or []))
    if args.check:
        try:
            current = out_path.read_text(encoding="utf-8")
        except (OSError, UnicodeError) as exc:
            print(f"{out_path.name}: unreadable input: {exc}")
            return 2
        if current != text:
            print(f"{out_path.name} is stale: run python3 gates/gen_req_gaps.py")
            return 1
        return 0
    try:
        out_path.write_text(text, encoding="utf-8")
    except OSError as exc:
        print(f"{out_path.name}: cannot write: {exc}")
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
