#!/usr/bin/env python3
"""Observed-red tests for gen_req_gaps.py."""

from __future__ import annotations

import contextlib
import io
import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
import gen_req_gaps  # noqa: E402

GENERATOR = ROOT / "gates" / "gen_req_gaps.py"

ENC_RS = "pub fn encode_thing() {}\npub fn decode_thing() {}\n"
DEC_RS = "pub fn decode_other() {}\n"
COMMENT_RS = "// pub fn encode_in_comment() {}\n/// pub fn encode_in_doc() {}\npub fn decode_x() {}\n"

INVENTORY = '''
[inventory]
id = "t"
title = "t"
source = "t"

[[group]]
id = "DER"
title = "DER"

[[group]]
id = "STD"
title = "STD"
parent = "DER"

[[group]]
id = "STD.X690"
title = "X690"
parent = "STD"

[[group]]
id = "SAFE"
title = "SAFE"
parent = "DER"

[[group]]
id = "CODEC"
title = "CODEC"
parent = "DER"

[[group]]
id = "PROF"
title = "PROF"
parent = "DER"

[[group]]
id = "API"
title = "API"
parent = "DER"
'''


def item(ident, parent="STD.X690", side="both", modules=("enc",), disposition="in", note=""):
    mods = ", ".join(f'"{m}"' for m in modules)
    text = (
        f'\n[[item]]\nid = "{ident}"\ntitle = "title {ident}"\nref = "r"\nparent = "{parent}"\n'
        f'force = "shall"\nside = "{side}"\nsource = "primary"\ndisposition = "{disposition}"\n'
        f"modules = [{mods}]\n"
    )
    if note:
        text += f'note = "{note}"\n'
    return text


def entry(kind, module, name, accept=(), reject=(), prove=()):
    def lst(values):
        return "[" + ", ".join(f'"{v}"' for v in values) + "]"

    bounded = "len <= 3" if kind == "kani" and prove else ""
    return (
        f'\n[[entry]]\nkind = "{kind}"\nfile = "der-verified/src/{module}.rs"\nname = "{name}"\n'
        f"accept = {lst(accept)}\nreject = {lst(reject)}\nprove = {lst(prove)}\n"
        f'bounded = "{bounded}"\nnone = ""\n'
    )


class Tree:
    """A small temporary requirements tree."""

    def __init__(self, items: str, entries: dict[str, str] | None = None, overrides: str = "",
                 sources: dict[str, str] | None = None):
        self._tmp = tempfile.TemporaryDirectory()
        self.root = Path(self._tmp.name)
        src = self.root / "der-verified" / "src"
        src.mkdir(parents=True)
        for name, text in (sources or {"enc": ENC_RS, "dec": DEC_RS}).items():
            (src / f"{name}.rs").write_text(text)
        req = self.root / "docs" / "requirements"
        (req / "evidence").mkdir(parents=True)
        (req / "der.inventory.toml").write_text(INVENTORY + items)
        for name, text in (entries or {}).items():
            (req / "evidence" / f"{name}.toml").write_text(text)
        (req / "obligations.toml").write_text(overrides)
        self.out = req / "test-gaps.md"

    def run(self, *extra: str) -> tuple[int, str]:
        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            code = gen_req_gaps.main(["--root", str(self.root), *extra])
        return code, buffer.getvalue()

    def results(self):
        req = self.root / "docs" / "requirements"
        results, skipped, errors, status = gen_req_gaps.build(
            self.root, req / "der.inventory.toml", req / "evidence", req / "obligations.toml"
        )
        return results, skipped, errors, status

    def by_id(self):
        results, _, errors, status = self.results()
        assert results is not None, (errors, status)
        return {r.row["id"]: r for r in results}

    def close(self):
        self._tmp.cleanup()


class StatusTests(unittest.TestCase):
    def tree(self, items, entries=None, overrides="", sources=None):
        t = Tree(items, entries, overrides, sources)
        self.addCleanup(t.close)
        return t

    def test_covered(self):
        t = self.tree(
            item("X690-1", modules=("dec",)),
            {"dec": entry("test", "dec", "a", accept=["X690-1"]) + entry("test", "dec", "r", reject=["X690-1"])},
        )
        r = t.by_id()["X690-1"]
        self.assertEqual(r.overall, "COVERED")
        self.assertEqual(r.obligation.needs, ("accept", "reject"))

    def test_partial(self):
        t = self.tree(
            item("X690-1", modules=("dec",)),
            {"dec": entry("test", "dec", "a", accept=["X690-1"])},
        )
        r = t.by_id()["X690-1"]
        self.assertEqual(r.overall, "PARTIAL")
        self.assertEqual(r.role_status, {"accept": "MET", "reject": "MISSING"})
        self.assertEqual(r.missing, ["reject test"])

    def test_proof_only(self):
        t = self.tree(
            item("X690-1", modules=("dec",)),
            {"dec": entry("kani", "dec", "k", reject=["X690-1"])},
        )
        r = t.by_id()["X690-1"]
        self.assertEqual(r.overall, "PROOF-ONLY")
        self.assertEqual(r.role_status["reject"], "PROOF-ONLY")
        self.assertEqual(r.role_status["accept"], "MISSING")

    def test_none(self):
        t = self.tree(item("X690-1", modules=("dec",)))
        r = t.by_id()["X690-1"]
        self.assertEqual(r.overall, "NONE")
        self.assertEqual(r.kind_totals, {"test": 0, "kani": 0, "lean": 0})

    def test_known_gap_flag(self):
        t = self.tree(item("X690-1", modules=("dec",), note="gap: not done"))
        self.assertTrue(t.by_id()["X690-1"].known_gap)

    def test_umbrella_and_non_in_rows_are_skipped(self):
        t = self.tree(
            item("X690-1", note="umbrella; decided by sentences")
            + item("X690-2", disposition="excluded")
            + item("X690-3", modules=("dec",))
        )
        results, skipped, _, _ = t.results()
        self.assertEqual([r.row["id"] for r in results], ["X690-3"])
        self.assertEqual(skipped, 1)


class RuleTests(unittest.TestCase):
    def tree(self, items, entries=None, overrides="", sources=None):
        t = Tree(items, entries, overrides, sources)
        self.addCleanup(t.close)
        return t

    def test_safe_family_needs_proof_and_tests_do_not_discharge(self):
        t = self.tree(
            item("SAFE-a-1", parent="SAFE", modules=("dec",)) + item("SAFE-b-1", parent="SAFE", modules=("dec",)),
            {"dec": entry("test", "dec", "a", accept=["SAFE-a-1"]) + entry("kani", "dec", "k", prove=["SAFE-b-1"])},
        )
        rows = t.by_id()
        self.assertEqual(rows["SAFE-a-1"].obligation.needs, ("prove",))
        self.assertEqual(rows["SAFE-a-1"].overall, "NONE")
        self.assertEqual(rows["SAFE-b-1"].overall, "COVERED")

    def test_api_family_is_review(self):
        t = self.tree(item("API-a-1", parent="API", modules=("dec",)))
        self.assertEqual(t.by_id()["API-a-1"].overall, "REVIEW")

    def test_codec_and_prof_families(self):
        ids = ["CODEC-x-unique", "CODEC-x-reject-nonder", "CODEC-x-encode-decode", "CODEC-x-decode-encode"]
        t = self.tree(
            "".join(item(i, parent="CODEC", modules=("enc",)) for i in ids)
            + item("PROF-p", parent="PROF", modules=("dec",))
        )
        rows = t.by_id()
        self.assertEqual(rows["CODEC-x-unique"].obligation.needs, ("reject",))
        self.assertEqual(rows["CODEC-x-reject-nonder"].obligation.needs, ("reject",))
        self.assertEqual(rows["CODEC-x-encode-decode"].obligation.needs, ("accept",))
        self.assertEqual(rows["CODEC-x-decode-encode"].obligation.needs, ("accept",))
        self.assertEqual(rows["PROF-p"].obligation.needs, ("accept", "reject"))

    def test_encoder_modules_are_derived_from_code_not_comments(self):
        t = self.tree(
            item("X690-1"),
            sources={"enc": ENC_RS, "dec": DEC_RS, "cmt": COMMENT_RS},
        )
        found, status = gen_req_gaps.encoder_modules(t.root)
        self.assertEqual(status, 0)
        self.assertEqual(found, {"enc"})

    def test_encoder_obligation_only_with_an_encoder_module(self):
        t = self.tree(
            item("X690-enc", side="encoder", modules=("enc",))
            + item("X690-noenc", side="encoder", modules=("dec",))
            + item("X690-both-enc", side="both", modules=("enc",))
            + item("X690-both-dec", side="both", modules=("dec",))
            + item("X690-decoder", side="decoder", modules=("enc",))
            + item("X690-issuer", side="issuer", modules=("dec",))
            + item("X690-rp", side="relying-party", modules=("dec",))
        )
        rows = t.by_id()
        self.assertEqual(rows["X690-enc"].obligation.needs, ("accept",))
        self.assertTrue(rows["X690-enc"].obligation.enc_accept)
        self.assertEqual(rows["X690-noenc"].obligation.needs, ())
        self.assertEqual(rows["X690-noenc"].overall, "NOT-REQUIRED")
        self.assertEqual(rows["X690-both-enc"].obligation.needs, ("accept", "reject"))
        self.assertTrue(rows["X690-both-enc"].obligation.enc_accept)
        self.assertEqual(rows["X690-both-dec"].obligation.needs, ("accept", "reject"))
        self.assertFalse(rows["X690-both-dec"].obligation.enc_accept)
        self.assertEqual(rows["X690-decoder"].obligation.needs, ("accept", "reject"))
        self.assertFalse(rows["X690-decoder"].obligation.enc_accept)
        self.assertEqual(rows["X690-issuer"].obligation.needs, ("accept", "reject"))
        self.assertEqual(rows["X690-rp"].obligation.needs, ("accept", "reject"))

    def test_encoder_accept_must_sit_in_an_encoder_module(self):
        t = self.tree(
            item("X690-1", side="both", modules=("enc",)) + item("X690-2", side="both", modules=("enc",)),
            {
                "dec": entry("test", "dec", "a", accept=["X690-1"]) + entry("test", "dec", "r", reject=["X690-1"]),
                "enc": entry("test", "enc", "a", accept=["X690-2"]) + entry("test", "enc", "r", reject=["X690-2"]),
            },
        )
        rows = t.by_id()
        self.assertEqual(rows["X690-1"].role_status["accept"], "MISSING-ENC")
        self.assertEqual(rows["X690-1"].overall, "PARTIAL")
        self.assertEqual(rows["X690-1"].missing, ["accept test in a module with an encoder"])
        self.assertEqual(rows["X690-2"].overall, "COVERED")

    def test_override_replaces_default(self):
        t = self.tree(
            item("X690-1", modules=("enc",)),
            {"enc": entry("test", "dec", "a", accept=["X690-1"])},
            overrides='[[override]]\nid = "X690-1"\nneeds = ["accept"]\nreason = "definition"\n',
        )
        r = t.by_id()["X690-1"]
        self.assertTrue(r.obligation.overridden)
        self.assertEqual(r.overall, "COVERED")


class OverrideErrorTests(unittest.TestCase):
    def errors(self, overrides: str, items: str | None = None) -> tuple[int, str]:
        t = Tree(
            items if items is not None else item("X690-1", modules=("dec",)) + item("X690-x", disposition="excluded"),
            overrides=overrides,
        )
        self.addCleanup(t.close)
        return t.run()

    def assertRed(self, overrides: str, fragment: str, items: str | None = None):
        code, out = self.errors(overrides, items)
        self.assertEqual(code, 1, out)
        self.assertIn(fragment, out)

    def test_unknown_id(self):
        self.assertRed('[[override]]\nid = "NOPE"\nneeds = ["accept"]\nreason = "r"\n', "unknown id")

    def test_non_in_row(self):
        self.assertRed('[[override]]\nid = "X690-x"\nneeds = ["accept"]\nreason = "r"\n', "not an `in` row")

    def test_umbrella_row(self):
        self.assertRed(
            '[[override]]\nid = "X690-u"\nneeds = ["accept"]\nreason = "r"\n',
            "umbrella",
            item("X690-u", note="umbrella; sentences decide"),
        )

    def test_empty_reason(self):
        self.assertRed('[[override]]\nid = "X690-1"\nneeds = ["accept"]\nreason = "  "\n', "reason must not be empty")

    def test_missing_reason(self):
        self.assertRed('[[override]]\nid = "X690-1"\nneeds = ["accept"]\n', "reason must not be empty")

    def test_unknown_role(self):
        self.assertRed('[[override]]\nid = "X690-1"\nneeds = ["bogus"]\nreason = "r"\n', "unknown role")

    def test_duplicate(self):
        one = '[[override]]\nid = "X690-1"\nneeds = ["accept"]\nreason = "r"\n'
        self.assertRed(one + "\n" + one, "duplicate override")

    def test_unknown_key(self):
        self.assertRed('[[override]]\nid = "X690-1"\nneeds = ["accept"]\nreason = "r"\nextra = 1\n', "unknown key")

    def test_unreadable_obligations_exits_2(self):
        t = Tree(item("X690-1", modules=("dec",)))
        self.addCleanup(t.close)
        (t.root / "docs" / "requirements" / "obligations.toml").unlink()
        code, _ = t.run()
        self.assertEqual(code, 2)


class CheckModeTests(unittest.TestCase):
    def test_check_detects_drift_and_missing(self):
        t = Tree(item("X690-1", modules=("dec",)))
        self.addCleanup(t.close)
        code, _ = t.run("--check")
        self.assertEqual(code, 2, "no report file yet is unreadable input")
        self.assertEqual(t.run()[0], 0)
        self.assertEqual(t.run("--check")[0], 0)
        # Drift 1: the report text is edited by hand.
        t.out.write_text(t.out.read_text() + "\nhand edit\n")
        code, out = t.run("--check")
        self.assertEqual(code, 1)
        self.assertIn("stale", out)
        # Regenerate, then drift 2: the evidence changes and the report is not regenerated.
        self.assertEqual(t.run()[0], 0)
        (t.root / "docs" / "requirements" / "evidence" / "dec.toml").write_text(
            entry("test", "dec", "a", accept=["X690-1"])
        )
        self.assertEqual(t.run("--check")[0], 1)
        self.assertEqual(t.run()[0], 0)
        self.assertEqual(t.run("--check")[0], 0)

    def test_report_lists_work_by_module(self):
        t = Tree(item("X690-1", modules=("dec",)))
        self.addCleanup(t.close)
        self.assertEqual(t.run()[0], 0)
        text = t.out.read_text()
        self.assertIn("### dec (1 row)", text)
        self.assertIn("- X690-1 [NONE]: missing accept test; missing reject test.", text)
        self.assertNotIn("orac" + "le", text.lower())


class RealFilesTest(unittest.TestCase):
    def run_gen(self, *args: str) -> subprocess.CompletedProcess:
        return subprocess.run(
            [sys.executable, "-I", str(GENERATOR), *args], capture_output=True, text=True, cwd=ROOT
        )

    def test_real_files_generate_then_check(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "test-gaps.md"
            done = self.run_gen("--out", str(out))
            self.assertEqual(done.returncode, 0, done.stdout + done.stderr)
            checked = self.run_gen("--check", "--out", str(out))
            self.assertEqual(checked.returncode, 0, checked.stdout + checked.stderr)

    def test_committed_report_is_current(self):
        done = self.run_gen("--check")
        self.assertEqual(done.returncode, 0, done.stdout + done.stderr)

    def test_real_overrides_all_have_reasons(self):
        rows, status = gen_req_gaps.load_overrides(ROOT / "docs" / "requirements" / "obligations.toml")
        self.assertEqual(status, 0)
        self.assertTrue(all(isinstance(r.get("reason"), str) and r["reason"].strip() for r in rows))


if __name__ == "__main__":
    unittest.main()
