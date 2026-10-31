#!/usr/bin/env python3
"""Regression test: every Lean extraction shim crate is its own Cargo workspace root.

The shims (`lean/extract*`) are excluded from the repo-root workspace, but an `exclude` entry only
helps when the repo root IS the nearest enclosing workspace. A checkout nested below another
directory with a workspace `Cargo.toml` (e.g. the proof recorder's git worktree under
`<repo>/.git/der-proof-checkout-*/checkout/`) makes cargo find the OUTER workspace and fail with
"current package believes it's in a workspace when it's not". An empty `[workspace]` table in each
shim manifest prevents that.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import tempfile
import tomllib
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SHIM_MANIFESTS = sorted(ROOT.glob("lean/extract*/Cargo.toml"))


def _load(path: Path) -> dict:
    with path.open("rb") as handle:
        return tomllib.load(handle)


class LeanShimWorkspaceTests(unittest.TestCase):
    def test_shims_discovered(self):
        self.assertTrue(SHIM_MANIFESTS, "no lean/extract*/Cargo.toml found")

    def test_root_exclude_matches_shim_set(self):
        exclude = set(_load(ROOT / "Cargo.toml")["workspace"]["exclude"])
        found = {m.parent.relative_to(ROOT).as_posix() for m in SHIM_MANIFESTS}
        self.assertEqual(exclude, found)

    def test_each_shim_declares_own_workspace(self):
        for manifest in SHIM_MANIFESTS:
            with self.subTest(shim=manifest.parent.name):
                self.assertIn(
                    "workspace",
                    _load(manifest),
                    f"{manifest.relative_to(ROOT)} has no top-level [workspace] table",
                )

    @unittest.skipUnless(shutil.which("cargo"), "cargo not on PATH; nested-workspace check skipped")
    def test_shims_resolve_when_nested_under_outer_workspace(self):
        with tempfile.TemporaryDirectory() as tmp:
            tmp_path = Path(tmp)
            (tmp_path / "Cargo.toml").write_text("[workspace]\nmembers = []\n")
            env = dict(os.environ, RUSTUP_TOOLCHAIN="stable")
            for manifest in SHIM_MANIFESTS:
                shim = manifest.parent
                # Shim sources `#[path]`-include der-verified/src, but `cargo metadata` does not
                # compile them, so only the manifest, lockfile and the lib stub are needed.
                dest = tmp_path / "nested" / "lean" / shim.name
                dest.mkdir(parents=True)
                shutil.copy(manifest, dest / "Cargo.toml")
                shutil.copy(shim / "Cargo.lock", dest / "Cargo.lock")
                shutil.copytree(shim / "src", dest / "src")
                with self.subTest(shim=shim.name):
                    result = subprocess.run(
                        [
                            "cargo", "metadata", "--no-deps", "--offline",
                            "--format-version", "1",
                            "--manifest-path", str(dest / "Cargo.toml"),
                        ],
                        env=env, capture_output=True, text=True, check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)


if __name__ == "__main__":
    unittest.main()
