#!/usr/bin/env python3
"""Validate the actual offline package outside Git, with its documented root."""
from pathlib import Path
import subprocess
import tarfile
import tempfile
import tomllib
import unittest

ROOT = Path(__file__).resolve().parent.parent
VALIDATOR = ROOT / 'gates/vendor/acceptance/format_acceptance/tools/check_acceptance.py'


class PackageAcceptanceTests(unittest.TestCase):
    def test_packed_manifest_validates_and_requires_the_inventory(self):
        with tempfile.TemporaryDirectory(prefix='der-package-') as tmp:
            target = Path(tmp)
            result = subprocess.run([
                'cargo', 'package', '--offline', '--no-verify', '--allow-dirty',
                '--manifest-path', str(ROOT / 'der-verified/Cargo.toml'),
                '--target-dir', str(target / 'target')],
                cwd=ROOT, capture_output=True, text=True, check=False)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            package = tomllib.loads((ROOT / 'der-verified/Cargo.toml').read_text())['package']
            name = f"{package['name']}-{package['version']}"
            with tarfile.open(target / 'target/package' / f'{name}.crate') as archive:
                archive.extractall(target / 'unpacked', filter='data')
            unpacked = target / 'unpacked' / name
            command = ['python3', '-B', str(VALIDATOR), '--strict', '--strict-weight',
                       '--root', str(unpacked), str(unpacked / 'acceptance.toml')]
            good = subprocess.run(command, cwd=target, capture_output=True, text=True, check=False)
            self.assertEqual(good.returncode, 0, good.stdout + good.stderr)
            self.assertIn('PASS', good.stdout)
            (unpacked / 'der.inventory.toml.vendored-copy').unlink()
            bad = subprocess.run(command, cwd=target, capture_output=True, text=True, check=False)
            self.assertNotEqual(bad.returncode, 0)
            self.assertIn('spec.inventory', bad.stdout + bad.stderr)


if __name__ == '__main__':
    unittest.main()
