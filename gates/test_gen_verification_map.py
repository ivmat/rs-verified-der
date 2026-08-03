#!/usr/bin/env python3
"""test_gen_verification_map.py — the verification-map gate's own gate.

`gen_verification_map.py` regenerates README.md's mermaid "verification map" from source, and
fails `--check` if the committed diagram disagrees. Nothing was stopping *that script* from
drifting silently: an over-strict parity check blocks a brand-new, perfectly ordinary codec
module before anyone can even look at the diagram, and an over-lenient one lets a module vanish
from the picture with no error at all. Both directions are tested here, paired, exactly as
`test_gen_proof_manifest.py` already does for its sibling gate.

Run:  python3 gates/test_gen_verification_map.py      (pure stdlib; wired into check.sh/check_fast.sh)
"""

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)


def _load(modname, filename):
    spec = importlib.util.spec_from_file_location(modname, os.path.join(HERE, filename))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gen = _load('gen_verification_map', 'gen_verification_map.py')


def real_readme():
    with open(gen.README, encoding='utf-8') as fh:
        return fh.read()


class Derivation(unittest.TestCase):
    """The DERIVED half: green/blue must track the tree, and only the tree."""

    def test_derive_colors_splits_roster_by_l4_membership(self):
        roster = {'tag', 'length', 'oid', 'bit_string'}
        l4 = {'tag', 'oid'}
        green, blue = gen.derive_colors(roster, l4)
        self.assertEqual(green, ['oid', 'tag'])
        self.assertEqual(blue, ['bit_string', 'length'])

    def test_a_lid_gain_moves_a_module_green(self):
        # Fault injection #1: simulate landing a NEW Lean lid on `bit_string`. Before: blue.
        roster = {'tag', 'bit_string'}
        l4_before = {'tag'}
        green_before, blue_before = gen.derive_colors(roster, l4_before)
        self.assertIn('bit_string', blue_before)
        self.assertNotIn('bit_string', green_before)
        # After the (simulated) lid lands:
        l4_after = {'tag', 'bit_string'}
        green_after, blue_after = gen.derive_colors(roster, l4_after)
        self.assertIn('bit_string', green_after)
        self.assertNotIn('bit_string', blue_after)

    def test_a_lid_loss_moves_a_module_back_to_blue(self):
        # The mirror image: a lid regresses (e.g. a `sorry` creeps back in and the lid is pulled).
        roster = {'tag', 'oid'}
        l4_before = {'tag', 'oid'}
        green_before, _ = gen.derive_colors(roster, l4_before)
        self.assertEqual(green_before, ['oid', 'tag'])
        l4_after = {'tag'}
        green_after, blue_after = gen.derive_colors(roster, l4_after)
        self.assertEqual(green_after, ['tag'])
        self.assertIn('oid', blue_after)

    def test_green_set_is_derived_from_the_same_l4_module_set_as_the_manifest(self):
        # Not a mock: the REAL crate's green set must equal gen_proof_manifest's own L4 set,
        # restricted to what tiers.txt harnesses -- if these two ever diverge, the map and
        # PROOF_MANIFEST.md would tell a reader two different stories about the same six codecs.
        roster = gen.roster_from_tiers()
        l4 = gen.gpm.l4_module_set()
        green, _blue = gen.derive_colors(roster, l4)
        self.assertEqual(set(green), l4 & roster)
        self.assertEqual(set(green), {'length', 'big_integer', 'oid', 'tag', 'tlv', 'sequence'})


class LayerClassification(unittest.TestCase):
    """`layer_of` must be TOTAL over the roster -- a never-seen-before module name is exactly the
    case a hand-maintained diagram would silently drop, and exactly the case this gate exists to
    keep from happening again."""

    def test_known_framing_modules_classify_as_framing(self):
        for m in ('tag', 'length', 'tlv'):
            self.assertEqual(gen.layer_of(m), 'framing')

    def test_x509_prefixed_module_classifies_as_structural(self):
        self.assertEqual(gen.layer_of('x509_something_brand_new'), 'structural')

    def test_an_unfamiliar_but_legitimate_new_codec_name_still_classifies_and_does_not_raise(self):
        # Over-strict direction: a codec nobody has seen before (not x509_*, not framing, not
        # `profile`) must still land somewhere sensible -- the `codecs` catch-all -- not be
        # rejected or silently dropped.
        self.assertEqual(gen.layer_of('ia5_string'), 'codecs')
        self.assertEqual(gen.layer_of('relative_oid'), 'codecs')


class DeclaredFile(unittest.TestCase):
    """`gates/map_declared.txt` parsing: the file's own internal shape, independent of the roster."""

    def _write(self, dirpath, rows):
        p = os.path.join(dirpath, 'declared.txt')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write('# header comment\n')
            for row in rows:
                fh.write('\t'.join(row) + '\n')
        return p

    def test_the_real_file_parses_and_every_row_is_sourced(self):
        rows = gen.read_declared()
        self.assertTrue(rows)
        for r in rows:
            self.assertIn(r['color'], gen.COLORS)
            self.assertIn(r['layer'], gen.LAYERS)
            self.assertTrue(r['source'].strip(), 'row %r has an empty source' % r['id'])

    def test_missing_source_column_content_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('yellow', 'thing_one', 'profile', 'A thing', '')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_bad_color_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('purple', 'thing_one', 'profile', 'A thing', 'README.md:1')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_bad_layer_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('yellow', 'thing_one', 'nowhere', 'A thing', 'README.md:1')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_non_mermaid_safe_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('yellow', 'Thing-One!', 'profile', 'A thing', 'README.md:1')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_wrong_field_count_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'declared.txt')
            with open(p, 'w', encoding='utf-8') as fh:
                fh.write('yellow\tthing_one\tprofile\n')  # missing label + source
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_duplicate_declared_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [
                ('yellow', 'thing_one', 'profile', 'A thing', 'README.md:1'),
                ('gray', 'thing_one', 'codecs', 'Another thing', 'README.md:2'),
            ])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_a_legitimate_well_formed_row_passes(self):
        # Over-strict direction: nothing above should reject a perfectly normal row.
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('red', 'some_wall', 'codecs', 'A wall we hit', 'TODO.md:1')])
            rows = gen.read_declared(p)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['color'], 'red')


class Parity(unittest.TestCase):
    """`parity_errors`: the two ways a module can disappear from -- or corrupt -- the picture."""

    def test_a_module_in_neither_derived_nor_declared_set_fails(self):
        # Fault injection: simulate a NEW module landing in gates/tiers.txt (so it is on the
        # roster) whose colour the render pipeline somehow failed to compute (e.g. a bug that
        # only appends to `blue` for some modules). It must not silently vanish from the picture.
        roster = {'tag', 'length', 'brand_new_module'}
        green, blue = ['tag'], ['length']   # 'brand_new_module' missing from both, by construction
        errs = gen.parity_errors(roster, green, blue, declared=[])
        self.assertTrue(any('brand_new_module' in e for e in errs), errs)
        self.assertTrue(any('vanish' in e for e in errs), errs)

    def test_a_module_correctly_covered_by_blue_does_not_fail(self):
        # Over-strict direction / mirror image of the above: the SAME new module, this time
        # correctly picked up by the ordinary roster-minus-l4 derivation, must not be flagged.
        roster = {'tag', 'length', 'brand_new_module'}
        l4 = set()
        green, blue = gen.derive_colors(roster, l4)
        errs = gen.parity_errors(roster, green, blue, declared=[])
        self.assertEqual(errs, [])

    def test_a_declared_id_colliding_with_a_derived_module_name_fails(self):
        roster = {'tag', 'length'}
        green, blue = ['tag'], ['length']
        declared = [{'id': 'tag', 'color': 'yellow', 'layer': 'framing', 'label': 'x',
                    'source': 'y'}]
        errs = gen.parity_errors(roster, green, blue, declared)
        self.assertTrue(any('collide' in e and 'tag' in e for e in errs), errs)

    def test_a_declared_id_not_colliding_with_anything_does_not_fail(self):
        roster = {'tag', 'length'}
        green, blue = ['tag'], ['length']
        declared = [{'id': 'totally_unrelated_id', 'color': 'yellow', 'layer': 'profile',
                    'label': 'x', 'source': 'y'}]
        self.assertEqual(gen.parity_errors(roster, green, blue, declared), [])

    def test_the_real_declared_file_does_not_collide_with_the_real_roster(self):
        roster = gen.roster_from_tiers()
        declared = gen.read_declared()
        collisions = {d['id'] for d in declared} & roster
        self.assertEqual(collisions, set(), 'declared id(s) shadow a real module: %s' % collisions)

    def test_compute_raises_on_an_l4_lid_for_a_module_absent_from_tiers(self):
        # A Lean lid landing on a module that (for whatever reason -- typo, a pulled harness) is
        # not itself Kani-harnessed in gates/tiers.txt must fail loudly, not drop the lid quietly.
        real_l4 = gen.gpm.l4_module_set
        try:
            gen.gpm.l4_module_set = lambda: real_l4() | {'a_module_with_no_kani_harness'}
            with self.assertRaises(SystemExit):
                gen.compute()
        finally:
            gen.gpm.l4_module_set = real_l4


class RegionPlumbing(unittest.TestCase):
    def test_the_real_readme_map_region_is_current(self):
        self.assertIsNone(gen.region_diff(real_readme()))

    def test_write_is_idempotent(self):
        once, missing = gen.rewrite(real_readme())
        self.assertFalse(missing)
        twice, _ = gen.rewrite(once)
        self.assertEqual(once, twice)

    def test_missing_marker_is_reported(self):
        text = real_readme().replace(gen.BEGIN % gen.NAME, '')
        _, missing = gen.rewrite(text)
        self.assertTrue(missing)

    def test_render_contains_every_roster_and_declared_id(self):
        rendered = gen.render()
        roster = gen.roster_from_tiers()
        for m in roster:
            self.assertIn(m + '[', rendered, '%s missing from rendered map' % m)
        for d in gen.read_declared():
            self.assertIn(d['id'] + '[', rendered, '%s missing from rendered map' % d['id'])


class GateExitCode(unittest.TestCase):
    """End-to-end: `main()`'s exit code and message, not just the internal diff function --
    exactly the same reasoning `test_gen_proof_manifest.py`'s `GateExitCode` class gives: every
    test above could pass while `main()` ignored its own findings and returned 0."""

    def _check(self, readme_text):
        with tempfile.NamedTemporaryFile('w', suffix='.md', delete=False,
                                          encoding='utf-8') as fh:
            fh.write(readme_text)
            path = fh.name
        real_readme_path, real_argv = gen.README, sys.argv
        try:
            gen.README = path
            sys.argv = ['gen_verification_map.py', '--check']
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = gen.main()
            return code, err.getvalue()
        finally:
            gen.README, sys.argv = real_readme_path, real_argv
            os.unlink(path)

    def test_committed_readme_exits_zero(self):
        code, err = self._check(real_readme())
        self.assertEqual(code, 0, err)

    def test_drifted_map_region_exits_one_and_names_the_gate(self):
        text = real_readme()
        b, e = gen.BEGIN % gen.NAME, gen.END % gen.NAME
        pre, rest = text.split(b, 1)
        _body, post = rest.split(e, 1)
        drifted = pre + b + '\nsomeone hand-edited this diagram\n' + e + post
        self.assertNotEqual(drifted, text)
        code, err = self._check(drifted)
        self.assertEqual(code, 1)
        self.assertIn('verification-map gate', err)
        self.assertIn('README.md', err)

    def test_missing_marker_exits_one(self):
        code, err = self._check(real_readme().replace(gen.BEGIN % gen.NAME, ''))
        self.assertEqual(code, 1)
        self.assertIn('missing generated region marker', err)

    def test_a_newline_only_difference_still_prints_a_diff(self):
        b = gen.BEGIN % gen.NAME
        text = real_readme().replace(b + '\n', b, 1)
        self.assertNotEqual(text, real_readme())
        code, err = self._check(text)
        self.assertEqual(code, 1)
        body = [l for l in err.split('\n') if l.strip().startswith(('+', '-'))
                and not l.strip().startswith(('+++', '---'))]
        self.assertTrue(body, 'gate reported a disagreement but printed no diff:\n' + err)


if __name__ == '__main__':
    unittest.main(verbosity=2, argv=[sys.argv[0]] + sys.argv[1:])
