#!/usr/bin/env python3
"""test_gen_verification_map.py — the verification-map gate's own gate.

`gen_verification_map.py` regenerates README.md's mermaid "verification map" from the acceptance/0
manifest plus the module roster, and fails `--check` if the committed diagram disagrees. Nothing was
stopping *that script* from drifting silently: an over-strict parity check blocks a brand-new,
perfectly ordinary codec module before anyone can even look at the diagram, and an over-lenient one
lets a module vanish from the picture with no error at all. Both directions are tested here, paired,
exactly as `test_gen_proof_manifest.py` already does for its sibling gate.

Since 2026-09-05 the map's colour is the assurance BAND, so this file also holds the line that
matters most for a front-page picture: **no node may be drawn stronger than the manifest says**, a
module the manifest does not rate at all is drawn `unrated` rather than banded, and the goal line
counts what it claims to count.

Run:  python3 gates/test_gen_verification_map.py      (pure stdlib; wired into check.sh/check_fast.sh)
"""

import contextlib
import copy
import importlib.util
import io
import os
import re
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

NODE_RE = re.compile(r'^\s+([a-z][a-z0-9_]*)\["(.*)"\]:::([a-z0-9_]+)$')


def real_readme():
    with open(gen.README, encoding='utf-8') as fh:
        return fh.read()


def rendered_nodes(text):
    """node id -> (header line, [member name, ...], mermaid class) for every node in a render."""
    out = {}
    for line in text.split('\n'):
        m = NODE_RE.match(line)
        if not m:
            continue
        parts = m.group(2).split('<br/>')
        names = [n.strip() for chunk in parts[1:] for n in chunk.split('·')]
        out[m.group(1)] = (parts[0], [n for n in names if n], m.group(3))
    return out


def claim(cid, band, grade='contract', weight='weighted'):
    return {'id': cid, 'band': band, 'grade': grade, 'weight': weight}


class ManifestReading(unittest.TestCase):
    """The manifest is the ONLY source of a colour. Reading it wrong is the one bug that would put
    a stronger colour on the front page than the evidence earns."""

    def _write(self, dirpath, body):
        p = os.path.join(dirpath, 'acceptance.toml')
        with open(p, 'w', encoding='utf-8') as fh:
            fh.write(body)
        return p

    def test_the_real_manifest_parses_and_every_claim_carries_a_known_band(self):
        claims, prov = gen.read_manifest()
        self.assertTrue(claims)
        for c in claims:
            self.assertIn(c['band'], gen.BAND_ORDER)
            self.assertTrue(c['grade'])
            self.assertIn(c['weight'], ('weighted', 'unweighted'))
        self.assertEqual(prov['claims_total'], len(claims))
        self.assertTrue(prov['commit'])

    def test_a_claim_with_no_band_reads_as_a0_not_as_something_better(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, '[[claim]]\nid = "PM/x"\ngrade = "probe"\n')
            claims, _prov = gen.read_manifest(p)
            self.assertEqual(claims[0]['band'], 'A0')
            self.assertEqual(claims[0]['weight'], 'unweighted')

    def test_an_unknown_band_fails_loudly_instead_of_being_drawn_as_something_else(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, '[[claim]]\nid = "PM/x"\nband = "A9"\n')
            with self.assertRaises(SystemExit):
                gen.read_manifest(p)

    def test_a_manifest_with_no_claims_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, '[subject]\nname = "x"\n')
            with self.assertRaises(SystemExit):
                gen.read_manifest(p)

    def test_a_missing_manifest_fails_rather_than_rendering_an_uncoloured_map(self):
        with self.assertRaises(SystemExit):
            gen.read_manifest(os.path.join(ROOT, 'no', 'such', 'acceptance.toml'))


class ClaimPlacement(unittest.TestCase):
    """Which node a claim lands in — and the two ways a claim or a module can go missing."""

    def test_module_and_lid_claims_are_split_by_id(self):
        roster = {'tag', 'big_integer'}
        by_module, by_lid, unmapped = gen.split_claims(
            [claim('PM/tag', 'A3'), claim('PM/lean-bigint', 'A4')], roster)
        self.assertEqual(set(by_module), {'tag'})
        self.assertEqual(set(by_lid), {'big_integer'})
        self.assertEqual(unmapped, [])

    def test_a_claim_that_maps_to_nothing_is_reported_not_dropped(self):
        _bm, _bl, unmapped = gen.split_claims([claim('PM/not_a_module', 'A3')], {'tag'})
        self.assertEqual(unmapped, ['PM/not_a_module'])

    def test_compute_raises_when_the_manifest_holds_a_claim_the_map_cannot_place(self):
        real = gen.read_manifest
        try:
            gen.read_manifest = lambda *a, **k: (real()[0] + [claim('PM/ghost_module', 'A4')],
                                                 real()[1])
            with self.assertRaises(SystemExit):
                gen.compute()
        finally:
            gen.read_manifest = real

    def test_the_manifest_lid_claims_match_the_tree_lid_set(self):
        # Not a mock: the REAL crate's PM/lean-* claims must name exactly the modules
        # gen_proof_manifest derives a Lean lid for -- if these diverge, the map and
        # PROOF_MANIFEST.md would tell a reader two different stories about the same six codecs.
        claims, _prov = gen.read_manifest()
        lids = {gen.lid_module(c['id']) for c in claims if gen.lid_module(c['id'])}
        self.assertEqual(lids, gen.gpm.l4_module_set())
        self.assertEqual(lids, {'length', 'big_integer', 'oid', 'tag', 'tlv', 'sequence'})

    def test_compute_raises_when_the_manifest_and_the_tree_disagree_about_lids(self):
        real_l4 = gen.gpm.l4_module_set
        try:
            gen.gpm.l4_module_set = lambda: real_l4() | {'boolean'}
            with self.assertRaises(SystemExit):
                gen.compute()
        finally:
            gen.gpm.l4_module_set = real_l4


class BandColouring(unittest.TestCase):
    """The anti-overclaim line: colour follows the band, and only the band."""

    def _facts(self):
        return copy.deepcopy(gen.compute())

    def test_every_module_is_drawn_under_its_own_manifest_band(self):
        facts = self._facts()
        nodes = rendered_nodes('\n'.join(gen.render_map(facts)))
        for node_id, (header, names, klass) in nodes.items():
            if node_id.startswith('lid_') or node_id == 'legend_all':
                continue
            for name in names:
                if name not in facts['by_module']:
                    continue                      # a declared label, not a module
                band = facts['by_module'][name]['band']
                self.assertTrue(header.startswith(band + ' '),
                                '%s is drawn in a %r node but the manifest says %s'
                                % (name, header, band))
                self.assertEqual(klass, gen._safe(band))

    def test_a_claim_that_loses_its_control_moves_from_a3_to_a0_in_the_picture(self):
        # Fault injection: a mutation control is withdrawn, so `tag` drops to A0. The picture must
        # follow it down -- a colour that survives a band drop is the whole failure being guarded.
        facts = self._facts()
        before = rendered_nodes('\n'.join(gen.render_map(facts)))
        self.assertTrue(any('tag' in names and header.startswith('A3')
                            for header, names, _c in before.values()))
        facts['by_module']['tag'] = claim('PM/tag', 'A0', 'ungraded', 'unweighted')
        after = rendered_nodes('\n'.join(gen.render_map(facts)))
        placed = [header for header, names, _c in after.values() if 'tag' in names]
        self.assertTrue(placed)
        for header in placed:
            self.assertFalse(header.startswith('A3'), placed)

    def test_a_module_with_no_claim_is_drawn_unrated_rather_than_banded(self):
        # The other overclaim route: a module the manifest has not rated must NOT inherit a
        # neighbour's colour. It gets its own dashed, uncoloured box.
        facts = self._facts()
        del facts['by_module']['boolean']
        nodes = rendered_nodes('\n'.join(gen.render_map(facts)))
        placed = [(header, klass) for header, names, klass in nodes.values() if 'boolean' in names]
        self.assertEqual(len(placed), 1, placed)
        header, klass = placed[0]
        self.assertEqual(klass, 'unrated')
        self.assertIn('no claim in the manifest', header)

    def test_a_band_holding_two_grades_is_drawn_as_two_nodes_not_one_mislabelled_node(self):
        facts = self._facts()
        facts['by_module']['boolean'] = claim('PM/boolean', 'A1', 'probe', 'unweighted')
        facts['by_module']['null'] = claim('PM/null', 'A1', 'ungraded', 'unweighted')
        nodes = rendered_nodes('\n'.join(gen.render_map(facts)))
        headers = {header for header, names, _c in nodes.values()
                   if 'boolean' in names or 'null' in names}
        self.assertEqual(len(headers), 2, headers)

    def test_group_key_splits_on_band_grade_and_weight(self):
        self.assertEqual(gen._band_group_key(claim('PM/x', 'A3', 'contract', 'weighted')),
                         ('A3', 'contract', 'weighted'))
        self.assertNotEqual(gen._band_group_key(claim('PM/x', 'A3', 'contract', 'weighted')),
                            gen._band_group_key(claim('PM/y', 'A3', 'probe', 'weighted')))


class GoalLine(unittest.TestCase):
    """The one sentence a reader takes away. It must be computed, never authored."""

    def test_target_progress_counts_a3_and_above_only(self):
        claims = [claim('a', 'A4'), claim('b', 'A3'), claim('c', 'A2'),
                  claim('d', 'A1'), claim('e', 'A0')]
        self.assertEqual(gen.target_progress(claims), (2, 5))

    def test_band_counts_account_for_every_claim(self):
        claims, _prov = gen.read_manifest()
        self.assertEqual(sum(gen.band_counts(claims).values()), len(claims))

    def test_the_rendered_goal_line_states_the_manifest_numbers(self):
        facts = gen.compute()
        at, total = gen.target_progress(facts['claims'])
        text = '\n'.join(gen.render_map(facts))
        self.assertIn('**%d of %d** claims reach %s or better' % (at, total, gen.TARGET_BAND), text)
        self.assertIn('**%d** do not' % (total - at), text)

    def test_the_goal_line_follows_the_manifest_down(self):
        facts = copy.deepcopy(gen.compute())
        facts['claims'] = [claim('PM/x', 'A0', 'ungraded', 'unweighted')] * 4
        text = '\n'.join(gen.render_map(facts))
        self.assertIn('**0 of 4** claims reach A3 or better', text)
        self.assertIn('**4** do not', text)

    def test_the_legend_prints_the_whole_ladder_with_counts(self):
        facts = gen.compute()
        counts = gen.band_counts(facts['claims'])
        text = '\n'.join(gen.render_map(facts))
        for band in gen.LEGEND_LADDER:
            self.assertIn('%s %s — %d claim(s)' % (band, gen.BAND_MEANING[band],
                                                   counts.get(band, 0)), text)

    def test_the_render_names_the_manifest_it_was_drawn_from(self):
        facts = gen.compute()
        text = '\n'.join(gen.render_map(facts))
        self.assertIn('der-verified/acceptance.toml', text)
        self.assertIn(facts['provenance']['commit'], text)

    def test_a_dirty_subject_tree_is_said_out_loud(self):
        facts = copy.deepcopy(gen.compute())
        facts['provenance']['dirty'] = True
        self.assertIn('DIRTY', '\n'.join(gen.render_map(facts)))


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
            self.assertIn(r['class'], gen.DECLARED_CLASSES)
            self.assertIn(r['layer'], gen.LAYERS)
            self.assertTrue(r['source'].strip(), 'row %r has an empty source' % r['id'])

    def test_missing_source_column_content_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('planned', 'thing_one', 'profile', 'A thing', '')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_bad_class_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('purple', 'thing_one', 'profile', 'A thing', 'README.md:1')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_a_band_in_the_class_column_fails(self):
        # A declared row says "there is NO claim here". Letting it name a band would put a colour
        # on the front page that no manifest, and no control, stands behind.
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('A3', 'thing_one', 'profile', 'A thing', 'README.md:1')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_bad_layer_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('planned', 'thing_one', 'nowhere', 'A thing', 'README.md:1')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_non_mermaid_safe_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('planned', 'Thing-One!', 'profile', 'A thing', 'README.md:1')])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_wrong_field_count_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, 'declared.txt')
            with open(p, 'w', encoding='utf-8') as fh:
                fh.write('planned\tthing_one\tprofile\n')  # missing label + source
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_duplicate_declared_id_fails(self):
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [
                ('planned', 'thing_one', 'profile', 'A thing', 'README.md:1'),
                ('out-of-scope', 'thing_one', 'codecs', 'Another thing', 'README.md:2'),
            ])
            with self.assertRaises(SystemExit):
                gen.read_declared(p)

    def test_a_legitimate_well_formed_row_passes(self):
        # Over-strict direction: nothing above should reject a perfectly normal row.
        with tempfile.TemporaryDirectory() as d:
            p = self._write(d, [('wall', 'some_wall', 'codecs', 'A wall we hit', 'TODO.md:1')])
            rows = gen.read_declared(p)
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]['class'], 'wall')


class Parity(unittest.TestCase):
    """`parity_errors`: the two ways a module can disappear from -- or corrupt -- the picture."""

    def test_a_module_in_neither_drawn_nor_declared_set_fails(self):
        # Fault injection: simulate a NEW module landing in gates/tiers.txt (so it is on the
        # roster) that the render pipeline somehow failed to draw. It must not silently vanish.
        roster = {'tag', 'length', 'brand_new_module'}
        errs = gen.parity_errors(roster, {'tag', 'length'}, declared=[])
        self.assertTrue(any('brand_new_module' in e for e in errs), errs)
        self.assertTrue(any('vanish' in e for e in errs), errs)

    def test_a_module_correctly_drawn_does_not_fail(self):
        # Over-strict direction / mirror image of the above: the SAME new module, this time drawn
        # (banded or unrated), must not be flagged.
        roster = {'tag', 'length', 'brand_new_module'}
        self.assertEqual(gen.parity_errors(roster, roster, declared=[]), [])

    def test_a_declared_id_colliding_with_a_module_name_fails(self):
        roster = {'tag', 'length'}
        declared = [{'id': 'tag', 'class': 'planned', 'layer': 'framing', 'label': 'x',
                     'source': 'y'}]
        errs = gen.parity_errors(roster, roster, declared)
        self.assertTrue(any('collide' in e and 'tag' in e for e in errs), errs)

    def test_a_declared_id_not_colliding_with_anything_does_not_fail(self):
        roster = {'tag', 'length'}
        declared = [{'id': 'totally_unrelated_id', 'class': 'planned', 'layer': 'profile',
                     'label': 'x', 'source': 'y'}]
        self.assertEqual(gen.parity_errors(roster, roster, declared), [])

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

    def test_render_contains_every_roster_module_as_a_substring(self):
        # Nodes are GROUPED (one per layer/band/grade, not one per module), so a module's own name
        # is not a node id -- it only survives as text merged into a group label. That is exactly
        # the place a rendering bug could drop a module while `parity_errors` (which only ever
        # looks at the SETS, never the rendered text) stays green. Every roster module must still
        # appear, verbatim, somewhere in the rendered map.
        rendered = gen.render()
        for m in gen.roster_from_tiers():
            self.assertIn(m, rendered, '%s missing from rendered map' % m)

    def test_render_contains_every_declared_label_as_a_substring(self):
        rendered = gen.render()
        for d in gen.read_declared():
            self.assertIn(d['label'], rendered, '%s missing from rendered map' % d['id'])


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

    def test_a_hand_upgraded_band_in_the_committed_region_exits_one(self):
        # The specific tamper this gate now exists to catch: someone repaints an A0 group as A3 in
        # the committed README without the manifest ever saying so.
        text = real_readme()
        drifted = text.replace('A0 · grade:', 'A3 · grade:', 1)
        self.assertNotEqual(drifted, text)
        code, err = self._check(drifted)
        self.assertEqual(code, 1)
        self.assertIn('verification-map gate', err)

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
