#!/usr/bin/env python3
"""test_gen_proof_manifest.py — the gate's own gate.

`gen_proof_manifest.py` is what stops a hand-typed count from drifting in the proof envelope.
Nothing was stopping *it* from drifting: an over-strict `--check` blocks an honest third party
before a single proof runs, and an over-lenient one silently stops enforcing the counts. Both
failure directions are cheap to test, and neither is visible by reading the script.

Run:  python3 gates/test_gen_proof_manifest.py      (pure stdlib; wired into check.sh/check_fast.sh)

The tests are structured in opposing pairs on purpose. Every leniency test ("this must NOT fail
the gate") is paired with a strictness test ("this MUST still fail the gate"), because the easy
way to make a gate stop complaining is to make it stop checking.
"""

import contextlib
import copy
import importlib.util
import io
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)

_spec = importlib.util.spec_from_file_location('gen_proof_manifest',
                                               os.path.join(HERE, 'gen_proof_manifest.py'))
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def facts():
    """Derived facts, collected once — `collect()` shells out to rustc/kani/git."""
    if not hasattr(facts, '_cache'):
        facts._cache = gen.collect()
    return copy.deepcopy(facts._cache)


def manifest():
    with open(gen.MANIFEST, encoding='utf-8') as fh:
        return fh.read()


class ThirdPartyEnvironment(unittest.TestCase):
    """A reader with a different toolchain checks out identical source. The gate must pass.

    This is the regression these tests were opened for: the observed-toolchain line lived inside
    the byte-compared `pins` region, so `./check.sh` failed at the manifest gate for anyone whose
    rustc differed from the machine that last ran `--write` — and told them to run `--write`,
    which would have rewritten the recorded pins for a source change that never happened.
    """

    def test_different_rustc_does_not_fail_check(self):
        f = facts()
        f['toolchain']['observed']['rustc'] = 'rustc 1.93.1 (0000000000 2026-01-01)'
        self.assertEqual([n for n, _, _ in gen.region_diffs(manifest(), f)], [])

    def test_absent_kani_and_aeneas_do_not_fail_check(self):
        # What a reader who has cloned the crate but installed none of the proof tooling sees.
        f = facts()
        f['toolchain']['observed'].update({
            'rustc': 'rustc 1.90.0 (deadbeef01 2025-09-01)',
            'kani': 'not installed on this machine',
            'aeneas_rev': 'absent',
            'charon_rev': 'absent',
        })
        self.assertEqual([n for n, _, _ in gen.region_diffs(manifest(), f)], [])

    def test_manifest_recorded_on_another_machine_does_not_fail_check(self):
        # The mirror image: the *committed* observed line came from someone else's machine.
        text = manifest()
        parts = gen.split_region(text, 'pins-observed')
        self.assertIsNotNone(parts, 'the pins-observed region markers are missing')
        pre, body, post = parts
        foreign = pre + (gen.BEGIN % 'pins-observed') + \
            '\nObserved on some other machine entirely: rustc `1.0.0`, Kani `absent`.\n' + \
            (gen.END % 'pins-observed') + post
        self.assertNotEqual(foreign, text, 'the substitution did not change the manifest')
        self.assertEqual([n for n, _, _ in gen.region_diffs(foreign, facts())], [])


class StillEnforced(unittest.TestCase):
    """The counter-tests. Loosening the gate for the environment must loosen nothing else."""

    def test_drifted_harness_count_still_fails_check(self):
        f = facts()
        f['totals']['harnesses'] += 1
        self.assertIn('inventory', [n for n, _, _ in gen.region_diffs(manifest(), f)])

    def test_drifted_doctest_count_still_fails_check(self):
        # The inventory-row half of the doctest fix: `--write` regenerates "crate-doc examples
        # run as doc-tests | N |" from `totals['doctests']`, so a drift there must fail `--check`
        # exactly like the harness count above does.
        f = facts()
        f['totals']['doctests'] += 1
        self.assertIn('inventory', [n for n, _, _ in gen.region_diffs(manifest(), f)])

    def test_drifted_declared_toolchain_pin_still_fails_check(self):
        # The declared pins share a section with the advisory line but are read from in-tree
        # files (ci.yml, lean/check_lean.sh, rust-toolchain.toml) — crate properties, enforced.
        for key, value in [('kani_ci', '0.99.0'), ('aeneas', 'f' * 40), ('charon', 'e' * 40),
                           ('rust_channel', 'beta'), ('lean', 'leanprover/lean4:v0.0.0')]:
            with self.subTest(pin=key):
                f = facts()
                f['toolchain']['declared'][key] = value
                self.assertIn('pins', [n for n, _, _ in gen.region_diffs(manifest(), f)])

    def test_advisory_set_stays_narrow(self):
        # A one-line tripwire: widening ADVISORY is how this gate would quietly stop enforcing.
        # Widened once, deliberately: `evidence-coverage` needs git history, which is an
        # environment probe exactly like `pins-observed`. Anything tree-derived stays enforced.
        self.assertEqual(gen.ADVISORY, {'pins-observed', 'evidence-coverage'})


class CommentStripping(unittest.TestCase):
    """The trap that produced three published wrong counts: prose mentions counted as code.

    DOCS-SYNC.md tells maintainers not to hand-grep because the naive greps count `#[test]`,
    `#[kani::unwind(..)]` and `kani::cover` *mentioned inside doc comments*. That promise is the
    script's, so it belongs in the script's tests rather than only in the prose asserting it.
    """

    def test_mentions_inside_comments_are_not_counted_as_code(self):
        lines = [
            '/// A doc comment mentioning #[test] and kani::cover and #[kani::unwind(16)].',
            '// A line comment mentioning #[kani::proof] too.',
            '    //! inner doc: #[test]',
            '#[test]',
            'fn real() { kani::cover!(true); }',
        ]
        kept = gen.strip_comments(lines)
        self.assertEqual(kept, ['#[test]', 'fn real() { kani::cover!(true); }'])


class DoctestCounting(unittest.TestCase):
    """`count_doctests` replaced `lib.count('```') // 2`, which had two bugs: it only ever read
    `lib.rs` (missing every other module's `//!` example), and it counted EVERY fence — including
    a ```` ```text ```` illustrative block — as if rustdoc ran it. Both directions matter and are
    tested here as an opposing pair, same discipline as `CountGuardCaseFolding` above: an
    over-lenient counter passes a gate that should have caught a real drift, and an over-strict one
    fails a gate for a legitimate doctest, blocking an honest contributor before a single proof
    runs. The crate's own measured total — `cargo test --doc` reports 33 — pins the real-source
    end of this pair.
    """

    def _lines(self, *lines):
        return '\n'.join(lines) + '\n'

    # --- over-lenient direction: a non-Rust fence must NOT be counted --------------------------

    def test_text_tagged_fence_is_not_counted(self):
        # This is the actual bug: every module in this crate pairs a bare (tested) fence with a
        # ```text (untested, illustrative) one, and `lib.count('```') // 2` could not tell them
        # apart — it would have silently doubled the count the moment `lib.rs` grew a second fence.
        src = self._lines('//! Example:', '//! ```text', '//! not real rust, illustrative only',
                          '//! ```')
        self.assertEqual(gen.count_doctests(src), 0)

    def test_other_non_rust_language_tags_are_not_counted(self):
        for lang in ('sh', 'bash', 'json', 'toml', 'yaml'):
            with self.subTest(lang=lang):
                src = self._lines('//! ```%s' % lang, '//! not rust', '//! ```')
                self.assertEqual(gen.count_doctests(src), 0)

    def test_fence_outside_a_doc_comment_is_not_counted(self):
        # A literal ``` inside a `#[test]` string (or any non-doc-comment line) is not prose
        # rustdoc ever sees as a fence; miscounting it would be a different flavour of
        # over-leniency (inventing doctests that do not exist).
        src = self._lines('    let s = "```";', '    let t = "```";')
        self.assertEqual(gen.count_doctests(src), 0)

    # --- over-strict direction: every fence rustdoc DOES run must still be counted -------------

    def test_bare_fence_is_counted(self):
        src = self._lines('//! Example:', '//! ```', '//! let x = 1;', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_explicit_rust_tag_is_counted(self):
        src = self._lines('//! ```rust', '//! let x = 1;', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_rust_doctest_attribute_fences_are_still_counted(self):
        # `no_run`, `should_panic`, `ignore`, `compile_fail`, editions, and combinations thereof
        # are all still Rust as far as rustdoc's fence classifier is concerned — only a REAL
        # language tag (`text`, `sh`, ...) opts a fence out. An over-strict fix that stopped
        # recognising these would undercount a legitimate module's doctest.
        for info in ('rust,no_run', 'should_panic', 'ignore', 'rust,ignore',
                    'compile_fail,E0308', 'rust,edition2021'):
            with self.subTest(info=info):
                src = self._lines('//! ```%s' % info, '//! code', '//! ```')
                self.assertEqual(gen.count_doctests(src), 1)

    def test_ignore_target_variant_is_counted(self):
        # `ignore-x86_64`-style platform-scoped ignores are a real rustdoc form this crate does
        # not currently use, but a counter that only recognised bare `ignore` would undercount the
        # day one is added.
        src = self._lines('//! ```ignore-x86_64', '//! code', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_counts_every_fence_across_multiple_doc_comments_in_one_file(self):
        # The load-bearing regression test for the actual bug: TWO doctest fences in one file,
        # the shape `lib.count('```') // 2` handled by accident (2 fences / 2 = 1, wrongly) but
        # would have gotten wrong the moment a THIRD fence (tested or not) was added anywhere.
        src = self._lines(
            '//! ```', '//! let a = 1;', '//! ```', '//!', '//! ```text', '//! illustrative',
            '//! ```',
            '', '/// A second doc comment on another item in the same file.', '/// ```',
            '/// let b = 2;', '/// ```',
        )
        self.assertEqual(gen.count_doctests(src), 2)   # the two REAL fences, not the ```text one

    # --- the crate's own measured total, so a regression in EITHER direction is caught end-to-end

    def test_crate_total_doctests_matches_the_measured_cargo_test_doc_count(self):
        # `cargo test --doc -p der-verified` reports "33 passed" (measured 2026-08-17, the
        # handover's own figure). This pins the whole pipeline — `count_doctests` summed across
        # every module in `SRC`, not just `lib.rs` — against ground truth, not just fixtures.
        self.assertEqual(facts()['totals']['doctests'], 33)

    def test_only_lib_rs_undercounts_against_the_all_module_total(self):
        # The counter-test for the fix itself: summing `count_doctests` over `lib.rs` ALONE (the
        # old scope) must NOT reach the real crate total, or this whole fix is a no-op that
        # happens to produce the same number by coincidence.
        lib_only = gen.count_doctests(gen.read_text(os.path.join(gen.SRC, 'lib.rs')))
        self.assertLess(lib_only, facts()['totals']['doctests'])


class RustdocAttributeSemantics(unittest.TestCase):
    """The release review's follow-up pass on `count_doctests`: the classifier must mirror rustdoc's ACTUAL
    fence-attribute semantics, not an assumed approximation of them. Every case below was
    verified empirically against the pinned toolchain (`rustc 1.93.1`, `rust-toolchain.toml`
    channel = "stable") with a throwaway probe crate before being encoded here — see the
    commentary above `RUST_DOCTEST_ATTRS` in `gen_proof_manifest.py` for the full probe notes.
    These tests pin that empirical finding in-repo so it cannot silently drift back to an
    assumption.
    """

    def _lines(self, *lines):
        return '\n'.join(lines) + '\n'

    # --- (a) `standalone_crate` is a real, currently-recognised token ---------------------------

    def test_standalone_crate_alone_is_counted(self):
        # Probed: ```standalone_crate``` alone (no `rust` token) is discovered AND run.
        src = self._lines('//! ```standalone_crate', '//! fn main() { assert_eq!(1, 1); }',
                          '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_standalone_without_crate_suffix_is_not_a_real_token(self):
        # Leniency counter-check: `standalone_crate` must be recognised as the EXACT token it is,
        # not a prefix match that would also (wrongly) accept a merely similar-looking word.
        src = self._lines('//! ```standalone', '//! not actually rust', '//! ```')
        self.assertEqual(gen.count_doctests(src), 0)

    # --- (b) `allow_fail` is obsolete/unrecognised on the pinned toolchain ----------------------

    def test_bare_allow_fail_is_not_counted(self):
        # Probed: ```allow_fail``` ALONE is not discovered as a doctest at all by rustc 1.93.1's
        # rustdoc -- treated exactly like an unknown language tag, not like a recognised
        # rust-doctest attribute. `allow_fail` must NOT be in RUST_DOCTEST_ATTRS.
        src = self._lines('//! ```allow_fail', '//! assert_eq!(1, 2);', '//! ```')
        self.assertEqual(gen.count_doctests(src), 0)

    def test_rust_comma_allow_fail_is_still_counted(self):
        # The explicit `rust` token alone is what makes this one count -- probed: it IS discovered
        # and RUN, and a failing assertion inside it reports as a hard FAILED (no "tolerate
        # failure" leniency from `allow_fail` on this toolchain). Recognised via the `rust` token,
        # not because `allow_fail` itself carries any meaning.
        src = self._lines('//! ```rust,allow_fail', '//! assert_eq!(1, 1);', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    # --- (c) ANY recognised token is sufficient, even alongside unrecognised ones ---------------

    def test_rust_plus_unknown_token_is_counted(self):
        # Probed: ```rust,foo``` is discovered and run -- the explicit `rust` token is enough.
        src = self._lines('//! ```rust,foo', '//! assert_eq!(1, 1);', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_known_attribute_plus_unknown_token_is_counted(self):
        # Probed: ```no_run,foo``` is discovered/compiled but NOT executed (`no_run` still
        # suppresses execution -- rustdoc labels this test "... - compile", not "... - run"; the
        # body below is `loop {}` specifically because it would hang forever if it were actually
        # executed, and the test still passes instantly). ANY recognised token suffices to make
        # the block a doctest at all, not specifically `rust`; whether it then EXECUTES is a
        # separate question this test does not assert on either way.
        src = self._lines('//! ```no_run,foo', '//! loop {}', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_only_unknown_tokens_are_not_counted(self):
        # The leniency-direction counter-check for (c): if NO token is recognised, the block is
        # still an ordinary non-Rust language sample, exactly like a single unknown tag. Probed:
        # ```bar,baz``` is not discovered at all.
        src = self._lines('//! ```bar,baz', '//! not rust', '//! ```')
        self.assertEqual(gen.count_doctests(src), 0)

    def test_bare_error_code_without_compile_fail_is_not_counted(self):
        # Probed: a bare ```E0308``` (no `compile_fail` alongside it) is NOT discovered -- the
        # error-code shape only matters when paired with the `compile_fail` token itself, which is
        # what ANY-of already handles; no special E-code normalisation is needed (and adding one
        # would silently regress ANY-of back toward over-leniency for this exact case).
        src = self._lines('//! ```E0308', '//! not valid rust', '//! ```')
        self.assertEqual(gen.count_doctests(src), 0)

    def test_compile_fail_with_error_code_is_counted(self):
        # `compile_fail` is discovered/compiled but NOT executed either (rustdoc expects the
        # block to FAIL to compile and never attempts to run it) -- this test only asserts it
        # counts as a doctest at all, not that it runs.
        src = self._lines('//! ```compile_fail,E0308', '//! let x: u8 = "not a number";', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_edition_number_rustdoc_has_never_shipped_is_still_counted(self):
        # Probed: ```edition2027``` (not a real edition on this toolchain) was still discovered
        # AND RUN -- rustdoc does not validate the edition value for classification, only that the
        # token has the `editionNNNN` shape. A hardcoded enum of known editions would itself go
        # stale the moment a new edition ships and a doc comment starts using it.
        src = self._lines('//! ```edition2027', '//! assert_eq!(1, 1);', '//! ```')
        self.assertEqual(gen.count_doctests(src), 1)

    # --- (d) doc-comment forms this scanner cannot parse: fail CLOSED, not silently -------------

    def test_block_doc_comment_fails_closed(self):
        # Probed: `/** ... */` block doc comments ARE compiled/run by rustdoc exactly like a `///`
        # one -- this scanner only understands `///`/`//!` line comments, so silently proceeding
        # would silently UNDER-count. It must raise instead.
        src = '/** block doc\n```\nassert_eq!(1, 1);\n```\n*/\npub fn f() {}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_inner_block_doc_comment_fails_closed(self):
        src = '/*! inner block doc\n```\nassert_eq!(1, 1);\n```\n*/\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_doc_attribute_form_fails_closed(self):
        # Probed: `#[doc = "..."]` (and its inner-attribute form `#![doc = "..."]`) are also
        # compiled/run exactly like a `///` comment -- same silent-undercount risk.
        src = '#[doc = "fenced\\n```\\nassert_eq!(1, 1);\\n```\\n"]\npub fn f() {}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_spaced_hash_bracket_doc_attribute_fails_closed(self):
        # Release-review regression: Rust's attribute syntax is token-level, not adjacency-
        # sensitive -- `# [doc = "..."]` (whitespace between `#` and `[`, and between `[` and
        # `doc`) is VALID Rust and compiles/runs as a doctest identically to `#[doc = "..."]`
        # (confirmed with a probe crate: `cargo test --doc` discovered and ran it). The original
        # tight `#!?\[doc\s*=` regex required `#`, an optional `!`, and `[` to be adjacent, so
        # this form slipped through silently returning 0 instead of raising.
        src = '# [doc = "fenced\\n```\\nassert_eq!(1, 1);\\n```\\n"]\npub fn f() {}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_spaced_inner_doc_attribute_fails_closed(self):
        # Same regression, the inner-attribute form: `#! [doc = "..."]` (space between `#!` and
        # `[`) is also valid and also compiles/runs as a doctest (confirmed with the same probe,
        # placed at module scope where an inner attribute is syntactically permitted).
        src = 'pub mod m {\n#! [doc = "fenced\\n```\\nassert_eq!(1, 1);\\n```\\n"]\n}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_cfg_attr_doc_form_with_nested_parens_fails_closed(self):
        # `#[cfg_attr(predicate, doc = "...")]` also compiles/runs as a doctest (confirmed with
        # the same probe) and is a materially different shape from the direct `#[doc = ...]`
        # form -- `doc = ` sits nested inside `cfg_attr(...)`'s own argument list. The predicate
        # here (`all()`) itself contains a `)`, which is exactly the shape that would defeat a
        # naive `[^)]*`-bounded scan (it would stop at the `)` closing `all(` and never reach
        # `doc =` at all) -- this is the regression case, not just the general form.
        src = '#[cfg_attr(all(), doc = "fenced\\n```\\nassert_eq!(1, 1);\\n```\\n")]\npub fn f() {}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_cfg_attr_doc_form_past_a_bounded_window_still_fails_closed(self):
        # Release-review round 3 regression: a prior version of this check used a 300-character
        # bounded window after `cfg_attr(` before giving up. That is failure-OPEN -- a real,
        # active `cfg_attr(..., doc = "...")` whose `doc =` happens to sit further in than the
        # bound silently returned 0 instead of raising. Reproduced with 301 spaces (one past the
        # old bound) before `all(), doc = ...`; the scan must now be unbounded.
        src = ('#[cfg_attr(' + (' ' * 301) + 'all(), doc = "fenced\\n```\\n'
               'assert_eq!(1, 1);\\n```\\n")]\npub fn f() {}\n')
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_cfg_attr_doc_form_with_bracket_inside_a_preceding_string_still_fails_closed(self):
        # The second failure-OPEN direction of the same bug: a prior version's window excluded
        # `]` entirely, so a `]` occurring INSIDE a string-literal argument that comes BEFORE
        # `doc =` (not the attribute's own closing bracket) stopped the scan early and it never
        # reached the real `doc =` token. Reproduced with a `feature = "with ] bracket"` argument
        # preceding `doc = "..."` in the same `cfg_attr(...)`.
        src = ('#[cfg_attr(feature = "with ] bracket", doc = "fenced\\n```\\n'
               'assert_eq!(1, 1);\\n```\\n")]\npub fn f() {}\n')
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_cfg_attr_with_comment_before_open_paren_fails_closed(self):
        # Release-review round 4 regression: Rust's tokenizer accepts an arbitrary run of
        # whitespace OR `/* ... */` block comments between any two tokens, so
        # `cfg_attr/*c*/(all(), doc = "...")` is valid and compiles/runs as a doctest identically
        # to the plain form -- confirmed with a probe crate. Caught by the STATIC layer
        # (gen_proof_manifest.py's comment-tolerant cfg_attr regex); the measured cross-check in
        # gates/check_doctest_count.py is the structural backstop for any FUTURE shape neither this
        # test nor that regex anticipates.
        src = '#[cfg_attr/*c*/(all(), doc = "fenced\\n```\\nassert_eq!(1, 1);\\n```\\n")]\npub fn f() {}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_cfg_attr_with_comment_before_doc_equals_fails_closed(self):
        # Same regression, the second reported spelling: a comment between `doc` and `=`
        # (`cfg_attr(all(), doc/*c*/ = "...")`) is also valid and also compiles/runs as a doctest
        # -- confirmed with the same probe. Caught by the STATIC layer.
        src = '#[cfg_attr(all(), doc/*c*/ = "fenced\\n```\\nassert_eq!(1, 1);\\n```\\n")]\npub fn f() {}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_cfg_attr_raw_identifier_spelling_fails_closed(self):
        # The third reported spelling: `r#cfg_attr` (the raw-identifier form of the same
        # identifier) is also valid Rust and also compiles/runs as a doctest -- confirmed with the
        # same probe. Caught by the STATIC layer (the `(?:r#)?` prefix in the cfg_attr regex).
        src = '#[r#cfg_attr(all(), doc = "fenced\\n```\\nassert_eq!(1, 1);\\n```\\n")]\npub fn f() {}\n'
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_cfg_attr_doc_cfg_badge_form_does_not_fail_closed(self):
        # Leniency counter-check: `#[cfg_attr(docsrs, doc(cfg(feature = "x")))]` is the common
        # "docs.rs cfg badge" idiom -- `doc(cfg(...))` ATTACHES metadata to existing docs, it does
        # not set doc TEXT via `doc = "..."`, so it never renders a fenced block of its own and
        # must not trip the fail-closed guard. `doc` here is followed by `(`, not `=`.
        src = '#[cfg_attr(docsrs, doc(cfg(feature = "x")))]\npub fn f() {}\n'
        self.assertEqual(gen.count_doctests(src), 0)   # does not raise

    def test_tilde_fence_inside_doc_comment_fails_closed(self):
        # Probed: CommonMark's `~~~` fence form is honoured by rustdoc exactly like backticks --
        # this scanner only recognises backtick fences.
        src = self._lines('//! ~~~', '//! assert_eq!(1, 1);', '//! ~~~')
        with self.assertRaises(SystemExit):
            gen.count_doctests(src)

    def test_fail_closed_message_names_the_path_when_given(self):
        # The error should be actionable: point at the offending file, not just "somewhere".
        src = '/** x\n```\ny\n```\n*/\n'
        with self.assertRaisesRegex(SystemExit, 'src/whatever.rs'):
            gen.count_doctests(src, 'src/whatever.rs')

    # --- leniency counter-checks for (d): ordinary, parseable forms must NOT trip the guard -----

    def test_ordinary_block_comment_without_doc_marker_does_not_fail_closed(self):
        # `/* ... */` (no `*` or `!` right after the opening `/*`) is an ORDINARY comment, not a
        # doc comment -- rustdoc never sees it at all, so it must not trip the fail-closed guard.
        src = '/* just a regular comment, not documentation */\npub fn f() {}\n'
        self.assertEqual(gen.count_doctests(src), 0)   # does not raise

    def test_doc_hidden_attribute_does_not_fail_closed(self):
        # `#[doc(hidden)]` and friends use the `(...)` attribute-macro form, not `#[doc = ...]`,
        # and can never carry a literal fenced doctest -- must not trip the guard.
        src = '#[doc(hidden)]\npub fn f() {}\n#[doc(alias = "g")]\npub fn g() {}\n'
        self.assertEqual(gen.count_doctests(src), 0)   # does not raise

    def test_normal_source_with_no_unparseable_forms_does_not_fail_closed(self):
        # The crate's own real modules must never trip this guard -- run it over every module.
        for f in sorted(os.listdir(gen.SRC)):
            if f.endswith('.rs'):
                with self.subTest(module=f):
                    gen.count_doctests(gen.read_text(os.path.join(gen.SRC, f)),
                                       os.path.join(gen.SRC, f))   # must not raise

    # --- four-or-more-backtick fences: SUPPORTED (not fail-closed), a cheap correct extension ---

    def test_four_backtick_fence_is_supported_not_failed_closed(self):
        # Probed: a bare ```` fence (no info string) is discovered and run identically to a
        # three-backtick one -- CommonMark allows longer opening fences (so a block that itself
        # needs to show ``` `` ` `` as literal text can be wrapped in more backticks). Chosen to
        # SUPPORT this (cheap, a one-character regex generalisation) rather than fail closed.
        src = self._lines('//! ````', '//! assert_eq!(1, 1);', '//! ````')
        self.assertEqual(gen.count_doctests(src), 1)

    def test_four_backtick_fence_with_text_tag_still_not_counted(self):
        src = self._lines('//! ````text', '//! not rust', '//! ````')
        self.assertEqual(gen.count_doctests(src), 0)

    def test_short_backtick_run_embedded_inside_a_longer_fence_does_not_close_it(self):
        # A four-backtick-opened block may contain a literal ``` `` ` `` (three backticks) as
        # example TEXT without closing the fence early -- CommonMark requires the closer to be at
        # least as long as the opener. Two fences, both counted; the embedded triple does not
        # split them into more (or fewer) than two.
        src = self._lines(
            '//! ````', '//! assert_eq!(1, 1); // shows a literal ``` here', '//! ````',
            '//!',
            '//! ```', '//! assert_eq!(2, 2);', '//! ```',
        )
        self.assertEqual(gen.count_doctests(src), 2)

    def test_same_or_longer_tick_run_with_trailing_text_does_not_close_the_fence(self):
        # Release-review regression: CommonMark permits a closing fence only when the remainder
        # of the line (after the ticks) is whitespace-only. A same-or-longer run of ticks
        # followed by non-whitespace TEXT is ordinary content inside the block, not a closer --
        # confirmed with a probe: a four-backtick-opened block containing the line
        # "````not-a-close, still content" (4 ticks, but with trailing text) is discovered/run as
        # ONE doctest, not two. The length-only check (`len(ticks) >= fence_len`, with no check on
        # what follows the ticks) used to treat that content line as a valid close and count two.
        src = self._lines(
            '//! ````',
            '//! let s = "example";',
            '//! ````not-a-close, still content',
            '//! assert_eq!(1, 1);',
            '//! ````',
        )
        self.assertEqual(gen.count_doctests(src), 1)

    def test_closing_fence_with_trailing_whitespace_only_still_closes(self):
        # The paired leniency check: a closer with ONLY trailing whitespace (no other text) must
        # still close the fence -- CommonMark explicitly permits spaces/tabs after the closing
        # ticks, and requiring a byte-exact empty remainder would be an over-strict regression.
        src = '//! ```   \n//! assert_eq!(1, 1);\n//! ```\t\n'
        self.assertEqual(gen.count_doctests(src), 1)

    def test_nbsp_after_candidate_closer_does_not_close_the_fence(self):
        # Release-review round 3 regression: Python's `str.strip()` treats U+00A0 NO-BREAK SPACE
        # (and other Unicode Zs whitespace) as strippable, but CommonMark's closing-fence rule
        # permits only literal spaces and tabs. Confirmed with a probe: a four-backtick candidate
        # closer followed by a single NBSP does NOT close the fence in rustdoc either (it is
        # discovered/run as ONE doctest); the old `info.strip() == ''` check wrongly treated the
        # NBSP-only remainder as "no trailing text" and closed early, miscounting two.
        nbsp = ' '
        src = self._lines(
            '//! ````',
            '//! let s = "example";',
            '//! ````' + nbsp,
            '//! assert_eq!(1, 1);',
            '//! ````',
        )
        self.assertEqual(gen.count_doctests(src), 1)


class DoctestGuardCatchesDrift(unittest.TestCase):
    """The `doctests` GUARDS entry: a hand-written "N doc-tests" claim in a guarded doc must be
    checked against the real count, the same way `tests`/`harnesses` already are. Before this
    entry existed, `docs/why-verified.md` said "30 doc-tests" while the true count was 33 and
    nothing noticed — this is the regression pair for that gap.
    """

    def test_stale_doctest_count_is_flagged(self):
        hits = gen.guard_line_hits('cargo test   # 472 tests + 30 doc-tests')
        self.assertIn(('doctests', 30, '30 doc-tests'), hits)

    def test_stale_module_and_crate_doc_examples_phrasing_is_flagged(self):
        # PROOF_MANIFEST.md §3.3 uses a THIRD phrasing the "doc-tests" guard above does not match
        # ("472 unit and regression tests (plus 30 module and crate-doc examples)") -- the release
        # review caught this sailing through `--check` at a stale 30 while the true count was
        # already 33. This is the regression pair for that specific phrase.
        hits = gen.guard_line_hits(
            'runs 472 unit and regression tests (plus 30 module and crate-doc examples) over')
        self.assertIn(('doctests', 30, '30 module and crate-doc examples'), hits)

    def test_correct_examples_phrasing_does_not_fail_check(self):
        f = facts()
        n = f['totals']['doctests']
        hits = gen.guard_line_hits(
            'runs 472 unit and regression tests (plus %d module and crate-doc examples) over' % n)
        got = [h for h in hits if h[0] == 'doctests'][0]
        self.assertEqual(got[1], n)

    def test_correct_doctest_count_in_guarded_doc_does_not_fail_check(self):
        # The leniency half of the pair: the CORRECT figure, once fixed, must not itself trip
        # the guard — a guard that flags every occurrence regardless of value would be as useless
        # as one that flags none.
        f = facts()
        n = f['totals']['doctests']
        hits = gen.guard_line_hits('cargo test   # 472 tests + %d doc-tests' % n)
        got = [h for h in hits if h[0] == 'doctests'][0]
        self.assertEqual(got[1], n)

    def test_doctest_guard_is_wired_into_guard_violations(self):
        # Wiring pin, same shape as `test_guard_violations_routes_through_guard_line_hits` above:
        # a private copy of the regex in `guard_line_hits` that `guard_violations` stopped calling
        # would still pass a value-only test. Drive it through an actual guarded doc's content.
        f = facts()
        bad_count = f['totals']['doctests'] + 5
        line = 'cargo test   # 472 tests + %d doc-tests' % bad_count
        with tempfile.NamedTemporaryFile('w', suffix='.md', delete=False, encoding='utf-8') as fh:
            fh.write(line + '\n')
            path = fh.name
        try:
            bad = []
            for lineno, l in enumerate(gen.read_text(path).split('\n'), 1):
                for key, got, matched in gen.guard_line_hits(l):
                    if got != f['totals'][key]:
                        bad.append((path, lineno, key, got, f['totals'][key], matched))
            self.assertTrue(any(b[2] == 'doctests' and b[3] == bad_count for b in bad))
        finally:
            os.unlink(path)


class CountGuardCaseFolding(unittest.TestCase):
    """A count-claim written sentence-initial (Titlecase spelled number) must still be guarded.

    `PROOF_MANIFEST` opened section 8.4 with "Four harnesses are **modular proofs**". The spelled-
    number alternatives in `NUM` are lowercase, so the guard — matching case-sensitively — never saw
    "Four", and the prose count sat at 4 while the generated table below it listed 8. The fix is the
    scoped `(?i:...)` group on the number token. These are an opposing pair: the leniency test pins
    that Titlecase counts are caught, the strictness test pins that the fold did NOT leak into the
    phrase (which would turn every Titlecased sentence into a false-hit candidate).
    """

    def _keys(self, line):
        return [(k, n) for k, n, _ in gen.guard_line_hits(line)]

    def test_capitalized_spelled_count_is_guarded(self):
        self.assertIn(('stub_harnesses', 4),
                      self._keys('Four harnesses are **modular proofs**: they replace a sub-parser'))

    def test_lowercase_spelled_count_still_guarded(self):
        self.assertIn(('stub_harnesses', 4),
                      self._keys('four harnesses are **modular proofs**'))

    def test_case_fold_is_scoped_to_the_number_not_the_phrase(self):
        # An all-caps PHRASE must not match: if it does, the scoped flag silently became global and
        # every Titlecased sentence is now a candidate false hit.
        self.assertEqual(gen.guard_line_hits('Four HARNESSES ARE **MODULAR proofs**'), [])

    def test_guard_violations_routes_through_guard_line_hits(self):
        # Wiring pin: if `guard_violations` regressed to a private inlined regex, the case-fold tests
        # above would pin a helper the gate no longer uses. A value-only assertion cannot catch that
        # regression — a lowercase count elsewhere in the guarded docs (README's "eight ... **modular**
        # proofs") would still trip a stale case-sensitive copy, so the violation appears either way.
        # Spy on the helper instead and assert the gate actually routes every line through it.
        import unittest.mock as mock
        real = gen.guard_line_hits
        seen = []

        def spy(line):
            seen.append(line)
            return real(line)

        with mock.patch.object(gen, 'guard_line_hits', spy):
            gen.guard_violations(facts())
        self.assertTrue(seen, 'guard_violations did not route through guard_line_hits')


class EntryPointAttributionScoping(unittest.TestCase):
    """`harnessed_entry_points` must be credited from `#[kani::proof]` bodies ONLY — never from a
    `#[kani::stub]` helper body. A `pub fn` merely NAMED in a stub body is not exercised by any
    harness, so crediting it would overclaim coverage. This is the load-bearing counter-test: it
    FAILS on the old whole-`mod proofs` match and passes on the harness-body-scoped match.
    """

    FIXTURE = '\n'.join([
        'pub fn target_fn(x: &[u8]) -> bool { x.is_empty() }',
        'pub fn other_fn(x: &[u8]) -> bool { !x.is_empty() }',
        '',
        '#[cfg(kani)]',
        'mod proofs {',
        '    use super::*;',
        '    #[allow(dead_code)]',
        '    fn stub_thing(_x: &[u8]) -> bool { target_fn(&[]) }',  # names target_fn in a HELPER body
        '    #[kani::proof]',
        '    fn only_names_other() {',
        '        let b: [u8; 4] = kani::any();',
        '        let _ = other_fn(&b);',  # harness names other_fn, NOT target_fn
        '    }',
        '}',
        '',
        '#[cfg(test)]',
        'mod tests {}',
        '',
    ])

    def _facts(self):
        with tempfile.NamedTemporaryFile('w', suffix='.rs', delete=False, encoding='utf-8') as fh:
            fh.write(self.FIXTURE)
            path = fh.name
        try:
            return gen.module_facts(path)
        finally:
            os.unlink(path)

    def test_stub_body_mention_does_not_credit_coverage(self):
        f = self._facts()
        self.assertIn('target_fn', f['unharnessed_entry_points'],
                      'a pub fn named only in a stub body was miscredited as harnessed')
        self.assertNotIn('target_fn', f['harnessed_entry_points'])

    def test_real_harness_body_mention_still_credits(self):
        # The paired leniency check: an entry point genuinely named in a #[kani::proof] body must
        # still be credited, so the scoping did not over-tighten into crediting nothing.
        f = self._facts()
        self.assertIn('other_fn', f['harnessed_entry_points'])


class RegionPlumbing(unittest.TestCase):
    def test_advisory_region_is_still_generated_and_still_marker_checked(self):
        # Advisory means "not byte-compared", NOT "not maintained": --write must still write it,
        # and a missing marker must still fail, so the provenance note cannot silently vanish.
        rendered = gen.render(facts(), 'pins-observed')
        self.assertIn('Observed on the machine', rendered)
        self.assertIn('rustc', rendered)

        text = manifest().replace(gen.BEGIN % 'pins-observed', '')
        _, missing = gen.rewrite(text, facts())
        self.assertIn('pins-observed', missing)

    def test_write_is_idempotent(self):
        once, missing = gen.rewrite(manifest(), facts())
        self.assertEqual(missing, [])
        twice, _ = gen.rewrite(once, facts())
        self.assertEqual(once, twice)

    def test_every_advisory_name_is_a_real_region(self):
        self.assertEqual(gen.ADVISORY - set(gen.REGIONS), set())


class GateExitCode(unittest.TestCase):
    """End-to-end: `check.sh` consults the *exit code* of `--check`, not `region_diffs`.

    Without this class every test above could pass while `main()` ignored its own findings and
    returned 0 — the gate would be green and vacuous, which is the failure mode this repo cares
    about most. So: drive `main()` itself, and assert on the exit code and the message.
    """

    def _check(self, text):
        """Run `--check` against `text` as if it were the committed manifest."""
        with tempfile.NamedTemporaryFile('w', suffix='.md', delete=False, encoding='utf-8') as fh:
            fh.write(text)
            path = fh.name
        real_manifest, real_argv = gen.MANIFEST, sys.argv
        try:
            gen.MANIFEST = path
            sys.argv = ['gen_proof_manifest.py', '--check']
            err = io.StringIO()
            with contextlib.redirect_stderr(err), contextlib.redirect_stdout(io.StringIO()):
                code = gen.main()
            return code, err.getvalue()
        finally:
            gen.MANIFEST, sys.argv = real_manifest, real_argv
            os.unlink(path)

    def test_committed_manifest_exits_zero(self):
        code, err = self._check(manifest())
        self.assertEqual(code, 0, err)

    def test_drifted_count_exits_one_and_names_the_region_and_the_lines(self):
        n = facts()['totals']['harnesses']
        old = '| `#[kani::proof]` harnesses | %d |' % n
        text = manifest()
        self.assertIn(old, text, 'inventory row not found — this test needs updating')
        code, err = self._check(text.replace(old, '| `#[kani::proof]` harnesses | %d |' % (n + 7)))
        self.assertEqual(code, 1)
        self.assertIn('inventory', err)          # names the disagreeing region…
        self.assertIn(str(n + 7), err)           # …and shows both sides, so the reader can judge
        self.assertIn(str(n), err)               # whether the source or the manifest is wrong.

    def test_foreign_observed_line_exits_zero(self):
        pre, _, post = gen.split_region(manifest(), 'pins-observed')
        foreign = pre + (gen.BEGIN % 'pins-observed') + \
            "\nObserved elsewhere: rustc `0.0.0`, Kani `not installed on this machine`.\n" + \
            (gen.END % 'pins-observed') + post
        code, err = self._check(foreign)
        self.assertEqual(code, 0, err)

    def test_a_newline_only_difference_still_prints_a_diff(self):
        # A failure that prints no diff is worse than the blanket message this replaced, and it is
        # exactly what stripping the region's bracketing newlines before diffing would produce.
        b = gen.BEGIN % 'inventory'
        text = manifest().replace(b + '\n', b, 1)   # delete the newline after the BEGIN marker
        self.assertNotEqual(text, manifest())
        code, err = self._check(text)
        self.assertEqual(code, 1)
        self.assertIn('inventory', err)
        # Not just the header: an actual +/- line from the unified diff must be there.
        body = [l for l in err.split('\n') if l.strip().startswith(('+', '-'))
                and not l.strip().startswith(('+++', '---'))]
        self.assertTrue(body, 'gate reported a disagreement but printed no diff:\n' + err)

    def test_missing_region_marker_exits_one(self):
        code, err = self._check(manifest().replace(gen.BEGIN % 'pins-observed', ''))
        self.assertEqual(code, 1)
        self.assertIn('pins-observed', err)


class MutationKill(unittest.TestCase):
    """Are the tests above worth anything? Break the gate on purpose and demand they notice.

    A test suite that passes against a gutted gate is the vacuity this crate spends most of its
    care avoiding, and "I checked once by hand" is not a check (DOCS-SYNC.md). So the check runs
    here, every time: each mutant below is a plausible way this gate could be weakened — reverting
    the fix, widening the advisory set to quiet a complaint, or short-circuiting the comparison —
    and each must be killed by a NAMED test, not merely by "something failed".
    """

    SUBJECTS = None  # filled in below, after the classes exist

    def _kills(self, mutate, restore):
        mutate()
        try:
            suite = unittest.TestSuite(unittest.defaultTestLoader.loadTestsFromTestCase(c)
                                       for c in self.SUBJECTS)
            res = unittest.TextTestRunner(stream=io.StringIO(), verbosity=0).run(suite)
        finally:
            restore()
        # subTest ids carry a " (pin='...')" suffix; the test's own name is what we assert on.
        return {tc.id().split('.')[-1].split(' ')[0] for tc, _ in res.failures + res.errors}

    def test_reverting_the_fix_is_caught(self):
        # Deliberately NOT requiring `test_committed_manifest_exits_zero` here: whether the
        # reverted gate fails on the committed manifest depends on whether THIS machine's rustc
        # happens to match the recorded one — on the machine that last ran `--write`, the buggy
        # gate is green. That is precisely why the bug reached a third party in the first place,
        # and why the required kills below are tests that inject a foreign toolchain themselves.
        original = set(gen.ADVISORY)   # capture, never hardcode -- see the note below
        killed = self._kills(lambda: setattr(gen, 'ADVISORY', set()),
                             lambda: setattr(gen, 'ADVISORY', original))
        self.assertLessEqual({'test_different_rustc_does_not_fail_check',
                              'test_absent_kani_and_aeneas_do_not_fail_check',
                              'test_manifest_recorded_on_another_machine_does_not_fail_check',
                              'test_foreign_observed_line_exits_zero'}, killed)

    def test_gutting_the_comparison_is_caught(self):
        real = gen.region_diffs
        killed = self._kills(lambda: setattr(gen, 'region_diffs', lambda text, f: []),
                             lambda: setattr(gen, 'region_diffs', real))
        self.assertLessEqual({'test_drifted_harness_count_still_fails_check',
                              'test_drifted_declared_toolchain_pin_still_fails_check',
                              'test_drifted_count_exits_one_and_names_the_region_and_the_lines'},
                             killed)

    def test_widening_the_advisory_set_is_caught(self):
        # Restore the value that was ACTUALLY there, not a hardcoded literal: a hardcoded restore
        # silently reverts a legitimate change to ADVISORY and corrupts every test that runs after
        # this one, which is order-dependent and exactly the kind of failure a test suite should not
        # have. (It did: adding `evidence-coverage` made a later test fail here, not in the code.)
        original = set(gen.ADVISORY)
        killed = self._kills(
            lambda: setattr(gen, 'ADVISORY', {'pins-observed', 'pins', 'inventory'}),
            lambda: setattr(gen, 'ADVISORY', original))
        self.assertLessEqual({'test_drifted_harness_count_still_fails_check',
                              'test_drifted_declared_toolchain_pin_still_fails_check'}, killed)


MutationKill.SUBJECTS = (ThirdPartyEnvironment, StillEnforced, RegionPlumbing, GateExitCode)



class HeadCoverageFact(unittest.TestCase):
    """Whether a committed run still speaks for HEAD is DERIVED from git, and rendered in its own
    ADVISORY region so a git-less clone can still pass `--check`. Both directions matter: it must not
    under-claim once a run log at HEAD exists, and it must stop claiming the moment verified source
    moves. Neither is checkable by eye, so gate both -- including that the region stays advisory,
    which is the regression that motivated the split."""

    def test_verified_paths_are_the_proof_bearing_ones(self):
        # If this list ever silently widened to include docs, a docs commit would invalidate a run
        # log and the manifest would start disclaiming for no reason.
        self.assertEqual(sorted(gen.VERIFIED_PATHS), ['der-verified/src', 'lean'])

    @contextlib.contextmanager
    def _throwaway_repo(self):
        """A disposable git repo carrying the VERIFIED_PATHS layout, with `gen.ROOT` pointed at it.

        These two tests MUST NOT read the developer's own checkout. `verified_source_unchanged_since`
        compares the commit against the WORKING TREE, not against HEAD (31b0994, so the manifest
        stops claiming currency the moment verified source is edited rather than one commit later).
        Against the real repo, "HEAD vs HEAD" is therefore false whenever anything under
        `der-verified/src` or `lean/` is uncommitted -- which is true during *every* commit that
        touches proof-bearing source, i.e. exactly when this gate runs from the pre-commit hook.

        That is not hypothetical. 31b0994 changed the semantics without changing this test, and the
        pair went unnoticed because no commit touched a VERIFIED_PATH in between. The next one that
        did was blocked by its own gate, with a self-test failure that pointed at nothing real.

        "Disposable" has to mean disposable from the AMBIENT GIT STATE too, or this trades one
        red-for-unrelated-reasons for another: a contributor with `commit.gpgsign` on and no usable
        key, or a `core.hooksPath` pointing at a global hook, would have the seed commit fail and the
        suite redden for something that is not this gate's business. Signing and hooks are therefore
        overridden per-invocation, `GIT_*` is scrubbed from the child environment, and `init` is given
        an empty template so a global one cannot install hooks or an `info/exclude` that would leave
        `seed.txt` unstageable. None of these were set on the machine this was written on, which is
        exactly why they need pinning rather than assuming.
        """
        with tempfile.TemporaryDirectory() as box:
            tmp = os.path.join(box, 'repo')
            template = os.path.join(box, 'empty-template')
            os.makedirs(tmp)
            os.makedirs(template)
            env = {k: v for k, v in os.environ.items() if not k.startswith('GIT_')}

            def run(*args):
                return subprocess.run(
                    ['git', '-c', 'commit.gpgsign=false', '-c', 'core.hooksPath=/dev/null',
                     '-C', tmp, *args],
                    capture_output=True, text=True, check=True, env=env).stdout.strip()
            run('init', '-q', '--template=' + template)
            run('config', 'user.email', 'test@example.invalid')
            run('config', 'user.name', 'test')
            for rel in gen.VERIFIED_PATHS:
                os.makedirs(os.path.join(tmp, rel), exist_ok=True)
                with open(os.path.join(tmp, rel, 'seed.txt'), 'w', encoding='utf-8') as fh:
                    fh.write('seed\n')
            run('add', '-A')
            run('commit', '-qm', 'seed')
            original_root = gen.ROOT
            gen.ROOT = tmp
            try:
                yield tmp, run
            finally:
                gen.ROOT = original_root

    def test_unchanged_since_head_is_true(self):
        # Clean tree, HEAD vs HEAD: nothing has changed.
        with self._throwaway_repo() as (_tmp, run):
            self.assertTrue(gen.verified_source_unchanged_since(run('rev-parse', 'HEAD')))

    def test_uncommitted_edit_to_verified_source_reads_as_changed(self):
        # The direction 31b0994 actually bought, and the one nothing covered: an UNCOMMITTED edit
        # under a VERIFIED_PATH must already read as superseding a run, because the pre-commit hook
        # writes this region while the change is still uncommitted.
        with self._throwaway_repo() as (tmp, run):
            head = run('rev-parse', 'HEAD')
            with open(os.path.join(tmp, gen.VERIFIED_PATHS[-1], 'seed.txt'), 'a',
                      encoding='utf-8') as fh:
                fh.write('an uncommitted edit\n')
            self.assertFalse(gen.verified_source_unchanged_since(head))

    def test_commit_predating_a_committed_source_change_reads_as_changed(self):
        # The third direction, and the one the pair above cannot see. Both tests move the WORKING
        # TREE and leave the recorded commit at HEAD, so an implementation that ignored its own
        # argument and merely asked "is the verified tree dirty?" -- `git diff HEAD -- paths` --
        # satisfied both while answering a different question entirely. Measured: that mutant passed
        # the whole suite, rc=0, 28/28. The predicate's actual job is "does the run recorded AT THIS
        # COMMIT still speak for what is here now", so it must go False for an OLD commit on a
        # perfectly CLEAN tree, which is the ordinary state of a repo whose proofs have gone stale.
        with self._throwaway_repo() as (tmp, run):
            before = run('rev-parse', 'HEAD')
            with open(os.path.join(tmp, gen.VERIFIED_PATHS[0], 'seed.txt'), 'a',
                      encoding='utf-8') as fh:
                fh.write('a committed change to verified source\n')
            run('add', '-A')
            run('commit', '-qm', 'move verified source')
            self.assertEqual(run('status', '--porcelain'), '', 'fixture tree must be clean here')
            self.assertFalse(gen.verified_source_unchanged_since(before))
            # …and the new commit does speak for it, so this is not just "always False".
            self.assertTrue(gen.verified_source_unchanged_since(run('rev-parse', 'HEAD')))

    def test_unrecorded_commit_is_unknown_not_true(self):
        # Fail-open would silently upgrade an unverifiable log to "covers HEAD".
        self.assertIsNone(gen.verified_source_unchanged_since('unrecorded'))
        self.assertIsNone(gen.verified_source_unchanged_since(''))

    def test_coverage_region_claims_head_when_a_live_log_exists(self):
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': True, 'failed': 0}]}
        self.assertIn('still speaks for HEAD', '\n'.join(gen.r_evidence_coverage(f)))

    def test_coverage_region_disclaims_when_the_log_predates_a_source_change(self):
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': False, 'failed': 0}]}
        out = '\n'.join(gen.r_evidence_coverage(f))
        self.assertIn('No committed run currently speaks for HEAD', out)
        self.assertIn('superseded', out)

    def test_coverage_region_ignores_a_log_that_recorded_failures(self):
        # A run with FAILED verdicts must never be read as establishing anything.
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': True, 'failed': 2}]}
        self.assertIn('No committed run currently speaks for HEAD',
                      '\n'.join(gen.r_evidence_coverage(f)))

    def test_coverage_region_reports_unknown_rather_than_defaulting_to_yes(self):
        f = {'evidence': [{'file': 'evidence/x.log', 'commit': 'abc1234',
                           'covers_head_source': None, 'failed': 0}]}
        out = '\n'.join(gen.r_evidence_coverage(f))
        self.assertIn('could not answer', out)
        self.assertNotIn('still speaks for HEAD', out)

    def test_no_evidence_says_so(self):
        self.assertIn('No committed run log', '\n'.join(gen.r_evidence_coverage({'evidence': []})))

    def test_coverage_region_is_advisory_so_a_git_less_clone_still_passes(self):
        # The regression this whole split exists to prevent.
        self.assertIn('evidence-coverage', gen.ADVISORY)

if __name__ == '__main__':
    # Default warning filters on purpose: nothing is suppressed, so a future DeprecationWarning in
    # the generator surfaces here. (The ResourceWarning flood this used to silence is gone — the
    # generator's reads now go through `read_text`, which closes the handle.)
    unittest.main(verbosity=2, argv=[sys.argv[0]] + sys.argv[1:])
