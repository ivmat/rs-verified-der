# Vendored: acceptance-format validator (pinned)

These three files are **vendored, not authored here**. They are copied verbatim from the
`acceptance-format` project and pinned at one commit. Do not edit them in this repo; a local fix
here would be silently lost on the next re-vendor, and worse, would mean this crate's certificate
was checked by a tool nobody else runs.

| file | sha256 |
|---|---|
| `check_acceptance.py` | `d3dfd2069dabec7e7020e9ffec68ecac7058f896ded37a080c5a34dbb77e8be3` |
| `m11.py` | `501a5116b63f06d396d45e578e885db041f06a0e54068015d0fd0d7a87ff989d` |
| `acceptance_grammar.py` | `c6529560feac9cd8c4202e61b9740d0e529553ecc06aa53a25205e9702b201ac` |

- **Upstream:** https://github.com/ivmat/acceptance-format
- **Pinned at commit:** `c8c00bb`
- **Vendored on:** 2026-08-30
- **Licence:** as published by that project.

The pin names a commit that is **publicly resolvable**, and that is a requirement rather than a
preference. A manifest whose `spec_sha` / `validator_sha` names a commit nobody outside the project
can fetch makes a reproducibility promise it cannot keep. If a future re-vendor can only reach an
unpublished revision, the correct move is to publish that revision first — not to record it here.

## Why vendored, and why pinned

The root `acceptance.toml` is this crate's machine-readable certificate. A certificate is only
worth its checker, so the checker cannot be a moving target:

- **Vendored, not fetched.** `check.sh` and `check_fast.sh` must be runnable by a third party
  offline, from this repo alone, with no network and no extra install. A gate that fetched its own
  validator would also let a remote change turn a published green red (or, worse, red green)
  without a commit here.
- **Pinned, not "latest".** The manifest records the `validator_sha` it was generated against, and
  `gates/check_acceptance_manifest.py` refuses the pair if that value and this pin disagree.
  Checking a manifest with a different revision of the format than it was emitted under is not a
  check; it is two different questions with one answer reported.

## Re-vendoring

1. Copy the three files from upstream at the new commit.
2. Update the commit, date and all three sha256 values above.
3. Update `PINNED_SPEC_SHA` in `gates/check_acceptance_manifest.py`.
4. **Re-emit** `acceptance.toml` against that same revision — never hand-edit its `validator_sha`
   to match. If the new revision changes what validates, that is a real finding about this crate's
   claims and belongs in `CHANGELOG.md` and `DECISIONS.md`, not in a one-character edit.
5. Run `./check.sh`.

The re-emit is step 4 and not optional: the manifest and the validator are a matched pair, and the
gate is written to fail rather than let them drift apart quietly.
